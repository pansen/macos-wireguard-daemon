//! Pure core for the `wgd launchd` subcommand: an installer for the
//! privileged launchd daemon plist. This module provides both the
//! plist-rendering / binary-location-validation logic and the
//! `wgd launchd install|restart|uninstall` command handlers, which own
//! every system-domain launchd operation (the Makefile and `wgd launchd reload`
//! both go through them). `wgd launchd agent ...` is dispatched from here
//! too, but its own installer/body live in `session_agent.rs` since it's a
//! per-user (GUI domain) LaunchAgent, not this module's system daemon.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context;
use nix::unistd::{chown, geteuid, Gid, Group, Uid, User};

use crate::cli::LaunchdCommand;
use crate::config;
use crate::launchctl::{remove_file_ignore_missing, run_checked, run_ignore_failure, xml_escape};
use crate::privileged_api::ConnectionScope;
use crate::privileged_client::PrivilegedClient;

pub(crate) const LABEL: &str = "me.pansen.wgd.privileged";
pub(crate) const PLIST_PATH: &str = "/Library/LaunchDaemons/me.pansen.wgd.privileged.plist";

/// Group whose members may talk to the privileged daemon's control socket.
/// Must match `AUTH_GROUP_NAME` in `src/privileged/mod.rs`, which is private
/// to that module and therefore unavailable from here.
const GROUP_NAME: &str = "wgd";

const PLIST_TEMPLATE: &str = include_str!("../etc/me.pansen.wgd.privileged.plist");
const BIN_PLACEHOLDER: &str = "@WGD_BIN@";
const SOCK_GROUP_MARKER: &str = "@SOCK_PATH_GROUP@";

/// Render the privileged daemon's launchd plist, substituting the daemon
/// binary path and the authorized-group GID into `template`.
fn render_plist_from(template: &str, daemon_binary: &str, gid: u32) -> anyhow::Result<String> {
    if !template.contains(BIN_PLACEHOLDER) {
        anyhow::bail!("plist template is missing the {BIN_PLACEHOLDER} placeholder");
    }

    let marker_line = template
        .lines()
        .find(|line| line.contains(SOCK_GROUP_MARKER))
        .ok_or_else(|| {
            anyhow::anyhow!("plist template is missing the {SOCK_GROUP_MARKER} marker comment")
        })?;
    let indent: String = marker_line
        .chars()
        .take_while(|c| c.is_whitespace())
        .collect();
    let group_kv = format!("{indent}<key>SockPathGroup</key>\n{indent}<integer>{gid}</integer>");

    // Replace the marker line on the raw template first (so it matches regardless
    // of where BIN_PLACEHOLDER sits), then substitute the escaped binary path.
    let rendered = template
        .replace(marker_line, &group_kv)
        .replace(BIN_PLACEHOLDER, &xml_escape(daemon_binary));

    // Fail closed: neither placeholder may survive, and the daemon Label the
    // restart/uninstall paths target must be present (guards a bad custom template).
    anyhow::ensure!(
        !rendered.contains(BIN_PLACEHOLDER),
        "rendered plist still contains {BIN_PLACEHOLDER}"
    );
    anyhow::ensure!(
        !rendered.contains(SOCK_GROUP_MARKER),
        "rendered plist still contains the {SOCK_GROUP_MARKER} marker"
    );
    anyhow::ensure!(
        rendered.contains(LABEL),
        "rendered plist is missing the expected launchd Label `{LABEL}` (custom template?)"
    );

    Ok(rendered)
}

/// Directories a root launchd job may run its binary from. Fixed, system
/// directories only: the same ones `trusted_exec::SYSTEM_PATH` trusts for
/// command resolution (`/usr/bin`, `/bin`, `/usr/sbin`, `/sbin`), plus
/// `/usr/local/bin` (`TRUSTED_BIN_PATH`, wgd's own install location).
///
/// The rendered plist makes launchd run this binary as root, so both the
/// path as invoked (e.g. `current_exe()`) and its canonicalized/symlink-
/// resolved target must live directly inside one of these -- otherwise a
/// user could swap the binary out from under root's launchd.
///
/// Finding 3 — Executable substitution through PATH: an allow-list of the
/// small, fixed set of directories root is expected to control, rather than
/// an open-ended (and inevitably incomplete) list of locations to reject.
/// The installer additionally checks ownership and write permissions of the
/// actual binary and its ancestors (`trusted_exec::validate_root_owned_path`).
const ALLOWED_BINARY_DIRS: &[&str] = &["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin"];

/// Where a not-yet-trusted binary is copied to before it's trusted.
/// Matches the Makefile's `WGD_BIN` convention.
const TRUSTED_BIN_PATH: &str = "/usr/local/bin/wgd";

pub fn validate_binary_location(invoked: &Path, resolved: &Path) -> anyhow::Result<()> {
    validate_one(invoked)?;
    validate_one(resolved)?;
    Ok(())
}

fn validate_one(path: &Path) -> anyhow::Result<()> {
    if !path.is_absolute() {
        anyhow::bail!(
            "refusing to install a launchd daemon that runs a non-absolute path ({}); \
             install a build from a system location such as /usr/local/bin with root-owned parent directories",
            path.display()
        );
    }

    let in_allowed_dir = path.parent().is_some_and(|parent| {
        ALLOWED_BINARY_DIRS
            .iter()
            .any(|dir| parent == Path::new(dir))
    });
    if !in_allowed_dir {
        anyhow::bail!(
            "refusing to install a launchd daemon that runs a binary from an untrusted \
             location ({}); place the wgd binary directly in one of: {}",
            path.display(),
            ALLOWED_BINARY_DIRS.join(", ")
        );
    }

    Ok(())
}

/// Locations `install_time_binary_path` refuses to relocate from: a regular
/// user's home directory, `/tmp`, and `/var/folders` are always
/// attacker-controlled, so copying a binary from one of these into a
/// root-owned, launchd-trusted path would be a privilege escalation
/// regardless of ownership.
///
/// This can't be expressed as an allow-list like `ALLOWED_BINARY_DIRS`
/// above: relocation exists precisely to accept binaries from *outside*
/// that fixed set (Homebrew's prefix, wherever it resolves to on this
/// machine, being the motivating case), so the set of acceptable sources is
/// open-ended by design. Homebrew's prefix is deliberately not in this list
/// -- it's the one admin-writable location `install_time_binary_path`
/// exists to relocate rather than reject, and it no longer needs to be
/// named for that to work.
const RELOCATION_DENY_PREFIXES: &[&str] = &[
    "/Users/",
    "/tmp/",
    "/private/tmp/",
    "/var/folders/",
    "/private/var/folders/",
    "/var/tmp/",
    "/private/var/tmp/",
];

/// Verify every ancestor of `path` is owned by root or by `invoking_uid` and
/// is not world-writable.
///
/// `reject_unsafe_relocation_source` above only denies a fixed list of
/// locations that are *always* attacker-controlled; by itself that allows
/// relocating from any other path, including one another, untrusted local
/// user made writable for themselves (e.g. `/opt/local/bin`), as long as it
/// isn't on the denylist. Since `relocate_to_trusted_path` copies the source
/// into a root-owned, launchd-trusted path while running as root, the source
/// must be traced back to root or to the person who typed `sudo`, not merely
/// checked against a list of known-bad prefixes.
fn require_owned_by_invoking_user_or_root(path: &Path, invoking_uid: Uid) -> anyhow::Result<()> {
    use std::os::unix::fs::MetadataExt;

    // A symlink ancestor isn't itself rejected here: Homebrew's `bin/wgd` is
    // routinely a symlink into its Cellar, and macOS's own `/var` and `/tmp`
    // are symlinks into `/private/...`, so a blanket rejection would reject
    // the exact case relocation exists to support. Ownership of the symlink
    // entry itself is still checked below (an attacker-owned symlink in an
    // otherwise-trusted directory fails there), and the caller separately
    // checks `resolved` -- `current_exe()` canonicalized -- so the real,
    // fully-dereferenced destination is always validated too.
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)
            .with_context(|| format!("failed to inspect {}", ancestor.display()))?;
        let owner = Uid::from_raw(metadata.uid());
        if owner.as_raw() != 0 && owner != invoking_uid {
            anyhow::bail!(
                "refusing to relocate a wgd binary through {} which is owned by a \
                 different user (uid {}); only files owned by root or by the user who \
                 ran sudo (uid {}) are trusted as a relocation source",
                ancestor.display(),
                owner.as_raw(),
                invoking_uid.as_raw()
            );
        }
        if metadata.mode() & 0o002 != 0 {
            anyhow::bail!(
                "refusing to relocate a wgd binary through {} which is world-writable",
                ancestor.display()
            );
        }
    }

    Ok(())
}

fn reject_unsafe_relocation_source(
    path: &Path,
    invoking_user_home: Option<&Path>,
) -> anyhow::Result<()> {
    if !path.is_absolute() {
        anyhow::bail!(
            "refusing to install a launchd daemon that runs a non-absolute path ({}); \
             install a build from a system location such as /usr/local/bin with root-owned parent directories",
            path.display()
        );
    }

    let path_str = path.to_string_lossy();

    for prefix in RELOCATION_DENY_PREFIXES {
        if path_str.starts_with(prefix) {
            anyhow::bail!(
                "refusing to install a launchd daemon that runs a binary from a user-writable \
                 location ({}); place the wgd binary in a system location such as \
                 /usr/local/bin with root-owned parent directories",
                path.display()
            );
        }
    }

    if let Some(home) = invoking_user_home {
        if path.starts_with(home) {
            anyhow::bail!(
                "refusing to install a launchd daemon that runs a binary from the invoking \
                 user's home directory ({}); place the wgd binary in a system location \
                 such as /usr/local/bin with root-owned parent directories",
                path.display()
            );
        }
    }

    Ok(())
}

pub fn dispatch(command: LaunchdCommand) -> anyhow::Result<()> {
    match command {
        LaunchdCommand::Install { plist_template } => cmd_install(plist_template),
        LaunchdCommand::Restart => cmd_restart(),
        LaunchdCommand::Reload(args) => {
            let config = config::load_config();
            let _command_scope = crate::privileged_client::CommandScopeGuard::begin(
                config.general.privileged_autostop_mode,
            );
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(crate::reload::run(args, &config))
        }
        LaunchdCommand::Uninstall => cmd_uninstall(),
        LaunchdCommand::Agent { command } => crate::session_agent::dispatch(command),
    }
}

fn cmd_install(plist_template: Option<PathBuf>) -> anyhow::Result<()> {
    require_root("install")?;

    // Validate everything that can refuse the install BEFORE mutating any
    // system state (group creation, membership, directories, plist).
    let user = invoking_user()?;
    let bin = install_time_binary_path()?;
    let bin_str = bin
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("wgd binary path is not valid UTF-8: {}", bin.display()))?;
    let template = match plist_template.as_deref() {
        Some(path) => fs::read_to_string(path)
            .with_context(|| format!("failed to read plist template {}", path.display()))?,
        None => PLIST_TEMPLATE.to_string(),
    };
    // Cheap fail-closed pre-check so a malformed template can't leave a
    // half-created group behind (render_plist_from re-checks below).
    anyhow::ensure!(
        template.contains(BIN_PLACEHOLDER),
        "plist template is missing the {BIN_PLACEHOLDER} placeholder"
    );
    anyhow::ensure!(
        template.lines().any(|l| l.contains(SOCK_GROUP_MARKER)),
        "plist template is missing the {SOCK_GROUP_MARKER} marker comment"
    );

    // --- system mutation begins here ---
    let (gid, member_added) = ensure_group_with_member(&user)?;
    ensure_directories(gid)?;
    register_authorization_right()?;
    let plist = render_plist_from(&template, bin_str, gid)?;
    write_plist(&plist)?;
    bootstrap()?;

    println!("wgd privileged daemon installed.");
    println!("  binary: {}", bin.display());
    println!("  plist:  {PLIST_PATH}");
    if let Some(path) = &plist_template {
        println!("  template: {}", path.display());
    }
    if member_added {
        println!(
            "Added {user} to the wgd group. If wgd reports permission denied when \
             connecting to the daemon, log out and back in for group membership to take effect."
        );
    }
    Ok(())
}

fn cmd_restart() -> anyhow::Result<()> {
    require_root("restart")?;
    // Re-run the same location validation as install, guarding against e.g.
    // `sudo ./target/debug/wgd launchd restart` restarting a daemon that
    // was installed from a different (system) location.
    let _ = daemon_binary_path()?;

    run_checked(
        "/bin/launchctl",
        &["kickstart", "-k", &format!("system/{LABEL}")],
    )
    .with_context(|| "daemon not installed? run: sudo wgd launchd install")?;

    println!("wgd privileged daemon restarted.");
    Ok(())
}

fn cmd_uninstall() -> anyhow::Result<()> {
    require_root("uninstall")?;

    // Bootout has no graceful shutdown path of its own (unlike the session
    // agent, the privileged daemon installs no SIGTERM handler), so any
    // tunnel still up at this point would be orphaned: its userspace helper,
    // routes, and DNS override left running with no socket left to reach
    // them through. Disconnect everything -- `Global` too, since this runs
    // as root -- while the daemon can still hear us.
    disconnect_all_connections();

    run_ignore_failure("/bin/launchctl", &["bootout", &format!("system/{LABEL}")]);
    // Parity with the old Makefile-based uninstall: leave the label
    // disabled. `cmd_install`'s `launchctl enable` clears this again on
    // reinstall.
    run_ignore_failure("/bin/launchctl", &["disable", &format!("system/{LABEL}")]);

    remove_file_ignore_missing(Path::new(PLIST_PATH))?;
    remove_file_ignore_missing(&config::privileged_socket_path())?;

    println!("wgd privileged daemon uninstalled.");
    println!("Intentionally kept (remove with `make purge/privileged` for a full removal):");
    println!("  the wgd binary");
    println!("  the wgd group");
    println!("  {}", config::root_log_dir().display());
    println!(
        "  the runtime directory ({})",
        config::privileged_socket_dir().display()
    );
    Ok(())
}

/// Disconnect every currently-connected stored connection, `Mine` and
/// `Global` alike, before the daemon that's the only thing able to stop
/// them goes away. Best-effort per connection, matching `connection
/// disconnect --all`: one stuck connection must not abort the rest of the
/// uninstall.
///
/// No autostart: a missing/refusing socket already means there is nothing
/// running to disconnect, and autostarting one here -- this command has no
/// `CommandScopeGuard` in scope to ask it to shut back down -- would leave
/// behind a daemon `launchctl bootout` below never touches (it was spawned
/// directly via `sudo`, not through launchd) and that runs forever under
/// the default `privileged_autostop_mode = Never`.
///
/// Runs the sweep twice: the daemon's own `reconcile_boot()` (see
/// `connection_store::reconcile_boot`) can race a *freshly spawned* daemon
/// reconnecting a `Global` `Automatic` record just after this lists it as
/// disconnected (only possible on the first daemon start of the boot, or
/// after a boot reconcile pass that had a failure -- `reconcile_boot` is a
/// no-op on every later spawn this boot). A second pass catches that without
/// needing to distinguish the rare case from the common one.
fn disconnect_all_connections() {
    for _ in 0..2 {
        disconnect_all_connections_once();
    }
}

fn disconnect_all_connections_once() {
    let client = PrivilegedClient::new().without_autostart();
    let connected = match client.list_connections(ConnectionScope::All) {
        Ok(connections) => connections.into_iter().filter(|conn| conn.connected),
        Err(error) => {
            eprintln!("Warning: failed to list connections before uninstall: {error:#}");
            return;
        }
    };
    for conn in connected {
        // Teardown ahead of an uninstall/reinstall, not the user asking this
        // tunnel to stay down -- a later `wgd launchd install` must still
        // bring an `Automatic` connection back up (see
        // `PrivilegedClient::disconnect_connection_for_teardown`'s doc
        // comment).
        match client.disconnect_connection_for_teardown(conn.id) {
            Ok(()) => println!("Disconnected {}", conn.id),
            Err(error) => eprintln!("Warning: failed to disconnect {}: {error:#}", conn.id),
        }
    }
}

/// Bail unless running as root, with a hint on how to re-invoke this command.
fn require_root(cmd_hint: &str) -> anyhow::Result<()> {
    if !geteuid().is_root() {
        anyhow::bail!("this command must run as root; try: sudo wgd launchd {cmd_hint}");
    }
    Ok(())
}

/// Home directory of the user who invoked `sudo`, if any. Used only by
/// `reject_unsafe_relocation_source` to catch a home directory that isn't
/// under the standard `/Users/` prefix its static denylist matches.
fn invoking_user_home() -> Option<PathBuf> {
    let user = std::env::var("SUDO_USER").ok()?;
    User::from_name(&user).ok().flatten().map(|u| u.dir)
}

/// UID of the user who invoked `sudo`, if any. Used only by
/// `require_owned_by_invoking_user_or_root` to trace a relocation source's
/// ownership back to the person who ran sudo, distinct from
/// `invoking_user_home`, which only feeds the path-prefix check.
fn invoking_user_uid() -> Option<Uid> {
    let user = std::env::var("SUDO_USER").ok()?;
    User::from_name(&user).ok().flatten().map(|u| u.uid)
}

/// The user who ran `sudo`, i.e. who should be added to the `wgd` group.
fn invoking_user() -> anyhow::Result<String> {
    match std::env::var("SUDO_USER") {
        Ok(user) if !user.is_empty() => Ok(user),
        _ => anyhow::bail!(
            "could not determine the invoking user (SUDO_USER is unset); run this via \
             `sudo wgd launchd install` from your normal account, or add yourself to the \
             wgd group manually with: sudo dseditgroup -o edit -a <user> -t user wgd"
        ),
    }
}

struct ResolvedBinary {
    invoked: PathBuf,
    resolved: PathBuf,
}

/// Resolve `current_exe()` and its symlink target, without validating either.
fn resolve_current_exe() -> anyhow::Result<ResolvedBinary> {
    let invoked =
        std::env::current_exe().context("failed to determine the running wgd binary path")?;
    let resolved = fs::canonicalize(&invoked)
        .with_context(|| format!("failed to resolve {}", invoked.display()))?;
    Ok(ResolvedBinary { invoked, resolved })
}

/// Validate the installed daemon and its parents before placing its path in a
/// root launchd job. The executable must be a regular file, not a Homebrew link.
fn daemon_binary_path() -> anyhow::Result<PathBuf> {
    let ResolvedBinary { invoked, resolved } = resolve_current_exe()?;
    validate_binary_location(&invoked, &resolved)?;
    crate::trusted_exec::validate_root_owned_path(
        &invoked,
        crate::trusted_exec::TrustedPath::Executable,
    )?;
    Ok(invoked)
}

/// Like `daemon_binary_path`, but used only by `cmd_install`: when the
/// running binary isn't already at a trusted, root-owned location (e.g. a
/// plain `brew install` or a Cask's `staged_path`, both admin/group-writable
/// and normally rejected by `validate_binary_location`), copy it into
/// `TRUSTED_BIN_PATH` first instead of failing, as long as it isn't coming
/// from a location that's always attacker-controlled (see
/// `RELOCATION_DENY_PREFIXES`). `cmd_restart`/`cmd_uninstall` keep using the
/// strict, non-relocating `daemon_binary_path` so a missing trusted copy
/// still fails loudly there instead of silently re-copying on every restart.
fn install_time_binary_path() -> anyhow::Result<PathBuf> {
    let ResolvedBinary { invoked, resolved } = resolve_current_exe()?;
    let already_trusted = validate_binary_location(&invoked, &resolved).is_ok()
        && crate::trusted_exec::validate_root_owned_path(
            &invoked,
            crate::trusted_exec::TrustedPath::Executable,
        )
        .is_ok();
    if already_trusted {
        return Ok(invoked);
    }
    relocate_to_trusted_path(&invoked, &resolved)
}

/// Copy `source` into `TRUSTED_BIN_PATH`, root:wheel 0755, atomically (temp
/// file + rename, mirroring `write_plist`). `install_time_binary_path` calls
/// this for a binary that isn't yet at a trusted location -- typically
/// Homebrew's admin/group-writable prefix -- so this copy is what lets a
/// root-run launchd job trust the binary afterward. It runs under the same
/// `sudo` gesture that already authorizes the rest of `launchd install`, the
/// same trust `sudo install ... /usr/local/bin/wgd` gave it by hand before
/// this existed.
fn relocate_to_trusted_path(invoked: &Path, resolved: &Path) -> anyhow::Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let home = invoking_user_home();
    // Still refuse sources that are always attacker-controlled, regardless
    // of the ownership check above having failed on them too.
    reject_unsafe_relocation_source(invoked, home.as_deref())?;
    reject_unsafe_relocation_source(resolved, home.as_deref())?;

    // The denylist above only rules out a fixed set of always-unsafe
    // locations; trace the source's actual ownership back to root or the
    // invoking user so an arbitrary writable directory outside that list
    // (e.g. one set up by a different, untrusted local user) isn't trusted
    // purely because its path isn't on the denylist.
    let invoking_uid = invoking_user_uid().ok_or_else(|| {
        anyhow::anyhow!(
            "could not determine the invoking user (SUDO_USER is unset); run this via \
             `sudo wgd launchd install` from your normal account"
        )
    })?;
    require_owned_by_invoking_user_or_root(invoked, invoking_uid)?;
    require_owned_by_invoking_user_or_root(resolved, invoking_uid)?;

    let source = resolved;

    let target = Path::new(TRUSTED_BIN_PATH);
    let target_dir = target
        .parent()
        .expect("TRUSTED_BIN_PATH has a parent directory");

    fs::create_dir_all(target_dir)
        .with_context(|| format!("failed to create {}", target_dir.display()))?;
    crate::trusted_exec::validate_root_owned_path(
        target_dir,
        crate::trusted_exec::TrustedPath::Directory,
    )
    .with_context(|| {
        format!(
            "cannot relocate the wgd binary into {}",
            target_dir.display()
        )
    })?;

    let tmp = PathBuf::from(format!("{TRUSTED_BIN_PATH}.tmp"));
    let relocate_result = (|| -> anyhow::Result<()> {
        fs::copy(source, &tmp)
            .with_context(|| format!("failed to copy {} to {}", source.display(), tmp.display()))?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("failed to chmod {}", tmp.display()))?;
        chown(&tmp, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))
            .with_context(|| format!("failed to chown {}", tmp.display()))?;
        fs::rename(&tmp, target)
            .with_context(|| format!("failed to install {}", target.display()))?;
        Ok(())
    })();

    if relocate_result.is_err() {
        // Best-effort cleanup; ignore errors.
        let _ = fs::remove_file(&tmp);
    }
    relocate_result?;

    crate::trusted_exec::validate_root_owned_path(
        target,
        crate::trusted_exec::TrustedPath::Executable,
    )
    .context("relocated wgd binary still failed the trusted-path check")?;

    println!(
        "Copied wgd to {TRUSTED_BIN_PATH} (root-owned; launchd daemons cannot run from \
         {} since it isn't root-owned).",
        source.display()
    );
    Ok(target.to_path_buf())
}

/// Ensure the `wgd` group exists and that `user` is a member, returning
/// its GID and whether membership was added during this install.
fn ensure_group_with_member(user: &str) -> anyhow::Result<(u32, bool)> {
    let read_ok = std::process::Command::new("/usr/sbin/dseditgroup")
        .args(["-o", "read", GROUP_NAME])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .with_context(|| "failed to run /usr/sbin/dseditgroup")?
        .success();
    if !read_ok {
        run_checked("/usr/sbin/dseditgroup", &["-o", "create", GROUP_NAME])?;
    }

    let already_member = std::process::Command::new("/usr/sbin/dseditgroup")
        .args(["-o", "checkmember", "-m", user, GROUP_NAME])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .with_context(|| "failed to check wgd group membership")?
        .success();
    if !already_member {
        run_checked(
            "/usr/sbin/dseditgroup",
            &["-o", "edit", "-a", user, "-t", "user", GROUP_NAME],
        )?;
    }

    Group::from_name(GROUP_NAME)
        .ok()
        .flatten()
        .map(|g| (g.gid.as_raw(), !already_member))
        .ok_or_else(|| anyhow::anyhow!("group {GROUP_NAME} not found after creation"))
}

/// Port of Makefile:23-27: create (or fix up) the log and runtime
/// directories with the permissions the privileged daemon expects.
fn ensure_directories(gid: u32) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let log_dir = config::root_log_dir();
    fs::create_dir_all(&log_dir)
        .with_context(|| format!("failed to create {}", log_dir.display()))?;
    fs::set_permissions(&log_dir, fs::Permissions::from_mode(0o755))
        .with_context(|| format!("failed to chmod {}", log_dir.display()))?;

    let sock_dir = config::privileged_socket_dir();
    fs::create_dir_all(&sock_dir)
        .with_context(|| format!("failed to create {}", sock_dir.display()))?;
    chown(&sock_dir, None, Some(Gid::from_raw(gid)))
        .with_context(|| format!("failed to chown {}", sock_dir.display()))?;
    fs::set_permissions(&sock_dir, fs::Permissions::from_mode(0o750))
        .with_context(|| format!("failed to chmod {}", sock_dir.display()))?;

    Ok(())
}

/// Register the custom authorization right the privileged daemon gates
/// configuration-changing connection operations behind (see
/// `privileged::authz`). A non-shared admin credential remains valid for
/// 60 seconds so the daemon can verify the client's authorization without
/// prompting again. The built-in `authenticate-admin` rule has timeout=0,
/// which forces authentication again during the daemon's verification.
/// Idempotent -- install and every privileged daemon startup write the same
/// bundled policy. Startup registration also upgrades existing installations
/// where the binary was replaced without re-running `launchd install`.
pub(crate) fn register_authorization_right() -> anyhow::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    anyhow::ensure!(
        nix::unistd::geteuid().is_root(),
        "registering the wgd authorization rule requires root; start the privileged service via launchd or sudo"
    );
    let mut child = Command::new("/usr/bin/security")
        .args([
            "authorizationdb",
            "write",
            crate::privileged::authz::RIGHT_NAME,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to run security authorizationdb write")?;
    let write_result = child
        .stdin
        .take()
        .expect("piped stdin")
        .write_all(include_bytes!(
            "../etc/me.pansen.wgd.modify-connection.plist"
        ));
    let output = child
        .wait_with_output()
        .context("failed to wait for security authorizationdb write")?;
    anyhow::ensure!(
        output.status.success(),
        "failed to register the {} authorization right ({}): {}",
        crate::privileged::authz::RIGHT_NAME,
        output.status,
        String::from_utf8_lossy(&output.stderr).trim()
    );
    write_result.context("failed to write the wgd authorization rule")
}

/// Write the rendered plist to `PLIST_PATH` atomically (temp file + rename)
/// with the ownership/permissions launchd expects of a system daemon plist.
fn write_plist(contents: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let tmp = PathBuf::from(format!("{PLIST_PATH}.tmp"));

    let write_result = (|| -> anyhow::Result<()> {
        fs::write(&tmp, contents).with_context(|| format!("failed to write {}", tmp.display()))?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))
            .with_context(|| format!("failed to chmod {}", tmp.display()))?;
        chown(&tmp, Some(Uid::from_raw(0)), Some(Gid::from_raw(0)))
            .with_context(|| format!("failed to chown {}", tmp.display()))?;
        fs::rename(&tmp, PLIST_PATH).with_context(|| format!("failed to install {PLIST_PATH}"))?;
        Ok(())
    })();

    if write_result.is_err() {
        // Best-effort cleanup; ignore errors.
        let _ = fs::remove_file(&tmp);
    }
    write_result
}

/// Port of Makefile:36-38 (order matters): drop any existing instance, clear
/// a stale "disabled" override, then bootstrap the plist.
fn bootstrap() -> anyhow::Result<()> {
    let target = format!("system/{LABEL}");

    // Not loaded yet is fine; ignore failure.
    run_ignore_failure("/bin/launchctl", &["bootout", &target]);
    // Clear any stale "disabled" override left over from a previous
    // uninstall — bootstrapping a disabled label fails with EIO.
    run_checked("/bin/launchctl", &["enable", &target])?;
    run_checked("/bin/launchctl", &["bootstrap", "system", PLIST_PATH])?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn require_root_errors_when_not_root() {
        // No-op under a root test runner (e.g. CI running as root); the
        // point of this test is the non-root case, which is how tests
        // normally run.
        if geteuid().is_root() {
            return;
        }
        let err = require_root("install").expect_err("must not be root");
        assert!(err.to_string().contains("sudo wgd launchd install"));
    }

    #[test]
    fn render_plist_substitutes_binary_and_gid() {
        let rendered = render_plist_from(PLIST_TEMPLATE, "/opt/homebrew/bin/wgd", 499)
            .expect("render succeeds");

        assert!(rendered.contains("<key>SockPathGroup</key>"));
        assert!(rendered.contains("<integer>499</integer>"));
        assert!(rendered.contains("/opt/homebrew/bin/wgd"));
        assert!(!rendered.contains(BIN_PLACEHOLDER));
        assert!(!rendered.contains("@SOCK_PATH_GROUP@"));
        assert!(rendered.contains("me.pansen.wgd.privileged"));
        assert!(rendered.contains("SockPathMode"));
    }

    #[test]
    fn render_plist_errors_when_bin_placeholder_missing() {
        let template = PLIST_TEMPLATE.replace(BIN_PLACEHOLDER, "/usr/local/bin/wgd");
        let err = render_plist_from(&template, "/opt/homebrew/bin/wgd", 499)
            .expect_err("missing bin placeholder should error");
        assert!(err.to_string().contains(BIN_PLACEHOLDER));
    }

    #[test]
    fn render_plist_errors_when_sock_group_marker_missing() {
        let template = PLIST_TEMPLATE.replace(SOCK_GROUP_MARKER, "");
        let err = render_plist_from(&template, "/opt/homebrew/bin/wgd", 499)
            .expect_err("missing marker should error");
        assert!(err.to_string().contains(SOCK_GROUP_MARKER));
    }

    #[test]
    fn render_rejects_template_without_label() {
        let modified = PLIST_TEMPLATE.replace(LABEL, "me.pansen.wgd.evil");
        let err = render_plist_from(&modified, "/usr/local/bin/wgd", 20)
            .expect_err("missing expected Label should error");
        assert!(err.to_string().contains("Label"));
    }

    #[test]
    fn render_escapes_binary_path() {
        let rendered =
            render_plist_from(PLIST_TEMPLATE, "/opt/t&t/bin/wgd", 20).expect("render succeeds");
        assert!(rendered.contains("/opt/t&amp;t/bin/wgd"));
        assert!(!rendered.contains("t&t/bin"));
    }

    #[test]
    fn rejects_user_home_directory() {
        assert!(validate_binary_location(
            Path::new("/Users/andi/p/wgd/target/release/wgd"),
            Path::new("/Users/andi/p/wgd/target/release/wgd"),
        )
        .is_err());
    }

    #[test]
    fn rejects_tmp() {
        assert!(validate_binary_location(Path::new("/tmp/wgd"), Path::new("/tmp/wgd")).is_err());
    }

    #[test]
    fn rejects_var_folders() {
        assert!(validate_binary_location(
            Path::new("/private/var/folders/xx/wgd"),
            Path::new("/private/var/folders/xx/wgd"),
        )
        .is_err());
    }

    #[test]
    fn rejects_var_tmp() {
        assert!(validate_binary_location(
            Path::new("/var/tmp/wgd"),
            Path::new("/private/var/tmp/wgd"),
        )
        .is_err());
    }

    #[test]
    fn rejects_relative_path() {
        assert!(validate_binary_location(Path::new("wgd"), Path::new("wgd")).is_err());
    }

    #[test]
    fn rejects_symlink_resolving_into_home_dir() {
        // Invoked path looks fine (/usr/local/bin), but the symlink target
        // resolves into a home directory build — must still be rejected.
        assert!(validate_binary_location(
            Path::new("/usr/local/bin/wgd"),
            Path::new("/Users/andi/target/release/wgd"),
        )
        .is_err());
    }

    #[test]
    fn rejects_custom_system_directory_outside_allow_list() {
        // Not a home directory or /tmp -- just some other system path that
        // isn't one of the fixed ALLOWED_BINARY_DIRS.
        assert!(validate_binary_location(
            Path::new("/opt/wgd/bin/wgd"),
            Path::new("/opt/wgd/bin/wgd"),
        )
        .is_err());
    }

    #[test]
    fn rejects_nested_subdirectory_of_an_allowed_dir() {
        // Allowed dirs hold binaries directly; a subdirectory underneath
        // one isn't itself an allowed location.
        assert!(validate_binary_location(
            Path::new("/usr/local/bin/extra/wgd"),
            Path::new("/usr/local/bin/extra/wgd"),
        )
        .is_err());
    }

    #[test]
    fn accepts_every_allowed_binary_dir() {
        for dir in ALLOWED_BINARY_DIRS {
            let path = Path::new(dir).join("wgd");
            assert!(
                validate_binary_location(&path, &path).is_ok(),
                "{} should be accepted",
                path.display()
            );
        }
    }

    #[test]
    fn rejects_homebrew_cellar_symlink_target() {
        assert!(validate_binary_location(
            Path::new("/opt/homebrew/bin/wgd"),
            Path::new("/opt/homebrew/Cellar/wgd/0.9.0/bin/wgd"),
        )
        .is_err());
    }

    #[test]
    fn relocation_source_check_allows_homebrew_but_not_user_controlled_locations() {
        // Homebrew's prefix (Apple Silicon here, but the point is that it's
        // not name-checked at all) is relocation-eligible...
        assert!(reject_unsafe_relocation_source(Path::new("/opt/homebrew/bin/wgd"), None).is_ok());
        // ...as is some other admin-writable, non-Homebrew prefix, since the
        // check no longer depends on matching Homebrew's literal path.
        assert!(reject_unsafe_relocation_source(Path::new("/opt/local/bin/wgd"), None).is_ok());
        // But genuinely user-controlled locations stay denied even for
        // relocation.
        assert!(reject_unsafe_relocation_source(Path::new("/Users/andi/wgd"), None).is_err());
        assert!(reject_unsafe_relocation_source(Path::new("/tmp/wgd"), None).is_err());
        assert!(
            reject_unsafe_relocation_source(Path::new("/private/var/folders/xx/wgd"), None,)
                .is_err()
        );
        assert!(reject_unsafe_relocation_source(
            Path::new("/opt/home/andi/wgd"),
            Some(Path::new("/opt/home/andi")),
        )
        .is_err());
    }

    #[test]
    fn ownership_check_accepts_files_owned_by_the_invoking_user() {
        let dir = std::env::temp_dir().join(format!("wgd-reloc-owner-ok-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("wgd");
        fs::write(&file, b"").unwrap();

        assert!(require_owned_by_invoking_user_or_root(&file, Uid::current()).is_ok());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ownership_check_rejects_a_source_owned_by_someone_else() {
        // Simulates the attack the relocation ownership check exists to
        // block: a source path that passes the static denylist (it isn't
        // /Users, /tmp, etc.) but is owned by neither root nor the user who
        // ran sudo -- e.g. another local user's files under an
        // admin-writable prefix such as /opt/local/bin.
        let dir = std::env::temp_dir().join(format!("wgd-reloc-owner-bad-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("wgd");
        fs::write(&file, b"").unwrap();

        let not_owner = Uid::from_raw(Uid::current().as_raw().wrapping_add(1));
        assert!(require_owned_by_invoking_user_or_root(&file, not_owner).is_err());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ownership_check_rejects_world_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("wgd-reloc-ww-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        let file = dir.join("wgd");
        fs::write(&file, b"").unwrap();

        assert!(require_owned_by_invoking_user_or_root(&file, Uid::current()).is_err());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ownership_check_accepts_a_symlink_owned_by_the_invoking_user() {
        // Mirrors Homebrew's own layout: `bin/wgd` is a symlink into the
        // Cellar. The symlink entry itself must still pass ownership, but
        // being a symlink at all must not be an automatic rejection.
        let dir = std::env::temp_dir().join(format!("wgd-reloc-symlink-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real-wgd");
        fs::write(&real, b"").unwrap();
        let link = dir.join("wgd");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        assert!(require_owned_by_invoking_user_or_root(&link, Uid::current()).is_ok());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ownership_check_rejects_a_symlink_owned_by_someone_else() {
        // The symlink entry's own ownership is still checked: an
        // attacker-owned symlink sitting in an otherwise-trusted directory
        // must not be trusted just because the directory around it is fine.
        let dir =
            std::env::temp_dir().join(format!("wgd-reloc-symlink-bad-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let real = dir.join("real-wgd");
        fs::write(&real, b"").unwrap();
        let link = dir.join("wgd");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let not_owner = Uid::from_raw(Uid::current().as_raw().wrapping_add(1));
        assert!(require_owned_by_invoking_user_or_root(&link, not_owner).is_err());

        fs::remove_dir_all(&dir).unwrap();
    }
}
