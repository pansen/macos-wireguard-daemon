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
use nix::sys::signal::{kill, Signal};
use nix::unistd::{chown, geteuid, Gid, Group, Pid, Uid, User};
use tracing::debug;

use crate::cli::LaunchdCommand;
use crate::config;
use crate::launchctl::{remove_file_ignore_missing, run_checked, run_ignore_failure, xml_escape};
use crate::privileged_api::{ConnectionScope, ConnectionStartMode, ConnectionSummary};
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
pub(crate) const TRUSTED_BIN_PATH: &str = "/usr/local/bin/wgd";

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
///
/// This is a lexical check, not a security boundary: the sudo gesture that
/// runs `launchd install` already executed the source binary as root, so at
/// best this is a foot-gun guard against an obviously wrong invocation
/// (`ownership`/writability is what `require_owned_by_invoking_user_or_root`
/// actually enforces). The `/System/Volumes/Data` entries below exist
/// because `fs::canonicalize` resolves through the data volume firmlink
/// without collapsing it back to the matching `/Users`, `/tmp`, or `/var`
/// path, so both spellings need listing for the guard to catch the same
/// locations either way.
const RELOCATION_DENY_PREFIXES: &[&str] = &[
    "/Users/",
    "/tmp/",
    "/private/tmp/",
    "/var/folders/",
    "/private/var/folders/",
    "/var/tmp/",
    "/private/var/tmp/",
    "/System/Volumes/Data/Users/",
    "/System/Volumes/Data/tmp/",
    "/System/Volumes/Data/private/tmp/",
    "/System/Volumes/Data/var/folders/",
    "/System/Volumes/Data/private/var/folders/",
    "/System/Volumes/Data/var/tmp/",
    "/System/Volumes/Data/private/var/tmp/",
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
        LaunchdCommand::Status {
            caller_in_wgd_group,
        } => cmd_status(caller_in_wgd_group),
        LaunchdCommand::Purge => cmd_purge(),
        LaunchdCommand::Agent { command } => crate::session_agent::dispatch(command),
    }
}

fn cmd_install(plist_template: Option<PathBuf>) -> anyhow::Result<()> {
    require_root("install")?;

    // Validate everything that can refuse the install BEFORE mutating any
    // system state (binary relocation, group creation, membership,
    // directories, plist). A bad --plist-template must abort before
    // install_time_binary_path() below ever touches /usr/local/bin/wgd.
    let user = invoking_user()?;
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
    let bin = install_time_binary_path()?;
    let bin_str = bin
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("wgd binary path is not valid UTF-8: {}", bin.display()))?;
    let (gid, member_added) = ensure_group_with_member(&user)?;
    ensure_directories(gid)?;
    register_authorization_right()?;
    let plist = render_plist_from(&template, bin_str, gid)?;
    write_plist(&plist)?;
    bootstrap()?;
    reap_stray_privileged_daemons();
    wait_for_launchd_socket();
    reconnect_automatic_connections(&bin);

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

    uninstall_daemon_core()?;

    println!("wgd privileged daemon uninstalled.");
    println!("Intentionally kept (this only unregisters the daemon):");
    println!("  the wgd binary");
    println!("  the wgd group");
    println!("  {}", config::root_log_dir().display());
    println!(
        "  the runtime directory ({})",
        config::privileged_socket_dir().display()
    );
    println!(
        "For a full removal: `brew uninstall --zap macos-wireguard-daemon` (Homebrew installs) \
         or `wgd launchd purge` (installs from source)."
    );
    Ok(())
}

/// Core teardown shared by `wgd launchd uninstall` and `wgd launchd purge`:
/// disconnect active tunnels, drop the DNS custody watch sentinel, bootout and
/// disable the launchd job, reap any stray daemon processes, and unlink the
/// plist and control socket.
fn uninstall_daemon_core() -> anyhow::Result<()> {
    // Bootout has no graceful shutdown path of its own (unlike the session
    // agent, the privileged daemon installs no SIGTERM handler), so any
    // tunnel still up at this point would be orphaned: its userspace helper,
    // routes, and DNS override left running with no socket left to reach
    // them through. Disconnect everything -- `Global` too, since this runs
    // as root -- while the daemon can still hear us.
    disconnect_all_connections();

    // The plist keeps the daemon alive while this sentinel exists (DNS crash
    // recovery); drop it first so launchd does not race the bootout below.
    // Pending records stay for `wgd dns repair`.
    remove_file_ignore_missing(&config::dns_custody_watch_path())?;
    run_ignore_failure("/bin/launchctl", &["bootout", &format!("system/{LABEL}")]);
    // Parity with the old Makefile-based uninstall: leave the label
    // disabled. `cmd_install`'s `launchctl enable` clears this again on
    // reinstall.
    run_ignore_failure("/bin/launchctl", &["disable", &format!("system/{LABEL}")]);
    reap_stray_privileged_daemons();

    remove_file_ignore_missing(Path::new(PLIST_PATH))?;
    remove_file_ignore_missing(&config::privileged_socket_path())?;
    Ok(())
}

fn cmd_status(caller_in_wgd_group: Option<bool>) -> anyhow::Result<()> {
    if !geteuid().is_root() {
        let in_group = caller_has_wgd_gid_in_process();
        if let Err(e) = escalate_launchd_status(in_group) {
            tracing::warn!(error = %format!("{e:#}"), "launchd_status_escalation_failed");
            eprintln!("sudo unavailable or declined; running the unprivileged checks only");
            let report = collect_status_report(Some(in_group));
            print!("{report}");
        }
        return Ok(());
    }

    let report = collect_status_report(caller_in_wgd_group);
    print!("{report}");
    Ok(())
}

fn cmd_purge() -> anyhow::Result<()> {
    if !geteuid().is_root() {
        return escalate_launchd_purge();
    }

    // 1. Unload and remove the invoking user's session agent plist if known,
    //    then terminate any remaining `wgd launchd agent run` processes.
    purge_invoking_user_session_agent();
    reap_session_agent_processes();

    // 2. Disconnect all connections and unregister the privileged daemon.
    uninstall_daemon_core()?;

    // 3. Restore any DNS left behind by dead helpers before deleting the
    //    runtime directory that holds `dns-custody/`.
    crate::privileged::sweep_dns_for_purge();

    // 4. Remove runtime state, logs, authorization rule, and the `wgd` group.
    remove_dir_all_ignore_missing(&config::privileged_runtime_dir())?;
    remove_dir_all_ignore_missing(&config::root_log_dir())?;
    run_ignore_failure(
        "/usr/bin/security",
        &[
            "authorizationdb",
            "remove",
            crate::privileged::authz::RIGHT_NAME,
        ],
    );
    run_ignore_failure("/usr/sbin/dseditgroup", &["-o", "delete", GROUP_NAME]);

    println!("wgd purged:");
    println!("  unregistered daemon and session agent");
    println!("  removed {}", config::privileged_runtime_dir().display());
    println!("  removed {}", config::root_log_dir().display());
    println!("  deleted group {GROUP_NAME}");
    println!("  kept the wgd binary (use `brew uninstall --zap` or remove the binary manually if desired)");
    let invoking_home = resolve_target_user().map(|(_, _, home)| home);
    let leftovers = other_users_session_agent_plists(Path::new("/Users"), invoking_home.as_deref());
    if !leftovers.is_empty() {
        println!("Session agents of other users are still registered and start again at their next login:");
        for plist in leftovers {
            println!("  {}", plist.display());
        }
        println!(
            "  each user can remove theirs with: launchctl bootout gui/$(id -u)/{}; rm <plist>",
            crate::session_agent::LABEL
        );
    }
    Ok(())
}

/// Session-agent plists under `users_dir/*/Library/LaunchAgents` except the
/// invoking user's, which `purge` already removed. Only the invoking user's
/// agent can be booted out from here (`gui/<uid>` of a user without a GUI
/// session may not exist), so the rest are reported rather than deleted.
fn other_users_session_agent_plists(users_dir: &Path, skip_home: Option<&Path>) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(users_dir) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|home| Some(home.as_path()) != skip_home)
        .map(|home| {
            home.join("Library/LaunchAgents")
                .join(format!("{}.plist", crate::session_agent::LABEL))
        })
        .filter(|plist| plist.exists())
        .collect();
    out.sort();
    out
}

fn remove_dir_all_ignore_missing(path: &Path) -> anyhow::Result<()> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", path.display())),
    }
}

fn purge_invoking_user_session_agent() {
    if let Some((_user, uid, home)) = resolve_target_user() {
        if uid != 0 {
            run_ignore_failure(
                "/bin/launchctl",
                &[
                    "bootout",
                    &format!("gui/{uid}/{}", crate::session_agent::LABEL),
                ],
            );
            let plist = home
                .join("Library/LaunchAgents")
                .join(format!("{}.plist", crate::session_agent::LABEL));
            let _ = remove_file_ignore_missing(&plist);
        }
    }
}

fn reap_session_agent_processes() {
    for pid in find_session_agent_pids() {
        debug!(pid, "reaping_session_agent_process");
        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
    }
}

fn escalate_launchd_status(caller_in_wgd_group: bool) -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("failed to determine the running wgd binary path")?;
    let mut cmd = std::process::Command::new("sudo");
    cmd.arg(&exe);
    if crate::logging::debug_enabled() {
        cmd.arg("--debug");
    }
    cmd.args([
        "launchd",
        "status",
        &format!("--caller-in-wgd-group={caller_in_wgd_group}"),
    ]);
    tracing::warn!(
        action = "launchd_status",
        method = "sudo",
        cause = "inspecting system launchd state and root-owned runtime paths requires root",
        "admin_authentication_requested"
    );
    let status = cmd
        .status()
        .context("failed to run sudo for wgd launchd status")?;
    anyhow::ensure!(
        status.success(),
        "sudo wgd launchd status failed ({status})"
    );
    Ok(())
}

fn escalate_launchd_purge() -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("failed to determine the running wgd binary path")?;
    let mut cmd = std::process::Command::new("sudo");
    cmd.arg(&exe);
    if crate::logging::debug_enabled() {
        cmd.arg("--debug");
    }
    cmd.args(["launchd", "purge"]);
    tracing::warn!(
        action = "launchd_purge",
        method = "sudo",
        cause = "purging the system launchd daemon, runtime directories, logs, and wgd group requires root",
        "admin_authentication_requested"
    );
    let status = cmd
        .status()
        .context("failed to run sudo for wgd launchd purge")?;
    anyhow::ensure!(status.success(), "sudo wgd launchd purge failed ({status})");
    Ok(())
}

/// Whether the current (unprivileged) process has the `wgd` group's GID active
/// in its supplementary or effective group list. Captured before escalating
/// via `sudo` so `launchd status` and `doctor` can tell a user whether their
/// current login session already picked up `wgd` membership.
pub(crate) fn caller_has_wgd_gid_in_process() -> bool {
    let Some(wgd_gid) = Group::from_name(GROUP_NAME).ok().flatten().map(|g| g.gid) else {
        return false;
    };
    if nix::unistd::getegid() == wgd_gid {
        return true;
    }
    process_groups().contains(&wgd_gid.as_raw())
}

/// The process's credential groups. `nix::unistd::getgroups` is configured
/// out on Apple targets, so this calls libc directly. On macOS this is the
/// group list the login session was started with (at most `NGROUPS_MAX`,
/// 16), which is exactly what tells whether a re-login is still pending.
fn process_groups() -> Vec<nix::libc::gid_t> {
    // SAFETY: a zero-sized call only returns the count; the second call
    // writes at most `buf.len()` entries into `buf`.
    unsafe {
        let count = nix::libc::getgroups(0, std::ptr::null_mut());
        if count <= 0 {
            return Vec::new();
        }
        let mut buf = vec![0 as nix::libc::gid_t; count as usize];
        let written = nix::libc::getgroups(count, buf.as_mut_ptr());
        if written < 0 {
            return Vec::new();
        }
        buf.truncate(written as usize);
        buf
    }
}

/// Build the full human-readable `wgd launchd status` report. Shared by
/// `wgd launchd status` and `wgd doctor`.
pub(crate) fn collect_status_report(caller_in_wgd_group: Option<bool>) -> String {
    use std::fmt::Write;

    let mut out = String::new();

    // 1. Privileged daemon state in launchd.
    let _ = writeln!(
        out,
        "==> daemon (expect: state = not running unless a DNS tunnel is up, sockets registered)"
    );
    // `launchctl print system/...` works without root; only the custody
    // watch note does not, because `dns-custody/` is 0700 root and
    // `exists()` would just report false there.
    match std::process::Command::new("/bin/launchctl")
        .args(["print", &format!("system/{LABEL}")])
        .output()
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in extract_launchd_daemon_lines(&stdout) {
                let _ = writeln!(out, "  {line}");
            }
        }
        Ok(output) => {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            let _ = writeln!(
                out,
                "  not loaded ({}; run: wgd launchd reload)",
                if stderr.is_empty() {
                    output.status.to_string()
                } else {
                    stderr
                }
            );
        }
        Err(err) => {
            let _ = writeln!(out, "  failed to run /bin/launchctl: {err}");
        }
    }
    if !geteuid().is_root() {
        let _ = writeln!(out, "  DNS custody watch: skipped (needs sudo)");
    } else if config::dns_custody_watch_path().exists() {
        let _ = writeln!(
            out,
            "  note: {} is present (DNS custody KeepAlive active)",
            config::dns_custody_watch_path().display()
        );
    }

    // 2. Control socket & socket directory expected-vs-actual permission checks.
    let wgd_group = Group::from_name(GROUP_NAME).ok().flatten();
    let wgd_gid = wgd_group.as_ref().map(|g| g.gid.as_raw());

    let _ = writeln!(out, "==> socket (expect: srw-rw---- root:{GROUP_NAME})");
    let _ = writeln!(
        out,
        "  {}",
        check_path_permissions(
            &config::privileged_socket_path(),
            ExpectedFileType::Socket,
            0o660,
            wgd_gid,
        )
    );

    let _ = writeln!(out, "==> socket dir (expect: drwxr-x--- root:{GROUP_NAME})");
    let _ = writeln!(
        out,
        "  {}",
        check_path_permissions(
            &config::privileged_socket_dir(),
            ExpectedFileType::Directory,
            0o750,
            wgd_gid,
        )
    );

    // 3. `wgd` group membership for the invoking user.
    let _ = writeln!(out, "==> group membership (expect: {GROUP_NAME} listed)");
    let _ = writeln!(
        out,
        "  {}",
        check_group_membership(wgd_gid, caller_in_wgd_group)
    );

    // 4. Session agent status for the invoking user.
    let _ = writeln!(out, "==> session agent");
    let _ = writeln!(out, "  {}", check_session_agent_status());

    // 5. Running wgd processes (daemon, userspace helpers, session agent).
    let _ = writeln!(out, "==> processes");
    for line in collect_wgd_process_lines() {
        let _ = writeln!(out, "  {line}");
    }

    out
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedFileType {
    Socket,
    Directory,
}

impl ExpectedFileType {
    fn type_char(self) -> char {
        match self {
            Self::Socket => 's',
            Self::Directory => 'd',
        }
    }
}

fn check_path_permissions(
    path: &Path,
    expected_kind: ExpectedFileType,
    expected_mode: u32,
    expected_gid: Option<u32>,
) -> String {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let expected_symbolic = format_symbolic_mode(expected_kind.type_char(), expected_mode);
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return format!(
                "MISSING  {} (expected {expected_symbolic} root:{GROUP_NAME})",
                path.display()
            );
        }
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied && !geteuid().is_root() => {
            return format!("skipped (needs sudo)  {}", path.display());
        }
        Err(err) => {
            return format!("ERROR  {}: {err}", path.display());
        }
    };

    let ft = meta.file_type();
    let actual_type_char = if ft.is_socket() {
        's'
    } else if ft.is_dir() {
        'd'
    } else if ft.is_symlink() {
        'l'
    } else if ft.is_file() {
        '-'
    } else {
        '?'
    };
    let actual_mode = meta.mode() & 0o7777;
    let actual_symbolic = format_symbolic_mode(actual_type_char, actual_mode);
    let uid = meta.uid();
    let gid = meta.gid();
    let owner_name = User::from_uid(Uid::from_raw(uid))
        .ok()
        .flatten()
        .map(|u| u.name)
        .unwrap_or_else(|| uid.to_string());
    let group_name = Group::from_gid(Gid::from_raw(gid))
        .ok()
        .flatten()
        .map(|g| g.name)
        .unwrap_or_else(|| gid.to_string());

    let matches_expected = actual_type_char == expected_kind.type_char()
        && actual_mode == expected_mode
        && uid == 0
        && expected_gid.is_some_and(|want_gid| gid == want_gid);

    if matches_expected {
        format!(
            "ok  {actual_symbolic}  {owner_name}:{group_name}  {}",
            path.display()
        )
    } else {
        format!(
            "MISMATCH  {actual_symbolic}  {owner_name}:{group_name}  {} (expected {expected_symbolic} root:{GROUP_NAME})",
            path.display()
        )
    }
}

fn format_symbolic_mode(type_char: char, mode: u32) -> String {
    let mut s = String::with_capacity(10);
    s.push(type_char);
    for (shift, set_bit, set_char, set_upper) in [
        (6, 0o4000, 's', 'S'),
        (3, 0o2000, 's', 'S'),
        (0, 0o1000, 't', 'T'),
    ] {
        let triad = (mode >> shift) & 0o7;
        s.push(if triad & 0o4 != 0 { 'r' } else { '-' });
        s.push(if triad & 0o2 != 0 { 'w' } else { '-' });
        let exec = triad & 0o1 != 0;
        let special = mode & set_bit != 0;
        s.push(match (exec, special) {
            (true, true) => set_char,
            (false, true) => set_upper,
            (true, false) => 'x',
            (false, false) => '-',
        });
    }
    s
}

/// Pick the service's own fields out of `launchctl print`. Only top-level
/// keys (one tab deep) count: nested blocks such as the resource and jetsam
/// coalitions carry their own `state = active` lines that say nothing about
/// the daemon.
fn extract_launchd_daemon_lines(print_output: &str) -> Vec<String> {
    const TOP_LEVEL_KEYS: &[&str] = &[
        "state =",
        "pid =",
        "runs =",
        "last exit code =",
        "immediate reason =",
    ];
    let mut out = Vec::new();
    for line in print_output.lines() {
        let trimmed = line.trim();
        let top_level = line.starts_with('\t') && !line.starts_with("\t\t");
        if (top_level && TOP_LEVEL_KEYS.iter().any(|key| trimmed.starts_with(key)))
            || trimmed.starts_with("\"Listeners\"")
            || trimmed.contains("ctl.sock")
        {
            out.push(trimmed.to_string());
        }
    }
    out
}

/// Resolve the invoking user `(username, uid, home_dir)`: prefers `SUDO_USER`
/// when running under `sudo`, falling back to the current process's real UID.
pub(crate) fn resolve_target_user() -> Option<(String, u32, PathBuf)> {
    if let Ok(sudo_user) = std::env::var("SUDO_USER") {
        if !sudo_user.is_empty() && sudo_user != "root" {
            if let Ok(Some(u)) = User::from_name(&sudo_user) {
                return Some((u.name, u.uid.as_raw(), u.dir));
            }
        }
    }
    let uid = nix::unistd::getuid();
    User::from_uid(uid)
        .ok()
        .flatten()
        .map(|u| (u.name, u.uid.as_raw(), u.dir))
}

fn check_group_membership(wgd_gid: Option<u32>, caller_in_wgd_group: Option<bool>) -> String {
    let Some(gid) = wgd_gid else {
        return format!("MISSING  group '{GROUP_NAME}' does not exist (run: wgd launchd reload)");
    };
    let Some((user, _uid, _home)) = resolve_target_user() else {
        return "unable to determine invoking user".to_string();
    };

    let in_ds = std::process::Command::new("/usr/sbin/dseditgroup")
        .args(["-o", "checkmember", "-m", &user, GROUP_NAME])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    // A direct `sudo wgd launchd status` has no `--caller-in-wgd-group`, and
    // root's own groups say nothing about the caller's shell, so whether a
    // re-login is still pending cannot be told here.
    let Some(in_session) = caller_in_wgd_group else {
        return if in_ds {
            format!(
                "ok  {user} is in {GROUP_NAME} group (gid {gid}); whether the current shell has it active is unknown under sudo (run without sudo to check)"
            )
        } else {
            format!("not in {GROUP_NAME} group — run `wgd launchd reload` and re-login")
        };
    };
    match (in_session, in_ds) {
        (true, _) => format!("ok  {user} is in {GROUP_NAME} group (gid {gid})"),
        (false, true) => format!(
            "WARN  {user} is in {GROUP_NAME} group (gid {gid}), but not active in current shell — re-login required"
        ),
        (false, false) => format!(
            "not in {GROUP_NAME} group — run `wgd launchd reload` and re-login"
        ),
    }
}

fn check_session_agent_status() -> String {
    let Some((user, uid, home)) = resolve_target_user() else {
        return "unable to determine invoking user".to_string();
    };
    let plist = home
        .join("Library/LaunchAgents")
        .join(format!("{}.plist", crate::session_agent::LABEL));
    let state = crate::session_agent::agent_state(uid, &home);
    // Which connections depend on the agent. If the daemon cannot be asked,
    // the missing agent stays informational.
    let dependents: Vec<String> = PrivilegedClient::new()
        .without_autostart()
        .list_connections(ConnectionScope::All)
        .map(|all| {
            crate::session_agent::agent_dependents(&all, uid)
                .iter()
                .map(|conn| conn.label())
                .collect()
        })
        .unwrap_or_default();
    format_session_agent_status(state, &user, uid, &plist, &dependents)
}

/// The doctor line for the session agent. With per-user `Automatic`
/// connections (`dependents`) a state other than `Loaded` is a `FAIL`;
/// without any it is just informational.
fn format_session_agent_status(
    state: crate::session_agent::AgentState,
    user: &str,
    uid: u32,
    plist: &Path,
    dependents: &[String],
) -> String {
    use crate::session_agent::AgentState;
    let label = crate::session_agent::LABEL;
    if state != AgentState::Loaded && !dependents.is_empty() {
        return format!(
            "FAIL  {}",
            crate::session_agent::agent_problem_message(state, dependents)
        );
    }
    match state {
        AgentState::Loaded => format!("loaded (gui/{uid}/{label})  {}", plist.display()),
        AgentState::NotInstalled => {
            format!("not installed for {user} ({} missing)", plist.display())
        }
        AgentState::Disabled => format!(
            "disabled for {user} (gui/{uid}/{label})  {} ({})",
            plist.display(),
            state.fix()
        ),
        AgentState::NotLoaded => format!(
            "not loaded (gui/{uid}/{label})  {} ({})",
            plist.display(),
            state.fix()
        ),
    }
}

fn collect_wgd_process_lines() -> Vec<String> {
    let output = match std::process::Command::new("/bin/ps")
        .args(["-axo", "pid=,uid=,user=,args="])
        .output()
    {
        Ok(out) if out.status.success() => out,
        _ => return vec!["failed to run /bin/ps".to_string()],
    };
    let lines =
        filter_wgd_process_lines(&String::from_utf8_lossy(&output.stdout), std::process::id());
    if lines.is_empty() {
        vec!["none running".to_string()]
    } else {
        lines
    }
}

fn filter_wgd_process_lines(ps_output: &str, self_pid: u32) -> Vec<String> {
    ps_output
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let (pid_str, rest) = trimmed.split_once(char::is_whitespace)?;
            let pid = pid_str.parse::<u32>().ok()?;
            if pid == self_pid {
                return None;
            }
            let (_uid_str, rest) = rest.trim_start().split_once(char::is_whitespace)?;
            let (user, args) = rest.trim_start().split_once(char::is_whitespace)?;
            let args = args.trim_start();
            let argv0 = args.split_whitespace().next()?;
            let is_wgd = Path::new(argv0).file_name() == Some("wgd".as_ref());
            if !is_wgd {
                return None;
            }
            // Skip transient diagnostic invocations (`wgd doctor`, `wgd launchd status`).
            let tokens: Vec<&str> = args.split_whitespace().collect();
            if tokens.contains(&"doctor")
                || (tokens.contains(&"launchd") && tokens.contains(&"status"))
            {
                return None;
            }
            Some(format!("pid={pid:<6} user={user:<10} {args}"))
        })
        .collect()
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
            Ok(()) => println!("Disconnected {}", conn.label()),
            Err(error) => eprintln!("Warning: failed to disconnect {}: {error:#}", conn.label()),
        }
    }
}

/// Bring `Automatic` connections back up after the daemon was (re)registered.
///
/// An upgrade runs the old version's `launchd uninstall` first, which tears
/// every tunnel down (`disconnect_all_connections`) without marking it
/// `user_disconnected`. Nothing else would reconnect them afterwards: the
/// session agent only reconciles when it starts (it keeps running across the
/// upgrade), and the daemon's own `reconcile_boot` runs once per boot.
/// Restarting the agent instead would make its SIGTERM teardown drop any
/// tunnel that is still up, so this connects the candidates directly, as
/// reconciliation (an explicit disconnect still wins).
///
/// Best-effort per connection, like the uninstall sweep. No autostart: the
/// socket was just confirmed reachable, and a missing daemon here must not
/// leave an ad hoc one behind.
fn reconnect_automatic_connections(bin: &Path) {
    let client = PrivilegedClient::new().without_autostart();
    let connections = match client.list_connections(ConnectionScope::All) {
        Ok(connections) => connections,
        Err(error) => {
            eprintln!("Warning: failed to list connections after install: {error:#}");
            return;
        }
    };
    // Per-user connections belong to a GUI session: only bring them up for
    // the user running the install, and only while their session agent is
    // loaded (it tears them down again at logout). A missing agent is
    // installed first, so a reboot does not leave their `Automatic`
    // connections down.
    let session = invoking_user_uid().map(|uid| {
        let agent_started = ensure_invoking_user_agent(bin, &connections);
        InstallSession {
            uid: uid.as_raw(),
            agent_loaded: agent_started || crate::session_agent::is_loaded(uid.as_raw()),
            agent_started,
        }
    });
    for conn in &connections {
        match post_install_action(conn, session) {
            PostInstallAction::Ignore => {}
            // Said out loud: a tunnel that silently stays down after an
            // upgrade is indistinguishable from this step not running at all.
            PostInstallAction::Skip(reason) => {
                println!("Not reconnecting {}: {reason}", conn.label());
            }
            PostInstallAction::Reconnect => {
                match client.connect_connection_for_reconciliation(conn.id, false) {
                    Ok(()) => println!("Reconnected {}", conn.label()),
                    Err(error) => {
                        eprintln!("Warning: failed to reconnect {}: {error:#}", conn.label());
                    }
                }
            }
        }
    }
}

/// The user who ran the install via `sudo`, as seen by
/// `reconnect_automatic_connections`.
#[derive(Clone, Copy)]
struct InstallSession {
    uid: u32,
    agent_loaded: bool,
    /// The agent was installed by this very install run.
    agent_started: bool,
}

/// Install the invoking user's session agent when one of their per-user
/// `Automatic` connections needs it and it is missing or not loaded. Returns
/// whether it started a fresh agent.
///
/// Root cannot run `launchd agent install` itself (it refuses root, and the
/// plist must belong to the user and be bootstrapped into their `gui/<uid>`
/// domain). So the same command is spawned as the user:
/// `launchctl asuser <uid>` enters their session's bootstrap namespace and
/// `sudo -u <user> -H` drops privileges and sets `$HOME`, which lets the
/// existing user-side install do all the work. A `Disabled` agent is only
/// reported, since the user may have switched it off on purpose. Failures
/// are loud but do not fail the daemon install.
fn ensure_invoking_user_agent(bin: &Path, connections: &[ConnectionSummary]) -> bool {
    use crate::session_agent::{
        agent_dependents, agent_problem_message, agent_state, plan_for, AgentPlan,
    };
    let Some((user, uid, home)) = resolve_target_user().filter(|(_, uid, _)| *uid != 0) else {
        return false;
    };
    let names: Vec<String> = agent_dependents(connections, uid)
        .iter()
        .map(|conn| conn.label())
        .collect();
    if names.is_empty() {
        return false;
    }
    let state = agent_state(uid, &home);
    let warn = |detail: &str| {
        eprintln!(
            "{}",
            crate::ui::warning(&format!(
                "Warning: {detail}{}",
                agent_problem_message(state, &names)
            ))
        );
    };
    match plan_for(state, true) {
        AgentPlan::Nothing => false,
        AgentPlan::Warn => {
            warn("");
            false
        }
        AgentPlan::Install => {
            let uid_arg = uid.to_string();
            let bin_arg = bin.to_string_lossy();
            let result = run_checked(
                "/bin/launchctl",
                &[
                    "asuser",
                    &uid_arg,
                    "/usr/bin/sudo",
                    "-u",
                    &user,
                    "-H",
                    &bin_arg,
                    "launchd",
                    "agent",
                    "install",
                    "--force",
                ],
            );
            match result {
                Ok(()) => {
                    println!(
                        "Installed the session agent for {user} (was {}): it brings up {} at login.",
                        state.describe(),
                        names.join(", ")
                    );
                    true
                }
                Err(error) => {
                    warn(&format!(
                        "could not install the session agent for {user} ({error:#}); "
                    ));
                    false
                }
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum PostInstallAction {
    /// Not an `Automatic` connection that is down; nothing to explain.
    Ignore,
    /// Down although `Automatic`, and deliberately left down for this reason.
    Skip(String),
    Reconnect,
}

/// What `reconnect_automatic_connections` does with `conn`: bring up every
/// `Automatic` connection that is down, unless it was explicitly
/// disconnected or is a per-user connection without a matching GUI session.
fn post_install_action(
    conn: &ConnectionSummary,
    session: Option<InstallSession>,
) -> PostInstallAction {
    if conn.start_mode != ConnectionStartMode::Automatic || conn.connected {
        return PostInstallAction::Ignore;
    }
    if conn.user_disconnected {
        return PostInstallAction::Skip(
            "explicitly disconnected; `wgd connection connect` brings it back".into(),
        );
    }
    if conn.global {
        return PostInstallAction::Reconnect;
    }
    let owner = conn
        .owner_uid
        .map_or_else(|| "-".to_string(), |uid| uid.to_string());
    match session {
        None => PostInstallAction::Skip(format!(
            "owned by uid {owner}, but the install did not run via sudo from a user session"
        )),
        Some(session) if conn.owner_uid != Some(session.uid) => PostInstallAction::Skip(format!(
            "owned by uid {owner}; its session agent reconnects it at that user's next login"
        )),
        Some(session) if !session.agent_loaded => PostInstallAction::Skip(format!(
            "session agent for uid {owner} is not loaded (install it with `wgd launchd agent install`)"
        )),
        // The fresh agent reconciles on start and connects this itself;
        // connecting it here too would race that for the same connection.
        Some(session) if session.agent_started => PostInstallAction::Skip(
            "the session agent was just installed and connects it itself".into(),
        ),
        Some(_) => PostInstallAction::Reconnect,
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
/// `RELOCATION_DENY_PREFIXES`). `cmd_restart` keeps using the strict,
/// non-relocating `daemon_binary_path` so a missing trusted copy still fails
/// loudly there instead of silently re-copying on every restart;
/// `cmd_uninstall` doesn't resolve the binary at all, since removing the
/// launchd registration doesn't need to know where it lives.
fn install_time_binary_path() -> anyhow::Result<PathBuf> {
    let ResolvedBinary { invoked, resolved } = resolve_current_exe()?;
    let location_valid = validate_binary_location(&invoked, &resolved).is_ok();
    let root_owned = location_valid
        && crate::trusted_exec::validate_root_owned_path(
            &invoked,
            crate::trusted_exec::TrustedPath::Executable,
        )
        .is_ok();
    if !should_relocate(location_valid, root_owned) {
        return Ok(invoked);
    }
    relocate_to_trusted_path(&invoked, &resolved)
}

/// Whether `install_time_binary_path` must relocate the running binary
/// before trusting it. Split out from the two filesystem checks that feed
/// it so the decision itself is coverable by a plain unit test: the checks
/// need real (and, for `root_owned`, often root-owned) files on disk to
/// exercise, which a normal, non-root test run can't set up.
fn should_relocate(location_valid: bool, root_owned: bool) -> bool {
    !(location_valid && root_owned)
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
        // Homebrew propagates the com.apple.quarantine xattr from the cask
        // download onto every staged file, and fs::copy's clonefile fast
        // path (same-volume copies) preserves xattrs, so it would otherwise
        // carry over into this root-owned copy and have Gatekeeper block
        // every later launchd restart of it. Best-effort: builds from
        // source, or an already-unquarantined source, simply don't have the
        // attribute to remove.
        strip_quarantine_attribute(&tmp);
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

/// Remove the `com.apple.quarantine` extended attribute from `path`, if
/// present. Best-effort: `/usr/bin/xattr -d` exits non-zero when the
/// attribute is already absent, which is the common case for a from-source
/// build and isn't an error worth failing the install over.
fn strip_quarantine_attribute(path: &Path) {
    let _ = std::process::Command::new("/usr/bin/xattr")
        .arg("-d")
        .arg("com.apple.quarantine")
        .arg(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
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

/// Block until launchd accepts connections on the control socket again.
///
/// `launchctl bootstrap` returns before launchd has set up the job's
/// `Sockets`: for a few hundred milliseconds afterwards the previous socket
/// file is still on disk with nothing listening, so connects fail with
/// `ECONNREFUSED`. A client in that window (e.g. `wgd launchd reload`'s very
/// next step) would otherwise read the daemon as down. Connecting makes
/// launchd spawn the daemon on demand, which then idles out as usual.
/// Best-effort: a socket that never shows up is reported, not fatal, since
/// the plist is already installed and `launchd restart` can recover it.
fn wait_for_launchd_socket() {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
    let socket_path = config::privileged_socket_path();
    let deadline = std::time::Instant::now() + TIMEOUT;
    loop {
        match std::os::unix::net::UnixStream::connect(&socket_path) {
            Ok(_) => return,
            Err(error) if std::time::Instant::now() >= deadline => {
                eprintln!(
                    "Warning: launchd socket {} not reachable after {}s: {error}; \
                     try: sudo {TRUSTED_BIN_PATH} launchd restart",
                    socket_path.display(),
                    TIMEOUT.as_secs()
                );
                return;
            }
            Err(error) => {
                debug!(error = %error, "launchd_socket_not_ready");
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        }
    }
}

/// Kill any `wgd privileged --serve` process launchd is not currently
/// tracking under our label.
///
/// These are leftovers from the client-side sudo-autostart fallback
/// (`PrivilegedClient::spawn_privileged_daemon`): they never register with
/// launchd, so `bootout`/`bootstrap` above can neither stop them nor even
/// see them. And once a newer daemon (ad hoc or launchd-bootstrapped) takes
/// over the control socket path, no client can dial an older one again to
/// ask it to shut down -- it just runs forever. Install and uninstall are
/// the two points an admin has already deliberately decided this daemon's
/// identity should change, so they're the right place to sweep up anything
/// left over from before. Best-effort: a failure here must not abort
/// install/uninstall, which both have more important work to do.
///
/// Snapshots the process list *before* asking launchd for its tracked pid,
/// not after: a client connecting between the two calls would make launchd
/// spawn the real daemon in the gap, and checking launchd first would then
/// read that fresh spawn as untracked and kill it out from under the
/// connecting client.
fn reap_stray_privileged_daemons() {
    let candidates = find_privileged_daemon_pids();
    let tracked_pid = launchd_tracked_pid();
    for pid in candidates {
        if Some(pid) == tracked_pid {
            continue;
        }
        debug!(pid, ?tracked_pid, "reaping_stray_privileged_daemon");
        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
    }
}

/// The pid launchd currently has running for our label, if any (idle
/// on-demand jobs and not-yet-installed labels both report none).
fn launchd_tracked_pid() -> Option<u32> {
    let output = std::process::Command::new("/bin/launchctl")
        .args(["print", &format!("system/{LABEL}")])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_launchd_tracked_pid(&String::from_utf8_lossy(&output.stdout))
}

fn parse_launchd_tracked_pid(print_output: &str) -> Option<u32> {
    print_output
        .lines()
        .find_map(|line| line.trim().strip_prefix("pid = ")?.parse::<u32>().ok())
}

/// Pids of every running root-owned `wgd ... privileged --serve ...`
/// process, ad hoc or launchd-managed alike. Identified by uid and full
/// command line rather than executable name or path: the same binary also
/// runs as the gotatun tunnel helper (`wgd <interface>`), the per-user
/// session agent, and every ordinary CLI invocation, all sharing
/// `/usr/local/bin/wgd` -- and, unlike the daemon, all normally running as
/// the invoking user rather than root.
fn find_privileged_daemon_pids() -> Vec<u32> {
    let output = match std::process::Command::new("/bin/ps")
        .args(["-axo", "pid=,uid=,args="])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    parse_privileged_daemon_pids(&String::from_utf8_lossy(&output.stdout))
}

fn parse_privileged_daemon_pids(ps_output: &str) -> Vec<u32> {
    ps_output
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid_str, rest) = line.split_once(char::is_whitespace)?;
            let pid = pid_str.parse::<u32>().ok()?;
            let (uid_str, args) = rest.trim_start().split_once(char::is_whitespace)?;
            if uid_str.trim().parse::<u32>().ok()? != 0 {
                return None;
            }
            let mut tokens = args.split_whitespace();
            let is_wgd = tokens
                .next()
                .is_some_and(|argv0| Path::new(argv0).file_name() == Some("wgd".as_ref()));
            let tokens: Vec<&str> = tokens.collect();
            // `--stdio` is the per-command stdio helper
            // (`spawn_privileged_stdio_session_non_interactive`): a dedicated
            // process for one client's request/response pair, torn down when
            // that client is done. It also matches `privileged --serve`, but
            // killing it here would abort whatever command is using it.
            let is_stdio_helper = tokens.contains(&"--stdio");
            (is_wgd
                && !is_stdio_helper
                && tokens.contains(&"privileged")
                && tokens.contains(&"--serve"))
            .then_some(pid)
        })
        .collect()
}

fn find_session_agent_pids() -> Vec<u32> {
    let output = match std::process::Command::new("/bin/ps")
        .args(["-axo", "pid=,args="])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    parse_session_agent_pids(&String::from_utf8_lossy(&output.stdout))
}

fn parse_session_agent_pids(ps_output: &str) -> Vec<u32> {
    ps_output
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let (pid_str, args) = line.split_once(char::is_whitespace)?;
            let pid = pid_str.parse::<u32>().ok()?;
            let mut tokens = args.split_whitespace();
            let is_wgd = tokens
                .next()
                .is_some_and(|argv0| Path::new(argv0).file_name() == Some("wgd".as_ref()));
            let rest: Vec<&str> = tokens.collect();
            (is_wgd && rest == ["launchd", "agent", "run"]).then_some(pid)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privileged_api::ConnectionId;
    use std::path::Path;

    fn summary(global: bool, owner_uid: Option<u32>) -> ConnectionSummary {
        ConnectionSummary {
            id: ConnectionId::new(),
            global,
            owner_uid,
            start_mode: ConnectionStartMode::Automatic,
            name: None,
            interface: "wg-aaaaaaaa".to_string(),
            connected: false,
            user_disconnected: false,
            addresses: Vec::new(),
            dns_servers: Vec::new(),
            mtu: None,
            peers: Vec::new(),
            fingerprint: None,
            source_path: None,
            dns_dynamic_store: false,
            bypass_links: Vec::new(),
            created_at: 0,
            updated_at: 0,
        }
    }

    fn session(uid: u32, agent_loaded: bool) -> Option<InstallSession> {
        Some(InstallSession {
            uid,
            agent_loaded,
            agent_started: false,
        })
    }

    fn is_skip(action: PostInstallAction) -> bool {
        matches!(action, PostInstallAction::Skip(_))
    }

    #[test]
    fn post_install_reconnects_down_automatic_connections_of_the_session_owner_and_globals() {
        let mine = summary(false, Some(501));
        let global = summary(true, None);
        assert_eq!(
            post_install_action(&mine, session(501, true)),
            PostInstallAction::Reconnect
        );
        assert_eq!(
            post_install_action(&global, session(501, false)),
            PostInstallAction::Reconnect
        );
        assert_eq!(
            post_install_action(&global, None),
            PostInstallAction::Reconnect
        );
    }

    #[test]
    fn post_install_explains_per_user_connections_it_leaves_down() {
        let mine = summary(false, Some(501));
        assert!(is_skip(post_install_action(
            &summary(false, Some(502)),
            session(501, true)
        )));
        // No GUI session agent (e.g. an upgrade over ssh): per-user tunnels
        // stay down until that user's session agent starts.
        assert!(is_skip(post_install_action(&mine, session(501, false))));
        assert!(is_skip(post_install_action(&mine, None)));
    }

    #[test]
    fn post_install_leaves_per_user_connections_to_a_freshly_installed_agent() {
        let mine = summary(false, Some(501));
        let fresh = Some(InstallSession {
            uid: 501,
            agent_loaded: true,
            agent_started: true,
        });
        assert!(is_skip(post_install_action(&mine, fresh)));
        // Global connections are not the agent's business.
        assert_eq!(
            post_install_action(&summary(true, None), fresh),
            PostInstallAction::Reconnect
        );
    }

    #[test]
    fn session_agent_status_fails_only_when_connections_depend_on_it() {
        use crate::session_agent::AgentState;
        let plist = Path::new("/Users/a/Library/LaunchAgents/x.plist");
        let deps = vec!["work".to_string()];
        for state in [
            AgentState::NotInstalled,
            AgentState::Disabled,
            AgentState::NotLoaded,
        ] {
            let with = format_session_agent_status(state, "a", 501, plist, &deps);
            assert!(with.starts_with("FAIL  "), "{with}");
            assert!(with.contains("work"));
            let without = format_session_agent_status(state, "a", 501, plist, &[]);
            assert!(!without.contains("FAIL"), "{without}");
        }
        let ok = format_session_agent_status(AgentState::Loaded, "a", 501, plist, &deps);
        assert!(ok.starts_with("loaded"));
    }

    #[test]
    fn post_install_respects_mode_state_and_explicit_disconnect() {
        let mut manual = summary(false, Some(501));
        manual.start_mode = ConnectionStartMode::Manual;
        let mut up = summary(false, Some(501));
        up.connected = true;
        let mut user_disconnected = summary(true, None);
        user_disconnected.user_disconnected = true;

        assert_eq!(
            post_install_action(&manual, session(501, true)),
            PostInstallAction::Ignore
        );
        assert_eq!(
            post_install_action(&up, session(501, true)),
            PostInstallAction::Ignore
        );
        assert!(is_skip(post_install_action(
            &user_disconnected,
            session(501, true)
        )));
    }

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
    fn parses_launchd_tracked_pid_from_print_output() {
        let output = "system/me.pansen.wgd.privileged = {\n\
             \tactive count = 1\n\
             \tstate = running\n\
             \n\
             \tprogram = /usr/local/bin/wgd\n\
             \tpid = 48766\n\
             \tsocket manager = 1\n\
             }";
        assert_eq!(parse_launchd_tracked_pid(output), Some(48766));
    }

    #[test]
    fn no_tracked_pid_when_job_is_idle_or_absent() {
        let idle = "system/me.pansen.wgd.privileged = {\n\tstate = waiting\n}";
        assert_eq!(parse_launchd_tracked_pid(idle), None);
        assert_eq!(parse_launchd_tracked_pid(""), None);
    }

    #[test]
    fn finds_privileged_daemon_pids_and_ignores_look_alikes() {
        // Same binary, seven different invocations, all root-owned except
        // the CLI command: the launchd-style daemon, the ad hoc
        // sudo-autostart daemon, the per-command stdio helper (also matches
        // `privileged --serve` but must not be reaped mid-command), the
        // gotatun tunnel helper (whose "interface" argument happens to start
        // with a digit, not a flag), the session agent, an ordinary CLI
        // command running as the invoking user, and a real `privileged
        // --serve` daemon that isn't root (shouldn't happen, excluded
        // anyway). Only the first two are stray-daemon candidates.
        let ps = "\
              100     0 /usr/local/bin/wgd --debug privileged --serve --authorized-group wgd --autostarted --idle-timeout-ms 60000\n\
              200     0 /usr/local/bin/wgd privileged --serve --autostarted --authorized-group staff --debug\n\
              250     0 /usr/local/bin/wgd privileged --serve --stdio --autostarted --authorized-group staff\n\
              300     0 /usr/local/bin/wgd wg-ca40dce0\n\
              400   503 /usr/local/bin/wgd launchd agent run\n\
              500   503 /usr/local/bin/wgd connection list\n\
              700   503 /usr/local/bin/wgd privileged --serve --stdio\n\
              600     0 /usr/bin/grep privileged --serve\n";
        let mut pids = parse_privileged_daemon_pids(ps);
        pids.sort_unstable();
        assert_eq!(pids, vec![100, 200]);
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

    #[test]
    fn should_relocate_only_when_both_checks_pass() {
        assert!(!should_relocate(true, true));
        assert!(should_relocate(true, false));
        assert!(should_relocate(false, true));
        assert!(should_relocate(false, false));
    }

    #[test]
    fn relocation_source_check_also_denies_data_volume_firmlink_spellings() {
        // /System/Volumes/Data/... is the same location as /..., reached
        // through the data volume firmlink that fs::canonicalize resolves
        // through without collapsing back to the shorter spelling.
        assert!(reject_unsafe_relocation_source(
            Path::new("/System/Volumes/Data/Users/andi/wgd"),
            None,
        )
        .is_err());
        assert!(
            reject_unsafe_relocation_source(Path::new("/System/Volumes/Data/tmp/wgd"), None,)
                .is_err()
        );
    }

    #[test]
    fn finds_other_users_session_agent_plists_but_not_the_invoking_users() {
        let root = std::env::temp_dir().join(format!("wgd-purge-test-{}", std::process::id()));
        let plist_name = format!("{}.plist", crate::session_agent::LABEL);
        for user in ["alice", "bob", "carol"] {
            fs::create_dir_all(root.join(user).join("Library/LaunchAgents")).unwrap();
        }
        fs::write(
            root.join("alice/Library/LaunchAgents").join(&plist_name),
            "",
        )
        .unwrap();
        fs::write(root.join("bob/Library/LaunchAgents").join(&plist_name), "").unwrap();
        let found = other_users_session_agent_plists(&root, Some(&root.join("alice")));
        fs::remove_dir_all(&root).unwrap();
        assert_eq!(
            found,
            vec![root.join("bob/Library/LaunchAgents").join(&plist_name)]
        );
    }

    #[test]
    fn symbolic_mode_renders_socket_and_directory_modes() {
        assert_eq!(format_symbolic_mode('s', 0o660), "srw-rw----");
        assert_eq!(format_symbolic_mode('d', 0o750), "drwxr-x---");
        assert_eq!(format_symbolic_mode('-', 0o755), "-rwxr-xr-x");
    }

    #[test]
    fn extracts_launchd_state_pid_and_listeners() {
        let sample = "\
system/me.pansen.wgd.privileged = {
\tactive count = 1
\tstate = running
\truns = 3
\tpid = 70043
\timmediate reason = ipc (socket)
\tlast exit code = 0
\tsockets = {
\t\t\"Listeners\" = {
\t\t\ttype = stream
\t\t\tpath = /Library/Application Support/wgd/run/ctl.sock
\t\t}
\t}
\tresource coalition = {
\t\tstate = active
\t}
\tjetsam coalition = {
\t\tstate = active
\t}
\tjob state = running
}";
        assert_eq!(
            extract_launchd_daemon_lines(sample),
            vec![
                "state = running".to_string(),
                "runs = 3".to_string(),
                "pid = 70043".to_string(),
                "immediate reason = ipc (socket)".to_string(),
                "last exit code = 0".to_string(),
                "\"Listeners\" = {".to_string(),
                "path = /Library/Application Support/wgd/run/ctl.sock".to_string(),
            ]
        );
    }

    #[test]
    fn filters_wgd_processes_and_skips_self_and_diagnostics() {
        let ps = "\
  100     0 root       /usr/local/bin/wgd --debug privileged --serve --authorized-group wgd\n\
  200     0 root       /usr/local/bin/wgd wg-1ce3a4a1\n\
  300   501 andi       /usr/local/bin/wgd launchd agent run\n\
  400   501 andi       /usr/local/bin/wgd doctor --report /tmp/r.log\n\
  500     0 root       /usr/local/bin/wgd launchd status --caller-in-wgd-group=true\n\
  600   501 andi       /bin/zsh\n";
        let lines = filter_wgd_process_lines(ps, 999);
        assert_eq!(lines.len(), 3);
        assert!(lines[0].contains("privileged --serve"));
        assert!(lines[1].contains("wg-1ce3a4a1"));
        assert!(lines[2].contains("launchd agent run"));
    }

    #[test]
    fn parses_session_agent_pids_only() {
        let ps = "\
  100 /usr/local/bin/wgd privileged --serve\n\
  300 /usr/local/bin/wgd launchd agent run\n\
  301 /opt/homebrew/bin/wgd launchd agent run\n\
  400 /usr/local/bin/wgd launchd agent status\n";
        assert_eq!(parse_session_agent_pids(ps), vec![300, 301]);
    }
}
