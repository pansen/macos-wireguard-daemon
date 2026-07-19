//! Pure core for the `tunmux launchd` subcommand: an installer for the
//! privileged launchd daemon plist. This module provides both the
//! plist-rendering / binary-location-validation logic and the
//! `tunmux launchd install|restart|uninstall` command handlers, porting
//! `make install/privileged`, `reload/privileged`, and the launchd parts of
//! `uninstall/privileged`.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::Context;
use nix::unistd::{chown, geteuid, Gid, Group, Uid, User};

use crate::cli::LaunchdCommand;
use crate::config;

pub(crate) const LABEL: &str = "me.pansen.tunmux.privileged";
pub(crate) const PLIST_PATH: &str = "/Library/LaunchDaemons/me.pansen.tunmux.privileged.plist";

/// Group whose members may talk to the privileged daemon's control socket.
/// Must match `AUTH_GROUP_NAME` in `src/privileged/mod.rs`, which is private
/// to that module and therefore unavailable from here.
const GROUP_NAME: &str = "tunmux";

const PLIST_TEMPLATE: &str = include_str!("../etc/me.pansen.tunmux.privileged.plist");
const BIN_PLACEHOLDER: &str = "@TUNMUX_BIN@";
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

/// Escape the five XML special characters so a path with e.g. `&` in it
/// still produces a well-formed plist.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Reject binaries in locations a regular user controls.
///
/// The rendered plist makes launchd run this binary as root, so both the
/// path as invoked (e.g. `current_exe()`) and its canonicalized/symlink-
/// resolved target must live in a location that isn't writable by an
/// unprivileged user — otherwise a user could swap the binary out from
/// under root's launchd.
///
/// This check is deliberately path-prefix-based, not ownership-based:
/// /opt/homebrew is user-owned by design on Apple Silicon (Homebrew installs
/// without root), so an ownership check would either reject legitimate
/// Homebrew installs or fail to catch the actual risk. Prefix-based
/// denylisting of known user-writable roots (home directories, temp dirs)
/// is the meaningful signal here.
pub fn validate_binary_location(
    invoked: &Path,
    resolved: &Path,
    invoking_user_home: Option<&Path>,
) -> anyhow::Result<()> {
    validate_one(invoked, invoking_user_home)?;
    validate_one(resolved, invoking_user_home)?;
    Ok(())
}

const REJECTED_PREFIXES: &[&str] = &[
    "/Users/",
    "/tmp/",
    "/private/tmp/",
    "/var/folders/",
    "/private/var/folders/",
    "/var/tmp/",
    "/private/var/tmp/",
];

fn validate_one(path: &Path, invoking_user_home: Option<&Path>) -> anyhow::Result<()> {
    if !path.is_absolute() {
        anyhow::bail!(
            "refusing to install a launchd daemon that runs a non-absolute path ({}); \
             install a build from a system location such as /usr/local/bin or via Homebrew",
            path.display()
        );
    }

    let path_str = path.to_string_lossy();

    for prefix in REJECTED_PREFIXES {
        if path_str.starts_with(prefix) {
            anyhow::bail!(
                "refusing to install a launchd daemon that runs a binary from a user-writable \
                 location ({}); place the tunmux binary in a system location such as \
                 /usr/local/bin or install it via Homebrew",
                path.display()
            );
        }
    }

    if let Some(home) = invoking_user_home {
        if path.starts_with(home) {
            anyhow::bail!(
                "refusing to install a launchd daemon that runs a binary from the invoking \
                 user's home directory ({}); place the tunmux binary in a system location \
                 such as /usr/local/bin or install it via Homebrew",
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
        LaunchdCommand::Uninstall => cmd_uninstall(),
    }
}

fn cmd_install(plist_template: Option<PathBuf>) -> anyhow::Result<()> {
    require_root("install")?;

    // Validate everything that can refuse the install BEFORE mutating any
    // system state (group creation, membership, directories, plist).
    let user = invoking_user()?;
    let bin = daemon_binary_path()?;
    let bin_str = bin.to_str().ok_or_else(|| {
        anyhow::anyhow!("tunmux binary path is not valid UTF-8: {}", bin.display())
    })?;
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
    let gid = ensure_group_with_member(&user)?;
    ensure_directories(gid)?;
    let plist = render_plist_from(&template, bin_str, gid)?;
    write_plist(&plist)?;
    bootstrap()?;

    println!("tunmux privileged daemon installed.");
    println!("  binary: {}", bin.display());
    println!("  plist:  {PLIST_PATH}");
    if let Some(path) = &plist_template {
        println!("  template: {}", path.display());
    }
    println!(
        "You may need to log out and back in (or run `newgrp tunmux`) for tunmux group \
         membership to take effect."
    );
    Ok(())
}

fn cmd_restart() -> anyhow::Result<()> {
    require_root("restart")?;
    // Re-run the same location validation as install, guarding against e.g.
    // `sudo ./target/debug/tunmux launchd restart` restarting a daemon that
    // was installed from a different (system) location.
    let _ = daemon_binary_path()?;

    run_checked(
        "/bin/launchctl",
        &["kickstart", "-k", &format!("system/{LABEL}")],
    )
    .with_context(|| "daemon not installed? run: sudo tunmux launchd install")?;

    println!("tunmux privileged daemon restarted.");
    Ok(())
}

fn cmd_uninstall() -> anyhow::Result<()> {
    require_root("uninstall")?;

    run_ignore_failure("/bin/launchctl", &["bootout", &format!("system/{LABEL}")]);
    // Parity with the old Makefile-based uninstall: leave the label
    // disabled. `cmd_install`'s `launchctl enable` clears this again on
    // reinstall.
    run_ignore_failure("/bin/launchctl", &["disable", &format!("system/{LABEL}")]);

    remove_file_ignore_missing(Path::new(PLIST_PATH))?;
    remove_file_ignore_missing(&config::privileged_socket_path())?;

    println!("tunmux privileged daemon uninstalled.");
    println!("Intentionally kept (remove with `make purge/privileged` for a full removal):");
    println!("  the tunmux binary");
    println!("  the tunmux group");
    println!("  {}", config::root_log_dir().display());
    println!(
        "  the runtime directory ({})",
        config::privileged_socket_dir().display()
    );
    Ok(())
}

/// Bail unless running as root, with a hint on how to re-invoke this command.
fn require_root(cmd_hint: &str) -> anyhow::Result<()> {
    if !geteuid().is_root() {
        anyhow::bail!("this command must run as root; try: sudo tunmux launchd {cmd_hint}");
    }
    Ok(())
}

/// Home directory of the user who invoked `sudo`, if any. Used only to feed
/// `validate_binary_location`'s third argument so non-standard home
/// locations are still covered; the function's static prefix denylist
/// applies regardless.
fn invoking_user_home() -> Option<PathBuf> {
    let user = std::env::var("SUDO_USER").ok()?;
    User::from_name(&user).ok().flatten().map(|u| u.dir)
}

/// The user who ran `sudo`, i.e. who should be added to the `tunmux` group.
fn invoking_user() -> anyhow::Result<String> {
    match std::env::var("SUDO_USER") {
        Ok(user) if !user.is_empty() => Ok(user),
        _ => anyhow::bail!(
            "could not determine the invoking user (SUDO_USER is unset); run this via \
             `sudo tunmux launchd install` from your normal account, or add yourself to the \
             tunmux group manually with: sudo dseditgroup -o edit -a <user> -t user tunmux"
        ),
    }
}

/// The daemon binary path to embed in the plist's ProgramArguments, after
/// validating it isn't installed somewhere a regular user could tamper with.
///
/// Deliberately not canonicalized: keeping the as-invoked path means a
/// Homebrew `opt` symlink stays stable across upgrades (only the symlink
/// target changes). If `current_exe()` itself ever returns an
/// already-canonicalized path on this platform, that only affects future
/// Homebrew opt-symlink stability, which the bottle packaging will need to
/// address; the current dev/Makefile flow installs straight to
/// /usr/local/bin, so it's unaffected either way.
fn daemon_binary_path() -> anyhow::Result<PathBuf> {
    let invoked =
        std::env::current_exe().context("failed to determine the running tunmux binary path")?;
    let resolved = fs::canonicalize(&invoked)
        .with_context(|| format!("failed to resolve {}", invoked.display()))?;
    validate_binary_location(&invoked, &resolved, invoking_user_home().as_deref())?;
    Ok(invoked)
}

/// Port of Makefile:19-20: ensure the `tunmux` group exists and that `user`
/// is a member, returning its GID.
fn ensure_group_with_member(user: &str) -> anyhow::Result<u32> {
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

    // Idempotent: re-adding an existing member is a no-op.
    run_checked(
        "/usr/sbin/dseditgroup",
        &["-o", "edit", "-a", user, "-t", "user", GROUP_NAME],
    )?;

    Group::from_name(GROUP_NAME)
        .ok()
        .flatten()
        .map(|g| g.gid.as_raw())
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

fn run_checked(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {program} {}", args.join(" ")))?;
    if !output.status.success() {
        anyhow::bail!(
            "{program} {} failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

fn run_ignore_failure(program: &str, args: &[&str]) {
    match std::process::Command::new(program).args(args).output() {
        Ok(output) if !output.status.success() => {
            tracing::debug!(
                program,
                args = ?args,
                status = ?output.status,
                stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                "launchd_command_ignored_failure"
            );
        }
        Err(err) => {
            tracing::debug!(program, args = ?args, error = %err, "launchd_command_failed_to_run");
        }
        Ok(_) => {}
    }
}

fn remove_file_ignore_missing(path: &Path) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", path.display())),
    }
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
        assert!(err.to_string().contains("sudo tunmux launchd install"));
    }

    #[test]
    fn render_plist_substitutes_binary_and_gid() {
        let rendered = render_plist_from(PLIST_TEMPLATE, "/opt/homebrew/bin/tunmux", 499)
            .expect("render succeeds");

        assert!(rendered.contains("<key>SockPathGroup</key>"));
        assert!(rendered.contains("<integer>499</integer>"));
        assert!(rendered.contains("/opt/homebrew/bin/tunmux"));
        assert!(!rendered.contains(BIN_PLACEHOLDER));
        assert!(!rendered.contains("@SOCK_PATH_GROUP@"));
        assert!(rendered.contains("me.pansen.tunmux.privileged"));
        assert!(rendered.contains("SockPathMode"));
    }

    #[test]
    fn render_plist_errors_when_bin_placeholder_missing() {
        let template = PLIST_TEMPLATE.replace(BIN_PLACEHOLDER, "/usr/local/bin/tunmux");
        let err = render_plist_from(&template, "/opt/homebrew/bin/tunmux", 499)
            .expect_err("missing bin placeholder should error");
        assert!(err.to_string().contains(BIN_PLACEHOLDER));
    }

    #[test]
    fn render_plist_errors_when_sock_group_marker_missing() {
        let template = PLIST_TEMPLATE.replace(SOCK_GROUP_MARKER, "");
        let err = render_plist_from(&template, "/opt/homebrew/bin/tunmux", 499)
            .expect_err("missing marker should error");
        assert!(err.to_string().contains(SOCK_GROUP_MARKER));
    }

    #[test]
    fn render_rejects_template_without_label() {
        let modified = PLIST_TEMPLATE.replace(LABEL, "me.pansen.tunmux.evil");
        let err = render_plist_from(&modified, "/usr/local/bin/tunmux", 20)
            .expect_err("missing expected Label should error");
        assert!(err.to_string().contains("Label"));
    }

    #[test]
    fn xml_escape_escapes_specials() {
        assert_eq!(xml_escape("/a&b/<c>"), "/a&amp;b/&lt;c&gt;");
    }

    #[test]
    fn render_escapes_binary_path() {
        let rendered =
            render_plist_from(PLIST_TEMPLATE, "/opt/t&t/bin/tunmux", 20).expect("render succeeds");
        assert!(rendered.contains("/opt/t&amp;t/bin/tunmux"));
        assert!(!rendered.contains("t&t/bin"));
    }

    #[test]
    fn rejects_user_home_directory() {
        assert!(validate_binary_location(
            Path::new("/Users/andi/p/tunmux/target/release/tunmux"),
            Path::new("/Users/andi/p/tunmux/target/release/tunmux"),
            None,
        )
        .is_err());
    }

    #[test]
    fn rejects_tmp() {
        assert!(
            validate_binary_location(Path::new("/tmp/tunmux"), Path::new("/tmp/tunmux"), None)
                .is_err()
        );
    }

    #[test]
    fn rejects_var_folders() {
        assert!(validate_binary_location(
            Path::new("/private/var/folders/xx/tunmux"),
            Path::new("/private/var/folders/xx/tunmux"),
            None,
        )
        .is_err());
    }

    #[test]
    fn rejects_var_tmp() {
        assert!(validate_binary_location(
            Path::new("/var/tmp/tunmux"),
            Path::new("/private/var/tmp/tunmux"),
            None,
        )
        .is_err());
    }

    #[test]
    fn rejects_relative_path() {
        assert!(validate_binary_location(Path::new("tunmux"), Path::new("tunmux"), None).is_err());
    }

    #[test]
    fn rejects_symlink_resolving_into_home_dir() {
        // Invoked path looks fine (/usr/local/bin), but the symlink target
        // resolves into a home directory build — must still be rejected.
        assert!(validate_binary_location(
            Path::new("/usr/local/bin/tunmux"),
            Path::new("/Users/andi/target/release/tunmux"),
            None,
        )
        .is_err());
    }

    #[test]
    fn rejects_non_standard_home_via_invoking_user_home() {
        assert!(validate_binary_location(
            Path::new("/opt/home/andi/tunmux"),
            Path::new("/opt/home/andi/tunmux"),
            Some(Path::new("/opt/home/andi")),
        )
        .is_err());
    }

    #[test]
    fn accepts_usr_local_bin() {
        assert!(validate_binary_location(
            Path::new("/usr/local/bin/tunmux"),
            Path::new("/usr/local/bin/tunmux"),
            None,
        )
        .is_ok());
    }

    #[test]
    fn accepts_homebrew_cellar_symlink_target() {
        assert!(validate_binary_location(
            Path::new("/opt/homebrew/bin/tunmux"),
            Path::new("/opt/homebrew/Cellar/tunmux/0.9.0/bin/tunmux"),
            None,
        )
        .is_ok());
    }
}
