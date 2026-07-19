//! Pure core for the `tunmux autoconnect` subcommand: an installer for the
//! per-user (GUI-domain) autoconnect LaunchAgent plist. This module provides
//! both the plist-rendering logic and the
//! `tunmux autoconnect install|reload|uninstall` command handlers, porting
//! `make install/autostart`, `reload/autostart`, and `uninstall/autostart`.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::Context;
use nix::unistd::{geteuid, getuid};

use crate::cli::AutoconnectCommand;
use crate::launchctl::{
    remove_file_ignore_missing, run_checked, run_ignore_failure, xml_escape, xml_unescape,
};

pub(crate) const LABEL: &str = "me.pansen.tunmux.autoconnect";

const PLIST_TEMPLATE: &str = include_str!("../etc/me.pansen.tunmux.autoconnect.plist");
const BIN_PLACEHOLDER: &str = "@TUNMUX_BIN@";
const HOME_PLACEHOLDER: &str = "@TUNMUX_HOME@";
const FLAG_PLACEHOLDER: &str = "@CONNECT_FLAG@";
const VALUE_PLACEHOLDER: &str = "@CONNECT_VALUE@";

/// The WireGuard config source the autoconnect agent should connect with,
/// mirroring the file/profile mutual exclusion of `WgconfConnectArgs`.
enum ConnectSource {
    File(String),
    Profile(String),
}

impl ConnectSource {
    fn flag(&self) -> &'static str {
        match self {
            ConnectSource::File(_) => "--file",
            ConnectSource::Profile(_) => "--profile",
        }
    }

    fn value(&self) -> &str {
        match self {
            ConnectSource::File(v) | ConnectSource::Profile(v) => v,
        }
    }
}

/// Render the autoconnect agent's launchd plist, substituting the tunmux
/// binary path, the invoking user's home directory, and the connect source
/// (file/profile flag + value) into `template`.
fn render_plist(
    template: &str,
    bin: &str,
    home: &str,
    source: &ConnectSource,
) -> anyhow::Result<String> {
    for placeholder in [
        BIN_PLACEHOLDER,
        HOME_PLACEHOLDER,
        FLAG_PLACEHOLDER,
        VALUE_PLACEHOLDER,
    ] {
        if !template.contains(placeholder) {
            anyhow::bail!("plist template is missing the {placeholder} placeholder");
        }
    }

    let rendered = template
        .replace(BIN_PLACEHOLDER, &xml_escape(bin))
        .replace(HOME_PLACEHOLDER, &xml_escape(home))
        .replace(FLAG_PLACEHOLDER, source.flag())
        .replace(VALUE_PLACEHOLDER, &xml_escape(source.value()));

    // Fail closed: none of the placeholders may survive, and the Label the
    // reload/uninstall paths target must be present (guards a bad custom
    // template).
    for placeholder in [
        BIN_PLACEHOLDER,
        HOME_PLACEHOLDER,
        FLAG_PLACEHOLDER,
        VALUE_PLACEHOLDER,
    ] {
        anyhow::ensure!(
            !rendered.contains(placeholder),
            "rendered plist still contains {placeholder}"
        );
    }
    anyhow::ensure!(
        rendered.contains(LABEL),
        "rendered plist is missing the expected launchd Label `{LABEL}` (custom template?)"
    );

    Ok(rendered)
}

pub fn dispatch(command: AutoconnectCommand) -> anyhow::Result<()> {
    match command {
        AutoconnectCommand::Install {
            file,
            profile,
            force,
        } => {
            let source = connect_source(file, profile)?;
            cmd_install(source, force)
        }
        AutoconnectCommand::List => cmd_list(),
        AutoconnectCommand::Reload => cmd_reload(),
        AutoconnectCommand::Uninstall => cmd_uninstall(),
    }
}

/// Build a `ConnectSource` from the CLI's file/profile options. clap already
/// guarantees exactly one is `Some` via `required_unless_present` /
/// `conflicts_with`; bail with a clear error in the (unreachable in
/// practice) case neither is set.
fn connect_source(file: Option<String>, profile: Option<String>) -> anyhow::Result<ConnectSource> {
    match (file, profile) {
        (Some(file), None) => Ok(ConnectSource::File(file)),
        (None, Some(profile)) => Ok(ConnectSource::Profile(profile)),
        _ => anyhow::bail!("exactly one of --file or --profile must be given"),
    }
}

fn cmd_install(source: ConnectSource, force: bool) -> anyhow::Result<()> {
    refuse_if_root()?;

    let home = std::env::var("HOME").context("could not determine $HOME")?;
    let uid = getuid().as_raw();
    let bin =
        std::env::current_exe().context("failed to determine the running tunmux binary path")?;
    let bin_str = bin.to_str().ok_or_else(|| {
        anyhow::anyhow!("tunmux binary path is not valid UTF-8: {}", bin.display())
    })?;

    // Existing-install guard. Mutate nothing before this check.
    let plist_path = launch_agents_dir(&home).join(format!("{LABEL}.plist"));
    if plist_path.exists() && !force {
        anyhow::bail!(
            "autoconnect agent already installed at {}; re-run with --force to overwrite and reload",
            plist_path.display()
        );
    }

    let plist = render_plist(PLIST_TEMPLATE, bin_str, &home, &source)?;

    let dir = launch_agents_dir(&home);
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    write_plist(&plist_path, &plist)?;

    let plist_path_str = plist_path.to_str().ok_or_else(|| {
        anyhow::anyhow!(
            "autoconnect plist path is not valid UTF-8: {}",
            plist_path.display()
        )
    })?;

    run_ignore_failure("/bin/launchctl", &["bootout", &domain_target(uid)]);
    run_checked(
        "/bin/launchctl",
        &["bootstrap", &gui_domain(uid), plist_path_str],
    )?;
    run_checked("/bin/launchctl", &["kickstart", "-k", &domain_target(uid)])?;

    println!("tunmux autoconnect agent installed.");
    println!("  plist:  {}", plist_path.display());
    println!("  binary: {}", bin.display());
    println!("  {}: {}", source.flag(), source.value());
    Ok(())
}

fn cmd_reload() -> anyhow::Result<()> {
    refuse_if_root()?;
    let uid = getuid().as_raw();

    run_checked("/bin/launchctl", &["kickstart", "-k", &domain_target(uid)]).with_context(
        || "autoconnect agent not installed? run: tunmux autoconnect install --file <path>",
    )?;

    println!("tunmux autoconnect agent reloaded.");
    Ok(())
}

fn cmd_uninstall() -> anyhow::Result<()> {
    refuse_if_root()?;

    let home = std::env::var("HOME").context("could not determine $HOME")?;
    let uid = getuid().as_raw();
    let plist_path = launch_agents_dir(&home).join(format!("{LABEL}.plist"));

    run_ignore_failure("/bin/launchctl", &["bootout", &domain_target(uid)]);
    remove_file_ignore_missing(&plist_path)?;

    println!("tunmux autoconnect agent uninstalled.");
    println!("  plist: {}", plist_path.display());
    Ok(())
}

/// Read-only listing of the installed autoconnect LaunchAgent plist(s) in the
/// invoking user's `~/Library/LaunchAgents`, each with its launchd load state
/// and the connect source it was rendered with. No root check: this only reads.
fn cmd_list() -> anyhow::Result<()> {
    let home = std::env::var("HOME").context("could not determine $HOME")?;
    let uid = getuid().as_raw();
    let dir = launch_agents_dir(&home);

    let mut plists: Vec<PathBuf> = match fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with(LABEL) && name.ends_with(".plist"))
            })
            .collect(),
        Err(err) if err.kind() == ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(err).with_context(|| format!("failed to read {}", dir.display())),
    };
    plists.sort();

    if plists.is_empty() {
        println!("No autoconnect agent installed.");
        return Ok(());
    }

    for (idx, path) in plists.iter().enumerate() {
        if idx > 0 {
            println!();
        }
        let label = path.file_stem().and_then(|s| s.to_str()).unwrap_or(LABEL);
        // 🟢 active (launchd has it loaded), 🔘 inactive (installed but not loaded).
        let marker = if is_loaded(uid, label) {
            "🟢"
        } else {
            "🔘"
        };
        println!("{marker}  {}", path.display());
        if let Some(source) = fs::read_to_string(path)
            .ok()
            .and_then(|contents| parse_connect_source(&contents))
        {
            println!("    {source}");
        }
    }
    Ok(())
}

/// Whether launchd currently has `label` bootstrapped in the user's GUI domain.
fn is_loaded(uid: u32, label: &str) -> bool {
    std::process::Command::new("/bin/launchctl")
        .args(["print", &domain_target_for(uid, label)])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Best-effort extraction of the `connect` source (flag + value) from a
/// rendered autoconnect plist, for display in `list`. Returns `None` when the
/// ProgramArguments don't have the expected `… connect <flag> <value> …` shape.
fn parse_connect_source(plist: &str) -> Option<String> {
    let strings: Vec<String> = plist
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            line.strip_prefix("<string>")
                .and_then(|rest| rest.strip_suffix("</string>"))
                .map(xml_unescape)
        })
        .collect();
    let idx = strings.iter().position(|s| s == "connect")?;
    let flag = strings.get(idx + 1)?;
    let value = strings.get(idx + 2)?;
    Some(format!("{flag} {value}"))
}

/// Write the rendered plist to `path` atomically (temp file + rename), user
/// owned mode 0644. Unlike `launchd::write_plist`, no chown: the user
/// installing this already owns the file.
fn write_plist(path: &Path, contents: &str) -> anyhow::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let tmp = PathBuf::from(format!("{}.tmp", path.display()));

    let write_result = (|| -> anyhow::Result<()> {
        fs::write(&tmp, contents).with_context(|| format!("failed to write {}", tmp.display()))?;
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))
            .with_context(|| format!("failed to chmod {}", tmp.display()))?;
        fs::rename(&tmp, path).with_context(|| format!("failed to install {}", path.display()))?;
        Ok(())
    })();

    if write_result.is_err() {
        // Best-effort cleanup; ignore errors.
        let _ = fs::remove_file(&tmp);
    }
    write_result
}

fn launch_agents_dir(home: &str) -> PathBuf {
    Path::new(home).join("Library/LaunchAgents")
}

fn gui_domain(uid: u32) -> String {
    format!("gui/{uid}")
}

fn domain_target(uid: u32) -> String {
    domain_target_for(uid, LABEL)
}

fn domain_target_for(uid: u32, label: &str) -> String {
    format!("gui/{uid}/{label}")
}

/// Bail if running as root: the autoconnect agent is per-user (GUI domain),
/// and must not be installed via `sudo`.
fn refuse_if_root() -> anyhow::Result<()> {
    if geteuid().is_root() {
        anyhow::bail!(
            "run `tunmux autoconnect install` as your normal user, not with sudo (the autoconnect agent is per-user)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuse_if_root_when_root() {
        // Unlike `launchd::require_root` (which errors when NOT root),
        // `refuse_if_root` errors only when running AS root. Test runners
        // normally run unprivileged, so assert the no-op branch there and
        // only assert the refusal itself under a root test runner (e.g. CI
        // running as root).
        if geteuid().is_root() {
            let err = refuse_if_root().expect_err("must refuse when root");
            assert!(err.to_string().contains("not with sudo"));
        } else {
            refuse_if_root().expect("must be a no-op when not root");
        }
    }

    #[test]
    fn render_plist_substitutes_all() {
        let source = ConnectSource::File("/tmp/x.conf".to_string());
        let rendered = render_plist(
            PLIST_TEMPLATE,
            "/opt/homebrew/bin/tunmux",
            "/Users/andi",
            &source,
        )
        .expect("render succeeds");

        assert!(rendered.contains("/opt/homebrew/bin/tunmux"));
        assert!(rendered.contains("/Users/andi"));
        assert!(rendered.contains("--file"));
        assert!(rendered.contains("/tmp/x.conf"));
        assert!(!rendered.contains(BIN_PLACEHOLDER));
        assert!(!rendered.contains(HOME_PLACEHOLDER));
        assert!(!rendered.contains(FLAG_PLACEHOLDER));
        assert!(!rendered.contains(VALUE_PLACEHOLDER));
        assert!(rendered.contains(LABEL));
    }

    #[test]
    fn render_plist_uses_profile_flag() {
        let source = ConnectSource::Profile("work".to_string());
        let rendered = render_plist(
            PLIST_TEMPLATE,
            "/opt/homebrew/bin/tunmux",
            "/Users/andi",
            &source,
        )
        .expect("render succeeds");

        assert!(rendered.contains("--profile"));
        assert!(rendered.contains("work"));
        assert!(!rendered.contains("--file"));
    }

    #[test]
    fn render_escapes_special_chars() {
        let source = ConnectSource::File("/tmp/a&b.conf".to_string());
        let rendered = render_plist(
            PLIST_TEMPLATE,
            "/opt/homebrew/bin/tunmux",
            "/Users/andi",
            &source,
        )
        .expect("render succeeds");

        assert!(rendered.contains("/tmp/a&amp;b.conf"));
        assert!(!rendered.contains("a&b.conf"));
    }

    #[test]
    fn render_errors_when_placeholder_missing() {
        let template = PLIST_TEMPLATE.replace(BIN_PLACEHOLDER, "/usr/local/bin/tunmux");
        let source = ConnectSource::File("/tmp/x.conf".to_string());
        let err = render_plist(
            &template,
            "/opt/homebrew/bin/tunmux",
            "/Users/andi",
            &source,
        )
        .expect_err("missing bin placeholder should error");
        assert!(err.to_string().contains(BIN_PLACEHOLDER));
    }

    #[test]
    fn parse_connect_source_round_trips_through_rendered_plist() {
        let source = ConnectSource::File("/tmp/a&b.conf".to_string());
        let rendered = render_plist(
            PLIST_TEMPLATE,
            "/opt/homebrew/bin/tunmux",
            "/Users/andi",
            &source,
        )
        .expect("render succeeds");
        assert_eq!(
            parse_connect_source(&rendered).as_deref(),
            Some("--file /tmp/a&b.conf")
        );
    }

    #[test]
    fn parse_connect_source_reads_profile_flag() {
        let source = ConnectSource::Profile("work".to_string());
        let rendered = render_plist(
            PLIST_TEMPLATE,
            "/opt/homebrew/bin/tunmux",
            "/Users/andi",
            &source,
        )
        .expect("render succeeds");
        assert_eq!(
            parse_connect_source(&rendered).as_deref(),
            Some("--profile work")
        );
    }
}
