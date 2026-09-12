//! `tunmux connection agent ...`: installer + long-lived body for the Phase 4
//! per-user session-reconciliation LaunchAgent. It never bakes a connect
//! source into its plist -- on every start it just asks the privileged
//! daemon for whatever is currently `Mine` + `Automatic` and connects it, so
//! adding/removing connections never requires touching the installed plist.
//! This replaced an earlier `autoconnect.rs` mechanism that polled
//! (`StartInterval`, no `KeepAlive`, one-shot per tick) and baked a
//! `--file`/`--profile` connect source into its plist at install time.
//!
//! This agent is long-lived (`RunAtLoad`+`KeepAlive`): it reconciles once on
//! start, then blocks on `SIGTERM` and disconnects its own connections
//! before exiting. launchd sends `SIGTERM` to an Aqua-session agent at
//! logout, so this covers logout -- it does **not** cover fast user
//! switching (switching sessions does not terminate the switched-away
//! session's agents), which is a known gap, not something this agent
//! actually handles today.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::Context;
use nix::sys::signal::{SigSet, Signal};
use nix::unistd::{geteuid, getuid};
use tracing::warn;

use crate::cli::ConnectionAgentCommand;
use crate::launchctl::{remove_file_ignore_missing, run_checked, run_ignore_failure, xml_escape};
use crate::privileged_api::{ConnectionScope, ConnectionStartMode};
use crate::privileged_client::PrivilegedClient;

pub(crate) const LABEL: &str = "me.pansen.tunmux.session-agent";

const PLIST_TEMPLATE: &str = include_str!("../etc/me.pansen.tunmux.session-agent.plist");
const BIN_PLACEHOLDER: &str = "@TUNMUX_BIN@";
const HOME_PLACEHOLDER: &str = "@TUNMUX_HOME@";

pub fn dispatch(command: ConnectionAgentCommand) -> anyhow::Result<()> {
    match command {
        ConnectionAgentCommand::Install { force } => cmd_install(force),
        ConnectionAgentCommand::Uninstall => cmd_uninstall(),
        ConnectionAgentCommand::Status => cmd_status(),
        ConnectionAgentCommand::Run => run(),
    }
}

fn render_plist(template: &str, bin: &str, home: &str) -> anyhow::Result<String> {
    for placeholder in [BIN_PLACEHOLDER, HOME_PLACEHOLDER] {
        if !template.contains(placeholder) {
            anyhow::bail!("plist template is missing the {placeholder} placeholder");
        }
    }

    let rendered = template
        .replace(BIN_PLACEHOLDER, &xml_escape(bin))
        .replace(HOME_PLACEHOLDER, &xml_escape(home));

    for placeholder in [BIN_PLACEHOLDER, HOME_PLACEHOLDER] {
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

/// Re-render and re-bootstrap the agent, for `tunmux reload`.
pub(crate) fn reinstall() -> anyhow::Result<()> {
    cmd_install(true)
}

fn cmd_install(force: bool) -> anyhow::Result<()> {
    refuse_if_root()?;

    let home = std::env::var("HOME").context("could not determine $HOME")?;
    let uid = getuid().as_raw();
    let bin =
        std::env::current_exe().context("failed to determine the running tunmux binary path")?;
    let bin_str = bin.to_str().ok_or_else(|| {
        anyhow::anyhow!("tunmux binary path is not valid UTF-8: {}", bin.display())
    })?;

    let plist_path = launch_agents_dir(&home).join(format!("{LABEL}.plist"));
    if plist_path.exists() && !force {
        anyhow::bail!(
            "session agent already installed at {}; re-run with --force to overwrite and reload",
            plist_path.display()
        );
    }

    let plist = render_plist(PLIST_TEMPLATE, bin_str, &home)?;

    let dir = launch_agents_dir(&home);
    fs::create_dir_all(&dir).with_context(|| format!("failed to create {}", dir.display()))?;
    write_plist(&plist_path, &plist)?;

    let plist_path_str = plist_path.to_str().ok_or_else(|| {
        anyhow::anyhow!(
            "session agent plist path is not valid UTF-8: {}",
            plist_path.display()
        )
    })?;

    // `bootout` (if it was already running, e.g. a re-install) sends SIGTERM
    // and waits for exit; `bootstrap` with `RunAtLoad=true` starts the fresh
    // instance immediately. No separate `kickstart -k` afterward: that would
    // just SIGTERM the instance `bootstrap` only just started, right as it's
    // in the middle of its own initial reconciliation.
    run_ignore_failure("/bin/launchctl", &["bootout", &domain_target(uid)]);
    run_checked(
        "/bin/launchctl",
        &["bootstrap", &gui_domain(uid), plist_path_str],
    )?;

    println!("tunmux session agent installed.");
    println!("  plist:  {}", plist_path.display());
    println!("  binary: {}", bin.display());
    println!(
        "  it will connect every `Automatic` connection owned by this user on login \
         (`tunmux connection mode <id> automatic`) and disconnect them again on logout."
    );
    Ok(())
}

fn cmd_uninstall() -> anyhow::Result<()> {
    refuse_if_root()?;

    let home = std::env::var("HOME").context("could not determine $HOME")?;
    let uid = getuid().as_raw();
    let plist_path = launch_agents_dir(&home).join(format!("{LABEL}.plist"));

    // `bootout` sends the agent SIGTERM, so the same teardown that runs at
    // logout also runs here, before the plist is removed.
    run_ignore_failure("/bin/launchctl", &["bootout", &domain_target(uid)]);
    remove_file_ignore_missing(&plist_path)?;

    println!("tunmux session agent uninstalled.");
    println!("  plist: {}", plist_path.display());
    Ok(())
}

fn cmd_status() -> anyhow::Result<()> {
    let home = std::env::var("HOME").context("could not determine $HOME")?;
    let uid = getuid().as_raw();
    let plist_path = launch_agents_dir(&home).join(format!("{LABEL}.plist"));

    if !plist_path.exists() {
        println!("No session agent installed.");
        return Ok(());
    }

    let marker = if is_loaded(uid) { "🟢" } else { "🔘" };
    println!("{marker}  {}", plist_path.display());
    Ok(())
}

/// The long-lived agent body launchd actually executes. Reconciles once on
/// start (best-effort per connection: a broken one logs and does not stop
/// the others), then blocks until `SIGTERM` and reconciles the opposite
/// direction (disconnect) before returning.
///
/// `SIGTERM` is blocked *before* the initial reconcile runs, not after: this
/// agent's own installer (`cmd_install`) bootstraps it (which starts it
/// immediately via `RunAtLoad`) and then kickstarts it, which sends exactly
/// this signal almost immediately -- if it arrived during
/// `reconcile_connect_mine()` while still on the default disposition, the
/// process would simply die with no teardown at all. Blocking first means a
/// signal that arrives during startup just stays pending until `sigwait`
/// picks it up afterward, instead of being lost.
pub fn run() -> anyhow::Result<()> {
    block_sigterm().context("failed to block SIGTERM")?;
    reconcile_connect_mine();
    wait_for_pending_sigterm().context("failed to wait for SIGTERM")?;
    reconcile_disconnect_mine();
    Ok(())
}

fn reconcile_connect_mine() {
    let client = PrivilegedClient::new();
    let connections = match client.list_connections(ConnectionScope::Mine) {
        Ok(connections) => connections,
        Err(error) => {
            warn!(error = %error, "session_agent_list_failed");
            return;
        }
    };
    for conn in connections {
        if conn.start_mode != ConnectionStartMode::Automatic || conn.connected {
            continue;
        }
        if let Err(error) = client.connect_connection(conn.id, false) {
            warn!(id = %conn.id, error = %error, "session_agent_connect_failed");
        }
    }
}

fn reconcile_disconnect_mine() {
    let client = PrivilegedClient::new();
    let connections = match client.list_connections(ConnectionScope::Mine) {
        Ok(connections) => connections,
        Err(error) => {
            warn!(error = %error, "session_agent_teardown_list_failed");
            return;
        }
    };
    for conn in connections {
        if !conn.connected {
            continue;
        }
        if let Err(error) = client.disconnect_connection(conn.id) {
            warn!(id = %conn.id, error = %error, "session_agent_disconnect_failed");
        }
    }
}

/// Block `SIGTERM` for the calling thread so it queues as pending instead of
/// running the default disposition (process termination) the moment it
/// arrives. This process has no other threads on the `connection agent run`
/// path (no tokio runtime, no spawned workers), so blocking it here blocks
/// it process-wide in practice.
fn block_sigterm() -> anyhow::Result<()> {
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGTERM);
    mask.thread_block()?;
    Ok(())
}

/// Block the calling thread until the `SIGTERM` blocked by [`block_sigterm`]
/// is delivered, via a synchronous `sigwait` rather than an async signal
/// handler -- simpler and avoids the usual async-signal-safety pitfalls (no
/// work happens inside a handler at all; this just parks until the signal is
/// pending, which it may already be by the time this is called).
fn wait_for_pending_sigterm() -> anyhow::Result<()> {
    let mut mask = SigSet::empty();
    mask.add(Signal::SIGTERM);
    loop {
        if mask.wait()? == Signal::SIGTERM {
            return Ok(());
        }
    }
}

/// Whether launchd currently has the agent bootstrapped in the user's GUI domain.
fn is_loaded(uid: u32) -> bool {
    std::process::Command::new("/bin/launchctl")
        .args(["print", &domain_target(uid)])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Write the rendered plist to `path` atomically (temp file + rename), user
/// owned mode 0644.
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
    format!("gui/{uid}/{LABEL}")
}

/// Bail if running as root: the session agent is per-user (GUI domain), and
/// must not be installed via `sudo`.
fn refuse_if_root() -> anyhow::Result<()> {
    if geteuid().is_root() {
        anyhow::bail!(
            "run `tunmux connection agent install` as your normal user, not with sudo \
             (the session agent is per-user)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_plist_substitutes_all() {
        let rendered = render_plist(PLIST_TEMPLATE, "/opt/homebrew/bin/tunmux", "/Users/andi")
            .expect("render succeeds");

        assert!(rendered.contains("/opt/homebrew/bin/tunmux"));
        assert!(rendered.contains("/Users/andi"));
        assert!(!rendered.contains(BIN_PLACEHOLDER));
        assert!(!rendered.contains(HOME_PLACEHOLDER));
        assert!(rendered.contains(LABEL));
    }

    #[test]
    fn render_errors_when_placeholder_missing() {
        let template = PLIST_TEMPLATE.replace(BIN_PLACEHOLDER, "/usr/local/bin/tunmux");
        let err = render_plist(&template, "/opt/homebrew/bin/tunmux", "/Users/andi")
            .expect_err("missing bin placeholder should error");
        assert!(err.to_string().contains(BIN_PLACEHOLDER));
    }

    #[test]
    fn render_escapes_special_chars() {
        let rendered = render_plist(PLIST_TEMPLATE, "/opt/homebrew/bin/tunmux", "/Users/a&b")
            .expect("render succeeds");
        assert!(rendered.contains("/Users/a&amp;b"));
        assert!(!rendered.contains("/Users/a&b\""));
    }

    #[test]
    fn refuse_if_root_when_root() {
        if geteuid().is_root() {
            let err = refuse_if_root().expect_err("must refuse when root");
            assert!(err.to_string().contains("not with sudo"));
        } else {
            refuse_if_root().expect("must be a no-op when not root");
        }
    }
}
