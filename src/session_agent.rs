//! `wgd launchd agent ...`: installer + long-lived body for the Phase 4
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
use tracing::{debug, warn};

use crate::cli::AgentCommand;
use crate::launchctl::{remove_file_ignore_missing, run_checked, run_ignore_failure, xml_escape};
use crate::privileged_api::{
    ConnectionId, ConnectionScope, ConnectionStartMode, ConnectionSummary,
};
use crate::privileged_client::PrivilegedClient;

pub(crate) const LABEL: &str = "me.pansen.wgd.session-agent";

const PLIST_TEMPLATE: &str = include_str!("../etc/me.pansen.wgd.session-agent.plist");
const BIN_PLACEHOLDER: &str = "@WGD_BIN@";
const HOME_PLACEHOLDER: &str = "@WGD_HOME@";

pub fn dispatch(command: AgentCommand) -> anyhow::Result<()> {
    match command {
        AgentCommand::Install { force } => cmd_install(force),
        AgentCommand::Uninstall => cmd_uninstall(),
        AgentCommand::Status => cmd_status(),
        AgentCommand::Run => run(),
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

/// Re-render and re-bootstrap the agent, for `wgd launchd reload`.
pub(crate) fn reinstall() -> anyhow::Result<()> {
    cmd_install(true)
}

fn cmd_install(force: bool) -> anyhow::Result<()> {
    refuse_if_root()?;

    let home = std::env::var("HOME").context("could not determine $HOME")?;
    let uid = getuid().as_raw();
    let bin = std::env::current_exe().context("failed to determine the running wgd binary path")?;
    let bin_str = bin
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("wgd binary path is not valid UTF-8: {}", bin.display()))?;

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
    //
    // `enable` runs first to clear any stale "disabled" override (left by a
    // previous uninstall, or by toggling the agent off in System Settings ->
    // Login Items) -- bootstrapping a disabled label fails with EIO, same
    // failure mode `launchd::bootstrap` guards against for the system daemon.
    run_ignore_failure("/bin/launchctl", &["bootout", &domain_target(uid)]);
    run_checked("/bin/launchctl", &["enable", &domain_target(uid)])?;
    run_checked(
        "/bin/launchctl",
        &["bootstrap", &gui_domain(uid), plist_path_str],
    )?;

    println!("wgd session agent installed.");
    println!("  plist:  {}", plist_path.display());
    println!("  binary: {}", bin.display());
    println!(
        "  it will connect every `Automatic` connection owned by this user on login \
         (`wgd connection mode <id> automatic`) and disconnect them again on logout."
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

    println!("wgd session agent uninstalled.");
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
/// `SIGTERM` is blocked *before* the initial reconcile runs, not after: a
/// re-install (`cmd_install`) sends this same signal via `bootout` to tear
/// down any already-running instance just before `bootstrap` starts the new
/// one -- if that signal arrived during `reconcile_connect_mine()` while
/// still on the default disposition, the process would simply die with no
/// teardown at all. Blocking first means a signal that arrives during
/// startup just stays pending until `sigwait` picks it up afterward, instead
/// of being lost.
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
    for id in connect_candidates(&connections) {
        if let Err(error) = client.connect_connection(id, false) {
            warn!(id = %id, error = %error, "session_agent_connect_failed");
        }
    }
}

/// Which of `connections` (already scoped to `Mine`) this agent start should
/// bring up: `Automatic`, not currently connected, and not explicitly
/// disconnected by the user since (see
/// `ConnectionSummary::user_disconnected` and
/// `issues/session-agent-overrides-disconnect.md` -- without this last
/// check, a `KeepAlive` relaunch of this agent mid-session would silently
/// undo an explicit `wgd connection disconnect`). Split out from
/// `reconcile_connect_mine` so the selection criteria can be unit tested
/// without a real `PrivilegedClient`, mirroring
/// `connection_store::boot_reconcile_candidates`.
fn connect_candidates(connections: &[ConnectionSummary]) -> Vec<ConnectionId> {
    let mut ids = Vec::new();
    for conn in connections {
        if conn.start_mode != ConnectionStartMode::Automatic || conn.connected {
            continue;
        }
        if conn.user_disconnected {
            debug!(
                id = %conn.id,
                "session_agent_skipping_user_disconnected_connection"
            );
            continue;
        }
        ids.push(conn.id);
    }
    ids
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
        // Logout teardown, not the user asking this tunnel to stay down: a
        // fresh login must still bring an `Automatic` connection back up, so
        // this must not persist `user_disconnected` (see
        // `PrivilegedClient::disconnect_connection_for_teardown`'s doc
        // comment).
        if let Err(error) = client.disconnect_connection_for_teardown(conn.id) {
            warn!(id = %conn.id, error = %error, "session_agent_disconnect_failed");
        }
    }
}

/// Block `SIGTERM` for the calling thread so it queues as pending instead of
/// running the default disposition (process termination) the moment it
/// arrives. This process has no other threads on the `launchd agent run`
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
            "run `wgd launchd agent install` as your normal user, not with sudo \
             (the session agent is per-user)"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(
        start_mode: ConnectionStartMode,
        connected: bool,
        user_disconnected: bool,
    ) -> ConnectionSummary {
        ConnectionSummary {
            id: ConnectionId::new(),
            global: false,
            owner_uid: Some(501),
            start_mode,
            name: None,
            interface: "wg-aaaaaaaa".to_string(),
            connected,
            user_disconnected,
            addresses: Vec::new(),
            dns_servers: Vec::new(),
            mtu: None,
            peers: Vec::new(),
            fingerprint: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    #[test]
    fn connect_candidates_selects_only_automatic_disconnected_and_not_user_disconnected() {
        let automatic_down = sample(ConnectionStartMode::Automatic, false, false);
        let manual_down = sample(ConnectionStartMode::Manual, false, false);
        let automatic_up = sample(ConnectionStartMode::Automatic, true, false);
        // The regression case this exists for: an `Automatic` connection the
        // user explicitly disconnected must not come back just because the
        // agent process bounced (see
        // `issues/session-agent-overrides-disconnect.md`).
        let automatic_user_disconnected = sample(ConnectionStartMode::Automatic, false, true);

        let candidates = connect_candidates(&[
            automatic_down.clone(),
            manual_down,
            automatic_up,
            automatic_user_disconnected,
        ]);
        assert_eq!(candidates, vec![automatic_down.id]);
    }

    #[test]
    fn connect_candidates_is_empty_for_no_connections() {
        assert_eq!(connect_candidates(&[]), Vec::new());
    }

    #[test]
    fn render_plist_substitutes_all() {
        let rendered = render_plist(PLIST_TEMPLATE, "/opt/homebrew/bin/wgd", "/Users/andi")
            .expect("render succeeds");

        assert!(rendered.contains("/opt/homebrew/bin/wgd"));
        assert!(rendered.contains("/Users/andi"));
        assert!(!rendered.contains(BIN_PLACEHOLDER));
        assert!(!rendered.contains(HOME_PLACEHOLDER));
        assert!(rendered.contains(LABEL));
    }

    #[test]
    fn render_errors_when_placeholder_missing() {
        let template = PLIST_TEMPLATE.replace(BIN_PLACEHOLDER, "/usr/local/bin/wgd");
        let err = render_plist(&template, "/opt/homebrew/bin/wgd", "/Users/andi")
            .expect_err("missing bin placeholder should error");
        assert!(err.to_string().contains(BIN_PLACEHOLDER));
    }

    #[test]
    fn render_escapes_special_chars() {
        let rendered = render_plist(PLIST_TEMPLATE, "/opt/homebrew/bin/wgd", "/Users/a&b")
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
