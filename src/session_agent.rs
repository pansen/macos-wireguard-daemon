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
    let installed = install_agent(force)?;
    println!("wgd session agent installed.");
    println!("  plist:  {}", installed.plist.display());
    println!("  binary: {}", installed.bin.display());
    println!(
        "  it will connect every `Automatic` connection owned by this user on login \
         (`wgd connection mode <id> automatic`) and disconnect them again on logout."
    );
    Ok(())
}

struct InstalledAgent {
    plist: PathBuf,
    bin: PathBuf,
}

/// Render the plist, write it and bootstrap the agent, without printing.
fn install_agent(force: bool) -> anyhow::Result<InstalledAgent> {
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

    Ok(InstalledAgent {
        plist: plist_path,
        bin,
    })
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
        // Reconciliation, not explicit user intent: the daemon re-checks
        // `user_disconnected` under the connection's lock before acting, so
        // a disconnect that commits after `connections` was snapshotted
        // above still wins even though this candidate list can't see it
        // (see `ConnectReason::Reconciliation`'s doc comment).
        if let Err(error) = client.connect_connection_for_reconciliation(id, false) {
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
pub(crate) fn is_loaded(uid: u32) -> bool {
    std::process::Command::new("/bin/launchctl")
        .args(["print", &domain_target(uid)])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Where a user's session agent stands. The rule this exists for: a per-user
/// (non-global) `Automatic` connection only comes up at login if its owner's
/// agent is active, so anything but `Loaded` means such a connection silently
/// stays down after a reboot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AgentState {
    /// The plist is missing.
    NotInstalled,
    /// Installed, but launchd has the label disabled (toggled off in System
    /// Settings -> Login Items, or a stale override). Possibly deliberate.
    Disabled,
    /// Installed and enabled, but not bootstrapped into the GUI domain.
    NotLoaded,
    Loaded,
}

impl AgentState {
    pub(crate) fn describe(self) -> &'static str {
        match self {
            Self::NotInstalled => "not installed",
            Self::Disabled => "disabled in Login Items",
            Self::NotLoaded => "installed but not loaded",
            Self::Loaded => "loaded",
        }
    }

    /// The command (or setting) that gets the agent back to `Loaded`.
    pub(crate) fn fix(self) -> &'static str {
        match self {
            Self::NotInstalled => "run `wgd launchd agent install`",
            Self::Disabled => {
                "re-enable it in System Settings -> General -> Login Items, \
                 or run `wgd launchd agent install --force`"
            }
            Self::NotLoaded => "run `wgd launchd agent install --force`",
            Self::Loaded => "",
        }
    }
}

/// What to do about an agent state when a per-user `Automatic` connection
/// depends on it.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AgentPlan {
    Nothing,
    Install,
    Warn,
}

/// `can_install` is false for root callers that have no way to install the
/// agent as the user. `Disabled` is never fixed automatically: the user may
/// have switched it off on purpose.
pub(crate) fn plan_for(state: AgentState, can_install: bool) -> AgentPlan {
    match state {
        AgentState::Loaded => AgentPlan::Nothing,
        AgentState::Disabled => AgentPlan::Warn,
        AgentState::NotInstalled | AgentState::NotLoaded if can_install => AgentPlan::Install,
        AgentState::NotInstalled | AgentState::NotLoaded => AgentPlan::Warn,
    }
}

/// State of the agent for the user `uid` whose home directory is `home`.
pub(crate) fn agent_state(uid: u32, home: &Path) -> AgentState {
    if !launch_agents_dir(&home.to_string_lossy())
        .join(format!("{LABEL}.plist"))
        .exists()
    {
        AgentState::NotInstalled
    } else if is_disabled(uid) {
        AgentState::Disabled
    } else if !is_loaded(uid) {
        AgentState::NotLoaded
    } else {
        AgentState::Loaded
    }
}

fn is_disabled(uid: u32) -> bool {
    std::process::Command::new("/bin/launchctl")
        .args(["print-disabled", &gui_domain(uid)])
        .stderr(Stdio::null())
        .output()
        .map(|out| parse_print_disabled(&String::from_utf8_lossy(&out.stdout), LABEL))
        .unwrap_or(false)
}

/// Whether `launchctl print-disabled` output lists `label` as disabled.
/// Current macOS prints `"label" => disabled`; older releases print
/// `"label" => true`.
fn parse_print_disabled(output: &str, label: &str) -> bool {
    let key = format!("\"{label}\"");
    output.lines().any(|line| {
        line.trim()
            .strip_prefix(&key)
            .and_then(|rest| rest.trim_start().strip_prefix("=>"))
            .is_some_and(|value| matches!(value.trim().trim_end_matches(';'), "disabled" | "true"))
    })
}

/// The per-user `Automatic` connections of `uid`: the ones that need the
/// session agent to come up at login.
pub(crate) fn agent_dependents(
    connections: &[ConnectionSummary],
    uid: u32,
) -> Vec<&ConnectionSummary> {
    connections
        .iter()
        .filter(|conn| {
            !conn.global
                && conn.start_mode == ConnectionStartMode::Automatic
                && conn.owner_uid == Some(uid)
        })
        .collect()
}

/// One-line explanation that `names` will not connect at login while the
/// agent is in `state`, with the fix.
pub(crate) fn agent_problem_message(state: AgentState, names: &[String]) -> String {
    format!(
        "session agent {}: {} (per-user, start mode Automatic) will NOT connect at login. Fix: {}.",
        state.describe(),
        names.join(", "),
        state.fix()
    )
}

/// `(uid, home)` of the user whose session agent matters for this process:
/// the caller itself, or the `sudo` invoker when running as root.
pub(crate) fn target_user() -> Option<(u32, PathBuf)> {
    if geteuid().is_root() {
        crate::launchd::resolve_target_user()
            .filter(|(_, uid, _)| *uid != 0)
            .map(|(_, uid, home)| (uid, home))
    } else {
        let uid = getuid();
        nix::unistd::User::from_uid(uid)
            .ok()
            .flatten()
            .map(|user| (uid.as_raw(), user.dir))
    }
}

/// Write-path guard, run after a command that made (or confirmed) a per-user
/// `Automatic` connection: make sure the owner's agent will bring it up at
/// login. Installs a missing or unloaded agent when running as the user,
/// warns loudly otherwise. Never fails the caller: the command it follows
/// already succeeded.
///
/// Installing starts the agent, whose startup reconcile connects every
/// `Automatic` connection that is down (and not `user_disconnected`); one that
/// is already connected is skipped by `connect_candidates`.
pub(crate) fn ensure_for_automatic(client: &PrivilegedClient) {
    let Some((uid, home)) = target_user() else {
        return;
    };
    let is_root = geteuid().is_root();
    let scope = if is_root {
        ConnectionScope::All
    } else {
        ConnectionScope::Mine
    };
    let connections = match client.list_connections(scope) {
        Ok(connections) => connections,
        Err(error) => {
            debug!(error = %error, "session_agent_check_list_failed");
            return;
        }
    };
    let names: Vec<String> = agent_dependents(&connections, uid)
        .iter()
        .map(|conn| conn.label())
        .collect();
    if names.is_empty() {
        return;
    }
    let state = agent_state(uid, &home);
    match plan_for(state, !is_root) {
        AgentPlan::Nothing => {}
        AgentPlan::Warn => eprintln!(
            "{}",
            crate::ui::warning(&format!(
                "Warning: {}",
                agent_problem_message(state, &names)
            ))
        ),
        AgentPlan::Install => match install_agent(true) {
            Ok(installed) => println!(
                "Installed the session agent ({}, was {}): it brings up {} at login.",
                installed.plist.display(),
                state.describe(),
                names.join(", ")
            ),
            Err(error) => eprintln!(
                "{}",
                crate::ui::warning(&format!(
                    "Warning: could not install the session agent ({error:#}); {}",
                    agent_problem_message(state, &names)
                ))
            ),
        },
    }
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
            source_path: None,
            dns_dynamic_store: false,
            bypass_links: Vec::new(),
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
    fn parse_print_disabled_detects_disabled_label() {
        let output = "disabled services = {\n\t\"com.example.a\" => enabled\n\t\"me.pansen.wgd.session-agent\" => disabled\n}\n";
        assert!(parse_print_disabled(output, LABEL));
        // Older macOS: `true` means disabled.
        let old = "{\n\t\"me.pansen.wgd.session-agent\" => true;\n}";
        assert!(parse_print_disabled(old, LABEL));
    }

    #[test]
    fn parse_print_disabled_ignores_enabled_absent_and_other_labels() {
        let enabled = "{\n\t\"me.pansen.wgd.session-agent\" => enabled\n}";
        assert!(!parse_print_disabled(enabled, LABEL));
        let old_enabled = "{\n\t\"me.pansen.wgd.session-agent\" => false;\n}";
        assert!(!parse_print_disabled(old_enabled, LABEL));
        let other = "{\n\t\"me.pansen.wgd.session-agent2\" => disabled\n\t\"other\" => disabled\n}";
        assert!(!parse_print_disabled(other, LABEL));
        assert!(!parse_print_disabled("", LABEL));
    }

    #[test]
    fn plan_per_state() {
        use AgentPlan::*;
        use AgentState::*;
        assert_eq!(plan_for(Loaded, true), Nothing);
        assert_eq!(plan_for(Loaded, false), Nothing);
        assert_eq!(plan_for(NotInstalled, true), Install);
        assert_eq!(plan_for(NotLoaded, true), Install);
        assert_eq!(plan_for(NotInstalled, false), Warn);
        assert_eq!(plan_for(NotLoaded, false), Warn);
        // Never re-enabled behind the user's back.
        assert_eq!(plan_for(Disabled, true), Warn);
        assert_eq!(plan_for(Disabled, false), Warn);
    }

    #[test]
    fn agent_dependents_are_per_user_automatic_and_owned() {
        let mut mine = sample(ConnectionStartMode::Automatic, false, false);
        mine.name = Some("work".into());
        let manual = sample(ConnectionStartMode::Manual, false, false);
        let mut global = sample(ConnectionStartMode::Automatic, false, false);
        global.global = true;
        global.owner_uid = None;
        let mut other_user = sample(ConnectionStartMode::Automatic, false, false);
        other_user.owner_uid = Some(502);

        let all = [mine.clone(), manual, global, other_user];
        let deps = agent_dependents(&all, 501);
        assert_eq!(deps.len(), 1);
        assert_eq!(deps[0].id, mine.id);
        assert!(agent_dependents(&all, 503).is_empty());
    }

    #[test]
    fn problem_message_names_connections_and_fix() {
        let names = vec!["a".to_string(), "b".to_string()];
        let msg = agent_problem_message(AgentState::NotInstalled, &names);
        assert!(msg.contains("a, b"));
        assert!(msg.contains("NOT connect at login"));
        assert!(msg.contains("wgd launchd agent install"));
        assert!(agent_problem_message(AgentState::NotLoaded, &names)
            .contains("wgd launchd agent install --force"));
        let disabled = agent_problem_message(AgentState::Disabled, &names);
        assert!(disabled.contains("Login Items"));
        assert!(disabled.contains("--force"));
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
