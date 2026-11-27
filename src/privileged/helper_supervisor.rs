//! Helper supervision: notice a userspace helper that ends on its own and
//! bring its connection back when it is `Automatic`.
//!
//! The daemon never stays a helper's parent (helpers daemonize), so it watches
//! each helper's pid with the same kqueue [`ExitWatcher`] the DNS custody watch
//! uses. When one exits, [`handle_exit`] decides under the connection's lock:
//!
//! - No `active/<id>.json` (a disconnect cleared it) or a newer live helper on
//!   the interface (a reconnect replaced it): expected, nothing to do.
//! - Otherwise the helper ended without the daemon asking. That is logged as a
//!   warning with the reason the helper recorded (`crate::helper_exit`).
//! - A requested exit (SIGTERM, SIGINT, socket removed by someone else) is
//!   left alone. A failure (`device_error`, `failed`) or a crash (no record)
//!   of an `Automatic` connection without `user_disconnected` is restarted
//!   with backoff, after waiting for a usable network: a helper that died
//!   because the network went away would otherwise fail again right away.
//!
//! Each watch holds one resident count, so a daemon with a supervised tunnel
//! does not idle-exit.
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use system_configuration::dynamic_store::SCDynamicStoreBuilder;
use tracing::{debug, info, warn};

use crate::helper_exit::HelperExitReason;
use crate::privileged_api::ConnectionId;

use super::connection_store::{self, ConnectionStartMode};
use super::dns_watch::{self, ExitWatcher, RegisterError};

/// Delay before each restart attempt; the last entry repeats.
const RESTART_BACKOFF: [Duration; 7] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(32),
    Duration::from_secs(60),
];

/// Failed connects (with a network present) before giving up.
const MAX_RESTART_ATTEMPTS: usize = 12;

/// How often to look for a network again while there is none.
const NETWORK_POLL: Duration = Duration::from_secs(2);

/// After `NOTE_EXIT`, how long to wait for the helper's socket to stop
/// accepting (see `dns_watch`'s `EXIT_GRACE`).
const EXIT_GRACE: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
struct SupervisedHelper {
    connection_id: ConnectionId,
    interface: String,
}

static WATCHER: OnceLock<ExitWatcher<SupervisedHelper>> = OnceLock::new();

/// Start the exit watcher. Without it (stdio transport, a kqueue failure)
/// helpers simply run unsupervised.
pub(super) fn init() {
    let result = ExitWatcher::new(
        "helper-supervisor",
        dns_watch::resident_count(),
        |pid, helper: SupervisedHelper| {
            dns_watch::spawn_held(move || handle_exit(pid, helper));
        },
    );
    match result {
        Ok(watcher) => {
            let _ = WATCHER.set(watcher);
        }
        Err(error) => warn!(error = %error, "privileged_helper_supervisor_unavailable"),
    }
}

/// Supervise the helper currently running for `id` on `interface`. Called
/// after every successful connect; a helper already watched is ignored.
pub(super) fn watch(id: ConnectionId, interface: &str) {
    let Some(watcher) = WATCHER.get() else {
        return;
    };
    let pid = match super::commands::read_gotatun_pid(&super::commands::gotatun_pid_path(interface))
    {
        Ok(Some(pid)) => pid,
        Ok(None) => {
            warn!(id = %id, interface, "privileged_helper_supervisor_no_pid");
            return;
        }
        Err(error) => {
            warn!(id = %id, interface, error = %error, "privileged_helper_supervisor_no_pid");
            return;
        }
    };
    let helper = SupervisedHelper {
        connection_id: id,
        interface: interface.to_string(),
    };
    match watcher.register(pid, helper) {
        Ok(()) => debug!(id = %id, interface, pid, "privileged_helper_supervisor_watching"),
        Err(RegisterError::AlreadyWatched) => {}
        Err(RegisterError::Gone(helper)) => {
            dns_watch::spawn_held(move || handle_exit(pid, helper));
        }
        Err(RegisterError::Io(errno)) => warn!(
            id = %id,
            interface,
            error = %errno,
            "privileged_helper_supervisor_register_failed"
        ),
    }
}

/// At daemon start: supervise every helper that is already running, e.g.
/// after launchd restarted the daemon underneath live tunnels.
pub(super) fn watch_running() {
    let connections = match connection_store::load_all() {
        Ok(connections) => connections,
        Err(error) => {
            warn!(error = %error, "privileged_helper_supervisor_listing_failed");
            return;
        }
    };
    for conn in connections {
        if connection_store::is_active(conn.id).unwrap_or(false)
            && connection_store::helper_is_live_without_record(&conn.interface)
        {
            watch(conn.id, &conn.interface);
        }
    }
}

/// What to do after a supervised helper exited.
#[derive(Debug, PartialEq, Eq)]
enum ExitPlan {
    /// The daemon (or a newer helper) already accounts for it.
    Expected,
    /// Somebody asked the helper to stop, or the connection must not come
    /// back on its own: log it and forget the active record.
    Leave,
    /// Bring the connection back.
    Restart,
}

/// The decision behind [`handle_exit`], given what was read under the
/// connection's lock. Split out so it can be tested without a daemon.
fn plan_exit(
    active: bool,
    newer_helper_live: bool,
    reason: Option<HelperExitReason>,
    start_mode: ConnectionStartMode,
    user_disconnected: bool,
) -> ExitPlan {
    if !active || newer_helper_live {
        return ExitPlan::Expected;
    }
    if reason.is_some_and(HelperExitReason::requested)
        || start_mode != ConnectionStartMode::Automatic
        || user_disconnected
    {
        return ExitPlan::Leave;
    }
    ExitPlan::Restart
}

fn reason_label(reason: Option<HelperExitReason>) -> &'static str {
    reason.map_or("no_exit_record", HelperExitReason::as_str)
}

fn handle_exit(pid: u32, helper: SupervisedHelper) {
    let SupervisedHelper {
        connection_id: id,
        interface,
    } = helper;
    let deadline = Instant::now() + EXIT_GRACE;
    while connection_store::helper_is_live_without_record(&interface) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(100));
    }

    // A disconnect or reconnect in flight holds this lock; once it is ours,
    // the active record says whether the daemon still wants this tunnel up.
    let conn_lock = match connection_store::lock_connection_patient(id) {
        Ok(lock) => lock,
        Err(error) => {
            warn!(id = %id, interface, pid, error = %error, "privileged_helper_supervisor_lock_failed");
            return;
        }
    };
    let active = match connection_store::load_active(id) {
        Ok(active) => active,
        Err(error) => {
            warn!(id = %id, interface, pid, error = %error, "privileged_helper_supervisor_active_read_failed");
            return;
        }
    };
    let stored = match connection_store::load(id) {
        Ok(Some(stored)) => stored,
        Ok(None) => {
            debug!(id = %id, interface, pid, "privileged_helper_exit_connection_removed");
            return;
        }
        Err(error) => {
            warn!(id = %id, interface, pid, error = %error, "privileged_helper_supervisor_load_failed");
            return;
        }
    };
    let reason = super::commands::read_helper_exit_reason(&interface);
    let newer_helper_live = connection_store::helper_is_live_without_record(&interface);
    let plan = plan_exit(
        active.is_some(),
        newer_helper_live,
        reason,
        stored.start_mode,
        stored.user_disconnected,
    );
    if plan == ExitPlan::Expected {
        debug!(id = %id, interface, pid, reason = reason_label(reason), "privileged_helper_exit_expected");
        return;
    }

    if reason.is_some_and(HelperExitReason::requested) {
        // Stopped by someone other than the daemon (launchd, shutdown, kill).
        info!(
            id = %id,
            interface,
            pid,
            reason = reason_label(reason),
            "privileged_helper_stopped_externally"
        );
    } else {
        warn!(
            id = %id,
            interface,
            pid,
            reason = reason_label(reason),
            start_mode = ?stored.start_mode,
            user_disconnected = stored.user_disconnected,
            restart = plan == ExitPlan::Restart,
            "privileged_helper_exited_unexpectedly"
        );
    }
    crate::status_notify::post(crate::status_notify::Trigger::HelperExited {
        interface: &interface,
        pid,
    });

    if plan == ExitPlan::Leave {
        if let Err(error) = connection_store::clear_active(&conn_lock, id) {
            warn!(id = %id, interface, error = %error, "privileged_helper_supervisor_clear_failed");
        }
        return;
    }
    let debug_enabled = active.is_some_and(|active| active.debug);
    drop(conn_lock);
    restart(id, &interface, debug_enabled);
}

/// Bring `id` back up, with backoff and only while a network is present.
/// Re-checks under the lock before every attempt whether the connection is
/// still wanted: an explicit disconnect, a session teardown or an explicit
/// connect in the meantime all end the loop.
fn restart(id: ConnectionId, interface: &str, debug_enabled: bool) {
    let mut failures = 0;
    loop {
        std::thread::sleep(RESTART_BACKOFF[failures.min(RESTART_BACKOFF.len() - 1)]);
        wait_for_network(id, interface);

        let conn_lock = match connection_store::lock_connection_patient(id) {
            Ok(lock) => lock,
            Err(error) => {
                warn!(id = %id, interface, error = %error, "privileged_helper_restart_lock_failed");
                failures += 1;
                if failures >= MAX_RESTART_ATTEMPTS {
                    return;
                }
                continue;
            }
        };
        let still_wanted = match (
            connection_store::load_active(id),
            connection_store::load(id),
        ) {
            (Ok(Some(_)), Ok(Some(stored))) => {
                stored.start_mode == ConnectionStartMode::Automatic && !stored.user_disconnected
            }
            _ => false,
        };
        if !still_wanted || connection_store::helper_is_live_without_record(interface) {
            info!(id = %id, interface, "privileged_helper_restart_no_longer_needed");
            return;
        }

        match super::connection_ops::connect(&conn_lock, id, debug_enabled) {
            Ok(()) => {
                info!(id = %id, interface, failures, "privileged_helper_restarted");
                return;
            }
            Err(error) => {
                failures += 1;
                warn!(
                    id = %id,
                    interface,
                    attempt = failures,
                    error = %error,
                    "privileged_helper_restart_failed"
                );
                if failures >= MAX_RESTART_ATTEMPTS {
                    warn!(id = %id, interface, attempts = failures, "privileged_helper_restart_gave_up");
                    if let Err(error) = connection_store::clear_active(&conn_lock, id) {
                        warn!(id = %id, interface, error = %error, "privileged_helper_supervisor_clear_failed");
                    }
                    return;
                }
            }
        }
    }
}

/// Block until macOS has a primary IPv4 or IPv6 network again. Waiting does
/// not count as a failed attempt.
fn wait_for_network(id: ConnectionId, interface: &str) {
    let started = Instant::now();
    let mut logged = false;
    while !network_available() {
        if !logged {
            info!(id = %id, interface, "privileged_helper_restart_waiting_for_network");
            logged = true;
        }
        std::thread::sleep(NETWORK_POLL);
    }
    if logged {
        info!(
            id = %id,
            interface,
            waited_ms = started.elapsed().as_millis() as u64,
            "privileged_helper_restart_network_available"
        );
    }
}

/// Whether configd publishes a primary service: `State:/Network/Global/IPv4`
/// or `.../IPv6` exist only while some interface has a usable route. If the
/// store cannot be opened, assume a network rather than wait forever.
fn network_available() -> bool {
    let Some(store) = SCDynamicStoreBuilder::new("wgd-helper-supervisor").build() else {
        return true;
    };
    store.get("State:/Network/Global/IPv4").is_some()
        || store.get("State:/Network/Global/IPv6").is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    const AUTO: ConnectionStartMode = ConnectionStartMode::Automatic;

    #[test]
    fn exits_the_daemon_accounts_for_are_expected() {
        // A disconnect cleared the active record.
        assert_eq!(
            plan_exit(
                false,
                false,
                Some(HelperExitReason::ControlSocketRemoved),
                AUTO,
                false
            ),
            ExitPlan::Expected
        );
        // A reconnect already started the next helper.
        assert_eq!(
            plan_exit(
                true,
                true,
                Some(HelperExitReason::ControlSocketRemoved),
                AUTO,
                false
            ),
            ExitPlan::Expected
        );
    }

    #[test]
    fn failures_and_crashes_of_automatic_connections_restart() {
        assert_eq!(
            plan_exit(
                true,
                false,
                Some(HelperExitReason::DeviceError),
                AUTO,
                false
            ),
            ExitPlan::Restart
        );
        assert_eq!(
            plan_exit(true, false, Some(HelperExitReason::Failed), AUTO, false),
            ExitPlan::Restart
        );
        // SIGKILL or a panic leaves no record.
        assert_eq!(plan_exit(true, false, None, AUTO, false), ExitPlan::Restart);
    }

    #[test]
    fn requested_exits_manual_and_user_disconnected_connections_stay_down() {
        for reason in [
            HelperExitReason::Sigterm,
            HelperExitReason::Sigint,
            HelperExitReason::ControlSocketRemoved,
        ] {
            assert_eq!(
                plan_exit(true, false, Some(reason), AUTO, false),
                ExitPlan::Leave
            );
        }
        assert_eq!(
            plan_exit(
                true,
                false,
                Some(HelperExitReason::DeviceError),
                ConnectionStartMode::Manual,
                false
            ),
            ExitPlan::Leave
        );
        assert_eq!(
            plan_exit(true, false, Some(HelperExitReason::DeviceError), AUTO, true),
            ExitPlan::Leave
        );
    }

    #[test]
    fn backoff_starts_fast_and_caps_at_a_minute() {
        assert_eq!(RESTART_BACKOFF[0], Duration::from_secs(1));
        assert_eq!(
            RESTART_BACKOFF[MAX_RESTART_ATTEMPTS.min(RESTART_BACKOFF.len() - 1)],
            Duration::from_secs(60)
        );
    }
}
