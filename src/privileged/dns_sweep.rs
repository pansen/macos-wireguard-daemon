//! DNS custody sweep: restore the DNS of helpers that died without teardown.
//!
//! See `issues/dns-crash-recovery.md`. The decision of what to do is a pure
//! function ([`plan_dns_sweep`]); everything around it (reading records and
//! live DNS, calling `networksetup`, rewriting records) is thin I/O.
use std::collections::HashSet;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::dns_custody::{self, DnsCustodyRecord, DnsCustodyService, RecordRead};
use crate::error::Result;
use crate::macos_dns;
use crate::privileged_api::{ConnectionId, DnsCustodyEntry, DnsCustodyStatus, DnsRestoreEvent};

use super::connection_ops::lock_system_network_mutation;
use super::connection_store;

/// A custody record together with the liveness verdict for its helper.
#[derive(Debug, Clone)]
pub(super) struct RecordState {
    pub record: DnsCustodyRecord,
    pub helper_live: bool,
}

/// The DNS list of one stored connection, for the record-less fallback.
#[derive(Debug, Clone)]
pub(super) struct StoredDns {
    pub servers: Vec<String>,
    pub helper_live: bool,
}

/// One step of a sweep, decided by [`plan_dns_sweep`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Action {
    /// The record's helper is alive; nothing to do.
    SkipLive { interface: String },
    /// The service still shows the tunnel DNS: put the recorded original back.
    Restore {
        interface: String,
        service: String,
        servers: Option<Vec<String>>,
        search_domains: Option<Vec<String>>,
    },
    /// Someone changed the DNS after the crash: leave it, forget the service.
    ServiceChanged { interface: String, service: String },
    /// The service is not in the current location's listing: keep it recorded.
    ServiceAbsent { interface: String, service: String },
    /// No record, but the DNS exactly matches a stored tunnel's list.
    ClearStray {
        service: String,
        servers: Vec<String>,
    },
}

/// Decide what a sweep does. `live_dns` is the current listing: one entry per
/// network service with its live DNS (`None` = nothing set). A service missing
/// from it is not in the current location.
pub(super) fn plan_dns_sweep(
    records: &[RecordState],
    live_dns: &[(String, Option<Vec<String>>)],
    stored: &[StoredDns],
) -> Vec<Action> {
    let live_of = |service: &str| -> Option<&Option<Vec<String>>> {
        live_dns
            .iter()
            .find(|(name, _)| name == service)
            .map(|(_, dns)| dns)
    };
    let mut actions = Vec::new();

    for state in records {
        let record = &state.record;
        if state.helper_live {
            actions.push(Action::SkipLive {
                interface: record.interface.clone(),
            });
            continue;
        }
        for service in &record.services {
            let interface = record.interface.clone();
            let name = service.service.clone();
            actions.push(match live_of(&service.service) {
                None => Action::ServiceAbsent {
                    interface,
                    service: name,
                },
                Some(live) if macos_dns::dns_lists_equal(live.as_deref(), &record.tunnel_dns) => {
                    Action::Restore {
                        interface,
                        service: name,
                        servers: service.original_dns_servers.clone(),
                        search_domains: service.original_search_domains.clone(),
                    }
                }
                Some(_) => Action::ServiceChanged {
                    interface,
                    service: name,
                },
            });
        }
    }

    // Fallback for strays nobody has a record for. A service listed in any
    // record is owned by that record (live helper, or handled above).
    let recorded: HashSet<&str> = records
        .iter()
        .flat_map(|state| state.record.services.iter().map(|s| s.service.as_str()))
        .collect();
    for (service, live) in live_dns {
        if recorded.contains(service.as_str()) {
            continue;
        }
        let Some(live) = live else { continue };
        let owned_by_live_tunnel = stored
            .iter()
            .any(|dns| dns.helper_live && macos_dns::dns_lists_equal(Some(live), &dns.servers));
        let matches_dead_tunnel = stored
            .iter()
            .any(|dns| !dns.helper_live && macos_dns::dns_lists_equal(Some(live), &dns.servers));
        if matches_dead_tunnel && !owned_by_live_tunnel {
            actions.push(Action::ClearStray {
                service: service.clone(),
                servers: live.clone(),
            });
        }
    }

    actions
}

/// Where a custody record stands after a sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum RecordStatus {
    /// Its helper is alive; the daemon watches it.
    Live,
    /// Dead helper and at least one service in the current location still
    /// waits to be restored (a restore failed): retry.
    Restorable,
    /// Dead helper, but every service belongs to another network location.
    /// Retried on daemon start only, never keeps the daemon resident.
    Deferred,
}

pub(super) fn classify_record(
    helper_live: bool,
    services: &[DnsCustodyService],
    listed: &[String],
) -> RecordStatus {
    if helper_live {
        RecordStatus::Live
    } else if services.iter().any(|s| listed.contains(&s.service)) {
        RecordStatus::Restorable
    } else {
        RecordStatus::Deferred
    }
}

/// Whether the `dns-custody/watch` sentinel (and with it launchd's KeepAlive)
/// is still needed: a live helper or a restorable record. Location-deferred
/// records do not count, or the daemon would stay resident for a service that
/// may never come back.
pub(super) fn sentinel_wanted(statuses: &[RecordStatus]) -> bool {
    statuses
        .iter()
        .any(|status| matches!(status, RecordStatus::Live | RecordStatus::Restorable))
}

/// What one sweep did. `died` lists the connections whose crashed helper left a
/// record behind, so the caller can clear their stale active marker.
#[derive(Debug, Default)]
pub(super) struct SweepSummary {
    pub restored: usize,
    pub cleared: usize,
    pub skipped_live: usize,
    /// Some restore or clear failed; the record stays for a retry.
    pub failed: usize,
    pub died: Vec<(ConnectionId, String)>,
    /// Services restored per crashed connection: (id, interface, services).
    pub restored_by: Vec<(ConnectionId, String, Vec<String>)>,
    /// What remains in `dns-custody/`; filled in by [`run_sweep`].
    pub custody: super::dns_watch::CustodyState,
}

/// Which records a sweep looks at.
pub(super) enum Scope<'a> {
    /// Every record, plus the record-less fallback.
    All,
    /// Only this interface's record, no fallback.
    Interface(&'a str),
}

/// Sweep everything, once, under the system network mutation lock, then clear
/// the stale active marker of every connection whose helper crashed.
///
/// The marker is cleared after the network lock is released: connect takes the
/// connection lock first and the network lock second, and the sweep must not
/// invert that order.
pub(super) fn sweep_dead_dns_custody() -> Result<SweepSummary> {
    run_sweep(Scope::All)
}

/// Same for the one record of `interface` (exit watch, connect-time check).
pub(super) fn sweep_interface(interface: &str) -> Result<SweepSummary> {
    run_sweep(Scope::Interface(interface))
}

fn run_sweep(scope: Scope<'_>) -> Result<SweepSummary> {
    let summary = {
        let _network_lock = lock_system_network_mutation()?;
        let mut summary = sweep_locked(scope)?;
        summary.custody = super::dns_watch::settle_locked();
        summary
    };
    for (id, interface) in &summary.died {
        clear_dead_active(*id, interface);
    }
    for (id, interface, services) in &summary.restored_by {
        remember_restore(*id, interface, services);
    }
    Ok(summary)
}

/// Result of [`sweep_once_and_clean`].
pub(super) struct OnceOutcome {
    pub summary: SweepSummary,
    /// Records still on disk because their helper is live or their services
    /// are not in the current location.
    pub kept: Vec<DnsCustodyEntry>,
}

/// One-shot sweep for uninstall: no watches, no sentinel, no retry loop. The
/// sentinel is removed first so launchd cannot restart a daemon underneath
/// us, and `dns-custody/` (with `*.corrupt`, `watch` and stray temp files)
/// is deleted when no record is left.
pub(super) fn sweep_once_and_clean() -> Result<OnceOutcome> {
    crate::state_file::remove_durable(&crate::config::dns_custody_watch_path())?;
    let summary = {
        let _network_lock = lock_system_network_mutation()?;
        sweep_locked(Scope::All)?
    };
    for (id, interface) in &summary.died {
        clear_dead_active(*id, interface);
    }
    let kept: Vec<DnsCustodyEntry> = record_paths()?
        .iter()
        .filter_map(|path| match dns_custody::read_record(path) {
            Ok(RecordRead::Record(record)) => Some(status_entry(
                record.connection_id,
                &record.interface,
                record.services.iter().map(|s| s.service.clone()).collect(),
            )),
            _ => None,
        })
        .collect();
    if kept.is_empty() {
        std::fs::remove_dir_all(crate::config::dns_custody_dir())?;
    }
    Ok(OnceOutcome { summary, kept })
}

fn clear_dead_active(id: ConnectionId, interface: &str) {
    let result = (|| -> Result<()> {
        let conn_lock = connection_store::lock_connection_patient(id)?;
        // A reconnect may have won the connection lock first.
        if connection_store::helper_is_live(id, interface, None, None) {
            return Ok(());
        }
        if connection_store::load(id)?.is_none() {
            return Ok(());
        }
        connection_store::clear_active(&conn_lock, id)
    })();
    if let Err(error) = result {
        warn!(id = %id, interface, error = %error, "privileged_dns_custody_clear_active_failed");
    }
}

/// The sweep proper. The caller holds the system network mutation lock.
pub(super) fn sweep_locked(scope: Scope<'_>) -> Result<SweepSummary> {
    let mut states = read_record_states(&scope)?;
    states.sort_by(|a, b| a.1.record.interface.cmp(&b.1.record.interface));

    let stored = match scope {
        Scope::All => stored_dns_lists(),
        Scope::Interface(_) => Vec::new(),
    };
    let needs_snapshot = states.iter().any(|(_, state)| !state.helper_live)
        || stored.iter().any(|dns| !dns.helper_live);
    let live_dns = if needs_snapshot {
        snapshot_live_dns()?
    } else {
        Vec::new()
    };

    let record_states: Vec<RecordState> = states.iter().map(|(_, s)| s.clone()).collect();
    let actions = plan_dns_sweep(&record_states, &live_dns, &stored);
    let summary = execute(&actions, &states);

    if summary.restored + summary.cleared > 0 {
        macos_dns::flush_resolver_cache();
    }

    let level_info = matches!(scope, Scope::All) || summary.restored + summary.cleared > 0;
    if level_info {
        info!(
            restored = summary.restored,
            cleared = summary.cleared,
            skipped_live = summary.skipped_live,
            "privileged_dns_sweep_complete"
        );
    } else {
        debug!(
            skipped_live = summary.skipped_live,
            "privileged_dns_sweep_complete"
        );
    }
    Ok(summary)
}

/// Apply the planned actions, then settle each dead record: delete it when
/// every service was restored or found changed, otherwise rewrite it with
/// only the services still pending (absent from this location, or whose
/// restore failed). The sweep is idempotent, so a crash in between only means
/// the next sweep sees the restored services as "changed" and drops them.
fn execute(actions: &[Action], states: &[(PathBuf, RecordState)]) -> SweepSummary {
    let mut summary = SweepSummary::default();
    let mut pending: HashSet<(String, String)> = HashSet::new();
    let mut restored_services: Vec<(String, String)> = Vec::new();

    for action in actions {
        match action {
            Action::SkipLive { .. } => summary.skipped_live += 1,
            Action::Restore {
                interface,
                service,
                servers,
                search_domains,
            } => {
                match macos_dns::restore_service(
                    service,
                    servers.as_deref(),
                    search_domains.as_deref(),
                ) {
                    Ok(()) => {
                        summary.restored += 1;
                        restored_services.push((interface.clone(), service.clone()));
                        info!(interface, service, "privileged_dns_custody_restored");
                    }
                    Err(error) => {
                        summary.failed += 1;
                        pending.insert((interface.clone(), service.clone()));
                        warn!(interface, service, error = %error, "privileged_dns_custody_restore_failed");
                    }
                }
            }
            Action::ServiceChanged { interface, service } => {
                info!(interface, service, "privileged_dns_custody_service_changed");
            }
            Action::ServiceAbsent { interface, service } => {
                debug!(interface, service, "privileged_dns_custody_service_absent");
                pending.insert((interface.clone(), service.clone()));
            }
            Action::ClearStray { service, servers } => {
                match macos_dns::set_dns_servers_empty(service) {
                    Ok(()) => {
                        summary.cleared += 1;
                        warn!(service, servers = ?servers, "privileged_dns_stray_cleared");
                    }
                    Err(error) => {
                        summary.failed += 1;
                        warn!(service, error = %error, "privileged_dns_stray_clear_failed");
                    }
                }
            }
        }
    }

    for (path, state) in states {
        if state.helper_live {
            continue;
        }
        let record = &state.record;
        let restored: Vec<String> = restored_services
            .iter()
            .filter(|(interface, _)| *interface == record.interface)
            .map(|(_, service)| service.clone())
            .collect();
        if !restored.is_empty() {
            summary
                .restored_by
                .push((record.connection_id, record.interface.clone(), restored));
        }
        let keep: Vec<DnsCustodyService> = record
            .services
            .iter()
            .filter(|s| pending.contains(&(record.interface.clone(), s.service.clone())))
            .cloned()
            .collect();
        let settled = if keep.is_empty() {
            crate::state_file::remove_durable(path)
        } else if keep.len() != record.services.len() {
            dns_custody::write_record(&DnsCustodyRecord {
                services: keep,
                ..record.clone()
            })
        } else {
            Ok(())
        };
        if let Err(error) = settled {
            summary.failed += 1;
            warn!(interface = %record.interface, error = %error, "privileged_dns_custody_record_update_failed");
        }
        // The helper is confirmed dead (and re-checked right here, still under
        // the network lock): drop the socket and pid files it left, or the next
        // connect would refuse over them.
        super::runtime_files::remove_if_dead_locked(&record.interface, || {
            connection_store::helper_is_live(
                record.connection_id,
                &record.interface,
                Some(record.helper_pid),
                Some(record.helper_start),
            )
        });
        summary
            .died
            .push((record.connection_id, record.interface.clone()));
    }
    summary
}

// ---- status (`ListDnsCustody`) ----------------------------------------------

/// File (in the runtime dir, not in `dns-custody/`, whose `*.json` files are
/// all records) remembering the last automatic restore of this boot.
const LAST_RESTORE_FILE: &str = "dns-last-restore.json";

#[derive(Debug, Serialize, Deserialize)]
struct LastRestore {
    boot_id: Option<String>,
    at: u64,
    connection_id: ConnectionId,
    interface: String,
    services: Vec<String>,
}

fn last_restore_path() -> PathBuf {
    crate::config::privileged_runtime_dir().join(LAST_RESTORE_FILE)
}

fn remember_restore(id: ConnectionId, interface: &str, services: &[String]) {
    let entry = LastRestore {
        boot_id: connection_store::boot_id(),
        at: connection_store::now_unix(),
        connection_id: id,
        interface: interface.to_string(),
        services: services.to_vec(),
    };
    let result = serde_json::to_vec(&entry)
        .map_err(std::io::Error::other)
        .and_then(|json| crate::state_file::write_atomic(&last_restore_path(), &json));
    if let Err(error) = result {
        warn!(error = %error, "privileged_dns_last_restore_write_failed");
    }
}

fn status_entry(id: ConnectionId, interface: &str, services: Vec<String>) -> DnsCustodyEntry {
    DnsCustodyEntry {
        id: Some(id),
        interface: interface.to_string(),
        name: connection_store::load(id)
            .ok()
            .flatten()
            .and_then(|c| c.name),
        services,
    }
}

/// Everything about custody that is not normal: records of dead helpers
/// (pending or deferred) and the last automatic restore of this boot. Records
/// whose helper is live are normal and omitted.
pub(super) fn custody_status() -> DnsCustodyStatus {
    let mut status = DnsCustodyStatus::default();
    if let Ok(states) = read_record_states(&Scope::All) {
        let listed = macos_dns::list_network_services().unwrap_or_else(|_| {
            states
                .iter()
                .flat_map(|(_, s)| s.record.services.iter().map(|svc| svc.service.clone()))
                .collect()
        });
        for (_, state) in &states {
            let record = &state.record;
            let services = record.services.iter().map(|s| s.service.clone()).collect();
            let entry = status_entry(record.connection_id, &record.interface, services);
            match classify_record(state.helper_live, &record.services, &listed) {
                RecordStatus::Live => {}
                RecordStatus::Restorable => status.pending.push(entry),
                RecordStatus::Deferred => status.deferred.push(entry),
            }
        }
    }
    let last = std::fs::read(last_restore_path())
        .ok()
        .and_then(|raw| serde_json::from_slice::<LastRestore>(&raw).ok())
        .filter(|last| last.boot_id.is_none() || last.boot_id == connection_store::boot_id());
    status.last_restore = last.map(|last| DnsRestoreEvent {
        entry: status_entry(last.connection_id, &last.interface, last.services),
        at: last.at,
    });
    status
}

/// Every record file in `dns-custody/`, in no particular order.
fn record_paths() -> std::io::Result<Vec<PathBuf>> {
    let entries = match std::fs::read_dir(crate::config::dns_custody_dir()) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut paths = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "json") {
            paths.push(path);
        }
    }
    Ok(paths)
}

/// Parse the records in scope and ask whether each one's helper is alive.
/// Corrupt files are renamed to `*.corrupt`; records from a newer schema are
/// left untouched and ignored.
pub(super) fn read_record_states(scope: &Scope<'_>) -> Result<Vec<(PathBuf, RecordState)>> {
    let mut states = Vec::new();
    for path in record_paths()? {
        let stem = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .unwrap_or_default()
            .to_string();
        if let Scope::Interface(interface) = scope {
            if stem != *interface {
                continue;
            }
        }
        let outcome = match dns_custody::read_record(&path) {
            Ok(RecordRead::Record(record)) if record.interface == stem => Ok(record),
            Ok(RecordRead::Record(_)) => Err("record names a different interface".to_string()),
            Ok(RecordRead::UnsupportedVersion(version)) => {
                debug!(path = %path.display(), version, "privileged_dns_custody_unsupported_version");
                continue;
            }
            Ok(RecordRead::Corrupt(reason)) => Err(reason),
            Err(error) => Err(error.to_string()),
        };
        match outcome {
            Ok(record) => {
                let helper_live = connection_store::helper_is_live(
                    record.connection_id,
                    &record.interface,
                    Some(record.helper_pid),
                    Some(record.helper_start),
                );
                states.push((
                    path,
                    RecordState {
                        record,
                        helper_live,
                    },
                ));
            }
            Err(reason) => {
                let quarantine = path.with_extension("corrupt");
                warn!(path = %path.display(), reason, "privileged_dns_custody_record_corrupt");
                if let Err(error) = std::fs::rename(&path, &quarantine) {
                    warn!(path = %path.display(), error = %error, "privileged_dns_custody_quarantine_failed");
                }
            }
        }
    }
    Ok(states)
}

/// DNS lists of every stored connection that has one, with helper liveness.
fn stored_dns_lists() -> Vec<StoredDns> {
    let connections = match connection_store::load_all() {
        Ok(connections) => connections,
        Err(error) => {
            warn!(error = %error, "privileged_dns_sweep_listing_failed");
            return Vec::new();
        }
    };
    connections
        .iter()
        .filter(|conn| !conn.config.dns_servers.is_empty())
        .map(|conn| StoredDns {
            servers: conn
                .config
                .dns_servers
                .iter()
                .map(ToString::to_string)
                .collect(),
            helper_live: connection_store::helper_is_live(conn.id, &conn.interface, None, None),
        })
        .collect()
}

/// Live DNS of every current network service. A failed listing or read aborts
/// the sweep: acting on a half-built view could drop a record that still has
/// something to restore.
fn snapshot_live_dns() -> Result<Vec<(String, Option<Vec<String>>)>> {
    use crate::error::AppError;
    let other = |error: anyhow::Error| AppError::Other(error.to_string());
    let services = macos_dns::list_network_services().map_err(other)?;
    if services.is_empty() {
        return Err(AppError::Other(
            "networksetup -listallnetworkservices returned no services".into(),
        ));
    }
    let mut live = Vec::with_capacity(services.len());
    for service in services {
        let dns = macos_dns::get_dns_servers(&service).map_err(other)?;
        live.push((service, dns));
    }
    Ok(live)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privileged::managed_pids::ProcessStart;

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(ToString::to_string).collect()
    }

    fn record(
        interface: &str,
        tunnel: &[&str],
        services: &[(&str, Option<&[&str]>)],
    ) -> DnsCustodyRecord {
        DnsCustodyRecord {
            version: dns_custody::DNS_CUSTODY_VERSION,
            connection_id: ConnectionId::new(),
            interface: interface.into(),
            helper_pid: 1,
            helper_start: ProcessStart { sec: 1, usec: 1 },
            tunnel_dns: list(tunnel),
            services: services
                .iter()
                .map(|(name, original)| DnsCustodyService {
                    service: (*name).into(),
                    original_dns_servers: original.map(list),
                    original_search_domains: original.map(|_| list(&["lan"])),
                })
                .collect(),
        }
    }

    fn state(record: DnsCustodyRecord, helper_live: bool) -> RecordState {
        RecordState {
            record,
            helper_live,
        }
    }

    fn live(entries: &[(&str, Option<&[&str]>)]) -> Vec<(String, Option<Vec<String>>)> {
        entries
            .iter()
            .map(|(name, dns)| ((*name).to_string(), dns.map(list)))
            .collect()
    }

    const TUNNEL: &[&str] = &["10.66.77.2", "100.64.1.1"];

    #[test]
    fn sentinel_is_kept_for_live_and_restorable_records_only() {
        use RecordStatus::*;
        assert!(sentinel_wanted(&[Live]));
        assert!(sentinel_wanted(&[Deferred, Restorable]));
        assert!(sentinel_wanted(&[Deferred, Live]));
        assert!(!sentinel_wanted(&[Deferred]));
        assert!(!sentinel_wanted(&[Deferred, Deferred]));
        assert!(!sentinel_wanted(&[]));
    }

    #[test]
    fn records_classify_by_liveness_and_location() {
        let rec = record("wg-a", TUNNEL, &[("Wi-Fi", None), ("Office", None)]);
        let listed = list(&["Wi-Fi"]);
        assert_eq!(
            classify_record(true, &rec.services, &listed),
            RecordStatus::Live
        );
        assert_eq!(
            classify_record(false, &rec.services, &listed),
            RecordStatus::Restorable
        );
        assert_eq!(
            classify_record(false, &rec.services, &list(&["Home"])),
            RecordStatus::Deferred
        );
    }

    #[test]
    fn dead_helper_with_tunnel_dns_still_set_restores_originals() {
        let rec = record("wg-a", TUNNEL, &[("Wi-Fi", Some(&["192.168.1.1"]))]);
        let actions = plan_dns_sweep(&[state(rec, false)], &live(&[("Wi-Fi", Some(TUNNEL))]), &[]);
        assert_eq!(
            actions,
            vec![Action::Restore {
                interface: "wg-a".into(),
                service: "Wi-Fi".into(),
                servers: Some(list(&["192.168.1.1"])),
                search_domains: Some(list(&["lan"])),
            }]
        );
    }

    #[test]
    fn adopted_stray_with_empty_original_resets_to_dhcp() {
        let rec = record("wg-a", TUNNEL, &[("Wi-Fi", None)]);
        let actions = plan_dns_sweep(&[state(rec, false)], &live(&[("Wi-Fi", Some(TUNNEL))]), &[]);
        assert_eq!(
            actions,
            vec![Action::Restore {
                interface: "wg-a".into(),
                service: "Wi-Fi".into(),
                servers: None,
                search_domains: None,
            }]
        );
    }

    #[test]
    fn dead_helper_with_user_changed_dns_is_left_alone() {
        let rec = record("wg-a", TUNNEL, &[("Wi-Fi", Some(&["192.168.1.1"]))]);
        let actions = plan_dns_sweep(
            &[state(rec, false)],
            &live(&[("Wi-Fi", Some(&["9.9.9.9"]))]),
            &[],
        );
        assert_eq!(
            actions,
            vec![Action::ServiceChanged {
                interface: "wg-a".into(),
                service: "Wi-Fi".into()
            }]
        );
    }

    #[test]
    fn live_helper_is_never_touched() {
        let rec = record("wg-a", TUNNEL, &[("Wi-Fi", Some(&["192.168.1.1"]))]);
        let actions = plan_dns_sweep(
            &[state(rec, true)],
            &live(&[("Wi-Fi", Some(TUNNEL))]),
            &[StoredDns {
                servers: list(TUNNEL),
                helper_live: true,
            }],
        );
        assert_eq!(
            actions,
            vec![Action::SkipLive {
                interface: "wg-a".into()
            }]
        );
    }

    #[test]
    fn service_missing_from_listing_keeps_the_record() {
        let rec = record("wg-a", TUNNEL, &[("Office Wi-Fi", Some(&["10.0.0.1"]))]);
        let actions = plan_dns_sweep(&[state(rec, false)], &live(&[("Wi-Fi", None)]), &[]);
        assert_eq!(
            actions,
            vec![Action::ServiceAbsent {
                interface: "wg-a".into(),
                service: "Office Wi-Fi".into()
            }]
        );
    }

    #[test]
    fn record_of_a_removed_connection_restores_from_the_record_alone() {
        // No stored connections at all: the plan still restores.
        let rec = record("wg-gone", TUNNEL, &[("Wi-Fi", Some(&["192.168.1.1"]))]);
        let actions = plan_dns_sweep(&[state(rec, false)], &live(&[("Wi-Fi", Some(TUNNEL))]), &[]);
        assert!(matches!(actions.as_slice(), [Action::Restore { .. }]));
    }

    #[test]
    fn stray_without_record_on_a_non_primary_service_is_cleared() {
        let actions = plan_dns_sweep(
            &[],
            &live(&[
                ("Wi-Fi", Some(&["192.168.1.1"])),
                ("Ethernet", Some(TUNNEL)),
            ]),
            &[StoredDns {
                servers: list(TUNNEL),
                helper_live: false,
            }],
        );
        assert_eq!(
            actions,
            vec![Action::ClearStray {
                service: "Ethernet".into(),
                servers: list(TUNNEL)
            }]
        );
    }

    #[test]
    fn stray_matching_a_connection_with_a_live_helper_is_left_alone() {
        let actions = plan_dns_sweep(
            &[],
            &live(&[("Wi-Fi", Some(TUNNEL))]),
            &[StoredDns {
                servers: list(TUNNEL),
                helper_live: true,
            }],
        );
        assert!(actions.is_empty());
    }

    #[test]
    fn same_list_on_a_dead_and_a_live_connection_is_left_alone() {
        let actions = plan_dns_sweep(
            &[],
            &live(&[("Wi-Fi", Some(TUNNEL))]),
            &[
                StoredDns {
                    servers: list(TUNNEL),
                    helper_live: false,
                },
                StoredDns {
                    servers: list(TUNNEL),
                    helper_live: true,
                },
            ],
        );
        assert!(actions.is_empty());
    }

    #[test]
    fn subset_and_superset_of_a_tunnel_list_are_user_dns() {
        let stored = [StoredDns {
            servers: list(TUNNEL),
            helper_live: false,
        }];
        let actions = plan_dns_sweep(
            &[],
            &live(&[
                ("Wi-Fi", Some(&["10.66.77.2"])),
                ("Ethernet", Some(&["10.66.77.2", "100.64.1.1", "1.1.1.1"])),
                ("USB", Some(&["100.64.1.1", "10.66.77.2"])),
            ]),
            &stored,
        );
        assert!(actions.is_empty());
    }

    #[test]
    fn services_in_a_record_are_not_swept_again_by_the_fallback() {
        let rec = record("wg-a", TUNNEL, &[("Wi-Fi", Some(&["192.168.1.1"]))]);
        let actions = plan_dns_sweep(
            &[state(rec, false)],
            &live(&[("Wi-Fi", Some(TUNNEL))]),
            &[StoredDns {
                servers: list(TUNNEL),
                helper_live: false,
            }],
        );
        assert!(matches!(actions.as_slice(), [Action::Restore { .. }]));
    }
}
