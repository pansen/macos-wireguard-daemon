use super::dns_plan::dns_decision;
use super::dns_plan::dns_reconcile_forced;
use super::dns_plan::macos_dns_server_in_local_subnet;
use super::dns_plan::plan_dns_actions;
use super::dns_plan::DnsDecision;
use super::dns_plan::DNS_POLICY;
use super::system::macos_local_connected_subnets;
use super::system::macos_primary_service;
use super::MacosCleanupState;
use super::MacosDnsFingerprint;
use super::MacosDnsServiceState;
use super::MacosReconcileInputs;
use anyhow::Context;
use std::net::IpAddr;
use tracing::{debug, info, warn};

/// Apply the tunnel's DNS to the services selected by `DNS_POLICY`, saving each
/// touched service's original config into `saved` for later restore. Returns the
/// DNS fingerprint observed *after* applying, so the reconciler's first tick is a
/// no-op. Shares its decision (`dns_decision`, including the LAN-collision rule)
/// and its per-service capture+apply path with the reconciler, so a colliding
/// tunnel DNS is never written in the first place.
pub(super) fn configure_macos_dns(
    inputs: &MacosReconcileInputs,
    local_subnets: &[(IpAddr, u8)],
    saved: &mut Vec<MacosDnsServiceState>,
) -> anyhow::Result<MacosDnsFingerprint> {
    if inputs.dns_servers.is_empty() {
        return Ok(MacosDnsFingerprint::default());
    }

    let fingerprint = macos_current_dns_fingerprint()?;
    let collision = macos_dns_server_in_local_subnet(&inputs.dns_servers, local_subnets);
    if let Some(collision) = &collision {
        log_dns_unreachable_local_lan(&inputs.interface, collision);
    }
    // Nothing is owned yet, so `Hold` and `RestoreAll` both mean "write nothing";
    // with no primary the reconciler applies once one appears.
    let decision = dns_decision(DNS_POLICY, &fingerprint, collision.is_some());
    for service in decision.targets() {
        saved.push(capture_macos_dns_service(service, &inputs.dns_servers)?);
        // Write-ahead: the record must list the service before its DNS changes.
        persist_dns_custody(saved, inputs);
        crate::macos_dns::set_dns_servers(service, &inputs.dns_servers)?;
        crate::macos_dns::set_search_domains_empty(service)?;
    }

    // Re-snapshot post-apply: the stored fingerprint must reflect the DNS we
    // just wrote so the first reconcile tick detects no change. DNS is already
    // applied at this point, so a failed re-snapshot must not fail connect —
    // fall back to the pre-apply fingerprint and let the first reconcile tick
    // observe the resulting drift and self-correct.
    Ok(macos_current_dns_fingerprint().unwrap_or_else(|error| {
        warn!(error = %error, "userspace_helper_dns_fingerprint_resnapshot_failed");
        fingerprint
    }))
}

/// Write the custody record for the services this helper currently owns, or
/// delete it when none are left. Best-effort: losing crash recovery must not
/// break connect, so a failure only logs. One function for the connect path,
/// the reconciler and teardown, so they cannot diverge.
pub(super) fn persist_dns_custody(
    services: &[MacosDnsServiceState],
    inputs: &MacosReconcileInputs,
) {
    let Some(identity) = &inputs.custody else {
        return;
    };
    if inputs.dns_servers.is_empty() {
        return;
    }
    let result = if services.is_empty() {
        crate::dns_custody::remove_record(&identity.interface)
    } else {
        let owned = services
            .iter()
            .map(crate::dns_custody::DnsCustodyService::from)
            .collect();
        // Record first, then sentinel; see `ensure_watch_sentinel` for why.
        crate::dns_custody::write_record(&identity.record(&inputs.dns_servers, owned))
            .and_then(|()| crate::dns_custody::ensure_watch_sentinel())
    };
    if let Err(error) = result {
        warn!(
            interface = identity.interface,
            error = %error,
            "userspace_helper_dns_custody_write_failed"
        );
    }
}

/// Restore every service in reverse order, then settle the custody record:
/// deleted when all restores worked, otherwise rewritten with only the
/// services that failed so the daemon's sweep retries them. Returns one
/// message per failure.
pub(super) fn restore_macos_dns_services(
    services: &[MacosDnsServiceState],
    inputs: &MacosReconcileInputs,
) -> Vec<String> {
    let mut errors = Vec::new();
    let mut failed = Vec::new();
    for service in services.iter().rev() {
        if let Err(error) = restore_macos_dns_service(service) {
            errors.push(format!(
                "restore DNS for {:?} failed: {error}",
                service.service
            ));
            failed.push(service.clone());
        }
    }
    persist_dns_custody(&failed, inputs);
    if failed.len() < services.len() {
        // At least one service is back on its original DNS; make it effective.
        crate::macos_dns::flush_resolver_cache();
    }
    errors
}

pub(super) fn restore_macos_dns_service(state: &MacosDnsServiceState) -> anyhow::Result<()> {
    crate::macos_dns::restore_service(
        &state.service,
        state.dns_servers.as_deref(),
        state.search_domains.as_deref(),
    )
}

pub(super) fn log_dns_unreachable_local_lan(interface: &str, collision: &(IpAddr, (IpAddr, u8))) {
    let (server, (subnet_ip, subnet_prefix)) = collision;
    warn!(
        interface,
        dns_server = %server,
        local_subnet = %format!("{subnet_ip}/{subnet_prefix}"),
        "userspace_helper_dns_unreachable_local_lan"
    );
}

/// Snapshot the current DNS-relevant environment. The service list itself
/// must be trustworthy: a healthy macOS always reports at least one network
/// service, so a failed or empty listing is a degraded read, not "all
/// services vanished" — returning it as fact would make `plan_dns_actions`
/// classify every owned service as vanished and drop (not restore) its saved
/// original. So a failed or empty listing aborts the snapshot. Everything
/// else — per-service DNS reads, the primary-service lookup — still degrades
/// to empty/`None` rather than aborting, mirroring `macos_local_connected_subnets`.
pub(super) fn macos_current_dns_fingerprint() -> anyhow::Result<MacosDnsFingerprint> {
    let mut services =
        crate::macos_dns::list_network_services().context("listing macOS network services")?;
    if services.is_empty() {
        anyhow::bail!("networksetup -listallnetworkservices returned no services");
    }
    services.sort();
    services.dedup();

    let mut observed = Vec::with_capacity(services.len());
    for svc in &services {
        // None on error → treat as "unknown/unset"; never panic the tick.
        let dns = crate::macos_dns::get_dns_servers(svc).unwrap_or_else(|error| {
            debug!(service = svc, error = %error, "userspace_helper_dns_read_failed");
            None
        });
        observed.push((svc.clone(), dns));
    }

    Ok(MacosDnsFingerprint {
        primary_service: macos_primary_service(),
        services,
        observed,
    })
}

/// Read a service's current DNS + search domains and wrap them for later
/// restore. When the service already shows the tunnel's DNS, its true original
/// is gone — a prior run set it and never cleaned up (crash, kill, or
/// `make uninstall`) — so adopt it with an **empty** original: teardown then
/// clears the stray back to DHCP instead of stranding an unreachable tunnel
/// resolver. We still never record the tunnel's own servers as the "original"
/// (`transparent_dns.md` §6.1); the recovery target is Empty, not tunnel DNS.
/// The tunnel resolver is only reachable through the tunnel, so a service
/// pinned to it without a tunnel is broken by definition — Empty is the only
/// safe restore.
pub(super) fn capture_macos_dns_service(
    service: &str,
    tunnel_dns: &[String],
) -> anyhow::Result<MacosDnsServiceState> {
    let dns = crate::macos_dns::get_dns_servers(service)?;
    if dns.as_deref() == Some(tunnel_dns) {
        return Ok(MacosDnsServiceState {
            service: service.to_string(),
            dns_servers: None,
            search_domains: None,
        });
    }
    let search = crate::macos_dns::get_search_domains(service)?;
    Ok(MacosDnsServiceState {
        service: service.to_string(),
        dns_servers: dns,
        search_domains: search,
    })
}

/// Re-apply DNS when the host DNS environment changed (roam, DHCP renewal, a new
/// or vanished service, a primary-service change). Cheap and silent when nothing
/// changed; expressive when it acts. Mirrors `macos_reconcile_routes`.
pub(in crate::userspace_helper) fn macos_reconcile_dns(state: &MacosCleanupState) -> bool {
    let inputs = &state.reconcile;
    if inputs.dns_servers.is_empty() {
        return false; // VPN promotes no DNS -> nothing to own.
    }

    let fingerprint = match macos_current_dns_fingerprint() {
        Ok(fingerprint) => fingerprint,
        // A degraded or failed listing must not be read as "all owned services
        // vanished" (see `macos_current_dns_fingerprint`): skip this tick rather
        // than acting on a half-built fingerprint, mirroring the route guard.
        Err(error) => {
            warn!(
                interface = inputs.interface,
                error = %error,
                "userspace_helper_dns_fingerprint_failed"
            );
            return false;
        }
    };

    // If the tunnel's own DNS server now lives inside a directly-connected LAN,
    // its route is excluded from the tunnel and the server is unreachable through
    // it. We must pull tunnel DNS back, but joining such a LAN need not change the
    // DNS fingerprint at all, so this is computed before the identity guard below.
    let local_subnets = macos_local_connected_subnets(&inputs.interface);
    let collision = macos_dns_server_in_local_subnet(&inputs.dns_servers, &local_subnets);

    let mut dns = state
        .dns
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // On a collision, target nothing so every owned service is restored to its
    // original DNS rather than left pointing at an unreachable (or
    // LAN-impersonatable) address.
    let owned: Vec<String> = dns.services.iter().map(|s| s.service.clone()).collect();
    let decision = dns_decision(DNS_POLICY, &fingerprint, collision.is_some());
    // No primary right now: change nothing. The stored fingerprint stays as it
    // was, so the tick where a primary reappears sees the difference and acts.
    if decision == DnsDecision::Hold {
        return false;
    }
    let targets = decision.targets().to_vec();

    // Normally skip when the DNS environment is unchanged, but still act when a
    // collision transition changed required ownership without moving the
    // fingerprint (see `dns_reconcile_forced`).
    if fingerprint == dns.fingerprint
        && !dns_reconcile_forced(collision.is_some(), &owned, &targets)
    {
        return false; // cheap identity check, same guard as routes.
    }

    let previous = dns.fingerprint.clone();
    info!(
        interface = inputs.interface,
        old_primary = ?previous.primary_service,
        new_primary = ?fingerprint.primary_service,
        old_services = previous.services.len(),
        new_services = fingerprint.services.len(),
        "userspace_helper_dns_change_detected"
    );

    if let Some(collision) = &collision {
        log_dns_unreachable_local_lan(&inputs.interface, collision);
    }

    let actions = plan_dns_actions(&inputs.dns_servers, &fingerprint, &owned, &targets);
    debug!(
        interface = inputs.interface,
        primary_service = ?fingerprint.primary_service,
        decision = ?decision,
        tunnel_dns = ?inputs.dns_servers,
        previous_observed_dns = ?previous.observed,
        observed_dns = ?fingerprint.observed,
        owned_services = ?owned,
        target_services = ?targets,
        actions = ?actions,
        "userspace_helper_dns_reconcile_plan"
    );

    let (mut applied, mut captured, mut restored, mut dropped, mut errors) =
        (0usize, 0usize, 0usize, 0usize, 0usize);

    // (a) Capture originals for services we are about to own. If a capture
    // fails we must not overwrite that service's DNS below: with no saved
    // original, teardown could never restore the user's settings.
    let mut capture_failed: Vec<&str> = Vec::new();
    for svc in &actions.capture {
        match capture_macos_dns_service(svc, &inputs.dns_servers) {
            Ok(saved) => {
                dns.services.push(saved);
                captured += 1;
            }
            Err(_) => {
                errors += 1;
                capture_failed.push(svc.as_str());
            }
        }
    }

    // (b) Release services we no longer target: restore the ones still present,
    // drop the ones whose host service has vanished. Keep the saved original if
    // a restore fails so teardown (or a later tick) can retry; dropping it would
    // strand the user's DNS settings.
    for svc in &actions.restore {
        let saved = dns.services.iter().find(|s| &s.service == svc).cloned();
        match saved {
            Some(saved) => {
                if restore_macos_dns_service(&saved).is_ok() {
                    restored += 1;
                    dns.services.retain(|s| &s.service != svc);
                } else {
                    errors += 1; // keep saved state for a retry
                }
            }
            None => dns.services.retain(|s| &s.service != svc),
        }
    }
    for svc in &actions.drop {
        dropped += 1;
        dns.services.retain(|s| &s.service != svc);
    }

    // Persist the owned set before any DNS is written: a newly captured service
    // must be on disk before (c) touches it, and a released one must leave the
    // record once its restore has succeeded.
    if captured + restored + dropped > 0 {
        persist_dns_custody(&dns.services, inputs);
    }

    // (c) (Re-)assert tunnel DNS on every target whose observed DNS has drifted,
    // except services whose original we failed to capture this tick.
    for svc in &actions.apply {
        if capture_failed.contains(&svc.as_str()) {
            continue; // never overwrite DNS we couldn't back up
        }
        if crate::macos_dns::set_dns_servers(svc, &inputs.dns_servers).is_ok()
            && crate::macos_dns::set_search_domains_empty(svc).is_ok()
        {
            applied += 1;
        } else {
            errors += 1;
        }
    }

    // Re-snapshot only when we actually changed system DNS, so the stored
    // fingerprint matches reality and the next tick doesn't see a spurious diff.
    // Captures and drops don't touch system DNS, so the pre-action snapshot is
    // still accurate when nothing was applied or restored.
    dns.fingerprint = if applied + restored > 0 {
        // On a failed re-snapshot, fall back to the pre-action fingerprint. It's
        // stale (it won't reflect the change we just made), but that only makes
        // the next tick re-detect the same drift and re-run idempotent actions —
        // safe, unlike trusting a degraded read as the new baseline.
        macos_current_dns_fingerprint().unwrap_or_else(|error| {
            warn!(
                interface = inputs.interface,
                error = %error,
                "userspace_helper_dns_fingerprint_resnapshot_failed"
            );
            fingerprint
        })
    } else {
        fingerprint
    };
    info!(
        interface = inputs.interface,
        applied, captured, restored, dropped, errors, "userspace_helper_dns_reconcile_applied"
    );
    true
}
