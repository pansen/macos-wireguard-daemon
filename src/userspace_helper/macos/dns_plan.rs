use super::net::macos_subnet_contains;
use super::MacosDnsFingerprint;
use std::net::IpAddr;

/// Which network services should carry the tunnel's DNS. `AllServices` matches
/// the historical connect-time behavior (now applied dynamically); `PrimaryOnly`
/// is the true analogue of the route LAN-exclusion — only the service that owns
/// global resolution gets tunnel DNS, so non-primary LANs keep their own.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DnsPolicy {
    #[allow(dead_code)]
    AllServices,
    PrimaryOnly,
}

/// Active DNS targeting policy. Switching this constant is the only change
/// needed to move between the phases described in `transparent_dns.md`.
pub(super) const DNS_POLICY: DnsPolicy = DnsPolicy::PrimaryOnly;

/// What the DNS reconciler should do with tunnel DNS. An empty target list is
/// ambiguous (`plan_dns_actions` reads it as "release everything owned"), so the
/// two reasons for having no targets are kept apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum DnsDecision {
    /// Own exactly these services.
    Apply(Vec<String>),
    /// A tunnel DNS server is unreachable (LAN collision): restore every owned
    /// service and write nothing.
    RestoreAll,
    /// No settled primary service, typically a moment during a network switch.
    /// Write nothing, and leave the services we already own untouched until a
    /// primary shows up again; releasing them now would only flap their DNS.
    Hold,
}

impl DnsDecision {
    /// The services to own after this decision. Empty for `RestoreAll` and `Hold`.
    pub(super) fn targets(&self) -> &[String] {
        match self {
            DnsDecision::Apply(targets) => targets,
            DnsDecision::RestoreAll | DnsDecision::Hold => &[],
        }
    }
}

/// Decide what to do with tunnel DNS. A collision wins over everything else.
/// `PrimaryOnly` targets just the service that owns global resolution; without
/// one (or if it isn't a current service) it holds rather than fanning out to
/// every service, which would overwrite unrelated VPN and tether services.
/// Used by both the connect-time apply and the reconciler so they cannot drift.
pub(super) fn dns_decision(
    policy: DnsPolicy,
    fp: &MacosDnsFingerprint,
    collision: bool,
) -> DnsDecision {
    if collision {
        return DnsDecision::RestoreAll;
    }
    match policy {
        DnsPolicy::AllServices => DnsDecision::Apply(fp.services.clone()),
        DnsPolicy::PrimaryOnly => match &fp.primary_service {
            Some(primary) if fp.services.iter().any(|s| s == primary) => {
                DnsDecision::Apply(vec![primary.clone()])
            }
            _ => DnsDecision::Hold,
        },
    }
}

/// A configured tunnel DNS server whose address falls inside a directly-connected
/// LAN subnet. When that happens the route covering the server is excluded from
/// the tunnel (see [`macos_route_excluded_by_local_subnet`]), so the server is no
/// longer reachable through the tunnel: queries would leak onto the LAN and hit
/// whatever host happens to hold that address. Returns the offending server and
/// the subnet it collides with so the reconciler can pull tunnel DNS back.
pub(super) fn macos_dns_server_in_local_subnet(
    dns_servers: &[String],
    local_subnets: &[(IpAddr, u8)],
) -> Option<(IpAddr, (IpAddr, u8))> {
    dns_servers.iter().find_map(|server| {
        let ip: IpAddr = server.parse().ok()?;
        let host_prefix = if ip.is_ipv4() { 32 } else { 128 };
        local_subnets
            .iter()
            .find(|local| macos_subnet_contains(local, &(ip, host_prefix)))
            .map(|local| (ip, *local))
    })
}

/// The pure decision behind a DNS reconcile: given the tunnel's DNS, the freshly
/// observed environment, the services we currently own, and the services we want
/// to own, decide what to do. Kept free of I/O so it is unit-testable.
#[derive(Debug, Default, PartialEq)]
pub(super) struct DnsActions {
    /// Targets we don't yet own and whose live DNS differs from the tunnel's:
    /// capture their original config, then assert tunnel DNS.
    pub(super) capture: Vec<String>,
    /// Owned services no longer targeted but still present: restore originals.
    pub(super) restore: Vec<String>,
    /// Owned services that have vanished: drop without restoring (gone already).
    pub(super) drop: Vec<String>,
    /// Targets whose observed DNS has drifted from the tunnel's: (re-)assert.
    pub(super) apply: Vec<String>,
}

pub(super) fn plan_dns_actions(
    tunnel_dns: &[String],
    fp: &MacosDnsFingerprint,
    owned: &[String],
    targets: &[String],
) -> DnsActions {
    let shows_tunnel = |svc: &str| -> bool {
        fp.observed
            .iter()
            .find(|(s, _)| s == svc)
            .and_then(|(_, d)| d.as_deref())
            == Some(tunnel_dns)
    };

    let mut actions = DnsActions::default();

    for svc in targets {
        let matches_tunnel = shows_tunnel(svc);
        // Capture whenever we don't already own the service — even if it already
        // shows the tunnel DNS. A not-owned service at tunnel DNS is a leak from
        // an earlier run whose real original is gone; capturing it (with an Empty
        // original, see `capture_macos_dns_service`) lets teardown clear the stray
        // instead of stranding an unreachable resolver. Owned services keep their
        // real captured original and are never re-captured.
        if !owned.iter().any(|s| s == svc) {
            actions.capture.push(svc.clone());
        }
        if !matches_tunnel {
            actions.apply.push(svc.clone());
        }
    }

    for svc in owned {
        if targets.iter().any(|s| s == svc) {
            continue;
        }
        if fp.services.iter().any(|s| s == svc) {
            actions.restore.push(svc.clone());
        } else {
            actions.drop.push(svc.clone());
        }
    }

    actions
}

/// Whether a DNS reconcile must act even though the observed fingerprint is
/// unchanged. A collision (a directly-connected LAN that shadows the tunnel
/// resolver) transitions ownership without necessarily moving the fingerprint,
/// because DHCP-provided resolvers are invisible to `networksetup -getdnsservers`
/// — joining or leaving such a LAN can leave every service's observed DNS
/// untouched. Two symmetric transitions:
///   * `must_pull_back`: a collision means we own services that now need
///     restoring to their originals.
///   * `must_reassert`: a cleared collision means services we should own are
///     currently unowned and need tunnel DNS (re-)applied. Without this, a
///     pull-back would never be undone until some other fingerprint-visible
///     event happened to knock it loose.
pub(super) fn dns_reconcile_forced(
    collision_present: bool,
    owned: &[String],
    targets: &[String],
) -> bool {
    let must_pull_back = collision_present && !owned.is_empty();
    let must_reassert = !collision_present && targets.iter().any(|t| !owned.contains(t));
    must_pull_back || must_reassert
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::userspace_helper::macos::test_support::dns_fp;
    use crate::userspace_helper::macos::test_support::subnet;

    #[test]
    fn dns_server_collision_with_local_subnet_is_detected() {
        let lan = subnet("55.56.57.0/24");

        // Tunnel DNS sits inside the joined LAN -> unreachable through the tunnel.
        let hit = macos_dns_server_in_local_subnet(&["55.56.57.2".to_string()], &[lan]);
        assert_eq!(hit, Some(("55.56.57.2".parse().unwrap(), lan)));

        // A DNS server outside every connected subnet is fine.
        assert!(
            macos_dns_server_in_local_subnet(&["9.9.9.9".to_string()], &[lan]).is_none(),
            "off-LAN DNS must not be treated as a collision"
        );

        // No connected subnets at all -> never a collision.
        assert!(macos_dns_server_in_local_subnet(&["55.56.57.2".to_string()], &[]).is_none());

        // Any colliding server in the list triggers pull-back; reports the first.
        let mixed = macos_dns_server_in_local_subnet(
            &["9.9.9.9".to_string(), "55.56.57.2".to_string()],
            &[lan],
        );
        assert_eq!(mixed, Some(("55.56.57.2".parse().unwrap(), lan)));
    }

    #[test]
    fn dns_decision_honours_policy_and_holds_without_primary() {
        let fp = dns_fp(
            Some("Wi-Fi"),
            &[
                ("Ethernet", Some(&["1.1.1.1"])),
                ("Wi-Fi", Some(&["1.1.1.1"])),
            ],
        );

        // AllServices targets every service.
        assert_eq!(
            dns_decision(DnsPolicy::AllServices, &fp, false),
            DnsDecision::Apply(vec!["Ethernet".to_string(), "Wi-Fi".to_string()])
        );

        // PrimaryOnly targets just the primary.
        assert_eq!(
            dns_decision(DnsPolicy::PrimaryOnly, &fp, false),
            DnsDecision::Apply(vec!["Wi-Fi".to_string()])
        );

        // PrimaryOnly with no detectable primary holds instead of fanning out.
        let no_primary = dns_fp(None, &[("Wi-Fi", None), ("Ethernet", None)]);
        assert_eq!(
            dns_decision(DnsPolicy::PrimaryOnly, &no_primary, false),
            DnsDecision::Hold
        );

        // So does a primary that isn't a current service.
        let stale_primary = dns_fp(Some("Bogus"), &[("Wi-Fi", None)]);
        assert_eq!(
            dns_decision(DnsPolicy::PrimaryOnly, &stale_primary, false),
            DnsDecision::Hold
        );
    }

    #[test]
    fn dns_decision_collision_restores_all_even_without_primary() {
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["10.66.77.2"]))]);
        let no_primary = dns_fp(None, &[("Wi-Fi", None)]);
        for fp in [&fp, &no_primary] {
            let decision = dns_decision(DnsPolicy::PrimaryOnly, fp, true);
            assert_eq!(decision, DnsDecision::RestoreAll);
            assert!(decision.targets().is_empty());
        }
    }

    #[test]
    fn initial_apply_with_tunnel_dns_in_local_subnet_targets_nothing() {
        // Same inputs the connect path feeds `configure_macos_dns`: tunnel DNS
        // 10.66.77.2 sits inside the home LAN, so nothing may be written.
        let tunnel_dns = vec!["10.66.77.2".to_string(), "100.64.1.1".to_string()];
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["192.168.1.1"]))]);
        let collision = macos_dns_server_in_local_subnet(&tunnel_dns, &[subnet("10.66.77.0/24")]);
        assert!(collision.is_some());

        let decision = dns_decision(DnsPolicy::PrimaryOnly, &fp, collision.is_some());
        let actions = plan_dns_actions(&tunnel_dns, &fp, &[], decision.targets());
        assert_eq!(actions, DnsActions::default());
        // Nothing owned and nothing to assert: the next tick must not be forced.
        assert!(!dns_reconcile_forced(true, &[], decision.targets()));
    }

    #[test]
    fn hold_without_primary_keeps_owned_services() {
        // Primary vanished mid network switch while we own Wi-Fi: the decision
        // targets nothing, and the reconciler returns before planning, so the
        // owned service is neither restored nor re-captured.
        let fp = dns_fp(None, &[("Wi-Fi", Some(&["100.64.0.1"])), ("Vpn", None)]);
        let decision = dns_decision(DnsPolicy::PrimaryOnly, &fp, false);
        assert_eq!(decision, DnsDecision::Hold);
        assert!(decision.targets().is_empty());

        // Contrast: planning with the empty target list would release it.
        let released = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], &[]);
        assert_eq!(released.restore, vec!["Wi-Fi".to_string()]);
    }

    #[test]
    fn collision_restores_owned_services() {
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["100.64.0.1"]))]);
        let decision = dns_decision(DnsPolicy::PrimaryOnly, &fp, true);
        let actions = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], decision.targets());
        assert_eq!(actions.restore, vec!["Wi-Fi".to_string()]);
        assert!(actions.capture.is_empty());
        assert!(actions.apply.is_empty());
        assert!(dns_reconcile_forced(
            true,
            &["Wi-Fi".to_string()],
            decision.targets()
        ));
    }

    #[test]
    fn primary_returning_after_hold_targets_the_primary() {
        let held = dns_fp(None, &[("Wi-Fi", Some(&["192.168.1.1"]))]);
        assert_eq!(
            dns_decision(DnsPolicy::PrimaryOnly, &held, false),
            DnsDecision::Hold
        );

        let back = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["192.168.1.1"]))]);
        let decision = dns_decision(DnsPolicy::PrimaryOnly, &back, false);
        assert_eq!(decision, DnsDecision::Apply(vec!["Wi-Fi".to_string()]));
        assert!(dns_reconcile_forced(false, &[], decision.targets()));
        let actions = plan_dns_actions(&tunnel(), &back, &[], decision.targets());
        assert_eq!(actions.capture, vec!["Wi-Fi".to_string()]);
        assert_eq!(actions.apply, vec!["Wi-Fi".to_string()]);
    }

    fn tunnel() -> Vec<String> {
        vec!["100.64.0.1".to_string()]
    }

    #[test]
    fn plan_dns_new_primary_captures_and_restores_previous() {
        // Roamed Wi-Fi -> Ethernet under PrimaryOnly: own Wi-Fi, target Ethernet.
        let fp = dns_fp(
            Some("Ethernet"),
            &[
                ("Ethernet", Some(&["192.168.1.1"])), // native DHCP DNS
                ("Wi-Fi", Some(&["100.64.0.1"])),     // still has our tunnel DNS
            ],
        );
        let targets = dns_decision(DnsPolicy::PrimaryOnly, &fp, false)
            .targets()
            .to_vec();
        let actions = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], &targets);

        assert_eq!(actions.capture, vec!["Ethernet".to_string()]);
        assert_eq!(actions.apply, vec!["Ethernet".to_string()]);
        assert_eq!(actions.restore, vec!["Wi-Fi".to_string()]);
        assert!(actions.drop.is_empty());
    }

    #[test]
    fn plan_dns_clobber_reapplies_without_recapturing() {
        // configd reverted our DNS on an owned, still-targeted service.
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["192.168.1.1"]))]);
        let targets = dns_decision(DnsPolicy::PrimaryOnly, &fp, false)
            .targets()
            .to_vec();
        let actions = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], &targets);

        assert!(actions.capture.is_empty()); // already owned → keep original
        assert_eq!(actions.apply, vec!["Wi-Fi".to_string()]);
        assert!(actions.restore.is_empty());
        assert!(actions.drop.is_empty());
    }

    #[test]
    fn plan_dns_new_service_captured_under_all_services() {
        let fp = dns_fp(
            Some("Wi-Fi"),
            &[
                ("Wi-Fi", Some(&["100.64.0.1"])), // owned, already tunnel
                ("Tether", Some(&["10.0.0.1"])),  // new service with native DNS
            ],
        );
        let targets = dns_decision(DnsPolicy::AllServices, &fp, false)
            .targets()
            .to_vec();
        let actions = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], &targets);

        assert_eq!(actions.capture, vec!["Tether".to_string()]);
        assert_eq!(actions.apply, vec!["Tether".to_string()]);
        assert!(actions.restore.is_empty());
        assert!(actions.drop.is_empty());
    }

    #[test]
    fn plan_dns_vanished_service_is_dropped_not_restored() {
        // We owned "Tether" but it's gone from the current services.
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["100.64.0.1"]))]);
        let targets = dns_decision(DnsPolicy::PrimaryOnly, &fp, false)
            .targets()
            .to_vec();
        let actions = plan_dns_actions(
            &tunnel(),
            &fp,
            &["Wi-Fi".to_string(), "Tether".to_string()],
            &targets,
        );

        assert_eq!(actions.drop, vec!["Tether".to_string()]);
        assert!(actions.restore.is_empty());
        assert!(actions.capture.is_empty());
        assert!(actions.apply.is_empty());
    }

    #[test]
    fn plan_dns_steady_state_is_a_no_op() {
        // Primary already shows tunnel DNS and is owned → nothing to do.
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["100.64.0.1"]))]);
        let targets = dns_decision(DnsPolicy::PrimaryOnly, &fp, false)
            .targets()
            .to_vec();
        let actions = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], &targets);
        assert_eq!(actions, DnsActions::default());
    }

    #[test]
    fn dns_reconcile_forced_covers_collision_transitions() {
        let wifi = || vec!["Wi-Fi".to_string()];

        // Steady state, no collision, already own the target: guard may skip.
        assert!(!dns_reconcile_forced(false, &wifi(), &wifi()));

        // Entering a colliding LAN while we own services: must pull back, even
        // though the fingerprint need not have moved.
        assert!(dns_reconcile_forced(true, &wifi(), &[]));

        // In a collision but owning nothing: nothing to restore, don't force.
        assert!(!dns_reconcile_forced(true, &[], &[]));

        // Leaving a collision: we own nothing but should own the primary again.
        // This is the roam-off-collision case that previously never re-applied.
        assert!(dns_reconcile_forced(false, &[], &wifi()));

        // No collision and every target already owned: don't force.
        assert!(!dns_reconcile_forced(false, &wifi(), &wifi()));

        // No collision, no targets (e.g. VPN promotes no DNS): don't force.
        assert!(!dns_reconcile_forced(false, &[], &[]));
    }

    #[test]
    fn plan_dns_adopts_leaked_tunnel_dns_on_unowned_target() {
        // A prior run left tunnel DNS on the primary but we don't own it (its
        // saved original was lost to a crash/kill/uninstall). Capture it so
        // teardown can restore it to Empty — otherwise the unreachable tunnel
        // resolver is stranded forever. Differs from the owned steady state:
        // here `owned` is empty.
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["100.64.0.1"]))]);
        let targets = dns_decision(DnsPolicy::PrimaryOnly, &fp, false)
            .targets()
            .to_vec();
        let actions = plan_dns_actions(&tunnel(), &fp, &[], &targets);

        assert_eq!(actions.capture, vec!["Wi-Fi".to_string()]); // adopt the leak
        assert!(actions.apply.is_empty()); // already tunnel DNS; nothing to re-assert
        assert!(actions.restore.is_empty());
        assert!(actions.drop.is_empty());
    }

    #[test]
    fn plan_dns_partial_overlap_is_not_a_match() {
        // VPN [100.64.0.1, 8.8.8.8] vs observed [100.64.0.1] is not equal → apply.
        let tunnel = vec!["100.64.0.1".to_string(), "8.8.8.8".to_string()];
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["100.64.0.1"]))]);
        let targets = dns_decision(DnsPolicy::PrimaryOnly, &fp, false)
            .targets()
            .to_vec();
        let actions = plan_dns_actions(&tunnel, &fp, &[], &targets);
        assert_eq!(actions.apply, vec!["Wi-Fi".to_string()]);
        assert_eq!(actions.capture, vec!["Wi-Fi".to_string()]);
    }
}
