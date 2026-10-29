use super::net::format_subnets;
use super::net::macos_network_base;
use super::net::macos_subnet_contains;
use super::net::parse_cidr;
use super::overview::log_macos_network_diagnostics;
use super::route_table::add_macos_route;
use super::route_table::del_macos_route;
use super::route_table::macos_restore_shadowed_lan_route;
use super::route_table::MacosRouteInstall;
use super::system::macos_local_connected_subnets;
use super::MacosCleanupState;
use super::MacosNetworkFingerprint;
use super::MacosReconcileInputs;
use super::MacosRoute;
use crate::bypass_links::BypassLink;
use anyhow::Context;
use ipnet::IpNet;
use std::net::IpAddr;
use tracing::{debug, info, warn};

pub(super) fn macos_allowed_routes(
    allowed_ips: &[String],
    interface: &str,
    has_ipv4_address: bool,
    has_ipv6_address: bool,
) -> Vec<MacosRoute> {
    let mut routes = Vec::new();
    for allowed in allowed_ips {
        match allowed.as_str() {
            "0.0.0.0/0" => {
                if !has_ipv4_address {
                    continue;
                }
                routes.push(MacosRoute {
                    is_ipv6: false,
                    destination: "0.0.0.0/1".to_string(),
                    interface: Some(interface.to_string()),
                    gateway: None,
                });
                routes.push(MacosRoute {
                    is_ipv6: false,
                    destination: "128.0.0.0/1".to_string(),
                    interface: Some(interface.to_string()),
                    gateway: None,
                });
            }
            "::/0" => {
                if !has_ipv6_address {
                    continue;
                }
                routes.push(MacosRoute {
                    is_ipv6: true,
                    destination: "::/1".to_string(),
                    interface: Some(interface.to_string()),
                    gateway: None,
                });
                routes.push(MacosRoute {
                    is_ipv6: true,
                    destination: "8000::/1".to_string(),
                    interface: Some(interface.to_string()),
                    gateway: None,
                });
            }
            other => {
                if other.contains(':') && !has_ipv6_address {
                    continue;
                }
                if !other.contains(':') && !has_ipv4_address {
                    continue;
                }
                routes.push(MacosRoute {
                    is_ipv6: other.contains(':'),
                    destination: other.to_string(),
                    interface: Some(interface.to_string()),
                    gateway: None,
                });
            }
        }
    }
    routes
}

/// The routes this tunnel wants installed for the given network environment:
/// the (optional) endpoint pin plus the AllowedIPs routes, minus any subnet
/// we are currently directly attached to (so we never hijack our own LAN) and
/// minus the prefixes of every active bypass link (`doc/lan-bypass-links.md`).
pub(super) fn macos_desired_routes(
    inputs: &MacosReconcileInputs,
    fingerprint: &MacosNetworkFingerprint,
) -> Vec<MacosRoute> {
    let mut routes = Vec::new();

    if inputs.endpoint_needs_pin {
        if let Some(gateway) = &fingerprint.endpoint_gateway {
            routes.push(MacosRoute {
                is_ipv6: inputs.endpoint_is_ipv6,
                destination: inputs.endpoint.to_string(),
                interface: None,
                gateway: Some(gateway.clone()),
            });
        }
    }

    for route in macos_allowed_routes(
        &inputs.allowed_ips,
        &inputs.interface,
        inputs.has_ipv4_address,
        inputs.has_ipv6_address,
    ) {
        if let Some((subnet_ip, subnet_prefix)) =
            macos_route_excluded_by_local_subnet(&route, &fingerprint.local_subnets)
        {
            debug!(
                destination = %route.destination,
                local_subnet = %format!("{subnet_ip}/{subnet_prefix}"),
                "userspace_helper_route_excluded_local_lan"
            );
            continue;
        }
        if let Some(exclusion) =
            macos_route_excluded_by_link(&route, &fingerprint.local_subnets, &inputs.bypass_links)
        {
            debug!(
                destination = %route.destination,
                anchor = %exclusion.anchor,
                "userspace_helper_route_excluded_linked"
            );
            continue;
        }
        routes.push(route);
    }

    routes
}

/// The link that keeps a tunnel route off the tunnel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct MacosLinkExclusion {
    /// The anchor of the link.
    pub(super) anchor: IpNet,
    /// The connected subnet that makes the anchor active; its device carries
    /// the bypassed traffic.
    pub(super) subnet: (IpAddr, u8),
}

/// Returns the first active link with a bypass prefix that equals the
/// destination of `route` or contains it, or `None` if the route should be
/// installed normally.
///
/// A link is active while some connected subnet contains its anchor, the same
/// containment the local-subnet exclusion applies to AllowedIPs entries. The
/// result depends on `local_subnets` and the static links only, so the route
/// fingerprint needs no field of its own. Linked prefixes deliberately never
/// join `local_subnets`: `macos_restore_shadowed_lan_route` would try to
/// re-add them as connected routes.
pub(super) fn macos_route_excluded_by_link(
    route: &MacosRoute,
    local_subnets: &[(IpAddr, u8)],
    links: &[BypassLink],
) -> Option<MacosLinkExclusion> {
    // Only tunnel-bound routes (interface, no gateway) are ours to bypass.
    if links.is_empty() || route.interface.is_none() || route.gateway.is_some() {
        return None;
    }
    let (ip, prefix) = parse_cidr(&route.destination).ok()?;
    let destination = IpNet::new(macos_network_base(ip, prefix), prefix).ok()?;
    links.iter().find_map(|link| {
        if !link.bypass.matches(&destination) {
            return None;
        }
        let anchor = (link.anchor.network(), link.anchor.prefix_len());
        local_subnets
            .iter()
            .find(|local| macos_subnet_contains(local, &anchor))
            .map(|subnet| MacosLinkExclusion {
                anchor: link.anchor,
                subnet: *subnet,
            })
    })
}

/// Returns the connected subnet that makes `route` local (so it must stay off
/// the tunnel), or `None` if the route should be installed normally.
pub(super) fn macos_route_excluded_by_local_subnet(
    route: &MacosRoute,
    local_subnets: &[(IpAddr, u8)],
) -> Option<(IpAddr, u8)> {
    // Only tunnel-bound routes (interface, no gateway) can hijack a LAN.
    if route.interface.is_none() || route.gateway.is_some() {
        return None;
    }
    let (ip, prefix) = parse_cidr(&route.destination).ok()?;
    let destination = (macos_network_base(ip, prefix), prefix);
    local_subnets
        .iter()
        .find(|local| macos_subnet_contains(local, &destination))
        .copied()
}

/// True when any AllowedIPs entry would route the endpoint into the tunnel.
pub(super) fn macos_allowed_ips_cover_endpoint(allowed_ips: &[String], endpoint: IpAddr) -> bool {
    allowed_ips.iter().any(|allowed| {
        let Ok((net, prefix)) = parse_cidr(allowed) else {
            return false;
        };
        match (net, endpoint) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                macos_network_base(endpoint, prefix) == macos_network_base(net, prefix)
            }
            _ => false,
        }
    })
}

/// How `macos_current_fingerprint` should treat a failed default-gateway lookup.
pub(super) enum GatewayFallback {
    /// Initial setup: a missing gateway is fatal. Without the pin the endpoint
    /// would route into the tunnel and break connectivity, so propagate the error.
    Require,
    /// Reconcile tick: keep this previously resolved gateway on a transient
    /// failure rather than silently dropping the endpoint pin.
    Keep(Option<String>),
}

/// Snapshot the current network environment that drives tunnel routing.
///
/// When the endpoint must be pinned out of the tunnel the default gateway is
/// required; `gateway_fallback` decides what happens if that lookup fails (see
/// [`GatewayFallback`]). The lookup is skipped entirely when no pin is needed, so
/// no-op reconcile ticks don't run `route get default`.
pub(super) fn macos_current_fingerprint(
    inputs: &MacosReconcileInputs,
    gateway_fallback: GatewayFallback,
) -> anyhow::Result<MacosNetworkFingerprint> {
    let local_subnets = macos_local_connected_subnets(&inputs.interface);
    let endpoint_gateway = if inputs.endpoint_needs_pin {
        match get_macos_default_gateway(inputs.endpoint_is_ipv6) {
            Ok(Some(gateway)) => Some(gateway),
            Ok(None) => match gateway_fallback {
                GatewayFallback::Require => anyhow::bail!(
                    "no default gateway available to pin endpoint {} out of the tunnel",
                    inputs.endpoint
                ),
                GatewayFallback::Keep(previous) => {
                    warn!(
                        interface = inputs.interface,
                        endpoint = %inputs.endpoint,
                        "userspace_helper_reconcile_gateway_unresolved_keeping_previous"
                    );
                    previous
                }
            },
            Err(error) => match gateway_fallback {
                GatewayFallback::Require => {
                    return Err(error.context(format!(
                        "failed to resolve default gateway to pin endpoint {} out of the tunnel",
                        inputs.endpoint
                    )));
                }
                GatewayFallback::Keep(previous) => {
                    warn!(
                        interface = inputs.interface,
                        endpoint = %inputs.endpoint,
                        error = %error,
                        "userspace_helper_reconcile_gateway_lookup_failed_keeping_previous"
                    );
                    previous
                }
            },
        }
    } else {
        None
    };
    Ok(MacosNetworkFingerprint {
        local_subnets,
        endpoint_gateway,
    })
}

/// Re-apply routing when the host network changed (roam, suspend/resume, link
/// up/down). Cheap and silent when nothing changed; expressive when it acts.
pub(in crate::userspace_helper) fn macos_reconcile_routes(state: &MacosCleanupState) -> bool {
    let inputs = &state.reconcile;

    let mut routing = state
        .routing
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Reconcile is best-effort: if the gateway lookup fails transiently, keep the
    // last known gateway rather than dropping the endpoint pin (which would route
    // the endpoint into the tunnel until the next change).
    let previous_gateway = routing.fingerprint.endpoint_gateway.clone();
    let fingerprint =
        match macos_current_fingerprint(inputs, GatewayFallback::Keep(previous_gateway)) {
            Ok(fingerprint) => fingerprint,
            // `Keep` mode does not propagate gateway errors, but stay defensive:
            // skip this tick rather than acting on a half-built fingerprint.
            Err(error) => {
                warn!(
                    interface = inputs.interface,
                    error = %error,
                    "userspace_helper_reconcile_fingerprint_failed"
                );
                return false;
            }
        };
    // An unchanged network normally means nothing to do. After a failed add or
    // delete it means "try the failed operations again": nothing else would.
    let retry = fingerprint == routing.fingerprint;
    if retry && routing.failing.is_empty() {
        return false;
    }

    if retry {
        debug!(
            interface = inputs.interface,
            failing = routing.failing.len(),
            "userspace_helper_route_reconcile_retry"
        );
    } else {
        let previous = routing.fingerprint.clone();
        info!(
            interface = inputs.interface,
            old_gateway = ?previous.endpoint_gateway,
            new_gateway = ?fingerprint.endpoint_gateway,
            old_local_subnets = %format_subnets(&previous.local_subnets),
            new_local_subnets = %format_subnets(&fingerprint.local_subnets),
            "userspace_helper_network_change_detected"
        );
    }

    let desired = macos_desired_routes(inputs, &fingerprint);
    debug!(
        interface = inputs.interface,
        previous_routes = ?routing.routes_added,
        desired_routes = ?desired,
        endpoint_pin = inputs.endpoint_needs_pin,
        "userspace_helper_route_reconcile_plan"
    );
    if !retry {
        log_macos_network_diagnostics("before_route_reconcile", inputs);
    }
    let applied = macos_apply_route_plan(
        &mut routing,
        desired,
        retry,
        &del_macos_route,
        &add_macos_route,
        &|route| {
            // Joining a LAN the tunnel already routed costs that LAN its
            // connected route; dropping ours is only half the repair.
            macos_restore_shadowed_lan_route(route, &fingerprint.local_subnets, &inputs.interface)
        },
    );
    routing.fingerprint = fingerprint.clone();

    if retry && applied.added + applied.removed == 0 {
        // Still failing, nothing new to report: stay quiet.
        return false;
    }
    info!(
        interface = inputs.interface,
        routes_added = applied.added,
        routes_removed = applied.removed,
        errors = applied.errors,
        "userspace_helper_reconcile_applied"
    );
    true
}

use super::{MacosRouteFailure, MacosRouteOperation, MacosRoutingState};

/// What one pass of [`macos_apply_route_plan`] did.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct RouteApplied {
    pub(super) added: usize,
    pub(super) removed: usize,
    pub(super) errors: usize,
}

/// Bring the routes this tunnel owns (`routing.routes_added`) in line with
/// `desired`, and record in `routing.failing` the operations that failed.
///
/// A route whose delete failed stays owned: it is still in the kernel, so the
/// next pass and teardown must try it again. A route whose add failed is not
/// owned, but it is remembered. On a `retry_only` pass (the network did not
/// change, so only the failures are being retried) just those adds and the
/// replacements waiting for a failed delete are attempted. The other desired
/// routes that are not installed were skipped on purpose (a physical
/// interface holds the prefix) and stay skipped.
///
/// `delete`, `add` and `restore` do the system calls (injected so tests need
/// no routing table); `restore` runs after each successful delete.
pub(super) fn macos_apply_route_plan(
    routing: &mut MacosRoutingState,
    desired: Vec<MacosRoute>,
    retry_only: bool,
    delete: &dyn Fn(&MacosRoute) -> anyhow::Result<()>,
    add: &dyn Fn(&MacosRoute) -> anyhow::Result<MacosRouteInstall>,
    restore: &dyn Fn(&MacosRoute),
) -> RouteApplied {
    let previous = std::mem::take(&mut routing.failing);
    let current = std::mem::take(&mut routing.routes_added);
    let mut installed: Vec<MacosRoute> = Vec::new();
    let mut failing: Vec<MacosRouteFailure> = Vec::new();
    let mut applied = RouteApplied::default();

    // Remove routes that are no longer desired (e.g. a LAN we just left, or a
    // stale endpoint pin via the previous gateway).
    for route in &current {
        if desired.contains(route) {
            installed.push(route.clone());
            continue;
        }
        match delete(route) {
            Ok(()) => {
                applied.removed += 1;
                note_retry_succeeded(&previous, route, MacosRouteOperation::Delete);
                restore(route);
            }
            Err(error) => {
                applied.errors += 1;
                // Still in the kernel, so still ours.
                installed.push(route.clone());
                failing.push(record_failure(
                    &previous,
                    route,
                    MacosRouteOperation::Delete,
                    &error,
                ));
            }
        }
    }

    // Add newly desired routes; keep the ones already present.
    for route in desired {
        if current.contains(&route) {
            continue;
        }
        // `route add` accepts EEXIST as success. While the old gateway is
        // still installed, that would falsely claim its replacement too;
        // retrying the old delete would then remove the only kernel entry.
        if failing.iter().any(|failure| {
            failure.operation == MacosRouteOperation::Delete
                && same_route_destination(&failure.route, &route)
        }) {
            continue;
        }
        let add_failed_before = previous
            .iter()
            .any(|f| f.route == route && f.operation == MacosRouteOperation::Add);
        let replacement_waited = previous.iter().any(|failure| {
            failure.operation == MacosRouteOperation::Delete
                && same_route_destination(&failure.route, &route)
        });
        if retry_only && !add_failed_before && !replacement_waited {
            continue;
        }
        match add(&route) {
            Ok(MacosRouteInstall::Owned) => {
                applied.added += 1;
                note_retry_succeeded(&previous, &route, MacosRouteOperation::Add);
                installed.push(route);
            }
            Ok(MacosRouteInstall::Foreign) => warn!(
                destination = %route.destination,
                "userspace_helper_route_skipped_physical_prefix"
            ),
            Err(error) => {
                applied.errors += 1;
                failing.push(record_failure(
                    &previous,
                    &route,
                    MacosRouteOperation::Add,
                    &error,
                ));
            }
        }
    }

    routing.routes_added = installed;
    routing.failing = failing;
    applied
}

/// The kernel key of a route, independent of its gateway or interface. Host
/// pins have no CIDR suffix; AllowedIPs may have non-canonical host bits.
fn same_route_destination(left: &MacosRoute, right: &MacosRoute) -> bool {
    match (
        super::route_table::macos_route_destination(left),
        super::route_table::macos_route_destination(right),
    ) {
        (Some(left), Some(right)) => left == right,
        _ => left.is_ipv6 == right.is_ipv6 && left.destination == right.destination,
    }
}

/// Whether a failure of `operation` on `route` repeats the identical failure of
/// the pass before.
fn is_repeated_failure(
    previous: &[MacosRouteFailure],
    route: &MacosRoute,
    operation: MacosRouteOperation,
    error: &str,
) -> bool {
    previous
        .iter()
        .any(|f| f.route == *route && f.operation == operation && f.error == error)
}

/// Log a failed operation and return the record to retry it. The first failure
/// of a route (or one with a different error than before) is a warning; the
/// same failure again is debug, so an error that persists does not fill the log
/// every tick.
fn record_failure(
    previous: &[MacosRouteFailure],
    route: &MacosRoute,
    operation: MacosRouteOperation,
    error: &anyhow::Error,
) -> MacosRouteFailure {
    let error = error.to_string();
    let repeated = is_repeated_failure(previous, route, operation, &error);
    let destination = &route.destination;
    match (operation, repeated) {
        (MacosRouteOperation::Add, false) => warn!(
            destination = %destination,
            error = %error,
            "userspace_helper_reconcile_route_add_failed"
        ),
        (MacosRouteOperation::Add, true) => debug!(
            destination = %destination,
            error = %error,
            "userspace_helper_reconcile_route_add_failed"
        ),
        (MacosRouteOperation::Delete, false) => warn!(
            destination = %destination,
            error = %error,
            "userspace_helper_reconcile_route_delete_failed"
        ),
        (MacosRouteOperation::Delete, true) => debug!(
            destination = %destination,
            error = %error,
            "userspace_helper_reconcile_route_delete_failed"
        ),
    }
    MacosRouteFailure {
        route: route.clone(),
        operation,
        error,
    }
}

/// Say so when an operation that failed on the pass before now worked.
fn note_retry_succeeded(
    previous: &[MacosRouteFailure],
    route: &MacosRoute,
    operation: MacosRouteOperation,
) {
    if previous
        .iter()
        .any(|f| f.route == *route && f.operation == operation)
    {
        info!(
            destination = %route.destination,
            operation = ?operation,
            "userspace_helper_reconcile_route_retry_succeeded"
        );
    }
}

#[cfg(test)]
#[path = "route_reconcile_tests.rs"]
mod reconcile_tests;

pub(super) fn get_macos_default_gateway(is_ipv6: bool) -> anyhow::Result<Option<String>> {
    let mut args = vec!["-n", "get"];
    if is_ipv6 {
        args.push("-inet6");
    }
    args.push("default");

    let output = crate::trusted_exec::command("route")
        .expect("system command is approved")
        .args(args)
        .output()
        .context("failed to run route -n get default")?;
    if !output.status.success() {
        if is_ipv6 {
            return Ok(None);
        }
        anyhow::bail!("route -n get default failed");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(value) = line.trim().strip_prefix("gateway:") {
            return Ok(Some(value.trim().to_string()));
        }
    }
    if is_ipv6 {
        Ok(None)
    } else {
        anyhow::bail!("default gateway not found")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::userspace_helper::macos::test_support::split_inputs;
    use crate::userspace_helper::macos::test_support::subnet;
    use crate::userspace_helper::macos::MacosNetworkFingerprint;
    use crate::userspace_helper::macos::MacosReconcileInputs;
    use crate::userspace_helper::macos::MacosRoute;
    use std::net::IpAddr;

    #[test]
    fn endpoint_pinned_only_when_allowed_ips_cover_it() {
        let endpoint: IpAddr = "23.88.101.22".parse().unwrap();
        let split = vec!["100.64.0.0/24".to_string(), "55.56.57.0/24".to_string()];
        assert!(!macos_allowed_ips_cover_endpoint(&split, endpoint));
        let full = vec!["0.0.0.0/0".to_string()];
        assert!(macos_allowed_ips_cover_endpoint(&full, endpoint));
    }

    #[test]
    fn local_lan_is_excluded_but_returns_to_the_tunnel_on_a_different_lan() {
        let inputs = split_inputs();

        // Sitting in the home LAN: that subnet must NOT be routed into the tunnel.
        let home = MacosNetworkFingerprint {
            local_subnets: vec![subnet("55.56.57.0/24")],
            endpoint_gateway: None,
        };
        let dests: Vec<String> = macos_desired_routes(&inputs, &home)
            .into_iter()
            .map(|route| route.destination)
            .collect();
        assert!(!dests.iter().any(|d| d == "55.56.57.0/24"));
        assert!(dests.iter().any(|d| d == "100.64.0.0/24"));

        // After roaming elsewhere, 55.56.57.0/24 is remote again and IS tunnelled.
        let elsewhere = MacosNetworkFingerprint {
            local_subnets: vec![subnet("10.20.30.0/24")],
            endpoint_gateway: None,
        };
        let dests: Vec<String> = macos_desired_routes(&inputs, &elsewhere)
            .into_iter()
            .map(|route| route.destination)
            .collect();
        assert!(dests.iter().any(|d| d == "55.56.57.0/24"));
        assert!(dests.iter().any(|d| d == "100.64.0.0/24"));
    }

    #[test]
    fn containment_matches_equal_and_more_specific_routes_only() {
        let local = subnet("55.56.57.0/24");

        let equal = MacosRoute {
            is_ipv6: false,
            destination: "55.56.57.0/24".to_string(),
            interface: Some("utun6".to_string()),
            gateway: None,
        };
        assert!(macos_route_excluded_by_local_subnet(&equal, &[local]).is_some());

        let more_specific = MacosRoute {
            is_ipv6: false,
            destination: "55.56.57.128/25".to_string(),
            interface: Some("utun6".to_string()),
            gateway: None,
        };
        assert!(macos_route_excluded_by_local_subnet(&more_specific, &[local]).is_some());

        // A broader supernet is not treated as local (we do not split routes).
        let broader = MacosRoute {
            is_ipv6: false,
            destination: "55.56.0.0/16".to_string(),
            interface: Some("utun6".to_string()),
            gateway: None,
        };
        assert!(macos_route_excluded_by_local_subnet(&broader, &[local]).is_none());

        // Gatewayed (non-tunnel) routes are never excluded.
        let gatewayed = MacosRoute {
            is_ipv6: false,
            destination: "55.56.57.0/24".to_string(),
            interface: None,
            gateway: Some("10.0.0.1".to_string()),
        };
        assert!(macos_route_excluded_by_local_subnet(&gatewayed, &[local]).is_none());
    }

    fn link(anchor: &str, bypass: &[&str]) -> BypassLink {
        BypassLink::new(
            anchor.parse().unwrap(),
            bypass
                .iter()
                .map(|prefix| prefix.parse().unwrap())
                .collect(),
        )
    }

    /// The home example of `doc/lan-bypass-links.md`.
    fn home_inputs(links: Vec<BypassLink>) -> MacosReconcileInputs {
        let mut inputs = split_inputs();
        inputs.allowed_ips = [
            "192.168.168.0/24",
            "100.64.1.0/24",
            "10.66.77.0/24",
            "192.168.188.1/32",
        ]
        .map(String::from)
        .to_vec();
        inputs.bypass_links = links;
        inputs
    }

    fn desired(inputs: &MacosReconcileInputs, local: &[&str]) -> Vec<String> {
        let fingerprint = MacosNetworkFingerprint {
            local_subnets: local.iter().map(|net| subnet(net)).collect(),
            endpoint_gateway: None,
        };
        macos_desired_routes(inputs, &fingerprint)
            .into_iter()
            .map(|route| route.destination)
            .collect()
    }

    #[test]
    fn link_bypass_applies_only_while_the_anchor_is_connected() {
        let inputs = home_inputs(vec![link("10.66.77.0/24", &["192.168.188.1/32"])]);

        // Away: everything goes through the tunnel.
        let away = desired(&inputs, &["172.16.5.0/24"]);
        assert_eq!(away.len(), 4);
        assert!(away.contains(&"192.168.188.1/32".to_string()));

        // At home: the LAN itself (local-subnet rule) and the linked host
        // leave the tunnel, the other two stay.
        let home = desired(&inputs, &["10.66.77.0/24"]);
        assert_eq!(home, vec!["192.168.168.0/24", "100.64.1.0/24"]);

        // Leaving again brings the linked host back.
        assert_eq!(desired(&inputs, &[]), away);
    }

    #[test]
    fn link_without_links_changes_nothing() {
        let inputs = home_inputs(Vec::new());
        assert_eq!(desired(&inputs, &["10.66.77.0/24"]).len(), 3);
    }

    #[test]
    fn anchor_inside_a_broader_connected_subnet_is_active() {
        // The LAN is a /16, the anchor a /24 inside it: containment, as for
        // AllowedIPs entries.
        let inputs = home_inputs(vec![link("10.66.77.0/24", &["192.168.188.1/32"])]);
        let dests = desired(&inputs, &["10.66.0.0/16"]);
        assert!(!dests.contains(&"192.168.188.1/32".to_string()));
    }

    #[test]
    fn anchor_broader_than_the_connected_subnet_is_inactive() {
        // Attached to a /25 of the anchor's /24: the Mac is not on the whole
        // anchor network, so the link stays off.
        let inputs = home_inputs(vec![link("10.66.77.0/24", &["192.168.188.1/32"])]);
        let dests = desired(&inputs, &["10.66.77.0/25"]);
        assert!(dests.contains(&"192.168.188.1/32".to_string()));
    }

    #[test]
    fn link_bypass_works_for_ipv6() {
        let mut inputs = home_inputs(vec![link("fd00:66::/64", &["fd00:188::1/128"])]);
        inputs.allowed_ips = vec!["fd00:188::1/128".to_string(), "fd00:168::/64".to_string()];
        inputs.has_ipv6_address = true;
        let home = desired(&inputs, &["fd00:66::/64"]);
        assert_eq!(home, vec!["fd00:168::/64"]);
        let away = desired(&inputs, &["10.66.77.0/24"]);
        assert_eq!(away.len(), 2);
        // A v4 connected subnet never activates a v6 anchor.
        let v4_lan = desired(&inputs, &["10.0.0.0/8"]);
        assert_eq!(v4_lan.len(), 2);
    }

    #[test]
    fn two_links_sharing_a_bypass_prefix_need_only_one_active_anchor() {
        let inputs = home_inputs(vec![
            link("10.66.77.0/24", &["192.168.188.1/32"]),
            link("172.16.5.0/24", &["192.168.188.1/32"]),
        ]);
        for local in ["10.66.77.0/24", "172.16.5.0/24"] {
            let dests = desired(&inputs, &[local]);
            assert!(!dests.contains(&"192.168.188.1/32".to_string()), "{local}");
        }
        let both = desired(&inputs, &["10.66.77.0/24", "172.16.5.0/24"]);
        assert!(!both.contains(&"192.168.188.1/32".to_string()));
        let neither = desired(&inputs, &["192.0.2.0/24"]);
        assert!(neither.contains(&"192.168.188.1/32".to_string()));
    }

    #[test]
    fn link_prefix_that_is_also_a_connected_subnet_is_excluded_once() {
        // 192.168.188.0/24 is both attached and linked: the local-subnet rule
        // already removes it, the link adds nothing and breaks nothing.
        let mut inputs = home_inputs(vec![link("10.66.77.0/24", &["192.168.188.0/24"])]);
        inputs.allowed_ips.push("192.168.188.0/24".to_string());
        let dests = desired(&inputs, &["10.66.77.0/24", "192.168.188.0/24"]);
        assert!(!dests.contains(&"192.168.188.0/24".to_string()));
        assert!(dests.contains(&"192.168.168.0/24".to_string()));
    }

    #[test]
    fn link_matches_the_normalised_destination_only() {
        let route = |destination: &str| MacosRoute {
            is_ipv6: false,
            destination: destination.to_string(),
            interface: Some("utun6".to_string()),
            gateway: None,
        };
        let links = [link("10.66.77.0/24", &["192.168.188.0/24"])];
        let local = [subnet("10.66.77.0/24")];

        // AllowedIPs may carry host bits; the comparison uses the network base.
        let exclusion = macos_route_excluded_by_link(&route("192.168.188.1/24"), &local, &links)
            .expect("normalised destination equals the bypass prefix");
        assert_eq!(exclusion.anchor, "10.66.77.0/24".parse().unwrap());
        assert_eq!(exclusion.subnet, subnet("10.66.77.0/24"));

        // A more specific route lies inside the prefix and goes with it; a
        // broader one or a neighbour does not.
        assert!(macos_route_excluded_by_link(&route("192.168.188.1/32"), &local, &links).is_some());
        for other in ["192.168.0.0/16", "192.168.189.0/24"] {
            assert!(macos_route_excluded_by_link(&route(other), &local, &links).is_none());
        }

        // The endpoint pin (gateway route) is never bypassed.
        let pin = MacosRoute {
            is_ipv6: false,
            destination: "192.168.188.0/24".to_string(),
            interface: None,
            gateway: Some("10.66.77.1".to_string()),
        };
        assert!(macos_route_excluded_by_link(&pin, &local, &links).is_none());
    }

    #[test]
    fn link_prefixes_never_join_the_connected_subnets() {
        // `macos_restore_shadowed_lan_route` works from `local_subnets`; a
        // linked prefix there would be re-added as an on-link route.
        let route = MacosRoute {
            is_ipv6: false,
            destination: "192.168.188.1/32".to_string(),
            interface: Some("utun6".to_string()),
            gateway: None,
        };
        assert!(macos_route_excluded_by_local_subnet(&route, &[subnet("10.66.77.0/24")]).is_none());
    }

    #[test]
    fn link_bypass_takes_routes_inside_the_prefix_off_the_tunnel_too() {
        // The /24 is bypassed; a /32 AllowedIPs entry inside it would keep
        // .7 on the tunnel if only the equal route went.
        let mut inputs = home_inputs(vec![link("10.66.77.0/24", &["192.168.188.0/24"])]);
        inputs.allowed_ips = [
            "10.66.77.0/24",
            "192.168.188.0/24",
            "192.168.188.7/32",
            "192.168.189.0/24",
            "192.168.168.0/24",
        ]
        .map(String::from)
        .to_vec();
        let home = desired(&inputs, &["10.66.77.0/24"]);
        assert_eq!(home, vec!["192.168.189.0/24", "192.168.168.0/24"]);
        // Away, all of them are tunnelled again.
        assert_eq!(desired(&inputs, &["172.16.5.0/24"]).len(), 5);
    }

    #[test]
    fn link_bypass_takes_ipv6_routes_inside_the_prefix_off_the_tunnel_too() {
        let mut inputs = home_inputs(vec![link("fd00:66::/64", &["fd00:188::/64"])]);
        inputs.allowed_ips = [
            "fd00:66::/64",
            "fd00:188::/64",
            "fd00:188::7/128",
            "fd00:189::/64",
        ]
        .map(String::from)
        .to_vec();
        inputs.has_ipv6_address = true;
        assert_eq!(desired(&inputs, &["fd00:66::/64"]), vec!["fd00:189::/64"]);
        assert_eq!(desired(&inputs, &[]).len(), 4);
    }
}
