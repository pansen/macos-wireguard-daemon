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
use anyhow::Context;
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
/// we are currently directly attached to (so we never hijack our own LAN).
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
        routes.push(route);
    }

    routes
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
    if fingerprint == routing.fingerprint {
        return false;
    }

    let previous = routing.fingerprint.clone();
    info!(
        interface = inputs.interface,
        old_gateway = ?previous.endpoint_gateway,
        new_gateway = ?fingerprint.endpoint_gateway,
        old_local_subnets = %format_subnets(&previous.local_subnets),
        new_local_subnets = %format_subnets(&fingerprint.local_subnets),
        "userspace_helper_network_change_detected"
    );

    let desired = macos_desired_routes(inputs, &fingerprint);
    let current = routing.routes_added.clone();
    debug!(
        interface = inputs.interface,
        previous_routes = ?current,
        desired_routes = ?desired,
        endpoint_pin = inputs.endpoint_needs_pin,
        "userspace_helper_route_reconcile_plan"
    );
    log_macos_network_diagnostics("before_route_reconcile", inputs);
    let mut installed: Vec<MacosRoute> = Vec::new();
    let (mut added, mut removed, mut errors) = (0usize, 0usize, 0usize);

    // Remove routes that are no longer desired (e.g. a LAN we just left, or a
    // stale endpoint pin via the previous gateway).
    for route in &current {
        if !desired.contains(route) {
            match del_macos_route(route) {
                Ok(()) => {
                    removed += 1;
                    // Joining a LAN the tunnel already routed costs that LAN its
                    // connected route; dropping ours is only half the repair.
                    macos_restore_shadowed_lan_route(
                        route,
                        &fingerprint.local_subnets,
                        &inputs.interface,
                    );
                }
                Err(error) => {
                    errors += 1;
                    warn!(
                        destination = %route.destination,
                        error = %error,
                        "userspace_helper_reconcile_route_delete_failed"
                    );
                }
            }
        }
    }

    // Add newly desired routes; keep the ones already present.
    for route in desired {
        if current.contains(&route) {
            installed.push(route);
            continue;
        }
        match add_macos_route(&route) {
            Ok(MacosRouteInstall::Owned) => {
                added += 1;
                installed.push(route);
            }
            Ok(MacosRouteInstall::Foreign) => warn!(
                destination = %route.destination,
                "userspace_helper_route_skipped_physical_prefix"
            ),
            Err(error) => {
                errors += 1;
                warn!(
                    destination = %route.destination,
                    error = %error,
                    "userspace_helper_reconcile_route_add_failed"
                );
            }
        }
    }

    routing.routes_added = installed;
    routing.fingerprint = fingerprint.clone();

    info!(
        interface = inputs.interface,
        routes_added = added,
        routes_removed = removed,
        errors,
        "userspace_helper_reconcile_applied"
    );
    true
}

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
}
