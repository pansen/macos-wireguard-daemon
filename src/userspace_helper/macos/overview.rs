use super::dns_plan::dns_decision;
use super::dns_plan::macos_dns_server_in_local_subnet;
use super::dns_plan::DnsDecision;
use super::dns_plan::DNS_POLICY;
use super::foreign::macos_foreign_tunnels;
use super::foreign::macos_global_resolvers;
use super::foreign::tailscaled_socket_present;
use super::foreign::MacosForeignSnapshot;
use super::route_table::macos_route_destination;
use super::route_table::macos_route_egress_interface;
use super::route_table::macos_route_table_entry;
use super::route_table::MacosRouteEntry;
use super::routes::macos_allowed_routes;
use super::routes::macos_route_excluded_by_link;
use super::routes::macos_route_excluded_by_local_subnet;
use super::system::macos_connected_subnet_device;
use super::system::macos_connected_subnets_by_device;
use super::MacosCleanupState;
use super::MacosDnsFingerprint;
use super::MacosDnsServiceState;
use super::MacosNetworkFingerprint;
use super::MacosReconcileInputs;
use super::MacosRoute;
use crate::status_model::DnsCollision;
use crate::status_model::DnsOverview;
use crate::status_model::DnsServiceRow;
use crate::status_model::DnsServiceStatus;
use crate::status_model::IpFamily;
use crate::status_model::LiveRoute;
use crate::status_model::NetworkOverview;
use crate::status_model::ResolverState;
use crate::status_model::RouteOutcome;
use crate::status_model::RouteRow;
use crate::status_model::RouteVia;
use crate::status_model::SystemResolver;
use crate::userspace_helper::exec::format_command_for_log;
use crate::userspace_helper::exec::run_command_capture_output;
use crate::userspace_helper::gotatun_query_socket_path;
use std::os::unix::fs::PermissionsExt;
use tracing::{debug, info, warn};

/// Read-only snapshots around network changes. Unlike the overview's owned-route
/// list, these show actual kernel routes (including split-tunnel default routes),
/// physical addresses/link state and DHCP's last received packet. The commands
/// are sequential observations, not an atomic snapshot or a live DHCP capture.
/// Keep them off steady-state ticks and skip all work unless DEBUG is enabled.
pub(in crate::userspace_helper) fn log_macos_network_diagnostics(
    reason: &str,
    inputs: &MacosReconcileInputs,
) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    let endpoint = inputs.endpoint.to_string();
    let family = if inputs.endpoint_is_ipv6 {
        "-inet6"
    } else {
        "-inet"
    };
    for (command, args) in [
        ("ifconfig", vec![]),
        ("scutil", vec!["--nwi"]),
        ("scutil", vec!["--dns"]),
        ("netstat", vec!["-rn"]),
        ("route", vec!["-n", "get", "-inet", "default"]),
        ("route", vec!["-n", "get", "-inet6", "default"]),
        ("route", vec!["-n", "get", family, endpoint.as_str()]),
    ] {
        log_macos_diagnostic_command(reason, &inputs.interface, command, &args);
    }
    // Include IPv6-only and link-local-only physical interfaces, since their
    // missing IPv4 lease is precisely what we need to investigate after wake.
    let mut devices: Vec<String> = macos_connected_subnets_by_device(&inputs.interface)
        .unwrap_or_default()
        .into_iter()
        .map(|(device, _)| device)
        .collect();
    devices.sort();
    devices.dedup();
    for device in devices {
        log_macos_diagnostic_command(
            reason,
            &inputs.interface,
            "ipconfig",
            &["getpacket", &device],
        );
    }
}

pub(super) fn log_macos_diagnostic_command(
    reason: &str,
    interface: &str,
    name: &str,
    args: &[&str],
) {
    let started = std::time::Instant::now();
    match run_command_capture_output(name, args) {
        Ok(output) => debug!(
            reason,
            interface,
            command = %format_command_for_log(name, args),
            status = %output.status,
            elapsed_ms = started.elapsed().as_millis(),
            stdout = %String::from_utf8_lossy(&output.stdout).trim(),
            stderr = %String::from_utf8_lossy(&output.stderr).trim(),
            "userspace_helper_network_diagnostic"
        ),
        Err(error) => debug!(
            reason,
            interface,
            command = %format_command_for_log(name, args),
            elapsed_ms = started.elapsed().as_millis(),
            error = %error,
            "userspace_helper_network_diagnostic_failed"
        ),
    }
}

/// Collect the host state behind the route + DNS overview of this tunnel.
/// Shells out to `route`/`ifconfig`/`scutil`, so call it off the async runtime.
pub(super) fn build_macos_network_overview(state: &MacosCleanupState) -> NetworkOverview {
    let inputs = &state.reconcile;
    let (routes, route_fingerprint) = {
        let routing = state
            .routing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (routing.routes_added.clone(), routing.fingerprint.clone())
    };
    let (owned_dns, dns_fingerprint) = {
        let dns = state
            .dns
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (dns.services.clone(), dns.fingerprint.clone())
    };
    // Snapshot the host's *foreign* tunnels and effective resolver so the
    // overview shows what else is steering traffic/DNS (e.g. Tailscale). These
    // are the parts that took a long debugging session to surface by hand.
    let foreign = MacosForeignSnapshot {
        tunnels: macos_foreign_tunnels(&inputs.interface),
        global_resolvers: macos_global_resolvers(),
        tailscaled_present: tailscaled_socket_present(),
    };
    let mut overview = assemble_macos_network_overview(
        inputs,
        &routes,
        &route_fingerprint,
        &owned_dns,
        &dns_fingerprint,
        &foreign,
        &|route| macos_route_destination(route).and_then(macos_route_table_entry),
        &|route| macos_route_destination(route).and_then(macos_route_egress_interface),
    );
    overview.dns.dynamic_store = state.dns_store_key.as_ref().map(|key| key.overview());
    overview
}

/// Log a full route + DNS overview as one structured field. Called once after
/// connect setup and after route/DNS reconciliation work, so the log shows the
/// resulting tunnel state.
pub(in crate::userspace_helper) fn log_macos_network_overview(
    reason: &str,
    state: &MacosCleanupState,
) {
    let overview = build_macos_network_overview(state);
    info!(
        reason,
        interface = state.reconcile.interface,
        overview = %serde_json::to_string(&overview).unwrap_or_default(),
        "network_overview"
    );
}

/// Serve the network overview on a per-interface Unix socket for the lifetime
/// of the tunnel. Each connection gets one freshly-collected overview as JSON and is
/// then closed — no request body is read, since the socket serves exactly one
/// thing. Runs on a dedicated blocking thread because collecting shells out to
/// `ifconfig`/`scutil`/`networksetup`, which must not block the async runtime.
pub(in crate::userspace_helper) fn spawn_overview_query_server(
    interface: &str,
    state: std::sync::Arc<MacosCleanupState>,
) {
    use std::io::Write;

    let path = gotatun_query_socket_path(interface);
    // A stale socket from a crashed predecessor would make bind() fail with
    // EADDRINUSE; clear it first (the pid file guards against a live double-run).
    let _ = std::fs::remove_file(&path);
    let listener = match std::os::unix::net::UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(error) => {
            warn!(interface, error = %error, "userspace_helper_query_socket_bind_failed");
            return;
        }
    };
    // Belt-and-suspenders: the runtime dir is already root-only, but pin the
    // socket private so only root (the privileged service) can connect.
    if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
        warn!(interface, error = %error, "userspace_helper_query_socket_chmod_failed");
    }

    let interface = interface.to_string();
    let thread_interface = interface.clone();
    let spawned = std::thread::Builder::new()
        .name(format!("wgd-overview-{interface}"))
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        let overview = build_macos_network_overview(&state);
                        let payload = match serde_json::to_vec(&overview) {
                            Ok(payload) => payload,
                            Err(error) => {
                                warn!(interface = thread_interface, error = %error, "userspace_helper_query_serialize_failed");
                                continue;
                            }
                        };
                        if let Err(error) = stream.write_all(&payload) {
                            debug!(interface = thread_interface, error = %error, "userspace_helper_query_write_failed");
                        }
                    }
                    Err(error) => {
                        debug!(interface = thread_interface, error = %error, "userspace_helper_query_accept_failed");
                    }
                }
            }
        });
    if let Err(error) = spawned {
        warn!(interface, error = %error, "userspace_helper_query_thread_spawn_failed");
    }
}

/// Gather the typed overview from already-collected host state. `probe`
/// answers the route-table lookup for a destination and `egress` the interface
/// the kernel would send it through (injected so tests need no live routing
/// table).
#[allow(clippy::too_many_arguments)]
pub(super) fn assemble_macos_network_overview(
    inputs: &MacosReconcileInputs,
    routes: &[MacosRoute],
    route_fingerprint: &MacosNetworkFingerprint,
    owned_dns: &[MacosDnsServiceState],
    dns_fingerprint: &MacosDnsFingerprint,
    foreign: &MacosForeignSnapshot,
    probe: &dyn Fn(&MacosRoute) -> Option<MacosRouteEntry>,
    egress: &dyn Fn(&MacosRoute) -> Option<String>,
) -> NetworkOverview {
    let dns_collision =
        macos_dns_server_in_local_subnet(&inputs.dns_servers, &route_fingerprint.local_subnets)
            .map(|(server, (subnet_ip, subnet_prefix))| DnsCollision {
                server: server.to_string(),
                local_subnet: format!("{subnet_ip}/{subnet_prefix}"),
            });
    NetworkOverview {
        interface: inputs.interface.clone(),
        endpoint: inputs.endpoint.to_string(),
        endpoint_pin: inputs.endpoint_needs_pin,
        gateway: route_fingerprint.endpoint_gateway.clone(),
        local_subnets: route_fingerprint
            .local_subnets
            .iter()
            .map(|(ip, prefix)| format!("{ip}/{prefix}"))
            .collect(),
        routes: macos_route_overview_rows(inputs, route_fingerprint, routes, probe, egress),
        dns: macos_dns_overview(inputs, owned_dns, dns_fingerprint, dns_collision),
        // Effective system resolver: what macOS actually resolves through right now,
        // independent of per-service config. Flags the case that stranded a whole
        // debugging session: the global resolver is a tunnel DNS server that is no
        // longer the tunnel's (a leak), or some other resolver has taken over.
        system_resolver: macos_system_resolver(&foreign.global_resolvers, &inputs.dns_servers),
        // Foreign tunnels: other VPN/utun interfaces sharing the host, plus a
        // userspace-Tailscale hint (it has no utun, so the socket is the only tell).
        foreign_tunnels: foreign.tunnels.clone(),
        tailscaled_running: foreign.tailscaled_present,
    }
}

/// The effective system resolver and how it relates to the tunnel's DNS. The
/// mismatch/leak cases are the ones worth eyeballing.
pub(super) fn macos_system_resolver(
    global_resolvers: &[String],
    tunnel_dns: &[String],
) -> SystemResolver {
    let state = if global_resolvers.is_empty() {
        ResolverState::Unset
    } else if global_resolvers == tunnel_dns {
        ResolverState::MatchesTunnel
    } else if !tunnel_dns.is_empty() && global_resolvers.iter().any(|r| tunnel_dns.contains(r)) {
        ResolverState::PartiallyTunnel
    } else {
        ResolverState::Foreign
    };
    SystemResolver {
        servers: global_resolvers.to_vec(),
        state,
    }
}

/// The destination as the kernel actually routes it: normalized to the network
/// base, so `192.168.188.1/24` reads as `192.168.188.0/24` and matches the
/// AllowedIPs line `wg` prints.
pub(super) fn macos_route_display_destination(route: &MacosRoute) -> String {
    match macos_route_destination(route) {
        Some((base, prefix)) => format!("{base}/{prefix}"),
        None => route.destination.clone(),
    }
}

/// How the kernel's answer for a prefix reads in the Live column: the device
/// or gateway that actually holds the entry right now, or absent.
pub(super) fn macos_live_route(entry: &Option<MacosRouteEntry>) -> LiveRoute {
    match entry {
        None => LiveRoute::Absent,
        Some(entry) => LiveRoute::Present {
            interface: entry.interface.clone(),
            gateway: entry.gateway.clone(),
            mtu: entry.mtu,
        },
    }
}

pub(super) fn macos_ip_family(is_ipv6: bool) -> IpFamily {
    if is_ipv6 {
        IpFamily::Ipv6
    } else {
        IpFamily::Ipv4
    }
}

/// Rows for the Routes table: every route the tunnel *wants* — the AllowedIPs
/// routes plus the endpoint pin — each with its outcome, next to what the
/// kernel table actually holds (Live/MTU). The earlier owned-only listing hid
/// exactly the entries worth debugging: a prefix excluded because we sit in
/// that LAN, one a foreign route-table entry keeps off the tunnel, or an
/// "owned" route the kernel has since dropped.
///
/// `probe` answers the route-table lookup for a destination and `egress` the
/// interface the kernel would send it through, whichever route wins (injected
/// so tests need no live routing table).
pub(super) fn macos_route_overview_rows(
    inputs: &MacosReconcileInputs,
    fingerprint: &MacosNetworkFingerprint,
    owned: &[MacosRoute],
    probe: &dyn Fn(&MacosRoute) -> Option<MacosRouteEntry>,
    egress: &dyn Fn(&MacosRoute) -> Option<String>,
) -> Vec<RouteRow> {
    let mut rows = Vec::new();

    // The endpoint pin exists so handshake traffic itself stays off the tunnel.
    if inputs.endpoint_needs_pin {
        let endpoint = inputs.endpoint.to_string();
        let pin = owned
            .iter()
            .find(|route| route.gateway.is_some() && route.destination == endpoint);
        let entry = pin.and_then(probe);
        rows.push(RouteRow {
            destination: endpoint,
            via: match pin.and_then(|route| route.gateway.as_deref()) {
                Some(gateway) => RouteVia::Gateway {
                    address: gateway.to_string(),
                },
                None => RouteVia::None,
            },
            family: macos_ip_family(inputs.endpoint_is_ipv6),
            live: macos_live_route(&entry),
            outcome: if pin.is_some() {
                RouteOutcome::EndpointPinned
            } else {
                RouteOutcome::EndpointPinMissing
            },
        });
    }

    let candidates = macos_allowed_routes(
        &inputs.allowed_ips,
        &inputs.interface,
        inputs.has_ipv4_address,
        inputs.has_ipv6_address,
    );
    for route in &candidates {
        let entry = probe(route);
        let (via, outcome) = if let Some(subnet) =
            macos_route_excluded_by_local_subnet(route, &fingerprint.local_subnets)
        {
            (
                RouteVia::Direct {
                    device: macos_connected_subnet_device(subnet, &inputs.interface),
                },
                RouteOutcome::ExcludedLocalSubnet {
                    subnet: format!("{}/{}", subnet.0, subnet.1),
                },
            )
        } else if let Some(exclusion) =
            macos_route_excluded_by_link(route, &fingerprint.local_subnets, &inputs.bypass_links)
        {
            let device = macos_connected_subnet_device(exclusion.subnet, &inputs.interface);
            // With the tunnel route gone the prefix falls back to the default
            // route, which may sit on another interface than the anchor's
            // (phase 4 of the spec fixes that). The kernel's answer decides
            // whether the prefix really left the tunnel.
            match macos_link_egress(
                device.as_deref(),
                &inputs.interface,
                owned.contains(route),
                egress(route),
            ) {
                LinkEgress::StillTunneled => (
                    RouteVia::Interface {
                        name: inputs.interface.clone(),
                    },
                    RouteOutcome::LinkedStillTunneled {
                        anchor: exclusion.anchor.to_string(),
                    },
                ),
                outcome => (
                    RouteVia::Direct {
                        device: device.clone(),
                    },
                    RouteOutcome::ExcludedLinked {
                        anchor: exclusion.anchor.to_string(),
                        device,
                        egress: match outcome {
                            LinkEgress::Elsewhere(interface) => Some(interface),
                            _ => None,
                        },
                    },
                ),
            }
        } else if owned.contains(route) {
            let kernel_agrees = entry
                .as_ref()
                .is_some_and(|entry| entry.interface == route.interface && !entry.has_gateway());
            (
                RouteVia::Interface {
                    name: inputs.interface.clone(),
                },
                if kernel_agrees {
                    RouteOutcome::Owned
                } else if entry.is_none() {
                    RouteOutcome::OwnedAbsentFromKernel
                } else {
                    RouteOutcome::OwnedKernelDisagrees
                },
            )
        } else {
            match &entry {
                Some(entry) if !entry.is_tunnel_owned() => (
                    RouteVia::None,
                    RouteOutcome::Blocked {
                        holder: entry.interface.clone(),
                    },
                ),
                _ => (RouteVia::None, RouteOutcome::ReconcilePending),
            }
        };
        rows.push(RouteRow {
            destination: macos_route_display_destination(route),
            via,
            family: macos_ip_family(route.is_ipv6),
            live: macos_live_route(&entry),
            outcome,
        });
    }

    // AllowedIPs of a family the tunnel has no address for never became
    // route candidates; show why instead of dropping them silently.
    for allowed in &inputs.allowed_ips {
        let is_ipv6 = allowed.contains(':');
        if (is_ipv6 && !inputs.has_ipv6_address) || (!is_ipv6 && !inputs.has_ipv4_address) {
            rows.push(RouteRow {
                destination: allowed.clone(),
                via: RouteVia::None,
                family: macos_ip_family(is_ipv6),
                live: LiveRoute::NotProbed,
                outcome: RouteOutcome::NoAddressForFamily,
            });
        }
    }

    // Owned leftovers no longer derived from AllowedIPs (mid-reconcile state).
    for route in owned {
        if candidates.contains(route) || (inputs.endpoint_needs_pin && route.gateway.is_some()) {
            continue;
        }
        let entry = probe(route);
        rows.push(RouteRow {
            destination: macos_route_display_destination(route),
            via: match (&route.gateway, &route.interface) {
                (Some(gateway), _) => RouteVia::Gateway {
                    address: gateway.clone(),
                },
                (None, Some(interface)) => RouteVia::Interface {
                    name: interface.clone(),
                },
                (None, None) => RouteVia::System,
            },
            family: macos_ip_family(route.is_ipv6),
            live: macos_live_route(&entry),
            outcome: RouteOutcome::NoLongerDesired,
        });
    }

    rows
}

/// Where the kernel sends a prefix an active link should have taken off the
/// tunnel.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum LinkEgress {
    /// Through the tunnel still: the route is not gone yet, or deleting it
    /// failed.
    StillTunneled,
    /// Through this interface, which is not the anchor's device.
    Elsewhere(String),
    /// Through the anchor's device, or the lookup does not say.
    Expected,
}

/// Classify the kernel's `actual` egress interface for a bypassed prefix. The
/// lookup wins over our bookkeeping, which may lag a kernel change. Only when
/// the lookup gives no answer does a route we still hold count as "still
/// tunneled".
pub(super) fn macos_link_egress(
    device: Option<&str>,
    tunnel_interface: &str,
    still_owned: bool,
    actual: Option<String>,
) -> LinkEgress {
    match actual {
        Some(actual) if actual == tunnel_interface => LinkEgress::StillTunneled,
        None if still_owned => LinkEgress::StillTunneled,
        Some(actual) if device.is_some_and(|device| device != actual) => {
            LinkEgress::Elsewhere(actual)
        }
        _ => LinkEgress::Expected,
    }
}

pub(super) fn macos_dns_overview(
    inputs: &MacosReconcileInputs,
    owned_dns: &[MacosDnsServiceState],
    dns_fingerprint: &MacosDnsFingerprint,
    unreachable: Option<DnsCollision>,
) -> DnsOverview {
    // Use the reconciler's own decision, otherwise the table contradicts it.
    // In active mode no service is a target: the dynamic store key carries
    // the tunnel DNS and needs no primary service.
    let decision = dns_decision(DNS_POLICY, dns_fingerprint, unreachable.is_some());
    let networksetup = inputs.dns_mode == crate::dns_dynamic_store::StoreKeyMode::Shadow;
    let targets = if networksetup {
        decision.targets()
    } else {
        &[]
    };
    let held = networksetup && decision == DnsDecision::Hold;
    let services = dns_fingerprint
        .services
        .iter()
        .map(|service| {
            let live_dns = dns_fingerprint
                .observed
                .iter()
                .find(|(observed_service, _)| observed_service == service)
                .and_then(|(_, servers)| servers.as_ref());
            let owned = owned_dns.iter().find(|state| &state.service == service);
            let targeted = targets.iter().any(|target| target == service);
            let live_matches_tunnel =
                live_dns.map(Vec::as_slice) == Some(inputs.dns_servers.as_slice());
            let status = match (targeted, owned.is_some(), live_matches_tunnel) {
                (true, true, true) => DnsServiceStatus::TunnelDnsActive,
                (true, true, false) => DnsServiceStatus::OwnedPendingReapply,
                (true, false, true) => DnsServiceStatus::AlreadyTunnelDns,
                (true, false, false) => DnsServiceStatus::TargetNotOwned,
                (false, true, _) if held => DnsServiceStatus::OwnedHeldNoPrimary,
                (false, true, _) => DnsServiceStatus::OwnedPendingRestore,
                // Live DNS still shows the tunnel server, but it now sits on the
                // local LAN — that address is no longer the VPN resolver.
                (false, false, true) if unreachable.is_some() => {
                    DnsServiceStatus::StaleTunnelDnsOnLan
                }
                (false, false, _) => DnsServiceStatus::NotTargeted,
            };
            DnsServiceRow {
                service: service.clone(),
                primary: dns_fingerprint.primary_service.as_ref() == Some(service),
                live_dns: live_dns.cloned(),
                owned: owned.is_some(),
                original_dns: owned.and_then(|state| state.dns_servers.clone()),
                status,
            }
        })
        .collect();
    DnsOverview {
        tunnel_servers: inputs.dns_servers.clone(),
        primary_service: dns_fingerprint.primary_service.clone(),
        // A pull-back or a missing primary (a transient between networks) leaves no
        // single active resolver to highlight.
        dormant: unreachable.is_some() || held,
        unreachable,
        services,
        // Filled in by `build_macos_network_overview`, which owns the key.
        dynamic_store: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status_model::DnsCollision;
    use crate::status_model::DnsOverview;
    use crate::status_model::DnsServiceStatus;
    use crate::status_model::IpFamily;
    use crate::status_model::LiveRoute;
    use crate::status_model::ResolverState;
    use crate::status_model::RouteOutcome;
    use crate::status_model::RouteRow;
    use crate::status_model::RouteVia;
    use crate::userspace_helper::macos::route_table::MacosRouteEntry;
    use crate::userspace_helper::macos::test_support::dns_fp;
    use crate::userspace_helper::macos::test_support::split_inputs;
    use crate::userspace_helper::macos::test_support::subnet;
    use crate::userspace_helper::macos::MacosNetworkFingerprint;
    use crate::userspace_helper::macos::MacosRoute;

    fn no_egress(_: &MacosRoute) -> Option<String> {
        None
    }

    #[test]
    fn route_overview_reports_a_linked_prefix_as_excluded() {
        let mut inputs = split_inputs();
        inputs.allowed_ips = vec!["10.66.77.0/24".to_string(), "192.168.188.1/32".to_string()];
        inputs.bypass_links = vec![crate::bypass_links::BypassLink::new(
            "10.66.77.0/24".parse().unwrap(),
            vec!["192.168.188.1/32".parse().unwrap()],
        )];
        let home = MacosNetworkFingerprint {
            local_subnets: vec![subnet("10.66.77.0/24")],
            endpoint_gateway: None,
        };
        let rows = macos_route_overview_rows(&inputs, &home, &[], &|_| None, &no_egress);
        let row = |destination: &str| rows.iter().find(|row| row.destination == destination);
        assert!(matches!(
            row("10.66.77.0/24").unwrap().outcome,
            RouteOutcome::ExcludedLocalSubnet { .. }
        ));
        let linked = row("192.168.188.1/32").unwrap();
        assert!(matches!(
            &linked.outcome,
            RouteOutcome::ExcludedLinked { anchor, egress: None, .. } if anchor == "10.66.77.0/24"
        ));
        assert!(matches!(linked.via, RouteVia::Direct { .. }));

        // Away from the anchor the link is inactive and the row is an
        // ordinary route again.
        let away = MacosNetworkFingerprint::default();
        let rows = macos_route_overview_rows(&inputs, &away, &[], &|_| None, &no_egress);
        let row = rows
            .iter()
            .find(|row| row.destination == "192.168.188.1/32")
            .unwrap();
        assert_eq!(row.outcome, RouteOutcome::ReconcilePending);
    }

    #[test]
    fn linked_prefix_still_routed_through_the_tunnel_is_not_reported_as_excluded() {
        let mut inputs = split_inputs();
        inputs.allowed_ips = vec!["10.66.77.0/24".to_string(), "192.168.188.1/32".to_string()];
        inputs.bypass_links = vec![crate::bypass_links::BypassLink::new(
            "10.66.77.0/24".parse().unwrap(),
            vec!["192.168.188.1/32".parse().unwrap()],
        )];
        let home = MacosNetworkFingerprint {
            local_subnets: vec![subnet("10.66.77.0/24")],
            endpoint_gateway: None,
        };
        let row_for = |owned: &[MacosRoute], egress: &dyn Fn(&MacosRoute) -> Option<String>| {
            macos_route_overview_rows(&inputs, &home, owned, &|_| None, egress)
                .into_iter()
                .find(|row| row.destination == "192.168.188.1/32")
                .unwrap()
        };
        let tunnel_route = MacosRoute {
            is_ipv6: false,
            destination: "192.168.188.1/32".to_string(),
            interface: Some("utun6".to_string()),
            gateway: None,
        };
        let is_excluded =
            |row: &RouteRow| matches!(row.outcome, RouteOutcome::ExcludedLinked { .. });

        // The kernel still sends it into our tunnel: removal is pending or
        // failed, whatever our own bookkeeping says.
        let row = row_for(&[], &|_| Some("utun6".to_string()));
        assert!(!is_excluded(&row), "{:?}", row.outcome);
        assert!(matches!(
            row.outcome,
            RouteOutcome::LinkedStillTunneled { .. }
        ));
        // Still on our books and the lookup gives no answer: same.
        let row = row_for(std::slice::from_ref(&tunnel_route), &|_| None);
        assert!(matches!(
            row.outcome,
            RouteOutcome::LinkedStillTunneled { .. }
        ));
        // The default route is where it went: excluded, as it should be.
        let row = row_for(&[], &|_| Some("en0".to_string()));
        assert!(is_excluded(&row), "{:?}", row.outcome);
        // On our books but the kernel already sends it to en0: the kernel wins.
        let row = row_for(std::slice::from_ref(&tunnel_route), &|_| {
            Some("en0".to_string())
        });
        assert!(is_excluded(&row), "{:?}", row.outcome);
    }

    #[test]
    fn link_egress_classifies_the_kernels_answer() {
        let classify = |device: Option<&str>, owned: bool, actual: Option<&str>| {
            macos_link_egress(device, "utun6", owned, actual.map(str::to_string))
        };
        use LinkEgress::*;
        // Another interface than the anchor's is named, whatever it is.
        assert_eq!(
            classify(Some("en0"), false, Some("en1")),
            Elsewhere("en1".into())
        );
        assert_eq!(
            classify(Some("en0"), false, Some("utun3")),
            Elsewhere("utun3".into())
        );
        // The anchor's device, or an unknown device or answer: nothing to say.
        assert_eq!(classify(Some("en0"), false, Some("en0")), Expected);
        assert_eq!(classify(None, false, Some("en1")), Expected);
        assert_eq!(classify(Some("en0"), false, None), Expected);
        // Our own tunnel is the answer: still tunneled, with or without a
        // device and whether or not we still list the route.
        assert_eq!(classify(Some("en0"), false, Some("utun6")), StillTunneled);
        assert_eq!(classify(None, true, Some("utun6")), StillTunneled);
        // No answer, but we still hold the route: assume it is in the kernel.
        assert_eq!(classify(Some("en0"), true, None), StillTunneled);
        // The kernel's answer wins over our bookkeeping.
        assert_eq!(classify(Some("en0"), true, Some("en0")), Expected);
    }

    #[test]
    fn route_overview_reports_every_allowed_ip_with_its_outcome() {
        let mut inputs = split_inputs();
        inputs.allowed_ips = vec![
            "55.56.57.0/24".to_string(),    // attached LAN -> excluded
            "100.64.0.0/24".to_string(),    // installed, kernel agrees -> owned
            "100.64.9.0/24".to_string(),    // installed, kernel lost it -> drift
            "10.20.30.0/24".to_string(),    // foreign table entry -> blocked
            "192.168.188.1/24".to_string(), // not owned -> pending, display normalized
            "2a01:db8::/64".to_string(),    // no IPv6 address -> not installed
        ];
        let fingerprint = MacosNetworkFingerprint {
            local_subnets: vec![subnet("55.56.57.0/24")],
            endpoint_gateway: None,
        };
        let tunnel_route = |destination: &str| MacosRoute {
            is_ipv6: false,
            destination: destination.to_string(),
            interface: Some("utun6".to_string()),
            gateway: None,
        };
        let owned = vec![tunnel_route("100.64.0.0/24"), tunnel_route("100.64.9.0/24")];
        let probe = |route: &MacosRoute| match route.destination.as_str() {
            "100.64.0.0/24" => Some(MacosRouteEntry {
                destination: subnet("100.64.0.0/24"),
                interface: Some("utun6".to_string()),
                gateway: None,
                mtu: Some(1384),
            }),
            "10.20.30.0/24" => Some(MacosRouteEntry {
                destination: subnet("10.20.30.0/24"),
                interface: Some("en0".to_string()),
                gateway: None,
                mtu: Some(1500),
            }),
            _ => None,
        };

        let rows = macos_route_overview_rows(&inputs, &fingerprint, &owned, &probe, &no_egress);
        let row = |destination: &str| -> &RouteRow {
            rows.iter()
                .find(|row| row.destination == destination)
                .unwrap_or_else(|| panic!("no row for {destination}"))
        };
        let present = |interface: &str, mtu| LiveRoute::Present {
            interface: Some(interface.to_string()),
            gateway: None,
            mtu,
        };

        assert!(matches!(
            &row("55.56.57.0/24").outcome,
            RouteOutcome::ExcludedLocalSubnet { subnet } if subnet == "55.56.57.0/24"
        ));
        assert_eq!(row("100.64.0.0/24").outcome, RouteOutcome::Owned);
        assert_eq!(row("100.64.0.0/24").live, present("utun6", Some(1384)));
        assert_eq!(
            row("100.64.9.0/24").outcome,
            RouteOutcome::OwnedAbsentFromKernel
        );
        assert_eq!(row("100.64.9.0/24").live, LiveRoute::Absent);
        assert_eq!(
            row("10.20.30.0/24").outcome,
            RouteOutcome::Blocked {
                holder: Some("en0".to_string())
            }
        );
        assert_eq!(row("10.20.30.0/24").live, present("en0", Some(1500)));
        // Destination is normalized to the network base for display.
        assert_eq!(
            row("192.168.188.0/24").outcome,
            RouteOutcome::ReconcilePending
        );
        let no_family = row("2a01:db8::/64");
        assert_eq!(no_family.outcome, RouteOutcome::NoAddressForFamily);
        assert_eq!(no_family.family, IpFamily::Ipv6);
        assert_eq!(no_family.live, LiveRoute::NotProbed);
    }

    #[test]
    fn route_overview_shows_endpoint_pin_state() {
        let mut inputs = split_inputs();
        inputs.allowed_ips = Vec::new();
        inputs.endpoint_needs_pin = true;
        let fingerprint = MacosNetworkFingerprint::default();
        let probe = |route: &MacosRoute| {
            (route.destination == "23.88.101.22").then(|| MacosRouteEntry {
                destination: subnet("23.88.101.22/32"),
                interface: Some("en0".to_string()),
                gateway: Some("192.168.1.1".to_string()),
                mtu: Some(1430),
            })
        };

        let pinned = vec![MacosRoute {
            is_ipv6: false,
            destination: "23.88.101.22".to_string(),
            interface: None,
            gateway: Some("192.168.1.1".to_string()),
        }];
        let rows = macos_route_overview_rows(&inputs, &fingerprint, &pinned, &probe, &no_egress);
        assert_eq!(rows[0].destination, "23.88.101.22");
        assert_eq!(
            rows[0].via,
            RouteVia::Gateway {
                address: "192.168.1.1".to_string()
            }
        );
        assert_eq!(
            rows[0].live,
            LiveRoute::Present {
                interface: Some("en0".to_string()),
                gateway: Some("192.168.1.1".to_string()),
                mtu: Some(1430),
            }
        );
        assert_eq!(rows[0].outcome, RouteOutcome::EndpointPinned);

        let rows = macos_route_overview_rows(&inputs, &fingerprint, &[], &probe, &no_egress);
        assert_eq!(rows[0].via, RouteVia::None);
        assert_eq!(rows[0].outcome, RouteOutcome::EndpointPinMissing);
    }

    #[test]
    fn overview_relabels_unreachable_dns_instead_of_claiming_it_is_active() {
        let mut inputs = split_inputs();
        inputs.dns_servers = vec!["55.56.57.2".to_string()];
        // Every service shows the tunnel DNS; none captured (owned) by us.
        let fp = dns_fp(
            Some("Wi-Fi"),
            &[
                ("Wi-Fi", Some(&["55.56.57.2"])),
                ("Thunderbolt Bridge", Some(&["55.56.57.2"])),
            ],
        );
        let collision = DnsCollision {
            server: "55.56.57.2".to_string(),
            local_subnet: "55.56.57.0/24".to_string(),
        };
        // The status of a service and whether the renderer dims its row.
        let status = |dns: &DnsOverview, svc: &str| -> (DnsServiceStatus, bool) {
            dns.services
                .iter()
                .find(|row| row.service == svc)
                .map(|row| {
                    (
                        row.status,
                        dns.dormant || row.status == DnsServiceStatus::NotTargeted,
                    )
                })
                .expect("service row present")
        };

        // Reachable: the primary genuinely shows tunnel DNS; a secondary is just
        // untargeted (and dimmed) under PrimaryOnly.
        let healthy = macos_dns_overview(&inputs, &[], &fp, None);
        assert_eq!(
            status(&healthy, "Wi-Fi"),
            (DnsServiceStatus::AlreadyTunnelDns, false)
        );
        assert_eq!(
            status(&healthy, "Thunderbolt Bridge"),
            (DnsServiceStatus::NotTargeted, true)
        );

        // Collision: the same address is now a LAN host, so no row may claim the
        // tunnel DNS is in use, and the whole dormant block is dimmed.
        let pulled_back = macos_dns_overview(&inputs, &[], &fp, Some(collision.clone()));
        assert_eq!(pulled_back.unreachable, Some(collision));
        assert_eq!(
            status(&pulled_back, "Wi-Fi"),
            (DnsServiceStatus::StaleTunnelDnsOnLan, true)
        );
        assert_eq!(
            status(&pulled_back, "Thunderbolt Bridge"),
            (DnsServiceStatus::StaleTunnelDnsOnLan, true)
        );

        // Transient with no settled primary: nothing is targeted and the whole
        // block is greyed.
        let no_primary = dns_fp(
            None,
            &[
                ("Wi-Fi", Some(&["55.56.57.2"])),
                ("Thunderbolt Bridge", Some(&["55.56.57.2"])),
            ],
        );
        let unsettled = macos_dns_overview(&inputs, &[], &no_primary, None);
        assert_eq!(
            status(&unsettled, "Wi-Fi"),
            (DnsServiceStatus::NotTargeted, true)
        );
        assert_eq!(
            status(&unsettled, "Thunderbolt Bridge"),
            (DnsServiceStatus::NotTargeted, true)
        );
    }

    #[test]
    fn active_dynamic_store_targets_no_service_and_needs_no_primary() {
        let mut inputs = split_inputs();
        inputs.dns_mode = crate::dns_dynamic_store::StoreKeyMode::Active;
        let with_primary = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["192.168.1.1"]))]);
        let overview = macos_dns_overview(&inputs, &[], &with_primary, None);
        assert_eq!(overview.services[0].status, DnsServiceStatus::NotTargeted);
        assert!(!overview.dormant);

        // `networksetup` would hold without a primary; the key does not care.
        let no_primary = dns_fp(None, &[("Wi-Fi", Some(&["192.168.1.1"]))]);
        assert!(!macos_dns_overview(&inputs, &[], &no_primary, None).dormant);
    }

    // --- foreign tunnels & system resolver overview ---

    #[test]
    fn system_resolver_flags_match_foreign_and_empty() {
        let tunnel = vec!["55.56.57.2".to_string()];
        let state = |resolvers: &[&str]| {
            let resolvers: Vec<String> = resolvers.iter().map(|r| r.to_string()).collect();
            macos_system_resolver(&resolvers, &tunnel).state
        };
        assert_eq!(state(&["55.56.57.2"]), ResolverState::MatchesTunnel);
        assert_eq!(state(&["1.1.1.1"]), ResolverState::Foreign);
        assert_eq!(
            state(&["55.56.57.2", "1.1.1.1"]),
            ResolverState::PartiallyTunnel
        );
        assert_eq!(state(&[]), ResolverState::Unset);
    }

    // --- DNS reconciler ---
}
