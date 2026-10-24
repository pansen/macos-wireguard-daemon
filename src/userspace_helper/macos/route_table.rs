use super::net::macos_network_base;
use super::net::macos_subnet_contains;
use super::net::parse_cidr;
use super::routes::macos_route_excluded_by_local_subnet;
use super::system::macos_connected_subnet_device;
use super::system::macos_connected_subnets_by_device;
use super::MacosRoute;
use crate::userspace_helper::exec::run_command;
use crate::userspace_helper::exec::run_command_capture_output;
use crate::userspace_helper::exec::run_command_with_exists_ok;
use std::net::IpAddr;
use tracing::{debug, info, warn};

/// Whether the tunnel ends up owning a route it tried to install.
#[derive(Clone, Copy, PartialEq)]
pub(super) enum MacosRouteInstall {
    /// The route is ours: we installed it, or replaced an earlier tunnel entry
    /// for the same prefix. Teardown and reconcile may remove it again.
    Owned,
    /// A physical interface already holds this prefix (its connected LAN route).
    /// Left untouched and not recorded as ours, so nothing later deletes it.
    Foreign,
}

pub(super) fn add_macos_route(route: &MacosRoute) -> anyhow::Result<MacosRouteInstall> {
    let mut args: Vec<String> = vec!["-q".into(), "-n".into(), "add".into()];
    args.push(if route.is_ipv6 { "-inet6" } else { "-inet" }.into());
    args.push(route.destination.clone());
    if let Some(gateway) = &route.gateway {
        args.push(gateway.clone());
    }
    if let Some(interface) = &route.interface {
        args.push("-interface".into());
        args.push(interface.clone());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    // Split routes (dev-bound, no explicit gateway) can linger on stale utun
    // devices; clear such an entry first so this tunnel owns the route. Only a
    // tunnel entry is cleared. Deleting the prefix unconditionally also removes
    // a physical interface's connected LAN route, and taking the prefix from a
    // LAN we are attached to makes that whole LAN unreachable.
    if route.interface.is_some() && route.gateway.is_none() {
        let entry = macos_route_destination(route).and_then(macos_route_table_entry);
        debug!(
            destination = route.destination,
            existing_entry = ?entry,
            "userspace_helper_route_install_lookup"
        );
        match entry {
            Some(entry) if !entry.is_tunnel_owned() => {
                let holder = entry.interface.clone();
                let tunnel = route.interface.as_deref().unwrap_or("");
                // A read failure leaves us unable to tell a live physical
                // route from a stale one; default to leaving it alone rather
                // than risking deletion of a LAN route that is still in use.
                let is_live = match macos_connected_subnets_by_device(tunnel) {
                    Some(connected) => macos_route_entry_is_live(&entry, &connected),
                    None => {
                        debug!(
                            destination = %route.destination,
                            "userspace_helper_route_liveness_check_skipped_ifconfig_failed"
                        );
                        true
                    }
                };
                if is_live {
                    debug!(
                        destination = %route.destination,
                        holder = holder.as_deref().unwrap_or("gateway"),
                        "userspace_helper_route_prefix_held_by_physical_interface"
                    );
                    return Ok(MacosRouteInstall::Foreign);
                }
                // The holder has no address in the prefix: a leftover from a
                // network we since left, which would blackhole the prefix.
                warn!(
                    destination = %route.destination,
                    holder = holder.as_deref().unwrap_or("gateway"),
                    "userspace_helper_route_stale_physical_entry_replaced"
                );
                if let Some(remaining) = macos_clear_route_entry(route, holder.as_deref()) {
                    warn!(
                        destination = %route.destination,
                        holder = remaining.interface.as_deref().unwrap_or("gateway"),
                        "userspace_helper_route_stale_physical_entry_survived_cleanup"
                    );
                    return Ok(MacosRouteInstall::Foreign);
                }
            }
            Some(_) => {
                if let Some(remaining) = macos_clear_route_entry(route, None) {
                    warn!(
                        destination = %route.destination,
                        holder = remaining.interface.as_deref().unwrap_or("gateway"),
                        "userspace_helper_route_stale_physical_entry_survived_cleanup"
                    );
                    return Ok(MacosRouteInstall::Foreign);
                }
            }
            None => {}
        }
    }

    let created = run_command_with_exists_ok("route", &refs)?;
    debug!(route = ?route, created, "userspace_helper_route_install_result");
    Ok(MacosRouteInstall::Owned)
}

/// Best-effort delete of the routing-table entry for `route`'s prefix,
/// re-probed afterwards since `route delete` failures are common (a stale
/// entry can be interface-scoped, or already gone) and silent. Returns the
/// entry that still occupies the prefix if it is not tunnel-owned, so the
/// caller can back off instead of reporting the route as installed while the
/// kernel still routes the prefix elsewhere.
///
/// When `ifscope` names the interface holding the entry, retry the delete with
/// `-ifscope`: stale connected routes survive a network switch as
/// interface-scoped entries, and a plain delete answers "not in table" for
/// those without removing anything.
pub(super) fn macos_clear_route_entry(
    route: &MacosRoute,
    ifscope: Option<&str>,
) -> Option<MacosRouteEntry> {
    let family = if route.is_ipv6 { "-inet6" } else { "-inet" };
    // Match del_macos_route: without -host/-net the delete can fail to match a
    // CIDR destination, leaving the stale dev-bound route behind.
    let kind = macos_route_target_kind(route);
    let args: Vec<&str> = vec!["-q", "-n", "delete", family, kind, &route.destination];
    let _ = run_command("route", &args);
    if let Some(device) = ifscope {
        let mut scoped = args.clone();
        scoped.push("-ifscope");
        scoped.push(device);
        let _ = run_command("route", &scoped);
    }
    macos_route_destination(route)
        .and_then(macos_route_table_entry)
        .filter(|entry| !entry.is_tunnel_owned())
}

/// Whether a routing-table entry reflects the current network state.
///
/// A dev-bound entry is live only while its holder interface has an address
/// whose connected subnet overlaps the entry's prefix. Without one the entry is
/// a leftover from a network we since left (macOS keeps interface-scoped clones
/// across Wi-Fi switches), and yielding to it would blackhole the prefix.
/// Gateway entries are somebody's deliberate configuration and count as live.
pub(super) fn macos_route_entry_is_live(
    entry: &MacosRouteEntry,
    connected: &[(String, (IpAddr, u8))],
) -> bool {
    if entry.has_gateway() {
        return true;
    }
    let Some(holder) = entry.interface.as_deref() else {
        return true;
    };
    connected.iter().any(|(device, local)| {
        device == holder
            && (macos_subnet_contains(local, &entry.destination)
                || macos_subnet_contains(&entry.destination, local))
    })
}

/// One entry of the kernel routing table, as `route -n get` reports it.
#[derive(Debug, PartialEq)]
pub(super) struct MacosRouteEntry {
    /// Network base and prefix length of the entry that answered the lookup.
    pub(super) destination: (IpAddr, u8),
    pub(super) interface: Option<String>,
    pub(super) gateway: Option<String>,
    /// Path MTU of the entry; `None` when the kernel reports 0 (unset).
    pub(super) mtu: Option<u32>,
}

impl MacosRouteEntry {
    pub(super) fn has_gateway(&self) -> bool {
        self.gateway.is_some()
    }

    /// True when a tunnel device holds this prefix directly, i.e. this or
    /// another tunnel installed it rather than the kernel deriving it from a
    /// physical interface address.
    pub(super) fn is_tunnel_owned(&self) -> bool {
        !self.has_gateway()
            && self
                .interface
                .as_deref()
                .is_some_and(|device| device.starts_with("utun"))
    }
}

/// The destination of `route` as a network base and prefix length.
pub(super) fn macos_route_destination(route: &MacosRoute) -> Option<(IpAddr, u8)> {
    let (ip, prefix) = if route.destination.contains('/') {
        parse_cidr(&route.destination).ok()?
    } else {
        let ip: IpAddr = route.destination.parse().ok()?;
        let prefix = if ip.is_ipv6() { 128 } else { 32 };
        (ip, prefix)
    };
    Some((macos_network_base(ip, prefix), prefix))
}

/// The routing table entry for exactly this prefix, or `None` when only a
/// broader route (or nothing) covers it.
///
/// `route get` answers with whatever route wins the lookup for an address, so
/// the reply is only an exact match when its own destination and mask match the
/// prefix we asked about. A network query carries its prefix: given a bare
/// network address, `route` infers a classful mask (`128.0.0.0` becomes a /16,
/// `0.0.0.0` the default route) and never finds a /1 split-default half. Host
/// queries stay bare, since a `/32` asks for a masked net entry and misses the
/// mask-less host routes the endpoint pin installs.
pub(super) fn macos_route_table_entry(destination: (IpAddr, u8)) -> Option<MacosRouteEntry> {
    let (ip, prefix) = destination;
    let is_ipv6 = ip.is_ipv6();
    let network = macos_network_base(ip, prefix);
    let host_prefix = if is_ipv6 { 128 } else { 32 };
    let base = if prefix == host_prefix {
        network.to_string()
    } else {
        format!("{network}/{prefix}")
    };
    let mut args: Vec<&str> = vec!["-n", "get"];
    if is_ipv6 {
        args.push("-inet6");
    }
    args.push(&base);
    let output = run_command_capture_output("route", &args).ok()?;
    if !output.status.success() {
        return None;
    }
    let entry = parse_macos_route_get(&String::from_utf8_lossy(&output.stdout), is_ipv6)?;
    (entry.destination == destination).then_some(entry)
}

/// Parse the `key: value` block `route -n get` prints for one lookup, plus the
/// mtu column of the trailing statistics table.
pub(super) fn parse_macos_route_get(text: &str, is_ipv6: bool) -> Option<MacosRouteEntry> {
    let (mut destination, mut mask, mut gateway, mut interface) = (None, None, None, None);
    let mut mtu = None;
    let mut stats_mtu_column = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("destination:") {
            destination = Some(value.trim().to_string());
        } else if let Some(value) = trimmed.strip_prefix("mask:") {
            mask = Some(value.trim().to_string());
        } else if let Some(value) = trimmed.strip_prefix("gateway:") {
            gateway = Some(value.trim().to_string());
        } else if let Some(value) = trimmed.strip_prefix("interface:") {
            interface = Some(value.trim().to_string());
        } else if let Some(column) = stats_mtu_column.take() {
            // The value row directly under the "recvpipe ... mtu expire" header.
            mtu = trimmed
                .split_whitespace()
                .nth(column)
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|value| *value != 0);
        } else if trimmed.starts_with("recvpipe") {
            stats_mtu_column = trimmed.split_whitespace().position(|name| name == "mtu");
        }
    }
    // `route` prints the unspecified address as "default". With a default mask
    // that is the default route, never the exact entry for a prefix we install;
    // with a real mask it is a prefix such as the 0.0.0.0/1 split-default half.
    let destination: IpAddr = match destination?.as_str() {
        "default" if mask.as_deref().is_some_and(|mask| mask != "default") => {
            if is_ipv6 {
                IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            }
        }
        value => value.parse().ok()?,
    };
    let prefix = match mask.as_deref() {
        // Host routes come back without a mask line.
        None => {
            if is_ipv6 {
                128
            } else {
                32
            }
        }
        Some("default") => 0,
        Some(value) => parse_macos_route_mask(value)?,
    };
    Some(MacosRouteEntry {
        destination: (macos_network_base(destination, prefix), prefix),
        interface,
        gateway,
        mtu,
    })
}

/// Convert a `route get` mask ("255.255.255.0", "ffff:ffff:ffff:ffff::") to a
/// prefix length.
pub(super) fn parse_macos_route_mask(mask: &str) -> Option<u8> {
    match mask.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => Some(u32::from(v4).count_ones() as u8),
        IpAddr::V6(v6) => Some(u128::from(v6).count_ones() as u8),
    }
}

/// Put back the connected route of a LAN whose prefix a tunnel route held.
///
/// While a dev-bound tunnel route occupies a prefix, the kernel cannot install
/// the connected route a physical interface derives from its own address. Join
/// such a LAN with the tunnel route already in place and the connected route is
/// silently skipped, so removing the tunnel route later leaves no route at all
/// and the LAN goes unreachable. Re-add it in that case.
pub(super) fn macos_restore_shadowed_lan_route(
    route: &MacosRoute,
    local_subnets: &[(IpAddr, u8)],
    tunnel_interface: &str,
) {
    let Some(subnet) = macos_route_excluded_by_local_subnet(route, local_subnets) else {
        return;
    };
    // The kernel entry survived (the tunnel route was more specific, or never
    // displaced it), so there is nothing to repair.
    if macos_route_table_entry(subnet).is_some() {
        return;
    }
    let Some(device) = macos_connected_subnet_device(subnet, tunnel_interface) else {
        return;
    };
    let (ip, prefix) = subnet;
    let destination = format!("{ip}/{prefix}");
    // Scoped to the owning device, matching how the kernel installs connected
    // routes; an unscoped entry would outrank the interface's own routing.
    let args = vec![
        "-q".to_string(),
        "-n".to_string(),
        "add".to_string(),
        if ip.is_ipv6() { "-inet6" } else { "-inet" }.to_string(),
        "-net".to_string(),
        destination.clone(),
        "-ifscope".to_string(),
        device.clone(),
        "-interface".to_string(),
        device.clone(),
    ];
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match run_command_with_exists_ok("route", &refs) {
        Ok(_) => info!(
            destination = %destination,
            device = %device,
            "userspace_helper_lan_route_restored"
        ),
        Err(error) => warn!(
            destination = %destination,
            device = %device,
            error = %error,
            "userspace_helper_lan_route_restore_failed"
        ),
    }
}

pub(super) fn del_macos_route(route: &MacosRoute) -> anyhow::Result<()> {
    let mut args: Vec<String> = vec!["-q".into(), "-n".into(), "delete".into()];
    args.push(if route.is_ipv6 { "-inet6" } else { "-inet" }.into());
    args.push(macos_route_target_kind(route).into());
    args.push(route.destination.clone());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run_command_capture_output("route", &refs)?;
    debug!(
        route = ?route,
        status = %output.status,
        stdout = %String::from_utf8_lossy(&output.stdout).trim(),
        stderr = %String::from_utf8_lossy(&output.stderr).trim(),
        "userspace_helper_route_delete_result"
    );
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stderr.contains("not in table") || stdout.contains("not in table") {
        return Ok(());
    }
    let detail = if !stderr.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    };
    anyhow::bail!("route {} failed: {}", refs.join(" "), detail)
}

pub(super) fn macos_route_target_kind(route: &MacosRoute) -> &'static str {
    let host_prefix = if route.is_ipv6 { "/128" } else { "/32" };
    if route.gateway.is_some()
        || route.destination.ends_with(host_prefix)
        || !route.destination.contains('/')
    {
        "-host"
    } else {
        "-net"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::userspace_helper::macos::test_support::subnet;
    use crate::userspace_helper::macos::MacosRoute;

    #[test]
    fn stale_physical_route_entry_is_not_live_without_a_backing_address() {
        let entry = MacosRouteEntry {
            destination: subnet("10.66.77.0/24"),
            interface: Some("en0".to_string()),
            gateway: None,
            mtu: None,
        };

        // en0 left the 10.66.77.0/24 LAN; only an unrelated subnet remains.
        let elsewhere = vec![("en0".to_string(), subnet("192.0.0.2/32"))];
        assert!(!macos_route_entry_is_live(&entry, &elsewhere));
        assert!(!macos_route_entry_is_live(&entry, &[]));

        // Attached to the LAN: the connected route must be respected.
        let attached = vec![("en0".to_string(), subnet("10.66.77.0/24"))];
        assert!(macos_route_entry_is_live(&entry, &attached));

        // The same subnet on a different interface does not back en0's entry.
        let other_device = vec![("en1".to_string(), subnet("10.66.77.0/24"))];
        assert!(!macos_route_entry_is_live(&entry, &other_device));

        // Overlap in either direction counts as backed.
        let broader_entry = MacosRouteEntry {
            destination: subnet("10.66.0.0/16"),
            interface: Some("en0".to_string()),
            gateway: None,
            mtu: None,
        };
        assert!(macos_route_entry_is_live(&broader_entry, &attached));

        // Gateway entries are deliberate configuration, never treated as stale.
        let gateway = MacosRouteEntry {
            destination: subnet("10.66.77.0/24"),
            interface: Some("en0".to_string()),
            gateway: Some("10.66.77.1".to_string()),
            mtu: None,
        };
        assert!(macos_route_entry_is_live(&gateway, &elsewhere));
    }

    #[test]
    fn macos_route_delete_uses_destination_kind_without_add_qualifiers() {
        let network = MacosRoute {
            is_ipv6: false,
            destination: "55.56.57.0/24".to_string(),
            interface: Some("utun9".to_string()),
            gateway: None,
        };
        assert_eq!(macos_route_target_kind(&network), "-net");

        let endpoint = MacosRoute {
            is_ipv6: false,
            destination: "23.88.101.22".to_string(),
            interface: None,
            gateway: Some("55.56.57.1".to_string()),
        };
        assert_eq!(macos_route_target_kind(&endpoint), "-host");

        let host_cidr = MacosRoute {
            is_ipv6: true,
            destination: "2001:db8::1/128".to_string(),
            interface: Some("utun9".to_string()),
            gateway: None,
        };
        assert_eq!(macos_route_target_kind(&host_cidr), "-host");
    }

    #[test]
    fn route_get_reply_identifies_the_entry_holding_a_prefix() {
        let lan = "   route to: 192.168.168.0\n\
                    destination: 192.168.168.0\n\
                           mask: 255.255.255.0\n\
                      interface: en0\n\
                          flags: <UP,DONE,CLONING>\n\
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n\
       0         0         0         0         0         0      1500         0\n";
        let entry = parse_macos_route_get(lan, false).expect("parsed");
        assert_eq!(entry.destination, subnet("192.168.168.0/24"));
        assert_eq!(entry.interface.as_deref(), Some("en0"));
        assert_eq!(entry.mtu, Some(1500));
        assert!(!entry.is_tunnel_owned());

        let tunnel = "   route to: 10.66.77.0\n\
                       destination: 10.66.77.0\n\
                              mask: 255.255.255.0\n\
                         interface: utun6\n";
        assert!(parse_macos_route_get(tunnel, false)
            .expect("parsed")
            .is_tunnel_owned());

        // Answered by the default route: no entry for this prefix.
        let covered = "   route to: 192.168.168.0\n\
                       destination: default\n\
                              mask: default\n\
                           gateway: 192.168.168.1\n\
                         interface: en0\n";
        assert_eq!(parse_macos_route_get(covered, false), None);

        // The lower split-default half: the unspecified address prints as
        // "default", but the mask says it is the /1, not the default route.
        let lower_half = "   route to: default\n\
                          destination: default\n\
                                 mask: 128.0.0.0\n\
                            interface: utun4\n";
        let entry = parse_macos_route_get(lower_half, false).expect("parsed");
        assert_eq!(entry.destination, subnet("0.0.0.0/1"));
        assert!(entry.is_tunnel_owned());

        let upper_half = "   route to: 128.0.0.0\n\
                          destination: 128.0.0.0\n\
                                 mask: 128.0.0.0\n\
                            interface: utun4\n";
        let entry = parse_macos_route_get(upper_half, false).expect("parsed");
        assert_eq!(entry.destination, subnet("128.0.0.0/1"));

        // A host route comes back without a mask line.
        let host = "   route to: 100.64.1.1\n\
                    destination: 100.64.1.1\n\
                      interface: utun6\n";
        let entry = parse_macos_route_get(host, false).expect("parsed");
        assert_eq!(entry.destination, subnet("100.64.1.1/32"));

        let v6 = "   route to: fd86:4939:da7b::\n\
                  destination: fd86:4939:da7b::\n\
                         mask: ffff:ffff:ffff:ffff::\n\
                    interface: en0\n";
        let entry = parse_macos_route_get(v6, true).expect("parsed");
        assert_eq!(entry.destination, subnet("fd86:4939:da7b::/64"));
        assert!(!entry.is_tunnel_owned());
    }

    #[test]
    fn a_gatewayed_tunnel_entry_is_not_treated_as_tunnel_owned() {
        // An endpoint pin lives on the physical path even though route get
        // names a tunnel-looking device; only dev-bound entries are ours.
        let entry = MacosRouteEntry {
            destination: subnet("23.88.101.22/32"),
            interface: Some("utun6".to_string()),
            gateway: Some("192.168.168.1".to_string()),
            mtu: None,
        };
        assert!(!entry.is_tunnel_owned());
    }

    #[test]
    fn route_destinations_normalise_to_network_base_and_prefix() {
        let network = MacosRoute {
            is_ipv6: false,
            destination: "192.168.168.42/24".to_string(),
            interface: Some("utun6".to_string()),
            gateway: None,
        };
        assert_eq!(
            macos_route_destination(&network),
            Some(subnet("192.168.168.0/24"))
        );

        let bare = MacosRoute {
            is_ipv6: false,
            destination: "23.88.101.22".to_string(),
            interface: None,
            gateway: Some("192.168.168.1".to_string()),
        };
        assert_eq!(
            macos_route_destination(&bare),
            Some(subnet("23.88.101.22/32"))
        );
    }
}
