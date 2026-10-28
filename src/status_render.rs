//! Text rendering of the typed status data in [`crate::status_model`].
//!
//! `wgd status` prints exactly this text. Both renderers build it from
//! [`crate::ui`] components, so whether it carries color is decided by the
//! caller's [`RenderCtx`] alone. The output has no trailing newline.

use crate::dns_dynamic_store::StoreKeyMode;
use crate::status_model::{
    DnsOverview, DnsServiceStatus, DynamicStoreKey, ForeignTunnelRow, IpFamily, LiveRoute,
    NetworkOverview, ResolverState, RouteOutcome, RouteRow, RouteVia, TunnelDnsState,
    WgDeviceStatus,
};
use crate::ui::{Component, KeyValue, Line, Note, RenderCtx, Role, Span, Table};

/// `wg show` style text of one device. `now_unix` turns the absolute
/// handshake time into the "N minutes" age.
pub fn render_wg_device(dev: &WgDeviceStatus, now_unix: u64, ctx: &RenderCtx) -> String {
    let mut out = String::new();
    let mut interface = KeyValue::with_heading(
        Span::styled("interface", Role::InterfaceLabel),
        Span::styled(dev.interface.as_str(), Role::Interface),
    );
    if let Some(public_key) = &dev.public_key {
        interface.row("public key", public_key.as_str());
    }
    interface.row("private key", "(hidden)");
    if let Some(port) = dev.listen_port {
        interface.row("listening port", port.to_string());
    }
    interface.render(ctx, &mut out);

    for peer in &dev.peers {
        out.push('\n');
        let mut block = KeyValue::with_heading(
            Span::styled("peer", Role::PeerLabel),
            Span::styled(peer.public_key.as_str(), Role::Peer),
        );
        if let Some(endpoint) = &peer.endpoint {
            block.row("endpoint", endpoint.as_str());
        }
        if !peer.allowed_ips.is_empty() {
            block.row("allowed ips", peer.allowed_ips.join(", "));
        }
        if peer.has_preshared_key {
            block.row("preshared key", "(hidden)");
        }
        match peer.latest_handshake_unix {
            Some(at) => {
                let (amount, unit) = wg_format_ago(now_unix.saturating_sub(at));
                block.row("latest handshake", quantity(amount.to_string(), unit));
            }
            None => block.row("latest handshake", "(none)"),
        }
        let (rx, rx_unit) = wg_format_bytes(peer.rx_bytes);
        let (tx, tx_unit) = wg_format_bytes(peer.tx_bytes);
        let mut transfer = quantity(rx, rx_unit);
        transfer.push(Span::plain(" received, "));
        transfer.extend(quantity(tx, tx_unit));
        transfer.push(Span::plain(" sent"));
        block.row("transfer", transfer);
        if let Some(secs) = peer.persistent_keepalive_secs {
            let mut keepalive = vec![Span::plain("every ")];
            keepalive.extend(quantity(secs.to_string(), "seconds"));
            block.row("persistent keepalive", keepalive);
        }
        block.render(ctx, &mut out);
    }

    out.trim_end().to_string()
}

/// `<amount> <unit>` with the unit styled.
fn quantity(amount: String, unit: &'static str) -> Vec<Span> {
    vec![
        Span::plain(format!("{amount} ")),
        Span::styled(unit, Role::Unit),
    ]
}

/// A handshake age as `wg show` prints it: the largest whole unit.
pub fn wg_format_ago(secs: u64) -> (u64, &'static str) {
    let count =
        |n: u64, one: &'static str, many: &'static str| (n, if n == 1 { one } else { many });
    if secs < 60 {
        return count(secs, "second", "seconds");
    }
    let mins = secs / 60;
    if mins < 60 {
        return count(mins, "minute", "minutes");
    }
    let hours = mins / 60;
    if hours < 24 {
        return count(hours, "hour", "hours");
    }
    count(hours / 24, "day", "days")
}

/// A byte count in binary units with two decimals, plain bytes below 1 KiB.
pub fn wg_format_bytes(bytes: u64) -> (String, &'static str) {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        (format!("{:.2}", bytes as f64 / GIB as f64), "GiB")
    } else if bytes >= MIB {
        (format!("{:.2}", bytes as f64 / MIB as f64), "MiB")
    } else if bytes >= KIB {
        (format!("{:.2}", bytes as f64 / KIB as f64), "KiB")
    } else {
        (bytes.to_string(), "B")
    }
}

/// The route/DNS overview text. Rows that are not in effect (routes the
/// tunnel does not hold, DNS services it does not carry, placeholder rows)
/// are muted; problems are notes under the line they concern.
pub fn render_network_overview(ov: &NetworkOverview, ctx: &RenderCtx) -> String {
    let mut out = String::new();
    let line = |out: &mut String, text: String| Line::from(text).render(ctx, out);

    line(&mut out, "wgd network overview".to_string());
    line(
        &mut out,
        format!(
            "interface={} endpoint={} endpoint_pin={} gateway={} local_subnets={}",
            ov.interface,
            ov.endpoint,
            if ov.endpoint_pin {
                "enabled"
            } else {
                "disabled"
            },
            ov.gateway.as_deref().unwrap_or("none"),
            format_list(&ov.local_subnets)
        ),
    );
    out.push('\n');

    line(
        &mut out,
        "Routes (AllowedIPs + endpoint pin, with what became of each)".to_string(),
    );
    route_table(&ov.routes).render(ctx, &mut out);
    tunnel_dns_table(&ov.dns).render(ctx, &mut out);
    dns_table(ov).render(ctx, &mut out);
    out.push('\n');

    if let Some(key) = &ov.dns.dynamic_store {
        dynamic_store_note(key).render(ctx, &mut out);
    }
    system_resolver_note(ov).render(ctx, &mut out);
    out.push('\n');

    line(
        &mut out,
        "Other tunnels (foreign VPN / utun interfaces)".to_string(),
    );
    foreign_tunnel_table(&ov.foreign_tunnels).render(ctx, &mut out);
    line(
        &mut out,
        format!(
            "tailscaled={}",
            if ov.tailscaled_running {
                "running (socket present; userspace mode has no utun of its own)"
            } else {
                "not detected"
            }
        ),
    );

    out.trim_end().to_string()
}

fn format_list(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

fn family_label(family: IpFamily) -> &'static str {
    match family {
        IpFamily::Ipv4 => "IPv4",
        IpFamily::Ipv6 => "IPv6",
    }
}

fn cells(values: Vec<String>) -> Vec<Span> {
    values.into_iter().map(Span::plain).collect()
}

fn strs(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

fn route_table(routes: &[RouteRow]) -> Table {
    let mut table = Table::new(&["Destination", "Via", "Family", "Live", "MTU", "Status"]);
    if routes.is_empty() {
        table.muted_row(cells(strs(&[
            "none",
            "-",
            "-",
            "-",
            "-",
            "no routes desired",
        ])));
        return table;
    }
    for row in routes {
        let via = match &row.via {
            RouteVia::None => "-".to_string(),
            RouteVia::Interface { name } => format!("interface {name}"),
            RouteVia::Gateway { address } => format!("gateway {address}"),
            RouteVia::Direct { device } => {
                format!("direct ({})", device.as_deref().unwrap_or("attached LAN"))
            }
            RouteVia::System => "system".to_string(),
        };
        let (live, mtu) = match &row.live {
            LiveRoute::NotProbed => ("-".to_string(), "-".to_string()),
            LiveRoute::Absent => ("absent".to_string(), "-".to_string()),
            LiveRoute::Present {
                interface,
                gateway,
                mtu,
            } => (
                match (gateway, interface) {
                    (Some(gateway), Some(interface)) => format!("{interface} via {gateway}"),
                    (Some(gateway), None) => format!("via {gateway}"),
                    (None, Some(interface)) => interface.clone(),
                    (None, None) => "?".to_string(),
                },
                mtu.map_or_else(|| "-".to_string(), |mtu| mtu.to_string()),
            ),
        };
        let row_cells = cells(vec![
            row.destination.clone(),
            via,
            family_label(row.family).to_string(),
            live,
            mtu,
            outcome_text(&row.outcome, row.family),
        ]);
        if route_in_effect(&row.outcome) {
            table.row(row_cells);
        } else {
            table.muted_row(row_cells);
        }
    }
    table
}

/// Whether the tunnel holds the route, so traffic for it actually takes the
/// path the row describes. Every other row is muted.
fn route_in_effect(outcome: &RouteOutcome) -> bool {
    match outcome {
        RouteOutcome::EndpointPinned
        | RouteOutcome::Owned
        | RouteOutcome::OwnedAbsentFromKernel
        | RouteOutcome::OwnedKernelDisagrees
        | RouteOutcome::NoLongerDesired => true,
        RouteOutcome::EndpointPinMissing
        | RouteOutcome::ExcludedLocalSubnet { .. }
        | RouteOutcome::Blocked { .. }
        | RouteOutcome::ReconcilePending
        | RouteOutcome::NoAddressForFamily => false,
    }
}

fn outcome_text(outcome: &RouteOutcome, family: IpFamily) -> String {
    match outcome {
        RouteOutcome::EndpointPinned => {
            "owned (endpoint pin: handshakes bypass the tunnel)".to_string()
        }
        RouteOutcome::EndpointPinMissing => {
            "missing: no default gateway to pin the endpoint to".to_string()
        }
        RouteOutcome::ExcludedLocalSubnet { subnet } => {
            format!("excluded: we are inside {subnet}, kept off the tunnel")
        }
        RouteOutcome::Owned => "owned".to_string(),
        RouteOutcome::OwnedAbsentFromKernel => {
            "owned, but absent from the kernel table (drift)".to_string()
        }
        RouteOutcome::OwnedKernelDisagrees => {
            "owned, but the kernel entry disagrees (see Live)".to_string()
        }
        RouteOutcome::Blocked { holder } => format!(
            "blocked: route table entry held by {}, unreachable via tunnel",
            holder.as_deref().unwrap_or("a gateway")
        ),
        RouteOutcome::ReconcilePending => "not installed: reconcile pending".to_string(),
        RouteOutcome::NoAddressForFamily => {
            format!(
                "not installed: tunnel has no {} address",
                family_label(family)
            )
        }
        RouteOutcome::NoLongerDesired => "owned: no longer desired, cleanup pending".to_string(),
    }
}

/// One row per tunnel DNS server with what became of it. Servers are muted
/// unless a service actually resolves through them.
fn tunnel_dns_table(dns: &DnsOverview) -> Table {
    let mut table = Table::new(&["Tunnel DNS", "Status"]);
    let state = dns.tunnel_dns_state();
    if state == TunnelDnsState::NoServers {
        table.muted_row(cells(strs(&["none", "the tunnel sets no DNS"])));
        return table;
    }
    let status = tunnel_dns_status(dns, &state);
    let active = state == TunnelDnsState::Active;
    for server in &dns.tunnel_servers {
        let row_cells = cells(vec![server.clone(), status.clone()]);
        if active {
            table.row(row_cells);
        } else {
            table.muted_row(row_cells);
        }
    }
    table
}

/// The "Status" cell of the tunnel DNS table, also shown by the menu bar.
pub fn tunnel_dns_status(dns: &DnsOverview, state: &TunnelDnsState) -> String {
    let primary = dns
        .primary_service
        .as_deref()
        .unwrap_or("the primary service");
    match state {
        TunnelDnsState::NoServers => "the tunnel sets no DNS".to_string(),
        TunnelDnsState::PulledBack(collision) => format!(
            "pulled back: {} is inside local LAN {}",
            collision.server, collision.local_subnet
        ),
        TunnelDnsState::Held => "held: no primary network service".to_string(),
        TunnelDnsState::Active if dns.via_dynamic_store() => {
            "active via the dynamic store".to_string()
        }
        TunnelDnsState::Active => format!("active via {primary}"),
        TunnelDnsState::Pending if dns.via_dynamic_store() => {
            "pending: dynamic store key not published".to_string()
        }
        TunnelDnsState::Pending => format!("pending: not applied to {primary} yet"),
    }
}

/// The tunnel's dynamic store key: what it is and whether it is where its
/// owner wants it (published, or withdrawn on a LAN collision).
fn dynamic_store_note(key: &DynamicStoreKey) -> Note {
    let domain = match key.mode {
        StoreKeyMode::Shadow => format!("match domain {}", key.match_domain),
        StoreKeyMode::Active => "match domain \"\" (every query)".to_string(),
    };
    let head = format!(
        "Dynamic store key ({})={} {domain}",
        key.mode.as_str(),
        key.key
    );
    match (key.wanted, key.present) {
        (true, Some(true)) => Note::info(format!("{head}: published")),
        (false, Some(false)) => Note::info(format!("{head}: withdrawn (LAN collision)")),
        (true, Some(false)) => Note::warn(format!("{head}: missing; the helper republishes it")),
        (false, Some(true)) => Note::warn(format!("{head}: still present although withdrawn")),
        (_, None) => Note::warn(format!("{head}: could not be read")),
    }
}

/// DNS rows, muted when not in effect: the whole block when it is dormant,
/// else the services that are not targeted.
fn dns_table(ov: &NetworkOverview) -> Table {
    let mut table = Table::new(&[
        "Service",
        "Role",
        "Live DNS",
        "Owned",
        "Original DNS",
        "Status",
    ]);
    if ov.dns.services.is_empty() {
        table.muted_row(cells(strs(&[
            "none",
            "-",
            "-",
            "no",
            "-",
            "no services observed",
        ])));
        return table;
    }
    let servers = |list: &Option<Vec<String>>| {
        list.as_ref()
            .map_or_else(|| "empty".to_string(), |servers| format_list(servers))
    };
    for row in &ov.dns.services {
        let row_cells = cells(vec![
            row.service.clone(),
            if row.primary { "primary" } else { "secondary" }.to_string(),
            servers(&row.live_dns),
            if row.owned { "yes" } else { "no" }.to_string(),
            servers(&row.original_dns),
            dns_status_text(row.status).to_string(),
        ]);
        if ov.dns.dormant || row.status == DnsServiceStatus::NotTargeted {
            table.muted_row(row_cells);
        } else {
            table.row(row_cells);
        }
    }
    table
}

fn dns_status_text(status: DnsServiceStatus) -> &'static str {
    match status {
        DnsServiceStatus::TunnelDnsActive => "tunnel DNS active",
        DnsServiceStatus::OwnedPendingReapply => "owned; pending reapply",
        DnsServiceStatus::AlreadyTunnelDns => "already tunnel DNS",
        DnsServiceStatus::TargetNotOwned => "target; not owned",
        DnsServiceStatus::OwnedHeldNoPrimary => "owned; held, no primary",
        DnsServiceStatus::OwnedPendingRestore => "owned; pending restore",
        DnsServiceStatus::StaleTunnelDnsOnLan => "stale tunnel DNS on LAN",
        DnsServiceStatus::NotTargeted => "not targeted",
    }
}

/// The effective system resolver: a plain line while it is unset or the
/// tunnel's, a warning when another resolver is (also) in charge.
fn system_resolver_note(ov: &NetworkOverview) -> Note {
    let servers = format_list(&ov.system_resolver.servers);
    match ov.system_resolver.state {
        ResolverState::Unset => Note::info("System resolver=none (DHCP/unset)"),
        ResolverState::MatchesTunnel => {
            Note::info(format!("System resolver={servers} (matches tunnel DNS)"))
        }
        ResolverState::PartiallyTunnel => Note::warn(format!(
            "System resolver {servers} is only partly tunnel DNS; another resolver is also active"
        )),
        ResolverState::Foreign => Note::warn(format!(
            "System resolver {servers} is not the tunnel resolver; a foreign VPN or DHCP owns resolution"
        )),
    }
}

fn foreign_tunnel_table(tunnels: &[ForeignTunnelRow]) -> Table {
    let mut table = Table::new(&["Interface", "MTU", "Addresses", "Note"]);
    if tunnels.is_empty() {
        table.muted_row(cells(strs(&["none", "-", "-", "no other tunnels"])));
        return table;
    }
    for t in tunnels {
        table.row(cells(vec![
            t.interface.clone(),
            t.mtu.map_or_else(|| "-".to_string(), |m| m.to_string()),
            if t.addresses.is_empty() {
                "link-local only".to_string()
            } else {
                t.addresses.join(", ")
            },
            if t.own {
                "wgd (own address; another/stale connection)"
            } else if t.cgnat {
                "CGNAT 100.64/10 (Tailscale?)"
            } else {
                "-"
            }
            .to_string(),
        ]));
    }
    table
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status_model::{
        DnsCollision, DnsOverview, DnsServiceRow, SystemResolver, WgPeerStatus,
    };
    use crate::ui::test_support::visible_ansi;

    const PLAIN: RenderCtx = RenderCtx::plain();

    fn sv(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    const NOW: u64 = 1_700_000_000;
    const SK_PUBLIC: &str = "B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=";
    const PEER_1: &str = "oaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2+v8A=";

    fn device(public_key: bool, port: Option<u16>, peers: Vec<WgPeerStatus>) -> WgDeviceStatus {
        WgDeviceStatus {
            interface: "wgconf0".to_string(),
            public_key: public_key.then(|| SK_PUBLIC.to_string()),
            listen_port: port,
            peers,
        }
    }

    fn peer(public_key: &str) -> WgPeerStatus {
        WgPeerStatus {
            public_key: public_key.to_string(),
            endpoint: None,
            allowed_ips: vec![],
            has_preshared_key: false,
            latest_handshake_unix: None,
            rx_bytes: 0,
            tx_bytes: 0,
            persistent_keepalive_secs: None,
        }
    }

    #[test]
    fn wg_device_without_peers() {
        insta::assert_snapshot!(
            "wg_device_no_peers",
            render_wg_device(&device(true, Some(51820), vec![]), NOW, &PLAIN)
        );
        insta::assert_snapshot!(
            "wg_device_bare",
            render_wg_device(&device(false, None, vec![]), NOW, &PLAIN)
        );
    }

    fn two_peers() -> WgDeviceStatus {
        let full = WgPeerStatus {
            endpoint: Some("203.0.113.7:51820".to_string()),
            allowed_ips: sv(&["10.66.77.0/24", "100.64.0.1/32"]),
            has_preshared_key: true,
            latest_handshake_unix: Some(NOW - 125),
            rx_bytes: 1536,
            tx_bytes: 5_242_880,
            persistent_keepalive_secs: Some(25),
            ..peer(PEER_1)
        };
        let bare = peer("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=");
        device(true, None, vec![full, bare])
    }

    #[test]
    fn wg_device_with_peers_renders_handshake_transfer_and_keepalive() {
        insta::assert_snapshot!(
            "wg_device_two_peers",
            render_wg_device(&two_peers(), NOW, &PLAIN)
        );

        let long_ago = WgPeerStatus {
            endpoint: Some("[2001:db8::1]:51820".to_string()),
            allowed_ips: sv(&["0.0.0.0/0", "::/0"]),
            latest_handshake_unix: Some(NOW - 12_600),
            rx_bytes: 1_048_576,
            tx_bytes: 3_221_225_472,
            ..peer(PEER_1)
        };
        insta::assert_snapshot!(
            "wg_device_hours_gib",
            render_wg_device(&device(true, Some(62401), vec![long_ago]), NOW, &PLAIN)
        );
    }

    #[test]
    fn wg_device_ansi_uses_the_wg_show_palette() {
        insta::assert_snapshot!(
            "wg_device_two_peers_ansi",
            visible_ansi(&render_wg_device(&two_peers(), NOW, &RenderCtx::ansi()))
        );
    }

    #[test]
    fn wg_units_pick_singular_and_scale() {
        assert_eq!(wg_format_ago(1), (1, "second"));
        assert_eq!(wg_format_ago(59), (59, "seconds"));
        assert_eq!(wg_format_ago(60), (1, "minute"));
        assert_eq!(wg_format_ago(3600), (1, "hour"));
        assert_eq!(wg_format_ago(2 * 86_400), (2, "days"));
        assert_eq!(wg_format_bytes(1023), ("1023".to_string(), "B"));
        assert_eq!(wg_format_bytes(1024), ("1.00".to_string(), "KiB"));
    }

    fn route(
        destination: &str,
        via: RouteVia,
        family: IpFamily,
        live: LiveRoute,
        outcome: RouteOutcome,
    ) -> RouteRow {
        RouteRow {
            destination: destination.to_string(),
            via,
            family,
            live,
            outcome,
        }
    }

    fn present(interface: Option<&str>, gateway: Option<&str>, mtu: Option<u32>) -> LiveRoute {
        LiveRoute::Present {
            interface: interface.map(str::to_string),
            gateway: gateway.map(str::to_string),
            mtu,
        }
    }

    fn interface_via(name: &str) -> RouteVia {
        RouteVia::Interface {
            name: name.to_string(),
        }
    }

    fn service(
        name: &str,
        primary: bool,
        live_dns: Option<&[&str]>,
        owned: bool,
        original_dns: Option<&[&str]>,
        status: DnsServiceStatus,
    ) -> DnsServiceRow {
        DnsServiceRow {
            service: name.to_string(),
            primary,
            live_dns: live_dns.map(sv),
            owned,
            original_dns: original_dns.map(sv),
            status,
        }
    }

    fn overview() -> NetworkOverview {
        NetworkOverview {
            interface: "utun6".to_string(),
            endpoint: "23.88.101.22".to_string(),
            endpoint_pin: false,
            gateway: None,
            local_subnets: vec![],
            routes: vec![],
            dns: DnsOverview {
                dynamic_store: None,
                tunnel_servers: sv(&["100.64.1.1"]),
                primary_service: None,
                unreachable: None,
                dormant: false,
                services: vec![],
            },
            system_resolver: SystemResolver {
                servers: vec![],
                state: ResolverState::Unset,
            },
            foreign_tunnels: vec![],
            tailscaled_running: false,
        }
    }

    fn resolver(servers: &[&str], state: ResolverState) -> SystemResolver {
        SystemResolver {
            servers: sv(servers),
            state,
        }
    }

    fn o1() -> NetworkOverview {
        use DnsServiceStatus::*;
        let tunnel = |interface: &str, mtu, addresses: &[&str], own, cgnat| ForeignTunnelRow {
            interface: interface.to_string(),
            mtu,
            addresses: sv(addresses),
            own,
            cgnat,
        };
        NetworkOverview {
            endpoint_pin: true,
            gateway: Some("192.168.1.1".to_string()),
            local_subnets: sv(&["55.56.57.0/24", "192.168.1.0/24"]),
            routes: vec![
                route(
                    "23.88.101.22",
                    RouteVia::Gateway {
                        address: "192.168.1.1".to_string(),
                    },
                    IpFamily::Ipv4,
                    present(Some("en0"), Some("192.168.1.1"), Some(1430)),
                    RouteOutcome::EndpointPinned,
                ),
                route(
                    "55.56.57.0/24",
                    RouteVia::Direct { device: None },
                    IpFamily::Ipv4,
                    LiveRoute::Absent,
                    RouteOutcome::ExcludedLocalSubnet {
                        subnet: "55.56.57.0/24".to_string(),
                    },
                ),
                route(
                    "100.64.0.0/24",
                    interface_via("utun6"),
                    IpFamily::Ipv4,
                    present(Some("utun6"), None, Some(1384)),
                    RouteOutcome::Owned,
                ),
                route(
                    "100.64.9.0/24",
                    interface_via("utun6"),
                    IpFamily::Ipv4,
                    LiveRoute::Absent,
                    RouteOutcome::OwnedAbsentFromKernel,
                ),
                route(
                    "100.64.5.0/24",
                    interface_via("utun6"),
                    IpFamily::Ipv4,
                    present(Some("en0"), None, Some(1500)),
                    RouteOutcome::OwnedKernelDisagrees,
                ),
                route(
                    "10.20.30.0/24",
                    RouteVia::None,
                    IpFamily::Ipv4,
                    present(Some("en0"), None, Some(1500)),
                    RouteOutcome::Blocked {
                        holder: Some("en0".to_string()),
                    },
                ),
                route(
                    "10.30.0.0/16",
                    RouteVia::None,
                    IpFamily::Ipv4,
                    present(None, Some("192.168.1.9"), None),
                    RouteOutcome::Blocked { holder: None },
                ),
                route(
                    "192.168.188.0/24",
                    RouteVia::None,
                    IpFamily::Ipv4,
                    LiveRoute::Absent,
                    RouteOutcome::ReconcilePending,
                ),
                route(
                    "2a01:db8::/64",
                    RouteVia::None,
                    IpFamily::Ipv6,
                    LiveRoute::NotProbed,
                    RouteOutcome::NoAddressForFamily,
                ),
                route(
                    "10.99.0.0/16",
                    interface_via("utun6"),
                    IpFamily::Ipv4,
                    present(Some("utun6"), None, None),
                    RouteOutcome::NoLongerDesired,
                ),
                route(
                    "10.98.0.0/16",
                    RouteVia::System,
                    IpFamily::Ipv4,
                    present(None, None, None),
                    RouteOutcome::NoLongerDesired,
                ),
                route(
                    "fd00::/8",
                    interface_via("utun6"),
                    IpFamily::Ipv6,
                    LiveRoute::Absent,
                    RouteOutcome::NoLongerDesired,
                ),
            ],
            dns: DnsOverview {
                dynamic_store: None,
                tunnel_servers: sv(&["100.64.1.1"]),
                primary_service: Some("Wi-Fi".to_string()),
                unreachable: None,
                dormant: false,
                services: vec![
                    service(
                        "Ethernet",
                        false,
                        Some(&["8.8.8.8"]),
                        true,
                        Some(&["1.1.1.1", "1.0.0.1"]),
                        OwnedPendingRestore,
                    ),
                    service("Thunderbolt Bridge", false, None, false, None, NotTargeted),
                    service(
                        "USB 10/100 LAN",
                        false,
                        Some(&["100.64.1.1"]),
                        false,
                        None,
                        NotTargeted,
                    ),
                    service(
                        "Wi-Fi",
                        true,
                        Some(&["100.64.1.1"]),
                        true,
                        Some(&["9.9.9.9"]),
                        TunnelDnsActive,
                    ),
                ],
            },
            system_resolver: resolver(&["100.64.1.1"], ResolverState::MatchesTunnel),
            foreign_tunnels: vec![
                tunnel("utun3", Some(1384), &["100.64.1.2"], true, true),
                tunnel(
                    "utun4",
                    Some(1280),
                    &["100.96.10.5", "fd7a::1"],
                    false,
                    true,
                ),
                tunnel("utun5", None, &[], false, false),
                tunnel("utun8", Some(1400), &["10.8.0.2"], false, false),
            ],
            tailscaled_running: true,
            ..overview()
        }
    }

    fn o2() -> NetworkOverview {
        NetworkOverview {
            endpoint_pin: true,
            routes: vec![route(
                "23.88.101.22",
                RouteVia::None,
                IpFamily::Ipv4,
                LiveRoute::Absent,
                RouteOutcome::EndpointPinMissing,
            )],
            dns: DnsOverview {
                dynamic_store: None,
                primary_service: Some("Wi-Fi".to_string()),
                services: vec![service(
                    "Wi-Fi",
                    true,
                    Some(&["8.8.8.8"]),
                    true,
                    None,
                    DnsServiceStatus::OwnedPendingReapply,
                )],
                ..overview().dns
            },
            system_resolver: resolver(&["1.1.1.1"], ResolverState::Foreign),
            ..overview()
        }
    }

    fn o2b() -> NetworkOverview {
        NetworkOverview {
            dns: DnsOverview {
                dynamic_store: None,
                primary_service: Some("Wi-Fi".to_string()),
                services: vec![service(
                    "Wi-Fi",
                    true,
                    Some(&["8.8.8.8"]),
                    false,
                    None,
                    DnsServiceStatus::TargetNotOwned,
                )],
                ..overview().dns
            },
            system_resolver: resolver(&["100.64.1.1", "1.1.1.1"], ResolverState::PartiallyTunnel),
            ..overview()
        }
    }

    fn o4() -> NetworkOverview {
        use DnsServiceStatus::*;
        NetworkOverview {
            gateway: Some("55.56.57.1".to_string()),
            local_subnets: sv(&["55.56.57.0/24"]),
            routes: vec![route(
                "100.64.0.0/24",
                interface_via("utun6"),
                IpFamily::Ipv4,
                present(Some("utun6"), None, Some(1384)),
                RouteOutcome::Owned,
            )],
            dns: DnsOverview {
                dynamic_store: None,
                tunnel_servers: sv(&["55.56.57.2", "100.64.1.1"]),
                primary_service: Some("Wi-Fi".to_string()),
                unreachable: Some(DnsCollision {
                    server: "55.56.57.2".to_string(),
                    local_subnet: "55.56.57.0/24".to_string(),
                }),
                dormant: true,
                services: vec![
                    service(
                        "Bridge",
                        false,
                        Some(&["8.8.8.8"]),
                        false,
                        None,
                        NotTargeted,
                    ),
                    service(
                        "Ethernet",
                        false,
                        Some(&["55.56.57.2", "100.64.1.1"]),
                        true,
                        Some(&["1.1.1.1"]),
                        OwnedPendingRestore,
                    ),
                    service(
                        "Wi-Fi",
                        true,
                        Some(&["55.56.57.2", "100.64.1.1"]),
                        false,
                        None,
                        StaleTunnelDnsOnLan,
                    ),
                ],
            },
            system_resolver: resolver(&["55.56.57.2", "100.64.1.1"], ResolverState::MatchesTunnel),
            ..overview()
        }
    }

    fn o5() -> NetworkOverview {
        use DnsServiceStatus::*;
        NetworkOverview {
            dns: DnsOverview {
                dynamic_store: None,
                dormant: true,
                services: vec![
                    service(
                        "Ethernet",
                        false,
                        Some(&["100.64.1.1"]),
                        false,
                        None,
                        NotTargeted,
                    ),
                    service(
                        "Wi-Fi",
                        false,
                        Some(&["100.64.1.1"]),
                        true,
                        Some(&["9.9.9.9"]),
                        OwnedHeldNoPrimary,
                    ),
                ],
                ..overview().dns
            },
            ..overview()
        }
    }

    fn o6() -> NetworkOverview {
        NetworkOverview {
            dns: DnsOverview {
                dynamic_store: None,
                primary_service: Some("Wi-Fi".to_string()),
                services: vec![
                    service(
                        "Ethernet",
                        false,
                        None,
                        false,
                        None,
                        DnsServiceStatus::NotTargeted,
                    ),
                    service(
                        "Wi-Fi",
                        true,
                        Some(&["100.64.1.1"]),
                        false,
                        None,
                        DnsServiceStatus::AlreadyTunnelDns,
                    ),
                ],
                ..overview().dns
            },
            system_resolver: resolver(&["100.64.1.1"], ResolverState::MatchesTunnel),
            tailscaled_running: true,
            ..overview()
        }
    }

    fn store_key(mode: StoreKeyMode, wanted: bool, present: Option<bool>) -> DynamicStoreKey {
        let match_domain = match mode {
            StoreKeyMode::Shadow => "wgd-shadow-1f0b2c3d-4e5f-8a6b-9c7d-0e1f2a3b4c5d.inactive",
            StoreKeyMode::Active => "",
        };
        DynamicStoreKey {
            key: "State:/Network/Service/1F0B2C3D-4E5F-8A6B-9C7D-0E1F2A3B4C5D/DNS".to_string(),
            mode,
            match_domain: match_domain.to_string(),
            wanted,
            present,
        }
    }

    /// `o1` with its inert shadow key published next to `networksetup`.
    fn o7() -> NetworkOverview {
        let mut ov = o1();
        ov.dns.dynamic_store = Some(store_key(StoreKeyMode::Shadow, true, Some(true)));
        ov
    }

    /// Phase 2: the active key carries the tunnel DNS, no service is a target.
    fn o8() -> NetworkOverview {
        use DnsServiceStatus::*;
        let mut ov = overview();
        ov.dns.primary_service = Some("Wi-Fi".to_string());
        ov.dns.services = vec![service("Wi-Fi", true, None, false, None, NotTargeted)];
        ov.dns.dynamic_store = Some(store_key(StoreKeyMode::Active, true, Some(true)));
        ov.system_resolver = resolver(&["100.64.1.1"], ResolverState::MatchesTunnel);
        ov
    }

    /// Active key that went missing: tunnel DNS is pending, with a warning.
    fn o9() -> NetworkOverview {
        let mut ov = o8();
        ov.dns.dynamic_store = Some(store_key(StoreKeyMode::Active, true, Some(false)));
        ov
    }

    fn cases() -> [(&'static str, NetworkOverview); 10] {
        [
            ("o1_routes_everything", o1()),
            ("o2_pin_missing_foreign_resolver", o2()),
            ("o2b_target_not_owned_partial_resolver", o2b()),
            ("o3_empty", overview()),
            ("o4_dns_collision", o4()),
            ("o5_held_no_primary", o5()),
            ("o6_already_tunnel_dns", o6()),
            ("o7_shadow_key", o7()),
            ("o8_active_key", o8()),
            ("o9_active_key_missing", o9()),
        ]
    }

    #[test]
    fn overview_plain() {
        for (name, ov) in cases() {
            insta::assert_snapshot!(
                format!("overview_{name}_plain"),
                render_network_overview(&ov, &PLAIN)
            );
        }
    }

    #[test]
    fn overview_ansi_mutes_inactive_dns_rows_and_marks_notes() {
        for (name, ov) in cases() {
            insta::assert_snapshot!(
                format!("overview_{name}_ansi"),
                visible_ansi(&render_network_overview(&ov, &RenderCtx::ansi()))
            );
        }
    }

    #[test]
    fn no_line_ends_in_whitespace() {
        for (name, ov) in cases() {
            for ctx in [PLAIN, RenderCtx::ansi()] {
                let text = render_network_overview(&ov, &ctx);
                assert!(
                    text.lines().all(|line| !line.ends_with(' ')),
                    "{name}: {text}"
                );
            }
        }
    }

    #[test]
    fn direct_route_names_the_device_when_known() {
        let mut ov = o1();
        ov.routes = vec![route(
            "55.56.57.0/24",
            RouteVia::Direct {
                device: Some("en0".to_string()),
            },
            IpFamily::Ipv4,
            LiveRoute::Absent,
            RouteOutcome::ExcludedLocalSubnet {
                subnet: "55.56.57.0/24".to_string(),
            },
        )];
        assert!(render_network_overview(&ov, &PLAIN).contains("direct (en0) | "));
    }

    #[test]
    fn overview_round_trips_through_json() {
        let ov = o1();
        let json = serde_json::to_string(&ov).unwrap();
        assert_eq!(serde_json::from_str::<NetworkOverview>(&json).unwrap(), ov);
    }
}
