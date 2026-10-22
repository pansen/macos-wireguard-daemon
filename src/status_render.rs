//! Text rendering of the typed status data in [`crate::status_model`].
//!
//! `wgd status` prints exactly this text. The output of both renderers has no
//! trailing whitespace after its last line; the last column of every table
//! row is padded to the column width, as it always was.

use crate::status_model::{
    DnsServiceStatus, ForeignTunnelRow, IpFamily, LiveRoute, NetworkOverview, ResolverState,
    RouteOutcome, RouteRow, RouteVia, WgDeviceStatus,
};

const DIM: &str = "\x1b[2m";
const RESET: &str = "\x1b[0m";

/// `wg show` style text of one device. `now_unix` turns the absolute
/// handshake time into the "N minutes" age.
pub fn render_wg_device(dev: &WgDeviceStatus, now_unix: u64) -> String {
    let mut out = String::new();
    out.push_str(&format!("interface: {}\n", dev.interface));
    if let Some(public_key) = &dev.public_key {
        out.push_str(&format!("  public key: {public_key}\n"));
    }
    out.push_str("  private key: (hidden)\n");
    if let Some(port) = dev.listen_port {
        out.push_str(&format!("  listening port: {port}\n"));
    }

    for peer in &dev.peers {
        out.push('\n');
        out.push_str(&format!("peer: {}\n", peer.public_key));
        if let Some(endpoint) = &peer.endpoint {
            out.push_str(&format!("  endpoint: {endpoint}\n"));
        }
        if !peer.allowed_ips.is_empty() {
            out.push_str(&format!("  allowed ips: {}\n", peer.allowed_ips.join(", ")));
        }
        if peer.has_preshared_key {
            out.push_str("  preshared key: (hidden)\n");
        }
        match peer.latest_handshake_unix {
            Some(at) => out.push_str(&format!(
                "  latest handshake: {}\n",
                wg_format_ago(now_unix.saturating_sub(at))
            )),
            None => out.push_str("  latest handshake: (none)\n"),
        }
        out.push_str(&format!(
            "  transfer: {} received, {} sent\n",
            wg_format_bytes(peer.rx_bytes),
            wg_format_bytes(peer.tx_bytes)
        ));
        if let Some(secs) = peer.persistent_keepalive_secs {
            out.push_str(&format!("  persistent keepalive: every {secs} seconds\n"));
        }
    }

    out.trim_end().to_string()
}

pub fn wg_format_ago(secs: u64) -> String {
    if secs < 60 {
        return format!("{secs} second{}", if secs == 1 { "" } else { "s" });
    }
    let mins = secs / 60;
    if mins < 60 {
        return format!("{mins} minute{}", if mins == 1 { "" } else { "s" });
    }
    let hours = mins / 60;
    if hours < 24 {
        return format!("{hours} hour{}", if hours == 1 { "" } else { "s" });
    }
    let days = hours / 24;
    format!("{days} day{}", if days == 1 { "" } else { "s" })
}

pub fn wg_format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if bytes >= GIB {
        format!("{:.2} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.2} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.2} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// The route/DNS overview text. With `ansi`, DNS rows that are not active
/// are wrapped in the dim escape.
pub fn render_network_overview(ov: &NetworkOverview, ansi: bool) -> String {
    let mut lines = vec![
        "wgd network overview".to_string(),
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
        String::new(),
        "Routes (AllowedIPs + endpoint pin, with what became of each)".to_string(),
    ];
    lines.extend(format_table(
        &["DESTINATION", "VIA", "FAMILY", "LIVE", "MTU", "STATUS"],
        &route_cells(&ov.routes),
    ));

    lines.push(String::new());
    let dns = &ov.dns;
    let mut dns_header = format!(
        "DNS tunnel_servers={} primary_service={}",
        format_list(&dns.tunnel_servers),
        dns.primary_service.as_deref().unwrap_or("none")
    );
    if let Some(collision) = &dns.unreachable {
        dns_header.push_str(&format!(
            " UNREACHABLE: {} is inside local LAN {}, tunnel DNS pulled back",
            collision.server, collision.local_subnet
        ));
    }
    lines.push(dns_header);
    let dns_rows = dns_cells(ov);
    let mut dns_lines = format_table(
        &[
            "SERVICE",
            "ROLE",
            "LIVE DNS",
            "OWNED",
            "ORIGINAL DNS",
            "STATUS",
        ],
        &dns_rows
            .iter()
            .map(|(cells, _)| cells.clone())
            .collect::<Vec<_>>(),
    );
    if ansi {
        for (line, (_, dimmed)) in dns_lines.iter_mut().skip(2).zip(&dns_rows) {
            if *dimmed {
                *line = format!("{DIM}{line}{RESET}");
            }
        }
    }
    lines.extend(dns_lines);

    lines.push(String::new());
    lines.push(system_resolver_line(ov));

    lines.push(String::new());
    lines.push("Other tunnels (foreign VPN / utun interfaces)".to_string());
    lines.extend(format_table(
        &["INTERFACE", "MTU", "ADDRESSES", "NOTE"],
        &foreign_tunnel_cells(&ov.foreign_tunnels),
    ));
    lines.push(format!(
        "tailscaled={}",
        if ov.tailscaled_running {
            "running (socket present; userspace mode has no utun of its own)"
        } else {
            "not detected"
        }
    ));

    lines.join("\n").trim_end().to_string()
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

fn route_cells(routes: &[RouteRow]) -> Vec<Vec<String>> {
    if routes.is_empty() {
        return vec![vec![
            "none".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "-".to_string(),
            "no routes desired".to_string(),
        ]];
    }
    routes
        .iter()
        .map(|row| {
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
            vec![
                row.destination.clone(),
                via,
                family_label(row.family).to_string(),
                live,
                mtu,
                outcome_text(&row.outcome, row.family),
            ]
        })
        .collect()
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
            "owned, but the kernel entry disagrees (see LIVE)".to_string()
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

/// DNS rows with their dim flag: the whole block when it is dormant, else
/// the services that are not targeted.
fn dns_cells(ov: &NetworkOverview) -> Vec<(Vec<String>, bool)> {
    if ov.dns.services.is_empty() {
        return vec![(
            vec![
                "none".to_string(),
                "-".to_string(),
                "-".to_string(),
                "no".to_string(),
                "-".to_string(),
                "no services observed".to_string(),
            ],
            true,
        )];
    }
    ov.dns
        .services
        .iter()
        .map(|row| {
            let servers = |list: &Option<Vec<String>>| {
                list.as_ref()
                    .map_or_else(|| "empty".to_string(), |servers| format_list(servers))
            };
            (
                vec![
                    row.service.clone(),
                    if row.primary { "primary" } else { "secondary" }.to_string(),
                    servers(&row.live_dns),
                    if row.owned { "yes" } else { "no" }.to_string(),
                    servers(&row.original_dns),
                    dns_status_text(row.status).to_string(),
                ],
                ov.dns.dormant || row.status == DnsServiceStatus::NotTargeted,
            )
        })
        .collect()
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

fn system_resolver_line(ov: &NetworkOverview) -> String {
    let note = match ov.system_resolver.state {
        ResolverState::Unset => "none (DHCP/unset)",
        ResolverState::MatchesTunnel => "matches tunnel DNS",
        ResolverState::PartiallyTunnel => {
            "partially tunnel DNS \u{2014} another resolver is also active"
        }
        ResolverState::Foreign => {
            "NOT the tunnel resolver \u{2014} a foreign VPN/DHCP owns resolution"
        }
    };
    format!(
        "System resolver={} ({note})",
        format_list(&ov.system_resolver.servers)
    )
}

fn foreign_tunnel_cells(tunnels: &[ForeignTunnelRow]) -> Vec<Vec<String>> {
    if tunnels.is_empty() {
        return vec![vec![
            "none".to_string(),
            "-".to_string(),
            "-".to_string(),
            "no other tunnels".to_string(),
        ]];
    }
    tunnels
        .iter()
        .map(|t| {
            vec![
                t.interface.clone(),
                t.mtu.map_or_else(|| "-".to_string(), |m| m.to_string()),
                if t.addresses.is_empty() {
                    "link-local only".to_string()
                } else {
                    t.addresses.join(", ")
                },
                if t.own {
                    "wgd (own address; another/stale connection)".to_string()
                } else if t.cgnat {
                    "CGNAT 100.64/10 (Tailscale?)".to_string()
                } else {
                    "-".to_string()
                },
            ]
        })
        .collect()
}

/// Plain table: columns padded to the widest cell, two spaces apart, a dashed
/// rule under the header. Returns the header, the rule and one line per row.
fn format_table(headers: &[&str], rows: &[Vec<String>]) -> Vec<String> {
    let mut widths: Vec<usize> = headers.iter().map(|header| header.len()).collect();
    for row in rows {
        for (index, value) in row.iter().enumerate() {
            if let Some(width) = widths.get_mut(index) {
                *width = (*width).max(value.len());
            }
        }
    }
    let format_row = |values: &[String]| {
        values
            .iter()
            .enumerate()
            .map(|(index, value)| format!("{value:<width$}", width = widths[index]))
            .collect::<Vec<_>>()
            .join("  ")
    };
    let header = format_row(
        &headers
            .iter()
            .map(|header| header.to_string())
            .collect::<Vec<_>>(),
    );
    let separator = widths
        .iter()
        .map(|width| "-".repeat(*width))
        .collect::<Vec<_>>()
        .join("  ");
    let mut lines = vec![header, separator];
    lines.extend(rows.iter().map(|row| format_row(row)));
    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status_model::{
        DnsCollision, DnsOverview, DnsServiceRow, SystemResolver, WgPeerStatus,
    };

    // Expected output captured from the text formatters that predate the
    // typed status model. The renderers must keep reproducing it byte for byte.
    const GOLDEN_W1_NO_PEERS: &[&str] = &[
        "interface: wgconf0",
        "  public key: B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=",
        "  private key: (hidden)",
        "  listening port: 51820",
    ];

    const GOLDEN_W2_BARE: &[&str] = &["interface: wgconf0", "  private key: (hidden)"];

    const GOLDEN_W3_TWO_PEERS: &[&str] = &[
        "interface: wgconf0",
        "  public key: B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=",
        "  private key: (hidden)",
        "",
        "peer: oaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2+v8A=",
        "  endpoint: 203.0.113.7:51820",
        "  allowed ips: 10.66.77.0/24, 100.64.0.1/32",
        "  preshared key: (hidden)",
        "  latest handshake: 2 minutes",
        "  transfer: 1.50 KiB received, 5.00 MiB sent",
        "  persistent keepalive: every 25 seconds",
        "",
        "peer: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=",
        "  latest handshake: (none)",
        "  transfer: 0 B received, 0 B sent",
    ];

    const GOLDEN_W4_HOURS_GIB: &[&str] = &[
        "interface: wgconf0",
        "  public key: B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=",
        "  private key: (hidden)",
        "  listening port: 62401",
        "",
        "peer: oaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2+v8A=",
        "  endpoint: [2001:db8::1]:51820",
        "  allowed ips: 0.0.0.0/0, ::/0",
        "  latest handshake: 3 hours",
        "  transfer: 1.00 MiB received, 3.00 GiB sent",
    ];

    const GOLDEN_O1_ROUTES_EVERYTHING_PLAIN: &[&str] = &[
    "wgd network overview",
    "interface=utun6 endpoint=23.88.101.22 endpoint_pin=enabled gateway=192.168.1.1 local_subnets=55.56.57.0/24, 192.168.1.0/24",
    "",
    "Routes (AllowedIPs + endpoint pin, with what became of each)",
    "DESTINATION       VIA                    FAMILY  LIVE                 MTU   STATUS                                                              ",
    "----------------  ---------------------  ------  -------------------  ----  --------------------------------------------------------------------",
    "23.88.101.22      gateway 192.168.1.1    IPv4    en0 via 192.168.1.1  1430  owned (endpoint pin: handshakes bypass the tunnel)                  ",
    "55.56.57.0/24     direct (attached LAN)  IPv4    absent               -     excluded: we are inside 55.56.57.0/24, kept off the tunnel          ",
    "100.64.0.0/24     interface utun6        IPv4    utun6                1384  owned                                                               ",
    "100.64.9.0/24     interface utun6        IPv4    absent               -     owned, but absent from the kernel table (drift)                     ",
    "100.64.5.0/24     interface utun6        IPv4    en0                  1500  owned, but the kernel entry disagrees (see LIVE)                    ",
    "10.20.30.0/24     -                      IPv4    en0                  1500  blocked: route table entry held by en0, unreachable via tunnel      ",
    "10.30.0.0/16      -                      IPv4    via 192.168.1.9      -     blocked: route table entry held by a gateway, unreachable via tunnel",
    "192.168.188.0/24  -                      IPv4    absent               -     not installed: reconcile pending                                    ",
    "2a01:db8::/64     -                      IPv6    -                    -     not installed: tunnel has no IPv6 address                           ",
    "10.99.0.0/16      interface utun6        IPv4    utun6                -     owned: no longer desired, cleanup pending                           ",
    "10.98.0.0/16      system                 IPv4    ?                    -     owned: no longer desired, cleanup pending                           ",
    "fd00::/8          interface utun6        IPv6    absent               -     owned: no longer desired, cleanup pending                           ",
    "",
    "DNS tunnel_servers=100.64.1.1 primary_service=Wi-Fi",
    "SERVICE             ROLE       LIVE DNS    OWNED  ORIGINAL DNS      STATUS                ",
    "------------------  ---------  ----------  -----  ----------------  ----------------------",
    "Ethernet            secondary  8.8.8.8     yes    1.1.1.1, 1.0.0.1  owned; pending restore",
    "Thunderbolt Bridge  secondary  empty       no     empty             not targeted          ",
    "USB 10/100 LAN      secondary  100.64.1.1  no     empty             not targeted          ",
    "Wi-Fi               primary    100.64.1.1  yes    9.9.9.9           tunnel DNS active     ",
    "",
    "System resolver=100.64.1.1 (matches tunnel DNS)",
    "",
    "Other tunnels (foreign VPN / utun interfaces)",
    "INTERFACE  MTU   ADDRESSES             NOTE                                       ",
    "---------  ----  --------------------  -------------------------------------------",
    "utun3      1384  100.64.1.2            wgd (own address; another/stale connection)",
    "utun4      1280  100.96.10.5, fd7a::1  CGNAT 100.64/10 (Tailscale?)               ",
    "utun5      -     link-local only       -                                          ",
    "utun8      1400  10.8.0.2              -                                          ",
    "tailscaled=running (socket present; userspace mode has no utun of its own)",
];

    const GOLDEN_O2_PIN_MISSING_FOREIGN_RESOLVER_PLAIN: &[&str] = &[
    "wgd network overview",
    "interface=utun6 endpoint=23.88.101.22 endpoint_pin=enabled gateway=none local_subnets=none",
    "",
    "Routes (AllowedIPs + endpoint pin, with what became of each)",
    "DESTINATION   VIA  FAMILY  LIVE    MTU  STATUS                                            ",
    "------------  ---  ------  ------  ---  --------------------------------------------------",
    "23.88.101.22  -    IPv4    absent  -    missing: no default gateway to pin the endpoint to",
    "",
    "DNS tunnel_servers=100.64.1.1 primary_service=Wi-Fi",
    "SERVICE  ROLE     LIVE DNS  OWNED  ORIGINAL DNS  STATUS                ",
    "-------  -------  --------  -----  ------------  ----------------------",
    "Wi-Fi    primary  8.8.8.8   yes    empty         owned; pending reapply",
    "",
    "System resolver=1.1.1.1 (NOT the tunnel resolver \u{2014} a foreign VPN/DHCP owns resolution)",
    "",
    "Other tunnels (foreign VPN / utun interfaces)",
    "INTERFACE  MTU  ADDRESSES  NOTE            ",
    "---------  ---  ---------  ----------------",
    "none       -    -          no other tunnels",
    "tailscaled=not detected",
];

    const GOLDEN_O2B_TARGET_NOT_OWNED_PARTIAL_RESOLVER_PLAIN: &[&str] = &[
    "wgd network overview",
    "interface=utun6 endpoint=23.88.101.22 endpoint_pin=disabled gateway=none local_subnets=none",
    "",
    "Routes (AllowedIPs + endpoint pin, with what became of each)",
    "DESTINATION  VIA  FAMILY  LIVE  MTU  STATUS           ",
    "-----------  ---  ------  ----  ---  -----------------",
    "none         -    -       -     -    no routes desired",
    "",
    "DNS tunnel_servers=100.64.1.1 primary_service=Wi-Fi",
    "SERVICE  ROLE     LIVE DNS  OWNED  ORIGINAL DNS  STATUS           ",
    "-------  -------  --------  -----  ------------  -----------------",
    "Wi-Fi    primary  8.8.8.8   no     empty         target; not owned",
    "",
    "System resolver=100.64.1.1, 1.1.1.1 (partially tunnel DNS \u{2014} another resolver is also active)",
    "",
    "Other tunnels (foreign VPN / utun interfaces)",
    "INTERFACE  MTU  ADDRESSES  NOTE            ",
    "---------  ---  ---------  ----------------",
    "none       -    -          no other tunnels",
    "tailscaled=not detected",
];

    const GOLDEN_O3_EMPTY_PLAIN: &[&str] = &[
    "wgd network overview",
    "interface=utun6 endpoint=23.88.101.22 endpoint_pin=disabled gateway=none local_subnets=none",
    "",
    "Routes (AllowedIPs + endpoint pin, with what became of each)",
    "DESTINATION  VIA  FAMILY  LIVE  MTU  STATUS           ",
    "-----------  ---  ------  ----  ---  -----------------",
    "none         -    -       -     -    no routes desired",
    "",
    "DNS tunnel_servers=100.64.1.1 primary_service=none",
    "SERVICE  ROLE  LIVE DNS  OWNED  ORIGINAL DNS  STATUS              ",
    "-------  ----  --------  -----  ------------  --------------------",
    "none     -     -         no     -             no services observed",
    "",
    "System resolver=none (none (DHCP/unset))",
    "",
    "Other tunnels (foreign VPN / utun interfaces)",
    "INTERFACE  MTU  ADDRESSES  NOTE            ",
    "---------  ---  ---------  ----------------",
    "none       -    -          no other tunnels",
    "tailscaled=not detected",
];

    const GOLDEN_O4_DNS_COLLISION_PLAIN: &[&str] = &[
    "wgd network overview",
    "interface=utun6 endpoint=23.88.101.22 endpoint_pin=disabled gateway=55.56.57.1 local_subnets=55.56.57.0/24",
    "",
    "Routes (AllowedIPs + endpoint pin, with what became of each)",
    "DESTINATION    VIA              FAMILY  LIVE   MTU   STATUS",
    "-------------  ---------------  ------  -----  ----  ------",
    "100.64.0.0/24  interface utun6  IPv4    utun6  1384  owned ",
    "",
    "DNS tunnel_servers=55.56.57.2, 100.64.1.1 primary_service=Wi-Fi UNREACHABLE: 55.56.57.2 is inside local LAN 55.56.57.0/24, tunnel DNS pulled back",
    "SERVICE   ROLE       LIVE DNS                OWNED  ORIGINAL DNS  STATUS                 ",
    "--------  ---------  ----------------------  -----  ------------  -----------------------",
    "Bridge    secondary  8.8.8.8                 no     empty         not targeted           ",
    "Ethernet  secondary  55.56.57.2, 100.64.1.1  yes    1.1.1.1       owned; pending restore ",
    "Wi-Fi     primary    55.56.57.2, 100.64.1.1  no     empty         stale tunnel DNS on LAN",
    "",
    "System resolver=55.56.57.2, 100.64.1.1 (matches tunnel DNS)",
    "",
    "Other tunnels (foreign VPN / utun interfaces)",
    "INTERFACE  MTU  ADDRESSES  NOTE            ",
    "---------  ---  ---------  ----------------",
    "none       -    -          no other tunnels",
    "tailscaled=not detected",
];

    const GOLDEN_O5_HELD_NO_PRIMARY_PLAIN: &[&str] = &[
    "wgd network overview",
    "interface=utun6 endpoint=23.88.101.22 endpoint_pin=disabled gateway=none local_subnets=none",
    "",
    "Routes (AllowedIPs + endpoint pin, with what became of each)",
    "DESTINATION  VIA  FAMILY  LIVE  MTU  STATUS           ",
    "-----------  ---  ------  ----  ---  -----------------",
    "none         -    -       -     -    no routes desired",
    "",
    "DNS tunnel_servers=100.64.1.1 primary_service=none",
    "SERVICE   ROLE       LIVE DNS    OWNED  ORIGINAL DNS  STATUS                 ",
    "--------  ---------  ----------  -----  ------------  -----------------------",
    "Ethernet  secondary  100.64.1.1  no     empty         not targeted           ",
    "Wi-Fi     secondary  100.64.1.1  yes    9.9.9.9       owned; held, no primary",
    "",
    "System resolver=none (none (DHCP/unset))",
    "",
    "Other tunnels (foreign VPN / utun interfaces)",
    "INTERFACE  MTU  ADDRESSES  NOTE            ",
    "---------  ---  ---------  ----------------",
    "none       -    -          no other tunnels",
    "tailscaled=not detected",
];

    const GOLDEN_O6_ALREADY_TUNNEL_DNS_PLAIN: &[&str] = &[
    "wgd network overview",
    "interface=utun6 endpoint=23.88.101.22 endpoint_pin=disabled gateway=none local_subnets=none",
    "",
    "Routes (AllowedIPs + endpoint pin, with what became of each)",
    "DESTINATION  VIA  FAMILY  LIVE  MTU  STATUS           ",
    "-----------  ---  ------  ----  ---  -----------------",
    "none         -    -       -     -    no routes desired",
    "",
    "DNS tunnel_servers=100.64.1.1 primary_service=Wi-Fi",
    "SERVICE   ROLE       LIVE DNS    OWNED  ORIGINAL DNS  STATUS            ",
    "--------  ---------  ----------  -----  ------------  ------------------",
    "Ethernet  secondary  empty       no     empty         not targeted      ",
    "Wi-Fi     primary    100.64.1.1  no     empty         already tunnel DNS",
    "",
    "System resolver=100.64.1.1 (matches tunnel DNS)",
    "",
    "Other tunnels (foreign VPN / utun interfaces)",
    "INTERFACE  MTU  ADDRESSES  NOTE            ",
    "---------  ---  ---------  ----------------",
    "none       -    -          no other tunnels",
    "tailscaled=running (socket present; userspace mode has no utun of its own)",
];

    const GOLDEN_O1_ROUTES_EVERYTHING_ANSI: &[&str] = &[
    "wgd network overview",
    "interface=utun6 endpoint=23.88.101.22 endpoint_pin=enabled gateway=192.168.1.1 local_subnets=55.56.57.0/24, 192.168.1.0/24",
    "",
    "Routes (AllowedIPs + endpoint pin, with what became of each)",
    "DESTINATION       VIA                    FAMILY  LIVE                 MTU   STATUS                                                              ",
    "----------------  ---------------------  ------  -------------------  ----  --------------------------------------------------------------------",
    "23.88.101.22      gateway 192.168.1.1    IPv4    en0 via 192.168.1.1  1430  owned (endpoint pin: handshakes bypass the tunnel)                  ",
    "55.56.57.0/24     direct (attached LAN)  IPv4    absent               -     excluded: we are inside 55.56.57.0/24, kept off the tunnel          ",
    "100.64.0.0/24     interface utun6        IPv4    utun6                1384  owned                                                               ",
    "100.64.9.0/24     interface utun6        IPv4    absent               -     owned, but absent from the kernel table (drift)                     ",
    "100.64.5.0/24     interface utun6        IPv4    en0                  1500  owned, but the kernel entry disagrees (see LIVE)                    ",
    "10.20.30.0/24     -                      IPv4    en0                  1500  blocked: route table entry held by en0, unreachable via tunnel      ",
    "10.30.0.0/16      -                      IPv4    via 192.168.1.9      -     blocked: route table entry held by a gateway, unreachable via tunnel",
    "192.168.188.0/24  -                      IPv4    absent               -     not installed: reconcile pending                                    ",
    "2a01:db8::/64     -                      IPv6    -                    -     not installed: tunnel has no IPv6 address                           ",
    "10.99.0.0/16      interface utun6        IPv4    utun6                -     owned: no longer desired, cleanup pending                           ",
    "10.98.0.0/16      system                 IPv4    ?                    -     owned: no longer desired, cleanup pending                           ",
    "fd00::/8          interface utun6        IPv6    absent               -     owned: no longer desired, cleanup pending                           ",
    "",
    "DNS tunnel_servers=100.64.1.1 primary_service=Wi-Fi",
    "SERVICE             ROLE       LIVE DNS    OWNED  ORIGINAL DNS      STATUS                ",
    "------------------  ---------  ----------  -----  ----------------  ----------------------",
    "Ethernet            secondary  8.8.8.8     yes    1.1.1.1, 1.0.0.1  owned; pending restore",
    "\x1b[2mThunderbolt Bridge  secondary  empty       no     empty             not targeted          \x1b[0m",
    "\x1b[2mUSB 10/100 LAN      secondary  100.64.1.1  no     empty             not targeted          \x1b[0m",
    "Wi-Fi               primary    100.64.1.1  yes    9.9.9.9           tunnel DNS active     ",
    "",
    "System resolver=100.64.1.1 (matches tunnel DNS)",
    "",
    "Other tunnels (foreign VPN / utun interfaces)",
    "INTERFACE  MTU   ADDRESSES             NOTE                                       ",
    "---------  ----  --------------------  -------------------------------------------",
    "utun3      1384  100.64.1.2            wgd (own address; another/stale connection)",
    "utun4      1280  100.96.10.5, fd7a::1  CGNAT 100.64/10 (Tailscale?)               ",
    "utun5      -     link-local only       -                                          ",
    "utun8      1400  10.8.0.2              -                                          ",
    "tailscaled=running (socket present; userspace mode has no utun of its own)",
];

    const GOLDEN_O3_EMPTY_ANSI: &[&str] = &[
    "wgd network overview",
    "interface=utun6 endpoint=23.88.101.22 endpoint_pin=disabled gateway=none local_subnets=none",
    "",
    "Routes (AllowedIPs + endpoint pin, with what became of each)",
    "DESTINATION  VIA  FAMILY  LIVE  MTU  STATUS           ",
    "-----------  ---  ------  ----  ---  -----------------",
    "none         -    -       -     -    no routes desired",
    "",
    "DNS tunnel_servers=100.64.1.1 primary_service=none",
    "SERVICE  ROLE  LIVE DNS  OWNED  ORIGINAL DNS  STATUS              ",
    "-------  ----  --------  -----  ------------  --------------------",
    "\x1b[2mnone     -     -         no     -             no services observed\x1b[0m",
    "",
    "System resolver=none (none (DHCP/unset))",
    "",
    "Other tunnels (foreign VPN / utun interfaces)",
    "INTERFACE  MTU  ADDRESSES  NOTE            ",
    "---------  ---  ---------  ----------------",
    "none       -    -          no other tunnels",
    "tailscaled=not detected",
];

    const GOLDEN_O4_DNS_COLLISION_ANSI: &[&str] = &[
    "wgd network overview",
    "interface=utun6 endpoint=23.88.101.22 endpoint_pin=disabled gateway=55.56.57.1 local_subnets=55.56.57.0/24",
    "",
    "Routes (AllowedIPs + endpoint pin, with what became of each)",
    "DESTINATION    VIA              FAMILY  LIVE   MTU   STATUS",
    "-------------  ---------------  ------  -----  ----  ------",
    "100.64.0.0/24  interface utun6  IPv4    utun6  1384  owned ",
    "",
    "DNS tunnel_servers=55.56.57.2, 100.64.1.1 primary_service=Wi-Fi UNREACHABLE: 55.56.57.2 is inside local LAN 55.56.57.0/24, tunnel DNS pulled back",
    "SERVICE   ROLE       LIVE DNS                OWNED  ORIGINAL DNS  STATUS                 ",
    "--------  ---------  ----------------------  -----  ------------  -----------------------",
    "\x1b[2mBridge    secondary  8.8.8.8                 no     empty         not targeted           \x1b[0m",
    "\x1b[2mEthernet  secondary  55.56.57.2, 100.64.1.1  yes    1.1.1.1       owned; pending restore \x1b[0m",
    "\x1b[2mWi-Fi     primary    55.56.57.2, 100.64.1.1  no     empty         stale tunnel DNS on LAN\x1b[0m",
    "",
    "System resolver=55.56.57.2, 100.64.1.1 (matches tunnel DNS)",
    "",
    "Other tunnels (foreign VPN / utun interfaces)",
    "INTERFACE  MTU  ADDRESSES  NOTE            ",
    "---------  ---  ---------  ----------------",
    "none       -    -          no other tunnels",
    "tailscaled=not detected",
];

    const GOLDEN_O5_HELD_NO_PRIMARY_ANSI: &[&str] = &[
    "wgd network overview",
    "interface=utun6 endpoint=23.88.101.22 endpoint_pin=disabled gateway=none local_subnets=none",
    "",
    "Routes (AllowedIPs + endpoint pin, with what became of each)",
    "DESTINATION  VIA  FAMILY  LIVE  MTU  STATUS           ",
    "-----------  ---  ------  ----  ---  -----------------",
    "none         -    -       -     -    no routes desired",
    "",
    "DNS tunnel_servers=100.64.1.1 primary_service=none",
    "SERVICE   ROLE       LIVE DNS    OWNED  ORIGINAL DNS  STATUS                 ",
    "--------  ---------  ----------  -----  ------------  -----------------------",
    "\x1b[2mEthernet  secondary  100.64.1.1  no     empty         not targeted           \x1b[0m",
    "\x1b[2mWi-Fi     secondary  100.64.1.1  yes    9.9.9.9       owned; held, no primary\x1b[0m",
    "",
    "System resolver=none (none (DHCP/unset))",
    "",
    "Other tunnels (foreign VPN / utun interfaces)",
    "INTERFACE  MTU  ADDRESSES  NOTE            ",
    "---------  ---  ---------  ----------------",
    "none       -    -          no other tunnels",
    "tailscaled=not detected",
];

    fn joined(lines: &[&str]) -> String {
        lines.join("\n")
    }

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
        assert_eq!(
            render_wg_device(&device(true, Some(51820), vec![]), NOW),
            joined(GOLDEN_W1_NO_PEERS)
        );
        assert_eq!(
            render_wg_device(&device(false, None, vec![]), NOW),
            joined(GOLDEN_W2_BARE)
        );
    }

    #[test]
    fn wg_device_with_peers_renders_handshake_transfer_and_keepalive() {
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
        assert_eq!(
            render_wg_device(&device(true, None, vec![full, bare]), NOW),
            joined(GOLDEN_W3_TWO_PEERS)
        );

        let long_ago = WgPeerStatus {
            endpoint: Some("[2001:db8::1]:51820".to_string()),
            allowed_ips: sv(&["0.0.0.0/0", "::/0"]),
            latest_handshake_unix: Some(NOW - 12_600),
            rx_bytes: 1_048_576,
            tx_bytes: 3_221_225_472,
            ..peer(PEER_1)
        };
        assert_eq!(
            render_wg_device(&device(true, Some(62401), vec![long_ago]), NOW),
            joined(GOLDEN_W4_HOURS_GIB)
        );
    }

    #[test]
    fn wg_units_pick_singular_and_scale() {
        assert_eq!(wg_format_ago(1), "1 second");
        assert_eq!(wg_format_ago(59), "59 seconds");
        assert_eq!(wg_format_ago(60), "1 minute");
        assert_eq!(wg_format_ago(3600), "1 hour");
        assert_eq!(wg_format_ago(2 * 86_400), "2 days");
        assert_eq!(wg_format_bytes(1023), "1023 B");
        assert_eq!(wg_format_bytes(1024), "1.00 KiB");
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

    #[test]
    fn overview_plain_matches_the_previous_text() {
        let cases: [(NetworkOverview, &[&str]); 7] = [
            (o1(), GOLDEN_O1_ROUTES_EVERYTHING_PLAIN),
            (o2(), GOLDEN_O2_PIN_MISSING_FOREIGN_RESOLVER_PLAIN),
            (o2b(), GOLDEN_O2B_TARGET_NOT_OWNED_PARTIAL_RESOLVER_PLAIN),
            (overview(), GOLDEN_O3_EMPTY_PLAIN),
            (o4(), GOLDEN_O4_DNS_COLLISION_PLAIN),
            (o5(), GOLDEN_O5_HELD_NO_PRIMARY_PLAIN),
            (o6(), GOLDEN_O6_ALREADY_TUNNEL_DNS_PLAIN),
        ];
        for (index, (ov, golden)) in cases.iter().enumerate() {
            assert_eq!(
                render_network_overview(ov, false),
                joined(golden),
                "case {index}"
            );
        }
    }

    #[test]
    fn overview_ansi_dims_inactive_dns_rows_only() {
        let cases: [(NetworkOverview, &[&str]); 4] = [
            (o1(), GOLDEN_O1_ROUTES_EVERYTHING_ANSI),
            (overview(), GOLDEN_O3_EMPTY_ANSI),
            (o4(), GOLDEN_O4_DNS_COLLISION_ANSI),
            (o5(), GOLDEN_O5_HELD_NO_PRIMARY_ANSI),
        ];
        for (index, (ov, golden)) in cases.iter().enumerate() {
            assert_eq!(
                render_network_overview(ov, true),
                joined(golden),
                "case {index}"
            );
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
        assert!(render_network_overview(&ov, false).contains("direct (en0)  "));
    }

    #[test]
    fn overview_round_trips_through_json() {
        let ov = o1();
        let json = serde_json::to_string(&ov).unwrap();
        assert_eq!(serde_json::from_str::<NetworkOverview>(&json).unwrap(), ov);
    }
}
