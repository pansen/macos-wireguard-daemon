use crate::status_model::ForeignTunnelRow;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

/// Snapshot of the host environment *outside* wgd's own routes/DNS — the
/// other VPNs and the effective resolver — bundled so the overview formatter
/// stays a single, testable call.
pub(super) struct MacosForeignSnapshot {
    pub(super) tunnels: Vec<ForeignTunnelRow>,
    pub(super) global_resolvers: Vec<String>,
    pub(super) tailscaled_present: bool,
}

pub(super) fn macos_foreign_tunnels(own_interface: &str) -> Vec<ForeignTunnelRow> {
    let output = match crate::trusted_exec::command("ifconfig")
        .expect("system command is approved")
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    // `crate::privileged::known_addresses()` is every address wgd has
    // assigned to one of its own stored connections, active or not. A
    // leftover interface from a connection that isn't the one currently
    // driving this overview (e.g. an orphaned utun from a previous connect
    // cycle) still carries one of these addresses, which is what tells it
    // apart from an actually-foreign VPN sharing the same CGNAT space.
    parse_foreign_tunnels(
        &String::from_utf8_lossy(&output.stdout),
        own_interface,
        &crate::privileged::known_addresses(),
    )
}

/// True for interface names that belong to a tunnel/VPN (vs en0, lo0, bridge…).
pub(super) fn is_tunnel_interface_name(name: &str) -> bool {
    const PREFIXES: [&str; 6] = ["utun", "tun", "tap", "ppp", "ipsec", "wg"];
    PREFIXES.iter().any(|p| name.starts_with(p))
}

/// 100.64.0.0/10 — RFC 6598 CGNAT, which Tailscale claims wholesale for tailnets.
pub(super) fn is_cgnat_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

/// Parse `ifconfig` into the foreign tunnel interfaces (UP, tunnel-named, not
/// our own). Pure so it can be unit-tested against captured fixtures.
pub(super) fn parse_foreign_tunnels(
    ifconfig: &str,
    own_interface: &str,
    own_addresses: &std::collections::HashSet<IpAddr>,
) -> Vec<ForeignTunnelRow> {
    let mut tunnels: Vec<ForeignTunnelRow> = Vec::new();
    let mut current: Option<ForeignTunnelRow> = None;

    for line in ifconfig.lines() {
        if !line.starts_with(|c: char| c.is_whitespace()) {
            // Header for a new interface: flush the previous one first.
            if let Some(tunnel) = current.take() {
                tunnels.push(tunnel);
            }
            let Some((name, rest)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            if name != own_interface && is_tunnel_interface_name(name) && rest.contains("UP") {
                let mtu = rest
                    .split_whitespace()
                    .skip_while(|t| *t != "mtu")
                    .nth(1)
                    .and_then(|m| m.parse::<u32>().ok());
                current = Some(ForeignTunnelRow {
                    interface: name.to_string(),
                    mtu,
                    addresses: Vec::new(),
                    cgnat: false,
                    own: false,
                });
            }
            continue;
        }
        let Some(tunnel) = current.as_mut() else {
            continue; // indented line for a non-qualifying interface
        };
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            if let Some(addr) = rest.split_whitespace().next() {
                if let Ok(ip) = addr.parse::<Ipv4Addr>() {
                    tunnel.addresses.push(addr.to_string());
                    tunnel.cgnat |= is_cgnat_v4(ip);
                    tunnel.own |= own_addresses.contains(&IpAddr::V4(ip));
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("inet6 ") {
            if let Some(addr) = rest.split_whitespace().next() {
                let bare = addr.split('%').next().unwrap_or(addr);
                if let Ok(ip) = bare.parse::<Ipv6Addr>() {
                    // Skip link-local; it says nothing about what the tunnel routes.
                    if !ip.is_loopback() && (ip.segments()[0] & 0xffc0) != 0xfe80 {
                        tunnel.addresses.push(bare.to_string());
                        tunnel.own |= own_addresses.contains(&IpAddr::V6(ip));
                    }
                }
            }
        }
    }
    if let Some(tunnel) = current.take() {
        tunnels.push(tunnel);
    }
    tunnels
}

pub(super) fn macos_global_resolvers() -> Vec<String> {
    let output = match crate::trusted_exec::command("scutil")
        .expect("system command is approved")
        .arg("--dns")
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    parse_scutil_global_resolvers(&String::from_utf8_lossy(&output.stdout))
}

/// Extract resolvers from the first (default) resolver block of `scutil --dns` —
/// the ones macOS uses for un-scoped lookups. Pure for testability.
pub(super) fn parse_scutil_global_resolvers(text: &str) -> Vec<String> {
    let mut resolvers = Vec::new();
    let mut in_first_resolver = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("resolver #") {
            if in_first_resolver {
                break; // past the default block; later blocks are scoped/secondary
            }
            in_first_resolver = trimmed == "resolver #1";
            continue;
        }
        if in_first_resolver {
            if let Some(value) = trimmed.strip_prefix("nameserver[") {
                if let Some((_, addr)) = value.split_once("] : ") {
                    let addr = addr.trim().to_string();
                    if !resolvers.contains(&addr) {
                        resolvers.push(addr);
                    }
                }
            }
        }
    }
    resolvers
}

/// tailscaled (kernel or userspace) registers this socket while running. Cheap
/// presence check — userspace Tailscale has no utun, so this is the only tell.
pub(super) fn tailscaled_socket_present() -> bool {
    std::path::Path::new("/var/run/tailscaled.socket").exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::status_model::ForeignTunnelRow;
    use std::net::IpAddr;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_foreign_tunnels_excludes_self_and_non_tunnels_flags_cgnat() {
        // utun4 is ours; utun5 is a foreign link-local-only tunnel; utun6 carries
        // a CGNAT address (Tailscale-ish); en0/lo0 are not tunnels.
        let ifconfig = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1384
\tinet 100.64.1.2 --> 100.64.1.2 netmask 0xffffffff
utun5: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet6 fe80::b18c:30f5:afb3:2cfd%utun5 prefixlen 64 scopeid 0x1b
utun6: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280
\tinet 100.96.10.5 --> 100.96.10.5 netmask 0xffffffff
\tinet6 fe80::dead%utun6 prefixlen 64 scopeid 0x1c
utun7: flags=0<> mtu 1500
\tinet 10.9.9.9 netmask 0xffffffff
";
        let tunnels = parse_foreign_tunnels(ifconfig, "utun4", &std::collections::HashSet::new());

        assert_eq!(
            tunnels,
            vec![
                ForeignTunnelRow {
                    interface: "utun5".to_string(),
                    mtu: Some(1380),
                    addresses: vec![], // link-local only
                    cgnat: false,
                    own: false,
                },
                ForeignTunnelRow {
                    interface: "utun6".to_string(),
                    mtu: Some(1280),
                    addresses: vec!["100.96.10.5".to_string()],
                    cgnat: true,
                    own: false,
                },
            ]
        );
        // utun4 (self) excluded; en0/lo0 not tunnels; utun7 is DOWN (no UP flag).
        assert!(!tunnels.iter().any(|t| t.interface == "utun4"));
        assert!(!tunnels.iter().any(|t| t.interface == "utun7"));
    }

    #[test]
    fn parse_foreign_tunnels_recognizes_own_other_connection_by_address() {
        // utun6 carries a CGNAT address that happens to belong to one of
        // wgd's own stored connections (e.g. an orphaned interface from a
        // previous connect cycle) — it should be identified as ours, not
        // flagged as a possible Tailscale tailnet.
        let ifconfig = "\
utun6: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1384
\tinet 100.64.1.2 --> 100.64.1.2 netmask 0xffffffff
";
        let own_addresses: std::collections::HashSet<IpAddr> =
            [IpAddr::V4(Ipv4Addr::new(100, 64, 1, 2))]
                .into_iter()
                .collect();
        let tunnels = parse_foreign_tunnels(ifconfig, "utun7", &own_addresses);

        assert_eq!(tunnels.len(), 1);
        assert!(tunnels[0].cgnat);
        assert!(tunnels[0].own);
    }

    #[test]
    fn parse_scutil_global_resolvers_takes_only_the_default_block() {
        let text = "\
DNS configuration

resolver #1
  nameserver[0] : 55.56.57.2
  nameserver[1] : 55.56.57.3
  flags    : Request A records

resolver #2
  domain   : local
  nameserver[0] : 224.0.0.251

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 8.8.8.8
";
        assert_eq!(
            parse_scutil_global_resolvers(text),
            vec!["55.56.57.2".to_string(), "55.56.57.3".to_string()]
        );
    }
}
