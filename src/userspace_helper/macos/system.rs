use super::net::macos_network_base;
use crate::userspace_helper::exec::run_command_capture_output;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use tracing::debug;

/// The human-readable network service name that currently owns the default
/// route / global resolver, or `None`. `scutil` speaks BSD device names (en0)
/// and `networksetup` speaks service names ("Wi-Fi"); bridge them via the
/// service order, matching on device.
pub(super) fn macos_primary_service() -> Option<String> {
    let primary_if = scutil_global_primary_interface()?;
    macos_service_name_for_device(&primary_if)
}

/// Ask `scutil` for the primary interface (BSD device, e.g. "en0").
pub(super) fn scutil_global_primary_interface() -> Option<String> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = crate::trusted_exec::command("scutil")
        .expect("system command is approved")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| debug!(error = %error, "userspace_helper_primary_interface_spawn_failed"))
        .ok()?;
    child
        .stdin
        .as_mut()?
        .write_all(b"show State:/Network/Global/IPv4\n")
        .map_err(|error| debug!(error = %error, "userspace_helper_primary_interface_write_failed"))
        .ok()?;
    // `wait_with_output` closes stdin first, so scutil sees EOF and exits.
    let output = child
        .wait_with_output()
        .map_err(|error| debug!(error = %error, "userspace_helper_primary_interface_wait_failed"))
        .ok()?;
    if !output.status.success() {
        debug!(
            status = %output.status,
            stderr = %String::from_utf8_lossy(&output.stderr).trim(),
            "userspace_helper_primary_interface_read_failed"
        );
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let primary = parse_scutil_primary_interface(&text);
    if primary.is_none() {
        debug!(state = %text.trim(), "userspace_helper_primary_interface_missing");
    }
    primary
}

/// Parse `PrimaryInterface : en0` out of `scutil show State:/Network/Global/IPv4`.
pub(super) fn parse_scutil_primary_interface(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("PrimaryInterface") {
            let value = rest.trim_start_matches([' ', ':']).trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Map a BSD device ("en0") to its `networksetup` service name ("Wi-Fi") via
/// `networksetup -listnetworkserviceorder`.
pub(super) fn macos_service_name_for_device(device: &str) -> Option<String> {
    let output = run_command_capture_output("networksetup", &["-listnetworkserviceorder"]).ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let service = parse_service_name_for_device(&text, device);
    if service.is_none() {
        debug!(device, service_order = %text.trim(), "userspace_helper_primary_service_unmapped");
    }
    service
}

/// Parse `networksetup -listnetworkserviceorder` output, returning the service
/// name whose `(Hardware Port: …, Device: <device>)` line matches `device`.
/// Pseudo-services without a real device (e.g. VPNs) are skipped.
pub(super) fn parse_service_name_for_device(text: &str, device: &str) -> Option<String> {
    let mut current_name: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(hw) = trimmed.strip_prefix("(Hardware Port:") {
            if parse_device_from_hw_line(hw).as_deref() == Some(device) {
                return current_name.clone();
            }
        } else if trimmed.starts_with('(') {
            // Service line: "(1) Wi-Fi" or "(*) Wi-Fi" (asterisk == disabled).
            if let Some((_, name)) = trimmed.split_once(')') {
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            }
        }
    }
    None
}

/// Extract the BSD device from the tail of a `(Hardware Port: …, Device: enX)`
/// line (the part passed in is everything after "(Hardware Port:").
pub(super) fn parse_device_from_hw_line(hw: &str) -> Option<String> {
    let idx = hw.find("Device:")?;
    let device = hw[idx + "Device:".len()..]
        .trim()
        .trim_end_matches(')')
        .trim();
    if device.is_empty() {
        None
    } else {
        Some(device.to_string())
    }
}

/// Directly-connected subnets of up, non-loopback, non-point-to-point
/// interfaces (the physical LANs), excluding the tunnel itself.
pub(super) fn macos_local_connected_subnets(tunnel_interface: &str) -> Vec<(IpAddr, u8)> {
    let mut subnets: Vec<(IpAddr, u8)> = macos_connected_subnets_by_device(tunnel_interface)
        .unwrap_or_default()
        .into_iter()
        .map(|(_, subnet)| subnet)
        .collect();
    subnets.sort();
    subnets.dedup();
    subnets
}

/// The device that carries `subnet`, for repairing its connected route.
pub(super) fn macos_connected_subnet_device(
    subnet: (IpAddr, u8),
    tunnel_interface: &str,
) -> Option<String> {
    macos_connected_subnets_by_device(tunnel_interface)
        .unwrap_or_default()
        .into_iter()
        .find(|(_, candidate)| *candidate == subnet)
        .map(|(device, _)| device)
}

/// Every connected subnet paired with the interface it belongs to, in ifconfig
/// order. `None` means the `ifconfig` read itself failed, distinct from a
/// successful read that simply found no connected subnets; callers that use
/// this to decide whether a route entry is stale must not conflate the two,
/// since a transient read failure would otherwise look like every physical
/// interface having lost its address.
pub(super) fn macos_connected_subnets_by_device(
    tunnel_interface: &str,
) -> Option<Vec<(String, (IpAddr, u8))>> {
    // Call ifconfig directly (not run_command_capture_output) to avoid emitting
    // a debug command log line on every reconcile tick.
    let output = match crate::trusted_exec::command("ifconfig")
        .expect("system command is approved")
        .output()
    {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            debug!(
                status = %output.status,
                stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                "userspace_helper_ifconfig_read_failed"
            );
            return None;
        }
        Err(error) => {
            debug!(error = %error, "userspace_helper_ifconfig_read_failed");
            return None;
        }
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut subnets = Vec::new();
    let mut device: Option<String> = None;
    for line in text.lines() {
        if !line.starts_with(|c: char| c.is_whitespace()) {
            // Interface header: "en0: flags=8863<UP,BROADCAST,...> mtu 1500".
            device = None;
            if let Some((name, rest)) = line.split_once(':') {
                let name = name.trim();
                if name != tunnel_interface
                    && rest.contains("UP")
                    && !rest.contains("LOOPBACK")
                    && !rest.contains("POINTOPOINT")
                {
                    device = Some(name.to_string());
                }
            }
            continue;
        }
        let Some(device) = device.as_deref() else {
            continue;
        };
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            if let Some(subnet) = parse_ifconfig_inet4_subnet(rest) {
                subnets.push((device.to_string(), subnet));
            }
        } else if let Some(rest) = trimmed.strip_prefix("inet6 ") {
            if let Some(subnet) = parse_ifconfig_inet6_subnet(rest) {
                subnets.push((device.to_string(), subnet));
            }
        }
    }
    Some(subnets)
}

pub(super) fn parse_ifconfig_inet4_subnet(rest: &str) -> Option<(IpAddr, u8)> {
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let ip: Ipv4Addr = fields.first()?.parse().ok()?;
    let mask_index = fields.iter().position(|field| *field == "netmask")?;
    let prefix = parse_macos_hex_netmask(fields.get(mask_index + 1)?)?;
    Some((macos_network_base(IpAddr::V4(ip), prefix), prefix))
}

pub(super) fn parse_ifconfig_inet6_subnet(rest: &str) -> Option<(IpAddr, u8)> {
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // Strip any zone id, e.g. "fe80::1%en0".
    let address = fields.first()?.split('%').next()?;
    let ip: Ipv6Addr = address.parse().ok()?;
    // Skip link-local (fe80::/10) and loopback; they are not routable LANs.
    if ip.is_loopback() || (ip.segments()[0] & 0xffc0) == 0xfe80 {
        return None;
    }
    let prefix_index = fields.iter().position(|field| *field == "prefixlen")?;
    let prefix: u8 = fields.get(prefix_index + 1)?.parse().ok()?;
    Some((macos_network_base(IpAddr::V6(ip), prefix), prefix))
}

/// Convert a macOS hex netmask ("0xffffff00") to a prefix length.
pub(super) fn parse_macos_hex_netmask(mask: &str) -> Option<u8> {
    let hex = mask
        .strip_prefix("0x")
        .or_else(|| mask.strip_prefix("0X"))?;
    Some(u32::from_str_radix(hex, 16).ok()?.count_ones() as u8)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_netmask_converts_to_prefix() {
        assert_eq!(parse_macos_hex_netmask("0xffffff00"), Some(24));
        assert_eq!(parse_macos_hex_netmask("0xffff0000"), Some(16));
        assert_eq!(parse_macos_hex_netmask("0xffffffff"), Some(32));
        assert_eq!(parse_macos_hex_netmask("0x00000000"), Some(0));
        assert_eq!(parse_macos_hex_netmask("not-hex"), None);
    }

    #[test]
    fn parse_scutil_primary_interface_extracts_device() {
        let output = "\
<dictionary> {
  PrimaryInterface : en0
  PrimaryService : 1A2B3C4D-0000-1111-2222-333344445555
  Router : 192.168.1.1
}
";
        assert_eq!(
            parse_scutil_primary_interface(output).as_deref(),
            Some("en0")
        );
        assert_eq!(
            parse_scutil_primary_interface("No such key").as_deref(),
            None
        );
    }

    #[test]
    fn parse_service_name_for_device_maps_devices_and_ignores_pseudo_services() {
        let output = "\
An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(3) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en5)

(*) VPN (Cisco IPSec)
(Hardware Port: VPN (Cisco IPSec), Device: )
";
        assert_eq!(
            parse_service_name_for_device(output, "en0").as_deref(),
            Some("Wi-Fi")
        );
        assert_eq!(
            parse_service_name_for_device(output, "bridge0").as_deref(),
            Some("Thunderbolt Bridge")
        );
        assert_eq!(
            parse_service_name_for_device(output, "en5").as_deref(),
            Some("USB 10/100/1000 LAN")
        );
        // Unknown device and the device-less VPN pseudo-service yield nothing.
        assert_eq!(parse_service_name_for_device(output, "en9"), None);
    }

    #[test]
    fn parse_device_from_hw_line_handles_present_and_empty() {
        assert_eq!(
            parse_device_from_hw_line(" Wi-Fi, Device: en0)").as_deref(),
            Some("en0")
        );
        assert_eq!(
            parse_device_from_hw_line(" VPN (Cisco IPSec), Device: )"),
            None
        );
        assert_eq!(parse_device_from_hw_line(" no device field here)"), None);
    }
}
