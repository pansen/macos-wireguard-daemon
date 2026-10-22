use anyhow::Context;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

/// True when `route` is equal to, or fully inside, the connected subnet `local`.
pub(super) fn macos_subnet_contains(local: &(IpAddr, u8), route: &(IpAddr, u8)) -> bool {
    if route.1 < local.1 {
        return false;
    }
    match (local.0, route.0) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
            macos_network_base(route.0, local.1) == macos_network_base(local.0, local.1)
        }
        _ => false,
    }
}

/// Mask `ip` down to its network base for the given prefix length.
pub(super) fn macos_network_base(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let masked = match prefix {
                0 => 0,
                p if p >= 32 => bits,
                p => bits & (u32::MAX << (32 - p)),
            };
            IpAddr::V4(Ipv4Addr::from(masked))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let masked = match prefix {
                0 => 0,
                p if p >= 128 => bits,
                p => bits & (u128::MAX << (128 - p)),
            };
            IpAddr::V6(Ipv6Addr::from(masked))
        }
    }
}

pub(super) fn format_subnets(subnets: &[(IpAddr, u8)]) -> String {
    if subnets.is_empty() {
        return "none".to_string();
    }
    subnets
        .iter()
        .map(|(ip, prefix)| format!("{ip}/{prefix}"))
        .collect::<Vec<_>>()
        .join(", ")
}

pub(super) fn parse_cidr(value: &str) -> anyhow::Result<(IpAddr, u8)> {
    let (ip, prefix) = value
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid cidr {}", value))?;
    let ip: IpAddr = ip
        .parse()
        .with_context(|| format!("invalid cidr IP {}", ip))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("invalid cidr prefix {}", prefix))?;
    Ok((ip, prefix))
}
