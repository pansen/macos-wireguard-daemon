use std::net::IpAddr;

use crate::error::{AppError, Result};
use tracing::info;

use super::backend::WgBackend;
use super::config::{validate_mtu, WgConfigParams};
use super::connection::{ConnectionState, DIRECT_INSTANCE};

/// Bring up a WireGuard tunnel.
///
/// On macOS there is no in-kernel WireGuard, so the "kernel" backend is served
/// by the gotatun userspace implementation, brought up from a regenerated
/// minimal config. Host routing/DNS are handled by the userspace helper.
pub fn up(
    params: &WgConfigParams<'_>,
    interface_name: &str,
    provider: &str,
    server_display_name: &str,
    disable_ipv6: bool,
) -> Result<()> {
    if disable_ipv6 && has_ipv6_interface_address(params.addresses) {
        return Err(AppError::WireGuard(
            "--disable-ipv6 can only be used when Interface.Address has no IPv6 entry".into(),
        ));
    }
    if let Some(mtu) = params.mtu {
        validate_mtu(mtu)?;
    }

    let wg_config = super::config::generate_config(params);
    super::userspace::up_raw(&wg_config, interface_name)?;

    let state = ConnectionState {
        instance_name: DIRECT_INSTANCE.to_string(),
        provider: provider.to_string(),
        interface_name: interface_name.to_string(),
        backend: WgBackend::Kernel,
        server_endpoint: format!("{}:{}", params.server_ip, params.server_port),
        server_display_name: server_display_name.to_string(),
        dns_servers: params.dns_servers.iter().map(|s| s.to_string()).collect(),
        source_path: None,
    };
    state.save()?;

    info!(
        interface = state.interface_name,
        provider = state.provider,
        server = server_display_name,
        "kernel_tunnel_setup_complete"
    );
    Ok(())
}

/// Tear down a kernel WireGuard tunnel (userspace-backed on macOS).
pub fn down(state: &ConnectionState) -> Result<()> {
    super::userspace::down_raw(&state.interface_name)?;
    ConnectionState::remove(&state.instance_name)?;
    info!(
        interface = state.interface_name,
        provider = state.provider,
        server = state.server_display_name,
        "kernel_tunnel_teardown_complete"
    );
    Ok(())
}

fn has_ipv6_interface_address(addresses: &[&str]) -> bool {
    addresses.iter().any(|cidr| {
        let ip = cidr.split('/').next().unwrap_or_default().trim();
        ip.parse::<IpAddr>().is_ok_and(|addr| addr.is_ipv6())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_mtu_rejects_too_small_values() {
        assert!(validate_mtu(575).is_err());
    }

    #[test]
    fn test_validate_mtu_accepts_reasonable_values() {
        assert!(validate_mtu(1280).is_ok());
    }

    #[test]
    fn test_has_ipv6_interface_address() {
        assert!(!has_ipv6_interface_address(&["10.0.0.2/32"]));
        assert!(has_ipv6_interface_address(&[
            "10.0.0.2/32",
            "fd7d:76ee:e68f:a993::2/128"
        ]));
    }
}
