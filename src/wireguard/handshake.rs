use std::net::IpAddr;

use tracing::warn;

use crate::error::Result;

/// Wait until the tunnel reports a handshake.
///
/// On macOS the userspace helper establishes the tunnel synchronously, so this
/// is a no-op kept for call-site symmetry with the bring-up paths.
pub fn wait_for_handshake(interface: &str, dns_servers: &[String]) -> Result<()> {
    let _ = (interface, dns_servers);
    Ok(())
}

#[must_use]
pub fn dns_servers_from_config(config_content: &str) -> Vec<String> {
    match super::config::parse_config(config_content) {
        Ok(parsed) => parsed
            .dns_servers
            .into_iter()
            .map(|server| server.trim().to_string())
            .filter(|server| server.parse::<IpAddr>().is_ok())
            .collect(),
        Err(err) => {
            warn!(
                error = %err,
                "wireguard_config_parse_failed_for_handshake_dns"
            );
            Vec::new()
        }
    }
}
