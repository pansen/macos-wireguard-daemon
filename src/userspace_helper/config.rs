use super::CONFIG_B64_ENV;
use super::MTU_OVERRIDE_ENV;
use anyhow::Context;
use base64::Engine;
use std::net::SocketAddr;

#[cfg(unix)]
#[derive(Debug, Clone)]
pub(super) struct ParsedUserspaceConfig {
    pub(super) private_key: [u8; 32],
    pub(super) addresses: Vec<String>,
    pub(super) dns_servers: Vec<String>,
    pub(super) mtu: Option<u16>,
    pub(super) peer_public_key: [u8; 32],
    pub(super) peer_preshared_key: Option<[u8; 32]>,
    pub(super) allowed_ips: Vec<String>,
    pub(super) endpoint: SocketAddr,
}

#[cfg(unix)]
pub(super) fn parse_config_from_env() -> anyhow::Result<Option<ParsedUserspaceConfig>> {
    let Some(encoded) = std::env::var_os(CONFIG_B64_ENV) else {
        return Ok(None);
    };
    let encoded = encoded
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("{} is not valid UTF-8", CONFIG_B64_ENV))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("failed to decode userspace WireGuard config")?;
    let text = String::from_utf8(bytes).context("userspace WireGuard config is not UTF-8")?;
    let mut config = parse_wg_quick_config(&text)?;
    if let Some(value) = std::env::var_os(MTU_OVERRIDE_ENV) {
        let value = value
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("{} is not valid UTF-8", MTU_OVERRIDE_ENV))?;
        apply_mtu_override(&mut config, value)?;
    }
    Ok(Some(config))
}

#[cfg(unix)]
pub(super) fn apply_mtu_override(
    config: &mut ParsedUserspaceConfig,
    value: &str,
) -> anyhow::Result<()> {
    config.mtu = Some(crate::wireguard::config::parse_mtu(value)?);
    Ok(())
}

/// Delegates to the shared [`crate::wireguard::connection_config`] parser (the
/// only WireGuard `.conf` parser in the codebase) and narrows its fully
/// general, multi-peer result down to the single peer this helper's gotatun
/// device can actually drive. A config with more than one `[Peer]` section is
/// an explicit error here rather than the old silent single-peer overwrite.
#[cfg(unix)]
pub(super) fn parse_wg_quick_config(config: &str) -> anyhow::Result<ParsedUserspaceConfig> {
    let parsed = crate::wireguard::connection_config::parse_connection_config(config)?;
    anyhow::ensure!(
        parsed.peers.len() == 1,
        "gotatun userspace backend supports exactly one [Peer] section, found {}",
        parsed.peers.len()
    );
    let peer = &parsed.peers[0];
    let endpoint = peer
        .endpoint
        .ok_or_else(|| anyhow::anyhow!("missing Peer.Endpoint"))?;

    Ok(ParsedUserspaceConfig {
        private_key: parsed.private_key.to_bytes(),
        addresses: parsed.addresses.iter().map(ToString::to_string).collect(),
        dns_servers: parsed.dns_servers.iter().map(ToString::to_string).collect(),
        mtu: parsed.mtu,
        peer_public_key: peer.public_key.to_bytes(),
        peer_preshared_key: peer.preshared_key.as_ref().map(|psk| *psk.as_bytes()),
        allowed_ips: peer.allowed_ips.iter().map(ToString::to_string).collect(),
        endpoint,
    })
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const CONFIG: &str = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\nMTU = 1280\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.1:51820\n";

    #[test]
    fn userspace_config_parses_mtu() {
        let parsed = parse_wg_quick_config(CONFIG).expect("parse config");
        assert_eq!(parsed.mtu, Some(1280));
    }

    #[test]
    fn userspace_config_rejects_invalid_mtu() {
        let config = CONFIG.replace("MTU = 1280", "MTU = 575");
        assert!(parse_wg_quick_config(&config).is_err());
    }

    #[test]
    fn explicit_mtu_overrides_config_mtu() {
        let mut parsed = parse_wg_quick_config(CONFIG).expect("parse config");
        apply_mtu_override(&mut parsed, "1420").expect("apply override");
        assert_eq!(parsed.mtu, Some(1420));
    }
}
