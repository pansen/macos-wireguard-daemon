use crate::error::{AppError, Result};

pub fn parse_mtu(value: &str) -> Result<u16> {
    let mtu = value
        .parse::<u16>()
        .map_err(|_| AppError::WireGuard(format!("invalid MTU {value:?} (expected an integer)")))?;
    validate_mtu(mtu)?;
    Ok(mtu)
}

/// Minimum MTU accepted anywhere in the codebase. The single source of truth for the
/// threshold -- callers go through [`validate_mtu`] rather than re-checking this directly.
pub const MIN_MTU: u16 = 576;

pub fn validate_mtu(mtu: u16) -> Result<()> {
    if mtu < MIN_MTU {
        return Err(AppError::WireGuard(format!(
            "invalid MTU {} (must be >= {})",
            mtu, MIN_MTU
        )));
    }
    Ok(())
}

/// Parameters needed to generate a WireGuard config.
pub struct WgConfigParams<'a> {
    pub private_key: &'a str,
    pub addresses: &'a [&'a str],
    pub dns_servers: &'a [&'a str],
    pub mtu: Option<u16>,
    pub server_public_key: &'a str,
    pub server_ip: &'a str,
    pub server_port: u16,
    pub preshared_key: Option<&'a str>,
    pub allowed_ips: &'a str,
}

/// Generate the content of a WireGuard .conf file.
#[must_use]
pub fn generate_config(params: &WgConfigParams<'_>) -> String {
    let addresses = params.addresses.join(", ");
    let dns = params.dns_servers.join(", ");

    let mut config = format!(
        "[Interface]\n\
         PrivateKey = {private_key}\n\
         Address = {addresses}\n\
         DNS = {dns}\n",
        private_key = params.private_key,
        addresses = addresses,
        dns = dns,
    );

    if let Some(mtu) = params.mtu {
        config.push_str(&format!("MTU = {}\n", mtu));
    }

    config.push_str("\n[Peer]\n");
    config.push_str(&format!("PublicKey = {}\n", params.server_public_key));

    if let Some(psk) = params.preshared_key {
        config.push_str(&format!("PresharedKey = {}\n", psk));
    }

    config.push_str(&format!(
        "AllowedIPs = {allowed_ips}\n\
         Endpoint = {server_ip}:{server_port}\n",
        allowed_ips = params.allowed_ips,
        server_ip = params.server_ip,
        server_port = params.server_port,
    ));

    config
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wg_config_generation() {
        let params = WgConfigParams {
            private_key: "cFRzNnhVcGRkSzlCUGRGTUpiUTJtYlZZSUxPbmJJaz0=",
            addresses: &["10.2.0.2/32"],
            dns_servers: &["10.2.0.1"],
            mtu: None,
            server_public_key: "c2VydmVyLXB1YmxpYy1rZXk=",
            server_ip: "198.51.100.1",
            server_port: 51820,
            preshared_key: None,
            allowed_ips: "0.0.0.0/0, ::/0",
        };

        let config = generate_config(&params);

        assert!(config.contains("[Interface]"));
        assert!(config.contains("[Peer]"));
        assert!(config.contains("PrivateKey = cFRzNnhVcGRkSzlCUGRGTUpiUTJtYlZZSUxPbmJJaz0="));
        assert!(config.contains("Address = 10.2.0.2/32"));
        assert!(config.contains("DNS = 10.2.0.1"));
        assert!(config.contains("PublicKey = c2VydmVyLXB1YmxpYy1rZXk="));
        assert!(config.contains("AllowedIPs = 0.0.0.0/0, ::/0"));
        assert!(config.contains("Endpoint = 198.51.100.1:51820"));
        assert!(!config.contains("PresharedKey"));
    }

    #[test]
    fn test_wg_config_with_preshared_key() {
        let params = WgConfigParams {
            private_key: "cHJpdmtleQ==",
            addresses: &["10.5.0.1/32", "fd7d:76ee:e68f:a993::1/128"],
            dns_servers: &["10.5.0.1", "fd7d:76ee:e68f:a993::1"],
            mtu: None,
            server_public_key: "cHVia2V5",
            server_ip: "1.2.3.4",
            server_port: 1637,
            preshared_key: Some("cHNr"),
            allowed_ips: "0.0.0.0/0, ::/0",
        };

        let config = generate_config(&params);

        assert!(config.contains("Address = 10.5.0.1/32, fd7d:76ee:e68f:a993::1/128"));
        assert!(config.contains("DNS = 10.5.0.1, fd7d:76ee:e68f:a993::1"));
        assert!(config.contains("PresharedKey = cHNr"));
    }

    #[test]
    fn test_wg_config_with_mtu() {
        let params = WgConfigParams {
            private_key: "priv",
            addresses: &["10.0.0.2/32"],
            dns_servers: &["10.0.0.1"],
            mtu: Some(1280),
            server_public_key: "pub",
            server_ip: "1.2.3.4",
            server_port: 51820,
            preshared_key: None,
            allowed_ips: "0.0.0.0/0, ::/0",
        };

        let config = generate_config(&params);
        assert!(config.contains("MTU = 1280"));
    }

    // Valid 32-byte keys, for roundtripping generated config text through the
    // canonical parser (`connection_config`), which validates key length —
    // unlike the deleted string-typed parser this file used to have its own
    // copy of.
    const PRIVATE_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const PUBLIC_KEY_B64: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";
    const PSK_B64: &str = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";

    #[test]
    fn generated_config_is_parseable_by_the_canonical_parser() {
        let params = WgConfigParams {
            private_key: PRIVATE_KEY_B64,
            addresses: &["10.2.0.2/32"],
            dns_servers: &["10.2.0.1"],
            mtu: None,
            server_public_key: PUBLIC_KEY_B64,
            server_ip: "198.51.100.1",
            server_port: 51820,
            preshared_key: None,
            allowed_ips: "0.0.0.0/0",
        };

        let config = generate_config(&params);
        let parsed = super::super::connection_config::parse_connection_config(&config).unwrap();

        assert_eq!(parsed.addresses.len(), 1);
        assert_eq!(parsed.dns_servers, vec!["10.2.0.1".parse::<std::net::IpAddr>().unwrap()]);
        assert_eq!(parsed.mtu, None);
        assert_eq!(parsed.peers.len(), 1);
        assert!(parsed.peers[0].preshared_key.is_none());
        assert_eq!(
            parsed.peers[0].endpoint,
            Some("198.51.100.1:51820".parse().unwrap())
        );
    }

    #[test]
    fn generated_config_with_psk_and_dual_stack_is_parseable() {
        let params = WgConfigParams {
            private_key: PRIVATE_KEY_B64,
            addresses: &["10.5.0.1/32", "fd7d:76ee:e68f:a993::1/128"],
            dns_servers: &["10.5.0.1", "fd7d:76ee:e68f:a993::1"],
            mtu: None,
            server_public_key: PUBLIC_KEY_B64,
            server_ip: "1.2.3.4",
            server_port: 1637,
            preshared_key: Some(PSK_B64),
            allowed_ips: "0.0.0.0/0, ::/0",
        };

        let config = generate_config(&params);
        let parsed = super::super::connection_config::parse_connection_config(&config).unwrap();

        assert_eq!(parsed.addresses.len(), 2);
        assert_eq!(parsed.dns_servers.len(), 2);
        assert_eq!(parsed.peers.len(), 1);
        assert!(parsed.peers[0].preshared_key.is_some());
        assert_eq!(parsed.peers[0].allowed_ips.len(), 2);
        assert_eq!(
            parsed.peers[0].endpoint,
            Some("1.2.3.4:1637".parse().unwrap())
        );
    }
}
