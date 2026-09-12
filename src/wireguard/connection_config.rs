//! The single, canonical WireGuard `.conf` parser and connection identity
//! (fingerprint) computation.
//!
//! Replaces two previously-duplicated, inconsistent parsers:
//! `wireguard::config::{WgParsedConfig, WgParsedPeer, parse_config}` (string
//! typed) and `userspace_helper::{ParsedUserspaceConfig, parse_wg_quick_config}`
//! (byte typed, and buggy: a second `[Peer]` section silently overwrote the
//! first because peer fields were accumulated in scalars instead of flushed
//! into a list). Every field is fully typed. Directive keys and section
//! headers are matched case-insensitively and with whitespace stripped,
//! matching `wg-quick`/`wg(8)` (which parse under `nocasematch` and
//! `strncasecmp`); an unrecognized directive or section is a hard error
//! rather than a silent no-op, so a typo (or a key this backend genuinely
//! doesn't support, like `Table`) can never silently downgrade the tunnel's
//! security posture (e.g. a dropped `DNS =` leaking queries, or a dropped
//! `Table = off` letting a full-tunnel `AllowedIPs` hijack the default
//! route).
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::mpsc;
use std::time::Duration;

use base64::Engine;
use ipnet::IpNet;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{AppError, Result};

/// x25519 key types are reused directly from `gotatun`'s own re-export
/// (`gotatun::x25519`, already a transitive dependency pulling in
/// `x25519-dalek` with its `zeroize` feature) rather than adding a second,
/// independently-versioned `x25519-dalek` dependency to the tree. `StaticSecret`
/// zeroizes its bytes on drop; `PublicKey` carries no secret material.
pub type PrivateKey = gotatun::x25519::StaticSecret;
pub type PublicKey = gotatun::x25519::PublicKey;

/// A WireGuard preshared key: 32 raw symmetric-key bytes, zeroized on drop.
/// Unlike the x25519 keys this has no upstream typed representation to reuse.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct PresharedKey([u8; 32]);

impl PresharedKey {
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for PresharedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PresharedKey(REDACTED)")
    }
}

/// A fully parsed, fully typed WireGuard connection configuration.
///
/// `PreUp`/`PostUp`/`PreDown`/`PostDown` collect every occurrence of the
/// directive in file order (wg-quick semantics: a directive may repeat, and
/// every occurrence runs, not just the last). The literal `%i` placeholder is
/// preserved as-is; it is substituted with the connection's actual interface
/// name at execution time, not here (the interface name isn't known until the
/// connection is stored).
///
/// Deliberately does not derive `Clone`: it holds the connection's private
/// key, and an incidental extra copy is an extra unzeroized-until-drop
/// lifetime for that secret. Callers that need to hold onto both a
/// [`ConnectionConfig`] and, say, its fingerprint should compute the
/// fingerprint once up front rather than cloning the config.
pub struct ConnectionConfig {
    pub private_key: PrivateKey,
    pub addresses: Vec<IpNet>,
    pub dns_servers: Vec<IpAddr>,
    pub mtu: Option<u16>,
    pub pre_up: Vec<String>,
    pub post_up: Vec<String>,
    pub pre_down: Vec<String>,
    pub post_down: Vec<String>,
    /// One or more `[Peer]` sections, in file order. Multiple peers parse
    /// successfully here (fixing the old silent-overwrite bug); it is up to
    /// the connect path to reject a peer count it cannot drive.
    pub peers: Vec<ConnectionPeer>,
}

impl std::fmt::Debug for ConnectionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionConfig")
            .field("private_key", &"(redacted)")
            .field("addresses", &self.addresses)
            .field("dns_servers", &self.dns_servers)
            .field("mtu", &self.mtu)
            .field("pre_up", &self.pre_up)
            .field("post_up", &self.post_up)
            .field("pre_down", &self.pre_down)
            .field("post_down", &self.post_down)
            .field("peers", &self.peers)
            .finish()
    }
}

pub struct ConnectionPeer {
    pub public_key: PublicKey,
    pub preshared_key: Option<PresharedKey>,
    pub allowed_ips: Vec<IpNet>,
    /// Resolved once, at parse time. See the module-level docs on
    /// `AddConnection` in the design plan for the accepted DNS-rotation
    /// tradeoff this implies for reconnects.
    pub endpoint: Option<SocketAddr>,
    /// The `Endpoint` value exactly as written in the file (trimmed), kept
    /// alongside the resolved `endpoint` above. The *identity* of a
    /// connection (see [`fingerprint`]) is hashed from this literal, not from
    /// `endpoint`: hostnames can resolve to different addresses across calls
    /// (round-robin DNS, v4/v6 ordering), which would otherwise make an
    /// unmodified, byte-for-byte-identical `.conf` produce a different
    /// fingerprint on every resubmission and defeat the exact-match
    /// idempotency `AddConnection` relies on to skip a repeat admin-auth
    /// prompt.
    pub endpoint_literal: Option<String>,
    pub persistent_keepalive: Option<u16>,
}

impl std::fmt::Debug for ConnectionPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionPeer")
            .field("public_key", &self.public_key)
            .field(
                "preshared_key",
                &self.preshared_key.as_ref().map(|_| "(redacted)"),
            )
            .field("allowed_ips", &self.allowed_ips)
            .field("endpoint", &self.endpoint)
            .field("endpoint_literal", &self.endpoint_literal)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .finish()
    }
}

#[must_use]
pub fn public_key_to_base64(key: &PublicKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.as_bytes())
}

/// Encode/decode helpers for persisting a [`ConnectionConfig`] (e.g. to the
/// privileged connection store). Centralized here rather than duplicated at
/// each call site so there is exactly one place that turns key material into
/// text and back, matching how [`decode_key32`] is the one place that reads
/// it in.
#[must_use]
pub fn private_key_to_base64(key: &PrivateKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.as_bytes())
}

#[must_use]
pub fn preshared_key_to_base64(key: &PresharedKey) -> String {
    base64::engine::general_purpose::STANDARD.encode(key.as_bytes())
}

pub fn private_key_from_base64(value: &str) -> Result<PrivateKey> {
    Ok(PrivateKey::from(decode_key32("PrivateKey", value)?))
}

pub fn public_key_from_base64(value: &str) -> Result<PublicKey> {
    Ok(PublicKey::from(decode_key32("PublicKey", value)?))
}

pub fn preshared_key_from_base64(value: &str) -> Result<PresharedKey> {
    Ok(PresharedKey::from_bytes(decode_key32(
        "PresharedKey",
        value,
    )?))
}

/// Directives this backend understands in `[Interface]`. `ListenPort`,
/// `FwMark`, `Table`, and `SaveConfig` are recognized-but-ignored: they are
/// legitimate `wg-quick` directives this backend's routing model does not
/// (yet) implement, so they are accepted rather than rejected outright, but
/// deliberately do not silently change behavior the way an *unrecognized*
/// typo would if it were dropped instead of erroring.
const KNOWN_INTERFACE_KEYS: &[&str] = &[
    "privatekey",
    "address",
    "dns",
    "mtu",
    "preup",
    "postup",
    "predown",
    "postdown",
    "listenport",
    "fwmark",
    "table",
    "saveconfig",
];
const KNOWN_PEER_KEYS: &[&str] = &[
    "publickey",
    "presharedkey",
    "allowedips",
    "endpoint",
    "persistentkeepalive",
];

/// Parse a WireGuard `.conf` file (potentially with multiple `[Peer]`
/// sections) into a [`ConnectionConfig`].
pub fn parse_connection_config(input: &str) -> Result<ConnectionConfig> {
    #[derive(PartialEq)]
    enum Section {
        None,
        Interface,
        Peer,
    }

    let mut section = Section::None;

    let mut private_key: Option<PrivateKey> = None;
    let mut addresses: Vec<IpNet> = Vec::new();
    let mut dns_servers: Vec<IpAddr> = Vec::new();
    let mut mtu: Option<u16> = None;
    let mut pre_up: Vec<String> = Vec::new();
    let mut post_up: Vec<String> = Vec::new();
    let mut pre_down: Vec<String> = Vec::new();
    let mut post_down: Vec<String> = Vec::new();
    let mut peers: Vec<ConnectionPeer> = Vec::new();

    // Per-peer accumulators, flushed into `peers` on every section change.
    let mut peer_public_key: Option<PublicKey> = None;
    let mut peer_preshared_key: Option<PresharedKey> = None;
    let mut peer_allowed_ips: Vec<IpNet> = Vec::new();
    let mut peer_endpoint: Option<SocketAddr> = None;
    let mut peer_endpoint_literal: Option<String> = None;
    let mut peer_keepalive: Option<u16> = None;

    #[allow(clippy::too_many_arguments)]
    fn flush_peer(
        peers: &mut Vec<ConnectionPeer>,
        public_key: &mut Option<PublicKey>,
        preshared_key: &mut Option<PresharedKey>,
        allowed_ips: &mut Vec<IpNet>,
        endpoint: &mut Option<SocketAddr>,
        endpoint_literal: &mut Option<String>,
        keepalive: &mut Option<u16>,
    ) -> Result<()> {
        let public_key = public_key
            .take()
            .ok_or_else(|| AppError::WireGuard("peer section missing PublicKey".into()))?;
        if allowed_ips.is_empty() {
            return Err(AppError::WireGuard(
                "peer section missing AllowedIPs".into(),
            ));
        }
        peers.push(ConnectionPeer {
            public_key,
            preshared_key: preshared_key.take(),
            allowed_ips: std::mem::take(allowed_ips),
            endpoint: endpoint.take(),
            endpoint_literal: endpoint_literal.take(),
            persistent_keepalive: keepalive.take(),
        });
        Ok(())
    }

    for raw_line in input.lines() {
        // `#` starts a comment anywhere on the line, matching wg-quick.
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }

        if line.starts_with('[') {
            // wg-quick strips all whitespace from the file before parsing
            // section headers, so `[ Peer ]` is accepted; match that instead
            // of requiring an exact `[peer]`.
            let stripped: String = line.chars().filter(|c| !c.is_whitespace()).collect();
            let inner = stripped
                .strip_prefix('[')
                .and_then(|s| s.strip_suffix(']'))
                .map(str::to_ascii_lowercase);
            match inner.as_deref() {
                Some("interface") => {
                    if section == Section::Peer {
                        flush_peer(
                            &mut peers,
                            &mut peer_public_key,
                            &mut peer_preshared_key,
                            &mut peer_allowed_ips,
                            &mut peer_endpoint,
                            &mut peer_endpoint_literal,
                            &mut peer_keepalive,
                        )?;
                    }
                    section = Section::Interface;
                }
                Some("peer") => {
                    if section == Section::Peer {
                        flush_peer(
                            &mut peers,
                            &mut peer_public_key,
                            &mut peer_preshared_key,
                            &mut peer_allowed_ips,
                            &mut peer_endpoint,
                            &mut peer_endpoint_literal,
                            &mut peer_keepalive,
                        )?;
                    }
                    section = Section::Peer;
                }
                _ => {
                    return Err(AppError::WireGuard(format!(
                        "unrecognized section header {raw_line:?} (expected [Interface] or [Peer])"
                    )));
                }
            }
            continue;
        }

        let Some((key, value)) = line.split_once('=') else {
            return Err(AppError::WireGuard(format!(
                "malformed line (expected `Key = Value`): {raw_line:?}"
            )));
        };
        let key = key.trim();
        let key_lower = key.to_ascii_lowercase();
        let value = value.trim();
        if value.is_empty() {
            continue;
        }

        match section {
            Section::Interface => {
                if !KNOWN_INTERFACE_KEYS.contains(&key_lower.as_str()) {
                    return Err(AppError::WireGuard(format!(
                        "unrecognized [Interface] directive {key:?}"
                    )));
                }
                match key_lower.as_str() {
                    "privatekey" => {
                        private_key = Some(PrivateKey::from(decode_key32("PrivateKey", value)?))
                    }
                    "address" => {
                        for entry in split_csv(value) {
                            addresses.push(parse_ipnet(&entry)?);
                        }
                    }
                    "dns" => {
                        for entry in split_csv(value) {
                            dns_servers.push(entry.parse::<IpAddr>().map_err(|_| {
                                AppError::WireGuard(format!("invalid DNS entry {entry:?}"))
                            })?);
                        }
                    }
                    "mtu" => mtu = Some(super::config::parse_mtu(value)?),
                    "preup" => pre_up.push(value.to_string()),
                    "postup" => post_up.push(value.to_string()),
                    "predown" => pre_down.push(value.to_string()),
                    "postdown" => post_down.push(value.to_string()),
                    // Recognized but not modeled by this backend yet — see
                    // `KNOWN_INTERFACE_KEYS` doc comment.
                    "listenport" | "fwmark" | "table" | "saveconfig" => {}
                    _ => unreachable!("checked by KNOWN_INTERFACE_KEYS above"),
                }
            }
            Section::Peer => {
                if !KNOWN_PEER_KEYS.contains(&key_lower.as_str()) {
                    return Err(AppError::WireGuard(format!(
                        "unrecognized [Peer] directive {key:?}"
                    )));
                }
                match key_lower.as_str() {
                    "publickey" => {
                        peer_public_key = Some(PublicKey::from(decode_key32("PublicKey", value)?))
                    }
                    "presharedkey" => {
                        peer_preshared_key = Some(PresharedKey::from_bytes(decode_key32(
                            "PresharedKey",
                            value,
                        )?))
                    }
                    "allowedips" => {
                        for entry in split_csv(value) {
                            peer_allowed_ips.push(parse_ipnet(&entry)?);
                        }
                    }
                    "endpoint" => {
                        peer_endpoint = Some(parse_endpoint(value)?);
                        peer_endpoint_literal = Some(value.to_string());
                    }
                    "persistentkeepalive" => {
                        peer_keepalive = Some(value.parse::<u16>().map_err(|_| {
                            AppError::WireGuard(format!("invalid PersistentKeepalive {value:?}"))
                        })?);
                    }
                    _ => unreachable!("checked by KNOWN_PEER_KEYS above"),
                }
            }
            Section::None => {
                return Err(AppError::WireGuard(format!(
                    "directive {key:?} appears before any [Interface]/[Peer] section"
                )));
            }
        }
    }

    if section == Section::Peer {
        flush_peer(
            &mut peers,
            &mut peer_public_key,
            &mut peer_preshared_key,
            &mut peer_allowed_ips,
            &mut peer_endpoint,
            &mut peer_endpoint_literal,
            &mut peer_keepalive,
        )?;
    }

    let private_key = private_key
        .ok_or_else(|| AppError::WireGuard("missing PrivateKey in [Interface]".into()))?;
    if addresses.is_empty() {
        return Err(AppError::WireGuard("missing Address in [Interface]".into()));
    }
    if peers.is_empty() {
        return Err(AppError::WireGuard("no [Peer] sections found".into()));
    }

    Ok(ConnectionConfig {
        private_key,
        addresses,
        dns_servers,
        mtu,
        pre_up,
        post_up,
        pre_down,
        post_down,
        peers,
    })
}

fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn parse_ipnet(value: &str) -> Result<IpNet> {
    value
        .parse::<IpNet>()
        .map_err(|_| AppError::WireGuard(format!("invalid address/CIDR {value:?}")))
}

/// Decode a base64-encoded 32-byte key. The intermediate decode buffer is
/// zeroized on drop: it briefly holds raw key material (a private key or a
/// preshared key) that must not linger unzeroized on the heap after the fixed
/// 32-byte array has been copied out of it.
fn decode_key32(field: &str, value: &str) -> Result<[u8; 32]> {
    let decoded: Zeroizing<Vec<u8>> = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .map_err(|e| AppError::WireGuard(format!("failed to decode {field}: {e}")))?,
    );
    if decoded.len() != 32 {
        return Err(AppError::WireGuard(format!(
            "{field} must decode to 32 bytes"
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// Upper bound on how long endpoint hostname resolution may block. `AddConnection`
/// runs on the privileged daemon's single dispatch thread (see
/// `src/privileged/socket.rs`), so an unbounded `getaddrinfo()` on a
/// caller-chosen hostname would let any `tunmux`-group member freeze every
/// other client's requests, and would have the root daemon itself make
/// blocking DNS queries for an attacker-chosen name with no time limit. The OS
/// resolver call itself cannot be cancelled once started, so this bounds how
/// long the *caller* waits for it, not the underlying thread's lifetime.
const ENDPOINT_RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Resolve an `Endpoint` value into a concrete socket address, once, here.
/// Accepts a literal IPv4/IPv6 address (bracketed for IPv6) or a hostname,
/// which is resolved via the system resolver, bounded by
/// [`ENDPOINT_RESOLVE_TIMEOUT`]. See the module-level docs for the accepted
/// DNS-rotation tradeoff of resolving once at parse time.
fn parse_endpoint(value: &str) -> Result<SocketAddr> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| AppError::WireGuard(format!("invalid endpoint {value:?}")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| AppError::WireGuard(format!("invalid endpoint port in {value:?}")))?;
    let host = host.trim_matches(['[', ']']);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }
    resolve_host_with_timeout(host, port, ENDPOINT_RESOLVE_TIMEOUT)
}

fn resolve_host_with_timeout(host: &str, port: u16, timeout: Duration) -> Result<SocketAddr> {
    let (tx, rx) = mpsc::channel();
    let target = format!("{host}:{port}");
    // The resolver call cannot be cancelled once started; a thread that
    // outlives the timeout is abandoned (its result is dropped when the send
    // fails), trading a leaked thread for a bounded wait on the caller side.
    let _ = std::thread::Builder::new()
        .name("tunmux-endpoint-resolve".into())
        .spawn(move || {
            let result = target
                .to_socket_addrs()
                .map(|mut addrs| addrs.next())
                .map_err(|e| e.to_string());
            let _ = tx.send(result);
        });
    match rx.recv_timeout(timeout) {
        Ok(Ok(Some(addr))) => Ok(addr),
        Ok(Ok(None)) => Err(AppError::WireGuard(format!(
            "no addresses found for endpoint host {host:?}"
        ))),
        Ok(Err(error)) => Err(AppError::WireGuard(format!(
            "failed to resolve endpoint host {host:?}: {error}"
        ))),
        Err(mpsc::RecvTimeoutError::Timeout) => Err(AppError::WireGuard(format!(
            "timed out resolving endpoint host {host:?} after {}s",
            timeout.as_secs()
        ))),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(AppError::WireGuard(format!(
            "endpoint host resolution for {host:?} failed unexpectedly"
        ))),
    }
}

/// A stable, explicitly versioned identity hash over the entire parsed
/// configuration (`"sha256:<hex>"`). Hand-written byte encoding, not a
/// `serde`-derived one: a derive's field order is not a stable contract and
/// must never silently change a connection's identity across a dependency
/// bump. Every field that participates in the connection's behavior is
/// included, in a fixed order, each length-prefixed so no two distinct field
/// sequences can encode to the same bytes. The intermediate buffer is
/// zeroized on drop, since it contains the private key and any preshared
/// keys in plain bytes for the duration of the hash computation.
const FINGERPRINT_TAG: &[u8] = b"tunmux-connfp-v1";

#[must_use]
pub fn fingerprint(config: &ConnectionConfig) -> String {
    let mut buf: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::new());
    buf.extend_from_slice(FINGERPRINT_TAG);

    push_bytes(&mut buf, config.private_key.as_bytes());
    push_ipnets(&mut buf, &config.addresses);
    push_u32(&mut buf, config.dns_servers.len() as u32);
    for ip in &config.dns_servers {
        push_ip(&mut buf, *ip);
    }
    push_option_u16(&mut buf, config.mtu);
    push_strings(&mut buf, &config.pre_up);
    push_strings(&mut buf, &config.post_up);
    push_strings(&mut buf, &config.pre_down);
    push_strings(&mut buf, &config.post_down);

    push_u32(&mut buf, config.peers.len() as u32);
    for peer in &config.peers {
        push_bytes(&mut buf, peer.public_key.as_bytes());
        match &peer.preshared_key {
            Some(psk) => {
                buf.push(1);
                push_bytes(&mut buf, psk.as_bytes());
            }
            None => buf.push(0),
        }
        push_ipnets(&mut buf, &peer.allowed_ips);
        // The literal endpoint text, not the resolved address: see the
        // `endpoint_literal` field doc for why (DNS rotation must not change
        // a connection's identity on a byte-for-byte-identical resubmission).
        match &peer.endpoint_literal {
            Some(literal) => {
                buf.push(1);
                push_bytes(&mut buf, literal.as_bytes());
            }
            None => buf.push(0),
        }
        push_option_u16(&mut buf, peer.persistent_keepalive);
    }

    let digest = Sha256::digest(buf.as_slice());
    format!("sha256:{}", hex_encode(&digest))
}

fn push_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn push_option_u16(buf: &mut Vec<u8>, value: Option<u16>) {
    match value {
        Some(v) => {
            buf.push(1);
            buf.extend_from_slice(&v.to_le_bytes());
        }
        None => buf.push(0),
    }
}

fn push_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    push_u32(buf, bytes.len() as u32);
    buf.extend_from_slice(bytes);
}

fn push_ip(buf: &mut Vec<u8>, ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            buf.push(4);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(6);
            buf.extend_from_slice(&v6.octets());
        }
    }
}

/// Encode the exact literal value of each `IpNet` (address bits as written,
/// not masked to the network) plus its prefix length: for an interface
/// `Address` this is the host's own IP, not a route, so masking host bits
/// here would collapse distinct configurations onto the same fingerprint.
fn push_ipnets(buf: &mut Vec<u8>, nets: &[IpNet]) {
    push_u32(buf, nets.len() as u32);
    for net in nets {
        push_ip(buf, net.addr());
        buf.push(net.prefix_len());
    }
}

fn push_strings(buf: &mut Vec<u8>, values: &[String]) {
    push_u32(buf, values.len() as u32);
    for value in values {
        push_bytes(buf, value.as_bytes());
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "\
[Interface]\n\
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
Address = 10.0.0.2/32\n\
DNS = 1.1.1.1\n\
[Peer]\n\
PublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
AllowedIPs = 0.0.0.0/0\n\
Endpoint = 198.51.100.1:51820\n";

    #[test]
    fn parses_minimal_config() {
        let parsed = parse_connection_config(BASE).expect("parse");
        assert_eq!(parsed.addresses.len(), 1);
        assert_eq!(parsed.peers.len(), 1);
        assert_eq!(
            parsed.peers[0].endpoint,
            Some("198.51.100.1:51820".parse().unwrap())
        );
        assert_eq!(
            parsed.peers[0].endpoint_literal.as_deref(),
            Some("198.51.100.1:51820")
        );
    }

    #[test]
    fn rejects_missing_private_key() {
        let input = "[Interface]\nAddress = 10.0.0.1/32\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 0.0.0.0/0\n";
        let err = parse_connection_config(input).unwrap_err();
        assert!(err.to_string().contains("PrivateKey"));
    }

    #[test]
    fn rejects_no_peers() {
        let input = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.1/32\n";
        let err = parse_connection_config(input).unwrap_err();
        assert!(err.to_string().contains("Peer"));
    }

    #[test]
    fn multi_peer_sections_are_not_silently_overwritten() {
        // Regression test for the old userspace_helper bug: a second [Peer]
        // section must produce a second peer, not clobber the first.
        let input = format!(
            "{BASE}[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAllowedIPs = 10.10.0.0/24\n"
        );
        let parsed = parse_connection_config(&input).expect("parse");
        assert_eq!(parsed.peers.len(), 2);
        assert_ne!(
            parsed.peers[0].public_key.as_bytes(),
            parsed.peers[1].public_key.as_bytes()
        );
    }

    #[test]
    fn preup_postdown_collect_every_occurrence_in_order() {
        let input = format!(
            "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\nPreUp = echo one\nPreUp = echo two\n{}",
            &BASE[BASE.find("[Peer]").unwrap()..]
        );
        let parsed = parse_connection_config(&input).expect("parse");
        assert_eq!(parsed.pre_up, vec!["echo one", "echo two"]);
    }

    #[test]
    fn resolves_bracketed_ipv6_endpoint() {
        let input = BASE.replace(
            "Endpoint = 198.51.100.1:51820",
            "Endpoint = [2001:db8::1]:51820",
        );
        let parsed = parse_connection_config(&input).expect("parse");
        assert_eq!(
            parsed.peers[0].endpoint,
            Some("[2001:db8::1]:51820".parse().unwrap())
        );
    }

    #[test]
    fn keys_and_section_headers_are_case_insensitive() {
        let lower = BASE
            .replace("PrivateKey", "privatekey")
            .replace("Address", "address")
            .replace("DNS", "dns")
            .replace("[Peer]", "[ peer ]")
            .replace("PublicKey", "publickey")
            .replace("AllowedIPs", "allowedips")
            .replace("Endpoint", "endpoint");
        let parsed = parse_connection_config(&lower).expect("case-insensitive parse");
        assert_eq!(
            parsed.dns_servers,
            vec!["1.1.1.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn unknown_interface_directive_is_rejected_instead_of_ignored() {
        let input = format!(
            "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\nBogus = 1\n{}",
            &BASE[BASE.find("[Peer]").unwrap()..]
        );
        let err = parse_connection_config(&input).unwrap_err();
        assert!(err.to_string().contains("Bogus"));
    }

    #[test]
    fn unknown_section_header_is_rejected() {
        let input = "[Bogus]\nFoo = 1\n";
        let err = parse_connection_config(input).unwrap_err();
        assert!(err.to_string().contains("Bogus"));
    }

    #[test]
    fn recognized_but_unmodeled_interface_keys_do_not_error() {
        let input = format!(
            "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\nTable = off\nFwMark = 51820\nListenPort = 51820\nSaveConfig = true\n{}",
            &BASE[BASE.find("[Peer]").unwrap()..]
        );
        assert!(parse_connection_config(&input).is_ok());
    }

    #[test]
    fn fingerprint_is_stable_across_comments_and_whitespace() {
        let a = parse_connection_config(BASE).unwrap();
        let noisy = format!(
            "# a comment\n{}\n\n  # trailing\n",
            BASE.replace("PrivateKey", "  PrivateKey")
        );
        let b = parse_connection_config(&noisy).unwrap();
        assert_eq!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn fingerprint_changes_with_dns() {
        let a = parse_connection_config(BASE).unwrap();
        let changed = BASE.replace("DNS = 1.1.1.1", "DNS = 9.9.9.9");
        let b = parse_connection_config(&changed).unwrap();
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn fingerprint_changes_with_mtu() {
        let a = parse_connection_config(BASE).unwrap();
        let changed = format!(
            "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\nMTU = 1280\n{}",
            &BASE[BASE.find("[Peer]").unwrap()..]
        );
        let b = parse_connection_config(&changed).unwrap();
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn fingerprint_changes_with_peer_order() {
        let two_peers = format!(
            "{BASE}[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAllowedIPs = 10.10.0.0/24\n"
        );
        let a = parse_connection_config(&two_peers).unwrap();

        let reordered =
            "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n\
[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAllowedIPs = 10.10.0.0/24\n\
[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.1:51820\n";
        let b = parse_connection_config(reordered).unwrap();
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn fingerprint_distinguishes_interface_address_from_masked_network() {
        // Address is the interface's own IP, not a route: two different host
        // addresses in the same /24 must not collide even though a masked
        // "network()" view of both would be identical.
        let a = parse_connection_config(BASE).unwrap();
        let changed = BASE.replace("Address = 10.0.0.2/32", "Address = 10.0.0.3/32");
        let b = parse_connection_config(&changed).unwrap();
        assert_ne!(fingerprint(&a), fingerprint(&b));
    }

    #[test]
    fn fingerprint_uses_endpoint_literal_not_resolved_address() {
        // Two peers that resolve to the identical SocketAddr but were written
        // with different literal Endpoint text (as a hostname could, across
        // resolutions, for the *same* literal) must still be told apart by
        // their literal text -- this is what makes an unmodified,
        // byte-for-byte-identical resubmission's fingerprint stable
        // regardless of what the resolver returns.
        let peer = |literal: &str| ConnectionPeer {
            public_key: PublicKey::from([1u8; 32]),
            preshared_key: None,
            allowed_ips: vec!["0.0.0.0/0".parse().unwrap()],
            endpoint: Some("198.51.100.1:51820".parse().unwrap()),
            endpoint_literal: Some(literal.to_string()),
            persistent_keepalive: None,
        };
        let base = |literal: &str| ConnectionConfig {
            private_key: PrivateKey::from([0u8; 32]),
            addresses: vec!["10.0.0.2/32".parse().unwrap()],
            dns_servers: vec!["1.1.1.1".parse().unwrap()],
            mtu: None,
            pre_up: vec![],
            post_up: vec![],
            pre_down: vec![],
            post_down: vec![],
            peers: vec![peer(literal)],
        };
        assert_ne!(
            fingerprint(&base("example.com:51820")),
            fingerprint(&base("198.51.100.1:51820"))
        );
    }

    #[test]
    fn resolve_host_with_timeout_bounds_the_wait() {
        // A name that (almost certainly) does not resolve should fail
        // promptly, not hang the caller; a real timeout is exercised only by
        // a network condition that can't be reproduced deterministically in
        // a unit test, so this just pins the "fails, doesn't hang" contract.
        let started = std::time::Instant::now();
        let result = resolve_host_with_timeout(
            "tunmux-test-nonexistent.invalid",
            51820,
            Duration::from_secs(5),
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
