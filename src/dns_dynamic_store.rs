//! Tunnel DNS key in the SystemConfiguration dynamic store (see
//! `doc/dns-dynamic-store.md`, "Rollout").
//!
//! Every DNS-promoting userspace helper publishes one State-only service per
//! connection. In shadow mode (phase 1, the default) its resolver matches only
//! `wgd-shadow-<uuid>.inactive`, so it never answers a real query and the
//! `networksetup` path stays in charge. Connections listed in the root-only
//! opt-in file (phase 2) publish the target shape with the match domain `""`
//! instead and skip `networksetup` entirely.
//!
//! This module holds what the helper, the daemon and `wgd status` share: the
//! key derivation, a read-only check and the opt-in file. Only the owning
//! helper writes the key (`userspace_helper::macos::dns_store_key`); a plain
//! `set` from any other session would make it permanent.
use std::io;
use std::path::PathBuf;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use system_configuration::dynamic_store::SCDynamicStoreBuilder;
use uuid::Uuid;

use crate::privileged_api::ConnectionId;

/// `SearchOrder` of the resolver. In shadow mode the match domain is unique
/// per connection, so ordering does not matter; in active mode several
/// opted-in tunnels with DNS are not ordered yet (see "Ordering").
pub const SEARCH_ORDER: i32 = 100_000;

/// Set to `1` by the daemon when it spawns the helper of an opted-in
/// connection.
pub const ACTIVE_ENV: &str = "WGD_DNS_DYNAMIC_STORE";

/// Shadow (probe match domain) or active (`""`, answers every query).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StoreKeyMode {
    Shadow,
    Active,
}

impl StoreKeyMode {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Shadow => "shadow",
            Self::Active => "active",
        }
    }
}

/// The synthetic service id for a connection: a UUIDv8 from a hash of the
/// connection id, so anyone who knows the id finds the key without state.
#[must_use]
pub fn tunnel_service_id(connection_id: ConnectionId) -> Uuid {
    let digest = Sha256::digest(format!("wgd-dns-service:{connection_id}").as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    uuid::Builder::from_custom_bytes(bytes).into_uuid()
}

/// `State:/Network/Service/<SERVICE-ID>/DNS`, with the id in the uppercase
/// form configd uses for its own service ids.
#[must_use]
pub fn dns_key(connection_id: ConnectionId) -> String {
    let id = tunnel_service_id(connection_id)
        .hyphenated()
        .encode_upper(&mut Uuid::encode_buffer())
        .to_string();
    format!("State:/Network/Service/{id}/DNS")
}

/// The match domain for `mode`. In shadow mode no real name falls under it
/// because the label carries the service id; `.inactive` tells a reader of
/// `scutil --dns` what the resolver is. `""` makes a domain-less resolver.
#[must_use]
pub fn match_domain(connection_id: ConnectionId, mode: StoreKeyMode) -> String {
    match mode {
        StoreKeyMode::Shadow => {
            format!("wgd-shadow-{}.inactive", tunnel_service_id(connection_id))
        }
        StoreKeyMode::Active => String::new(),
    }
}

/// Whether the connection's key exists. Opens a plain session and only reads.
pub fn key_present(connection_id: ConnectionId) -> anyhow::Result<bool> {
    let store = SCDynamicStoreBuilder::new("wgd-dns-store-read")
        .build()
        .context("SCDynamicStoreCreate failed")?;
    Ok(store.get(dns_key(connection_id).as_str()).is_some())
}

/// Root-only opt-in list for active mode (phase 2): one connection id per
/// line, `#` starts a comment. Edited by hand with sudo; the daemon reads it
/// each time it spawns a helper.
#[must_use]
pub fn opt_in_path() -> PathBuf {
    crate::config::privileged_runtime_dir().join("dns-dynamic-store")
}

/// Whether `connection_id` is listed in the opt-in file. A missing file means
/// nobody opted in. The file decides which DNS path root takes, so a file
/// that is not root-owned or is group/other writable counts as an error.
pub fn opted_in(connection_id: ConnectionId) -> io::Result<bool> {
    let path = opt_in_path();
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    crate::trusted_exec::validate_root_owned_path(&path, crate::trusted_exec::TrustedPath::File)?;
    let listed = parse_opt_in(&text).any(|listed| listed == connection_id);
    Ok(listed)
}

/// Connection ids in the opt-in file; malformed lines are skipped.
fn parse_opt_in(text: &str) -> impl Iterator<Item = ConnectionId> + '_ {
    text.lines()
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter_map(|line| line.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_id_is_stable_and_versioned() {
        let id: ConnectionId = "6f1c1f1e-7c35-4f0e-9a43-3c9f2b8f3d10".parse().unwrap();
        assert_eq!(tunnel_service_id(id), tunnel_service_id(id));
        assert_eq!(tunnel_service_id(id).get_version_num(), 8);
        assert_ne!(
            tunnel_service_id(id),
            tunnel_service_id(ConnectionId::new())
        );
    }

    #[test]
    fn key_and_domain_share_the_service_id() {
        let id = ConnectionId::new();
        let service = tunnel_service_id(id);
        assert_eq!(
            dns_key(id),
            format!(
                "State:/Network/Service/{}/DNS",
                service.to_string().to_uppercase()
            )
        );
        assert_eq!(
            match_domain(id, StoreKeyMode::Shadow),
            format!("wgd-shadow-{service}.inactive")
        );
        assert_eq!(match_domain(id, StoreKeyMode::Active), "");
    }

    #[test]
    fn opt_in_parses_ids_and_skips_comments_and_junk() {
        let a: ConnectionId = "6f1c1f1e-7c35-4f0e-9a43-3c9f2b8f3d10".parse().unwrap();
        let b: ConnectionId = "0a0b0c0d-0000-4000-8000-000000000001".parse().unwrap();
        let text = format!(
            "# opted in\n{a}  # laptop\n\nnot-an-id\n  {b}\n# {}\n",
            ConnectionId::new()
        );
        assert_eq!(parse_opt_in(&text).collect::<Vec<_>>(), vec![a, b]);
    }
}
