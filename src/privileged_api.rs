use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Opaque, randomly generated identity for a stored connection (see
/// `privileged::connection_store`). Never derived from caller input --
/// `AddConnection` is the only place one is minted, and interface names are
/// in turn derived from it deterministically rather than accepted from a
/// caller, closing off interface-name-as-untrusted-input. Lives in this
/// module (the RPC wire-contract) rather than in `connection_store` because
/// it appears directly in `PrivilegedRequest`/`PrivilegedResponse` variants,
/// not only in the on-disk record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ConnectionId(Uuid);

impl ConnectionId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Deterministic interface name: `wg-` plus the first 8 hex characters of
    /// the UUID's simple (unhyphenated) form, which is always lowercase hex
    /// and therefore always satisfies [`validate_interface_name`]'s `wg-*`
    /// rule. Collisions are astronomically unlikely but not impossible, so
    /// `connection_store::allocate_unique_interface` still checks uniqueness
    /// under the index lock rather than trusting this alone.
    #[must_use]
    pub fn interface_name(&self) -> String {
        format!("wg-{}", &self.0.simple().to_string()[..8])
    }
}

impl Default for ConnectionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ConnectionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl FromStr for ConnectionId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionStartMode {
    #[default]
    Manual,
    Automatic,
}

/// Which connections a `ListConnections` call should return. `All` is
/// rejected in `dispatch()` for a non-root caller; `Mine` filters to the
/// caller's own `owner_uid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionScope {
    Mine,
    Global,
    All,
}

/// Redacted view of a stored connection for `ListConnections`/`GetConnection`
/// responses -- never carries `private_key`/`preshared_key`/`raw_conf`.
/// `fingerprint` is `None` for every `ListConnections` entry and is only ever
/// populated for a `GetConnection` response the caller was authorized (owner
/// or root) to see, per the design plan's `GetConnection` access rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionSummary {
    pub id: ConnectionId,
    pub global: bool,
    pub owner_uid: Option<u32>,
    pub start_mode: ConnectionStartMode,
    pub name: Option<String>,
    pub interface: String,
    pub connected: bool,
    pub addresses: Vec<String>,
    pub dns_servers: Vec<String>,
    pub mtu: Option<u16>,
    pub peers: Vec<PeerSummary>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSummary {
    pub public_key: String,
    pub allowed_ips: Vec<String>,
    pub endpoint: Option<String>,
    pub has_preshared_key: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrivilegedRequest {
    LeaseAcquire {
        token: String,
    },
    LeaseRelease {
        token: String,
    },
    ShutdownIfIdle,

    /// Liveness probe for a userspace tunnel: returns whether the UAPI control
    /// socket at `/var/run/wireguard/<interface>.sock` exists. Run by the
    /// privileged service (root) because that directory is `0750 root:daemon`
    /// and cannot be stat'd by an unprivileged caller — a local `exists()`
    /// check there is permission-blind and always reports the tunnel as down.
    InterfaceActive {
        interface: String,
    },

    /// Run `wg show <interface>` and return the output (reads the UAPI socket at
    /// `/var/run/wireguard/<interface>.sock` for userspace interfaces).
    WgShow {
        interface: String,
    },

    /// Fetch the live route/DNS overview for a userspace tunnel by querying the
    /// helper's `/var/run/wireguard/<interface>.tunmux.query.sock`. Proxied
    /// through the privileged service because that socket is root-only.
    NetworkOverview {
        interface: String,
    },

    /// Parse and validate a WireGuard `.conf` exactly once, storing the
    /// result under a fresh opaque `ConnectionId` -- or, if an existing
    /// record already has the identical `(fingerprint, global, owner_uid)`
    /// identity, returning that record's id unchanged (see the design plan's
    /// fingerprint section for why this exact-match case must be a silent
    /// no-op rather than creating a duplicate or re-engaging admin auth).
    /// `mtu_override`, if given, is baked into the stored config/raw text at
    /// add time rather than carried as a separate per-connect parameter.
    AddConnection {
        conf_text: String,
        global: bool,
        #[serde(default)]
        start_mode: ConnectionStartMode,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        mtu_override: Option<u16>,
        /// Present once the caller has completed the macOS admin-auth
        /// challenge for a genuinely new/changed configuration (see
        /// `privileged::authz`); absent on the first attempt.
        #[serde(default)]
        auth_external_form: Option<Vec<u8>>,
    },

    RemoveConnection {
        id: ConnectionId,
        #[serde(default)]
        auth_external_form: Option<Vec<u8>>,
    },

    ConnectConnection {
        id: ConnectionId,
        #[serde(default)]
        debug: bool,
    },

    DisconnectConnection {
        id: ConnectionId,
    },

    SetConnectionMode {
        id: ConnectionId,
        start_mode: ConnectionStartMode,
        #[serde(default)]
        auth_external_form: Option<Vec<u8>>,
    },

    ListConnections {
        scope: ConnectionScope,
    },

    GetConnection {
        id: ConnectionId,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PrivilegedResponse {
    Unit,
    Bool(bool),
    Pid(u32),
    Text(String),
    Error { code: String, message: String },
    ConnectionId(ConnectionId),
    Connection(ConnectionSummary),
    ConnectionList(Vec<ConnectionSummary>),
}

/// Upper bound on the size of a submitted `.conf`. Generous for any real
/// WireGuard config (which are a handful of KiB at most even with many
/// peers) while keeping a malicious oversized submission cheap to reject
/// before it ever reaches the parser.
pub const MAX_CONF_TEXT_BYTES: usize = 64 * 1024;

/// Charset/length rule shared by every user-supplied *name* this API
/// accepts (a connection's `name` here).
pub(crate) fn validate_name_charset(name: &str, max_len: usize) -> Result<(), String> {
    if name.is_empty() {
        return Err("name cannot be empty".into());
    }
    if name.len() > max_len {
        return Err(format!("name is too long (max {max_len} characters)"));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.')
    {
        return Err(format!(
            "invalid name {name:?}; use only lowercase letters, digits, '-', '_' or '.'"
        ));
    }
    Ok(())
}

impl PrivilegedRequest {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::LeaseAcquire { token } | Self::LeaseRelease { token } => {
                validate_lease_token(token)
            }
            Self::ShutdownIfIdle => Ok(()),
            Self::InterfaceActive { interface } => validate_interface_name(interface),
            Self::WgShow { interface } => validate_interface_name(interface),
            Self::NetworkOverview { interface } => validate_interface_name(interface),
            Self::AddConnection {
                conf_text,
                name,
                mtu_override,
                ..
            } => {
                if conf_text.trim().is_empty() {
                    return Err("conf_text cannot be empty".into());
                }
                if conf_text.len() > MAX_CONF_TEXT_BYTES {
                    return Err(format!(
                        "conf_text exceeds the {MAX_CONF_TEXT_BYTES}-byte limit"
                    ));
                }
                if let Some(name) = name {
                    validate_name_charset(name, 64)?;
                }
                if let Some(mtu) = mtu_override {
                    crate::wireguard::config::validate_mtu(*mtu).map_err(|e| e.to_string())?;
                }
                Ok(())
            }
            Self::RemoveConnection { .. } => Ok(()),
            Self::ConnectConnection { .. } => Ok(()),
            Self::DisconnectConnection { .. } => Ok(()),
            Self::SetConnectionMode { .. } => Ok(()),
            Self::ListConnections { .. } => Ok(()),
            Self::GetConnection { .. } => Ok(()),
        }
    }
}

pub(crate) fn validate_interface_name(interface: &str) -> Result<(), String> {
    if interface == "wgconf0" {
        return Ok(());
    }
    // On macOS, WireGuard TUN interfaces are named utunN (kernel-assigned).
    // "utun" (no number) is also accepted as the name passed to the tunnel setup on macOS.
    if interface == "utun" {
        return Ok(());
    }
    if let Some(suffix) = interface.strip_prefix("utun") {
        if !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit()) && suffix.len() <= 3 {
            return Ok(());
        }
    }
    if !interface.starts_with("wg-") {
        return Err("interface must be wgconf0, utun, utunN, or wg-*".into());
    }
    let suffix = &interface["wg-".len()..];
    if suffix.is_empty() || suffix.len() > 12 {
        return Err("wg-* interface suffix must be 1..=12 chars".into());
    }
    if !suffix
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err("wg-* interface name contains invalid characters".into());
    }
    Ok(())
}

fn validate_lease_token(token: &str) -> Result<(), String> {
    if token.is_empty() || token.len() > 64 {
        return Err("lease token must be 1..=64 chars".into());
    }
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '-' || c == '_')
    {
        return Err("lease token contains invalid characters".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::validate_interface_name;

    #[test]
    fn direct_provider_interfaces_are_allowed() {
        assert!(validate_interface_name("wgconf0").is_ok());
    }

    #[test]
    fn wg_prefixed_interfaces_are_allowed() {
        for iface in ["wg-a", "wg-us-sjc-507", "wg-51820"] {
            assert!(validate_interface_name(iface).is_ok(), "iface {}", iface);
        }
    }

    #[test]
    fn utun_interfaces_are_allowed() {
        for iface in ["utun", "utun0", "utun5", "utun99"] {
            assert!(validate_interface_name(iface).is_ok(), "iface {}", iface);
        }
    }
}
