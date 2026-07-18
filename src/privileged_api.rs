use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WgQuickAction {
    Up,
    Down,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GotaTunAction {
    Up,
    Down,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrivilegedRequest {
    WgQuickRun {
        action: WgQuickAction,
        interface: String,
        provider: String,
        config_content: String,
        #[serde(default)]
        prefer_userspace: bool,
    },
    GotaTunRun {
        action: GotaTunAction,
        interface: String,
        config_content: String,
        #[serde(default)]
        mtu_override: Option<u16>,
        #[serde(default)]
        debug: bool,
    },

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PrivilegedResponse {
    Unit,
    Bool(bool),
    Pid(u32),
    Text(String),
    Error { code: String, message: String },
}

impl PrivilegedRequest {
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::WgQuickRun {
                interface,
                provider,
                ..
            } => {
                validate_interface_name(interface)?;
                validate_provider(provider)?;
                Ok(())
            }
            Self::GotaTunRun {
                action,
                interface,
                config_content,
                mtu_override,
                ..
            } => {
                validate_interface_name(interface)?;
                if matches!(action, GotaTunAction::Up) && config_content.trim().is_empty() {
                    return Err("config_content cannot be empty".into());
                }
                if let Some(mtu) = mtu_override {
                    crate::wireguard::config::validate_mtu(*mtu).map_err(|e| e.to_string())?;
                }
                Ok(())
            }
            Self::LeaseAcquire { token } | Self::LeaseRelease { token } => {
                validate_lease_token(token)
            }
            Self::ShutdownIfIdle => Ok(()),
            Self::InterfaceActive { interface } => validate_interface_name(interface),
            Self::WgShow { interface } => validate_interface_name(interface),
        }
    }
}

fn validate_interface_name(interface: &str) -> Result<(), String> {
    if interface == "wgconf0" {
        return Ok(());
    }
    // On macOS, WireGuard TUN interfaces are named utunN (kernel-assigned).
    // "utun" (no number) is also accepted as the name passed to wg-quick on macOS.
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

fn validate_provider(provider: &str) -> Result<(), String> {
    if provider == "wgconf" {
        Ok(())
    } else {
        Err("provider must be wgconf".into())
    }
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
    use super::{validate_interface_name, validate_provider};

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

    #[test]
    fn known_providers_are_allowed() {
        assert!(validate_provider("wgconf").is_ok());
        assert!(validate_provider("proton").is_err());
    }
}
