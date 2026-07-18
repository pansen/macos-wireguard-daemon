use std::fs;
use std::os::unix::fs::PermissionsExt;

use serde::{Deserialize, Serialize};
use tracing::info;

use crate::config;
use crate::error::Result;

use super::backend::WgBackend;

/// Reserved instance name for the traditional all-traffic VPN mode.
pub const DIRECT_INSTANCE: &str = "_direct";

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectionState {
    pub instance_name: String,
    pub provider: String,
    pub interface_name: String,
    pub backend: WgBackend,
    pub server_endpoint: String,
    pub server_display_name: String,
    #[serde(default)]
    pub dns_servers: Vec<String>,
    /// Canonicalized path of the source `.conf` this tunnel was brought up from
    /// (wgconf direct mode only). Lets a repeat `connect --if-missing` recognize
    /// that the same source is already live and no-op instead of erroring.
    #[serde(default)]
    pub source_path: Option<String>,
}

impl ConnectionState {
    /// Save to ~/.config/tunmux/connections/<instance>.json
    pub fn save(&self) -> Result<()> {
        config::ensure_connections_dir()?;
        let path = config::connections_dir().join(format!("{}.json", self.instance_name));
        let json = serde_json::to_string_pretty(self)?;
        fs::write(&path, &json)?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        info!( path = ?path.display().to_string(), "connection_state_saved");
        Ok(())
    }

    /// Load a specific instance.
    pub fn load(instance: &str) -> Result<Option<Self>> {
        let path = config::connections_dir().join(format!("{}.json", instance));
        if !path.exists() {
            return Ok(None);
        }
        let json = fs::read_to_string(&path)?;
        let state: Self = serde_json::from_str(&json)?;
        Ok(Some(state))
    }

    /// Load all active connections.
    pub fn load_all() -> Result<Vec<Self>> {
        let dir = config::connections_dir();
        if !dir.exists() {
            return Ok(Vec::new());
        }
        let mut connections = Vec::new();
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("json") {
                let json = fs::read_to_string(&path)?;
                match serde_json::from_str::<Self>(&json) {
                    Ok(state) => connections.push(state),
                    Err(e) => {
                        tracing::warn!(
                            path = ?path.display().to_string(),
                            error = ?e.to_string(), "connection_state_entry_skipped");
                    }
                }
            }
        }
        Ok(connections)
    }

    /// Remove a specific instance's state file.
    pub fn remove(instance: &str) -> Result<()> {
        let path = config::connections_dir().join(format!("{}.json", instance));
        if path.exists() {
            fs::remove_file(&path)?;
            info!( instance = ?instance, "connection_state_removed");
        }
        Ok(())
    }

    /// Best-effort probe of whether this saved connection is still actually
    /// active on the system. Used to tell a real, live tunnel apart from stale
    /// state left behind by a reboot or crash (e.g. a `_direct.json` whose
    /// interface and control socket no longer exist after boot).
    #[must_use]
    pub fn is_live(&self) -> bool {
        use super::{userspace, wg_quick};
        match self.backend {
            WgBackend::Userspace => userspace::is_interface_active(&self.interface_name),
            // Kernel and wg-quick both back a named interface (Linux) or a
            // kernel-assigned utunN (macOS); the same probe applies.
            WgBackend::WgQuick | WgBackend::Kernel => {
                wg_quick::is_interface_active(&self.interface_name)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wireguard::backend::WgBackend;

    fn sample(backend: WgBackend, interface: &str) -> ConnectionState {
        ConnectionState {
            instance_name: DIRECT_INSTANCE.to_string(),
            provider: "wgconf".to_string(),
            interface_name: interface.to_string(),
            backend,
            server_endpoint: "198.51.100.1:51820".to_string(),
            server_display_name: "test".to_string(),
            dns_servers: vec![],
            source_path: None,
        }
    }

    // The reboot bug: a saved userspace tunnel whose control socket no longer
    // exists must be reported as not live (so the stale state gets pruned).
    #[test]
    fn userspace_state_with_missing_interface_is_not_live() {
        let state = sample(WgBackend::Userspace, "__tunmux_nonexistent_test_iface__");
        assert!(!state.is_live());
    }
}
