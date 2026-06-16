use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::Result;

const APP_DIR: &str = "tunmux";

// ── TOML config ────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub general: GeneralConfig,
    pub wgconf: WgconfConfig,
}

impl AppConfig {
    /// Returns the hook config for a given provider.
    pub fn hooks_for(&self, provider: Provider) -> &HookConfig {
        match provider {
            Provider::Wgconf => &self.wgconf.hooks,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    pub backend: String,
    pub credential_store: CredentialStore,
    pub proxy_access_log: bool,
    pub privileged_transport: PrivilegedTransport,
    pub privileged_autostart: bool,
    pub privileged_autostart_timeout_ms: u64,
    pub privileged_authorized_group: String,
    pub privileged_autostop_mode: PrivilegedAutostopMode,
    pub privileged_autostop_timeout_ms: u64,
    pub hooks: HookConfig,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            backend: default_backend().to_string(),
            credential_store: default_credential_store(),
            proxy_access_log: false,
            privileged_transport: PrivilegedTransport::Socket,
            privileged_autostart: true,
            privileged_autostart_timeout_ms: 5000,
            privileged_authorized_group: String::new(),
            privileged_autostop_mode: PrivilegedAutostopMode::Never,
            privileged_autostop_timeout_ms: 30000,
            hooks: HookConfig::default(),
        }
    }
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct HookConfig {
    pub ifup: Vec<String>,
    pub ifdown: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStore {
    #[default]
    File,
    Keyring,
    Auto,
}

fn default_backend() -> &'static str {
    #[cfg(target_os = "macos")]
    {
        "userspace"
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        "kernel"
    }
    #[cfg(not(unix))]
    {
        "wg-quick"
    }
}

fn default_credential_store() -> CredentialStore {
    CredentialStore::File
}

#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegedAutostopMode {
    #[default]
    Never,
    Command,
    Timeout,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegedTransport {
    #[default]
    Socket,
    Stdio,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct WgconfConfig {
    pub hooks: HookConfig,
}

pub fn load_config() -> AppConfig {
    let path = app_config_dir().join("config.toml");
    match fs::read_to_string(&path) {
        Ok(text) => match toml::from_str(&text) {
            Ok(cfg) => cfg,
            Err(e) => {
                eprintln!(
                    "warning: failed to parse {}: {}\n\
                     Using default configuration. Fix the file or remove it to silence this warning.",
                    path.display(),
                    e
                );
                AppConfig::default()
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => AppConfig::default(),
        Err(e) => {
            eprintln!(
                "warning: unable to read {}: {}\nUsing default configuration.",
                path.display(),
                e
            );
            AppConfig::default()
        }
    }
}

// ── Provider enum ──────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Provider {
    #[value(name = "wgconf")]
    Wgconf,
}

impl Provider {
    #[must_use]
    pub fn dir_name(self) -> &'static str {
        match self {
            Provider::Wgconf => "wgconf",
        }
    }

    /// Alias for `dir_name` – kept for call-site readability.
    #[must_use]
    pub fn label(self) -> &'static str {
        self.dir_name()
    }

    /// Parse a provider directory name (e.g. `"wgconf"`) into its enum variant.
    #[must_use]
    pub fn from_dir_name(name: &str) -> Option<Self> {
        match name {
            "wgconf" => Some(Provider::Wgconf),
            _ => None,
        }
    }
}

// ── Path helpers ───────────────────────────────────────────────

/// Root config directory: ~/.config/tunmux/
#[must_use]
pub fn app_config_dir() -> PathBuf {
    xdg_config_home().join(APP_DIR)
}

#[must_use]
pub fn privileged_socket_path() -> PathBuf {
    privileged_socket_dir().join("ctl.sock")
}

#[must_use]
pub fn privileged_socket_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    return PathBuf::from("/Library/Application Support/tunmux/run");
    #[cfg(not(target_os = "macos"))]
    return PathBuf::from("/var/run/tunmux");
}

pub fn ensure_privileged_socket_dir() -> Result<()> {
    let dir = privileged_socket_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o750))?;
    }
    Ok(())
}

#[must_use]
pub fn privileged_runtime_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    return PathBuf::from("/Library/Application Support/tunmux");
    #[cfg(not(target_os = "macos"))]
    return PathBuf::from("/var/lib/tunmux");
}

/// Root-owned log directory for privileged services (gotatun helper on Linux, the
/// privileged proxy daemon): `/var/log/tunmux`.
#[must_use]
pub fn root_log_dir() -> PathBuf {
    PathBuf::from("/var/log/tunmux")
}

pub fn ensure_root_log_dir() -> Result<()> {
    let dir = root_log_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        // World-readable so the user can tail the root service's logs.
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755))?;
    }
    Ok(())
}

/// macOS user-visible log directory: `~/Library/Logs` (what Console.app shows).
/// Used for user-owned logs (the local proxy); root-owned logs go to
/// [`root_log_dir`] instead. Callers run as the user, so `HOME` is already theirs.
/// Log file the gotatun userspace helper writes and the privileged service tails.
/// Single source of truth shared by the helper (writer) and the service
/// (clear-at-connect + tail), which must agree on the path.
///
/// The helper runs as root (the privileged daemon spawns it), so its log is a
/// root service and lives under `/var/log/tunmux/<interface>.log` on all platforms.
#[must_use]
pub fn gotatun_helper_log_path(interface: &str) -> PathBuf {
    root_log_dir().join(format!("{interface}.log"))
}

pub fn ensure_privileged_runtime_dir() -> Result<()> {
    let dir = privileged_runtime_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

#[must_use]
pub fn privileged_wg_dir() -> PathBuf {
    privileged_runtime_dir().join("wg")
}

#[must_use]
pub fn privileged_proxy_dir() -> PathBuf {
    privileged_runtime_dir().join("proxy")
}

pub fn ensure_privileged_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        fs::create_dir_all(path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Provider-specific config directory: ~/.config/tunmux/<provider>/
#[must_use]
pub fn config_dir(provider: Provider) -> PathBuf {
    app_config_dir().join(provider.dir_name())
}

/// Connections directory: ~/.config/tunmux/connections/
#[must_use]
pub fn connections_dir() -> PathBuf {
    app_config_dir().join("connections")
}

/// User-owned proxy runtime directory: ~/.config/tunmux/proxy/
#[must_use]
pub fn user_proxy_dir() -> PathBuf {
    app_config_dir().join("proxy")
}

pub fn ensure_connections_dir() -> Result<()> {
    let dir = connections_dir();
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn xdg_config_home() -> PathBuf {
    if let Some(config) = std::env::var_os("XDG_CONFIG_HOME") {
        PathBuf::from(config)
    } else if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".config")
    } else {
        PathBuf::from("/tmp")
    }
}
