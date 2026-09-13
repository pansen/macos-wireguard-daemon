use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use serde::Deserialize;

use crate::error::Result;

const APP_DIR: &str = "tunmux";

// ── TOML config ────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct AppConfig {
    pub general: GeneralConfig,
}

#[derive(Debug, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    pub credential_store: CredentialStore,
    pub privileged_transport: PrivilegedTransport,
    pub privileged_autostart: bool,
    pub privileged_autostart_timeout_ms: u64,
    pub privileged_authorized_group: String,
    pub privileged_autostop_mode: PrivilegedAutostopMode,
    pub privileged_autostop_timeout_ms: u64,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            credential_store: default_credential_store(),
            privileged_transport: PrivilegedTransport::Socket,
            privileged_autostart: true,
            privileged_autostart_timeout_ms: 5000,
            privileged_authorized_group: String::new(),
            privileged_autostop_mode: PrivilegedAutostopMode::Never,
            privileged_autostop_timeout_ms: 30000,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStore {
    #[default]
    File,
    Keyring,
    Auto,
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
    PathBuf::from("/Library/Application Support/tunmux/run")
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
    PathBuf::from("/Library/Application Support/tunmux")
}

/// Root-owned log directory for the privileged gotatun helper: `/var/log/tunmux`.
#[must_use]
pub fn root_log_dir() -> PathBuf {
    PathBuf::from("/var/log/tunmux")
}

pub fn ensure_root_log_dir() -> Result<()> {
    // Finding 2 — Protected log disclosure: the directory must not allow an
    // unprivileged process to replace the log or insert a symlink between reads.
    let dir = root_log_dir();
    fs::create_dir_all(&dir)?;
    crate::trusted_exec::validate_root_owned_path(
        &fs::canonicalize(&dir)?,
        crate::trusted_exec::TrustedPath::Directory,
    )?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Log file the gotatun userspace helper writes and the privileged service tails.
/// Single source of truth shared by the helper (writer) and the service
/// (clear-at-connect + tail), which must agree on the path.
///
/// The helper runs as root (the privileged daemon spawns it), so its log lives
/// under `/var/log/tunmux/<interface>.log`.
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
    // Finding 5 — Incorrect tunnel adoption and connection races: the
    // authoritative identity and mutation lock require a root-controlled parent.
    crate::trusted_exec::validate_root_owned_path(
        &dir,
        crate::trusted_exec::TrustedPath::Directory,
    )?;
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
