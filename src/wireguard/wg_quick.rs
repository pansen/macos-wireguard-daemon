use crate::config;
use crate::error::Result;
use crate::privileged_api::WgQuickAction;
use crate::privileged_client::PrivilegedClient;
use tracing::info;

use super::handshake;

/// Write the WireGuard config and bring up the interface.
/// Returns the effective interface name used (may differ from the requested name on macOS,
/// where TUN interfaces must be named `utunN` and the number is assigned by the kernel).
pub fn up(
    config_content: &str,
    interface_name: &str,
    provider: config::Provider,
    prefer_userspace: bool,
) -> Result<String> {
    let effective = platform_interface_name(interface_name);
    let client = PrivilegedClient::new();
    info!(
        "Requesting privileged wg-quick up for {} ({}) [userspace={}]",
        effective,
        provider.dir_name(),
        prefer_userspace
    );
    client.wg_quick_run(
        WgQuickAction::Up,
        &effective,
        provider.dir_name(),
        config_content,
        prefer_userspace,
    )?;
    let dns_servers = handshake::dns_servers_from_config(config_content);
    handshake::wait_for_handshake(&effective, &dns_servers)?;
    Ok(effective)
}

/// On macOS, TUN interfaces must be named `utunN`; the kernel assigns the number automatically.
/// Any requested name that is not already a `utun*` name is mapped to `"utun"` so that
/// wg-quick (or the WireGuard network extension) picks the next available slot.
fn platform_interface_name(name: &str) -> String {
    if name == "utun" || name.starts_with("utun") {
        return name.to_string();
    }
    "utun".to_string()
}

/// Bring down the WireGuard interface and remove the config.
pub fn down(interface_name: &str, provider: config::Provider) -> Result<()> {
    let client = PrivilegedClient::new();
    info!(
        "Requesting privileged wg-quick down for {} ({})",
        interface_name,
        provider.dir_name()
    );
    client.wg_quick_run(
        WgQuickAction::Down,
        interface_name,
        provider.dir_name(),
        "",
        false,
    )
}

/// Finding 5 — Incorrect tunnel adoption and connection races: probe the
/// requested interface through root, not whether any unrelated VPN is active.
#[must_use]
pub fn is_interface_active(interface_name: &str) -> bool {
    super::userspace::is_interface_active(interface_name)
}

fn _provider_name(provider: config::Provider) -> &'static str {
    provider.dir_name()
}

// Keep legacy path helpers untouched for compatibility with current call sites
// and tests if needed.
#[must_use]
pub fn _config_file_path(interface_name: &str, provider: config::Provider) -> std::path::PathBuf {
    config::config_dir(provider).join(format!("{}.conf", interface_name))
}
