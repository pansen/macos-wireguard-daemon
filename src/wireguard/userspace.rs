use crate::config;
use crate::error::Result;
use crate::privileged_api::GotaTunAction;
use crate::privileged_client::{is_retryable_transport_error, PrivilegedClient};
use tracing::info;

use super::handshake;

/// Bring up a WireGuard tunnel using the embedded gotatun userspace backend.
pub fn up_with_mtu(
    config_content: &str,
    interface_name: &str,
    provider: config::Provider,
    mtu_override: Option<u16>,
) -> Result<String> {
    let _ = provider;
    up_raw_with_mtu(config_content, interface_name, mtu_override)?;
    Ok(interface_name.to_string())
}

/// Bring up a userspace tunnel directly via gotatun helper.
pub fn up_raw(config_content: &str, interface_name: &str) -> Result<()> {
    up_raw_with_mtu(config_content, interface_name, None)
}

pub fn up_raw_with_mtu(
    config_content: &str,
    interface_name: &str,
    mtu_override: Option<u16>,
) -> Result<()> {
    let client = PrivilegedClient::new();
    info!(
        interface = ?interface_name,
        "Requesting privileged gotatun userspace up"
    );
    client.gotatun_run(
        GotaTunAction::Up,
        interface_name,
        config_content,
        mtu_override,
    )?;
    let dns_servers = handshake::dns_servers_from_config(config_content);
    handshake::wait_for_handshake(interface_name, &dns_servers)
}

/// Tear down a userspace WireGuard tunnel.
pub fn down(interface_name: &str, provider: config::Provider) -> Result<()> {
    let _ = provider;
    down_raw(interface_name)
}

/// Tear down a userspace tunnel directly via gotatun helper.
pub fn down_raw(interface_name: &str) -> Result<()> {
    let client = PrivilegedClient::new();
    info!(
        interface = ?interface_name,
        "Requesting privileged gotatun userspace down"
    );
    client.gotatun_run(GotaTunAction::Down, interface_name, "", None)
}

/// Check if a userspace interface appears active by control socket presence.
///
/// The UAPI control socket lives in `/var/run/wireguard`, which is
/// `0750 root:daemon` on macOS. An unprivileged caller cannot even stat inside
/// it, so a local `Path::exists()` is permission-blind: `stat` fails with
/// `EACCES` and `exists()` returns `false`, making a live tunnel look dead.
/// That false negative drove an autoconnect reconnect storm. Ask the privileged
/// service instead — it runs as root and can see the socket. On any transport
/// error we conservatively report "not active" (matching the old best-effort
/// semantics).
#[must_use]
pub fn is_interface_active(interface_name: &str) -> bool {
    let client = PrivilegedClient::new();
    // The privileged daemon is on-demand and idle-exits; the first probe after
    // an idle exit can race its cold start and return a *transport error*. A
    // bare `unwrap_or(false)` there reports a live tunnel as down, which then
    // wrongly clears saved connection state (see `direct_connection_active`)
    // and drives a needless disconnect / re-adopt churn every autoconnect
    // cycle. An authoritative `Ok(active)` from the daemon is returned
    // immediately (so a genuinely-down tunnel stays fast); only a transport
    // error is retried briefly so the probe settles on the true state.
    const ATTEMPTS: usize = 4;
    const BACKOFF: std::time::Duration = std::time::Duration::from_millis(200);
    for attempt in 0..ATTEMPTS {
        match client.interface_active(interface_name) {
            Ok(active) => return active,
            Err(err) if attempt + 1 < ATTEMPTS && is_retryable_transport_error(&err) => {
                tracing::debug!(
                    interface = interface_name,
                    error = %err,
                    "interface_active probe errored; retrying (daemon cold start?)"
                );
                std::thread::sleep(BACKOFF);
            }
            Err(err) => {
                // Either an authoritative (non-transport) error, or the last
                // attempt — report inactive without further retries.
                tracing::debug!(
                    interface = interface_name,
                    error = %err,
                    "interface_active probe failed; reporting inactive"
                );
                return false;
            }
        }
    }
    false
}
