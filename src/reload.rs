//! `tunmux reload`: put both launchd services back into a known-good state
//! and bring stored connections back up. This is the recovery path after a
//! macOS update (which can leave the system daemon booted out or disabled)
//! or after anything else that left tunmux behaving oddly.
//!
//! The privileged daemon is re-registered by re-invoking this same binary
//! under `sudo`, because the system domain needs root while the session
//! agent lives in the user's GUI domain and must not be touched as root. Run
//! the command as your normal user; only that one step escalates.

use std::path::Path;
use std::process::Command;

use anyhow::Context;
use nix::unistd::geteuid;

use crate::cli::ReloadArgs;
use crate::config::AppConfig;
use crate::privileged_api::ConnectionScope;
use crate::privileged_client::PrivilegedClient;

pub async fn run(_args: ReloadArgs, _config: &AppConfig) -> anyhow::Result<()> {
    refuse_if_root()?;

    let exe =
        std::env::current_exe().context("failed to determine the running tunmux binary path")?;

    step("re-registering the privileged daemon (sudo)");
    install_privileged_daemon(&exe)?;

    // Tunnels from before the reload describe a daemon and helper processes
    // that no longer exist, so drop them before the agent reconnects.
    step("disconnecting this user's active connections");
    disconnect_all_mine()?;

    step("re-registering the session agent");
    crate::session_agent::reinstall()?;

    println!();
    println!("tunmux reload complete. Check with: tunmux status");
    Ok(())
}

/// Disconnect every one of the caller's currently-connected stored
/// connections. Best-effort per connection, matching `connection disconnect
/// --all`: one stuck connection must not abort the rest of the reload.
fn disconnect_all_mine() -> anyhow::Result<()> {
    let client = PrivilegedClient::new();
    let connected: Vec<_> = client
        .list_connections(ConnectionScope::Mine)?
        .into_iter()
        .filter(|conn| conn.connected)
        .collect();
    if connected.is_empty() {
        println!("Not connected.");
        return Ok(());
    }
    for conn in connected {
        if let Err(error) = client.disconnect_connection(conn.id) {
            eprintln!("Warning: failed to disconnect {}: {error:#}", conn.id);
            continue;
        }
        println!("Disconnected {}", conn.id);
    }
    Ok(())
}

/// Re-run `launchd install` (bootout, enable, bootstrap) as root. Install
/// rather than restart: an OS update can leave the label disabled or booted
/// out entirely, which `launchctl kickstart` cannot recover from, and the
/// install path is idempotent.
fn install_privileged_daemon(exe: &Path) -> anyhow::Result<()> {
    let mut command = Command::new("sudo");
    command.arg(exe).arg("launchd").arg("install");
    if crate::logging::debug_enabled() {
        command.arg("--debug");
    }

    // Inherited stdio: sudo needs the terminal to prompt for a password, and
    // the installer's own output belongs in this command's output.
    let status = command
        .status()
        .context("failed to run sudo for the privileged daemon install")?;
    anyhow::ensure!(
        status.success(),
        "sudo {} launchd install failed ({status})",
        exe.display()
    );
    Ok(())
}

fn step(what: &str) {
    println!("==> {what}");
}

/// Bail if running as root. Two of the three steps are per-user: under sudo
/// the disconnect would attribute to root's own connections and the agent
/// install would target root's GUI domain.
fn refuse_if_root() -> anyhow::Result<()> {
    if geteuid().is_root() {
        anyhow::bail!(
            "run `tunmux reload` as your normal user, not with sudo; it escalates the \
             privileged daemon step on its own"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuse_if_root_when_root() {
        if geteuid().is_root() {
            let err = refuse_if_root().expect_err("must refuse when root");
            assert!(err.to_string().contains("not with sudo"));
        } else {
            refuse_if_root().expect("must be a no-op when not root");
        }
    }
}
