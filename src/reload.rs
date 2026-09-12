//! `tunmux reload`: put both launchd services back into a known-good state
//! and bring the tunnel up again. This is the recovery path after a macOS
//! update (which can leave the system daemon booted out or disabled) or after
//! anything else that left tunmux behaving oddly.
//!
//! The privileged daemon is re-registered by re-invoking this same binary
//! under `sudo`, because the system domain needs root while the autoconnect
//! agent lives in the user's GUI domain and must not be touched as root. Run
//! the command as your normal user; only that one step escalates.

use std::path::Path;
use std::process::Command;

use anyhow::Context;
use nix::unistd::geteuid;

use crate::cli::{ReloadArgs, WgconfCommand};
use crate::config::AppConfig;

pub async fn run(args: ReloadArgs, config: &AppConfig) -> anyhow::Result<()> {
    refuse_if_root()?;

    let exe =
        std::env::current_exe().context("failed to determine the running tunmux binary path")?;

    step("re-registering the privileged daemon (sudo)");
    install_privileged_daemon(&exe)?;

    // Tunnels from before the reload describe a daemon and helper processes
    // that no longer exist, so drop them before the agent reconnects.
    step("disconnecting active wgconf tunnels");
    crate::wgconf::handlers::dispatch(
        WgconfCommand::Disconnect {
            instance: None,
            all: true,
        },
        config,
    )
    .await?;
    // The disconnect above only acts on what this process's own connection
    // state believes is connected. Also reset the privileged daemon's own
    // record directly, so a record left behind by a crashed or desynced
    // prior run can't silently survive this reload.
    if let Err(error) = crate::wgconf::handlers::force_reset_direct_interface() {
        eprintln!("Warning: could not confirm privileged tunnel state was reset: {error:#}");
    }

    step("re-registering the autoconnect agent");
    crate::autoconnect::reinstall(args.file, args.profile)?;

    println!();
    println!("tunmux reload complete. Check with: tunmux status");
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
/// the disconnect would write root-owned connection state and the agent
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
