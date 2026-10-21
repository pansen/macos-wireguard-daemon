//! Shared `connect`/`disconnect` implementation for one stored connection,
//! called from the RPC dispatch arms (Phase 2) and, in a later phase, from
//! daemon-boot and per-user-session reconciliation. One code path, several
//! callers, so the anti-adoption/anti-drift checks live in exactly one place.
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use tracing::{debug, warn};

use crate::error::{AppError, Result};
use crate::privileged_api::ConnectionId;
use crate::wireguard::connection_config::{self, ConnectionConfig};

use super::connection_store::{self, ActiveConnectionState, ConnectionLock, StoredConnection};

const SOCK_DIR: &str = "/var/run/wireguard";

fn socket_path(interface: &str) -> PathBuf {
    Path::new(SOCK_DIR).join(format!("{interface}.sock"))
}

/// Finding 5: the gotatun helper's setup/teardown mutates machine-global
/// state (default route pinning, DNS via `networksetup` on whichever service
/// currently owns resolution), not anything scoped to one interface, so two
/// bring-ups/teardowns running at once across different connections can still
/// corrupt each other's captured "previous state" or clobber each other's
/// route/DNS changes. Per-connection locks alone do not prevent that; this
/// does. Taken here, on the worker thread `dispatch.rs` spawns for
/// `Connect`/`Disconnect` (and on the boot/session reconciliation threads
/// that call into this same `connect`/`disconnect`), not on the accept
/// thread, so the daemon keeps serving other clients while this waits.
pub(super) fn lock_system_network_mutation() -> Result<std::fs::File> {
    const TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
    crate::state_file::lock_with_timeout(
        &crate::config::privileged_runtime_dir().join("tunnel-operation.lock"),
        TIMEOUT,
    )
    .map_err(Into::into)
}

/// Confirm the helper behind a lingering socket is dead and remove what it left
/// behind: DNS (via its custody record, if any) and its runtime files. Takes the
/// system network mutation lock so no helper can be mid-start meanwhile.
fn clear_dead_helper_leftovers(id: ConnectionId, interface: &str) -> Result<()> {
    let _network_lock = lock_system_network_mutation()?;
    // With a record: restores DNS and, for a dead helper, removes its files.
    if let Err(error) =
        super::dns_sweep::sweep_locked(super::dns_sweep::Scope::Interface(interface))
    {
        warn!(id = %id, error = %error, "connection_connect_dns_sweep_failed");
    }
    // Without a record (no DNS, or started before records existed) only the pid
    // file can vouch for the helper. A record that is still on disk belongs to
    // a live or already handled helper; leave that to the sweep above.
    let has_record = crate::dns_custody::record_path(interface)
        .map(|path| path.exists())
        .unwrap_or(false);
    if !has_record {
        super::runtime_files::remove_if_dead_locked(interface, || {
            connection_store::helper_is_live_without_record(interface)
        });
    }
    Ok(())
}

fn conflict() -> AppError {
    AppError::WireGuard(
        "this connection's interface is already in an unverified state; disconnect it before reconnecting".into(),
    )
}

fn stale_error() -> AppError {
    AppError::WireGuard(
        "stored connection is stale (its raw configuration no longer matches its recorded identity); remove and re-add it".into(),
    )
}

/// Re-parse `stored.raw_conf` and confirm it still fingerprints to
/// `stored.fingerprint`. Guards against a parser version change (or on-disk
/// tampering) making the daemon's stored identity and the text it would
/// actually execute silently diverge: the helper re-parses `raw_conf` itself
/// (see `userspace_helper::parse_wg_quick_config`), so if that reparse would
/// now disagree with what this record was fingerprinted as, refuse rather
/// than run with drifted semantics.
fn reparse_and_verify(stored: &StoredConnection) -> Result<ConnectionConfig> {
    let reparsed = connection_config::parse_connection_config(&stored.raw_conf)?;
    if connection_config::fingerprint(&reparsed) != stored.fingerprint {
        return Err(stale_error());
    }
    Ok(reparsed)
}

/// Bring up one stored connection. Must be called while holding that
/// connection's [`ConnectionLock`] (see `connection_store::lock_connection`).
pub(super) fn connect(
    conn_lock: &ConnectionLock,
    id: ConnectionId,
    debug_enabled: bool,
) -> Result<()> {
    let stored = connection_store::load(id)?
        .ok_or_else(|| AppError::Other("connection not found".into()))?;
    let reparsed = reparse_and_verify(&stored)?;

    // gotatun drives exactly one peer today; a config with more must be
    // rejected explicitly here rather than silently degraded (see
    // `connection_config`'s multi-peer parsing fix).
    if reparsed.peers.len() != 1 {
        return Err(AppError::WireGuard(format!(
            "connect requires exactly one [Peer] section, found {}",
            reparsed.peers.len()
        )));
    }

    let socket = socket_path(&stored.interface);

    // A helper that died without teardown (SIGKILL, panic) leaves its socket
    // behind, which would otherwise fail this connect with `conflict()` below
    // or make the idempotency check treat a dead tunnel as up. Remove the
    // leftovers once the helper is confirmed dead; a socket that still accepts
    // connections is untouched and keeps yielding `conflict()`.
    if socket.try_exists()? {
        clear_dead_helper_leftovers(id, &stored.interface)?;
    }

    // Anti-adoption/idempotency check, ported from `tunnel_state::connect`
    // (Finding 5): identity is now the stored fingerprint rather than a raw
    // config-content string, but the actual race guard is unchanged -- it is
    // always the real UAPI socket's device/inode/ctime, never the interface
    // name or a caller-supplied value.
    if let Some(active) = connection_store::load_active(id)? {
        let metadata = match fs::metadata(&active.socket) {
            Ok(metadata) => Some(metadata),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        if let Some(metadata) = metadata {
            if metadata.dev() != active.device
                || metadata.ino() != active.inode
                || metadata.ctime() != active.changed_sec
                || metadata.ctime_nsec() != active.changed_nsec
            {
                return Err(conflict());
            }
            return if active.fingerprint == stored.fingerprint {
                Ok(())
            } else {
                Err(conflict())
            };
        }
        // The recorded socket is gone: stale marker, fall through to start fresh.
    }
    if socket.try_exists()? {
        return Err(conflict());
    }

    run_hooks(&reparsed.pre_up, &stored.interface, "PreUp")?;
    {
        let _network_lock = lock_system_network_mutation()?;
        // The directory is created at daemon start; re-ensure it here in case
        // someone removed it while the daemon was running, because the helper
        // never creates it (see `userspace_helper::persist_dns_custody`).
        crate::config::ensure_dns_custody_dir()?;
        // A crashed predecessor on this interface may have left DNS behind.
        // The daemon's startup sweep normally resolved that already; doing it
        // here too means the helper below can never capture a stray as the
        // user's original. Best-effort: a failing sweep must not block connect.
        if let Err(error) =
            super::dns_sweep::sweep_locked(super::dns_sweep::Scope::Interface(&stored.interface))
        {
            warn!(id = %id, error = %error, "connection_connect_dns_sweep_failed");
        }
        // From here a crash can leave DNS behind. launchd keeps the daemon
        // alive while this sentinel exists, so someone is always around to
        // notice (see `dns_watch`).
        if !reparsed.dns_servers.is_empty() {
            super::dns_watch::create_sentinel_locked();
        }
        // PreUp already ran; nothing to roll back here if this fails, since
        // the tunnel itself never came up.
        let up = super::commands::run_gotatun_up(
            id,
            &stored.interface,
            &stored.raw_conf,
            None,
            debug_enabled,
        );
        // Success or not: watch the helper's record if it wrote one, and drop
        // the sentinel again if nothing needs it.
        super::dns_watch::settle_locked();
        up?;
    }
    if let Err(error) = run_hooks(&reparsed.post_up, &stored.interface, "PostUp") {
        // Mirror `configure_network_macos`'s rollback-on-setup-failure
        // pattern: a failed PostUp must not leave a half-configured tunnel
        // the caller believes never started.
        let rollback = (|| -> Result<()> {
            let _network_lock = lock_system_network_mutation()?;
            super::commands::run_gotatun_down(&stored.interface)
        })();
        if let Err(rollback_error) = rollback {
            return Err(AppError::WireGuard(format!(
                "PostUp failed: {error}; rollback also failed: {rollback_error}"
            )));
        }
        return Err(error);
    }

    let metadata = fs::metadata(&socket)?;
    connection_store::save_active(
        conn_lock,
        id,
        &ActiveConnectionState {
            fingerprint: stored.fingerprint.clone(),
            interface: stored.interface.clone(),
            socket: socket.clone(),
            device: metadata.dev(),
            inode: metadata.ino(),
            changed_sec: metadata.ctime(),
            changed_nsec: metadata.ctime_nsec(),
            connected_at: connection_store::now_unix(),
        },
    )?;
    debug!(id = %id, interface = %stored.interface, "connection_connected");
    Ok(())
}

/// Tear down one stored connection. Must be called while holding that
/// connection's [`ConnectionLock`].
pub(super) fn disconnect(conn_lock: &ConnectionLock, id: ConnectionId) -> Result<()> {
    let stored = connection_store::load(id)?
        .ok_or_else(|| AppError::Other("connection not found".into()))?;

    // Hooks are best-effort on the way down: refusing to tear down a tunnel
    // the caller wants gone, just because a hook script is broken, would
    // strand them with an active connection they explicitly asked to remove.
    match connection_config::parse_connection_config(&stored.raw_conf) {
        Ok(reparsed) => {
            run_hooks_best_effort(&reparsed.pre_down, &stored.interface, "PreDown");
            {
                let _network_lock = lock_system_network_mutation()?;
                super::commands::run_gotatun_down(&stored.interface)?;
            }
            run_hooks_best_effort(&reparsed.post_down, &stored.interface, "PostDown");
        }
        Err(error) => {
            warn!(id = %id, error = %error, "connection_disconnect_hooks_skipped_unparseable_raw_conf");
            let _network_lock = lock_system_network_mutation()?;
            super::commands::run_gotatun_down(&stored.interface)?;
        }
    }

    connection_store::clear_active(conn_lock, id)?;
    debug!(id = %id, interface = %stored.interface, "connection_disconnected");
    Ok(())
}

fn substitute_interface(cmd: &str, interface: &str) -> String {
    cmd.replace("%i", interface)
}

fn run_hooks(commands: &[String], interface: &str, label: &str) -> Result<()> {
    for cmd in commands {
        run_hook(cmd, interface, label)?;
    }
    Ok(())
}

fn run_hooks_best_effort(commands: &[String], interface: &str, label: &str) {
    for cmd in commands {
        if let Err(error) = run_hook(cmd, interface, label) {
            warn!(interface, %label, error = %error, "connection_hook_failed_best_effort");
        }
    }
}

/// Run one hook line as root via `sh -c`, with `%i` substituted for the
/// connection's actual interface name. Safe to allow uniformly for both
/// global and per-user connections: `AddConnection`'s admin-authentication
/// gate means hook content can never enter the store without an admin having
/// already approved it, regardless of scope (see the design plan's
/// authorization section).
fn run_hook(cmd: &str, interface: &str, label: &str) -> Result<()> {
    let substituted = substitute_interface(cmd, interface);
    debug!(interface, %label, cmd = %substituted, "connection_hook_run");
    let status = crate::trusted_exec::command("sh")?
        .arg("-c")
        .arg(&substituted)
        .status()
        .map_err(|e| AppError::Other(format!("{label} hook failed to start: {e}")))?;
    if !status.success() {
        return Err(AppError::WireGuard(format!(
            "{label} hook exited {status}: {substituted}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitute_interface_replaces_every_occurrence() {
        assert_eq!(
            substitute_interface("ip link set %i up; echo %i", "wg-aaaaaaaa"),
            "ip link set wg-aaaaaaaa up; echo wg-aaaaaaaa"
        );
    }

    #[test]
    fn substitute_interface_is_a_no_op_without_placeholder() {
        assert_eq!(substitute_interface("echo hi", "wg-aaaaaaaa"), "echo hi");
    }
}
