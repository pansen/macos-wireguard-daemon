#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::unix::net::UnixDatagram;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::time::Duration;

#[cfg(unix)]
use anyhow::Context;
#[cfg(unix)]
use daemonize::Daemonize;
#[cfg(unix)]
use gotatun::device::uapi::UapiServer;
#[cfg(unix)]
use gotatun::device::{DefaultDeviceTransports, Device, DeviceBuilder, Peer};
#[cfg(unix)]
use gotatun::tun::tun_async_device::TunDevice;
#[cfg(unix)]
use gotatun::x25519::{PublicKey, StaticSecret};
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};
#[cfg(unix)]
use tracing::{debug, info, warn};

mod config;
mod exec;
#[cfg(target_os = "macos")]
mod macos;

use self::config::parse_config_from_env;
use self::config::ParsedUserspaceConfig;
use self::exec::write_runtime_file;
use self::exec::write_runtime_file_atomic;
#[cfg(target_os = "macos")]
use macos::cleanup_network_macos;
#[cfg(target_os = "macos")]
use macos::configure_network_macos;
#[cfg(target_os = "macos")]
use macos::dns::macos_reconcile_dns;
#[cfg(target_os = "macos")]
use macos::log_macos_transfer_sample;
#[cfg(target_os = "macos")]
use macos::overview::log_macos_network_diagnostics;
#[cfg(target_os = "macos")]
use macos::overview::log_macos_network_overview;
#[cfg(target_os = "macos")]
use macos::overview::spawn_overview_query_server;
#[cfg(target_os = "macos")]
use macos::routes::macos_reconcile_routes;
#[cfg(target_os = "macos")]
use macos::run_macos_maintenance;
#[cfg(target_os = "macos")]
use macos::MacosCleanupState;

#[cfg(unix)]
const READY_OK: &[u8] = &[1];

#[cfg(unix)]
const READY_ERR: &[u8] = &[0];

#[cfg(unix)]
const SOCK_DIR: &str = "/var/run/wireguard";

#[cfg(unix)]
const HELPER_ENV: &str = "WGD_GOTATUN_HELPER";

#[cfg(unix)]
const CONFIG_B64_ENV: &str = "WGD_GOTATUN_CONFIG_B64";

#[cfg(unix)]
const CONNECTION_ID_ENV: &str = "WGD_CONNECTION_ID";

#[cfg(unix)]
const MTU_OVERRIDE_ENV: &str = "WGD_GOTATUN_MTU_OVERRIDE";

/// How often the macOS shutdown loop reconciles routes against the current LAN.
/// Reconciling re-snapshots the network fingerprint (running `ifconfig`), which is
/// too heavy to do on every 1s tick, so it runs on this slower cadence instead.
#[cfg(target_os = "macos")]
const MACOS_RECONCILE_INTERVAL: Duration = Duration::from_secs(3);

#[cfg(unix)]
fn gotatun_pid_path(interface: &str) -> PathBuf {
    PathBuf::from(SOCK_DIR).join(format!("{interface}.wgd.pid"))
}

#[cfg(unix)]
fn gotatun_name_path(interface: &str) -> PathBuf {
    PathBuf::from(SOCK_DIR).join(format!("{interface}.wgd.name"))
}

#[cfg(unix)]
fn gotatun_cleanup_status_path(interface: &str) -> PathBuf {
    PathBuf::from(SOCK_DIR).join(format!("{interface}.wgd.cleanup"))
}

/// Unix socket the helper listens on to serve the live network overview. The
/// privileged service (also root) connects here on behalf of `wgd status`;
/// the state it renders lives only in this process's memory, so a query channel
/// is the only way to expose it. Lives under the same `0750 root:daemon`
/// runtime dir as the UAPI socket, so unprivileged callers can't reach it.
#[cfg(target_os = "macos")]
fn gotatun_query_socket_path(interface: &str) -> PathBuf {
    PathBuf::from(SOCK_DIR).join(format!("{interface}.wgd.query.sock"))
}

#[cfg(unix)]
fn gotatun_log_path(interface: &str) -> PathBuf {
    // Shared with the privileged service (which clears and tails this file), so
    // both derive it from the same place: /var/log/wgd/<iface>.log on all
    // platforms (see config::gotatun_helper_log_path).
    crate::config::gotatun_helper_log_path(interface)
}

#[cfg(unix)]
struct RunningDevice {
    #[allow(dead_code)]
    interface_name: String,
    control_interface_name: String,
    control_socket_path: PathBuf,
    device: Device<DefaultDeviceTransports>,
    cleanup: CleanupState,
}

#[cfg(unix)]
enum CleanupState {
    None,
    #[cfg(target_os = "macos")]
    // `Arc` (not `Box`) so the overview query server thread can share the live
    // routing/DNS state with the reconciler without copying it.
    Macos(std::sync::Arc<MacosCleanupState>),
}

#[cfg(unix)]
pub fn maybe_run_from_env() -> bool {
    if std::env::var_os(HELPER_ENV).is_none() {
        return false;
    }

    // Logging is initialized to a per-interface file inside the daemonized child (see
    // daemonize_and_run); not here, because the helper detaches from its parent's stdio.

    let mut args = std::env::args();
    let _program = args.next();
    let interface = match args.next() {
        Some(value) => value,
        None => {
            eprintln!("wgd gotatun helper: missing interface argument");
            std::process::exit(2);
        }
    };
    if args.next().is_some() {
        eprintln!("wgd gotatun helper: unexpected extra arguments");
        std::process::exit(2);
    }

    if let Err(e) = daemonize_and_run(&interface) {
        eprintln!("wgd gotatun helper failed: {e}");
        std::process::exit(1);
    }
    true
}

#[cfg(unix)]
fn daemonize_and_run(interface: &str) -> anyhow::Result<()> {
    let (child_tx, parent_rx) = UnixDatagram::pair().context("failed to create status socket")?;
    let stdout = File::options()
        .write(true)
        .open("/dev/stdout")
        .context("failed to open /dev/stdout for helper logging")?;
    let stderr = File::options()
        .write(true)
        .open("/dev/stderr")
        .context("failed to open /dev/stderr for helper logging")?;
    let daemonize = Daemonize::new()
        .working_directory("/tmp")
        .stdout(stdout)
        .stderr(stderr);

    match daemonize.execute() {
        daemonize::Outcome::Parent(Err(e)) => {
            anyhow::bail!("failed to daemonize userspace helper: {}", e);
        }
        daemonize::Outcome::Parent(Ok(_)) => {
            let mut status = [0u8; 1];
            parent_rx
                .recv(&mut status)
                .context("failed to receive startup status from helper child")?;
            if status == READY_OK {
                return Ok(());
            }
            anyhow::bail!("userspace helper child reported startup failure");
        }
        daemonize::Outcome::Child(result) => {
            let signal_parent = |ok: bool| -> io::Result<()> {
                child_tx.send(if ok { READY_OK } else { READY_ERR })?;
                Ok(())
            };

            if let Err(e) = result {
                let _ = signal_parent(false);
                anyhow::bail!("failed to initialize userspace helper child: {}", e);
            }

            // Log to a per-interface file rather than inherited stdio. This stops the helper's
            // output from leaking into whichever terminal the privileged service was started in,
            // and lets the service tail this file to stream setup/teardown logs back to the
            // caller. Synchronous writer so the service reads complete lines without a flush race.
            // Ensure the runtime dir exists first (it is otherwise created later by start_device).
            let _ = std::fs::create_dir_all(SOCK_DIR);
            crate::config::ensure_root_log_dir()?;
            let log_path = gotatun_log_path(interface);
            crate::logging::init_file_sync(&log_path.to_string_lossy(), false)?;

            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("failed to create tokio runtime for userspace helper")?;

            let running = match rt.block_on(start_device(interface)) {
                Ok(value) => value,
                Err(e) => {
                    let _ = signal_parent(false);
                    return Err(e);
                }
            };

            let pid_path = gotatun_pid_path(interface);
            if let Err(error) = write_runtime_file(&pid_path, &std::process::id().to_string()) {
                cleanup_network(&running).ok();
                rt.block_on(async {
                    running.device.stop().await;
                });
                let _ = std::fs::remove_file(&running.control_socket_path);
                let _ = std::fs::remove_file(gotatun_name_path(interface));
                let _ = signal_parent(false);
                return Err(error.context("failed to write userspace helper pid file"));
            }

            if let Err(error) = signal_parent(true) {
                cleanup_network(&running).ok();
                rt.block_on(async {
                    running.device.stop().await;
                });
                let _ = std::fs::remove_file(&running.control_socket_path);
                let _ = std::fs::remove_file(&pid_path);
                let _ = std::fs::remove_file(gotatun_name_path(interface));
                return Err(error).context("failed to notify parent about helper startup");
            }
            debug!(
                interface = running.control_interface_name,
                actual_interface = running.interface_name,
                pid = std::process::id(),
                "userspace_helper_ready"
            );

            // Expose the live network overview for `wgd status`. Best-effort:
            // a bind failure only costs the status view, not the tunnel.
            #[cfg(target_os = "macos")]
            if let CleanupState::Macos(state) = &running.cleanup {
                spawn_overview_query_server(
                    &running.control_interface_name,
                    std::sync::Arc::clone(state),
                );
            }

            let shutdown_started = std::time::Instant::now();
            let wait_result = rt.block_on(wait_for_shutdown(&running));
            info!(
                interface = running.control_interface_name,
                elapsed_ms = shutdown_started.elapsed().as_millis(),
                result = ?wait_result.as_ref().map(|_| ()).map_err(|error| error.to_string()),
                "userspace_helper_shutdown_triggered"
            );

            let cleanup_started = std::time::Instant::now();
            let cleanup_result = cleanup_network(&running);
            info!(
                interface = running.control_interface_name,
                elapsed_ms = cleanup_started.elapsed().as_millis(),
                result = ?cleanup_result.as_ref().map(|_| ()).map_err(|error| error.to_string()),
                "userspace_helper_network_cleanup_complete"
            );

            let control_socket_path = running.control_socket_path.clone();
            let stop_started = std::time::Instant::now();
            let stop_result = rt.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), running.device.stop())
                    .await
                    .map_err(|_| anyhow::anyhow!("gotatun device stop timed out after 5 seconds"))
            });
            debug!(
                interface,
                elapsed_ms = stop_started.elapsed().as_millis(),
                result = ?stop_result.as_ref().map(|_| ()).map_err(|error| error.to_string()),
                "userspace_helper_device_stop_complete"
            );

            let mut errors = Vec::new();
            if let Err(error) = wait_result {
                errors.push(format!("shutdown wait failed: {error}"));
            }
            if let Err(error) = cleanup_result {
                errors.push(format!("network cleanup failed: {error}"));
            }
            if let Err(error) = stop_result {
                // Exiting the helper closes the tunnel fd even if gotatun's graceful
                // stop future stalls. The privileged caller verifies utun removal.
                warn!(
                    interface,
                    error = %error,
                    "userspace_helper_device_stop_forced_by_process_exit"
                );
            }
            let final_result = finish_cleanup(errors);

            let status = match &final_result {
                Ok(()) => "ok\n".to_string(),
                Err(error) => format!("error: {error}\n"),
            };
            write_runtime_file_atomic(&gotatun_cleanup_status_path(interface), &status)?;
            let _ = std::fs::remove_file(&control_socket_path);
            let _ = std::fs::remove_file(&pid_path);
            let _ = std::fs::remove_file(gotatun_name_path(interface));
            // The query server thread dies with the process; drop its socket file
            // so a later tunnel on the same interface binds cleanly.
            #[cfg(target_os = "macos")]
            let _ = std::fs::remove_file(gotatun_query_socket_path(interface));

            final_result?;
        }
    }

    Ok(())
}

#[cfg(unix)]
async fn start_device(interface: &str) -> anyhow::Result<RunningDevice> {
    let parsed_config = parse_config_from_env()?;
    let tun_name = helper_tun_name(interface);
    let tun = TunDevice::from_name(&tun_name)
        .map_err(|e| anyhow::anyhow!("failed to create TUN device {}: {}", interface, e))?;
    let interface_name = tun
        .name()
        .map_err(|e| anyhow::anyhow!("failed to resolve TUN interface name: {}", e))?;

    #[cfg(target_os = "macos")]
    if let Some(name_file) = std::env::var_os("WG_TUN_NAME_FILE") {
        tokio::fs::write(&name_file, &interface_name)
            .await
            .with_context(|| {
                format!(
                    "failed writing WG_TUN_NAME_FILE at {}",
                    PathBuf::from(name_file).display()
                )
            })?;
    }

    let uapi = UapiServer::default_unix_socket(interface, None, None)
        .map_err(|e| anyhow::anyhow!("failed to create UAPI socket for {}: {}", interface, e))?;

    let device = DeviceBuilder::new()
        .with_uapi(uapi)
        .with_default_udp()
        .with_ip(tun)
        .build()
        .await
        .map_err(|e| anyhow::anyhow!("failed to start gotatun device {}: {}", interface_name, e))?;

    if let Some(config) = parsed_config.as_ref() {
        if let Err(e) = apply_wireguard_config(&device, config).await {
            device.stop().await;
            let _ = std::fs::remove_file(PathBuf::from(SOCK_DIR).join(format!("{interface}.sock")));
            return Err(e);
        }
    }

    let cleanup = if let Some(config) = parsed_config.as_ref() {
        match configure_network(&interface_name, config, custody_identity(interface)) {
            Ok(cleanup) => cleanup,
            Err(e) => {
                device.stop().await;
                let _ =
                    std::fs::remove_file(PathBuf::from(SOCK_DIR).join(format!("{interface}.sock")));
                return Err(e);
            }
        }
    } else {
        CleanupState::None
    };

    let control_socket_path = PathBuf::from(SOCK_DIR).join(format!("{}.sock", interface));
    write_runtime_file(&gotatun_name_path(interface), &interface_name)
        .context("failed to write userspace helper interface name")?;
    Ok(RunningDevice {
        interface_name,
        control_interface_name: interface.to_string(),
        control_socket_path,
        device,
        cleanup,
    })
}

#[cfg(unix)]
async fn wait_for_shutdown(running: &RunningDevice) -> anyhow::Result<()> {
    let mut sigint = signal(SignalKind::interrupt()).context("failed to set SIGINT handler")?;
    let mut sigterm = signal(SignalKind::terminate()).context("failed to set SIGTERM handler")?;
    let mut ticker = tokio::time::interval(Duration::from_secs(1));
    #[cfg(target_os = "macos")]
    let mut next_transfer_sample_at = std::time::Instant::now();
    #[cfg(target_os = "macos")]
    let mut next_reconcile_at = std::time::Instant::now();
    #[cfg(target_os = "macos")]
    let mut last_transfer: Option<(u64, u64)> = None;

    loop {
        tokio::select! {
            _ = sigint.recv() => {
                info!(interface = running.control_interface_name, trigger = "sigint", "userspace_helper_shutdown_requested");
                break;
            },
            _ = sigterm.recv() => {
                info!(interface = running.control_interface_name, trigger = "sigterm", "userspace_helper_shutdown_requested");
                break;
            },
            _ = ticker.tick() => {
                if !running.control_socket_path.exists() {
                    info!(interface = running.control_interface_name, trigger = "control_socket_removed", "userspace_helper_shutdown_requested");
                    break;
                }

                #[cfg(target_os = "macos")]
                {
                    // Adapt routing to network changes (roam, suspend/resume,
                    // link up/down) live, without requiring a reconnect. Throttled
                    // off the 1s tick. System commands must run off-runtime:
                    // this current-thread runtime also drives WireGuard packets.
                    if std::time::Instant::now() >= next_reconcile_at {
                        next_reconcile_at = std::time::Instant::now() + MACOS_RECONCILE_INTERVAL;
                        if let CleanupState::Macos(state) = &running.cleanup {
                            let state = std::sync::Arc::clone(state);
                            run_macos_maintenance("reconcile", move || {
                                let routes_changed = macos_reconcile_routes(&state);
                                let dns_changed = macos_reconcile_dns(&state);
                                if routes_changed || dns_changed {
                                    log_macos_network_diagnostics("after_reconcile", &state.reconcile);
                                    log_macos_network_overview("reconcile", &state);
                                }
                            })
                            .await?;
                        }
                    }

                    if std::time::Instant::now() >= next_transfer_sample_at {
                        next_transfer_sample_at = std::time::Instant::now() + Duration::from_secs(5);
                        log_macos_transfer_sample(
                            &running.control_interface_name,
                            &mut last_transfer,
                        )
                        .await?;
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(unix)]
async fn apply_wireguard_config(
    device: &Device<DefaultDeviceTransports>,
    config: &ParsedUserspaceConfig,
) -> anyhow::Result<()> {
    let private_key = StaticSecret::from(config.private_key);
    let mut peer =
        Peer::new(PublicKey::from(config.peer_public_key)).with_endpoint(config.endpoint);
    peer.preshared_key = config.peer_preshared_key;

    for allowed in &config.allowed_ips {
        let network = allowed
            .parse()
            .with_context(|| format!("invalid AllowedIPs entry {}", allowed))?;
        peer.allowed_ips.push(network);
    }

    device
        .write(async move |device| {
            device.clear_peers();
            device.set_private_key(private_key).await;
            device.add_peer(peer);
        })
        .await
        .map_err(|e| anyhow::anyhow!("failed to configure gotatun device: {}", e))?;
    Ok(())
}

#[cfg(unix)]
fn helper_tun_name(interface: &str) -> String {
    if interface == "utun" || interface.starts_with("utun") {
        return interface.to_string();
    }
    "utun".to_string()
}

/// Identity for the DNS custody record: the connection id the daemon passed
/// in, this process's pid and its start time. `None` (with a WARN) when any
/// part is missing, which only disables crash recovery for this session.
#[cfg(unix)]
fn custody_identity(interface: &str) -> Option<crate::dns_custody::DnsCustodyIdentity> {
    let raw = std::env::var(CONNECTION_ID_ENV).ok()?;
    let connection_id = match raw.parse::<crate::privileged_api::ConnectionId>() {
        Ok(id) => id,
        Err(error) => {
            warn!(error = %error, "userspace_helper_dns_custody_unavailable");
            return None;
        }
    };
    let helper_pid = std::process::id();
    let Some(helper_start) = crate::privileged::managed_pids::process_start_ticks(helper_pid)
    else {
        warn!(
            error = "own start time unreadable",
            "userspace_helper_dns_custody_unavailable"
        );
        return None;
    };
    Some(crate::dns_custody::DnsCustodyIdentity {
        connection_id,
        interface: interface.to_string(),
        helper_pid,
        helper_start,
    })
}

#[cfg(unix)]
fn configure_network(
    interface: &str,
    config: &ParsedUserspaceConfig,
    custody: Option<crate::dns_custody::DnsCustodyIdentity>,
) -> anyhow::Result<CleanupState> {
    let cleanup = configure_network_macos(interface, config, custody)?;
    Ok(CleanupState::Macos(std::sync::Arc::new(cleanup)))
}

#[cfg(unix)]
fn cleanup_network(running: &RunningDevice) -> anyhow::Result<()> {
    match &running.cleanup {
        CleanupState::None => Ok(()),
        #[cfg(target_os = "macos")]
        CleanupState::Macos(state) => cleanup_network_macos(state),
    }
}

#[cfg(unix)]
fn finish_cleanup(errors: Vec<String>) -> anyhow::Result<()> {
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(errors.join("; "))
    }
}
