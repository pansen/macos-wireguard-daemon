#[cfg(unix)]
use base64::Engine;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::net::{IpAddr, SocketAddr};
#[cfg(target_os = "macos")]
use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::UnixDatagram;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Command, Output};
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
use tracing::{debug, info, trace, warn};

#[cfg(unix)]
const READY_OK: &[u8] = &[1];
#[cfg(unix)]
const READY_ERR: &[u8] = &[0];
#[cfg(unix)]
const SOCK_DIR: &str = "/var/run/wireguard";
#[cfg(unix)]
const HELPER_ENV: &str = "TUNMUX_GOTATUN_HELPER";
#[cfg(unix)]
const CONFIG_B64_ENV: &str = "TUNMUX_GOTATUN_CONFIG_B64";
#[cfg(unix)]
const MTU_OVERRIDE_ENV: &str = "TUNMUX_GOTATUN_MTU_OVERRIDE";

/// How often the macOS shutdown loop reconciles routes against the current LAN.
/// Reconciling re-snapshots the network fingerprint (running `ifconfig`), which is
/// too heavy to do on every 1s tick, so it runs on this slower cadence instead.
#[cfg(target_os = "macos")]
const MACOS_RECONCILE_INTERVAL: Duration = Duration::from_secs(3);

#[cfg(unix)]
fn gotatun_pid_path(interface: &str) -> PathBuf {
    PathBuf::from(SOCK_DIR).join(format!("{interface}.tunmux.pid"))
}

#[cfg(unix)]
fn gotatun_name_path(interface: &str) -> PathBuf {
    PathBuf::from(SOCK_DIR).join(format!("{interface}.tunmux.name"))
}

#[cfg(unix)]
fn gotatun_cleanup_status_path(interface: &str) -> PathBuf {
    PathBuf::from(SOCK_DIR).join(format!("{interface}.tunmux.cleanup"))
}

#[cfg(unix)]
fn gotatun_log_path(interface: &str) -> PathBuf {
    // Shared with the privileged service (which clears and tails this file), so
    // both derive it from the same place: /var/log/tunmux/<iface>.log on all
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
    Macos(Box<MacosCleanupState>),
}

#[cfg(target_os = "macos")]
struct MacosCleanupState {
    /// Live routing state. Mutated by the network-change reconciler while the
    /// tunnel is up and read by teardown, hence the interior mutability.
    routing: std::sync::Mutex<MacosRoutingState>,
    /// Live DNS state. Like `routing`, the reconciler keeps this in sync with
    /// the active LAN while the tunnel is up and teardown reads it to restore.
    dns: std::sync::Mutex<MacosDnsState>,
    /// Immutable inputs the reconciler replays on every network change.
    reconcile: MacosReconcileInputs,
}

/// Routing state the reconciler keeps in sync with the live network.
#[cfg(target_os = "macos")]
struct MacosRoutingState {
    /// Routes this tunnel currently owns; the source of truth for teardown.
    routes_added: Vec<MacosRoute>,
    /// Last observed network environment. A change drives reconciliation.
    fingerprint: MacosNetworkFingerprint,
}

/// DNS state the reconciler keeps in sync with the active LAN.
#[cfg(target_os = "macos")]
struct MacosDnsState {
    /// Services we currently own, each carrying the original config to restore
    /// at teardown. Mutated as the reconciler takes/releases ownership.
    services: Vec<MacosDnsServiceState>,
    /// Last observed DNS-relevant environment. A change drives reconciliation.
    fingerprint: MacosDnsFingerprint,
}

/// Inputs captured at connect that the reconciler needs to recompute routing.
#[cfg(target_os = "macos")]
struct MacosReconcileInputs {
    interface: String,
    endpoint: IpAddr,
    endpoint_is_ipv6: bool,
    /// Whether the endpoint must be pinned out of the tunnel via the physical
    /// gateway. Only true when AllowedIPs would otherwise capture it (e.g. a
    /// full tunnel); split tunnels reach the endpoint over the default route,
    /// so an unpinned endpoint roams to a new network with no stale route.
    endpoint_needs_pin: bool,
    allowed_ips: Vec<String>,
    dns_servers: Vec<String>,
    has_ipv4_address: bool,
    has_ipv6_address: bool,
}

/// A snapshot of the host network environment relevant to tunnel routing.
#[cfg(target_os = "macos")]
#[derive(Clone, Default, PartialEq)]
struct MacosNetworkFingerprint {
    /// Directly-connected subnets of physical interfaces (the LANs we must not
    /// hijack), sorted+deduped for stable comparison.
    local_subnets: Vec<(IpAddr, u8)>,
    /// Default gateway for the endpoint's address family (for the endpoint pin).
    endpoint_gateway: Option<String>,
}

#[cfg(target_os = "macos")]
#[derive(Clone, PartialEq)]
struct MacosRoute {
    is_ipv6: bool,
    destination: String,
    interface: Option<String>,
    gateway: Option<String>,
}

#[cfg(target_os = "macos")]
#[derive(Clone)]
struct MacosDnsServiceState {
    service: String,
    dns_servers: Option<Vec<String>>,
    search_domains: Option<Vec<String>>,
}

/// A snapshot of the host DNS-relevant environment. Equality drives the DNS
/// reconciler the same way `MacosNetworkFingerprint` drives the route one.
#[cfg(target_os = "macos")]
#[derive(Clone, Default, PartialEq)]
struct MacosDnsFingerprint {
    /// The service that currently owns global resolution (the primary service
    /// name), or `None` if it can't be determined.
    primary_service: Option<String>,
    /// All current service names, sorted+deduped — detects appear/disappear.
    services: Vec<String>,
    /// Per-service DNS as currently observed on the system, sorted by service.
    /// Detects DHCP clobber (our DNS silently replaced) without trusting our
    /// own cached view. `None` == "no DNS set" (networksetup "Empty"). Server
    /// lists are left in the order `networksetup` returns them (order is
    /// significant to macOS) so equality is stable across ticks.
    observed: Vec<(String, Option<Vec<String>>)>,
}

/// Which network services should carry the tunnel's DNS. `AllServices` matches
/// the historical connect-time behavior (now applied dynamically); `PrimaryOnly`
/// is the true analogue of the route LAN-exclusion — only the service that owns
/// global resolution gets tunnel DNS, so non-primary LANs keep their own.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum DnsPolicy {
    #[allow(dead_code)]
    AllServices,
    PrimaryOnly,
}

/// Active DNS targeting policy. Switching this constant is the only change
/// needed to move between the phases described in `transparent_dns.md`.
#[cfg(target_os = "macos")]
const DNS_POLICY: DnsPolicy = DnsPolicy::PrimaryOnly;

#[cfg(unix)]
#[derive(Debug, Clone)]
struct ParsedUserspaceConfig {
    private_key: [u8; 32],
    addresses: Vec<String>,
    dns_servers: Vec<String>,
    mtu: Option<u16>,
    peer_public_key: [u8; 32],
    peer_preshared_key: Option<[u8; 32]>,
    allowed_ips: Vec<String>,
    endpoint: SocketAddr,
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
            eprintln!("tunmux gotatun helper: missing interface argument");
            std::process::exit(2);
        }
    };
    if args.next().is_some() {
        eprintln!("tunmux gotatun helper: unexpected extra arguments");
        std::process::exit(2);
    }

    if let Err(e) = daemonize_and_run(&interface) {
        eprintln!("tunmux gotatun helper failed: {e}");
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
            // Ensure the log's parent dir exists (on macOS this is ~/Library/Logs,
            // which normally exists; create_dir_all is cheap insurance).
            let log_path = gotatun_log_path(interface);
            if let Some(parent) = log_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let _ = crate::logging::init_file_sync(&log_path.to_string_lossy(), false);

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
            let shutdown_started = std::time::Instant::now();
            let wait_result = rt.block_on(wait_for_shutdown(&running));
            debug!(
                interface = running.control_interface_name,
                elapsed_ms = shutdown_started.elapsed().as_millis(),
                result = ?wait_result.as_ref().map(|_| ()).map_err(|error| error.to_string()),
                "userspace_helper_shutdown_triggered"
            );

            let cleanup_started = std::time::Instant::now();
            let cleanup_result = cleanup_network(&running);
            debug!(
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
        match configure_network(&interface_name, config) {
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
    let diag_enabled = true;
    #[cfg(target_os = "macos")]
    let mut next_diag_at = std::time::Instant::now();
    #[cfg(target_os = "macos")]
    let mut next_reconcile_at = std::time::Instant::now();
    #[cfg(target_os = "macos")]
    let mut last_transfer: Option<(u64, u64)> = None;
    #[cfg(target_os = "macos")]
    let mut last_probe_sent: Option<(bool, bool)> = None;

    #[cfg(target_os = "macos")]
    info!(
        interface = running.control_interface_name,
        "userspace_helper_dataplane_probe_enabled"
    );

    loop {
        tokio::select! {
            _ = sigint.recv() => {
                debug!(interface = running.control_interface_name, trigger = "sigint", "userspace_helper_shutdown_requested");
                break;
            },
            _ = sigterm.recv() => {
                debug!(interface = running.control_interface_name, trigger = "sigterm", "userspace_helper_shutdown_requested");
                break;
            },
            _ = ticker.tick() => {
                if !running.control_socket_path.exists() {
                    debug!(interface = running.control_interface_name, trigger = "control_socket_removed", "userspace_helper_shutdown_requested");
                    break;
                }

                #[cfg(target_os = "macos")]
                {
                    // Adapt routing to network changes (roam, suspend/resume,
                    // link up/down) live, without requiring a reconnect. Throttled
                    // off the 1s tick so the `ifconfig` snapshot stays cheap.
                    if std::time::Instant::now() >= next_reconcile_at {
                        next_reconcile_at = std::time::Instant::now() + MACOS_RECONCILE_INTERVAL;
                        if let CleanupState::Macos(state) = &running.cleanup {
                            let routes_changed = macos_reconcile_routes(state);
                            let dns_changed = macos_reconcile_dns(state);
                            if routes_changed || dns_changed {
                                log_macos_network_overview("reconcile", state);
                            }
                        }
                    }

                    if diag_enabled && std::time::Instant::now() >= next_diag_at {
                        next_diag_at = std::time::Instant::now() + Duration::from_secs(5);
                        log_macos_dataplane_probe(
                            &running.control_interface_name,
                            &mut last_transfer,
                            &mut last_probe_sent,
                        )
                        .await;
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(target_os = "macos")]
async fn log_macos_dataplane_probe(
    interface: &str,
    last_transfer: &mut Option<(u64, u64)>,
    last_probe_sent: &mut Option<(bool, bool)>,
) {
    let ipv4_probe_sent = send_udp_probe(SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53)));
    let ipv6_probe_sent = send_udp_probe(SocketAddr::from((
        Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
        53,
    )));

    // A probe-send flag flipping (a send starting or stopping to work) is worth
    // surfacing at INFO; an unchanged flag is not.
    let probe_sent_changed = *last_probe_sent != Some((ipv4_probe_sent, ipv6_probe_sent));
    *last_probe_sent = Some((ipv4_probe_sent, ipv6_probe_sent));

    match read_wg_transfer_bytes(interface).await {
        Ok(Some((rx_bytes, tx_bytes))) => {
            let (delta_rx_bytes, delta_tx_bytes) = last_transfer
                .map(|(prev_rx, prev_tx)| {
                    (
                        rx_bytes.saturating_sub(prev_rx),
                        tx_bytes.saturating_sub(prev_tx),
                    )
                })
                .unwrap_or((0, 0));
            *last_transfer = Some((rx_bytes, tx_bytes));
            // Steady idle tunnels probe every 5s with no movement; keep that
            // heartbeat at DEBUG so default (INFO) logs stay quiet, and only
            // surface probes that actually moved bytes or changed send state.
            let noteworthy = delta_rx_bytes != 0 || delta_tx_bytes != 0 || probe_sent_changed;
            if noteworthy {
                info!(
                    interface,
                    ipv4_probe_sent,
                    ipv6_probe_sent,
                    rx_bytes,
                    tx_bytes,
                    delta_rx_bytes,
                    delta_tx_bytes,
                    "userspace_helper_dataplane_probe"
                );
            } else {
                debug!(
                    interface,
                    ipv4_probe_sent,
                    ipv6_probe_sent,
                    rx_bytes,
                    tx_bytes,
                    delta_rx_bytes,
                    delta_tx_bytes,
                    "userspace_helper_dataplane_probe"
                );
            }
        }
        Ok(None) => {
            info!(
                interface,
                ipv4_probe_sent, ipv6_probe_sent, "userspace_helper_dataplane_probe_no_transfer"
            );
        }
        Err(error) => {
            warn!(
                interface,
                ipv4_probe_sent,
                ipv6_probe_sent,
                error = %error,
                "userspace_helper_dataplane_probe_failed"
            );
        }
    }
}

#[cfg(target_os = "macos")]
fn send_udp_probe(target: SocketAddr) -> bool {
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let Ok(socket) = UdpSocket::bind(bind) else {
        return false;
    };
    socket.send_to(&[0], target).is_ok()
}

#[cfg(target_os = "macos")]
async fn read_wg_transfer_bytes(interface: &str) -> anyhow::Result<Option<(u64, u64)>> {
    // `wg show <iface> transfer` connects to gotatun's in-process UAPI socket, which can only
    // be serviced by the async UAPI task running on this same runtime. Running the command
    // inline would block the runtime thread and self-deadlock (the runtime can no longer poll
    // the task that `wg` is waiting on). Run it on a blocking thread, bounded by a timeout, so
    // the runtime stays free to answer the UAPI request and a stuck `wg` can never wedge us.
    let owned_interface = interface.to_string();
    let output = {
        let _suppress_probe_uapi_log = crate::logging::suppress_gotatun_uapi_connection_logs();
        match tokio::time::timeout(
            Duration::from_secs(4),
            tokio::task::spawn_blocking(move || {
                Command::new("wg")
                    .args(["show", &owned_interface, "transfer"])
                    .output()
            }),
        )
        .await
        {
            Ok(join_result) => join_result
                .context("wg show transfer task panicked")?
                .context("failed to run wg show transfer")?,
            Err(_) => anyhow::bail!("wg show {} transfer timed out", interface),
        }
    };
    if !output.status.success() {
        anyhow::bail!("wg show {} transfer failed", interface);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut parsed_any = false;
    let mut rx_total: u64 = 0;
    let mut tx_total: u64 = 0;

    for line in stdout.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 3 {
            continue;
        }
        let Ok(rx) = fields[1].parse::<u64>() else {
            continue;
        };
        let Ok(tx) = fields[2].parse::<u64>() else {
            continue;
        };
        parsed_any = true;
        rx_total = rx_total.saturating_add(rx);
        tx_total = tx_total.saturating_add(tx);
    }

    if parsed_any {
        Ok(Some((rx_total, tx_total)))
    } else {
        Ok(None)
    }
}

#[cfg(unix)]
fn parse_config_from_env() -> anyhow::Result<Option<ParsedUserspaceConfig>> {
    let Some(encoded) = std::env::var_os(CONFIG_B64_ENV) else {
        return Ok(None);
    };
    let encoded = encoded
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("{} is not valid UTF-8", CONFIG_B64_ENV))?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("failed to decode userspace WireGuard config")?;
    let text = String::from_utf8(bytes).context("userspace WireGuard config is not UTF-8")?;
    let mut config = parse_wg_quick_config(&text)?;
    if let Some(value) = std::env::var_os(MTU_OVERRIDE_ENV) {
        let value = value
            .to_str()
            .ok_or_else(|| anyhow::anyhow!("{} is not valid UTF-8", MTU_OVERRIDE_ENV))?;
        apply_mtu_override(&mut config, value)?;
    }
    Ok(Some(config))
}

#[cfg(unix)]
fn apply_mtu_override(config: &mut ParsedUserspaceConfig, value: &str) -> anyhow::Result<()> {
    config.mtu = Some(crate::wireguard::config::parse_mtu(value)?);
    Ok(())
}

#[cfg(unix)]
fn parse_wg_quick_config(config: &str) -> anyhow::Result<ParsedUserspaceConfig> {
    enum Section {
        None,
        Interface,
        Peer,
    }

    let mut section = Section::None;
    let mut private_key = None;
    let mut addresses: Vec<String> = Vec::new();
    let mut dns_servers: Vec<String> = Vec::new();
    let mut mtu = None;
    let mut peer_public_key = None;
    let mut peer_preshared_key = None;
    let mut allowed_ips: Vec<String> = Vec::new();
    let mut endpoint = None;

    for raw_line in config.lines() {
        let line = raw_line.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = match &line[1..line.len() - 1] {
                "Interface" => Section::Interface,
                "Peer" => Section::Peer,
                _ => Section::None,
            };
            continue;
        }

        let Some((raw_key, raw_value)) = line.split_once('=') else {
            continue;
        };
        let key = raw_key.trim();
        let value = raw_value.trim();
        if value.is_empty() {
            continue;
        }

        match section {
            Section::Interface => match key {
                "PrivateKey" => private_key = Some(decode_key32("PrivateKey", value)?),
                "Address" => addresses = split_csv(value),
                "DNS" => dns_servers = split_csv(value),
                "MTU" => mtu = Some(crate::wireguard::config::parse_mtu(value)?),
                _ => {}
            },
            Section::Peer => match key {
                "PublicKey" => peer_public_key = Some(decode_key32("PublicKey", value)?),
                "PresharedKey" => peer_preshared_key = Some(decode_key32("PresharedKey", value)?),
                "AllowedIPs" => allowed_ips = split_csv(value),
                "Endpoint" => endpoint = Some(parse_endpoint(value)?),
                _ => {}
            },
            Section::None => {}
        }
    }

    let private_key = private_key.ok_or_else(|| anyhow::anyhow!("missing Interface.PrivateKey"))?;
    if addresses.is_empty() {
        anyhow::bail!("missing Interface.Address");
    }
    let peer_public_key =
        peer_public_key.ok_or_else(|| anyhow::anyhow!("missing Peer.PublicKey"))?;
    if allowed_ips.is_empty() {
        anyhow::bail!("missing Peer.AllowedIPs");
    }
    let endpoint = endpoint.ok_or_else(|| anyhow::anyhow!("missing Peer.Endpoint"))?;

    Ok(ParsedUserspaceConfig {
        private_key,
        addresses,
        dns_servers,
        mtu,
        peer_public_key,
        peer_preshared_key,
        allowed_ips,
        endpoint,
    })
}

#[cfg(unix)]
fn split_csv(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(ToString::to_string)
        .collect()
}

#[cfg(all(test, unix))]
mod userspace_config_tests {
    use super::*;

    const CONFIG: &str = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\nMTU = 1280\n[Peer]\nPublicKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.1:51820\n";

    #[test]
    fn userspace_config_parses_mtu() {
        let parsed = parse_wg_quick_config(CONFIG).expect("parse config");
        assert_eq!(parsed.mtu, Some(1280));
    }

    #[test]
    fn userspace_config_rejects_invalid_mtu() {
        let config = CONFIG.replace("MTU = 1280", "MTU = 575");
        assert!(parse_wg_quick_config(&config).is_err());
    }

    #[test]
    fn explicit_mtu_overrides_config_mtu() {
        let mut parsed = parse_wg_quick_config(CONFIG).expect("parse config");
        apply_mtu_override(&mut parsed, "1420").expect("apply override");
        assert_eq!(parsed.mtu, Some(1420));
    }
}

#[cfg(unix)]
fn decode_key32(field: &str, value: &str) -> anyhow::Result<[u8; 32]> {
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .with_context(|| format!("failed to decode {}", field))?;
    if decoded.len() != 32 {
        anyhow::bail!("{} must decode to 32 bytes", field);
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

#[cfg(unix)]
fn parse_endpoint(value: &str) -> anyhow::Result<SocketAddr> {
    if let Ok(addr) = value.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let (host, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid endpoint {}", value))?;
    let ip: IpAddr = host
        .trim_matches(['[', ']'])
        .parse()
        .with_context(|| format!("invalid endpoint IP {}", host))?;
    let port: u16 = port
        .parse()
        .with_context(|| format!("invalid endpoint port {}", port))?;
    Ok(SocketAddr::new(ip, port))
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

#[cfg(unix)]
fn configure_network(
    interface: &str,
    config: &ParsedUserspaceConfig,
) -> anyhow::Result<CleanupState> {
    let cleanup = configure_network_macos(interface, config)?;
    Ok(CleanupState::Macos(Box::new(cleanup)))
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
fn write_runtime_file(path: &std::path::Path, contents: &str) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    // This runs as the privileged helper, so a symlink planted under the runtime
    // dir could otherwise redirect the write (and the chmod) to clobber an
    // arbitrary file. O_NOFOLLOW makes open() fail rather than follow a final-
    // component symlink, and mode(0o600) creates the file private from the start.
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("failed to write {}", path.display()))?;
    file.write_all(contents.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    // Pin permissions for the case where the file already existed (open() does not
    // re-apply mode to an existing file).
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .with_context(|| format!("failed to chmod {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn write_runtime_file_atomic(path: &std::path::Path, contents: &str) -> anyhow::Result<()> {
    let temp_path = path.with_extension(format!("tmp.{}", std::process::id()));
    write_runtime_file(&temp_path, contents)?;
    std::fs::rename(&temp_path, path)
        .with_context(|| format!("failed to publish {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn run_command(name: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = run_command_capture_output(name, args)?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    anyhow::bail!("{} {} failed: {}", name, args.join(" "), detail);
}

#[cfg(unix)]
fn run_command_with_exists_ok(name: &str, args: &[&str]) -> anyhow::Result<bool> {
    let output = run_command_capture_output(name, args)?;
    if output.status.success() {
        return Ok(true);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stderr.contains("File exists") || stdout.contains("File exists") {
        return Ok(false);
    }
    let detail = stderr.trim();
    if detail.is_empty() {
        anyhow::bail!("{} {} failed", name, args.join(" "));
    }
    anyhow::bail!("{} {} failed: {}", name, args.join(" "), detail);
}

#[cfg(unix)]
fn run_command_capture_output(name: &str, args: &[&str]) -> anyhow::Result<Output> {
    trace!(command = %format_command_for_log(name, args), "userspace_helper_command");
    Command::new(name)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {} {}", name, args.join(" ")))
}

#[cfg(unix)]
fn format_command_for_log(name: &str, args: &[&str]) -> String {
    if args.is_empty() {
        return name.to_string();
    }
    format!("{} {}", name, args.join(" "))
}

#[cfg(target_os = "macos")]
fn configure_network_macos(
    interface: &str,
    config: &ParsedUserspaceConfig,
) -> anyhow::Result<MacosCleanupState> {
    let has_ipv4_address = config
        .addresses
        .iter()
        .any(|address| !address.contains(':'));
    let has_ipv6_address = config.addresses.iter().any(|address| address.contains(':'));
    let endpoint_is_ipv6 = matches!(config.endpoint.ip(), IpAddr::V6(_));
    let endpoint_family_supported = !endpoint_is_ipv6 || has_ipv6_address;
    // Decision (1): only pin the endpoint out of the tunnel when AllowedIPs
    // would otherwise capture it (full tunnel). A split tunnel reaches the
    // endpoint over the default route, so leaving it unpinned means roaming to
    // a new LAN "just works" with no stale gateway route to fix up.
    let endpoint_needs_pin = endpoint_family_supported
        && macos_allowed_ips_cover_endpoint(&config.allowed_ips, config.endpoint.ip());

    let inputs = MacosReconcileInputs {
        interface: interface.to_string(),
        endpoint: config.endpoint.ip(),
        endpoint_is_ipv6,
        endpoint_needs_pin,
        allowed_ips: config.allowed_ips.clone(),
        dns_servers: config.dns_servers.clone(),
        has_ipv4_address,
        has_ipv6_address,
    };

    let mut routes_added: Vec<MacosRoute> = Vec::new();
    let mut dns_services: Vec<MacosDnsServiceState> = Vec::new();
    let mut fingerprint = MacosNetworkFingerprint::default();
    let mut dns_fingerprint = MacosDnsFingerprint::default();

    let setup_result = (|| -> anyhow::Result<()> {
        if let Some(mtu) = config.mtu {
            let mtu = mtu.to_string();
            run_command("ifconfig", &[interface, "mtu", &mtu])?;
        }
        for address in &config.addresses {
            let (ip, prefix) = parse_cidr(address)?;
            match ip {
                IpAddr::V4(addr) => {
                    let ip_string = addr.to_string();
                    run_command(
                        "ifconfig",
                        &[interface, "inet", address, ip_string.as_str(), "alias"],
                    )?;
                }
                IpAddr::V6(addr) => {
                    let ip_string = addr.to_string();
                    let prefix_string = prefix.to_string();
                    run_command(
                        "ifconfig",
                        &[
                            interface,
                            "inet6",
                            ip_string.as_str(),
                            "prefixlen",
                            prefix_string.as_str(),
                            "alias",
                        ],
                    )?;
                }
            }
        }
        run_command("ifconfig", &[interface, "up"])?;
        if let Err(error) = run_command("ifconfig", &[interface, "-rxcsum", "-txcsum"]) {
            warn!(
                interface,
                error = %error,
                "userspace_helper_disable_checksum_offload_failed"
            );
        }

        // Compute the initial desired routes the same way the reconciler will,
        // so the LAN-exclusion is applied from the very first packet. A missing
        // gateway here is fatal: an unpinned endpoint would route into the tunnel.
        fingerprint = macos_current_fingerprint(&inputs, GatewayFallback::Require)?;
        for route in macos_desired_routes(&inputs, &fingerprint) {
            add_macos_route(&route)?;
            routes_added.push(route);
        }
        // Apply DNS the same way the reconciler will, then seed the DNS
        // fingerprint so the first reconcile tick is a no-op.
        dns_fingerprint = configure_macos_dns(config, &mut dns_services)?;
        Ok(())
    })();

    if let Err(setup_error) = setup_result {
        let mut errors = Vec::new();
        for route in routes_added.iter().rev() {
            if let Err(error) = del_macos_route(route) {
                errors.push(error.to_string());
            }
        }
        for service in dns_services.iter().rev() {
            if let Err(error) = restore_macos_dns_service(service) {
                errors.push(format!(
                    "restore DNS for {:?} failed: {error}",
                    service.service
                ));
            }
        }
        return if errors.is_empty() {
            Err(setup_error)
        } else {
            Err(anyhow::anyhow!(
                "setup failed: {}; rollback failed: {}",
                setup_error,
                errors.join("; ")
            ))
        };
    }

    let cleanup = MacosCleanupState {
        routing: std::sync::Mutex::new(MacosRoutingState {
            routes_added,
            fingerprint,
        }),
        dns: std::sync::Mutex::new(MacosDnsState {
            services: dns_services,
            fingerprint: dns_fingerprint,
        }),
        reconcile: inputs,
    };
    log_macos_network_overview("connect", &cleanup);
    Ok(cleanup)
}

#[cfg(target_os = "macos")]
fn cleanup_network_macos(state: &MacosCleanupState) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    // Restore routes then DNS, taking the `routing` and `dns` locks
    // independently (never both at once) to avoid any ordering hazard with the
    // reconciler.
    {
        let routing = state
            .routing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        debug!(
            routes = routing.routes_added.len(),
            "userspace_helper_network_cleanup_routes"
        );
        for route in routing.routes_added.iter().rev() {
            if let Err(error) = del_macos_route(route) {
                errors.push(error.to_string());
            }
        }
    }
    {
        let dns = state
            .dns
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        debug!(
            dns_services = dns.services.len(),
            "userspace_helper_network_cleanup_dns"
        );
        for service in dns.services.iter().rev() {
            if let Err(error) = restore_macos_dns_service(service) {
                errors.push(format!(
                    "restore DNS for {:?} failed: {error}",
                    service.service
                ));
            }
        }
    }
    finish_cleanup(errors)
}

#[cfg(unix)]
fn finish_cleanup(errors: Vec<String>) -> anyhow::Result<()> {
    if errors.is_empty() {
        Ok(())
    } else {
        anyhow::bail!(errors.join("; "))
    }
}

/// Apply the tunnel's DNS to the services selected by `DNS_POLICY`, saving each
/// touched service's original config into `saved` for later restore. Returns the
/// DNS fingerprint observed *after* applying, so the reconciler's first tick is a
/// no-op. Shares its per-service capture+apply path with the reconciler.
#[cfg(target_os = "macos")]
fn configure_macos_dns(
    config: &ParsedUserspaceConfig,
    saved: &mut Vec<MacosDnsServiceState>,
) -> anyhow::Result<MacosDnsFingerprint> {
    if config.dns_servers.is_empty() {
        return Ok(MacosDnsFingerprint::default());
    }

    let fingerprint = macos_current_dns_fingerprint()?;
    for service in dns_target_services(DNS_POLICY, &fingerprint) {
        saved.push(capture_macos_dns_service(&service, &config.dns_servers)?);
        set_macos_dns_servers(&service, &config.dns_servers)?;
        set_macos_search_domains_empty(&service)?;
    }

    // Re-snapshot post-apply: the stored fingerprint must reflect the DNS we
    // just wrote so the first reconcile tick detects no change. DNS is already
    // applied at this point, so a failed re-snapshot must not fail connect —
    // fall back to the pre-apply fingerprint and let the first reconcile tick
    // observe the resulting drift and self-correct.
    Ok(macos_current_dns_fingerprint().unwrap_or_else(|error| {
        warn!(error = %error, "userspace_helper_dns_fingerprint_resnapshot_failed");
        fingerprint
    }))
}

#[cfg(target_os = "macos")]
fn restore_macos_dns_service(state: &MacosDnsServiceState) -> anyhow::Result<()> {
    match &state.dns_servers {
        Some(servers) => set_macos_dns_servers(&state.service, servers)?,
        None => set_macos_dns_servers_empty(&state.service)?,
    }

    match &state.search_domains {
        Some(domains) => set_macos_search_domains(&state.service, domains)?,
        None => set_macos_search_domains_empty(&state.service)?,
    }

    Ok(())
}

#[cfg(target_os = "macos")]
fn list_macos_network_services() -> anyhow::Result<Vec<String>> {
    let output = run_command_capture_output("networksetup", &["-listallnetworkservices"])?;
    if !output.status.success() {
        anyhow::bail!("networksetup -listallnetworkservices failed");
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut services = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("An asterisk") {
            continue;
        }
        let service = trimmed.strip_prefix('*').map(str::trim).unwrap_or(trimmed);
        if !service.is_empty() {
            services.push(service.to_string());
        }
    }

    Ok(services)
}

#[cfg(target_os = "macos")]
fn get_macos_dns_servers(service: &str) -> anyhow::Result<Option<Vec<String>>> {
    get_macos_networksetup_values(service, "-getdnsservers", "DNS Servers")
}

#[cfg(target_os = "macos")]
fn get_macos_search_domains(service: &str) -> anyhow::Result<Option<Vec<String>>> {
    get_macos_networksetup_values(service, "-getsearchdomains", "Search Domains")
}

#[cfg(target_os = "macos")]
fn get_macos_networksetup_values(
    service: &str,
    flag: &str,
    value_label: &str,
) -> anyhow::Result<Option<Vec<String>>> {
    let output = run_command_capture_output("networksetup", &[flag, service])?;
    if !output.status.success() {
        anyhow::bail!("networksetup {} {} failed", flag, service);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let marker = format!("There aren't any {} set", value_label);
    if stdout.lines().any(|line| line.contains(&marker)) {
        return Ok(None);
    }

    let values: Vec<String> = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();

    if values.is_empty() || values == ["Empty".to_string()] {
        Ok(None)
    } else {
        Ok(Some(values))
    }
}

#[cfg(target_os = "macos")]
fn set_macos_dns_servers(service: &str, dns_servers: &[String]) -> anyhow::Result<()> {
    let mut args: Vec<&str> = Vec::with_capacity(2 + dns_servers.len());
    args.push("-setdnsservers");
    args.push(service);
    args.extend(dns_servers.iter().map(String::as_str));
    run_command("networksetup", &args)
}

#[cfg(target_os = "macos")]
fn set_macos_dns_servers_empty(service: &str) -> anyhow::Result<()> {
    run_command("networksetup", &["-setdnsservers", service, "Empty"])
}

#[cfg(target_os = "macos")]
fn set_macos_search_domains(service: &str, domains: &[String]) -> anyhow::Result<()> {
    let mut args: Vec<&str> = Vec::with_capacity(2 + domains.len());
    args.push("-setsearchdomains");
    args.push(service);
    args.extend(domains.iter().map(String::as_str));
    run_command("networksetup", &args)
}

#[cfg(target_os = "macos")]
fn set_macos_search_domains_empty(service: &str) -> anyhow::Result<()> {
    run_command("networksetup", &["-setsearchdomains", service, "Empty"])
}

#[cfg(target_os = "macos")]
fn add_macos_route(route: &MacosRoute) -> anyhow::Result<bool> {
    let mut args: Vec<String> = vec!["-q".into(), "-n".into(), "add".into()];
    args.push(if route.is_ipv6 { "-inet6" } else { "-inet" }.into());
    args.push(route.destination.clone());
    if let Some(gateway) = &route.gateway {
        args.push(gateway.clone());
    }
    if let Some(interface) = &route.interface {
        args.push("-interface".into());
        args.push(interface.clone());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    // Split routes (dev-bound, no explicit gateway) can linger on stale utun
    // devices; clear any existing entry first so this tunnel owns the route.
    if route.interface.is_some() && route.gateway.is_none() {
        let mut delete_args: Vec<String> = vec!["-q".into(), "-n".into(), "delete".into()];
        delete_args.push(if route.is_ipv6 { "-inet6" } else { "-inet" }.into());
        // Match del_macos_route: without -host/-net the delete can fail to match a
        // CIDR destination, leaving the stale dev-bound route behind.
        delete_args.push(macos_route_target_kind(route).into());
        delete_args.push(route.destination.clone());
        let delete_refs: Vec<&str> = delete_args.iter().map(String::as_str).collect();
        let _ = run_command("route", &delete_refs);
    }

    run_command_with_exists_ok("route", &refs)
}

#[cfg(target_os = "macos")]
fn del_macos_route(route: &MacosRoute) -> anyhow::Result<()> {
    let mut args: Vec<String> = vec!["-q".into(), "-n".into(), "delete".into()];
    args.push(if route.is_ipv6 { "-inet6" } else { "-inet" }.into());
    args.push(macos_route_target_kind(route).into());
    args.push(route.destination.clone());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run_command_capture_output("route", &refs)?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    if stderr.contains("not in table") || stdout.contains("not in table") {
        return Ok(());
    }
    let detail = if !stderr.trim().is_empty() {
        stderr.trim()
    } else {
        stdout.trim()
    };
    anyhow::bail!("route {} failed: {}", refs.join(" "), detail)
}

#[cfg(target_os = "macos")]
fn macos_route_target_kind(route: &MacosRoute) -> &'static str {
    let host_prefix = if route.is_ipv6 { "/128" } else { "/32" };
    if route.gateway.is_some()
        || route.destination.ends_with(host_prefix)
        || !route.destination.contains('/')
    {
        "-host"
    } else {
        "-net"
    }
}

#[cfg(target_os = "macos")]
fn macos_allowed_routes(
    allowed_ips: &[String],
    interface: &str,
    has_ipv4_address: bool,
    has_ipv6_address: bool,
) -> Vec<MacosRoute> {
    let mut routes = Vec::new();
    for allowed in allowed_ips {
        match allowed.as_str() {
            "0.0.0.0/0" => {
                if !has_ipv4_address {
                    continue;
                }
                routes.push(MacosRoute {
                    is_ipv6: false,
                    destination: "0.0.0.0/1".to_string(),
                    interface: Some(interface.to_string()),
                    gateway: None,
                });
                routes.push(MacosRoute {
                    is_ipv6: false,
                    destination: "128.0.0.0/1".to_string(),
                    interface: Some(interface.to_string()),
                    gateway: None,
                });
            }
            "::/0" => {
                if !has_ipv6_address {
                    continue;
                }
                routes.push(MacosRoute {
                    is_ipv6: true,
                    destination: "::/1".to_string(),
                    interface: Some(interface.to_string()),
                    gateway: None,
                });
                routes.push(MacosRoute {
                    is_ipv6: true,
                    destination: "8000::/1".to_string(),
                    interface: Some(interface.to_string()),
                    gateway: None,
                });
            }
            other => {
                if other.contains(':') && !has_ipv6_address {
                    continue;
                }
                if !other.contains(':') && !has_ipv4_address {
                    continue;
                }
                routes.push(MacosRoute {
                    is_ipv6: other.contains(':'),
                    destination: other.to_string(),
                    interface: Some(interface.to_string()),
                    gateway: None,
                });
            }
        }
    }
    routes
}

/// The routes this tunnel wants installed for the given network environment:
/// the (optional) endpoint pin plus the AllowedIPs routes, minus any subnet
/// we are currently directly attached to (so we never hijack our own LAN).
#[cfg(target_os = "macos")]
fn macos_desired_routes(
    inputs: &MacosReconcileInputs,
    fingerprint: &MacosNetworkFingerprint,
) -> Vec<MacosRoute> {
    let mut routes = Vec::new();

    if inputs.endpoint_needs_pin {
        if let Some(gateway) = &fingerprint.endpoint_gateway {
            routes.push(MacosRoute {
                is_ipv6: inputs.endpoint_is_ipv6,
                destination: inputs.endpoint.to_string(),
                interface: None,
                gateway: Some(gateway.clone()),
            });
        }
    }

    for route in macos_allowed_routes(
        &inputs.allowed_ips,
        &inputs.interface,
        inputs.has_ipv4_address,
        inputs.has_ipv6_address,
    ) {
        if let Some((subnet_ip, subnet_prefix)) =
            macos_route_excluded_by_local_subnet(&route, &fingerprint.local_subnets)
        {
            debug!(
                destination = %route.destination,
                local_subnet = %format!("{subnet_ip}/{subnet_prefix}"),
                "userspace_helper_route_excluded_local_lan"
            );
            continue;
        }
        routes.push(route);
    }

    routes
}

/// Returns the connected subnet that makes `route` local (so it must stay off
/// the tunnel), or `None` if the route should be installed normally.
#[cfg(target_os = "macos")]
fn macos_route_excluded_by_local_subnet(
    route: &MacosRoute,
    local_subnets: &[(IpAddr, u8)],
) -> Option<(IpAddr, u8)> {
    // Only tunnel-bound routes (interface, no gateway) can hijack a LAN.
    if route.interface.is_none() || route.gateway.is_some() {
        return None;
    }
    let (ip, prefix) = parse_cidr(&route.destination).ok()?;
    let destination = (macos_network_base(ip, prefix), prefix);
    local_subnets
        .iter()
        .find(|local| macos_subnet_contains(local, &destination))
        .copied()
}

/// True when `route` is equal to, or fully inside, the connected subnet `local`.
#[cfg(target_os = "macos")]
fn macos_subnet_contains(local: &(IpAddr, u8), route: &(IpAddr, u8)) -> bool {
    if route.1 < local.1 {
        return false;
    }
    match (local.0, route.0) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
            macos_network_base(route.0, local.1) == macos_network_base(local.0, local.1)
        }
        _ => false,
    }
}

/// Mask `ip` down to its network base for the given prefix length.
#[cfg(target_os = "macos")]
fn macos_network_base(ip: IpAddr, prefix: u8) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let masked = match prefix {
                0 => 0,
                p if p >= 32 => bits,
                p => bits & (u32::MAX << (32 - p)),
            };
            IpAddr::V4(Ipv4Addr::from(masked))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let masked = match prefix {
                0 => 0,
                p if p >= 128 => bits,
                p => bits & (u128::MAX << (128 - p)),
            };
            IpAddr::V6(Ipv6Addr::from(masked))
        }
    }
}

/// True when any AllowedIPs entry would route the endpoint into the tunnel.
#[cfg(target_os = "macos")]
fn macos_allowed_ips_cover_endpoint(allowed_ips: &[String], endpoint: IpAddr) -> bool {
    allowed_ips.iter().any(|allowed| {
        let Ok((net, prefix)) = parse_cidr(allowed) else {
            return false;
        };
        match (net, endpoint) {
            (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
                macos_network_base(endpoint, prefix) == macos_network_base(net, prefix)
            }
            _ => false,
        }
    })
}

/// How `macos_current_fingerprint` should treat a failed default-gateway lookup.
#[cfg(target_os = "macos")]
enum GatewayFallback {
    /// Initial setup: a missing gateway is fatal. Without the pin the endpoint
    /// would route into the tunnel and break connectivity, so propagate the error.
    Require,
    /// Reconcile tick: keep this previously resolved gateway on a transient
    /// failure rather than silently dropping the endpoint pin.
    Keep(Option<String>),
}

/// Snapshot the current network environment that drives tunnel routing.
///
/// When the endpoint must be pinned out of the tunnel the default gateway is
/// required; `gateway_fallback` decides what happens if that lookup fails (see
/// [`GatewayFallback`]). The lookup is skipped entirely when no pin is needed, so
/// no-op reconcile ticks don't run `route get default`.
#[cfg(target_os = "macos")]
fn macos_current_fingerprint(
    inputs: &MacosReconcileInputs,
    gateway_fallback: GatewayFallback,
) -> anyhow::Result<MacosNetworkFingerprint> {
    let local_subnets = macos_local_connected_subnets(&inputs.interface);
    let endpoint_gateway = if inputs.endpoint_needs_pin {
        match get_macos_default_gateway(inputs.endpoint_is_ipv6) {
            Ok(Some(gateway)) => Some(gateway),
            Ok(None) => match gateway_fallback {
                GatewayFallback::Require => anyhow::bail!(
                    "no default gateway available to pin endpoint {} out of the tunnel",
                    inputs.endpoint
                ),
                GatewayFallback::Keep(previous) => {
                    warn!(
                        interface = inputs.interface,
                        endpoint = %inputs.endpoint,
                        "userspace_helper_reconcile_gateway_unresolved_keeping_previous"
                    );
                    previous
                }
            },
            Err(error) => match gateway_fallback {
                GatewayFallback::Require => {
                    return Err(error.context(format!(
                        "failed to resolve default gateway to pin endpoint {} out of the tunnel",
                        inputs.endpoint
                    )));
                }
                GatewayFallback::Keep(previous) => {
                    warn!(
                        interface = inputs.interface,
                        endpoint = %inputs.endpoint,
                        error = %error,
                        "userspace_helper_reconcile_gateway_lookup_failed_keeping_previous"
                    );
                    previous
                }
            },
        }
    } else {
        None
    };
    Ok(MacosNetworkFingerprint {
        local_subnets,
        endpoint_gateway,
    })
}

/// Re-apply routing when the host network changed (roam, suspend/resume, link
/// up/down). Cheap and silent when nothing changed; expressive when it acts.
#[cfg(target_os = "macos")]
fn macos_reconcile_routes(state: &MacosCleanupState) -> bool {
    let inputs = &state.reconcile;

    let mut routing = state
        .routing
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // Reconcile is best-effort: if the gateway lookup fails transiently, keep the
    // last known gateway rather than dropping the endpoint pin (which would route
    // the endpoint into the tunnel until the next change).
    let previous_gateway = routing.fingerprint.endpoint_gateway.clone();
    let fingerprint =
        match macos_current_fingerprint(inputs, GatewayFallback::Keep(previous_gateway)) {
            Ok(fingerprint) => fingerprint,
            // `Keep` mode does not propagate gateway errors, but stay defensive:
            // skip this tick rather than acting on a half-built fingerprint.
            Err(error) => {
                warn!(
                    interface = inputs.interface,
                    error = %error,
                    "userspace_helper_reconcile_fingerprint_failed"
                );
                return false;
            }
        };
    if fingerprint == routing.fingerprint {
        return false;
    }

    let previous = routing.fingerprint.clone();
    info!(
        interface = inputs.interface,
        old_gateway = ?previous.endpoint_gateway,
        new_gateway = ?fingerprint.endpoint_gateway,
        old_local_subnets = %format_subnets(&previous.local_subnets),
        new_local_subnets = %format_subnets(&fingerprint.local_subnets),
        "userspace_helper_network_change_detected"
    );

    let desired = macos_desired_routes(inputs, &fingerprint);
    let current = routing.routes_added.clone();
    let mut installed: Vec<MacosRoute> = Vec::new();
    let (mut added, mut removed, mut errors) = (0usize, 0usize, 0usize);

    // Remove routes that are no longer desired (e.g. a LAN we just left, or a
    // stale endpoint pin via the previous gateway).
    for route in &current {
        if !desired.contains(route) {
            match del_macos_route(route) {
                Ok(()) => removed += 1,
                Err(error) => {
                    errors += 1;
                    warn!(
                        destination = %route.destination,
                        error = %error,
                        "userspace_helper_reconcile_route_delete_failed"
                    );
                }
            }
        }
    }

    // Add newly desired routes; keep the ones already present.
    for route in desired {
        if current.contains(&route) {
            installed.push(route);
            continue;
        }
        match add_macos_route(&route) {
            Ok(_) => {
                added += 1;
                installed.push(route);
            }
            Err(error) => {
                errors += 1;
                warn!(
                    destination = %route.destination,
                    error = %error,
                    "userspace_helper_reconcile_route_add_failed"
                );
            }
        }
    }

    routing.routes_added = installed;
    routing.fingerprint = fingerprint.clone();

    info!(
        interface = inputs.interface,
        routes_added = added,
        routes_removed = removed,
        errors,
        "userspace_helper_reconcile_applied"
    );
    true
}

/// The services that should carry tunnel DNS under `policy`. `PrimaryOnly`
/// targets just the service that owns global resolution; if that can't be
/// determined (or isn't a current service) it falls back to `AllServices` so we
/// never leave the primary resolver leaked (`transparent_dns.md` §6.3).
#[cfg(target_os = "macos")]
fn dns_target_services(policy: DnsPolicy, fp: &MacosDnsFingerprint) -> Vec<String> {
    match policy {
        DnsPolicy::AllServices => fp.services.clone(),
        DnsPolicy::PrimaryOnly => match &fp.primary_service {
            Some(primary) if fp.services.iter().any(|s| s == primary) => vec![primary.clone()],
            _ => fp.services.clone(),
        },
    }
}

/// A configured tunnel DNS server whose address falls inside a directly-connected
/// LAN subnet. When that happens the route covering the server is excluded from
/// the tunnel (see [`macos_route_excluded_by_local_subnet`]), so the server is no
/// longer reachable through the tunnel: queries would leak onto the LAN and hit
/// whatever host happens to hold that address. Returns the offending server and
/// the subnet it collides with so the reconciler can pull tunnel DNS back.
#[cfg(target_os = "macos")]
fn macos_dns_server_in_local_subnet(
    dns_servers: &[String],
    local_subnets: &[(IpAddr, u8)],
) -> Option<(IpAddr, (IpAddr, u8))> {
    dns_servers.iter().find_map(|server| {
        let ip: IpAddr = server.parse().ok()?;
        let host_prefix = if ip.is_ipv4() { 32 } else { 128 };
        local_subnets
            .iter()
            .find(|local| macos_subnet_contains(local, &(ip, host_prefix)))
            .map(|local| (ip, *local))
    })
}

/// The pure decision behind a DNS reconcile: given the tunnel's DNS, the freshly
/// observed environment, the services we currently own, and the services we want
/// to own, decide what to do. Kept free of I/O so it is unit-testable.
#[cfg(target_os = "macos")]
#[derive(Debug, Default, PartialEq)]
struct DnsActions {
    /// Targets we don't yet own and whose live DNS differs from the tunnel's:
    /// capture their original config, then assert tunnel DNS.
    capture: Vec<String>,
    /// Owned services no longer targeted but still present: restore originals.
    restore: Vec<String>,
    /// Owned services that have vanished: drop without restoring (gone already).
    drop: Vec<String>,
    /// Targets whose observed DNS has drifted from the tunnel's: (re-)assert.
    apply: Vec<String>,
}

#[cfg(target_os = "macos")]
fn plan_dns_actions(
    tunnel_dns: &[String],
    fp: &MacosDnsFingerprint,
    owned: &[String],
    targets: &[String],
) -> DnsActions {
    let shows_tunnel = |svc: &str| -> bool {
        fp.observed
            .iter()
            .find(|(s, _)| s == svc)
            .and_then(|(_, d)| d.as_deref())
            == Some(tunnel_dns)
    };

    let mut actions = DnsActions::default();

    for svc in targets {
        let matches_tunnel = shows_tunnel(svc);
        // Capture whenever we don't already own the service — even if it already
        // shows the tunnel DNS. A not-owned service at tunnel DNS is a leak from
        // an earlier run whose real original is gone; capturing it (with an Empty
        // original, see `capture_macos_dns_service`) lets teardown clear the stray
        // instead of stranding an unreachable resolver. Owned services keep their
        // real captured original and are never re-captured.
        if !owned.iter().any(|s| s == svc) {
            actions.capture.push(svc.clone());
        }
        if !matches_tunnel {
            actions.apply.push(svc.clone());
        }
    }

    for svc in owned {
        if targets.iter().any(|s| s == svc) {
            continue;
        }
        if fp.services.iter().any(|s| s == svc) {
            actions.restore.push(svc.clone());
        } else {
            actions.drop.push(svc.clone());
        }
    }

    actions
}

/// Snapshot the current DNS-relevant environment. The service list itself
/// must be trustworthy: a healthy macOS always reports at least one network
/// service, so a failed or empty listing is a degraded read, not "all
/// services vanished" — returning it as fact would make `plan_dns_actions`
/// classify every owned service as vanished and drop (not restore) its saved
/// original. So a failed or empty listing aborts the snapshot. Everything
/// else — per-service DNS reads, the primary-service lookup — still degrades
/// to empty/`None` rather than aborting, mirroring `macos_local_connected_subnets`.
#[cfg(target_os = "macos")]
fn macos_current_dns_fingerprint() -> anyhow::Result<MacosDnsFingerprint> {
    let mut services = list_macos_network_services().context("listing macOS network services")?;
    if services.is_empty() {
        anyhow::bail!("networksetup -listallnetworkservices returned no services");
    }
    services.sort();
    services.dedup();

    let mut observed = Vec::with_capacity(services.len());
    for svc in &services {
        // None on error → treat as "unknown/unset"; never panic the tick.
        let dns = get_macos_dns_servers(svc).ok().flatten();
        observed.push((svc.clone(), dns));
    }

    Ok(MacosDnsFingerprint {
        primary_service: macos_primary_service(),
        services,
        observed,
    })
}

/// Read a service's current DNS + search domains and wrap them for later
/// restore. When the service already shows the tunnel's DNS, its true original
/// is gone — a prior run set it and never cleaned up (crash, kill, or
/// `make uninstall`) — so adopt it with an **empty** original: teardown then
/// clears the stray back to DHCP instead of stranding an unreachable tunnel
/// resolver. We still never record the tunnel's own servers as the "original"
/// (`transparent_dns.md` §6.1); the recovery target is Empty, not tunnel DNS.
/// The tunnel resolver is only reachable through the tunnel, so a service
/// pinned to it without a tunnel is broken by definition — Empty is the only
/// safe restore.
#[cfg(target_os = "macos")]
fn capture_macos_dns_service(
    service: &str,
    tunnel_dns: &[String],
) -> anyhow::Result<MacosDnsServiceState> {
    let dns = get_macos_dns_servers(service)?;
    if dns.as_deref() == Some(tunnel_dns) {
        return Ok(MacosDnsServiceState {
            service: service.to_string(),
            dns_servers: None,
            search_domains: None,
        });
    }
    let search = get_macos_search_domains(service)?;
    Ok(MacosDnsServiceState {
        service: service.to_string(),
        dns_servers: dns,
        search_domains: search,
    })
}

/// Re-apply DNS when the host DNS environment changed (roam, DHCP renewal, a new
/// or vanished service, a primary-service change). Cheap and silent when nothing
/// changed; expressive when it acts. Mirrors `macos_reconcile_routes`.
#[cfg(target_os = "macos")]
fn macos_reconcile_dns(state: &MacosCleanupState) -> bool {
    let inputs = &state.reconcile;
    if inputs.dns_servers.is_empty() {
        return false; // VPN promotes no DNS -> nothing to own.
    }

    let fingerprint = match macos_current_dns_fingerprint() {
        Ok(fingerprint) => fingerprint,
        // A degraded or failed listing must not be read as "all owned services
        // vanished" (see `macos_current_dns_fingerprint`): skip this tick rather
        // than acting on a half-built fingerprint, mirroring the route guard.
        Err(error) => {
            warn!(
                interface = inputs.interface,
                error = %error,
                "userspace_helper_dns_fingerprint_failed"
            );
            return false;
        }
    };

    // If the tunnel's own DNS server now lives inside a directly-connected LAN,
    // its route is excluded from the tunnel and the server is unreachable through
    // it. We must pull tunnel DNS back, but joining such a LAN need not change the
    // DNS fingerprint at all, so this is computed before the identity guard below.
    let local_subnets = macos_local_connected_subnets(&inputs.interface);
    let collision = macos_dns_server_in_local_subnet(&inputs.dns_servers, &local_subnets);

    let mut dns = state
        .dns
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    // Normally skip when the DNS environment is unchanged. But still act when a
    // collision means we own services that now need restoring to their originals.
    let must_pull_back = collision.is_some() && !dns.services.is_empty();
    if fingerprint == dns.fingerprint && !must_pull_back {
        return false; // cheap identity check, same guard as routes.
    }

    let previous = dns.fingerprint.clone();
    info!(
        interface = inputs.interface,
        old_primary = ?previous.primary_service,
        new_primary = ?fingerprint.primary_service,
        old_services = previous.services.len(),
        new_services = fingerprint.services.len(),
        "userspace_helper_dns_change_detected"
    );

    // On a collision, target nothing so every owned service is restored to its
    // original DNS rather than left pointing at an unreachable (or
    // LAN-impersonatable) address.
    let targets = match collision {
        Some((server, (subnet_ip, subnet_prefix))) => {
            warn!(
                interface = inputs.interface,
                dns_server = %server,
                local_subnet = %format!("{subnet_ip}/{subnet_prefix}"),
                "userspace_helper_dns_unreachable_local_lan"
            );
            Vec::new()
        }
        None => dns_target_services(DNS_POLICY, &fingerprint),
    };
    let owned: Vec<String> = dns.services.iter().map(|s| s.service.clone()).collect();
    let actions = plan_dns_actions(&inputs.dns_servers, &fingerprint, &owned, &targets);

    let (mut applied, mut captured, mut restored, mut dropped, mut errors) =
        (0usize, 0usize, 0usize, 0usize, 0usize);

    // (a) Capture originals for services we are about to own. If a capture
    // fails we must not overwrite that service's DNS below: with no saved
    // original, teardown could never restore the user's settings.
    let mut capture_failed: Vec<&str> = Vec::new();
    for svc in &actions.capture {
        match capture_macos_dns_service(svc, &inputs.dns_servers) {
            Ok(saved) => {
                dns.services.push(saved);
                captured += 1;
            }
            Err(_) => {
                errors += 1;
                capture_failed.push(svc.as_str());
            }
        }
    }

    // (b) Release services we no longer target: restore the ones still present,
    // drop the ones whose host service has vanished. Keep the saved original if
    // a restore fails so teardown (or a later tick) can retry; dropping it would
    // strand the user's DNS settings.
    for svc in &actions.restore {
        let saved = dns.services.iter().find(|s| &s.service == svc).cloned();
        match saved {
            Some(saved) => {
                if restore_macos_dns_service(&saved).is_ok() {
                    restored += 1;
                    dns.services.retain(|s| &s.service != svc);
                } else {
                    errors += 1; // keep saved state for a retry
                }
            }
            None => dns.services.retain(|s| &s.service != svc),
        }
    }
    for svc in &actions.drop {
        dropped += 1;
        dns.services.retain(|s| &s.service != svc);
    }

    // (c) (Re-)assert tunnel DNS on every target whose observed DNS has drifted,
    // except services whose original we failed to capture this tick.
    for svc in &actions.apply {
        if capture_failed.contains(&svc.as_str()) {
            continue; // never overwrite DNS we couldn't back up
        }
        if set_macos_dns_servers(svc, &inputs.dns_servers).is_ok()
            && set_macos_search_domains_empty(svc).is_ok()
        {
            applied += 1;
        } else {
            errors += 1;
        }
    }

    // Re-snapshot only when we actually changed system DNS, so the stored
    // fingerprint matches reality and the next tick doesn't see a spurious diff.
    // Captures and drops don't touch system DNS, so the pre-action snapshot is
    // still accurate when nothing was applied or restored.
    dns.fingerprint = if applied + restored > 0 {
        // On a failed re-snapshot, fall back to the pre-action fingerprint. It's
        // stale (it won't reflect the change we just made), but that only makes
        // the next tick re-detect the same drift and re-run idempotent actions —
        // safe, unlike trusting a degraded read as the new baseline.
        macos_current_dns_fingerprint().unwrap_or_else(|error| {
            warn!(
                interface = inputs.interface,
                error = %error,
                "userspace_helper_dns_fingerprint_resnapshot_failed"
            );
            fingerprint
        })
    } else {
        fingerprint
    };
    info!(
        interface = inputs.interface,
        applied, captured, restored, dropped, errors, "userspace_helper_dns_reconcile_applied"
    );
    true
}

/// The human-readable network service name that currently owns the default
/// route / global resolver, or `None`. `scutil` speaks BSD device names (en0)
/// and `networksetup` speaks service names ("Wi-Fi"); bridge them via the
/// service order, matching on device.
#[cfg(target_os = "macos")]
fn macos_primary_service() -> Option<String> {
    let primary_if = scutil_global_primary_interface()?;
    macos_service_name_for_device(&primary_if)
}

/// Ask `scutil` for the primary interface (BSD device, e.g. "en0").
#[cfg(target_os = "macos")]
fn scutil_global_primary_interface() -> Option<String> {
    use std::io::Write;
    use std::process::Stdio;

    let mut child = Command::new("scutil")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child
        .stdin
        .as_mut()?
        .write_all(b"show State:/Network/Global/IPv4\n")
        .ok()?;
    // `wait_with_output` closes stdin first, so scutil sees EOF and exits.
    let output = child.wait_with_output().ok()?;
    if !output.status.success() {
        return None;
    }
    parse_scutil_primary_interface(&String::from_utf8_lossy(&output.stdout))
}

/// Parse `PrimaryInterface : en0` out of `scutil show State:/Network/Global/IPv4`.
#[cfg(target_os = "macos")]
fn parse_scutil_primary_interface(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("PrimaryInterface") {
            let value = rest.trim_start_matches([' ', ':']).trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

/// Map a BSD device ("en0") to its `networksetup` service name ("Wi-Fi") via
/// `networksetup -listnetworkserviceorder`.
#[cfg(target_os = "macos")]
fn macos_service_name_for_device(device: &str) -> Option<String> {
    let output = run_command_capture_output("networksetup", &["-listnetworkserviceorder"]).ok()?;
    if !output.status.success() {
        return None;
    }
    parse_service_name_for_device(&String::from_utf8_lossy(&output.stdout), device)
}

/// Parse `networksetup -listnetworkserviceorder` output, returning the service
/// name whose `(Hardware Port: …, Device: <device>)` line matches `device`.
/// Pseudo-services without a real device (e.g. VPNs) are skipped.
#[cfg(target_os = "macos")]
fn parse_service_name_for_device(text: &str, device: &str) -> Option<String> {
    let mut current_name: Option<String> = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(hw) = trimmed.strip_prefix("(Hardware Port:") {
            if parse_device_from_hw_line(hw).as_deref() == Some(device) {
                return current_name.clone();
            }
        } else if trimmed.starts_with('(') {
            // Service line: "(1) Wi-Fi" or "(*) Wi-Fi" (asterisk == disabled).
            if let Some((_, name)) = trimmed.split_once(')') {
                let name = name.trim();
                if !name.is_empty() {
                    current_name = Some(name.to_string());
                }
            }
        }
    }
    None
}

/// Extract the BSD device from the tail of a `(Hardware Port: …, Device: enX)`
/// line (the part passed in is everything after "(Hardware Port:").
#[cfg(target_os = "macos")]
fn parse_device_from_hw_line(hw: &str) -> Option<String> {
    let idx = hw.find("Device:")?;
    let device = hw[idx + "Device:".len()..]
        .trim()
        .trim_end_matches(')')
        .trim();
    if device.is_empty() {
        None
    } else {
        Some(device.to_string())
    }
}

/// Emit a full route + DNS overview. Called once after connect setup and after
/// route/DNS reconciliation work, so the log shows the resulting tunnel state.
#[cfg(target_os = "macos")]
fn log_macos_network_overview(reason: &str, state: &MacosCleanupState) {
    let inputs = &state.reconcile;
    let (routes, route_fingerprint) = {
        let routing = state
            .routing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (routing.routes_added.clone(), routing.fingerprint.clone())
    };
    let (owned_dns, dns_fingerprint) = {
        let dns = state
            .dns
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        (dns.services.clone(), dns.fingerprint.clone())
    };
    // Snapshot the host's *foreign* tunnels and effective resolver so the
    // overview shows what else is steering traffic/DNS (e.g. Tailscale). These
    // are the parts that took a long debugging session to surface by hand.
    let foreign = MacosForeignSnapshot {
        tunnels: macos_foreign_tunnels(&inputs.interface),
        global_resolvers: macos_global_resolvers(),
        tailscaled_present: tailscaled_socket_present(),
    };
    let table = format_macos_network_overview_table(
        inputs,
        &routes,
        &route_fingerprint,
        &owned_dns,
        &dns_fingerprint,
        &foreign,
    );
    info!(reason, interface = inputs.interface, "\n{table}\n");
}

#[cfg(target_os = "macos")]
fn format_macos_network_overview_table(
    inputs: &MacosReconcileInputs,
    routes: &[MacosRoute],
    route_fingerprint: &MacosNetworkFingerprint,
    owned_dns: &[MacosDnsServiceState],
    dns_fingerprint: &MacosDnsFingerprint,
    foreign: &MacosForeignSnapshot,
) -> String {
    let mut lines = vec![
        "tunmux network overview".to_string(),
        format!(
            "interface={} endpoint={} endpoint_pin={} gateway={} local_subnets={}",
            inputs.interface,
            inputs.endpoint,
            if inputs.endpoint_needs_pin {
                "enabled"
            } else {
                "disabled"
            },
            route_fingerprint
                .endpoint_gateway
                .as_deref()
                .unwrap_or("none"),
            format_subnets(&route_fingerprint.local_subnets)
        ),
        String::new(),
        "Routes".to_string(),
    ];
    lines.extend(format_table(
        &["DESTINATION", "VIA", "FAMILY", "STATUS"],
        &macos_route_overview_rows(routes),
    ));
    lines.push(String::new());
    let dns_collision =
        macos_dns_server_in_local_subnet(&inputs.dns_servers, &route_fingerprint.local_subnets);
    let mut dns_header = format!(
        "DNS tunnel_servers={} primary_service={}",
        format_list(&inputs.dns_servers),
        dns_fingerprint.primary_service.as_deref().unwrap_or("none")
    );
    if let Some((server, (subnet_ip, subnet_prefix))) = dns_collision {
        dns_header.push_str(&format!(
            " UNREACHABLE: {server} is inside local LAN {subnet_ip}/{subnet_prefix}, tunnel DNS pulled back"
        ));
    }
    lines.push(dns_header);
    lines.extend(format_table_with_dimmed_rows(
        &[
            "SERVICE",
            "ROLE",
            "LIVE DNS",
            "OWNED",
            "ORIGINAL DNS",
            "STATUS",
        ],
        &macos_dns_overview_rows(inputs, owned_dns, dns_fingerprint, dns_collision.is_some()),
        macos_log_table_ansi_enabled(),
    ));

    // Effective system resolver: what macOS actually resolves through right now,
    // independent of per-service config. Flags the case that stranded a whole
    // debugging session — the global resolver is a tunnel DNS server that is no
    // longer the tunnel's (a leak), or some other resolver has taken over.
    lines.push(String::new());
    lines.push(format_system_resolver_line(
        &foreign.global_resolvers,
        &inputs.dns_servers,
    ));

    // Foreign tunnels: other VPN/utun interfaces sharing the host, plus a
    // userspace-Tailscale hint (it has no utun, so the socket is the only tell).
    lines.push(String::new());
    lines.push("Other tunnels (foreign VPN / utun interfaces)".to_string());
    lines.extend(format_table(
        &["INTERFACE", "MTU", "ADDRESSES", "NOTE"],
        &foreign_tunnel_overview_rows(&foreign.tunnels),
    ));
    lines.push(format!(
        "tailscaled={}",
        if foreign.tailscaled_present {
            "running (socket present; userspace mode has no utun of its own)"
        } else {
            "not detected"
        }
    ));

    lines.join("\n")
}

/// One-line summary of the effective system resolver and how it relates to the
/// tunnel's DNS. The mismatch/leak cases are the ones worth eyeballing.
#[cfg(target_os = "macos")]
fn format_system_resolver_line(global_resolvers: &[String], tunnel_dns: &[String]) -> String {
    let note = if global_resolvers.is_empty() {
        "none (DHCP/unset)"
    } else if global_resolvers == tunnel_dns {
        "matches tunnel DNS"
    } else if !tunnel_dns.is_empty() && global_resolvers.iter().any(|r| tunnel_dns.contains(r)) {
        "partially tunnel DNS — another resolver is also active"
    } else {
        "NOT the tunnel resolver — a foreign VPN/DHCP owns resolution"
    };
    format!("System resolver={} ({note})", format_list(global_resolvers))
}

/// Snapshot of the host environment *outside* tunmux's own routes/DNS — the
/// other VPNs and the effective resolver — bundled so the overview formatter
/// stays a single, testable call.
#[cfg(target_os = "macos")]
struct MacosForeignSnapshot {
    tunnels: Vec<ForeignTunnel>,
    global_resolvers: Vec<String>,
    tailscaled_present: bool,
}

/// A non-tunmux tunnel interface sharing the host (another VPN). Surfaced in the
/// overview so an interfering peer (kernel-mode Tailscale, another WireGuard,
/// IPSec, …) is visible instead of needing manual `ifconfig`/`netstat`.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq)]
struct ForeignTunnel {
    interface: String,
    mtu: Option<u32>,
    /// Routable addresses (IPv4 + non-link-local IPv6). Empty == link-local only.
    addresses: Vec<String>,
    /// Carries a 100.64.0.0/10 (CGNAT) address — the Tailscale tailnet signature.
    cgnat: bool,
}

#[cfg(target_os = "macos")]
fn macos_foreign_tunnels(own_interface: &str) -> Vec<ForeignTunnel> {
    let output = match Command::new("ifconfig").output() {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    parse_foreign_tunnels(&String::from_utf8_lossy(&output.stdout), own_interface)
}

/// True for interface names that belong to a tunnel/VPN (vs en0, lo0, bridge…).
#[cfg(target_os = "macos")]
fn is_tunnel_interface_name(name: &str) -> bool {
    const PREFIXES: [&str; 6] = ["utun", "tun", "tap", "ppp", "ipsec", "wg"];
    PREFIXES.iter().any(|p| name.starts_with(p))
}

/// 100.64.0.0/10 — RFC 6598 CGNAT, which Tailscale claims wholesale for tailnets.
#[cfg(target_os = "macos")]
fn is_cgnat_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

/// Parse `ifconfig` into the foreign tunnel interfaces (UP, tunnel-named, not
/// our own). Pure so it can be unit-tested against captured fixtures.
#[cfg(target_os = "macos")]
fn parse_foreign_tunnels(ifconfig: &str, own_interface: &str) -> Vec<ForeignTunnel> {
    let mut tunnels: Vec<ForeignTunnel> = Vec::new();
    let mut current: Option<ForeignTunnel> = None;

    for line in ifconfig.lines() {
        if !line.starts_with(|c: char| c.is_whitespace()) {
            // Header for a new interface: flush the previous one first.
            if let Some(tunnel) = current.take() {
                tunnels.push(tunnel);
            }
            let Some((name, rest)) = line.split_once(':') else {
                continue;
            };
            let name = name.trim();
            if name != own_interface && is_tunnel_interface_name(name) && rest.contains("UP") {
                let mtu = rest
                    .split_whitespace()
                    .skip_while(|t| *t != "mtu")
                    .nth(1)
                    .and_then(|m| m.parse::<u32>().ok());
                current = Some(ForeignTunnel {
                    interface: name.to_string(),
                    mtu,
                    addresses: Vec::new(),
                    cgnat: false,
                });
            }
            continue;
        }
        let Some(tunnel) = current.as_mut() else {
            continue; // indented line for a non-qualifying interface
        };
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            if let Some(addr) = rest.split_whitespace().next() {
                if let Ok(ip) = addr.parse::<Ipv4Addr>() {
                    tunnel.addresses.push(addr.to_string());
                    tunnel.cgnat |= is_cgnat_v4(ip);
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("inet6 ") {
            if let Some(addr) = rest.split_whitespace().next() {
                let bare = addr.split('%').next().unwrap_or(addr);
                if let Ok(ip) = bare.parse::<Ipv6Addr>() {
                    // Skip link-local; it says nothing about what the tunnel routes.
                    if !ip.is_loopback() && (ip.segments()[0] & 0xffc0) != 0xfe80 {
                        tunnel.addresses.push(bare.to_string());
                    }
                }
            }
        }
    }
    if let Some(tunnel) = current.take() {
        tunnels.push(tunnel);
    }
    tunnels
}

#[cfg(target_os = "macos")]
fn foreign_tunnel_overview_rows(tunnels: &[ForeignTunnel]) -> Vec<Vec<String>> {
    if tunnels.is_empty() {
        return vec![vec![
            "none".to_string(),
            "-".to_string(),
            "-".to_string(),
            "no other tunnels".to_string(),
        ]];
    }
    tunnels
        .iter()
        .map(|t| {
            vec![
                t.interface.clone(),
                t.mtu.map_or_else(|| "-".to_string(), |m| m.to_string()),
                if t.addresses.is_empty() {
                    "link-local only".to_string()
                } else {
                    t.addresses.join(", ")
                },
                if t.cgnat {
                    "CGNAT 100.64/10 (Tailscale?)".to_string()
                } else {
                    "-".to_string()
                },
            ]
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn macos_global_resolvers() -> Vec<String> {
    let output = match Command::new("scutil").arg("--dns").output() {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    parse_scutil_global_resolvers(&String::from_utf8_lossy(&output.stdout))
}

/// Extract resolvers from the first (default) resolver block of `scutil --dns` —
/// the ones macOS uses for un-scoped lookups. Pure for testability.
#[cfg(target_os = "macos")]
fn parse_scutil_global_resolvers(text: &str) -> Vec<String> {
    let mut resolvers = Vec::new();
    let mut in_first_resolver = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("resolver #") {
            if in_first_resolver {
                break; // past the default block; later blocks are scoped/secondary
            }
            in_first_resolver = trimmed == "resolver #1";
            continue;
        }
        if in_first_resolver {
            if let Some(value) = trimmed.strip_prefix("nameserver[") {
                if let Some((_, addr)) = value.split_once("] : ") {
                    let addr = addr.trim().to_string();
                    if !resolvers.contains(&addr) {
                        resolvers.push(addr);
                    }
                }
            }
        }
    }
    resolvers
}

/// tailscaled (kernel or userspace) registers this socket while running. Cheap
/// presence check — userspace Tailscale has no utun, so this is the only tell.
#[cfg(target_os = "macos")]
fn tailscaled_socket_present() -> bool {
    std::path::Path::new("/var/run/tailscaled.socket").exists()
}

#[cfg(target_os = "macos")]
fn macos_route_overview_rows(routes: &[MacosRoute]) -> Vec<Vec<String>> {
    if routes.is_empty() {
        return vec![vec![
            "none".to_string(),
            "-".to_string(),
            "-".to_string(),
            "no routes owned".to_string(),
        ]];
    }
    routes
        .iter()
        .map(|route| {
            vec![
                route.destination.clone(),
                match (&route.gateway, &route.interface) {
                    (Some(gateway), _) => format!("gateway {gateway}"),
                    (None, Some(interface)) => format!("interface {interface}"),
                    (None, None) => "system".to_string(),
                },
                if route.is_ipv6 { "IPv6" } else { "IPv4" }.to_string(),
                "owned".to_string(),
            ]
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn macos_dns_overview_rows(
    inputs: &MacosReconcileInputs,
    owned_dns: &[MacosDnsServiceState],
    dns_fingerprint: &MacosDnsFingerprint,
    dns_unreachable: bool,
) -> Vec<(Vec<String>, bool)> {
    if dns_fingerprint.services.is_empty() {
        return vec![(
            vec![
                "none".to_string(),
                "-".to_string(),
                "-".to_string(),
                "no".to_string(),
                "-".to_string(),
                "no services observed".to_string(),
            ],
            true,
        )];
    }

    // A collision pulls tunnel DNS back, so nothing is targeted; reflect that here
    // too, otherwise the table contradicts the reconciler's actual decision.
    let targets = if dns_unreachable {
        Vec::new()
    } else {
        dns_target_services(DNS_POLICY, dns_fingerprint)
    };
    // No settled primary (a transient between networks) means the PrimaryOnly
    // fallback targets every service, so there is no single active resolver to
    // highlight — grey the whole block as unsettled, like the pull-back case.
    let dormant = dns_unreachable || dns_fingerprint.primary_service.is_none();
    dns_fingerprint
        .services
        .iter()
        .map(|service| {
            let live_dns = dns_fingerprint
                .observed
                .iter()
                .find(|(observed_service, _)| observed_service == service)
                .and_then(|(_, servers)| servers.as_ref());
            let owned = owned_dns.iter().find(|state| &state.service == service);
            let targeted = targets.iter().any(|target| target == service);
            let live_matches_tunnel =
                live_dns.map(Vec::as_slice) == Some(inputs.dns_servers.as_slice());
            let status = match (targeted, owned.is_some(), live_matches_tunnel) {
                (true, true, true) => "tunnel DNS active",
                (true, true, false) => "owned; pending reapply",
                (true, false, true) => "already tunnel DNS",
                (true, false, false) => "target; not owned",
                (false, true, _) => "owned; pending restore",
                // Live DNS still shows the tunnel server, but it now sits on the
                // local LAN — that address is no longer the VPN resolver.
                (false, false, true) if dns_unreachable => "stale tunnel DNS on LAN",
                (false, false, _) => "not targeted",
            };
            (
                vec![
                    service.clone(),
                    if dns_fingerprint.primary_service.as_ref() == Some(service) {
                        "primary"
                    } else {
                        "secondary"
                    }
                    .to_string(),
                    live_dns.map_or_else(|| "empty".to_string(), |servers| format_list(servers)),
                    if owned.is_some() { "yes" } else { "no" }.to_string(),
                    owned
                        .and_then(|state| state.dns_servers.as_ref())
                        .map_or_else(|| "empty".to_string(), |servers| format_list(servers)),
                    status.to_string(),
                ],
                // Grey out inactive rows: the whole block when it is dormant
                // (pulled back, or no settled primary), else untargeted services.
                dormant || status == "not targeted",
            )
        })
        .collect()
}

#[cfg(target_os = "macos")]
fn macos_log_table_ansi_enabled() -> bool {
    let Some(value) = std::env::var_os(crate::logging::COLOR_ENV) else {
        return false;
    };
    matches!(
        value.to_string_lossy().to_ascii_lowercase().as_str(),
        "always" | "1" | "true" | "yes" | "on"
    )
}

#[cfg(target_os = "macos")]
fn format_table_with_dimmed_rows(
    headers: &[&str],
    rows: &[(Vec<String>, bool)],
    ansi: bool,
) -> Vec<String> {
    let plain_rows = rows.iter().map(|(row, _)| row.clone()).collect::<Vec<_>>();
    let mut lines = format_table(headers, &plain_rows);
    for (line, (_, dimmed)) in lines.iter_mut().skip(2).zip(rows.iter()) {
        if ansi && *dimmed {
            *line = format!("\x1b[2m{line}\x1b[0m");
        }
    }
    lines
}

#[cfg(target_os = "macos")]
fn format_table(headers: &[&str], rows: &[Vec<String>]) -> Vec<String> {
    let mut widths: Vec<usize> = headers.iter().map(|header| header.len()).collect();
    for row in rows {
        for (index, value) in row.iter().enumerate() {
            if let Some(width) = widths.get_mut(index) {
                *width = (*width).max(value.len());
            }
        }
    }

    let header = format_table_row(
        &headers
            .iter()
            .map(|header| header.to_string())
            .collect::<Vec<_>>(),
        &widths,
    );
    let separator = widths
        .iter()
        .map(|width| "-".repeat(*width))
        .collect::<Vec<_>>()
        .join("  ");
    let mut lines = vec![header, separator];
    lines.extend(rows.iter().map(|row| format_table_row(row, &widths)));
    lines
}

#[cfg(target_os = "macos")]
fn format_table_row(values: &[String], widths: &[usize]) -> String {
    values
        .iter()
        .enumerate()
        .map(|(index, value)| format!("{value:<width$}", width = widths[index]))
        .collect::<Vec<_>>()
        .join("  ")
}

/// Directly-connected subnets of up, non-loopback, non-point-to-point
/// interfaces (the physical LANs), excluding the tunnel itself.
#[cfg(target_os = "macos")]
fn macos_local_connected_subnets(tunnel_interface: &str) -> Vec<(IpAddr, u8)> {
    // Call ifconfig directly (not run_command_capture_output) to avoid emitting
    // a debug command log line on every reconcile tick.
    let output = match Command::new("ifconfig").output() {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut subnets = Vec::new();
    let mut interface_qualifies = false;
    for line in text.lines() {
        if !line.starts_with(|c: char| c.is_whitespace()) {
            // Interface header: "en0: flags=8863<UP,BROADCAST,...> mtu 1500".
            interface_qualifies = false;
            if let Some((name, rest)) = line.split_once(':') {
                interface_qualifies = name.trim() != tunnel_interface
                    && rest.contains("UP")
                    && !rest.contains("LOOPBACK")
                    && !rest.contains("POINTOPOINT");
            }
            continue;
        }
        if !interface_qualifies {
            continue;
        }
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            if let Some(subnet) = parse_ifconfig_inet4_subnet(rest) {
                subnets.push(subnet);
            }
        } else if let Some(rest) = trimmed.strip_prefix("inet6 ") {
            if let Some(subnet) = parse_ifconfig_inet6_subnet(rest) {
                subnets.push(subnet);
            }
        }
    }
    subnets.sort();
    subnets.dedup();
    subnets
}

#[cfg(target_os = "macos")]
fn parse_ifconfig_inet4_subnet(rest: &str) -> Option<(IpAddr, u8)> {
    let fields: Vec<&str> = rest.split_whitespace().collect();
    let ip: Ipv4Addr = fields.first()?.parse().ok()?;
    let mask_index = fields.iter().position(|field| *field == "netmask")?;
    let prefix = parse_macos_hex_netmask(fields.get(mask_index + 1)?)?;
    Some((macos_network_base(IpAddr::V4(ip), prefix), prefix))
}

#[cfg(target_os = "macos")]
fn parse_ifconfig_inet6_subnet(rest: &str) -> Option<(IpAddr, u8)> {
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // Strip any zone id, e.g. "fe80::1%en0".
    let address = fields.first()?.split('%').next()?;
    let ip: Ipv6Addr = address.parse().ok()?;
    // Skip link-local (fe80::/10) and loopback; they are not routable LANs.
    if ip.is_loopback() || (ip.segments()[0] & 0xffc0) == 0xfe80 {
        return None;
    }
    let prefix_index = fields.iter().position(|field| *field == "prefixlen")?;
    let prefix: u8 = fields.get(prefix_index + 1)?.parse().ok()?;
    Some((macos_network_base(IpAddr::V6(ip), prefix), prefix))
}

/// Convert a macOS hex netmask ("0xffffff00") to a prefix length.
#[cfg(target_os = "macos")]
fn parse_macos_hex_netmask(mask: &str) -> Option<u8> {
    let hex = mask
        .strip_prefix("0x")
        .or_else(|| mask.strip_prefix("0X"))?;
    Some(u32::from_str_radix(hex, 16).ok()?.count_ones() as u8)
}

#[cfg(target_os = "macos")]
fn format_subnets(subnets: &[(IpAddr, u8)]) -> String {
    if subnets.is_empty() {
        return "none".to_string();
    }
    subnets
        .iter()
        .map(|(ip, prefix)| format!("{ip}/{prefix}"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(target_os = "macos")]
fn format_list(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_string()
    } else {
        items.join(", ")
    }
}

#[cfg(target_os = "macos")]
fn get_macos_default_gateway(is_ipv6: bool) -> anyhow::Result<Option<String>> {
    let mut args = vec!["-n", "get"];
    if is_ipv6 {
        args.push("-inet6");
    }
    args.push("default");

    let output = Command::new("route")
        .args(args)
        .output()
        .context("failed to run route -n get default")?;
    if !output.status.success() {
        if is_ipv6 {
            return Ok(None);
        }
        anyhow::bail!("route -n get default failed");
    }
    let text = String::from_utf8_lossy(&output.stdout);
    for line in text.lines() {
        if let Some(value) = line.trim().strip_prefix("gateway:") {
            return Ok(Some(value.trim().to_string()));
        }
    }
    if is_ipv6 {
        Ok(None)
    } else {
        anyhow::bail!("default gateway not found")
    }
}

#[cfg(target_os = "macos")]
fn parse_cidr(value: &str) -> anyhow::Result<(IpAddr, u8)> {
    let (ip, prefix) = value
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("invalid cidr {}", value))?;
    let ip: IpAddr = ip
        .parse()
        .with_context(|| format!("invalid cidr IP {}", ip))?;
    let prefix: u8 = prefix
        .parse()
        .with_context(|| format!("invalid cidr prefix {}", prefix))?;
    Ok((ip, prefix))
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn subnet(value: &str) -> (IpAddr, u8) {
        let (ip, prefix) = parse_cidr(value).expect("valid cidr");
        (macos_network_base(ip, prefix), prefix)
    }

    #[test]
    fn macos_route_delete_uses_destination_kind_without_add_qualifiers() {
        let network = MacosRoute {
            is_ipv6: false,
            destination: "55.56.57.0/24".to_string(),
            interface: Some("utun9".to_string()),
            gateway: None,
        };
        assert_eq!(macos_route_target_kind(&network), "-net");

        let endpoint = MacosRoute {
            is_ipv6: false,
            destination: "23.88.101.22".to_string(),
            interface: None,
            gateway: Some("55.56.57.1".to_string()),
        };
        assert_eq!(macos_route_target_kind(&endpoint), "-host");

        let host_cidr = MacosRoute {
            is_ipv6: true,
            destination: "2001:db8::1/128".to_string(),
            interface: Some("utun9".to_string()),
            gateway: None,
        };
        assert_eq!(macos_route_target_kind(&host_cidr), "-host");
    }

    #[test]
    fn hex_netmask_converts_to_prefix() {
        assert_eq!(parse_macos_hex_netmask("0xffffff00"), Some(24));
        assert_eq!(parse_macos_hex_netmask("0xffff0000"), Some(16));
        assert_eq!(parse_macos_hex_netmask("0xffffffff"), Some(32));
        assert_eq!(parse_macos_hex_netmask("0x00000000"), Some(0));
        assert_eq!(parse_macos_hex_netmask("not-hex"), None);
    }

    #[test]
    fn endpoint_pinned_only_when_allowed_ips_cover_it() {
        let endpoint: IpAddr = "23.88.101.22".parse().unwrap();
        let split = vec!["100.64.0.0/24".to_string(), "55.56.57.0/24".to_string()];
        assert!(!macos_allowed_ips_cover_endpoint(&split, endpoint));
        let full = vec!["0.0.0.0/0".to_string()];
        assert!(macos_allowed_ips_cover_endpoint(&full, endpoint));
    }

    fn split_inputs() -> MacosReconcileInputs {
        MacosReconcileInputs {
            interface: "utun6".to_string(),
            endpoint: "23.88.101.22".parse().unwrap(),
            endpoint_is_ipv6: false,
            endpoint_needs_pin: false,
            allowed_ips: vec!["55.56.57.0/24".to_string(), "100.64.0.0/24".to_string()],
            dns_servers: vec!["100.64.1.1".to_string()],
            has_ipv4_address: true,
            has_ipv6_address: false,
        }
    }

    #[test]
    fn local_lan_is_excluded_but_returns_to_the_tunnel_on_a_different_lan() {
        let inputs = split_inputs();

        // Sitting in the home LAN: that subnet must NOT be routed into the tunnel.
        let home = MacosNetworkFingerprint {
            local_subnets: vec![subnet("55.56.57.0/24")],
            endpoint_gateway: None,
        };
        let dests: Vec<String> = macos_desired_routes(&inputs, &home)
            .into_iter()
            .map(|route| route.destination)
            .collect();
        assert!(!dests.iter().any(|d| d == "55.56.57.0/24"));
        assert!(dests.iter().any(|d| d == "100.64.0.0/24"));

        // After roaming elsewhere, 55.56.57.0/24 is remote again and IS tunnelled.
        let elsewhere = MacosNetworkFingerprint {
            local_subnets: vec![subnet("10.20.30.0/24")],
            endpoint_gateway: None,
        };
        let dests: Vec<String> = macos_desired_routes(&inputs, &elsewhere)
            .into_iter()
            .map(|route| route.destination)
            .collect();
        assert!(dests.iter().any(|d| d == "55.56.57.0/24"));
        assert!(dests.iter().any(|d| d == "100.64.0.0/24"));
    }

    #[test]
    fn containment_matches_equal_and_more_specific_routes_only() {
        let local = subnet("55.56.57.0/24");

        let equal = MacosRoute {
            is_ipv6: false,
            destination: "55.56.57.0/24".to_string(),
            interface: Some("utun6".to_string()),
            gateway: None,
        };
        assert!(macos_route_excluded_by_local_subnet(&equal, &[local]).is_some());

        let more_specific = MacosRoute {
            is_ipv6: false,
            destination: "55.56.57.128/25".to_string(),
            interface: Some("utun6".to_string()),
            gateway: None,
        };
        assert!(macos_route_excluded_by_local_subnet(&more_specific, &[local]).is_some());

        // A broader supernet is not treated as local (we do not split routes).
        let broader = MacosRoute {
            is_ipv6: false,
            destination: "55.56.0.0/16".to_string(),
            interface: Some("utun6".to_string()),
            gateway: None,
        };
        assert!(macos_route_excluded_by_local_subnet(&broader, &[local]).is_none());

        // Gatewayed (non-tunnel) routes are never excluded.
        let gatewayed = MacosRoute {
            is_ipv6: false,
            destination: "55.56.57.0/24".to_string(),
            interface: None,
            gateway: Some("10.0.0.1".to_string()),
        };
        assert!(macos_route_excluded_by_local_subnet(&gatewayed, &[local]).is_none());
    }

    #[test]
    fn dns_server_collision_with_local_subnet_is_detected() {
        let lan = subnet("55.56.57.0/24");

        // Tunnel DNS sits inside the joined LAN -> unreachable through the tunnel.
        let hit = macos_dns_server_in_local_subnet(&["55.56.57.2".to_string()], &[lan]);
        assert_eq!(hit, Some(("55.56.57.2".parse().unwrap(), lan)));

        // A DNS server outside every connected subnet is fine.
        assert!(
            macos_dns_server_in_local_subnet(&["9.9.9.9".to_string()], &[lan]).is_none(),
            "off-LAN DNS must not be treated as a collision"
        );

        // No connected subnets at all -> never a collision.
        assert!(macos_dns_server_in_local_subnet(&["55.56.57.2".to_string()], &[]).is_none());

        // Any colliding server in the list triggers pull-back; reports the first.
        let mixed = macos_dns_server_in_local_subnet(
            &["9.9.9.9".to_string(), "55.56.57.2".to_string()],
            &[lan],
        );
        assert_eq!(mixed, Some(("55.56.57.2".parse().unwrap(), lan)));
    }

    #[test]
    fn overview_relabels_unreachable_dns_instead_of_claiming_it_is_active() {
        let mut inputs = split_inputs();
        inputs.dns_servers = vec!["55.56.57.2".to_string()];
        // Every service shows the tunnel DNS; none captured (owned) by us.
        let fp = dns_fp(
            Some("Wi-Fi"),
            &[
                ("Wi-Fi", Some(&["55.56.57.2"])),
                ("Thunderbolt Bridge", Some(&["55.56.57.2"])),
            ],
        );
        let status = |rows: &[(Vec<String>, bool)], svc: &str| -> (String, bool) {
            rows.iter()
                .find(|(cols, _)| cols[0] == svc)
                .map(|(cols, dimmed)| (cols[5].clone(), *dimmed))
                .expect("service row present")
        };

        // Reachable: the primary genuinely shows tunnel DNS; a secondary is just
        // untargeted (and dimmed) under PrimaryOnly.
        let healthy = macos_dns_overview_rows(&inputs, &[], &fp, false);
        assert_eq!(
            status(&healthy, "Wi-Fi"),
            ("already tunnel DNS".into(), false)
        );
        assert_eq!(
            status(&healthy, "Thunderbolt Bridge"),
            ("not targeted".into(), true)
        );

        // Collision: the same address is now a LAN host, so no row may claim the
        // tunnel DNS is in use, and the whole dormant block is dimmed.
        let pulled_back = macos_dns_overview_rows(&inputs, &[], &fp, true);
        assert_eq!(
            status(&pulled_back, "Wi-Fi"),
            ("stale tunnel DNS on LAN".into(), true)
        );
        assert_eq!(
            status(&pulled_back, "Thunderbolt Bridge"),
            ("stale tunnel DNS on LAN".into(), true)
        );

        // Transient with no settled primary: PrimaryOnly falls back to all
        // services, but with no active resolver the whole block is greyed.
        let no_primary = dns_fp(
            None,
            &[
                ("Wi-Fi", Some(&["55.56.57.2"])),
                ("Thunderbolt Bridge", Some(&["55.56.57.2"])),
            ],
        );
        let unsettled = macos_dns_overview_rows(&inputs, &[], &no_primary, false);
        assert_eq!(
            status(&unsettled, "Wi-Fi"),
            ("already tunnel DNS".into(), true)
        );
        assert_eq!(
            status(&unsettled, "Thunderbolt Bridge"),
            ("already tunnel DNS".into(), true)
        );
    }

    // --- foreign tunnels & system resolver overview ---

    #[test]
    fn parse_foreign_tunnels_excludes_self_and_non_tunnels_flags_cgnat() {
        // utun4 is ours; utun5 is a foreign link-local-only tunnel; utun6 carries
        // a CGNAT address (Tailscale-ish); en0/lo0 are not tunnels.
        let ifconfig = "\
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.20 netmask 0xffffff00 broadcast 192.168.1.255
utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1384
\tinet 100.64.1.2 --> 100.64.1.2 netmask 0xffffffff
utun5: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet6 fe80::b18c:30f5:afb3:2cfd%utun5 prefixlen 64 scopeid 0x1b
utun6: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1280
\tinet 100.96.10.5 --> 100.96.10.5 netmask 0xffffffff
\tinet6 fe80::dead%utun6 prefixlen 64 scopeid 0x1c
utun7: flags=0<> mtu 1500
\tinet 10.9.9.9 netmask 0xffffffff
";
        let tunnels = parse_foreign_tunnels(ifconfig, "utun4");

        assert_eq!(
            tunnels,
            vec![
                ForeignTunnel {
                    interface: "utun5".to_string(),
                    mtu: Some(1380),
                    addresses: vec![], // link-local only
                    cgnat: false,
                },
                ForeignTunnel {
                    interface: "utun6".to_string(),
                    mtu: Some(1280),
                    addresses: vec!["100.96.10.5".to_string()],
                    cgnat: true,
                },
            ]
        );
        // utun4 (self) excluded; en0/lo0 not tunnels; utun7 is DOWN (no UP flag).
        assert!(!tunnels.iter().any(|t| t.interface == "utun4"));
        assert!(!tunnels.iter().any(|t| t.interface == "utun7"));
    }

    #[test]
    fn foreign_tunnel_rows_render_empty_and_cgnat() {
        assert_eq!(
            foreign_tunnel_overview_rows(&[]),
            vec![vec![
                "none".to_string(),
                "-".to_string(),
                "-".to_string(),
                "no other tunnels".to_string()
            ]]
        );
        let rows = foreign_tunnel_overview_rows(&[ForeignTunnel {
            interface: "utun6".to_string(),
            mtu: Some(1280),
            addresses: vec!["100.96.10.5".to_string()],
            cgnat: true,
        }]);
        assert_eq!(rows[0][0], "utun6");
        assert_eq!(rows[0][1], "1280");
        assert_eq!(rows[0][3], "CGNAT 100.64/10 (Tailscale?)");
    }

    #[test]
    fn parse_scutil_global_resolvers_takes_only_the_default_block() {
        let text = "\
DNS configuration

resolver #1
  nameserver[0] : 55.56.57.2
  nameserver[1] : 55.56.57.3
  flags    : Request A records

resolver #2
  domain   : local
  nameserver[0] : 224.0.0.251

DNS configuration (for scoped queries)

resolver #1
  nameserver[0] : 8.8.8.8
";
        assert_eq!(
            parse_scutil_global_resolvers(text),
            vec!["55.56.57.2".to_string(), "55.56.57.3".to_string()]
        );
    }

    #[test]
    fn system_resolver_line_flags_match_foreign_and_empty() {
        let tunnel = vec!["55.56.57.2".to_string()];
        assert!(
            format_system_resolver_line(&["55.56.57.2".to_string()], &tunnel)
                .contains("matches tunnel DNS")
        );
        assert!(
            format_system_resolver_line(&["1.1.1.1".to_string()], &tunnel)
                .contains("NOT the tunnel resolver")
        );
        assert!(format_system_resolver_line(
            &["55.56.57.2".to_string(), "1.1.1.1".to_string()],
            &tunnel
        )
        .contains("partially tunnel DNS"));
        assert!(format_system_resolver_line(&[], &tunnel).contains("none (DHCP/unset)"));
    }

    // --- DNS reconciler ---

    fn dns_fp(primary: Option<&str>, observed: &[(&str, Option<&[&str]>)]) -> MacosDnsFingerprint {
        let observed: Vec<(String, Option<Vec<String>>)> = observed
            .iter()
            .map(|(svc, dns)| {
                (
                    svc.to_string(),
                    dns.map(|servers| servers.iter().map(|s| s.to_string()).collect()),
                )
            })
            .collect();
        let mut services: Vec<String> = observed.iter().map(|(s, _)| s.clone()).collect();
        services.sort();
        services.dedup();
        MacosDnsFingerprint {
            primary_service: primary.map(str::to_string),
            services,
            observed,
        }
    }

    #[test]
    fn dns_target_services_honours_policy_and_falls_back() {
        let fp = dns_fp(
            Some("Wi-Fi"),
            &[
                ("Ethernet", Some(&["1.1.1.1"])),
                ("Wi-Fi", Some(&["1.1.1.1"])),
            ],
        );

        // AllServices targets every service.
        assert_eq!(
            dns_target_services(DnsPolicy::AllServices, &fp),
            vec!["Ethernet".to_string(), "Wi-Fi".to_string()]
        );

        // PrimaryOnly targets just the primary.
        assert_eq!(
            dns_target_services(DnsPolicy::PrimaryOnly, &fp),
            vec!["Wi-Fi".to_string()]
        );

        // PrimaryOnly with no detectable primary falls back to all services.
        let no_primary = dns_fp(None, &[("Wi-Fi", None), ("Ethernet", None)]);
        assert_eq!(
            dns_target_services(DnsPolicy::PrimaryOnly, &no_primary),
            vec!["Ethernet".to_string(), "Wi-Fi".to_string()]
        );

        // PrimaryOnly whose primary isn't a current service also falls back.
        let stale_primary = dns_fp(Some("Bogus"), &[("Wi-Fi", None)]);
        assert_eq!(
            dns_target_services(DnsPolicy::PrimaryOnly, &stale_primary),
            vec!["Wi-Fi".to_string()]
        );
    }

    fn tunnel() -> Vec<String> {
        vec!["100.64.0.1".to_string()]
    }

    #[test]
    fn plan_dns_new_primary_captures_and_restores_previous() {
        // Roamed Wi-Fi -> Ethernet under PrimaryOnly: own Wi-Fi, target Ethernet.
        let fp = dns_fp(
            Some("Ethernet"),
            &[
                ("Ethernet", Some(&["192.168.1.1"])), // native DHCP DNS
                ("Wi-Fi", Some(&["100.64.0.1"])),     // still has our tunnel DNS
            ],
        );
        let targets = dns_target_services(DnsPolicy::PrimaryOnly, &fp);
        let actions = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], &targets);

        assert_eq!(actions.capture, vec!["Ethernet".to_string()]);
        assert_eq!(actions.apply, vec!["Ethernet".to_string()]);
        assert_eq!(actions.restore, vec!["Wi-Fi".to_string()]);
        assert!(actions.drop.is_empty());
    }

    #[test]
    fn plan_dns_clobber_reapplies_without_recapturing() {
        // configd reverted our DNS on an owned, still-targeted service.
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["192.168.1.1"]))]);
        let targets = dns_target_services(DnsPolicy::PrimaryOnly, &fp);
        let actions = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], &targets);

        assert!(actions.capture.is_empty()); // already owned → keep original
        assert_eq!(actions.apply, vec!["Wi-Fi".to_string()]);
        assert!(actions.restore.is_empty());
        assert!(actions.drop.is_empty());
    }

    #[test]
    fn plan_dns_new_service_captured_under_all_services() {
        let fp = dns_fp(
            Some("Wi-Fi"),
            &[
                ("Wi-Fi", Some(&["100.64.0.1"])), // owned, already tunnel
                ("Tether", Some(&["10.0.0.1"])),  // new service with native DNS
            ],
        );
        let targets = dns_target_services(DnsPolicy::AllServices, &fp);
        let actions = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], &targets);

        assert_eq!(actions.capture, vec!["Tether".to_string()]);
        assert_eq!(actions.apply, vec!["Tether".to_string()]);
        assert!(actions.restore.is_empty());
        assert!(actions.drop.is_empty());
    }

    #[test]
    fn plan_dns_vanished_service_is_dropped_not_restored() {
        // We owned "Tether" but it's gone from the current services.
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["100.64.0.1"]))]);
        let targets = dns_target_services(DnsPolicy::PrimaryOnly, &fp);
        let actions = plan_dns_actions(
            &tunnel(),
            &fp,
            &["Wi-Fi".to_string(), "Tether".to_string()],
            &targets,
        );

        assert_eq!(actions.drop, vec!["Tether".to_string()]);
        assert!(actions.restore.is_empty());
        assert!(actions.capture.is_empty());
        assert!(actions.apply.is_empty());
    }

    #[test]
    fn plan_dns_steady_state_is_a_no_op() {
        // Primary already shows tunnel DNS and is owned → nothing to do.
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["100.64.0.1"]))]);
        let targets = dns_target_services(DnsPolicy::PrimaryOnly, &fp);
        let actions = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], &targets);
        assert_eq!(actions, DnsActions::default());
    }

    #[test]
    fn plan_dns_adopts_leaked_tunnel_dns_on_unowned_target() {
        // A prior run left tunnel DNS on the primary but we don't own it (its
        // saved original was lost to a crash/kill/uninstall). Capture it so
        // teardown can restore it to Empty — otherwise the unreachable tunnel
        // resolver is stranded forever. Differs from the owned steady state:
        // here `owned` is empty.
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["100.64.0.1"]))]);
        let targets = dns_target_services(DnsPolicy::PrimaryOnly, &fp);
        let actions = plan_dns_actions(&tunnel(), &fp, &[], &targets);

        assert_eq!(actions.capture, vec!["Wi-Fi".to_string()]); // adopt the leak
        assert!(actions.apply.is_empty()); // already tunnel DNS; nothing to re-assert
        assert!(actions.restore.is_empty());
        assert!(actions.drop.is_empty());
    }

    #[test]
    fn plan_dns_partial_overlap_is_not_a_match() {
        // VPN [100.64.0.1, 8.8.8.8] vs observed [100.64.0.1] is not equal → apply.
        let tunnel = vec!["100.64.0.1".to_string(), "8.8.8.8".to_string()];
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["100.64.0.1"]))]);
        let targets = dns_target_services(DnsPolicy::PrimaryOnly, &fp);
        let actions = plan_dns_actions(&tunnel, &fp, &[], &targets);
        assert_eq!(actions.apply, vec!["Wi-Fi".to_string()]);
        assert_eq!(actions.capture, vec!["Wi-Fi".to_string()]);
    }

    #[test]
    fn parse_scutil_primary_interface_extracts_device() {
        let output = "\
<dictionary> {
  PrimaryInterface : en0
  PrimaryService : 1A2B3C4D-0000-1111-2222-333344445555
  Router : 192.168.1.1
}
";
        assert_eq!(
            parse_scutil_primary_interface(output).as_deref(),
            Some("en0")
        );
        assert_eq!(
            parse_scutil_primary_interface("No such key").as_deref(),
            None
        );
    }

    #[test]
    fn parse_service_name_for_device_maps_devices_and_ignores_pseudo_services() {
        let output = "\
An asterisk (*) denotes that a network service is disabled.
(1) Wi-Fi
(Hardware Port: Wi-Fi, Device: en0)

(2) Thunderbolt Bridge
(Hardware Port: Thunderbolt Bridge, Device: bridge0)

(3) USB 10/100/1000 LAN
(Hardware Port: USB 10/100/1000 LAN, Device: en5)

(*) VPN (Cisco IPSec)
(Hardware Port: VPN (Cisco IPSec), Device: )
";
        assert_eq!(
            parse_service_name_for_device(output, "en0").as_deref(),
            Some("Wi-Fi")
        );
        assert_eq!(
            parse_service_name_for_device(output, "bridge0").as_deref(),
            Some("Thunderbolt Bridge")
        );
        assert_eq!(
            parse_service_name_for_device(output, "en5").as_deref(),
            Some("USB 10/100/1000 LAN")
        );
        // Unknown device and the device-less VPN pseudo-service yield nothing.
        assert_eq!(parse_service_name_for_device(output, "en9"), None);
    }

    #[test]
    fn parse_device_from_hw_line_handles_present_and_empty() {
        assert_eq!(
            parse_device_from_hw_line(" Wi-Fi, Device: en0)").as_deref(),
            Some("en0")
        );
        assert_eq!(
            parse_device_from_hw_line(" VPN (Cisco IPSec), Device: )"),
            None
        );
        assert_eq!(parse_device_from_hw_line(" no device field here)"), None);
    }
}
