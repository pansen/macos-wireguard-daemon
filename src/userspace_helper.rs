#[cfg(unix)]
use base64::Engine;
#[cfg(unix)]
use std::fs::File;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::net::{IpAddr, SocketAddr};
#[cfg(target_os = "macos")]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::net::UnixDatagram;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::process::Output;
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

#[cfg(target_os = "macos")]
use crate::status_model::{
    DnsCollision, DnsOverview, DnsServiceRow, DnsServiceStatus, ForeignTunnelRow, IpFamily,
    LiveRoute, NetworkOverview, ResolverState, RouteOutcome, RouteRow, RouteVia, SystemResolver,
};

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
    /// Identity for the persistent DNS custody record. `None` disables the
    /// record (no `WGD_CONNECTION_ID`, or the helper's own start time was
    /// unreadable); connect still works, only crash recovery is lost.
    custody: Option<crate::dns_custody::DnsCustodyIdentity>,
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
#[derive(Debug, Clone, PartialEq)]
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

/// The persisted form of an owned service is the same "original" the helper
/// holds in memory, not a second notion of it.
#[cfg(target_os = "macos")]
impl From<&MacosDnsServiceState> for crate::dns_custody::DnsCustodyService {
    fn from(state: &MacosDnsServiceState) -> Self {
        Self {
            service: state.service.clone(),
            original_dns_servers: state.dns_servers.clone(),
            original_search_domains: state.search_domains.clone(),
        }
    }
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

#[cfg(target_os = "macos")]
async fn run_macos_maintenance<T: Send + 'static>(
    operation: &'static str,
    work: impl FnOnce() -> T + Send + 'static,
) -> anyhow::Result<T> {
    // Await each job so ticks cannot overlap and teardown cannot race a worker
    // that is still changing routes or DNS. Awaiting yields the runtime thread
    // to the packet engine, unlike synchronous subprocess/socket operations.
    tokio::task::spawn_blocking(move || {
        let started = std::time::Instant::now();
        let result = work();
        debug!(
            operation,
            elapsed_ms = started.elapsed().as_millis(),
            "userspace_helper_maintenance_complete"
        );
        result
    })
    .await
    .with_context(|| format!("macOS {operation} maintenance task panicked"))
}

/// Sample the tunnel's WireGuard transfer counters.
///
/// This only reads counters the device already maintains; it generates no
/// traffic of its own. An earlier version first sent a UDP byte to public DNS
/// resolvers on both families to try to prove the dataplane worked. That never
/// established anything: nothing validated a reply, unrelated traffic accounts
/// for any counter movement, and under a split tunnel those destinations were
/// not in AllowedIPs and so left through the physical interface without
/// touching WireGuard at all. It also cost about two seconds per sample,
/// because closing a filtered socket waits out `net.cfil.close_wait_timeout`.
/// See `doc/macos-udp-probe-delay.md`.
#[cfg(target_os = "macos")]
async fn log_macos_transfer_sample(
    interface: &str,
    last_transfer: &mut Option<(u64, u64)>,
) -> anyhow::Result<()> {
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
            // An idle tunnel samples every 5s with no movement; keep that
            // heartbeat at DEBUG so default (INFO) logs stay quiet, and only
            // surface samples where bytes actually moved.
            let moved = delta_rx_bytes != 0 || delta_tx_bytes != 0;
            if moved {
                info!(
                    interface,
                    rx_bytes,
                    tx_bytes,
                    delta_rx_bytes,
                    delta_tx_bytes,
                    "userspace_helper_transfer_sample"
                );
            } else {
                debug!(
                    interface,
                    rx_bytes,
                    tx_bytes,
                    delta_rx_bytes,
                    delta_tx_bytes,
                    "userspace_helper_transfer_sample"
                );
            }
        }
        Ok(None) => {
            info!(interface, "userspace_helper_transfer_sample_unavailable");
        }
        Err(error) => {
            // Stays at WARN: a genuine UAPI failure means the device stopped
            // answering. One benign case reaches here, a sample racing teardown
            // after the control socket was removed, which reports ENOENT.
            warn!(
                interface,
                error = %error,
                "userspace_helper_transfer_sample_failed"
            );
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
async fn read_wg_transfer_bytes(interface: &str) -> anyhow::Result<Option<(u64, u64)>> {
    // Finding 3 — Executable substitution through PATH: query our own UAPI
    // instead of requiring a Homebrew wg binary for the default backend.
    // The blocking reader runs off-runtime so the device can answer its query.
    let socket_path = PathBuf::from(SOCK_DIR).join(format!("{interface}.sock"));
    let _suppress_probe_uapi_log = crate::logging::suppress_gotatun_uapi_connection_logs();
    tokio::time::timeout(
        Duration::from_secs(4),
        tokio::task::spawn_blocking(move || {
            use std::io::{BufRead, BufReader, Read, Write};
            let mut stream = std::os::unix::net::UnixStream::connect(socket_path)?;
            stream.set_read_timeout(Some(Duration::from_secs(4)))?;
            stream.set_write_timeout(Some(Duration::from_secs(4)))?;
            stream.write_all(b"get=1\n\n")?;
            let mut reader = BufReader::new(stream).take(256 * 1024);
            let mut rx: u64 = 0;
            let mut tx: u64 = 0;
            let mut any = false;
            loop {
                let mut line = String::new();
                anyhow::ensure!(
                    reader.read_line(&mut line)? != 0,
                    "incomplete UAPI response"
                );
                let line = line.trim();
                if let Some(value) = line.strip_prefix("rx_bytes=") {
                    rx = rx.saturating_add(value.parse::<u64>()?);
                    any = true;
                } else if let Some(value) = line.strip_prefix("tx_bytes=") {
                    tx = tx.saturating_add(value.parse::<u64>()?);
                    any = true;
                } else if line == "errno=0" {
                    return Ok(if any { Some((rx, tx)) } else { None });
                } else if line.starts_with("errno=") {
                    anyhow::bail!("UAPI transfer query failed");
                }
            }
        }),
    )
    .await
    .context("UAPI transfer query timed out")?
    .context("UAPI transfer reader panicked")?
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

/// Delegates to the shared [`crate::wireguard::connection_config`] parser (the
/// only WireGuard `.conf` parser in the codebase) and narrows its fully
/// general, multi-peer result down to the single peer this helper's gotatun
/// device can actually drive. A config with more than one `[Peer]` section is
/// an explicit error here rather than the old silent single-peer overwrite.
#[cfg(unix)]
fn parse_wg_quick_config(config: &str) -> anyhow::Result<ParsedUserspaceConfig> {
    let parsed = crate::wireguard::connection_config::parse_connection_config(config)?;
    anyhow::ensure!(
        parsed.peers.len() == 1,
        "gotatun userspace backend supports exactly one [Peer] section, found {}",
        parsed.peers.len()
    );
    let peer = &parsed.peers[0];
    let endpoint = peer
        .endpoint
        .ok_or_else(|| anyhow::anyhow!("missing Peer.Endpoint"))?;

    Ok(ParsedUserspaceConfig {
        private_key: parsed.private_key.to_bytes(),
        addresses: parsed.addresses.iter().map(ToString::to_string).collect(),
        dns_servers: parsed.dns_servers.iter().map(ToString::to_string).collect(),
        mtu: parsed.mtu,
        peer_public_key: peer.public_key.to_bytes(),
        peer_preshared_key: peer.preshared_key.as_ref().map(|psk| *psk.as_bytes()),
        allowed_ips: peer.allowed_ips.iter().map(ToString::to_string).collect(),
        endpoint,
    })
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
    let output = crate::trusted_exec::command(name)?
        .args(args)
        .output()
        .with_context(|| format!("failed to run {} {}", name, args.join(" ")))?;
    if !output.status.success() {
        debug!(
            command = %format_command_for_log(name, args),
            status = %output.status,
            stdout = %String::from_utf8_lossy(&output.stdout).trim(),
            stderr = %String::from_utf8_lossy(&output.stderr).trim(),
            "userspace_helper_command_failed"
        );
    }
    Ok(output)
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
    custody: Option<crate::dns_custody::DnsCustodyIdentity>,
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
        custody,
    };
    log_macos_network_diagnostics("before_connect", &inputs);

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
            match add_macos_route(&route)? {
                MacosRouteInstall::Owned => routes_added.push(route),
                // A physical interface holds the prefix; leave it alone rather
                // than claiming a route teardown would then delete.
                MacosRouteInstall::Foreign => warn!(
                    destination = %route.destination,
                    "userspace_helper_route_skipped_physical_prefix"
                ),
            }
        }
        // Apply DNS the same way the reconciler will, then seed the DNS
        // fingerprint so the first reconcile tick is a no-op.
        dns_fingerprint =
            configure_macos_dns(&inputs, &fingerprint.local_subnets, &mut dns_services)?;
        Ok(())
    })();

    if let Err(setup_error) = setup_result {
        let mut errors = Vec::new();
        for route in routes_added.iter().rev() {
            match del_macos_route(route) {
                Ok(()) => {
                    macos_restore_shadowed_lan_route(route, &fingerprint.local_subnets, interface)
                }
                Err(error) => errors.push(error.to_string()),
            }
        }
        errors.extend(restore_macos_dns_services(&dns_services, &inputs));
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
    // Restore persistent DNS before spending the shutdown window on routes.
    // Keep route cleanup (including shadowed LAN-route restoration) intact.
    // Take the `dns` and `routing` locks independently (never both at once)
    // to avoid any ordering hazard with the reconciler.
    {
        let dns = state
            .dns
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        info!(
            dns_services = dns.services.len(),
            "userspace_helper_network_cleanup_dns"
        );
        errors.extend(restore_macos_dns_services(&dns.services, &state.reconcile));
    }
    {
        let routing = state
            .routing
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        debug!(
            routes = routing.routes_added.len(),
            "userspace_helper_network_cleanup_routes"
        );
        let local_subnets = macos_local_connected_subnets(&state.reconcile.interface);
        for route in routing.routes_added.iter().rev() {
            match del_macos_route(route) {
                Ok(()) => macos_restore_shadowed_lan_route(
                    route,
                    &local_subnets,
                    &state.reconcile.interface,
                ),
                Err(error) => errors.push(error.to_string()),
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
/// no-op. Shares its decision (`dns_decision`, including the LAN-collision rule)
/// and its per-service capture+apply path with the reconciler, so a colliding
/// tunnel DNS is never written in the first place.
#[cfg(target_os = "macos")]
fn configure_macos_dns(
    inputs: &MacosReconcileInputs,
    local_subnets: &[(IpAddr, u8)],
    saved: &mut Vec<MacosDnsServiceState>,
) -> anyhow::Result<MacosDnsFingerprint> {
    if inputs.dns_servers.is_empty() {
        return Ok(MacosDnsFingerprint::default());
    }

    let fingerprint = macos_current_dns_fingerprint()?;
    let collision = macos_dns_server_in_local_subnet(&inputs.dns_servers, local_subnets);
    if let Some(collision) = &collision {
        log_dns_unreachable_local_lan(&inputs.interface, collision);
    }
    // Nothing is owned yet, so `Hold` and `RestoreAll` both mean "write nothing";
    // with no primary the reconciler applies once one appears.
    let decision = dns_decision(DNS_POLICY, &fingerprint, collision.is_some());
    for service in decision.targets() {
        saved.push(capture_macos_dns_service(service, &inputs.dns_servers)?);
        // Write-ahead: the record must list the service before its DNS changes.
        persist_dns_custody(saved, inputs);
        crate::macos_dns::set_dns_servers(service, &inputs.dns_servers)?;
        crate::macos_dns::set_search_domains_empty(service)?;
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

/// Write the custody record for the services this helper currently owns, or
/// delete it when none are left. Best-effort: losing crash recovery must not
/// break connect, so a failure only logs. One function for the connect path,
/// the reconciler and teardown, so they cannot diverge.
#[cfg(target_os = "macos")]
fn persist_dns_custody(services: &[MacosDnsServiceState], inputs: &MacosReconcileInputs) {
    let Some(identity) = &inputs.custody else {
        return;
    };
    if inputs.dns_servers.is_empty() {
        return;
    }
    let result = if services.is_empty() {
        crate::dns_custody::remove_record(&identity.interface)
    } else {
        let owned = services
            .iter()
            .map(crate::dns_custody::DnsCustodyService::from)
            .collect();
        crate::dns_custody::write_record(&identity.record(&inputs.dns_servers, owned))
    };
    if let Err(error) = result {
        warn!(
            interface = identity.interface,
            error = %error,
            "userspace_helper_dns_custody_write_failed"
        );
    }
}

/// Restore every service in reverse order, then settle the custody record:
/// deleted when all restores worked, otherwise rewritten with only the
/// services that failed so the daemon's sweep retries them. Returns one
/// message per failure.
#[cfg(target_os = "macos")]
fn restore_macos_dns_services(
    services: &[MacosDnsServiceState],
    inputs: &MacosReconcileInputs,
) -> Vec<String> {
    let mut errors = Vec::new();
    let mut failed = Vec::new();
    for service in services.iter().rev() {
        if let Err(error) = restore_macos_dns_service(service) {
            errors.push(format!(
                "restore DNS for {:?} failed: {error}",
                service.service
            ));
            failed.push(service.clone());
        }
    }
    persist_dns_custody(&failed, inputs);
    if failed.len() < services.len() {
        // At least one service is back on its original DNS; make it effective.
        crate::macos_dns::flush_resolver_cache();
    }
    errors
}

#[cfg(target_os = "macos")]
fn restore_macos_dns_service(state: &MacosDnsServiceState) -> anyhow::Result<()> {
    crate::macos_dns::restore_service(
        &state.service,
        state.dns_servers.as_deref(),
        state.search_domains.as_deref(),
    )
}

/// Whether the tunnel ends up owning a route it tried to install.
#[cfg(target_os = "macos")]
#[derive(Clone, Copy, PartialEq)]
enum MacosRouteInstall {
    /// The route is ours: we installed it, or replaced an earlier tunnel entry
    /// for the same prefix. Teardown and reconcile may remove it again.
    Owned,
    /// A physical interface already holds this prefix (its connected LAN route).
    /// Left untouched and not recorded as ours, so nothing later deletes it.
    Foreign,
}

#[cfg(target_os = "macos")]
fn add_macos_route(route: &MacosRoute) -> anyhow::Result<MacosRouteInstall> {
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
    // devices; clear such an entry first so this tunnel owns the route. Only a
    // tunnel entry is cleared. Deleting the prefix unconditionally also removes
    // a physical interface's connected LAN route, and taking the prefix from a
    // LAN we are attached to makes that whole LAN unreachable.
    if route.interface.is_some() && route.gateway.is_none() {
        let entry = macos_route_destination(route).and_then(macos_route_table_entry);
        debug!(
            destination = route.destination,
            existing_entry = ?entry,
            "userspace_helper_route_install_lookup"
        );
        match entry {
            Some(entry) if !entry.is_tunnel_owned() => {
                let holder = entry.interface.clone();
                let tunnel = route.interface.as_deref().unwrap_or("");
                // A read failure leaves us unable to tell a live physical
                // route from a stale one; default to leaving it alone rather
                // than risking deletion of a LAN route that is still in use.
                let is_live = match macos_connected_subnets_by_device(tunnel) {
                    Some(connected) => macos_route_entry_is_live(&entry, &connected),
                    None => {
                        debug!(
                            destination = %route.destination,
                            "userspace_helper_route_liveness_check_skipped_ifconfig_failed"
                        );
                        true
                    }
                };
                if is_live {
                    debug!(
                        destination = %route.destination,
                        holder = holder.as_deref().unwrap_or("gateway"),
                        "userspace_helper_route_prefix_held_by_physical_interface"
                    );
                    return Ok(MacosRouteInstall::Foreign);
                }
                // The holder has no address in the prefix: a leftover from a
                // network we since left, which would blackhole the prefix.
                warn!(
                    destination = %route.destination,
                    holder = holder.as_deref().unwrap_or("gateway"),
                    "userspace_helper_route_stale_physical_entry_replaced"
                );
                if let Some(remaining) = macos_clear_route_entry(route, holder.as_deref()) {
                    warn!(
                        destination = %route.destination,
                        holder = remaining.interface.as_deref().unwrap_or("gateway"),
                        "userspace_helper_route_stale_physical_entry_survived_cleanup"
                    );
                    return Ok(MacosRouteInstall::Foreign);
                }
            }
            Some(_) => {
                if let Some(remaining) = macos_clear_route_entry(route, None) {
                    warn!(
                        destination = %route.destination,
                        holder = remaining.interface.as_deref().unwrap_or("gateway"),
                        "userspace_helper_route_stale_physical_entry_survived_cleanup"
                    );
                    return Ok(MacosRouteInstall::Foreign);
                }
            }
            None => {}
        }
    }

    let created = run_command_with_exists_ok("route", &refs)?;
    debug!(route = ?route, created, "userspace_helper_route_install_result");
    Ok(MacosRouteInstall::Owned)
}

/// Best-effort delete of the routing-table entry for `route`'s prefix,
/// re-probed afterwards since `route delete` failures are common (a stale
/// entry can be interface-scoped, or already gone) and silent. Returns the
/// entry that still occupies the prefix if it is not tunnel-owned, so the
/// caller can back off instead of reporting the route as installed while the
/// kernel still routes the prefix elsewhere.
///
/// When `ifscope` names the interface holding the entry, retry the delete with
/// `-ifscope`: stale connected routes survive a network switch as
/// interface-scoped entries, and a plain delete answers "not in table" for
/// those without removing anything.
#[cfg(target_os = "macos")]
fn macos_clear_route_entry(route: &MacosRoute, ifscope: Option<&str>) -> Option<MacosRouteEntry> {
    let family = if route.is_ipv6 { "-inet6" } else { "-inet" };
    // Match del_macos_route: without -host/-net the delete can fail to match a
    // CIDR destination, leaving the stale dev-bound route behind.
    let kind = macos_route_target_kind(route);
    let args: Vec<&str> = vec!["-q", "-n", "delete", family, kind, &route.destination];
    let _ = run_command("route", &args);
    if let Some(device) = ifscope {
        let mut scoped = args.clone();
        scoped.push("-ifscope");
        scoped.push(device);
        let _ = run_command("route", &scoped);
    }
    macos_route_destination(route)
        .and_then(macos_route_table_entry)
        .filter(|entry| !entry.is_tunnel_owned())
}

/// Whether a routing-table entry reflects the current network state.
///
/// A dev-bound entry is live only while its holder interface has an address
/// whose connected subnet overlaps the entry's prefix. Without one the entry is
/// a leftover from a network we since left (macOS keeps interface-scoped clones
/// across Wi-Fi switches), and yielding to it would blackhole the prefix.
/// Gateway entries are somebody's deliberate configuration and count as live.
#[cfg(target_os = "macos")]
fn macos_route_entry_is_live(
    entry: &MacosRouteEntry,
    connected: &[(String, (IpAddr, u8))],
) -> bool {
    if entry.has_gateway() {
        return true;
    }
    let Some(holder) = entry.interface.as_deref() else {
        return true;
    };
    connected.iter().any(|(device, local)| {
        device == holder
            && (macos_subnet_contains(local, &entry.destination)
                || macos_subnet_contains(&entry.destination, local))
    })
}

/// One entry of the kernel routing table, as `route -n get` reports it.
#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq)]
struct MacosRouteEntry {
    /// Network base and prefix length of the entry that answered the lookup.
    destination: (IpAddr, u8),
    interface: Option<String>,
    gateway: Option<String>,
    /// Path MTU of the entry; `None` when the kernel reports 0 (unset).
    mtu: Option<u32>,
}

#[cfg(target_os = "macos")]
impl MacosRouteEntry {
    fn has_gateway(&self) -> bool {
        self.gateway.is_some()
    }

    /// True when a tunnel device holds this prefix directly, i.e. this or
    /// another tunnel installed it rather than the kernel deriving it from a
    /// physical interface address.
    fn is_tunnel_owned(&self) -> bool {
        !self.has_gateway()
            && self
                .interface
                .as_deref()
                .is_some_and(|device| device.starts_with("utun"))
    }
}

/// The destination of `route` as a network base and prefix length.
#[cfg(target_os = "macos")]
fn macos_route_destination(route: &MacosRoute) -> Option<(IpAddr, u8)> {
    let (ip, prefix) = if route.destination.contains('/') {
        parse_cidr(&route.destination).ok()?
    } else {
        let ip: IpAddr = route.destination.parse().ok()?;
        let prefix = if ip.is_ipv6() { 128 } else { 32 };
        (ip, prefix)
    };
    Some((macos_network_base(ip, prefix), prefix))
}

/// The routing table entry for exactly this prefix, or `None` when only a
/// broader route (or nothing) covers it.
///
/// `route get` answers with whatever route wins the lookup for an address, so
/// the reply is only an exact match when its own destination and mask match the
/// prefix we asked about.
#[cfg(target_os = "macos")]
fn macos_route_table_entry(destination: (IpAddr, u8)) -> Option<MacosRouteEntry> {
    let (ip, prefix) = destination;
    let is_ipv6 = ip.is_ipv6();
    let base = macos_network_base(ip, prefix).to_string();
    let mut args: Vec<&str> = vec!["-n", "get"];
    if is_ipv6 {
        args.push("-inet6");
    }
    args.push(&base);
    let output = run_command_capture_output("route", &args).ok()?;
    if !output.status.success() {
        return None;
    }
    let entry = parse_macos_route_get(&String::from_utf8_lossy(&output.stdout), is_ipv6)?;
    (entry.destination == destination).then_some(entry)
}

/// Parse the `key: value` block `route -n get` prints for one lookup, plus the
/// mtu column of the trailing statistics table.
#[cfg(target_os = "macos")]
fn parse_macos_route_get(text: &str, is_ipv6: bool) -> Option<MacosRouteEntry> {
    let (mut destination, mut mask, mut gateway, mut interface) = (None, None, None, None);
    let mut mtu = None;
    let mut stats_mtu_column = None;
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(value) = trimmed.strip_prefix("destination:") {
            destination = Some(value.trim().to_string());
        } else if let Some(value) = trimmed.strip_prefix("mask:") {
            mask = Some(value.trim().to_string());
        } else if let Some(value) = trimmed.strip_prefix("gateway:") {
            gateway = Some(value.trim().to_string());
        } else if let Some(value) = trimmed.strip_prefix("interface:") {
            interface = Some(value.trim().to_string());
        } else if let Some(column) = stats_mtu_column.take() {
            // The value row directly under the "recvpipe ... mtu expire" header.
            mtu = trimmed
                .split_whitespace()
                .nth(column)
                .and_then(|value| value.parse::<u32>().ok())
                .filter(|value| *value != 0);
        } else if trimmed.starts_with("recvpipe") {
            stats_mtu_column = trimmed.split_whitespace().position(|name| name == "mtu");
        }
    }
    // A default route reports "default" rather than an address; it never is the
    // exact entry for a prefix we install, so failing to parse is the answer.
    let destination: IpAddr = destination?.parse().ok()?;
    let prefix = match mask.as_deref() {
        // Host routes come back without a mask line.
        None => {
            if is_ipv6 {
                128
            } else {
                32
            }
        }
        Some("default") => 0,
        Some(value) => parse_macos_route_mask(value)?,
    };
    Some(MacosRouteEntry {
        destination: (macos_network_base(destination, prefix), prefix),
        interface,
        gateway,
        mtu,
    })
}

/// Convert a `route get` mask ("255.255.255.0", "ffff:ffff:ffff:ffff::") to a
/// prefix length.
#[cfg(target_os = "macos")]
fn parse_macos_route_mask(mask: &str) -> Option<u8> {
    match mask.parse::<IpAddr>().ok()? {
        IpAddr::V4(v4) => Some(u32::from(v4).count_ones() as u8),
        IpAddr::V6(v6) => Some(u128::from(v6).count_ones() as u8),
    }
}

/// Put back the connected route of a LAN whose prefix a tunnel route held.
///
/// While a dev-bound tunnel route occupies a prefix, the kernel cannot install
/// the connected route a physical interface derives from its own address. Join
/// such a LAN with the tunnel route already in place and the connected route is
/// silently skipped, so removing the tunnel route later leaves no route at all
/// and the LAN goes unreachable. Re-add it in that case.
#[cfg(target_os = "macos")]
fn macos_restore_shadowed_lan_route(
    route: &MacosRoute,
    local_subnets: &[(IpAddr, u8)],
    tunnel_interface: &str,
) {
    let Some(subnet) = macos_route_excluded_by_local_subnet(route, local_subnets) else {
        return;
    };
    // The kernel entry survived (the tunnel route was more specific, or never
    // displaced it), so there is nothing to repair.
    if macos_route_table_entry(subnet).is_some() {
        return;
    }
    let Some(device) = macos_connected_subnet_device(subnet, tunnel_interface) else {
        return;
    };
    let (ip, prefix) = subnet;
    let destination = format!("{ip}/{prefix}");
    // Scoped to the owning device, matching how the kernel installs connected
    // routes; an unscoped entry would outrank the interface's own routing.
    let args = vec![
        "-q".to_string(),
        "-n".to_string(),
        "add".to_string(),
        if ip.is_ipv6() { "-inet6" } else { "-inet" }.to_string(),
        "-net".to_string(),
        destination.clone(),
        "-ifscope".to_string(),
        device.clone(),
        "-interface".to_string(),
        device.clone(),
    ];
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    match run_command_with_exists_ok("route", &refs) {
        Ok(_) => info!(
            destination = %destination,
            device = %device,
            "userspace_helper_lan_route_restored"
        ),
        Err(error) => warn!(
            destination = %destination,
            device = %device,
            error = %error,
            "userspace_helper_lan_route_restore_failed"
        ),
    }
}

#[cfg(target_os = "macos")]
fn del_macos_route(route: &MacosRoute) -> anyhow::Result<()> {
    let mut args: Vec<String> = vec!["-q".into(), "-n".into(), "delete".into()];
    args.push(if route.is_ipv6 { "-inet6" } else { "-inet" }.into());
    args.push(macos_route_target_kind(route).into());
    args.push(route.destination.clone());
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let output = run_command_capture_output("route", &refs)?;
    debug!(
        route = ?route,
        status = %output.status,
        stdout = %String::from_utf8_lossy(&output.stdout).trim(),
        stderr = %String::from_utf8_lossy(&output.stderr).trim(),
        "userspace_helper_route_delete_result"
    );
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
    debug!(
        interface = inputs.interface,
        previous_routes = ?current,
        desired_routes = ?desired,
        endpoint_pin = inputs.endpoint_needs_pin,
        "userspace_helper_route_reconcile_plan"
    );
    log_macos_network_diagnostics("before_route_reconcile", inputs);
    let mut installed: Vec<MacosRoute> = Vec::new();
    let (mut added, mut removed, mut errors) = (0usize, 0usize, 0usize);

    // Remove routes that are no longer desired (e.g. a LAN we just left, or a
    // stale endpoint pin via the previous gateway).
    for route in &current {
        if !desired.contains(route) {
            match del_macos_route(route) {
                Ok(()) => {
                    removed += 1;
                    // Joining a LAN the tunnel already routed costs that LAN its
                    // connected route; dropping ours is only half the repair.
                    macos_restore_shadowed_lan_route(
                        route,
                        &fingerprint.local_subnets,
                        &inputs.interface,
                    );
                }
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
            Ok(MacosRouteInstall::Owned) => {
                added += 1;
                installed.push(route);
            }
            Ok(MacosRouteInstall::Foreign) => warn!(
                destination = %route.destination,
                "userspace_helper_route_skipped_physical_prefix"
            ),
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

/// What the DNS reconciler should do with tunnel DNS. An empty target list is
/// ambiguous (`plan_dns_actions` reads it as "release everything owned"), so the
/// two reasons for having no targets are kept apart.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum DnsDecision {
    /// Own exactly these services.
    Apply(Vec<String>),
    /// A tunnel DNS server is unreachable (LAN collision): restore every owned
    /// service and write nothing.
    RestoreAll,
    /// No settled primary service, typically a moment during a network switch.
    /// Write nothing, and leave the services we already own untouched until a
    /// primary shows up again; releasing them now would only flap their DNS.
    Hold,
}

#[cfg(target_os = "macos")]
impl DnsDecision {
    /// The services to own after this decision. Empty for `RestoreAll` and `Hold`.
    fn targets(&self) -> &[String] {
        match self {
            DnsDecision::Apply(targets) => targets,
            DnsDecision::RestoreAll | DnsDecision::Hold => &[],
        }
    }
}

/// Decide what to do with tunnel DNS. A collision wins over everything else.
/// `PrimaryOnly` targets just the service that owns global resolution; without
/// one (or if it isn't a current service) it holds rather than fanning out to
/// every service, which would overwrite unrelated VPN and tether services.
/// Used by both the connect-time apply and the reconciler so they cannot drift.
#[cfg(target_os = "macos")]
fn dns_decision(policy: DnsPolicy, fp: &MacosDnsFingerprint, collision: bool) -> DnsDecision {
    if collision {
        return DnsDecision::RestoreAll;
    }
    match policy {
        DnsPolicy::AllServices => DnsDecision::Apply(fp.services.clone()),
        DnsPolicy::PrimaryOnly => match &fp.primary_service {
            Some(primary) if fp.services.iter().any(|s| s == primary) => {
                DnsDecision::Apply(vec![primary.clone()])
            }
            _ => DnsDecision::Hold,
        },
    }
}

#[cfg(target_os = "macos")]
fn log_dns_unreachable_local_lan(interface: &str, collision: &(IpAddr, (IpAddr, u8))) {
    let (server, (subnet_ip, subnet_prefix)) = collision;
    warn!(
        interface,
        dns_server = %server,
        local_subnet = %format!("{subnet_ip}/{subnet_prefix}"),
        "userspace_helper_dns_unreachable_local_lan"
    );
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
    let mut services =
        crate::macos_dns::list_network_services().context("listing macOS network services")?;
    if services.is_empty() {
        anyhow::bail!("networksetup -listallnetworkservices returned no services");
    }
    services.sort();
    services.dedup();

    let mut observed = Vec::with_capacity(services.len());
    for svc in &services {
        // None on error → treat as "unknown/unset"; never panic the tick.
        let dns = crate::macos_dns::get_dns_servers(svc).unwrap_or_else(|error| {
            debug!(service = svc, error = %error, "userspace_helper_dns_read_failed");
            None
        });
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
    let dns = crate::macos_dns::get_dns_servers(service)?;
    if dns.as_deref() == Some(tunnel_dns) {
        return Ok(MacosDnsServiceState {
            service: service.to_string(),
            dns_servers: None,
            search_domains: None,
        });
    }
    let search = crate::macos_dns::get_search_domains(service)?;
    Ok(MacosDnsServiceState {
        service: service.to_string(),
        dns_servers: dns,
        search_domains: search,
    })
}

/// Whether a DNS reconcile must act even though the observed fingerprint is
/// unchanged. A collision (a directly-connected LAN that shadows the tunnel
/// resolver) transitions ownership without necessarily moving the fingerprint,
/// because DHCP-provided resolvers are invisible to `networksetup -getdnsservers`
/// — joining or leaving such a LAN can leave every service's observed DNS
/// untouched. Two symmetric transitions:
///   * `must_pull_back`: a collision means we own services that now need
///     restoring to their originals.
///   * `must_reassert`: a cleared collision means services we should own are
///     currently unowned and need tunnel DNS (re-)applied. Without this, a
///     pull-back would never be undone until some other fingerprint-visible
///     event happened to knock it loose.
#[cfg(target_os = "macos")]
fn dns_reconcile_forced(collision_present: bool, owned: &[String], targets: &[String]) -> bool {
    let must_pull_back = collision_present && !owned.is_empty();
    let must_reassert = !collision_present && targets.iter().any(|t| !owned.contains(t));
    must_pull_back || must_reassert
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

    // On a collision, target nothing so every owned service is restored to its
    // original DNS rather than left pointing at an unreachable (or
    // LAN-impersonatable) address.
    let owned: Vec<String> = dns.services.iter().map(|s| s.service.clone()).collect();
    let decision = dns_decision(DNS_POLICY, &fingerprint, collision.is_some());
    // No primary right now: change nothing. The stored fingerprint stays as it
    // was, so the tick where a primary reappears sees the difference and acts.
    if decision == DnsDecision::Hold {
        return false;
    }
    let targets = decision.targets().to_vec();

    // Normally skip when the DNS environment is unchanged, but still act when a
    // collision transition changed required ownership without moving the
    // fingerprint (see `dns_reconcile_forced`).
    if fingerprint == dns.fingerprint
        && !dns_reconcile_forced(collision.is_some(), &owned, &targets)
    {
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

    if let Some(collision) = &collision {
        log_dns_unreachable_local_lan(&inputs.interface, collision);
    }

    let actions = plan_dns_actions(&inputs.dns_servers, &fingerprint, &owned, &targets);
    debug!(
        interface = inputs.interface,
        primary_service = ?fingerprint.primary_service,
        decision = ?decision,
        tunnel_dns = ?inputs.dns_servers,
        previous_observed_dns = ?previous.observed,
        observed_dns = ?fingerprint.observed,
        owned_services = ?owned,
        target_services = ?targets,
        actions = ?actions,
        "userspace_helper_dns_reconcile_plan"
    );

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

    // Persist the owned set before any DNS is written: a newly captured service
    // must be on disk before (c) touches it, and a released one must leave the
    // record once its restore has succeeded.
    if captured + restored + dropped > 0 {
        persist_dns_custody(&dns.services, inputs);
    }

    // (c) (Re-)assert tunnel DNS on every target whose observed DNS has drifted,
    // except services whose original we failed to capture this tick.
    for svc in &actions.apply {
        if capture_failed.contains(&svc.as_str()) {
            continue; // never overwrite DNS we couldn't back up
        }
        if crate::macos_dns::set_dns_servers(svc, &inputs.dns_servers).is_ok()
            && crate::macos_dns::set_search_domains_empty(svc).is_ok()
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

    let mut child = crate::trusted_exec::command("scutil")
        .expect("system command is approved")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| debug!(error = %error, "userspace_helper_primary_interface_spawn_failed"))
        .ok()?;
    child
        .stdin
        .as_mut()?
        .write_all(b"show State:/Network/Global/IPv4\n")
        .map_err(|error| debug!(error = %error, "userspace_helper_primary_interface_write_failed"))
        .ok()?;
    // `wait_with_output` closes stdin first, so scutil sees EOF and exits.
    let output = child
        .wait_with_output()
        .map_err(|error| debug!(error = %error, "userspace_helper_primary_interface_wait_failed"))
        .ok()?;
    if !output.status.success() {
        debug!(
            status = %output.status,
            stderr = %String::from_utf8_lossy(&output.stderr).trim(),
            "userspace_helper_primary_interface_read_failed"
        );
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let primary = parse_scutil_primary_interface(&text);
    if primary.is_none() {
        debug!(state = %text.trim(), "userspace_helper_primary_interface_missing");
    }
    primary
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
    let text = String::from_utf8_lossy(&output.stdout);
    let service = parse_service_name_for_device(&text, device);
    if service.is_none() {
        debug!(device, service_order = %text.trim(), "userspace_helper_primary_service_unmapped");
    }
    service
}

/// Read-only snapshots around network changes. Unlike the overview's owned-route
/// list, these show actual kernel routes (including split-tunnel default routes),
/// physical addresses/link state and DHCP's last received packet. The commands
/// are sequential observations, not an atomic snapshot or a live DHCP capture.
/// Keep them off steady-state ticks and skip all work unless DEBUG is enabled.
#[cfg(target_os = "macos")]
fn log_macos_network_diagnostics(reason: &str, inputs: &MacosReconcileInputs) {
    if !tracing::enabled!(tracing::Level::DEBUG) {
        return;
    }
    let endpoint = inputs.endpoint.to_string();
    let family = if inputs.endpoint_is_ipv6 {
        "-inet6"
    } else {
        "-inet"
    };
    for (command, args) in [
        ("ifconfig", vec![]),
        ("scutil", vec!["--nwi"]),
        ("scutil", vec!["--dns"]),
        ("netstat", vec!["-rn"]),
        ("route", vec!["-n", "get", "-inet", "default"]),
        ("route", vec!["-n", "get", "-inet6", "default"]),
        ("route", vec!["-n", "get", family, endpoint.as_str()]),
    ] {
        log_macos_diagnostic_command(reason, &inputs.interface, command, &args);
    }
    // Include IPv6-only and link-local-only physical interfaces, since their
    // missing IPv4 lease is precisely what we need to investigate after wake.
    let mut devices: Vec<String> = macos_connected_subnets_by_device(&inputs.interface)
        .unwrap_or_default()
        .into_iter()
        .map(|(device, _)| device)
        .collect();
    devices.sort();
    devices.dedup();
    for device in devices {
        log_macos_diagnostic_command(
            reason,
            &inputs.interface,
            "ipconfig",
            &["getpacket", &device],
        );
    }
}

#[cfg(target_os = "macos")]
fn log_macos_diagnostic_command(reason: &str, interface: &str, name: &str, args: &[&str]) {
    let started = std::time::Instant::now();
    match run_command_capture_output(name, args) {
        Ok(output) => debug!(
            reason,
            interface,
            command = %format_command_for_log(name, args),
            status = %output.status,
            elapsed_ms = started.elapsed().as_millis(),
            stdout = %String::from_utf8_lossy(&output.stdout).trim(),
            stderr = %String::from_utf8_lossy(&output.stderr).trim(),
            "userspace_helper_network_diagnostic"
        ),
        Err(error) => debug!(
            reason,
            interface,
            command = %format_command_for_log(name, args),
            elapsed_ms = started.elapsed().as_millis(),
            error = %error,
            "userspace_helper_network_diagnostic_failed"
        ),
    }
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

/// Collect the host state behind the route + DNS overview of this tunnel.
/// Shells out to `route`/`ifconfig`/`scutil`, so call it off the async runtime.
#[cfg(target_os = "macos")]
fn build_macos_network_overview(state: &MacosCleanupState) -> NetworkOverview {
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
    assemble_macos_network_overview(
        inputs,
        &routes,
        &route_fingerprint,
        &owned_dns,
        &dns_fingerprint,
        &foreign,
        &|route| macos_route_destination(route).and_then(macos_route_table_entry),
    )
}

/// Log a full route + DNS overview as one structured field. Called once after
/// connect setup and after route/DNS reconciliation work, so the log shows the
/// resulting tunnel state.
#[cfg(target_os = "macos")]
fn log_macos_network_overview(reason: &str, state: &MacosCleanupState) {
    let overview = build_macos_network_overview(state);
    info!(
        reason,
        interface = state.reconcile.interface,
        overview = %serde_json::to_string(&overview).unwrap_or_default(),
        "network_overview"
    );
}

/// Serve the network overview on a per-interface Unix socket for the lifetime
/// of the tunnel. Each connection gets one freshly-collected overview as JSON and is
/// then closed — no request body is read, since the socket serves exactly one
/// thing. Runs on a dedicated blocking thread because collecting shells out to
/// `ifconfig`/`scutil`/`networksetup`, which must not block the async runtime.
#[cfg(target_os = "macos")]
fn spawn_overview_query_server(interface: &str, state: std::sync::Arc<MacosCleanupState>) {
    use std::io::Write;

    let path = gotatun_query_socket_path(interface);
    // A stale socket from a crashed predecessor would make bind() fail with
    // EADDRINUSE; clear it first (the pid file guards against a live double-run).
    let _ = std::fs::remove_file(&path);
    let listener = match std::os::unix::net::UnixListener::bind(&path) {
        Ok(listener) => listener,
        Err(error) => {
            warn!(interface, error = %error, "userspace_helper_query_socket_bind_failed");
            return;
        }
    };
    // Belt-and-suspenders: the runtime dir is already root-only, but pin the
    // socket private so only root (the privileged service) can connect.
    if let Err(error) = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)) {
        warn!(interface, error = %error, "userspace_helper_query_socket_chmod_failed");
    }

    let interface = interface.to_string();
    let thread_interface = interface.clone();
    let spawned = std::thread::Builder::new()
        .name(format!("wgd-overview-{interface}"))
        .spawn(move || {
            for stream in listener.incoming() {
                match stream {
                    Ok(mut stream) => {
                        let overview = build_macos_network_overview(&state);
                        let payload = match serde_json::to_vec(&overview) {
                            Ok(payload) => payload,
                            Err(error) => {
                                warn!(interface = thread_interface, error = %error, "userspace_helper_query_serialize_failed");
                                continue;
                            }
                        };
                        if let Err(error) = stream.write_all(&payload) {
                            debug!(interface = thread_interface, error = %error, "userspace_helper_query_write_failed");
                        }
                    }
                    Err(error) => {
                        debug!(interface = thread_interface, error = %error, "userspace_helper_query_accept_failed");
                    }
                }
            }
        });
    if let Err(error) = spawned {
        warn!(interface, error = %error, "userspace_helper_query_thread_spawn_failed");
    }
}

/// Gather the typed overview from already-collected host state. `probe`
/// answers the route-table lookup for a destination (injected so tests need no
/// live routing table).
#[cfg(target_os = "macos")]
fn assemble_macos_network_overview(
    inputs: &MacosReconcileInputs,
    routes: &[MacosRoute],
    route_fingerprint: &MacosNetworkFingerprint,
    owned_dns: &[MacosDnsServiceState],
    dns_fingerprint: &MacosDnsFingerprint,
    foreign: &MacosForeignSnapshot,
    probe: &dyn Fn(&MacosRoute) -> Option<MacosRouteEntry>,
) -> NetworkOverview {
    let dns_collision =
        macos_dns_server_in_local_subnet(&inputs.dns_servers, &route_fingerprint.local_subnets)
            .map(|(server, (subnet_ip, subnet_prefix))| DnsCollision {
                server: server.to_string(),
                local_subnet: format!("{subnet_ip}/{subnet_prefix}"),
            });
    NetworkOverview {
        interface: inputs.interface.clone(),
        endpoint: inputs.endpoint.to_string(),
        endpoint_pin: inputs.endpoint_needs_pin,
        gateway: route_fingerprint.endpoint_gateway.clone(),
        local_subnets: route_fingerprint
            .local_subnets
            .iter()
            .map(|(ip, prefix)| format!("{ip}/{prefix}"))
            .collect(),
        routes: macos_route_overview_rows(inputs, route_fingerprint, routes, probe),
        dns: macos_dns_overview(inputs, owned_dns, dns_fingerprint, dns_collision),
        // Effective system resolver: what macOS actually resolves through right now,
        // independent of per-service config. Flags the case that stranded a whole
        // debugging session: the global resolver is a tunnel DNS server that is no
        // longer the tunnel's (a leak), or some other resolver has taken over.
        system_resolver: macos_system_resolver(&foreign.global_resolvers, &inputs.dns_servers),
        // Foreign tunnels: other VPN/utun interfaces sharing the host, plus a
        // userspace-Tailscale hint (it has no utun, so the socket is the only tell).
        foreign_tunnels: foreign.tunnels.clone(),
        tailscaled_running: foreign.tailscaled_present,
    }
}

/// The effective system resolver and how it relates to the tunnel's DNS. The
/// mismatch/leak cases are the ones worth eyeballing.
#[cfg(target_os = "macos")]
fn macos_system_resolver(global_resolvers: &[String], tunnel_dns: &[String]) -> SystemResolver {
    let state = if global_resolvers.is_empty() {
        ResolverState::Unset
    } else if global_resolvers == tunnel_dns {
        ResolverState::MatchesTunnel
    } else if !tunnel_dns.is_empty() && global_resolvers.iter().any(|r| tunnel_dns.contains(r)) {
        ResolverState::PartiallyTunnel
    } else {
        ResolverState::Foreign
    };
    SystemResolver {
        servers: global_resolvers.to_vec(),
        state,
    }
}

/// Snapshot of the host environment *outside* wgd's own routes/DNS — the
/// other VPNs and the effective resolver — bundled so the overview formatter
/// stays a single, testable call.
#[cfg(target_os = "macos")]
struct MacosForeignSnapshot {
    tunnels: Vec<ForeignTunnelRow>,
    global_resolvers: Vec<String>,
    tailscaled_present: bool,
}

#[cfg(target_os = "macos")]
fn macos_foreign_tunnels(own_interface: &str) -> Vec<ForeignTunnelRow> {
    let output = match crate::trusted_exec::command("ifconfig")
        .expect("system command is approved")
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    // `crate::privileged::known_addresses()` is every address wgd has
    // assigned to one of its own stored connections, active or not. A
    // leftover interface from a connection that isn't the one currently
    // driving this overview (e.g. an orphaned utun from a previous connect
    // cycle) still carries one of these addresses, which is what tells it
    // apart from an actually-foreign VPN sharing the same CGNAT space.
    parse_foreign_tunnels(
        &String::from_utf8_lossy(&output.stdout),
        own_interface,
        &crate::privileged::known_addresses(),
    )
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
fn parse_foreign_tunnels(
    ifconfig: &str,
    own_interface: &str,
    own_addresses: &std::collections::HashSet<IpAddr>,
) -> Vec<ForeignTunnelRow> {
    let mut tunnels: Vec<ForeignTunnelRow> = Vec::new();
    let mut current: Option<ForeignTunnelRow> = None;

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
                current = Some(ForeignTunnelRow {
                    interface: name.to_string(),
                    mtu,
                    addresses: Vec::new(),
                    cgnat: false,
                    own: false,
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
                    tunnel.own |= own_addresses.contains(&IpAddr::V4(ip));
                }
            }
        } else if let Some(rest) = trimmed.strip_prefix("inet6 ") {
            if let Some(addr) = rest.split_whitespace().next() {
                let bare = addr.split('%').next().unwrap_or(addr);
                if let Ok(ip) = bare.parse::<Ipv6Addr>() {
                    // Skip link-local; it says nothing about what the tunnel routes.
                    if !ip.is_loopback() && (ip.segments()[0] & 0xffc0) != 0xfe80 {
                        tunnel.addresses.push(bare.to_string());
                        tunnel.own |= own_addresses.contains(&IpAddr::V6(ip));
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
fn macos_global_resolvers() -> Vec<String> {
    let output = match crate::trusted_exec::command("scutil")
        .expect("system command is approved")
        .arg("--dns")
        .output()
    {
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

/// The destination as the kernel actually routes it: normalized to the network
/// base, so `192.168.188.1/24` reads as `192.168.188.0/24` and matches the
/// AllowedIPs line `wg` prints.
#[cfg(target_os = "macos")]
fn macos_route_display_destination(route: &MacosRoute) -> String {
    match macos_route_destination(route) {
        Some((base, prefix)) => format!("{base}/{prefix}"),
        None => route.destination.clone(),
    }
}

/// How the kernel's answer for a prefix reads in the Live column: the device
/// or gateway that actually holds the entry right now, or absent.
#[cfg(target_os = "macos")]
fn macos_live_route(entry: &Option<MacosRouteEntry>) -> LiveRoute {
    match entry {
        None => LiveRoute::Absent,
        Some(entry) => LiveRoute::Present {
            interface: entry.interface.clone(),
            gateway: entry.gateway.clone(),
            mtu: entry.mtu,
        },
    }
}

#[cfg(target_os = "macos")]
fn macos_ip_family(is_ipv6: bool) -> IpFamily {
    if is_ipv6 {
        IpFamily::Ipv6
    } else {
        IpFamily::Ipv4
    }
}

/// Rows for the Routes table: every route the tunnel *wants* — the AllowedIPs
/// routes plus the endpoint pin — each with its outcome, next to what the
/// kernel table actually holds (Live/MTU). The earlier owned-only listing hid
/// exactly the entries worth debugging: a prefix excluded because we sit in
/// that LAN, one a foreign route-table entry keeps off the tunnel, or an
/// "owned" route the kernel has since dropped.
///
/// `probe` answers the route-table lookup for a destination (injected so tests
/// need no live routing table).
#[cfg(target_os = "macos")]
fn macos_route_overview_rows(
    inputs: &MacosReconcileInputs,
    fingerprint: &MacosNetworkFingerprint,
    owned: &[MacosRoute],
    probe: &dyn Fn(&MacosRoute) -> Option<MacosRouteEntry>,
) -> Vec<RouteRow> {
    let mut rows = Vec::new();

    // The endpoint pin exists so handshake traffic itself stays off the tunnel.
    if inputs.endpoint_needs_pin {
        let endpoint = inputs.endpoint.to_string();
        let pin = owned
            .iter()
            .find(|route| route.gateway.is_some() && route.destination == endpoint);
        let entry = pin.and_then(probe);
        rows.push(RouteRow {
            destination: endpoint,
            via: match pin.and_then(|route| route.gateway.as_deref()) {
                Some(gateway) => RouteVia::Gateway {
                    address: gateway.to_string(),
                },
                None => RouteVia::None,
            },
            family: macos_ip_family(inputs.endpoint_is_ipv6),
            live: macos_live_route(&entry),
            outcome: if pin.is_some() {
                RouteOutcome::EndpointPinned
            } else {
                RouteOutcome::EndpointPinMissing
            },
        });
    }

    let candidates = macos_allowed_routes(
        &inputs.allowed_ips,
        &inputs.interface,
        inputs.has_ipv4_address,
        inputs.has_ipv6_address,
    );
    for route in &candidates {
        let entry = probe(route);
        let (via, outcome) = if let Some(subnet) =
            macos_route_excluded_by_local_subnet(route, &fingerprint.local_subnets)
        {
            (
                RouteVia::Direct {
                    device: macos_connected_subnet_device(subnet, &inputs.interface),
                },
                RouteOutcome::ExcludedLocalSubnet {
                    subnet: format!("{}/{}", subnet.0, subnet.1),
                },
            )
        } else if owned.contains(route) {
            let kernel_agrees = entry
                .as_ref()
                .is_some_and(|entry| entry.interface == route.interface && !entry.has_gateway());
            (
                RouteVia::Interface {
                    name: inputs.interface.clone(),
                },
                if kernel_agrees {
                    RouteOutcome::Owned
                } else if entry.is_none() {
                    RouteOutcome::OwnedAbsentFromKernel
                } else {
                    RouteOutcome::OwnedKernelDisagrees
                },
            )
        } else {
            match &entry {
                Some(entry) if !entry.is_tunnel_owned() => (
                    RouteVia::None,
                    RouteOutcome::Blocked {
                        holder: entry.interface.clone(),
                    },
                ),
                _ => (RouteVia::None, RouteOutcome::ReconcilePending),
            }
        };
        rows.push(RouteRow {
            destination: macos_route_display_destination(route),
            via,
            family: macos_ip_family(route.is_ipv6),
            live: macos_live_route(&entry),
            outcome,
        });
    }

    // AllowedIPs of a family the tunnel has no address for never became
    // route candidates; show why instead of dropping them silently.
    for allowed in &inputs.allowed_ips {
        let is_ipv6 = allowed.contains(':');
        if (is_ipv6 && !inputs.has_ipv6_address) || (!is_ipv6 && !inputs.has_ipv4_address) {
            rows.push(RouteRow {
                destination: allowed.clone(),
                via: RouteVia::None,
                family: macos_ip_family(is_ipv6),
                live: LiveRoute::NotProbed,
                outcome: RouteOutcome::NoAddressForFamily,
            });
        }
    }

    // Owned leftovers no longer derived from AllowedIPs (mid-reconcile state).
    for route in owned {
        if candidates.contains(route) || (inputs.endpoint_needs_pin && route.gateway.is_some()) {
            continue;
        }
        let entry = probe(route);
        rows.push(RouteRow {
            destination: macos_route_display_destination(route),
            via: match (&route.gateway, &route.interface) {
                (Some(gateway), _) => RouteVia::Gateway {
                    address: gateway.clone(),
                },
                (None, Some(interface)) => RouteVia::Interface {
                    name: interface.clone(),
                },
                (None, None) => RouteVia::System,
            },
            family: macos_ip_family(route.is_ipv6),
            live: macos_live_route(&entry),
            outcome: RouteOutcome::NoLongerDesired,
        });
    }

    rows
}

#[cfg(target_os = "macos")]
fn macos_dns_overview(
    inputs: &MacosReconcileInputs,
    owned_dns: &[MacosDnsServiceState],
    dns_fingerprint: &MacosDnsFingerprint,
    unreachable: Option<DnsCollision>,
) -> DnsOverview {
    // Use the reconciler's own decision, otherwise the table contradicts it.
    let decision = dns_decision(DNS_POLICY, dns_fingerprint, unreachable.is_some());
    let targets = decision.targets();
    let held = decision == DnsDecision::Hold;
    let services = dns_fingerprint
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
                (true, true, true) => DnsServiceStatus::TunnelDnsActive,
                (true, true, false) => DnsServiceStatus::OwnedPendingReapply,
                (true, false, true) => DnsServiceStatus::AlreadyTunnelDns,
                (true, false, false) => DnsServiceStatus::TargetNotOwned,
                (false, true, _) if held => DnsServiceStatus::OwnedHeldNoPrimary,
                (false, true, _) => DnsServiceStatus::OwnedPendingRestore,
                // Live DNS still shows the tunnel server, but it now sits on the
                // local LAN — that address is no longer the VPN resolver.
                (false, false, true) if unreachable.is_some() => {
                    DnsServiceStatus::StaleTunnelDnsOnLan
                }
                (false, false, _) => DnsServiceStatus::NotTargeted,
            };
            DnsServiceRow {
                service: service.clone(),
                primary: dns_fingerprint.primary_service.as_ref() == Some(service),
                live_dns: live_dns.cloned(),
                owned: owned.is_some(),
                original_dns: owned.and_then(|state| state.dns_servers.clone()),
                status,
            }
        })
        .collect();
    DnsOverview {
        tunnel_servers: inputs.dns_servers.clone(),
        primary_service: dns_fingerprint.primary_service.clone(),
        // A pull-back or a missing primary (a transient between networks) leaves no
        // single active resolver to highlight.
        dormant: unreachable.is_some() || held,
        unreachable,
        services,
    }
}

/// Directly-connected subnets of up, non-loopback, non-point-to-point
/// interfaces (the physical LANs), excluding the tunnel itself.
#[cfg(target_os = "macos")]
fn macos_local_connected_subnets(tunnel_interface: &str) -> Vec<(IpAddr, u8)> {
    let mut subnets: Vec<(IpAddr, u8)> = macos_connected_subnets_by_device(tunnel_interface)
        .unwrap_or_default()
        .into_iter()
        .map(|(_, subnet)| subnet)
        .collect();
    subnets.sort();
    subnets.dedup();
    subnets
}

/// The device that carries `subnet`, for repairing its connected route.
#[cfg(target_os = "macos")]
fn macos_connected_subnet_device(subnet: (IpAddr, u8), tunnel_interface: &str) -> Option<String> {
    macos_connected_subnets_by_device(tunnel_interface)
        .unwrap_or_default()
        .into_iter()
        .find(|(_, candidate)| *candidate == subnet)
        .map(|(device, _)| device)
}

/// Every connected subnet paired with the interface it belongs to, in ifconfig
/// order. `None` means the `ifconfig` read itself failed, distinct from a
/// successful read that simply found no connected subnets; callers that use
/// this to decide whether a route entry is stale must not conflate the two,
/// since a transient read failure would otherwise look like every physical
/// interface having lost its address.
#[cfg(target_os = "macos")]
fn macos_connected_subnets_by_device(
    tunnel_interface: &str,
) -> Option<Vec<(String, (IpAddr, u8))>> {
    // Call ifconfig directly (not run_command_capture_output) to avoid emitting
    // a debug command log line on every reconcile tick.
    let output = match crate::trusted_exec::command("ifconfig")
        .expect("system command is approved")
        .output()
    {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            debug!(
                status = %output.status,
                stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                "userspace_helper_ifconfig_read_failed"
            );
            return None;
        }
        Err(error) => {
            debug!(error = %error, "userspace_helper_ifconfig_read_failed");
            return None;
        }
    };
    let text = String::from_utf8_lossy(&output.stdout);
    let mut subnets = Vec::new();
    let mut device: Option<String> = None;
    for line in text.lines() {
        if !line.starts_with(|c: char| c.is_whitespace()) {
            // Interface header: "en0: flags=8863<UP,BROADCAST,...> mtu 1500".
            device = None;
            if let Some((name, rest)) = line.split_once(':') {
                let name = name.trim();
                if name != tunnel_interface
                    && rest.contains("UP")
                    && !rest.contains("LOOPBACK")
                    && !rest.contains("POINTOPOINT")
                {
                    device = Some(name.to_string());
                }
            }
            continue;
        }
        let Some(device) = device.as_deref() else {
            continue;
        };
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("inet ") {
            if let Some(subnet) = parse_ifconfig_inet4_subnet(rest) {
                subnets.push((device.to_string(), subnet));
            }
        } else if let Some(rest) = trimmed.strip_prefix("inet6 ") {
            if let Some(subnet) = parse_ifconfig_inet6_subnet(rest) {
                subnets.push((device.to_string(), subnet));
            }
        }
    }
    Some(subnets)
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
fn get_macos_default_gateway(is_ipv6: bool) -> anyhow::Result<Option<String>> {
    let mut args = vec!["-n", "get"];
    if is_ipv6 {
        args.push("-inet6");
    }
    args.push("default");

    let output = crate::trusted_exec::command("route")
        .expect("system command is approved")
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

    /// Time a UDP socket's creation+bind, send and close separately.
    ///
    /// This is the reproduction for `doc/macos-udp-probe-delay.md`, kept out of
    /// the production path: it exists to re-measure the environment (a macOS
    /// content filter's close-wait), not to diagnose the tunnel. Logging happens
    /// only after the close, because a synchronous log between send and close
    /// would give the filter extra time to detach and shorten what we measure.
    #[cfg(target_os = "macos")]
    fn measure_udp_socket_lifecycle(target: SocketAddr) {
        use std::net::UdpSocket;

        let bind = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let started = std::time::Instant::now();
        // std combines socket creation and the bind syscall.
        let bound = UdpSocket::bind(bind);
        let bind_elapsed = started.elapsed();
        let socket = match bound {
            Ok(socket) => socket,
            Err(error) => {
                debug!(
                    %target,
                    bind_us = bind_elapsed.as_micros(),
                    %error,
                    "userspace_helper_udp_probe_bind_failed"
                );
                return;
            }
        };
        let started = std::time::Instant::now();
        let sent = socket.send_to(&[0], target);
        let send_elapsed = started.elapsed();
        let started = std::time::Instant::now();
        drop(socket);
        let drop_elapsed = started.elapsed();
        debug!(
            %target,
            bind_us = bind_elapsed.as_micros(),
            send_us = send_elapsed.as_micros(),
            drop_us = drop_elapsed.as_micros(),
            result = ?sent,
            "userspace_helper_udp_probe_timing"
        );
    }

    // Runs the measurement in the same awaited blocking worker the helper uses,
    // so the numbers reflect that context. Sends public traffic; never in CI.
    #[cfg(target_os = "macos")]
    #[tokio::test(flavor = "current_thread")]
    #[ignore = "manual diagnostic: sends UDP packets to public DNS addresses"]
    async fn measure_public_udp_probe_lifecycle() {
        run_macos_maintenance("udp_probe_diagnostic", || {
            let subscriber = tracing_subscriber::fmt()
                .with_max_level(tracing::Level::DEBUG)
                .with_test_writer()
                .with_ansi(false)
                .without_time()
                .finish();
            // Install on the worker itself; thread-local subscribers are not
            // automatically carried into spawn_blocking.
            tracing::subscriber::with_default(subscriber, || {
                for _ in 0..3 {
                    measure_udp_socket_lifecycle(SocketAddr::from((Ipv4Addr::new(8, 8, 8, 8), 53)));
                    measure_udp_socket_lifecycle(SocketAddr::from((
                        Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
                        53,
                    )));
                }
            });
        })
        .await
        .unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn blocked_maintenance_does_not_stall_network_io() {
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();

        let maintenance = run_macos_maintenance("test", move || {
            started_tx.send(()).unwrap();
            // Only the async network task can release this blocking operation.
            // A timeout lets an inline-blocking regression fail instead of hang.
            release_rx.recv_timeout(Duration::from_secs(5))
        });
        let traffic = async {
            started_rx.await.unwrap();
            sender
                .send_to(b"ping", receiver.local_addr().unwrap())
                .await
                .unwrap();
            let mut packet = [0; 4];
            let (len, _) = receiver.recv_from(&mut packet).await.unwrap();
            assert_eq!(&packet[..len], b"ping");
            let _ = release_tx.send(());
        };

        // Poll maintenance first so running it inline would block the only
        // runtime thread before it can deliver the UDP packet.
        let (result, ()) = tokio::join!(biased; maintenance, traffic);
        result
            .expect("maintenance worker completed")
            .expect("network I/O must progress while maintenance is blocked");
    }

    fn subnet(value: &str) -> (IpAddr, u8) {
        let (ip, prefix) = parse_cidr(value).expect("valid cidr");
        (macos_network_base(ip, prefix), prefix)
    }

    #[test]
    fn route_overview_reports_every_allowed_ip_with_its_outcome() {
        let mut inputs = split_inputs();
        inputs.allowed_ips = vec![
            "55.56.57.0/24".to_string(),    // attached LAN -> excluded
            "100.64.0.0/24".to_string(),    // installed, kernel agrees -> owned
            "100.64.9.0/24".to_string(),    // installed, kernel lost it -> drift
            "10.20.30.0/24".to_string(),    // foreign table entry -> blocked
            "192.168.188.1/24".to_string(), // not owned -> pending, display normalized
            "2a01:db8::/64".to_string(),    // no IPv6 address -> not installed
        ];
        let fingerprint = MacosNetworkFingerprint {
            local_subnets: vec![subnet("55.56.57.0/24")],
            endpoint_gateway: None,
        };
        let tunnel_route = |destination: &str| MacosRoute {
            is_ipv6: false,
            destination: destination.to_string(),
            interface: Some("utun6".to_string()),
            gateway: None,
        };
        let owned = vec![tunnel_route("100.64.0.0/24"), tunnel_route("100.64.9.0/24")];
        let probe = |route: &MacosRoute| match route.destination.as_str() {
            "100.64.0.0/24" => Some(MacosRouteEntry {
                destination: subnet("100.64.0.0/24"),
                interface: Some("utun6".to_string()),
                gateway: None,
                mtu: Some(1384),
            }),
            "10.20.30.0/24" => Some(MacosRouteEntry {
                destination: subnet("10.20.30.0/24"),
                interface: Some("en0".to_string()),
                gateway: None,
                mtu: Some(1500),
            }),
            _ => None,
        };

        let rows = macos_route_overview_rows(&inputs, &fingerprint, &owned, &probe);
        let row = |destination: &str| -> &RouteRow {
            rows.iter()
                .find(|row| row.destination == destination)
                .unwrap_or_else(|| panic!("no row for {destination}"))
        };
        let present = |interface: &str, mtu| LiveRoute::Present {
            interface: Some(interface.to_string()),
            gateway: None,
            mtu,
        };

        assert!(matches!(
            &row("55.56.57.0/24").outcome,
            RouteOutcome::ExcludedLocalSubnet { subnet } if subnet == "55.56.57.0/24"
        ));
        assert_eq!(row("100.64.0.0/24").outcome, RouteOutcome::Owned);
        assert_eq!(row("100.64.0.0/24").live, present("utun6", Some(1384)));
        assert_eq!(
            row("100.64.9.0/24").outcome,
            RouteOutcome::OwnedAbsentFromKernel
        );
        assert_eq!(row("100.64.9.0/24").live, LiveRoute::Absent);
        assert_eq!(
            row("10.20.30.0/24").outcome,
            RouteOutcome::Blocked {
                holder: Some("en0".to_string())
            }
        );
        assert_eq!(row("10.20.30.0/24").live, present("en0", Some(1500)));
        // Destination is normalized to the network base for display.
        assert_eq!(
            row("192.168.188.0/24").outcome,
            RouteOutcome::ReconcilePending
        );
        let no_family = row("2a01:db8::/64");
        assert_eq!(no_family.outcome, RouteOutcome::NoAddressForFamily);
        assert_eq!(no_family.family, IpFamily::Ipv6);
        assert_eq!(no_family.live, LiveRoute::NotProbed);
    }

    #[test]
    fn route_overview_shows_endpoint_pin_state() {
        let mut inputs = split_inputs();
        inputs.allowed_ips = Vec::new();
        inputs.endpoint_needs_pin = true;
        let fingerprint = MacosNetworkFingerprint::default();
        let probe = |route: &MacosRoute| {
            (route.destination == "23.88.101.22").then(|| MacosRouteEntry {
                destination: subnet("23.88.101.22/32"),
                interface: Some("en0".to_string()),
                gateway: Some("192.168.1.1".to_string()),
                mtu: Some(1430),
            })
        };

        let pinned = vec![MacosRoute {
            is_ipv6: false,
            destination: "23.88.101.22".to_string(),
            interface: None,
            gateway: Some("192.168.1.1".to_string()),
        }];
        let rows = macos_route_overview_rows(&inputs, &fingerprint, &pinned, &probe);
        assert_eq!(rows[0].destination, "23.88.101.22");
        assert_eq!(
            rows[0].via,
            RouteVia::Gateway {
                address: "192.168.1.1".to_string()
            }
        );
        assert_eq!(
            rows[0].live,
            LiveRoute::Present {
                interface: Some("en0".to_string()),
                gateway: Some("192.168.1.1".to_string()),
                mtu: Some(1430),
            }
        );
        assert_eq!(rows[0].outcome, RouteOutcome::EndpointPinned);

        let rows = macos_route_overview_rows(&inputs, &fingerprint, &[], &probe);
        assert_eq!(rows[0].via, RouteVia::None);
        assert_eq!(rows[0].outcome, RouteOutcome::EndpointPinMissing);
    }

    #[test]
    fn stale_physical_route_entry_is_not_live_without_a_backing_address() {
        let entry = MacosRouteEntry {
            destination: subnet("10.66.77.0/24"),
            interface: Some("en0".to_string()),
            gateway: None,
            mtu: None,
        };

        // en0 left the 10.66.77.0/24 LAN; only an unrelated subnet remains.
        let elsewhere = vec![("en0".to_string(), subnet("192.0.0.2/32"))];
        assert!(!macos_route_entry_is_live(&entry, &elsewhere));
        assert!(!macos_route_entry_is_live(&entry, &[]));

        // Attached to the LAN: the connected route must be respected.
        let attached = vec![("en0".to_string(), subnet("10.66.77.0/24"))];
        assert!(macos_route_entry_is_live(&entry, &attached));

        // The same subnet on a different interface does not back en0's entry.
        let other_device = vec![("en1".to_string(), subnet("10.66.77.0/24"))];
        assert!(!macos_route_entry_is_live(&entry, &other_device));

        // Overlap in either direction counts as backed.
        let broader_entry = MacosRouteEntry {
            destination: subnet("10.66.0.0/16"),
            interface: Some("en0".to_string()),
            gateway: None,
            mtu: None,
        };
        assert!(macos_route_entry_is_live(&broader_entry, &attached));

        // Gateway entries are deliberate configuration, never treated as stale.
        let gateway = MacosRouteEntry {
            destination: subnet("10.66.77.0/24"),
            interface: Some("en0".to_string()),
            gateway: Some("10.66.77.1".to_string()),
            mtu: None,
        };
        assert!(macos_route_entry_is_live(&gateway, &elsewhere));
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
    fn route_get_reply_identifies_the_entry_holding_a_prefix() {
        let lan = "   route to: 192.168.168.0\n\
                    destination: 192.168.168.0\n\
                           mask: 255.255.255.0\n\
                      interface: en0\n\
                          flags: <UP,DONE,CLONING>\n\
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire\n\
       0         0         0         0         0         0      1500         0\n";
        let entry = parse_macos_route_get(lan, false).expect("parsed");
        assert_eq!(entry.destination, subnet("192.168.168.0/24"));
        assert_eq!(entry.interface.as_deref(), Some("en0"));
        assert_eq!(entry.mtu, Some(1500));
        assert!(!entry.is_tunnel_owned());

        let tunnel = "   route to: 10.66.77.0\n\
                       destination: 10.66.77.0\n\
                              mask: 255.255.255.0\n\
                         interface: utun6\n";
        assert!(parse_macos_route_get(tunnel, false)
            .expect("parsed")
            .is_tunnel_owned());

        // Answered by the default route: no entry for this prefix.
        let covered = "   route to: 192.168.168.0\n\
                       destination: default\n\
                              mask: default\n\
                           gateway: 192.168.168.1\n\
                         interface: en0\n";
        assert_eq!(parse_macos_route_get(covered, false), None);

        // A host route comes back without a mask line.
        let host = "   route to: 100.64.1.1\n\
                    destination: 100.64.1.1\n\
                      interface: utun6\n";
        let entry = parse_macos_route_get(host, false).expect("parsed");
        assert_eq!(entry.destination, subnet("100.64.1.1/32"));

        let v6 = "   route to: fd86:4939:da7b::\n\
                  destination: fd86:4939:da7b::\n\
                         mask: ffff:ffff:ffff:ffff::\n\
                    interface: en0\n";
        let entry = parse_macos_route_get(v6, true).expect("parsed");
        assert_eq!(entry.destination, subnet("fd86:4939:da7b::/64"));
        assert!(!entry.is_tunnel_owned());
    }

    #[test]
    fn a_gatewayed_tunnel_entry_is_not_treated_as_tunnel_owned() {
        // An endpoint pin lives on the physical path even though route get
        // names a tunnel-looking device; only dev-bound entries are ours.
        let entry = MacosRouteEntry {
            destination: subnet("23.88.101.22/32"),
            interface: Some("utun6".to_string()),
            gateway: Some("192.168.168.1".to_string()),
            mtu: None,
        };
        assert!(!entry.is_tunnel_owned());
    }

    #[test]
    fn route_destinations_normalise_to_network_base_and_prefix() {
        let network = MacosRoute {
            is_ipv6: false,
            destination: "192.168.168.42/24".to_string(),
            interface: Some("utun6".to_string()),
            gateway: None,
        };
        assert_eq!(
            macos_route_destination(&network),
            Some(subnet("192.168.168.0/24"))
        );

        let bare = MacosRoute {
            is_ipv6: false,
            destination: "23.88.101.22".to_string(),
            interface: None,
            gateway: Some("192.168.168.1".to_string()),
        };
        assert_eq!(
            macos_route_destination(&bare),
            Some(subnet("23.88.101.22/32"))
        );
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
            custody: None,
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
        let collision = DnsCollision {
            server: "55.56.57.2".to_string(),
            local_subnet: "55.56.57.0/24".to_string(),
        };
        // The status of a service and whether the renderer dims its row.
        let status = |dns: &DnsOverview, svc: &str| -> (DnsServiceStatus, bool) {
            dns.services
                .iter()
                .find(|row| row.service == svc)
                .map(|row| {
                    (
                        row.status,
                        dns.dormant || row.status == DnsServiceStatus::NotTargeted,
                    )
                })
                .expect("service row present")
        };

        // Reachable: the primary genuinely shows tunnel DNS; a secondary is just
        // untargeted (and dimmed) under PrimaryOnly.
        let healthy = macos_dns_overview(&inputs, &[], &fp, None);
        assert_eq!(
            status(&healthy, "Wi-Fi"),
            (DnsServiceStatus::AlreadyTunnelDns, false)
        );
        assert_eq!(
            status(&healthy, "Thunderbolt Bridge"),
            (DnsServiceStatus::NotTargeted, true)
        );

        // Collision: the same address is now a LAN host, so no row may claim the
        // tunnel DNS is in use, and the whole dormant block is dimmed.
        let pulled_back = macos_dns_overview(&inputs, &[], &fp, Some(collision.clone()));
        assert_eq!(pulled_back.unreachable, Some(collision));
        assert_eq!(
            status(&pulled_back, "Wi-Fi"),
            (DnsServiceStatus::StaleTunnelDnsOnLan, true)
        );
        assert_eq!(
            status(&pulled_back, "Thunderbolt Bridge"),
            (DnsServiceStatus::StaleTunnelDnsOnLan, true)
        );

        // Transient with no settled primary: nothing is targeted and the whole
        // block is greyed.
        let no_primary = dns_fp(
            None,
            &[
                ("Wi-Fi", Some(&["55.56.57.2"])),
                ("Thunderbolt Bridge", Some(&["55.56.57.2"])),
            ],
        );
        let unsettled = macos_dns_overview(&inputs, &[], &no_primary, None);
        assert_eq!(
            status(&unsettled, "Wi-Fi"),
            (DnsServiceStatus::NotTargeted, true)
        );
        assert_eq!(
            status(&unsettled, "Thunderbolt Bridge"),
            (DnsServiceStatus::NotTargeted, true)
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
        let tunnels = parse_foreign_tunnels(ifconfig, "utun4", &std::collections::HashSet::new());

        assert_eq!(
            tunnels,
            vec![
                ForeignTunnelRow {
                    interface: "utun5".to_string(),
                    mtu: Some(1380),
                    addresses: vec![], // link-local only
                    cgnat: false,
                    own: false,
                },
                ForeignTunnelRow {
                    interface: "utun6".to_string(),
                    mtu: Some(1280),
                    addresses: vec!["100.96.10.5".to_string()],
                    cgnat: true,
                    own: false,
                },
            ]
        );
        // utun4 (self) excluded; en0/lo0 not tunnels; utun7 is DOWN (no UP flag).
        assert!(!tunnels.iter().any(|t| t.interface == "utun4"));
        assert!(!tunnels.iter().any(|t| t.interface == "utun7"));
    }

    #[test]
    fn parse_foreign_tunnels_recognizes_own_other_connection_by_address() {
        // utun6 carries a CGNAT address that happens to belong to one of
        // wgd's own stored connections (e.g. an orphaned interface from a
        // previous connect cycle) — it should be identified as ours, not
        // flagged as a possible Tailscale tailnet.
        let ifconfig = "\
utun6: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1384
\tinet 100.64.1.2 --> 100.64.1.2 netmask 0xffffffff
";
        let own_addresses: std::collections::HashSet<IpAddr> =
            [IpAddr::V4(Ipv4Addr::new(100, 64, 1, 2))]
                .into_iter()
                .collect();
        let tunnels = parse_foreign_tunnels(ifconfig, "utun7", &own_addresses);

        assert_eq!(tunnels.len(), 1);
        assert!(tunnels[0].cgnat);
        assert!(tunnels[0].own);
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
    fn system_resolver_flags_match_foreign_and_empty() {
        let tunnel = vec!["55.56.57.2".to_string()];
        let state = |resolvers: &[&str]| {
            let resolvers: Vec<String> = resolvers.iter().map(|r| r.to_string()).collect();
            macos_system_resolver(&resolvers, &tunnel).state
        };
        assert_eq!(state(&["55.56.57.2"]), ResolverState::MatchesTunnel);
        assert_eq!(state(&["1.1.1.1"]), ResolverState::Foreign);
        assert_eq!(
            state(&["55.56.57.2", "1.1.1.1"]),
            ResolverState::PartiallyTunnel
        );
        assert_eq!(state(&[]), ResolverState::Unset);
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
    fn custody_service_keeps_empty_originals_as_none() {
        let adopted = MacosDnsServiceState {
            service: "Wi-Fi".into(),
            dns_servers: None,
            search_domains: None,
        };
        let captured = MacosDnsServiceState {
            service: "Ethernet".into(),
            dns_servers: Some(vec!["192.168.1.1".into()]),
            search_domains: Some(vec!["lan".into()]),
        };
        let adopted = crate::dns_custody::DnsCustodyService::from(&adopted);
        let captured = crate::dns_custody::DnsCustodyService::from(&captured);
        assert_eq!(adopted.original_dns_servers, None);
        assert_eq!(adopted.original_search_domains, None);
        assert_eq!(
            captured.original_dns_servers,
            Some(vec!["192.168.1.1".to_string()])
        );
        assert_eq!(
            captured.original_search_domains,
            Some(vec!["lan".to_string()])
        );
    }

    #[test]
    fn dns_decision_honours_policy_and_holds_without_primary() {
        let fp = dns_fp(
            Some("Wi-Fi"),
            &[
                ("Ethernet", Some(&["1.1.1.1"])),
                ("Wi-Fi", Some(&["1.1.1.1"])),
            ],
        );

        // AllServices targets every service.
        assert_eq!(
            dns_decision(DnsPolicy::AllServices, &fp, false),
            DnsDecision::Apply(vec!["Ethernet".to_string(), "Wi-Fi".to_string()])
        );

        // PrimaryOnly targets just the primary.
        assert_eq!(
            dns_decision(DnsPolicy::PrimaryOnly, &fp, false),
            DnsDecision::Apply(vec!["Wi-Fi".to_string()])
        );

        // PrimaryOnly with no detectable primary holds instead of fanning out.
        let no_primary = dns_fp(None, &[("Wi-Fi", None), ("Ethernet", None)]);
        assert_eq!(
            dns_decision(DnsPolicy::PrimaryOnly, &no_primary, false),
            DnsDecision::Hold
        );

        // So does a primary that isn't a current service.
        let stale_primary = dns_fp(Some("Bogus"), &[("Wi-Fi", None)]);
        assert_eq!(
            dns_decision(DnsPolicy::PrimaryOnly, &stale_primary, false),
            DnsDecision::Hold
        );
    }

    #[test]
    fn dns_decision_collision_restores_all_even_without_primary() {
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["10.66.77.2"]))]);
        let no_primary = dns_fp(None, &[("Wi-Fi", None)]);
        for fp in [&fp, &no_primary] {
            let decision = dns_decision(DnsPolicy::PrimaryOnly, fp, true);
            assert_eq!(decision, DnsDecision::RestoreAll);
            assert!(decision.targets().is_empty());
        }
    }

    #[test]
    fn initial_apply_with_tunnel_dns_in_local_subnet_targets_nothing() {
        // Same inputs the connect path feeds `configure_macos_dns`: tunnel DNS
        // 10.66.77.2 sits inside the home LAN, so nothing may be written.
        let tunnel_dns = vec!["10.66.77.2".to_string(), "100.64.1.1".to_string()];
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["192.168.1.1"]))]);
        let collision = macos_dns_server_in_local_subnet(&tunnel_dns, &[subnet("10.66.77.0/24")]);
        assert!(collision.is_some());

        let decision = dns_decision(DnsPolicy::PrimaryOnly, &fp, collision.is_some());
        let actions = plan_dns_actions(&tunnel_dns, &fp, &[], decision.targets());
        assert_eq!(actions, DnsActions::default());
        // Nothing owned and nothing to assert: the next tick must not be forced.
        assert!(!dns_reconcile_forced(true, &[], decision.targets()));
    }

    #[test]
    fn hold_without_primary_keeps_owned_services() {
        // Primary vanished mid network switch while we own Wi-Fi: the decision
        // targets nothing, and the reconciler returns before planning, so the
        // owned service is neither restored nor re-captured.
        let fp = dns_fp(None, &[("Wi-Fi", Some(&["100.64.0.1"])), ("Vpn", None)]);
        let decision = dns_decision(DnsPolicy::PrimaryOnly, &fp, false);
        assert_eq!(decision, DnsDecision::Hold);
        assert!(decision.targets().is_empty());

        // Contrast: planning with the empty target list would release it.
        let released = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], &[]);
        assert_eq!(released.restore, vec!["Wi-Fi".to_string()]);
    }

    #[test]
    fn collision_restores_owned_services() {
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["100.64.0.1"]))]);
        let decision = dns_decision(DnsPolicy::PrimaryOnly, &fp, true);
        let actions = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], decision.targets());
        assert_eq!(actions.restore, vec!["Wi-Fi".to_string()]);
        assert!(actions.capture.is_empty());
        assert!(actions.apply.is_empty());
        assert!(dns_reconcile_forced(
            true,
            &["Wi-Fi".to_string()],
            decision.targets()
        ));
    }

    #[test]
    fn primary_returning_after_hold_targets_the_primary() {
        let held = dns_fp(None, &[("Wi-Fi", Some(&["192.168.1.1"]))]);
        assert_eq!(
            dns_decision(DnsPolicy::PrimaryOnly, &held, false),
            DnsDecision::Hold
        );

        let back = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["192.168.1.1"]))]);
        let decision = dns_decision(DnsPolicy::PrimaryOnly, &back, false);
        assert_eq!(decision, DnsDecision::Apply(vec!["Wi-Fi".to_string()]));
        assert!(dns_reconcile_forced(false, &[], decision.targets()));
        let actions = plan_dns_actions(&tunnel(), &back, &[], decision.targets());
        assert_eq!(actions.capture, vec!["Wi-Fi".to_string()]);
        assert_eq!(actions.apply, vec!["Wi-Fi".to_string()]);
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
        let targets = dns_decision(DnsPolicy::PrimaryOnly, &fp, false)
            .targets()
            .to_vec();
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
        let targets = dns_decision(DnsPolicy::PrimaryOnly, &fp, false)
            .targets()
            .to_vec();
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
        let targets = dns_decision(DnsPolicy::AllServices, &fp, false)
            .targets()
            .to_vec();
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
        let targets = dns_decision(DnsPolicy::PrimaryOnly, &fp, false)
            .targets()
            .to_vec();
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
        let targets = dns_decision(DnsPolicy::PrimaryOnly, &fp, false)
            .targets()
            .to_vec();
        let actions = plan_dns_actions(&tunnel(), &fp, &["Wi-Fi".to_string()], &targets);
        assert_eq!(actions, DnsActions::default());
    }

    #[test]
    fn dns_reconcile_forced_covers_collision_transitions() {
        let wifi = || vec!["Wi-Fi".to_string()];

        // Steady state, no collision, already own the target: guard may skip.
        assert!(!dns_reconcile_forced(false, &wifi(), &wifi()));

        // Entering a colliding LAN while we own services: must pull back, even
        // though the fingerprint need not have moved.
        assert!(dns_reconcile_forced(true, &wifi(), &[]));

        // In a collision but owning nothing: nothing to restore, don't force.
        assert!(!dns_reconcile_forced(true, &[], &[]));

        // Leaving a collision: we own nothing but should own the primary again.
        // This is the roam-off-collision case that previously never re-applied.
        assert!(dns_reconcile_forced(false, &[], &wifi()));

        // No collision and every target already owned: don't force.
        assert!(!dns_reconcile_forced(false, &wifi(), &wifi()));

        // No collision, no targets (e.g. VPN promotes no DNS): don't force.
        assert!(!dns_reconcile_forced(false, &[], &[]));
    }

    #[test]
    fn plan_dns_adopts_leaked_tunnel_dns_on_unowned_target() {
        // A prior run left tunnel DNS on the primary but we don't own it (its
        // saved original was lost to a crash/kill/uninstall). Capture it so
        // teardown can restore it to Empty — otherwise the unreachable tunnel
        // resolver is stranded forever. Differs from the owned steady state:
        // here `owned` is empty.
        let fp = dns_fp(Some("Wi-Fi"), &[("Wi-Fi", Some(&["100.64.0.1"]))]);
        let targets = dns_decision(DnsPolicy::PrimaryOnly, &fp, false)
            .targets()
            .to_vec();
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
        let targets = dns_decision(DnsPolicy::PrimaryOnly, &fp, false)
            .targets()
            .to_vec();
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
