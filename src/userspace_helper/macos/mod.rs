use anyhow::Context;
pub(super) mod dns;
mod dns_plan;
mod dns_store_key;
mod foreign;
mod net;
pub(super) mod overview;
mod route_table;
pub(super) mod routes;
mod system;
#[cfg(test)]
mod test_support;

use self::dns::configure_macos_dns;
use self::dns::restore_macos_dns_services;
use self::dns_plan::macos_dns_server_in_local_subnet;
use self::dns_store_key::DnsStoreKey;
use self::net::parse_cidr;
use self::overview::log_macos_network_diagnostics;
use self::overview::log_macos_network_overview;
use self::route_table::add_macos_route;
use self::route_table::del_macos_route;
use self::route_table::macos_restore_shadowed_lan_route;
use self::route_table::MacosRouteInstall;
use self::routes::macos_allowed_ips_cover_endpoint;
use self::routes::macos_current_fingerprint;
use self::routes::macos_desired_routes;
use self::routes::GatewayFallback;
use self::system::macos_local_connected_subnets;
use crate::userspace_helper::config::ParsedUserspaceConfig;
use crate::userspace_helper::exec::run_command;
use crate::userspace_helper::finish_cleanup;
use crate::userspace_helper::SOCK_DIR;
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{debug, info, warn};

pub(super) struct MacosCleanupState {
    /// Live routing state. Mutated by the network-change reconciler while the
    /// tunnel is up and read by teardown, hence the interior mutability.
    routing: std::sync::Mutex<MacosRoutingState>,
    /// Live DNS state. Like `routing`, the reconciler keeps this in sync with
    /// the active LAN while the tunnel is up and teardown reads it to restore.
    dns: std::sync::Mutex<MacosDnsState>,
    /// Owner of the DNS key in the dynamic store (`doc/dns-dynamic-store.md`,
    /// "Rollout"). `None` without tunnel DNS, without a connection id, or
    /// when its thread could not start.
    dns_store_key: Option<DnsStoreKey>,
    /// Immutable inputs the reconciler replays on every network change.
    pub(super) reconcile: MacosReconcileInputs,
}

/// Routing state the reconciler keeps in sync with the live network.
struct MacosRoutingState {
    /// Routes this tunnel currently owns; the source of truth for teardown.
    routes_added: Vec<MacosRoute>,
    /// Last observed network environment. A change drives reconciliation.
    fingerprint: MacosNetworkFingerprint,
}

/// DNS state the reconciler keeps in sync with the active LAN.
struct MacosDnsState {
    /// Services we currently own, each carrying the original config to restore
    /// at teardown. Mutated as the reconciler takes/releases ownership.
    services: Vec<MacosDnsServiceState>,
    /// Last observed DNS-relevant environment. A change drives reconciliation.
    fingerprint: MacosDnsFingerprint,
}

/// Inputs captured at connect that the reconciler needs to recompute routing.
pub(super) struct MacosReconcileInputs {
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
    /// `Active`: the dynamic store key carries the tunnel DNS and the
    /// `networksetup` path (capture, custody, reconcile) is skipped.
    /// `Shadow`: `networksetup` as always, plus an inert probe key.
    dns_mode: crate::dns_dynamic_store::StoreKeyMode,
    /// Validated by the daemon (`doc/lan-bypass-links.md`); static for the
    /// life of the helper. Whether a link is active follows from the
    /// fingerprint's `local_subnets`, so the fingerprint needs no field.
    bypass_links: Vec<crate::bypass_links::BypassLink>,
}

/// A snapshot of the host network environment relevant to tunnel routing.
#[derive(Clone, Default, PartialEq)]
struct MacosNetworkFingerprint {
    /// Directly-connected subnets of physical interfaces (the LANs we must not
    /// hijack), sorted+deduped for stable comparison.
    local_subnets: Vec<(IpAddr, u8)>,
    /// Default gateway for the endpoint's address family (for the endpoint pin).
    endpoint_gateway: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
struct MacosRoute {
    is_ipv6: bool,
    destination: String,
    interface: Option<String>,
    gateway: Option<String>,
}

#[derive(Clone)]
struct MacosDnsServiceState {
    service: String,
    dns_servers: Option<Vec<String>>,
    search_domains: Option<Vec<String>>,
}

/// The persisted form of an owned service is the same "original" the helper
/// holds in memory, not a second notion of it.
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

pub(super) async fn run_macos_maintenance<T: Send + 'static>(
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
pub(super) async fn log_macos_transfer_sample(
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

pub(super) fn configure_network_macos(
    interface: &str,
    config: &ParsedUserspaceConfig,
    connection_id: Option<crate::privileged_api::ConnectionId>,
    custody: Option<crate::dns_custody::DnsCustodyIdentity>,
    dns_mode: crate::dns_dynamic_store::StoreKeyMode,
    bypass_links: Vec<crate::bypass_links::BypassLink>,
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
        dns_mode,
        bypass_links,
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
        // fingerprint so the first reconcile tick is a no-op. In active mode
        // the dynamic store key below is the tunnel's DNS instead.
        if dns_mode == crate::dns_dynamic_store::StoreKeyMode::Shadow {
            dns_fingerprint =
                configure_macos_dns(&inputs, &fingerprint.local_subnets, &mut dns_services)?;
        }
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

    // After routes, like the `networksetup` path; withdrawn from the start
    // when the tunnel DNS collides with a connected LAN.
    let dns_store_key = connection_id
        .filter(|_| !inputs.dns_servers.is_empty())
        .and_then(|connection_id| {
            let collision =
                macos_dns_server_in_local_subnet(&inputs.dns_servers, &fingerprint.local_subnets);
            DnsStoreKey::start(
                interface,
                connection_id,
                dns_mode,
                &inputs.dns_servers,
                collision.is_none(),
            )
        });

    let cleanup = MacosCleanupState {
        routing: std::sync::Mutex::new(MacosRoutingState {
            routes_added,
            fingerprint,
        }),
        dns: std::sync::Mutex::new(MacosDnsState {
            services: dns_services,
            fingerprint: dns_fingerprint,
        }),
        dns_store_key,
        reconcile: inputs,
    };
    log_macos_network_overview("connect", &cleanup);
    Ok(cleanup)
}

pub(super) fn cleanup_network_macos(state: &MacosCleanupState) -> anyhow::Result<()> {
    let mut errors = Vec::new();
    // The dynamic store key goes first, before routes (see "Lifecycle").
    if let Some(key) = &state.dns_store_key {
        key.remove();
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;
    use std::net::SocketAddr;
    use std::time::Duration;

    /// Time a UDP socket's creation+bind, send and close separately.
    ///
    /// This is the reproduction for `doc/macos-udp-probe-delay.md`, kept out of
    /// the production path: it exists to re-measure the environment (a macOS
    /// content filter's close-wait), not to diagnose the tunnel. Logging happens
    /// only after the close, because a synchronous log between send and close
    /// would give the filter extra time to detach and shorten what we measure.
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
}
