use std::os::unix::net::UnixStream;
use std::process::Command;
use std::time::{Duration, Instant};

use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use tracing::{debug, info};

use crate::error::{AppError, Result};
use crate::privileged_api::ConnectionId;
use crate::status_model::{NetworkOverview, WgDeviceStatus, WgPeerStatus};

use super::daemon::self_executable_for_spawn;
use super::managed_pids::{pid_is_alive, process_executable};

/// Fetch the live network overview from a userspace helper's query socket.
/// Returns `Ok(None)` when there is no such socket (kernel backend, or
/// the tunnel isn't a gotatun userspace one) so the caller can quietly skip it.
pub(super) fn run_network_overview(interface: &str) -> Result<Option<NetworkOverview>> {
    use std::io::Read;

    let socket_path =
        std::path::PathBuf::from("/var/run/wireguard").join(format!("{interface}.wgd.query.sock"));
    if !socket_path.exists() {
        return Ok(None);
    }

    let mut stream = UnixStream::connect(&socket_path)
        .map_err(|e| AppError::Other(format!("overview query connect: {e}")))?;
    let mut payload = Vec::new();
    stream
        .read_to_end(&mut payload)
        .map_err(|e| AppError::Other(format!("overview query read: {e}")))?;
    let overview = serde_json::from_slice(&payload).map_err(|e| {
        AppError::Other(format!(
            "overview query for {interface} returned invalid JSON: {e}"
        ))
    })?;
    Ok(Some(overview))
}

pub(super) fn run_wg_show(interface: &str) -> Result<WgDeviceStatus> {
    let socket_path =
        std::path::PathBuf::from("/var/run/wireguard").join(format!("{interface}.sock"));

    if socket_path.exists() {
        run_wg_show_uapi(interface, &socket_path)
    } else {
        // Kernel backend: no UAPI socket; wg is already a dependency of WireguardSet.
        run_wg_show_kernel(interface)
    }
}

fn run_wg_show_uapi(interface: &str, socket_path: &std::path::Path) -> Result<WgDeviceStatus> {
    use std::io::BufRead;

    debug!(socket = ?socket_path.display().to_string(), "uapi_get");
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| AppError::WireGuard(format!("UAPI connect: {e}")))?;
    std::io::Write::write_all(&mut stream, b"get=1\n\n")
        .map_err(|e| AppError::WireGuard(format!("UAPI write: {e}")))?;

    // The UAPI protocol terminates responses with errno=N\n\n (double newline)
    // but keeps the socket open. Read line-by-line and stop after the empty
    // line that follows the errno= line, rather than waiting for EOF.
    let mut raw = String::new();
    let reader = std::io::BufReader::new(&mut stream);
    let mut saw_errno = false;
    for line in reader.lines() {
        let line = line.map_err(|e| AppError::WireGuard(format!("UAPI read: {e}")))?;
        if line.starts_with("errno=") {
            saw_errno = true;
            raw.push_str(&line);
            raw.push('\n');
        } else if line.is_empty() && saw_errno {
            break;
        } else {
            raw.push_str(&line);
            raw.push('\n');
        }
    }

    parse_wg_show(&raw, interface)
}

fn run_wg_show_kernel(_interface: &str) -> Result<WgDeviceStatus> {
    // macOS has no in-kernel WireGuard; userspace tunnels always expose a UAPI
    // socket, so this path (no socket present) means the interface is not up.
    Err(AppError::WireGuard(
        "no WireGuard UAPI socket for interface (tunnel not active)".to_string(),
    ))
}

/// Parse a UAPI `get=1` response into the device state.
pub(super) fn parse_wg_show(raw: &str, interface: &str) -> Result<WgDeviceStatus> {
    use base64::Engine;
    use gotatun::x25519::{PublicKey, StaticSecret};

    struct PeerState {
        public_key_b64: String,
        has_preshared_key: bool,
        endpoint: Option<String>,
        allowed_ips: Vec<String>,
        last_handshake_sec: u64,
        rx_bytes: u64,
        tx_bytes: u64,
        keepalive: u32,
    }

    let mut listen_port: u16 = 0;
    let mut iface_pub_b64 = String::new();
    let mut peers: Vec<PeerState> = Vec::new();
    let mut current_peer: Option<PeerState> = None;

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };

        match key {
            "private_key" => {
                if let Ok(bytes) = wg_hex_to_32(value) {
                    let secret = StaticSecret::from(bytes);
                    let public = PublicKey::from(&secret);
                    iface_pub_b64 =
                        base64::engine::general_purpose::STANDARD.encode(public.as_bytes());
                }
            }
            "listen_port" => listen_port = value.parse().unwrap_or(0),
            "public_key" => {
                if let Some(peer) = current_peer.take() {
                    peers.push(peer);
                }
                if let Ok(bytes) = wg_hex_to_32(value) {
                    current_peer = Some(PeerState {
                        public_key_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
                        has_preshared_key: false,
                        endpoint: None,
                        allowed_ips: Vec::new(),
                        last_handshake_sec: 0,
                        rx_bytes: 0,
                        tx_bytes: 0,
                        keepalive: 0,
                    });
                }
            }
            _ => {
                if let Some(ref mut peer) = current_peer {
                    match key {
                        "preshared_key" => {
                            peer.has_preshared_key =
                                value.as_bytes().iter().any(|byte| *byte != b'0')
                        }
                        "endpoint" => peer.endpoint = Some(value.to_string()),
                        "allowed_ip" => peer.allowed_ips.push(value.to_string()),
                        "last_handshake_time_sec" => {
                            peer.last_handshake_sec = value.parse().unwrap_or(0)
                        }
                        "rx_bytes" => peer.rx_bytes = value.parse().unwrap_or(0),
                        "tx_bytes" => peer.tx_bytes = value.parse().unwrap_or(0),
                        "persistent_keepalive_interval" => {
                            peer.keepalive = value.parse().unwrap_or(0)
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    if let Some(peer) = current_peer.take() {
        peers.push(peer);
    }

    Ok(WgDeviceStatus {
        interface: interface.to_string(),
        public_key: (!iface_pub_b64.is_empty()).then_some(iface_pub_b64),
        listen_port: (listen_port != 0).then_some(listen_port),
        peers: peers
            .into_iter()
            .map(|peer| WgPeerStatus {
                public_key: peer.public_key_b64,
                endpoint: peer.endpoint,
                allowed_ips: peer.allowed_ips,
                has_preshared_key: peer.has_preshared_key,
                latest_handshake_unix: (peer.last_handshake_sec > 0)
                    .then_some(peer.last_handshake_sec),
                rx_bytes: peer.rx_bytes,
                tx_bytes: peer.tx_bytes,
                persistent_keepalive_secs: (peer.keepalive > 0).then_some(peer.keepalive),
            })
            .collect(),
    })
}

pub(super) fn wg_hex_to_32(s: &str) -> std::result::Result<[u8; 32], ()> {
    if s.len() != 64 {
        return Err(());
    }
    let mut bytes = [0u8; 32];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(bytes)
}

pub(super) fn run_gotatun_up(
    connection_id: ConnectionId,
    interface: &str,
    config_content: &str,
    mtu_override: Option<u16>,
    dns_dynamic_store: bool,
    bypass_links: &[crate::bypass_links::BypassLink],
    debug_enabled: bool,
) -> Result<()> {
    use base64::Engine;

    // Finding 5 — Incorrect tunnel adoption and connection races: the
    // dispatcher verifies identity under its mutation lock. A helper whose
    // socket vanished may still be cleaning up; never start over its files.
    if read_gotatun_pid(&gotatun_pid_path(interface))?.is_some_and(pid_is_alive) {
        return Err(AppError::WireGuard(
            "existing helper is still running; disconnect it before reconnecting".into(),
        ));
    }

    let exe = self_executable_for_spawn()?;
    let config_b64 = base64::engine::general_purpose::STANDARD.encode(config_content);
    rotate_helper_log(&gotatun_log_path(interface)).map_err(|error| {
        AppError::Other(format!(
            "failed to rotate helper log for {interface}: {error}"
        ))
    })?;
    for path in [
        gotatun_pid_path(interface),
        gotatun_name_path(interface),
        gotatun_cleanup_status_path(interface),
    ] {
        let _ = std::fs::remove_file(path);
    }

    debug!(
        cmd = format!("{} {} [WGD_GOTATUN_HELPER=1]", exe.display(), interface),
        "exec"
    );
    let mut command = Command::new(exe);
    crate::trusted_exec::sanitize(&mut command);
    command
        .env("WGD_GOTATUN_HELPER", "1")
        .env("WGD_GOTATUN_CONFIG_B64", config_b64)
        .env("WGD_CONNECTION_ID", connection_id.to_string())
        .arg(interface);
    // Phase 2 of `doc/dns-dynamic-store.md`: opted-in connections publish
    // their DNS through the dynamic store instead of `networksetup`.
    if dns_dynamic_store {
        info!(%connection_id, "privileged_dns_via_dynamic_store");
        command.env(crate::dns_dynamic_store::ACTIVE_ENV, "1");
    }
    // `doc/lan-bypass-links.md`: only links that validate reach the helper.
    if !bypass_links.is_empty() {
        info!(%connection_id, links = bypass_links.len(), "privileged_bypass_links_passed");
        command.env(
            crate::bypass_links::ENV,
            crate::bypass_links::to_env_value(bypass_links),
        );
    } else {
        // Never inherit links from the daemon's own environment.
        command.env_remove(crate::bypass_links::ENV);
    }
    if let Some(mtu) = mtu_override {
        command.env("WGD_GOTATUN_MTU_OVERRIDE", mtu.to_string());
    }
    if debug_enabled {
        command.env("WGD_DEBUG", "1");
    }
    if let Some(color) = std::env::var_os(crate::logging::COLOR_ENV) {
        command.env(crate::logging::COLOR_ENV, color);
    }
    let status = command
        .status()
        .map_err(|e| AppError::Other(format!("gotatun up failed to start: {}", e)))?;

    if !status.success() {
        return Err(AppError::WireGuard(format!("gotatun up exited {}", status)));
    }
    let pid_path = gotatun_pid_path(interface);
    let pid = read_gotatun_pid(&pid_path)?.ok_or_else(|| {
        AppError::WireGuard(format!(
            "gotatun helper started without writing {}",
            pid_path.display()
        ))
    })?;
    if !pid_is_alive(pid) {
        return Err(AppError::WireGuard(format!(
            "gotatun helper process {} exited during startup",
            pid
        )));
    }
    ensure_gotatun_process_identity(pid)?;
    Ok(())
}

/// Keep one previous session as `<interface>.1.log`, leaving the current path
/// free for a fresh log. Do not start a helper if rotation fails: appending to
/// the old log would mix sessions and hide the failure. A missing current log
/// leaves any previous session intact.
fn rotate_helper_log(path: &std::path::Path) -> std::io::Result<()> {
    match std::fs::rename(path, path.with_extension("1.log")) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(super) fn run_gotatun_down(interface: &str) -> Result<()> {
    let socket_path =
        std::path::PathBuf::from("/var/run/wireguard").join(format!("{interface}.sock"));
    let pid_path = gotatun_pid_path(interface);
    let name_path = gotatun_name_path(interface);
    let cleanup_status_path = gotatun_cleanup_status_path(interface);
    let actual_interface = std::fs::read_to_string(&name_path)
        .ok()
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty());

    let tracked_pid = read_gotatun_pid(&pid_path)?;
    if let Some(pid) = tracked_pid.filter(|pid| pid_is_alive(*pid)) {
        ensure_gotatun_process_identity(pid)?;
    }

    let started = Instant::now();
    debug!(
        interface,
        pid = ?tracked_pid,
        socket = %socket_path.display(),
        actual_interface = ?actual_interface,
        "gotatun_shutdown_begin"
    );

    if tracked_pid.is_none()
        && actual_interface.is_none()
        && !socket_path.exists()
        && !cleanup_status_path.exists()
    {
        debug!(interface, "gotatun_shutdown_already_absent");
        return Ok(());
    }

    if socket_path.exists() {
        // The helper treats removal of its UAPI socket as a cooperative shutdown request.
        std::fs::remove_file(&socket_path).map_err(|e| {
            AppError::Other(format!(
                "failed to remove gotatun control socket {}: {}",
                socket_path.display(),
                e
            ))
        })?;
        debug!(interface, "gotatun_shutdown_socket_removed");
    }

    let cleanup_status = wait_for_cleanup_status(&cleanup_status_path, Duration::from_secs(15));
    let cleanup_status = match cleanup_status {
        Some(status) => status,
        None => {
            if let Some(pid) = tracked_pid.filter(|pid| pid_is_alive(*pid)) {
                debug!(pid, interface, "gotatun_shutdown_sigterm_fallback");
                match kill(Pid::from_raw(pid as i32), Signal::SIGTERM) {
                    Ok(()) | Err(nix::errno::Errno::ESRCH) => {}
                    Err(error) => {
                        return Err(AppError::Other(format!(
                            "failed to signal gotatun helper {}: {}",
                            pid, error
                        )));
                    }
                }
            }
            wait_for_cleanup_status(&cleanup_status_path, Duration::from_secs(5)).ok_or_else(
                || {
                    AppError::WireGuard(format!(
                        "gotatun helper did not confirm cleanup within {} seconds; pid={:?}, interface={:?}",
                        started.elapsed().as_secs(),
                        tracked_pid,
                        actual_interface
                    ))
                },
            )?
        }
    };

    match cleanup_status.as_str() {
        "ok" => {}
        cleanup_status => {
            return Err(AppError::WireGuard(format!(
                "gotatun helper cleanup failed: {}",
                cleanup_status
            )));
        }
    }

    if let Some(actual_interface) = actual_interface.as_deref() {
        let deadline = Instant::now() + Duration::from_secs(5);
        while macos_interface_exists(actual_interface) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        if macos_interface_exists(actual_interface) {
            return Err(AppError::WireGuard(format!(
                "userspace tunnel interface {} still exists after confirmed network cleanup",
                actual_interface
            )));
        }
    }

    debug!(
        interface,
        pid = ?tracked_pid,
        elapsed_ms = started.elapsed().as_millis(),
        "gotatun_shutdown_complete"
    );

    for path in [pid_path, name_path, cleanup_status_path] {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

fn wait_for_cleanup_status(path: &std::path::Path, timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    loop {
        match std::fs::read_to_string(path) {
            Ok(status) if !status.trim().is_empty() => return Some(status.trim().to_string()),
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                debug!(
                    path = %path.display(),
                    error = %error,
                    "gotatun_cleanup_status_read_failed"
                );
            }
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn macos_interface_exists(interface: &str) -> bool {
    crate::trusted_exec::command("ifconfig")
        .expect("system command is approved")
        .arg(interface)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

pub(super) fn read_gotatun_pid(path: &std::path::Path) -> Result<Option<u32>> {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let pid = raw.trim().parse::<u32>().map_err(|error| {
        AppError::Other(format!(
            "invalid gotatun pid in {}: {}",
            path.display(),
            error
        ))
    })?;
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(AppError::Other(format!(
            "invalid gotatun pid {} in {}",
            pid,
            path.display()
        )));
    }
    Ok(Some(pid))
}

fn ensure_gotatun_process_identity(pid: u32) -> Result<()> {
    let expected = std::env::current_exe()
        .map_err(|error| AppError::Other(format!("cannot resolve current executable: {error}")))?;
    let actual = process_executable(pid).ok_or_else(|| {
        AppError::Other(format!(
            "cannot resolve executable for gotatun helper pid {}",
            pid
        ))
    })?;

    let expected = std::fs::canonicalize(&expected).unwrap_or(expected);
    let actual = std::fs::canonicalize(&actual).unwrap_or(actual);
    if actual != expected {
        return Err(AppError::Other(format!(
            "refusing to signal pid {} because executable {} does not match {}",
            pid,
            actual.display(),
            expected.display()
        )));
    }
    Ok(())
}

pub(super) fn gotatun_pid_path(interface: &str) -> std::path::PathBuf {
    gotatun_runtime_path(interface, "pid")
}

pub(super) fn gotatun_name_path(interface: &str) -> std::path::PathBuf {
    gotatun_runtime_path(interface, "name")
}

fn gotatun_cleanup_status_path(interface: &str) -> std::path::PathBuf {
    gotatun_runtime_path(interface, "cleanup")
}

/// Log file the gotatun helper writes to. The service tails this to stream the
/// helper's setup/teardown output back to the calling CLI. Shares the single
/// source of truth in `config` with `userspace_helper` so the paths always match.
///
/// `/var/log/wgd/<interface>.log` on all platforms (see
/// `config::gotatun_helper_log_path`).
pub(super) fn gotatun_log_path(interface: &str) -> std::path::PathBuf {
    crate::config::gotatun_helper_log_path(interface)
}

/// Control socket of the helper's UAPI server.
pub(super) fn gotatun_socket_path(interface: &str) -> std::path::PathBuf {
    std::path::PathBuf::from("/var/run/wireguard").join(format!("{interface}.sock"))
}

/// Socket the helper serves its live network overview on.
pub(super) fn gotatun_query_socket_path(interface: &str) -> std::path::PathBuf {
    gotatun_runtime_path(interface, "query.sock")
}

fn gotatun_runtime_path(interface: &str, suffix: &str) -> std::path::PathBuf {
    std::path::PathBuf::from("/var/run/wireguard").join(format!("{interface}.wgd.{suffix}"))
}

#[cfg(test)]
mod tests {
    use super::{
        ensure_gotatun_process_identity, gotatun_runtime_path, parse_wg_show, read_gotatun_pid,
        rotate_helper_log, wait_for_cleanup_status,
    };
    use crate::status_model::WgPeerStatus;

    fn temp_path(label: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "wgd-gotatun-{label}-{}-{nonce}",
            std::process::id()
        ))
    }

    #[test]
    fn helper_log_rotation_keeps_only_the_previous_session() {
        let dir = temp_path("log-rotation");
        std::fs::create_dir(&dir).unwrap();
        let current = dir.join("wg-aaaaaaaa.log");
        let previous = dir.join("wg-aaaaaaaa.1.log");
        std::fs::write(&current, "first session\n").unwrap();

        rotate_helper_log(&current).unwrap();
        assert!(!current.exists());
        assert_eq!(
            std::fs::read_to_string(&previous).unwrap(),
            "first session\n"
        );

        std::fs::write(&current, "second session\n").unwrap();
        rotate_helper_log(&current).unwrap();
        assert!(!current.exists());
        assert_eq!(
            std::fs::read_to_string(&previous).unwrap(),
            "second session\n"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn missing_current_helper_log_preserves_the_previous_session() {
        let dir = temp_path("missing-log");
        std::fs::create_dir(&dir).unwrap();
        let current = dir.join("wg-aaaaaaaa.log");
        let previous = dir.join("wg-aaaaaaaa.1.log");

        rotate_helper_log(&current).unwrap();
        assert!(!previous.exists());
        std::fs::write(&previous, "previous session\n").unwrap();
        rotate_helper_log(&current).unwrap();
        assert_eq!(
            std::fs::read_to_string(&previous).unwrap(),
            "previous session\n"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn helper_log_rotation_reports_errors_without_discarding_the_current_log() {
        let dir = temp_path("failed-log-rotation");
        std::fs::create_dir(&dir).unwrap();
        let current = dir.join("wg-aaaaaaaa.log");
        let previous = dir.join("wg-aaaaaaaa.1.log");
        std::fs::write(&current, "current session\n").unwrap();
        std::fs::create_dir(&previous).unwrap();

        assert!(rotate_helper_log(&current).is_err());
        assert_eq!(
            std::fs::read_to_string(&current).unwrap(),
            "current session\n"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn gotatun_runtime_paths_are_scoped_to_interface() {
        assert_eq!(
            gotatun_runtime_path("wgconf0", "cleanup"),
            std::path::PathBuf::from("/var/run/wireguard/wgconf0.wgd.cleanup")
        );
    }

    #[test]
    fn read_gotatun_pid_handles_missing_valid_and_invalid_files() {
        let path = temp_path("pid");
        assert_eq!(read_gotatun_pid(&path).expect("missing pid"), None);

        std::fs::write(&path, format!("{}\n", std::process::id())).expect("write valid pid");
        assert_eq!(
            read_gotatun_pid(&path).expect("valid pid"),
            Some(std::process::id())
        );

        std::fs::write(&path, "0\n").expect("write invalid pid");
        assert!(read_gotatun_pid(&path).is_err());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn current_process_matches_gotatun_executable_identity_check() {
        ensure_gotatun_process_identity(std::process::id()).expect("current executable identity");
    }

    #[test]
    fn cleanup_status_waits_for_helper_confirmation() {
        let path = temp_path("cleanup-status");
        let writer_path = path.clone();
        let writer = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(20));
            std::fs::write(writer_path, "ok\n").expect("write cleanup status");
        });

        let status = wait_for_cleanup_status(&path, std::time::Duration::from_secs(1));
        writer.join().expect("cleanup status writer");
        let _ = std::fs::remove_file(path);
        assert_eq!(status.as_deref(), Some("ok"));
    }

    const PRIVATE_KEY_HEX: &str =
        "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
    const PEER_1_HEX: &str = "a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0";
    const PEER_2_HEX: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn parse_wg_show_reads_the_interface() {
        let raw = format!("private_key={PRIVATE_KEY_HEX}\nlisten_port=51820\nerrno=0\n\n");
        let device = parse_wg_show(&raw, "wgconf0").unwrap();
        assert_eq!(device.interface, "wgconf0");
        assert_eq!(
            device.public_key.as_deref(),
            Some("B6N8vBQgk8i3VdwbEOhstCY3StFqqFPtC9/AsrhtHHw=")
        );
        assert_eq!(device.listen_port, Some(51820));
        assert!(device.peers.is_empty());
    }

    #[test]
    fn parse_wg_show_without_key_or_port_leaves_them_unset() {
        let device = parse_wg_show("errno=0\n\n", "wgconf0").unwrap();
        assert_eq!(device.public_key, None);
        assert_eq!(device.listen_port, None);
        let zero_port = parse_wg_show("listen_port=0\nerrno=0\n\n", "wgconf0").unwrap();
        assert_eq!(zero_port.listen_port, None);
    }

    #[test]
    fn parse_wg_show_reads_peers() {
        let zero = "0".repeat(64);
        let psk = "ff".repeat(32);
        let raw = format!(
            "private_key={PRIVATE_KEY_HEX}\n\
             public_key={PEER_1_HEX}\npreshared_key={psk}\nendpoint=203.0.113.7:51820\n\
             allowed_ip=10.66.77.0/24\nallowed_ip=100.64.0.1/32\n\
             last_handshake_time_sec=1699999875\nlast_handshake_time_nsec=5\n\
             tx_bytes=5242880\nrx_bytes=1536\npersistent_keepalive_interval=25\n\
             public_key={PEER_2_HEX}\npreshared_key={zero}\ntx_bytes=0\nrx_bytes=0\n\
             last_handshake_time_sec=0\npersistent_keepalive_interval=0\nerrno=0\n\n"
        );
        let device = parse_wg_show(&raw, "wgconf0").unwrap();
        assert_eq!(
            device.peers,
            vec![
                WgPeerStatus {
                    public_key: "oaKjpKWmp6ipqqusra6vsLGys7S1tre4ubq7vL2+v8A=".to_string(),
                    endpoint: Some("203.0.113.7:51820".to_string()),
                    allowed_ips: vec!["10.66.77.0/24".to_string(), "100.64.0.1/32".to_string()],
                    has_preshared_key: true,
                    latest_handshake_unix: Some(1_699_999_875),
                    rx_bytes: 1536,
                    tx_bytes: 5_242_880,
                    persistent_keepalive_secs: Some(25),
                },
                WgPeerStatus {
                    public_key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE=".to_string(),
                    endpoint: None,
                    allowed_ips: vec![],
                    has_preshared_key: false,
                    latest_handshake_unix: None,
                    rx_bytes: 0,
                    tx_bytes: 0,
                    persistent_keepalive_secs: None,
                },
            ]
        );
    }
}
