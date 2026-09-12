// `pub(crate)` rather than private: `client_authorize` runs client-side (in
// the unprivileged CLI process, not the daemon) and is called directly from
// `privileged_client`, which needs to reach past this module's usual privacy.
pub(crate) mod authz;
mod commands;
mod connection_ops;
mod connection_store;
mod daemon;
mod dispatch;
mod managed_pids;
mod socket;

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::FromRawFd;
use std::time::Duration;

use nix::unistd::Group;
use nix::unistd::{chown, Gid};
use tracing::{debug, info};

use crate::config;
use crate::privileged_api::{PrivilegedRequest, PrivilegedResponse};

use dispatch::dispatch;

const AUTH_GROUP_NAME: &str = "tunmux";

struct ControlState {
    leases: HashSet<String>,
    allow_shutdown: bool,
    shutdown_requested: bool,
}

impl ControlState {
    fn new(allow_shutdown: bool) -> Self {
        Self {
            leases: HashSet::new(),
            allow_shutdown,
            shutdown_requested: false,
        }
    }

    fn prune_stale_leases(&mut self) {
        self.leases
            .retain(|token| managed_pids::lease_token_is_live(token));
    }

    fn should_exit_now(&mut self) -> bool {
        if !self.allow_shutdown || !self.shutdown_requested {
            return false;
        }
        self.prune_stale_leases();
        self.leases.is_empty()
    }
}

pub fn serve(
    cli_authorized_group: Option<String>,
    cli_idle_timeout_ms: Option<u64>,
    cli_autostarted: bool,
) -> anyhow::Result<()> {
    let authorized_group = resolve_authorized_group(cli_authorized_group);
    let idle_timeout = cli_idle_timeout_ms.map(|ms| Duration::from_millis(ms.max(100)));
    debug!(
        autostarted = ?cli_autostarted,
        idle_timeout_ms = ?idle_timeout.map(|d| d.as_millis()).unwrap_or(0) as u64, "privileged_service_start");
    config::ensure_privileged_socket_dir()?;
    config::ensure_privileged_runtime_dir()?;
    config::ensure_root_log_dir()?;
    connection_store::ensure_store_dirs()?;

    // Resolve group GID for chown of socket dir and file.
    let group_gid = authorized_group
        .as_deref()
        .and_then(read_group_gid)
        .or_else(|| read_group_gid(AUTH_GROUP_NAME));

    // Chown socket directory so group members can traverse it (mode 0750).
    if let Some(gid) = group_gid {
        let socket_dir = config::privileged_socket_dir();
        chown(&socket_dir, None, Some(Gid::from_raw(gid)))?;
        info!(
            path = ?socket_dir.display().to_string(),
            gid = ?gid, "socket_dir_chowned");
    }

    let activated = launchd_activated_listener()?;

    let listener = match activated {
        Some(listener) => {
            info!("privileged_service_socket_activation");
            // launchd created the socket; set group and mode here since SockPathGroup
            // in the plist requires an integer GID which isn't known at plist-authoring time.
            let socket_path = config::privileged_socket_path();
            std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o660))?;
            if let Some(gid) = group_gid {
                chown(&socket_path, None, Some(Gid::from_raw(gid)))?;
                info!(
                    path = ?socket_path.display().to_string(),
                    gid = ?gid, "socket_file_chowned");
            }
            listener
        }
        None => {
            let socket_path = config::privileged_socket_path();
            if socket_path.exists() {
                let _ = std::fs::remove_file(&socket_path);
            }

            let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
            let perms = std::fs::Permissions::from_mode(0o660);
            std::fs::set_permissions(&socket_path, perms)?;

            // Chown socket file so group members can connect (mode 0660).
            if let Some(gid) = group_gid {
                chown(&socket_path, None, Some(Gid::from_raw(gid)))?;
                info!(
                    path = ?socket_path.display().to_string(),
                    gid = ?gid, "socket_file_chowned");
            }

            info!(
                socket = ?socket_path.display().to_string(), "privileged_service_listening");
            listener
        }
    };

    let mut control_state = ControlState::new(cli_autostarted);
    // Phase 3: bring up global `Automatic` connections in the background,
    // only once the listener above is already bound and accepting -- doing
    // this serially beforehand would delay every client behind N
    // helper-startup handshakes (see `connection_store::reconcile_boot`'s
    // doc comment).
    std::thread::spawn(connection_store::reconcile_boot);
    socket::serve(listener, &mut control_state, idle_timeout)
}

pub fn serve_stdio(cli_idle_timeout_ms: Option<u64>, cli_autostarted: bool) -> anyhow::Result<()> {
    debug!(
        autostarted = ?cli_autostarted,
        idle_timeout_ms = ?cli_idle_timeout_ms.unwrap_or(0), "privileged_stdio_service_start");
    config::ensure_privileged_runtime_dir()?;
    config::ensure_root_log_dir()?;
    connection_store::ensure_store_dirs()?;

    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut reader = BufReader::new(stdin.lock());
    let mut writer = stdout.lock();
    let mut control_state = ControlState::new(cli_autostarted);

    loop {
        let mut payload = String::new();
        // Finding 4 — Idle clients blocking the daemon: stdio is a dedicated
        // process per caller, but still needs the same bounded frame size.
        let bytes = std::io::Read::take(&mut reader, socket::MAX_REQUEST_BYTES as u64 + 1)
            .read_line(&mut payload)?;
        anyhow::ensure!(bytes <= socket::MAX_REQUEST_BYTES, "request too large");
        if bytes == 0 {
            debug!("privileged_stdio_service_exiting_stdin_eof");
            return Ok(());
        }

        // stdio is one request at a time: a `Pending` (Connect/Disconnect)
        // outcome is simply awaited here rather than interleaved with other
        // clients the way the socket transport (`socket.rs`) has to.
        let (logs, response) = match process_request_payload(&payload, &mut control_state, None) {
            RequestOutcome::Immediate(logs, response) => (logs, response),
            RequestOutcome::Pending(rx) => (
                Vec::new(),
                rx.recv().unwrap_or_else(|_| PrivilegedResponse::Error {
                    code: "Other".into(),
                    message: "worker thread ended without a response".into(),
                }),
            ),
        };
        let buffer = encode_response_frames(&logs, &response)?;
        writer.write_all(&buffer)?;
        writer.flush()?;

        if control_state.should_exit_now() {
            debug!("privileged_stdio_service_stop_condition_explicit_shutdown_no_leases");
            info!("privileged_stdio_service_exiting_explicit_shutdown");
            return Ok(());
        }
    }
}

extern "C" {
    fn launch_activate_socket(
        name: *const std::ffi::c_char,
        fds: *mut *mut std::ffi::c_int,
        cnt: *mut usize,
    ) -> std::ffi::c_int;
}

/// Retrieve a launchd socket-activation listener for the `Listeners` socket
/// declared in the LaunchDaemon plist. Returns `Ok(None)` when this process was not
/// launched by launchd with that socket (e.g. a sudo-spawned daemon), so the caller
/// falls through to the self-bind path.
fn launchd_activated_listener() -> anyhow::Result<Option<std::os::unix::net::UnixListener>> {
    use nix::libc;
    use std::ffi::CString;

    let name = CString::new("Listeners").unwrap();
    let mut fds: *mut std::ffi::c_int = std::ptr::null_mut();
    let mut count: usize = 0;

    // SAFETY: launch_activate_socket writes a heap-allocated fd array we must free.
    let ret = unsafe { launch_activate_socket(name.as_ptr(), &mut fds, &mut count) };
    if ret != 0 || fds.is_null() || count == 0 {
        if !fds.is_null() {
            unsafe { libc::free(fds as *mut libc::c_void) };
        }
        // Non-zero (commonly ESRCH when not launchd-managed) → not activated.
        return Ok(None);
    }

    // We declare exactly one listener socket in the plist; take the first fd.
    // Defensively close any extras (a misconfigured plist or future change could
    // hand us more) so they aren't leaked when we free the array.
    let fd = unsafe { *fds };
    for i in 1..count {
        unsafe { libc::close(*fds.add(i)) };
    }
    unsafe { libc::free(fds as *mut libc::c_void) };

    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd) };
    Ok(Some(listener))
}

/// Serialize zero or more log frames (`{"log":"…"}`) followed by the response, each as a
/// newline-delimited JSON line. The CLI prints log frames and returns on the response frame.
fn encode_response_frames(
    logs: &[String],
    response: &PrivilegedResponse,
) -> anyhow::Result<Vec<u8>> {
    let mut buffer = Vec::new();
    for line in logs {
        serde_json::to_writer(&mut buffer, &serde_json::json!({ "log": line }))?;
        buffer.push(b'\n');
    }
    serde_json::to_writer(&mut buffer, response)?;
    buffer.push(b'\n');
    Ok(buffer)
}

/// Outcome of one dispatch call, as seen by the transport layer. `Pending` is
/// produced only for `ConnectConnection`/`DisconnectConnection` (see
/// `dispatch::DispatchOutcome`); the stdio transport just blocks on it
/// (stdio is inherently one-request-at-a-time), while the socket transport
/// (`socket.rs`) keeps polling other clients while it waits.
pub(super) enum RequestOutcome {
    Immediate(Vec<String>, PrivilegedResponse),
    Pending(std::sync::mpsc::Receiver<PrivilegedResponse>),
}

fn process_request_payload(
    payload: &str,
    control_state: &mut ControlState,
    peer: Option<(u32, u32)>,
) -> RequestOutcome {
    if payload.trim().is_empty() {
        return RequestOutcome::Immediate(
            Vec::new(),
            PrivilegedResponse::Error {
                code: "Protocol".into(),
                message: "empty privileged request".into(),
            },
        );
    }

    let request: PrivilegedRequest = match serde_json::from_str::<PrivilegedRequest>(payload) {
        Ok(req) => req,
        Err(e) => {
            return RequestOutcome::Immediate(
                Vec::new(),
                PrivilegedResponse::Error {
                    code: "Protocol".into(),
                    message: format!("invalid request format: {}", e),
                },
            );
        }
    };

    // Finding 2 — Protected log disclosure: reject untrusted names before any
    // handler constructs a path from them, including on the error path.
    if let Err(e) = request.validate() {
        return RequestOutcome::Immediate(
            Vec::new(),
            PrivilegedResponse::Error {
                code: "Validation".into(),
                message: e,
            },
        );
    }

    let request_kind = describe_request(&request);
    // `None` (stdio) means the caller has already proven root by reaching
    // this process at all -- see `dispatch::PeerOrigin`'s doc comment.
    let origin = match peer {
        Some((uid, gid)) => {
            info!(
                transport = ?"socket",
                uid = ?uid,
                gid = ?gid,
                request = ?request_kind, "privileged_request_received");
            dispatch::PeerOrigin::Socket(uid)
        }
        None => {
            info!(
                transport = ?"stdio",
                request = ?request_kind, "privileged_request_received");
            dispatch::PeerOrigin::Stdio
        }
    };

    match dispatch(request, control_state, origin) {
        dispatch::DispatchOutcome::Immediate(response) => {
            RequestOutcome::Immediate(Vec::new(), response)
        }
        dispatch::DispatchOutcome::Pending(rx) => RequestOutcome::Pending(rx),
    }
}

fn describe_request(request: &PrivilegedRequest) -> &'static str {
    match request {
        PrivilegedRequest::LeaseAcquire { .. } => "LeaseAcquire",
        PrivilegedRequest::LeaseRelease { .. } => "LeaseRelease",
        PrivilegedRequest::ShutdownIfIdle => "ShutdownIfIdle",
        PrivilegedRequest::InterfaceActive { .. } => "InterfaceActive",
        PrivilegedRequest::WgShow { .. } => "WgShow",
        PrivilegedRequest::NetworkOverview { .. } => "NetworkOverview",
        PrivilegedRequest::AddConnection { .. } => "AddConnection",
        PrivilegedRequest::RemoveConnection { .. } => "RemoveConnection",
        PrivilegedRequest::ConnectConnection { .. } => "ConnectConnection",
        PrivilegedRequest::DisconnectConnection { .. } => "DisconnectConnection",
        PrivilegedRequest::SetConnectionMode { .. } => "SetConnectionMode",
        PrivilegedRequest::ListConnections { .. } => "ListConnections",
        PrivilegedRequest::GetConnection { .. } => "GetConnection",
    }
}

fn resolve_authorized_group(cli_group: Option<String>) -> Option<String> {
    if let Some(group) = cli_group {
        let trimmed = group.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    if let Ok(group) = std::env::var("TUNMUX_PRIVILEGED_GROUP") {
        let trimmed = group.trim().to_string();
        if !trimmed.is_empty() {
            return Some(trimmed);
        }
    }

    Some(AUTH_GROUP_NAME.to_string())
}

fn read_group_gid(group_name: &str) -> Option<u32> {
    Group::from_name(group_name)
        .ok()
        .flatten()
        .map(|g| g.gid.as_raw())
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    /// Split the framed bytes into one JSON value per newline-delimited line.
    fn parse_frames(bytes: &[u8]) -> Vec<serde_json::Value> {
        let text = std::str::from_utf8(bytes).expect("frames must be valid utf-8");
        // A trailing newline after the final frame must not yield an empty line.
        text.lines()
            .map(|line| serde_json::from_str(line).expect("each frame is one JSON line"))
            .collect()
    }

    #[test]
    fn encodes_response_with_zero_logs_as_single_frame() {
        let bytes = encode_response_frames(&[], &PrivilegedResponse::Unit).unwrap();
        let frames = parse_frames(&bytes);
        assert_eq!(frames.len(), 1, "no log frames, just the response");
        assert_eq!(frames[0], serde_json::json!({ "kind": "unit" }));
    }

    #[test]
    fn encodes_logs_in_order_before_response() {
        let logs = vec![
            "first".to_string(),
            "second".to_string(),
            "third".to_string(),
        ];
        let response = PrivilegedResponse::Bool(true);
        let bytes = encode_response_frames(&logs, &response).unwrap();
        let frames = parse_frames(&bytes);

        assert_eq!(frames.len(), logs.len() + 1);
        for (frame, expected) in frames.iter().zip(&logs) {
            assert_eq!(frame, &serde_json::json!({ "log": expected }));
        }
        // The response frame trails the logs and is not a log frame.
        let last = frames.last().unwrap();
        assert!(last.get("log").is_none());
        assert_eq!(last, &serde_json::json!({ "kind": "bool", "value": true }));
    }

    #[test]
    fn log_frames_survive_quotes_and_newlines() {
        // Embedded quotes/newlines must be JSON-escaped so each frame stays on a
        // single line and round-trips back to the original content verbatim.
        let logs = vec![
            "has \"quotes\" inside".to_string(),
            "line one\nline two".to_string(),
            "tab\tand \\ backslash".to_string(),
        ];
        let bytes = encode_response_frames(&logs, &PrivilegedResponse::Unit).unwrap();
        let frames = parse_frames(&bytes);

        assert_eq!(frames.len(), logs.len() + 1);
        for (frame, expected) in frames.iter().zip(&logs) {
            assert_eq!(frame["log"], serde_json::json!(expected));
        }
    }
}
