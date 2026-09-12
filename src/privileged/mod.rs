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
mod tunnel_state;

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

/// Cap on bytes read from the helper log tail when finishing a capture, so a
/// runaway/verbose helper log can't be slurped wholesale into the daemon's memory.
const MAX_HELPER_TAIL_BYTES: usize = 256 * 1024;

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
    // capture constructs a path or opens a file, including on the error path.
    if let Err(e) = request.validate() {
        return RequestOutcome::Immediate(
            Vec::new(),
            PrivilegedResponse::Error {
                code: "Validation".into(),
                message: e,
            },
        );
    }

    // For gotatun up/down, capture this request's log output (the service's own lines via the
    // thread-local capture, plus the helper's log file) so it can be streamed to the caller.
    // Begin before the `privileged_request_received` line so it is included.
    let gotatun_capture = gotatun_capture_for(&request);

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
            let logs = finish_gotatun_capture(gotatun_capture);
            RequestOutcome::Immediate(logs, response)
        }
        dispatch::DispatchOutcome::Pending(rx) => RequestOutcome::Pending(rx),
    }
}

struct HelperLogCapture {
    path: std::path::PathBuf,
    offset: u64,
    inode: Option<u64>,
}

/// Capture new output only. A fresh helper replaces its log, while a verified
/// idempotent connect must not replay the previous session's entire log.
fn gotatun_capture_for(request: &PrivilegedRequest) -> Option<HelperLogCapture> {
    use std::os::unix::fs::MetadataExt;
    let PrivilegedRequest::GotaTunRun { interface, .. } = request else {
        return None;
    };
    crate::logging::begin_log_capture();
    let path = commands::gotatun_log_path(interface);
    let metadata = std::fs::symlink_metadata(&path).ok();
    Some(HelperLogCapture {
        path,
        offset: metadata.as_ref().map(|m| m.len()).unwrap_or(0),
        inode: metadata.map(|m| m.ino()),
    })
}

/// Finish a capture started by `gotatun_capture_for`: merge the service's captured lines with the
/// helper's log tail, ordered by timestamp. Returns empty if no capture was active.
fn finish_gotatun_capture(capture: Option<HelperLogCapture>) -> Vec<String> {
    use std::os::unix::fs::MetadataExt;
    let service_lines = crate::logging::take_log_capture();
    let Some(HelperLogCapture {
        path,
        offset,
        inode,
    }) = capture
    else {
        return Vec::new();
    };
    let current_inode = std::fs::symlink_metadata(&path).ok().map(|m| m.ino());
    let offset = if inode == current_inode { offset } else { 0 };
    let helper_lines = read_log_tail(&path, offset);
    merge_log_lines(service_lines, helper_lines)
}

/// Read a log file from `offset` to its end, returned as lines. The offset may land mid-line or
/// even mid-UTF-8-codepoint (it can be derived from a raw `metadata.len()`), so the bytes are
/// split on `\n` and decoded lossily -- a single bad byte can't discard the whole tail. A leading
/// partial line is dropped only when `offset` is verified to fall inside a line. The read is capped
/// at [`MAX_HELPER_TAIL_BYTES`]; past the cap a `(truncated)` marker is appended.
fn read_log_tail(path: &std::path::Path, offset: u64) -> Vec<String> {
    use std::io::{Read, Seek, SeekFrom};
    use std::os::unix::fs::OpenOptionsExt;
    // Finding 2 — Protected log disclosure: a log must be a regular file,
    // never a symlink to another root-readable file or a blocking FIFO.
    let Ok(mut file) = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)
    else {
        return Vec::new();
    };
    if !file.metadata().is_ok_and(|metadata| metadata.is_file()) {
        return Vec::new();
    }

    // Peek at the byte just before `offset`: if it isn't a newline, `offset` sits inside a line and
    // the first chunk we read is a partial line to be discarded. If it is a newline (or offset==0)
    // the first chunk is a whole line and must be kept.
    let starts_mid_line = match offset.checked_sub(1) {
        Some(prev_offset) => {
            if file.seek(SeekFrom::Start(prev_offset)).is_err() {
                return Vec::new();
            }
            let mut prev = [0u8; 1];
            file.read_exact(&mut prev).is_ok() && prev[0] != b'\n'
        }
        None => false,
    };

    if file.seek(SeekFrom::Start(offset)).is_err() {
        return Vec::new();
    }

    // Read at most the cap (+1 byte to detect overflow) so the whole file can't be pulled in.
    let mut buffer = Vec::new();
    if Read::by_ref(&mut file)
        .take(MAX_HELPER_TAIL_BYTES as u64 + 1)
        .read_to_end(&mut buffer)
        .is_err()
    {
        return Vec::new();
    }
    let truncated = buffer.len() > MAX_HELPER_TAIL_BYTES;
    if truncated {
        buffer.truncate(MAX_HELPER_TAIL_BYTES);
    }

    let mut lines: Vec<String> = buffer
        .split(|&byte| byte == b'\n')
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();
    // `split` yields a trailing empty element after the file's final newline.
    if lines.last().is_some_and(String::is_empty) {
        lines.pop();
    }
    if starts_mid_line && !lines.is_empty() {
        lines.remove(0);
    }
    if truncated {
        lines.push("(helper log tail truncated)".to_string());
    }
    lines
}

/// Merge service and helper log lines, ordered by their leading timestamp. The timestamp is a
/// fixed-width prefix so lexicographic order is chronological; a stable sort keeps same-second
/// lines in insertion order (service lines first).
fn merge_log_lines(service: Vec<String>, helper: Vec<String>) -> Vec<String> {
    let mut all = service;
    all.extend(helper);
    // Only reorder lines whose leading token actually looks like our timestamp.
    // When either side has no parseable timestamp we treat the pair as equal so
    // the stable sort leaves them in insertion order (service lines first) rather
    // than trusting a brittle fixed-width slice of whatever the line happens to be.
    all.sort_by(|a, b| match (leading_timestamp(a), leading_timestamp(b)) {
        (Some(ta), Some(tb)) => ta.cmp(tb),
        _ => std::cmp::Ordering::Equal,
    });
    all
}

/// Extract the leading RFC3339 timestamp token (e.g. `2026-06-14T08:18:02Z`) from a
/// log line, or `None` if the first whitespace-delimited token isn't shaped like one.
fn leading_timestamp(line: &str) -> Option<&str> {
    const TIMESTAMP_LEN: usize = "2026-06-14T08:18:02Z".len();
    let token = line.split_whitespace().next()?;
    if token.len() == TIMESTAMP_LEN && token.ends_with('Z') {
        Some(token)
    } else {
        None
    }
}

fn describe_request(request: &PrivilegedRequest) -> &'static str {
    match request {
        PrivilegedRequest::GotaTunRun { .. } => "GotaTunRun",
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

    #[test]
    fn invalid_interface_cannot_disclose_a_log() {
        let path = std::env::temp_dir().join(format!("tunmux-private-{}.log", std::process::id()));
        std::fs::write(&path, "PRIVATE_SENTINEL\n").unwrap();
        let absolute = path.to_str().unwrap().strip_suffix(".log").unwrap();
        for interface in [absolute.to_owned(), format!("../../../{absolute}")] {
            let payload = serde_json::json!({
                "kind": "gota_tun_run", "action": "Up", "interface": interface,
                "config_content": "unused"
            })
            .to_string();
            let RequestOutcome::Immediate(logs, response) =
                process_request_payload(&payload, &mut ControlState::new(false), None)
            else {
                panic!("validation failure must be an immediate response");
            };
            assert!(logs.is_empty());
            assert!(
                matches!(response, PrivilegedResponse::Error { code, .. } if code == "Validation")
            );
        }
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "PRIVATE_SENTINEL\n"
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn log_reader_rejects_symlinks_and_fifos() {
        use std::os::unix::fs::symlink;
        let dir = std::env::temp_dir().join(format!("tunmux-log-types-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let private = dir.join("private.log");
        std::fs::write(&private, "PRIVATE_SENTINEL\n").unwrap();
        let link = dir.join("helper.log");
        symlink(&private, &link).unwrap();
        assert!(read_log_tail(&link, 0).is_empty());
        let fifo = dir.join("fifo.log");
        nix::unistd::mkfifo(
            &fifo,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        assert!(read_log_tail(&fifo, 0).is_empty());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn idempotent_capture_skips_old_log_but_new_helper_starts_at_zero() {
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("tunmux-capture-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("helper.log");
        std::fs::write(&path, "old session\n").unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        let capture = || HelperLogCapture {
            path: path.clone(),
            offset: metadata.len(),
            inode: Some(metadata.ino()),
        };
        assert!(finish_gotatun_capture(Some(capture())).is_empty());
        let replacement = dir.join("new.log");
        std::fs::write(&replacement, "new session\n").unwrap();
        std::fs::rename(&replacement, &path).unwrap();
        assert_eq!(finish_gotatun_capture(Some(capture())), ["new session"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

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

    #[test]
    fn merge_orders_by_timestamp_and_keeps_service_first_on_ties() {
        let service = vec![
            "2026-06-14T08:18:02Z service-a".to_string(),
            "2026-06-14T08:18:04Z service-b".to_string(),
        ];
        let helper = vec![
            "2026-06-14T08:18:01Z helper-a".to_string(),
            "2026-06-14T08:18:02Z helper-b".to_string(),
        ];
        let merged = merge_log_lines(service, helper);
        assert_eq!(
            merged,
            vec![
                "2026-06-14T08:18:01Z helper-a".to_string(),
                // Same second as helper-b: stable sort keeps the service line first.
                "2026-06-14T08:18:02Z service-a".to_string(),
                "2026-06-14T08:18:02Z helper-b".to_string(),
                "2026-06-14T08:18:04Z service-b".to_string(),
            ]
        );
    }

    #[test]
    fn merge_falls_back_to_insertion_order_for_untimestamped_lines() {
        // Lines without a parseable timestamp must not be reordered against each
        // other (no fixed-width slice of arbitrary text decides their order).
        let service = vec![
            "no timestamp here".to_string(),
            "another bare line".to_string(),
        ];
        let helper = vec!["also untimestamped".to_string()];
        let merged = merge_log_lines(service.clone(), helper.clone());
        assert_eq!(merged, [service, helper].concat());
    }

    #[test]
    fn leading_timestamp_only_matches_well_formed_prefix() {
        assert_eq!(
            leading_timestamp("2026-06-14T08:18:02Z hello"),
            Some("2026-06-14T08:18:02Z")
        );
        assert_eq!(leading_timestamp("hello world"), None);
        assert_eq!(leading_timestamp(""), None);
        // Right length but not a timestamp (no trailing Z).
        assert_eq!(leading_timestamp("abcdefghijklmnopqrst rest"), None);
    }

    fn temp_log_path(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("tunmux-tail-{}-{}.log", tag, std::process::id()))
    }

    #[test]
    fn read_log_tail_keeps_whole_lines_from_boundary_offset() {
        let path = temp_log_path("boundary");
        std::fs::write(&path, "line one\nline two\nline three\n").unwrap();
        assert_eq!(
            read_log_tail(&path, 0),
            vec!["line one", "line two", "line three"]
        );
        // Offset 9 is the boundary right after "line one\n"; whole lines are kept.
        assert_eq!(read_log_tail(&path, 9), vec!["line two", "line three"]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_log_tail_drops_leading_partial_line() {
        let path = temp_log_path("partial");
        std::fs::write(&path, "line one\nline two\n").unwrap();
        // Offset 3 lands inside "line one"; the partial prefix is discarded.
        assert_eq!(read_log_tail(&path, 3), vec!["line two"]);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_log_tail_decodes_invalid_utf8_lossily() {
        let path = temp_log_path("utf8");
        // A lone 0xFF byte is invalid UTF-8; the surrounding lines must still survive.
        std::fs::write(&path, b"good\n\xFFbad\n").unwrap();
        let lines = read_log_tail(&path, 0);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], "good");
        assert!(lines[1].contains("bad"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn read_log_tail_caps_oversize_input_with_marker() {
        let path = temp_log_path("truncate");
        let big = "x".repeat(MAX_HELPER_TAIL_BYTES + 1024);
        std::fs::write(&path, format!("{big}\n")).unwrap();
        let lines = read_log_tail(&path, 0);
        assert_eq!(lines.last().unwrap(), "(helper log tail truncated)");
        let _ = std::fs::remove_file(&path);
    }
}
