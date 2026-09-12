use crate::error::AppError;
use crate::privileged_api::{
    ConnectionId, ConnectionScope, ConnectionStartMode, ConnectionSummary, PeerSummary,
    PrivilegedRequest, PrivilegedResponse,
};

use super::authz;
use super::commands::{run_network_overview, run_wg_show};
use super::connection_store::{self, StoredConnection};
use super::ControlState;
use crate::wireguard::connection_config;
use tracing::debug;

/// Identifies the caller for authorization purposes. `Socket(uid)` is a real
/// peer uid from `getpeereid()` on the accepted connection; `Stdio` means the
/// caller has *already proven root* by reaching this process at all (the
/// stdio daemon is only ever spawned via `sudo -n <exe> privileged --serve
/// --stdio`, see `privileged_client/transport.rs`) -- treating it as uid 0 is
/// simply true, not a misattribution.
#[derive(Debug, Clone, Copy)]
pub(super) enum PeerOrigin {
    Socket(u32),
    Stdio,
}

impl PeerOrigin {
    fn uid(self) -> u32 {
        match self {
            PeerOrigin::Socket(uid) => uid,
            PeerOrigin::Stdio => 0,
        }
    }

    fn is_root(self) -> bool {
        self.uid() == 0
    }

    /// Best-effort per-user attribution for a non-global `AddConnection`
    /// when the caller is root only because it's the stdio transport.
    /// Explicitly **not a security boundary**: a process that has already
    /// reached root here could set any environment variable and claim any
    /// UID, but it could already do arbitrary damage as root regardless --
    /// this only decides which per-user bucket a label goes in.
    fn attributed_owner_uid(self) -> u32 {
        match self {
            PeerOrigin::Socket(uid) => uid,
            PeerOrigin::Stdio => std::env::var("SUDO_UID")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        }
    }
}

/// Outcome of one dispatch call. `Pending` is used only by
/// `ConnectConnection`/`DisconnectConnection`: the actual work runs on a
/// spawned worker thread (see the design plan's concurrency correction) so a
/// slow connect/disconnect on one connection cannot freeze the single-threaded
/// accept loop that also has to keep serving every other client.
pub(super) enum DispatchOutcome {
    Immediate(PrivilegedResponse),
    Pending(std::sync::mpsc::Receiver<PrivilegedResponse>),
}

pub(super) fn dispatch(
    request: PrivilegedRequest,
    control_state: &mut ControlState,
    origin: PeerOrigin,
) -> DispatchOutcome {
    match request {
        PrivilegedRequest::LeaseAcquire { token } => {
            control_state.prune_stale_leases();
            control_state.leases.insert(token);
            debug!(
                lease_count = ?control_state.leases.len(), "privileged_lease_acquired");
            DispatchOutcome::Immediate(PrivilegedResponse::Unit)
        }

        PrivilegedRequest::LeaseRelease { token } => {
            control_state.leases.remove(token.as_str());
            control_state.prune_stale_leases();
            debug!(
                lease_count = ?control_state.leases.len(), "privileged_lease_released");
            DispatchOutcome::Immediate(PrivilegedResponse::Unit)
        }

        PrivilegedRequest::ShutdownIfIdle => {
            if !control_state.allow_shutdown {
                return DispatchOutcome::Immediate(PrivilegedResponse::Error {
                    code: "Control".into(),
                    message: "shutdown control is disabled for this daemon instance".into(),
                });
            }
            control_state.shutdown_requested = true;
            control_state.prune_stale_leases();
            debug!(
                remaining_leases = ?control_state.leases.len(), "privileged_shutdown_if_idle_requested");
            DispatchOutcome::Immediate(PrivilegedResponse::Bool(control_state.leases.is_empty()))
        }

        PrivilegedRequest::WgShow { interface } => {
            if let Some(response) = legacy_interface_access_denied(&interface, origin) {
                return DispatchOutcome::Immediate(response);
            }
            DispatchOutcome::Immediate(match run_wg_show(interface.as_str()) {
                Ok(output) => PrivilegedResponse::Text(output),
                Err(e) => PrivilegedResponse::Error {
                    code: categorize_error(&e),
                    message: format!("{}", e),
                },
            })
        }

        PrivilegedRequest::NetworkOverview { interface } => {
            if let Some(response) = legacy_interface_access_denied(&interface, origin) {
                return DispatchOutcome::Immediate(response);
            }
            DispatchOutcome::Immediate(match run_network_overview(interface.as_str()) {
                // No query socket (kernel backend, or not up): empty text
                // tells the caller to render nothing rather than an error.
                Ok(overview) => PrivilegedResponse::Text(overview.unwrap_or_default()),
                Err(e) => PrivilegedResponse::Error {
                    code: categorize_error(&e),
                    message: format!("{}", e),
                },
            })
        }

        PrivilegedRequest::InterfaceActive { interface } => {
            if let Some(response) = legacy_interface_access_denied(&interface, origin) {
                return DispatchOutcome::Immediate(response);
            }
            // The userspace UAPI control socket. Checked here (as root) because
            // `/var/run/wireguard` is `0750 root:daemon` and unreachable from an
            // unprivileged caller; this mirrors the old local `exists()` probe
            // but from a context that can actually see the socket.
            let socket_path =
                std::path::Path::new("/var/run/wireguard").join(format!("{interface}.sock"));
            DispatchOutcome::Immediate(PrivilegedResponse::Bool(socket_path.exists()))
        }

        PrivilegedRequest::AddConnection {
            conf_text,
            global,
            start_mode,
            name,
            mtu_override,
            auth_external_form,
        } => DispatchOutcome::Immediate(handle_add_connection(
            origin,
            conf_text,
            global,
            start_mode,
            name,
            mtu_override,
            auth_external_form,
        )),

        PrivilegedRequest::RemoveConnection {
            id,
            auth_external_form,
        } => DispatchOutcome::Immediate(handle_remove_connection(origin, id, auth_external_form)),

        PrivilegedRequest::ConnectConnection { id, debug } => {
            handle_connect_connection(origin, id, debug)
        }

        PrivilegedRequest::DisconnectConnection { id } => handle_disconnect_connection(origin, id),

        PrivilegedRequest::SetConnectionMode {
            id,
            start_mode,
            auth_external_form,
        } => DispatchOutcome::Immediate(handle_set_connection_mode(
            origin,
            id,
            start_mode,
            auth_external_form,
        )),

        PrivilegedRequest::ListConnections { scope } => {
            DispatchOutcome::Immediate(handle_list_connections(origin, scope))
        }

        PrivilegedRequest::GetConnection { id } => {
            DispatchOutcome::Immediate(handle_get_connection(origin, id))
        }
    }
}

// ---- connection-store request handlers -------------------------------------

fn handle_add_connection(
    origin: PeerOrigin,
    conf_text: String,
    global: bool,
    start_mode: ConnectionStartMode,
    name: Option<String>,
    mtu_override: Option<u16>,
    auth_external_form: Option<Vec<u8>>,
) -> PrivilegedResponse {
    if global && !origin.is_root() {
        return auth_denied("adding a global connection requires root");
    }
    let owner_uid = if global {
        None
    } else {
        Some(origin.attributed_owner_uid())
    };

    let conf_text = match mtu_override {
        Some(mtu) => apply_mtu_override_to_conf_text(&conf_text, mtu),
        None => conf_text,
    };
    let parsed = match connection_config::parse_connection_config(&conf_text) {
        Ok(parsed) => parsed,
        Err(error) => return error_response(error),
    };
    let fingerprint = connection_config::fingerprint(&parsed);

    let index_lock = match connection_store::lock_index() {
        Ok(lock) => lock,
        Err(error) => return lock_error_response(error),
    };

    match connection_store::find_by_identity(&index_lock, &fingerprint, global, owner_uid) {
        Ok(Some(existing)) => return PrivilegedResponse::ConnectionId(existing.id),
        Ok(None) => {}
        Err(error) => return error_response(error),
    }

    // A genuinely new/changed configuration: requires admin authentication
    // (see `authz`) regardless of `global`, since this is the only path
    // through which root-executed hook content can enter the store.
    if let Err(response) = require_admin_auth(auth_external_form.as_deref()) {
        return response;
    }

    let (id, interface) = match connection_store::allocate_unique_interface(&index_lock) {
        Ok(value) => value,
        Err(error) => return error_response(error),
    };
    let now = connection_store::now_unix();
    let stored = StoredConnection {
        id,
        fingerprint,
        global,
        owner_uid,
        start_mode,
        name,
        config: parsed,
        raw_conf: conf_text,
        interface,
        created_at: now,
        updated_at: now,
    };
    match connection_store::create(&index_lock, &stored) {
        Ok(()) => PrivilegedResponse::ConnectionId(id),
        Err(error) => error_response(error),
    }
}

fn handle_remove_connection(
    origin: PeerOrigin,
    id: ConnectionId,
    auth_external_form: Option<Vec<u8>>,
) -> PrivilegedResponse {
    let index_lock = match connection_store::lock_index() {
        Ok(lock) => lock,
        Err(error) => return lock_error_response(error),
    };
    let stored = match connection_store::load(id) {
        Ok(Some(stored)) => stored,
        Ok(None) => return not_found(),
        Err(error) => return error_response(error),
    };
    if let Some(response) = authorize_access(&stored, origin) {
        return response;
    }
    let conn_lock = match connection_store::lock_connection(id) {
        Ok(lock) => lock,
        Err(error) => return lock_error_response(error),
    };
    match connection_store::is_active(id) {
        Ok(true) => {
            return PrivilegedResponse::Error {
                code: "Busy".into(),
                message: "connection is active; disconnect it before removing".into(),
            }
        }
        Ok(false) => {}
        Err(error) => return error_response(error),
    }
    if let Err(response) = require_admin_auth(auth_external_form.as_deref()) {
        return response;
    }
    match connection_store::remove(&index_lock, &conn_lock, id) {
        Ok(()) => PrivilegedResponse::Unit,
        Err(error) => error_response(error),
    }
}

fn handle_connect_connection(origin: PeerOrigin, id: ConnectionId, debug: bool) -> DispatchOutcome {
    let stored = match connection_store::load(id) {
        Ok(Some(stored)) => stored,
        Ok(None) => return DispatchOutcome::Immediate(not_found()),
        Err(error) => return DispatchOutcome::Immediate(error_response(error)),
    };
    if let Some(response) = authorize_access(&stored, origin) {
        return DispatchOutcome::Immediate(response);
    }
    let (tx, rx) = std::sync::mpsc::channel();
    // The store's root-directory override is thread-local (see
    // `connection_store::current_test_root`'s doc comment); a spawned worker
    // thread needs it re-applied explicitly so a test exercising this path
    // doesn't reach for the real system path from the worker thread.
    #[cfg(test)]
    let test_root = connection_store::current_test_root();
    std::thread::spawn(move || {
        #[cfg(test)]
        if let Some(root) = test_root {
            connection_store::set_test_root(root);
        }
        let response = match connection_store::lock_connection(id) {
            Ok(conn_lock) => match super::connection_ops::connect(&conn_lock, id, debug) {
                Ok(()) => PrivilegedResponse::Unit,
                Err(error) => error_response(error),
            },
            Err(error) => lock_error_response(error),
        };
        let _ = tx.send(response);
    });
    DispatchOutcome::Pending(rx)
}

fn handle_disconnect_connection(origin: PeerOrigin, id: ConnectionId) -> DispatchOutcome {
    let stored = match connection_store::load(id) {
        Ok(Some(stored)) => stored,
        Ok(None) => return DispatchOutcome::Immediate(not_found()),
        Err(error) => return DispatchOutcome::Immediate(error_response(error)),
    };
    if let Some(response) = authorize_access(&stored, origin) {
        return DispatchOutcome::Immediate(response);
    }
    let (tx, rx) = std::sync::mpsc::channel();
    #[cfg(test)]
    let test_root = connection_store::current_test_root();
    std::thread::spawn(move || {
        #[cfg(test)]
        if let Some(root) = test_root {
            connection_store::set_test_root(root);
        }
        let response = match connection_store::lock_connection(id) {
            Ok(conn_lock) => match super::connection_ops::disconnect(&conn_lock, id) {
                Ok(()) => PrivilegedResponse::Unit,
                Err(error) => error_response(error),
            },
            Err(error) => lock_error_response(error),
        };
        let _ = tx.send(response);
    });
    DispatchOutcome::Pending(rx)
}

fn handle_set_connection_mode(
    origin: PeerOrigin,
    id: ConnectionId,
    start_mode: ConnectionStartMode,
    auth_external_form: Option<Vec<u8>>,
) -> PrivilegedResponse {
    let conn_lock = match connection_store::lock_connection(id) {
        Ok(lock) => lock,
        Err(error) => return lock_error_response(error),
    };
    let mut stored = match connection_store::load(id) {
        Ok(Some(stored)) => stored,
        Ok(None) => return not_found(),
        Err(error) => return error_response(error),
    };
    if let Some(response) = authorize_access(&stored, origin) {
        return response;
    }

    // The "elevating" transition: this is what makes a hook-bearing config
    // auto-run as root at every future boot with no further human
    // involvement, so it alone requires admin authentication. Every other
    // transition (per-user, downgrading global to Manual, or a no-op)
    // proceeds on ownership alone.
    let elevating = stored.global
        && stored.start_mode == ConnectionStartMode::Manual
        && start_mode == ConnectionStartMode::Automatic;
    if elevating {
        if let Err(response) = require_admin_auth(auth_external_form.as_deref()) {
            return response;
        }
    }

    if stored.start_mode == start_mode {
        return PrivilegedResponse::Unit;
    }
    stored.start_mode = start_mode;
    stored.updated_at = connection_store::now_unix();
    match connection_store::update(&conn_lock, &stored) {
        Ok(()) => PrivilegedResponse::Unit,
        Err(error) => error_response(error),
    }
}

fn handle_list_connections(origin: PeerOrigin, scope: ConnectionScope) -> PrivilegedResponse {
    if matches!(scope, ConnectionScope::All) && !origin.is_root() {
        return auth_denied("listing all connections requires root");
    }
    let all = match connection_store::load_all() {
        Ok(all) => all,
        Err(error) => return error_response(error),
    };
    let filtered: Vec<StoredConnection> = all
        .into_iter()
        .filter(|conn| match scope {
            ConnectionScope::Mine => conn.owner_uid == Some(origin.uid()),
            ConnectionScope::Global => conn.global,
            ConnectionScope::All => true,
        })
        .collect();
    let summaries = filtered
        .iter()
        .map(|conn| {
            let connected = connection_store::is_active(conn.id).unwrap_or(false);
            summarize(conn, connected, false)
        })
        .collect();
    PrivilegedResponse::ConnectionList(summaries)
}

fn handle_get_connection(origin: PeerOrigin, id: ConnectionId) -> PrivilegedResponse {
    let stored = match connection_store::load(id) {
        Ok(Some(stored)) => stored,
        Ok(None) => return not_found(),
        Err(error) => return error_response(error),
    };
    if let Some(response) = authorize_access(&stored, origin) {
        return response;
    }
    let connected = connection_store::is_active(id).unwrap_or(false);
    PrivilegedResponse::Connection(summarize(&stored, connected, true))
}

// ---- shared helpers ---------------------------------------------------------

/// A global record has no owner other than root; a per-user record's owner
/// (or root) may access/mutate it. Used for both read (`GetConnection`) and
/// mutating (`Remove`/`Connect`/`Disconnect`/`SetConnectionMode`) requests --
/// the design plan applies the same ownership rule to both.
fn authorize_access(record: &StoredConnection, origin: PeerOrigin) -> Option<PrivilegedResponse> {
    let authorized = if record.global {
        origin.is_root()
    } else {
        origin.is_root() || Some(origin.uid()) == record.owner_uid
    };
    if authorized {
        None
    } else {
        Some(auth_denied("not authorized for this connection"))
    }
}

/// Gate for the legacy interface-string-keyed ops (`WgShow`,
/// `NetworkOverview`, `InterfaceActive`), which predate per-connection
/// ownership and take a bare interface name with no id to authorize against.
/// If `interface` happens to be a stored connection's own interface (derived
/// deterministically from its id, and in practice learnable by any reachable
/// caller via a `ListConnections{Global}` response), apply the exact same
/// ownership rule the new ops use; a name that matches no stored connection
/// (e.g. `wgconf0`, or a bare `utunN`) is not gated at all, preserving
/// pre-existing behavior for genuinely unmanaged
/// interfaces. Without this, any reachable `tunmux`-group member could learn
/// a global connection's interface name from `ListConnections` and then use
/// these ungated legacy ops to read its peer/handshake data or tear it down.
fn legacy_interface_access_denied(
    interface: &str,
    origin: PeerOrigin,
) -> Option<PrivilegedResponse> {
    match connection_store::find_by_interface(interface) {
        Ok(Some(record)) => authorize_access(&record, origin),
        Ok(None) => None,
        Err(error) => Some(error_response(error)),
    }
}

// `PrivilegedResponse` is used as an Err type here purely as a short-circuit
// return value for dispatch handlers (matching their own return type), not
// propagated through a real error chain, so its size is not a concern here.
#[allow(clippy::result_large_err)]
fn require_admin_auth(form: Option<&[u8]>) -> std::result::Result<(), PrivilegedResponse> {
    match form {
        None => Err(auth_required()),
        Some(bytes) => authz::verify_external_form(bytes).map_err(|error| match error {
            AppError::Auth(message) => auth_denied(message),
            other => auth_denied(other.to_string()),
        }),
    }
}

fn summarize(
    conn: &StoredConnection,
    connected: bool,
    include_fingerprint: bool,
) -> ConnectionSummary {
    ConnectionSummary {
        id: conn.id,
        global: conn.global,
        owner_uid: conn.owner_uid,
        start_mode: conn.start_mode,
        name: conn.name.clone(),
        interface: conn.interface.clone(),
        connected,
        addresses: conn
            .config
            .addresses
            .iter()
            .map(ToString::to_string)
            .collect(),
        dns_servers: conn
            .config
            .dns_servers
            .iter()
            .map(ToString::to_string)
            .collect(),
        mtu: conn.config.mtu,
        peers: conn
            .config
            .peers
            .iter()
            .map(|peer| PeerSummary {
                public_key: connection_config::public_key_to_base64(&peer.public_key),
                allowed_ips: peer.allowed_ips.iter().map(ToString::to_string).collect(),
                endpoint: peer.endpoint_literal.clone(),
                has_preshared_key: peer.preshared_key.is_some(),
            })
            .collect(),
        fingerprint: if include_fingerprint {
            Some(conn.fingerprint.clone())
        } else {
            None
        },
        created_at: conn.created_at,
        updated_at: conn.updated_at,
    }
}

/// Rewrite (or insert) the `[Interface]` section's `MTU` directive in `conf_text`
/// before it is ever parsed/fingerprinted/stored, so the stored `raw_conf` and
/// the parsed `ConnectionConfig` always agree -- required for
/// `ConnectConnection`'s anti-drift re-parse check (`connection_ops::reparse_and_verify`),
/// which would otherwise see the override reflected in `config.mtu` but not in
/// the text it re-parses from.
fn apply_mtu_override_to_conf_text(conf_text: &str, mtu: u16) -> String {
    let mut in_interface = false;
    let mut found = false;
    let mut out = String::with_capacity(conf_text.len() + 16);
    for raw_line in conf_text.lines() {
        let trimmed = raw_line.trim();
        if trimmed.starts_with('[') {
            in_interface = trimmed.eq_ignore_ascii_case("[interface]");
            out.push_str(raw_line);
            out.push('\n');
            continue;
        }
        if in_interface {
            if let Some((key, _)) = trimmed.split_once('=') {
                if key.trim().eq_ignore_ascii_case("mtu") {
                    out.push_str(&format!("MTU = {mtu}\n"));
                    found = true;
                    continue;
                }
            }
        }
        out.push_str(raw_line);
        out.push('\n');
    }
    if found {
        return out;
    }
    // No existing MTU directive: insert one right after the [Interface] header.
    let mut result = String::with_capacity(out.len() + 16);
    let mut inserted = false;
    for line in out.lines() {
        result.push_str(line);
        result.push('\n');
        if !inserted && line.trim().eq_ignore_ascii_case("[interface]") {
            result.push_str(&format!("MTU = {mtu}\n"));
            inserted = true;
        }
    }
    result
}

fn not_found() -> PrivilegedResponse {
    PrivilegedResponse::Error {
        code: "NotFound".into(),
        message: "connection not found".into(),
    }
}

fn auth_denied(message: impl Into<String>) -> PrivilegedResponse {
    PrivilegedResponse::Error {
        code: "Auth".into(),
        message: message.into(),
    }
}

fn auth_required() -> PrivilegedResponse {
    PrivilegedResponse::Error {
        code: "AuthRequired".into(),
        message: "admin authentication required for this change".into(),
    }
}

fn busy(message: impl Into<String>) -> PrivilegedResponse {
    PrivilegedResponse::Error {
        code: "Busy".into(),
        message: message.into(),
    }
}

fn error_response(error: AppError) -> PrivilegedResponse {
    match error {
        AppError::Auth(message) => auth_denied(message),
        AppError::WireGuard(message) => PrivilegedResponse::Error {
            code: "WireGuard".into(),
            message,
        },
        other => PrivilegedResponse::Error {
            code: "Other".into(),
            message: other.to_string(),
        },
    }
}

fn lock_error_response(error: AppError) -> PrivilegedResponse {
    if let AppError::Io(io_error) = &error {
        if io_error.kind() == std::io::ErrorKind::WouldBlock {
            return busy(
                "another operation on this connection is in progress; retry once it finishes",
            );
        }
    }
    error_response(error)
}

pub(super) fn categorize_error(error: &AppError) -> String {
    if matches!(error, AppError::WireGuard(_)) {
        "WireGuard".into()
    } else {
        "Kernel".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_CONF: &str = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.1:51820\n";

    /// Point the connection store at a throwaway temp directory for the
    /// duration of `body`, then clean it up. Each test runs on its own
    /// thread by default, so this thread-local override isolates tests from
    /// each other and from the real (root-owned) system path.
    fn with_test_store<R>(label: &str, body: impl FnOnce() -> R) -> R {
        let dir = std::env::temp_dir().join(format!(
            "tunmux-dispatch-test-{label}-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        connection_store::set_test_root(dir.clone());
        let result = body();
        let _ = std::fs::remove_dir_all(&dir);
        result
    }

    fn add_connection(
        origin: PeerOrigin,
        conf: &str,
        global: bool,
        auth: Option<Vec<u8>>,
    ) -> PrivilegedResponse {
        handle_add_connection(
            origin,
            conf.to_string(),
            global,
            ConnectionStartMode::Manual,
            None,
            None,
            auth,
        )
    }

    fn valid_auth() -> Option<Vec<u8>> {
        Some(authz::TEST_VALID_EXTERNAL_FORM.to_vec())
    }

    fn connection_id(response: &PrivilegedResponse) -> ConnectionId {
        match response {
            PrivilegedResponse::ConnectionId(id) => *id,
            other => panic!("expected ConnectionId response, got {other:?}"),
        }
    }

    fn error_code(response: &PrivilegedResponse) -> &str {
        match response {
            PrivilegedResponse::Error { code, .. } => code.as_str(),
            other => panic!("expected an Error response, got {other:?}"),
        }
    }

    #[test]
    fn add_connection_global_requires_root() {
        with_test_store("global-root", || {
            let response = add_connection(PeerOrigin::Socket(501), SAMPLE_CONF, true, valid_auth());
            assert_eq!(error_code(&response), "Auth");
        });
    }

    #[test]
    fn add_connection_new_config_requires_admin_auth_then_succeeds_with_it() {
        with_test_store("new-config-auth", || {
            let without_token = add_connection(PeerOrigin::Socket(0), SAMPLE_CONF, true, None);
            assert_eq!(error_code(&without_token), "AuthRequired");

            let with_token = add_connection(PeerOrigin::Socket(0), SAMPLE_CONF, true, valid_auth());
            assert!(matches!(with_token, PrivilegedResponse::ConnectionId(_)));
        });
    }

    #[test]
    fn add_connection_rejects_a_forged_auth_token() {
        with_test_store("forged-token", || {
            let bogus: Option<Vec<u8>> = Some(vec![0u8; authz::EXTERNAL_FORM_LENGTH]);
            let response = add_connection(PeerOrigin::Socket(0), SAMPLE_CONF, true, bogus);
            assert_eq!(error_code(&response), "Auth");
        });
    }

    #[test]
    fn add_connection_identical_resubmission_is_idempotent_without_auth() {
        with_test_store("dedup", || {
            let first = add_connection(PeerOrigin::Socket(0), SAMPLE_CONF, true, valid_auth());
            let first_id = connection_id(&first);

            // No auth token this time: an exact-match resubmission must be a
            // silent no-op, never re-engaging the admin-auth flow.
            let second = add_connection(PeerOrigin::Socket(0), SAMPLE_CONF, true, None);
            assert_eq!(connection_id(&second), first_id);
        });
    }

    #[test]
    fn add_connection_same_text_different_global_scope_is_a_distinct_connection() {
        with_test_store("scope-distinct", || {
            let global = connection_id(&add_connection(
                PeerOrigin::Socket(0),
                SAMPLE_CONF,
                true,
                valid_auth(),
            ));
            let per_user = connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));
            assert_ne!(global, per_user);
        });
    }

    #[test]
    fn remove_connection_nonexistent_returns_not_found_without_engaging_auth() {
        with_test_store("remove-missing", || {
            let response =
                handle_remove_connection(PeerOrigin::Socket(0), ConnectionId::new(), None);
            assert_eq!(error_code(&response), "NotFound");
        });
    }

    #[test]
    fn remove_connection_requires_ownership_or_root() {
        with_test_store("remove-ownership", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));

            let denied = handle_remove_connection(PeerOrigin::Socket(502), id, valid_auth());
            assert_eq!(error_code(&denied), "Auth");

            let owner_without_auth = handle_remove_connection(PeerOrigin::Socket(501), id, None);
            assert_eq!(error_code(&owner_without_auth), "AuthRequired");

            let owner_with_auth =
                handle_remove_connection(PeerOrigin::Socket(501), id, valid_auth());
            assert!(matches!(owner_with_auth, PrivilegedResponse::Unit));
        });
    }

    #[test]
    fn root_may_remove_any_users_connection() {
        with_test_store("remove-root", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));
            let response = handle_remove_connection(PeerOrigin::Socket(0), id, valid_auth());
            assert!(matches!(response, PrivilegedResponse::Unit));
        });
    }

    #[test]
    fn connect_and_disconnect_reject_a_non_owner_before_spawning_any_worker() {
        with_test_store("connect-ownership", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));

            match handle_connect_connection(PeerOrigin::Socket(502), id, false) {
                DispatchOutcome::Immediate(response) => assert_eq!(error_code(&response), "Auth"),
                DispatchOutcome::Pending(_) => {
                    panic!("unauthorized connect must not spawn a worker")
                }
            }
            match handle_disconnect_connection(PeerOrigin::Socket(502), id) {
                DispatchOutcome::Immediate(response) => assert_eq!(error_code(&response), "Auth"),
                DispatchOutcome::Pending(_) => {
                    panic!("unauthorized disconnect must not spawn a worker")
                }
            }
        });
    }

    fn error_code_opt(response: &PrivilegedResponse) -> Option<&str> {
        match response {
            PrivilegedResponse::Error { code, .. } => Some(code.as_str()),
            _ => None,
        }
    }

    #[test]
    fn legacy_wg_show_is_gated_by_ownership_when_interface_belongs_to_a_connection() {
        // Regression test: WgShow/NetworkOverview/InterfaceActive predate
        // per-connection ownership and take a bare interface name; without
        // `legacy_interface_access_denied` any reachable caller could learn a
        // global connection's interface via ListConnections and then read
        // (WgShow) or otherwise act on it despite not owning it.
        with_test_store("legacy-gate-wgshow", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));
            let interface = connection_store::load(id).unwrap().unwrap().interface;
            let mut control_state = ControlState::new(false);

            let denied = dispatch(
                PrivilegedRequest::WgShow {
                    interface: interface.clone(),
                },
                &mut control_state,
                PeerOrigin::Socket(502),
            );
            match denied {
                DispatchOutcome::Immediate(response) => assert_eq!(error_code(&response), "Auth"),
                DispatchOutcome::Pending(_) => panic!("WgShow must be an immediate response"),
            }

            // The owner is not blocked by the ownership gate (WgShow itself
            // still errors here since no real tunnel is up in this
            // environment, but that error must not be "Auth").
            let owner_attempt = dispatch(
                PrivilegedRequest::WgShow { interface },
                &mut control_state,
                PeerOrigin::Socket(501),
            );
            match owner_attempt {
                DispatchOutcome::Immediate(response) => {
                    assert_ne!(error_code_opt(&response), Some("Auth"))
                }
                DispatchOutcome::Pending(_) => panic!("WgShow must be an immediate response"),
            }
        });
    }

    #[test]
    fn legacy_ops_on_an_unmanaged_interface_are_not_gated() {
        // An interface name that matches no stored connection (the legacy
        // wgconf CLI path) must behave exactly as before -- no ownership
        // concept applies to it.
        with_test_store("legacy-unmanaged", || {
            let mut control_state = ControlState::new(false);
            let response = dispatch(
                PrivilegedRequest::InterfaceActive {
                    interface: "wgconf0".to_string(),
                },
                &mut control_state,
                PeerOrigin::Socket(501),
            );
            match response {
                DispatchOutcome::Immediate(PrivilegedResponse::Bool(_)) => {}
                DispatchOutcome::Immediate(_) => {
                    panic!("expected an unauthorized-gate-free Bool response")
                }
                DispatchOutcome::Pending(_) => {
                    panic!("InterfaceActive must be an immediate response")
                }
            }
        });
    }

    #[test]
    fn connect_on_nonexistent_connection_is_not_found() {
        with_test_store("connect-missing", || {
            match handle_connect_connection(PeerOrigin::Socket(0), ConnectionId::new(), false) {
                DispatchOutcome::Immediate(response) => {
                    assert_eq!(error_code(&response), "NotFound")
                }
                DispatchOutcome::Pending(_) => {
                    panic!("nonexistent connection must not spawn a worker")
                }
            }
        });
    }

    #[test]
    fn connect_by_the_owner_spawns_a_worker_and_eventually_responds() {
        with_test_store("connect-worker", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));
            match handle_connect_connection(PeerOrigin::Socket(501), id, false) {
                DispatchOutcome::Pending(rx) => {
                    // The actual gotatun bring-up will fail in this
                    // environment (no root networking access); this only
                    // proves the worker plumbing itself completes rather
                    // than hanging. A real bring-up is a manual end-to-end
                    // check (see the design plan's Verification section).
                    let response = rx
                        .recv_timeout(std::time::Duration::from_secs(20))
                        .expect("worker thread must eventually respond");
                    let _ = response;
                }
                DispatchOutcome::Immediate(response) => {
                    panic!("authorized connect must spawn a worker, got {response:?}")
                }
            }
        });
    }

    #[test]
    fn set_connection_mode_elevating_a_global_connection_requires_auth() {
        with_test_store("mode-elevate", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(0),
                SAMPLE_CONF,
                true,
                valid_auth(),
            ));

            let without_auth = handle_set_connection_mode(
                PeerOrigin::Socket(0),
                id,
                ConnectionStartMode::Automatic,
                None,
            );
            assert_eq!(error_code(&without_auth), "AuthRequired");

            let with_auth = handle_set_connection_mode(
                PeerOrigin::Socket(0),
                id,
                ConnectionStartMode::Automatic,
                valid_auth(),
            );
            assert!(matches!(with_auth, PrivilegedResponse::Unit));
        });
    }

    #[test]
    fn set_connection_mode_downgrading_a_global_connection_needs_no_auth() {
        with_test_store("mode-downgrade", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(0),
                SAMPLE_CONF,
                true,
                valid_auth(),
            ));
            handle_set_connection_mode(
                PeerOrigin::Socket(0),
                id,
                ConnectionStartMode::Automatic,
                valid_auth(),
            );

            let response = handle_set_connection_mode(
                PeerOrigin::Socket(0),
                id,
                ConnectionStartMode::Manual,
                None,
            );
            assert!(matches!(response, PrivilegedResponse::Unit));
        });
    }

    #[test]
    fn set_connection_mode_on_a_per_user_connection_needs_no_auth() {
        with_test_store("mode-per-user", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));
            let response = handle_set_connection_mode(
                PeerOrigin::Socket(501),
                id,
                ConnectionStartMode::Automatic,
                None,
            );
            assert!(matches!(response, PrivilegedResponse::Unit));
        });
    }

    #[test]
    fn set_connection_mode_no_op_needs_no_auth() {
        with_test_store("mode-noop", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(0),
                SAMPLE_CONF,
                true,
                valid_auth(),
            ));
            // Already Manual; re-requesting Manual is a no-op even though the
            // connection is global.
            let response = handle_set_connection_mode(
                PeerOrigin::Socket(0),
                id,
                ConnectionStartMode::Manual,
                None,
            );
            assert!(matches!(response, PrivilegedResponse::Unit));
        });
    }

    #[test]
    fn list_connections_all_requires_root() {
        with_test_store("list-all", || {
            let response = handle_list_connections(PeerOrigin::Socket(501), ConnectionScope::All);
            assert_eq!(error_code(&response), "Auth");
            let response = handle_list_connections(PeerOrigin::Socket(0), ConnectionScope::All);
            assert!(matches!(response, PrivilegedResponse::ConnectionList(_)));
        });
    }

    #[test]
    fn list_connections_mine_filters_by_owner() {
        with_test_store("list-mine", || {
            connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));
            let conf_other = SAMPLE_CONF.replace("DNS = 1.1.1.1", "DNS = 9.9.9.9");
            connection_id(&add_connection(
                PeerOrigin::Socket(502),
                &conf_other,
                false,
                valid_auth(),
            ));

            let PrivilegedResponse::ConnectionList(mine) =
                handle_list_connections(PeerOrigin::Socket(501), ConnectionScope::Mine)
            else {
                panic!("expected a connection list");
            };
            assert_eq!(mine.len(), 1);
            assert_eq!(mine[0].owner_uid, Some(501));
        });
    }

    #[test]
    fn get_connection_requires_ownership_and_only_then_includes_fingerprint() {
        with_test_store("get-connection", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));

            let denied = handle_get_connection(PeerOrigin::Socket(502), id);
            assert_eq!(error_code(&denied), "Auth");

            let PrivilegedResponse::Connection(summary) =
                handle_get_connection(PeerOrigin::Socket(501), id)
            else {
                panic!("expected a connection summary");
            };
            assert!(summary.fingerprint.is_some());
        });
    }

    #[test]
    fn list_connections_never_includes_a_fingerprint() {
        with_test_store("list-no-fingerprint", || {
            connection_id(&add_connection(
                PeerOrigin::Socket(0),
                SAMPLE_CONF,
                true,
                valid_auth(),
            ));
            let PrivilegedResponse::ConnectionList(all) =
                handle_list_connections(PeerOrigin::Socket(0), ConnectionScope::Global)
            else {
                panic!("expected a connection list");
            };
            assert_eq!(all.len(), 1);
            assert!(all[0].fingerprint.is_none());
        });
    }

    #[test]
    fn mtu_override_is_baked_into_raw_conf_before_fingerprinting() {
        with_test_store("mtu-override", || {
            let response = handle_add_connection(
                PeerOrigin::Socket(0),
                SAMPLE_CONF.to_string(),
                true,
                ConnectionStartMode::Manual,
                None,
                Some(1280),
                valid_auth(),
            );
            let id = connection_id(&response);
            let stored = connection_store::load(id).unwrap().unwrap();
            assert_eq!(stored.config.mtu, Some(1280));
            assert!(stored.raw_conf.contains("MTU = 1280"));
            // The anti-drift check depends on this agreeing exactly.
            let reparsed = connection_config::parse_connection_config(&stored.raw_conf).unwrap();
            assert_eq!(
                connection_config::fingerprint(&reparsed),
                stored.fingerprint
            );
        });
    }

    #[test]
    fn apply_mtu_override_inserts_when_absent_and_replaces_when_present() {
        let inserted = apply_mtu_override_to_conf_text(
            "[Interface]\nPrivateKey = a\nAddress = 10.0.0.2/32\n",
            1300,
        );
        assert!(inserted.contains("[Interface]\nMTU = 1300\n"));

        let replaced = apply_mtu_override_to_conf_text(
            "[Interface]\nMTU = 1400\nAddress = 10.0.0.2/32\n",
            1300,
        );
        assert!(replaced.contains("MTU = 1300"));
        assert!(!replaced.contains("1400"));
    }
}
