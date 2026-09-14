use crate::error::AppError;
use crate::privileged_api::{
    ConnectReason, ConnectionId, ConnectionScope, ConnectionStartMode, ConnectionSummary,
    DisconnectReason, PeerSummary, PrivilegedRequest, PrivilegedResponse,
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
            force,
            auth_external_form,
        } => DispatchOutcome::Immediate(handle_add_connection(
            origin,
            conf_text,
            global,
            start_mode,
            name,
            mtu_override,
            force,
            auth_external_form,
        )),

        PrivilegedRequest::RemoveConnection {
            id,
            auth_external_form,
        } => DispatchOutcome::Immediate(handle_remove_connection(origin, id, auth_external_form)),

        PrivilegedRequest::ConnectConnection { id, debug, reason } => {
            handle_connect_connection(origin, id, debug, reason)
        }

        PrivilegedRequest::DisconnectConnection { id, reason } => {
            handle_disconnect_connection(origin, id, reason)
        }

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

#[allow(clippy::too_many_arguments)]
fn handle_add_connection(
    origin: PeerOrigin,
    conf_text: String,
    global: bool,
    start_mode: ConnectionStartMode,
    name: Option<String>,
    mtu_override: Option<u16>,
    force: bool,
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
        Ok(Some(existing)) => {
            return reconcile_existing_add(
                &index_lock,
                existing,
                name,
                start_mode,
                force,
                auth_external_form.as_deref(),
            );
        }
        Ok(None) => {}
        Err(error) => return error_response(error),
    }

    // Not the exact-match case above, so this is either a genuinely new name
    // or a changed config superseding an old record under the same name.
    // Reject the latter unless the caller passed `force`, so a `name` a
    // `ConnectConnection`-by-name lookup could resolve stays unique; `force`
    // callers are expected to remove the superseded record right after this
    // call returns its (different) id.
    if !force {
        if let Some(name) = &name {
            match connection_store::find_by_name(&index_lock, name, global, owner_uid) {
                Ok(Some(existing)) => {
                    return PrivilegedResponse::Error {
                        code: "NameInUse".into(),
                        message: format!(
                            "a connection named {name:?} already exists ({}); remove it first, or resubmit allowing the name to be replaced",
                            existing.id
                        ),
                    };
                }
                Ok(None) => {}
                Err(error) => return error_response(error),
            }
        }
    }

    // A genuinely new/changed configuration: requires admin authentication
    // (see `authz`) regardless of `global`, since this is the only path
    // through which root-executed hook content can enter the store.
    if let Err(response) = require_admin_auth(
        auth_external_form.as_deref(),
        "storing a new or changed connection configuration that may contain hooks executed as root",
    ) {
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
        user_disconnected: false,
    };
    match connection_store::create(&index_lock, &stored) {
        Ok(()) => PrivilegedResponse::ConnectionId(id),
        Err(error) => error_response(error),
    }
}

/// `AddConnection`'s exact-match dedup path (see §2 of the design plan):
/// byte-for-byte-identical parsed content is a no-op for the config itself,
/// but the caller may still be asking to change this record's mutable
/// metadata (`name`, `start_mode`) -- e.g. `make install`'s `connection add
/// --force --start-mode automatic` re-running against a connection a user
/// has since set back to `manual`. Without this, an identical resubmission
/// would silently ignore a genuinely requested `name`/`start_mode` change.
/// The caller already holds [`connection_store::IndexLock`]; `owner_uid` in
/// the identity lookup that produced `existing` was either the caller's own
/// attributed uid (per-user) or required root (global, checked before this
/// is ever reached), so `existing` is already known to be this caller's own
/// record -- no separate ownership check needed here.
fn reconcile_existing_add(
    index_lock: &connection_store::IndexLock,
    mut existing: StoredConnection,
    name: Option<String>,
    start_mode: ConnectionStartMode,
    force: bool,
    auth_external_form: Option<&[u8]>,
) -> PrivilegedResponse {
    let id = existing.id;
    let name_changed = name.is_some() && name != existing.name;
    let mode_changed = start_mode != existing.start_mode;
    if !name_changed && !mode_changed {
        return PrivilegedResponse::ConnectionId(id);
    }

    if name_changed {
        if let Some(new_name) = &name {
            if !force {
                match connection_store::find_by_name(
                    index_lock,
                    new_name,
                    existing.global,
                    existing.owner_uid,
                ) {
                    Ok(Some(other)) if other.id != id => {
                        return PrivilegedResponse::Error {
                            code: "NameInUse".into(),
                            message: format!(
                                "a connection named {new_name:?} already exists ({}); remove it first, or resubmit allowing the name to be replaced",
                                other.id
                            ),
                        };
                    }
                    Ok(_) => {}
                    Err(error) => return error_response(error),
                }
            }
        }
    }

    // Same rule as `SetConnectionMode`: only the transition that makes a
    // global connection auto-run as root at every future boot with no
    // further human involvement requires proof of admin authentication.
    let elevating = mode_changed
        && existing.global
        && existing.start_mode == ConnectionStartMode::Manual
        && start_mode == ConnectionStartMode::Automatic;
    if elevating {
        if let Err(response) = require_admin_auth(
            auth_external_form,
            "enabling automatic startup of a global connection and its hooks as root at every boot",
        ) {
            return response;
        }
    }

    let conn_lock = match connection_store::lock_connection(id) {
        Ok(lock) => lock,
        Err(error) => return lock_error_response(error),
    };
    if name_changed {
        existing.name = name;
    }
    if mode_changed {
        existing.start_mode = start_mode;
        // Same rule `SetConnectionMode` applies: a resubmission that lands
        // on `Automatic` (e.g. `make install`'s `connection add --force
        // --start-mode automatic`) is an explicit request to have this
        // connection managed again, so it clears any earlier explicit
        // disconnect -- see `StoredConnection::user_disconnected`.
        if start_mode == ConnectionStartMode::Automatic {
            existing.user_disconnected = false;
        }
    }
    existing.updated_at = connection_store::now_unix();
    match connection_store::update(&conn_lock, &existing) {
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
    if let Err(response) = require_admin_auth(
        auth_external_form.as_deref(),
        "removing a stored connection configuration from the privileged connection store",
    ) {
        return response;
    }
    match connection_store::remove(&index_lock, &conn_lock, id) {
        Ok(()) => PrivilegedResponse::Unit,
        Err(error) => error_response(error),
    }
}

fn handle_connect_connection(
    origin: PeerOrigin,
    id: ConnectionId,
    debug: bool,
    reason: ConnectReason,
) -> DispatchOutcome {
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
        let response = match connection_store::lock_connection_patient(id) {
            Ok(conn_lock) => match resolve_connect_intent(&conn_lock, id, reason) {
                Ok(true) => match super::connection_ops::connect(&conn_lock, id, debug) {
                    Ok(()) => PrivilegedResponse::Unit,
                    Err(error) => error_response(error),
                },
                Ok(false) => {
                    debug!(
                        id = %id,
                        "reconciliation_connect_skipped_user_disconnected"
                    );
                    PrivilegedResponse::Unit
                }
                Err(error) => error_response(error),
            },
            Err(error) => lock_error_response(error),
        };
        let _ = tx.send(response);
    });
    DispatchOutcome::Pending(rx)
}

/// Decide whether a `ConnectConnection` may proceed, and update
/// `StoredConnection::user_disconnected` accordingly -- both read fresh
/// under the caller's [`ConnectionLock`] rather than trusting whatever the
/// caller observed before racing to acquire it (see `ConnectReason`'s doc
/// comment: a reconciliation pass's candidate list is a snapshot that can
/// predate a user's brand-new explicit disconnect committing to disk).
/// Returns whether `connect` should actually run.
///
/// `User`: unambiguous fresh intent regardless of the flag's current state,
/// so it's cleared unconditionally (covering `connect`'s idempotent
/// "already active" branch too) and this always returns `true`.
///
/// `Reconciliation`: never clears the flag; returns `false` (back off,
/// without touching the flag) if it's set, so an automatic bring-up can
/// never override a disconnect that has already committed by the time this
/// lock is acquired, no matter how stale the caller's own snapshot was.
fn resolve_connect_intent(
    conn_lock: &connection_store::ConnectionLock,
    id: ConnectionId,
    reason: ConnectReason,
) -> crate::error::Result<bool> {
    let Some(mut stored) = connection_store::load(id)? else {
        return Ok(true); // let `connect` produce its usual "not found" error
    };
    match reason {
        ConnectReason::User => {
            if stored.user_disconnected {
                stored.user_disconnected = false;
                connection_store::update(conn_lock, &stored)?;
            }
            Ok(true)
        }
        ConnectReason::Reconciliation => Ok(!stored.user_disconnected),
    }
}

fn handle_disconnect_connection(
    origin: PeerOrigin,
    id: ConnectionId,
    reason: DisconnectReason,
) -> DispatchOutcome {
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
        let response = match connection_store::lock_connection_patient(id) {
            Ok(conn_lock) => match mark_user_disconnected(&conn_lock, id, reason) {
                Ok(()) => match super::connection_ops::disconnect(&conn_lock, id) {
                    Ok(()) => PrivilegedResponse::Unit,
                    Err(error) => error_response(error),
                },
                Err(error) => error_response(error),
            },
            Err(error) => lock_error_response(error),
        };
        let _ = tx.send(response);
    });
    DispatchOutcome::Pending(rx)
}

/// Record `StoredConnection::user_disconnected` for an explicit
/// (`DisconnectReason::User`) disconnect *before* tearing the tunnel down --
/// not only on success, so that a teardown that half-fails still leaves the
/// intent recorded and the connection down after the next agent restart
/// (rather than looking like an ordinary crash the agent should paper over).
/// `DisconnectReason::SessionTeardown` (session-agent logout,
/// `wgd launchd reload`/`uninstall`) never sets it: those tear connections
/// down to restore a known-good running state, not because anyone asked a
/// specific tunnel to stay down. Requires the caller's [`ConnectionLock`].
fn mark_user_disconnected(
    conn_lock: &connection_store::ConnectionLock,
    id: ConnectionId,
    reason: DisconnectReason,
) -> crate::error::Result<()> {
    if reason != DisconnectReason::User {
        return Ok(());
    }
    let Some(mut stored) = connection_store::load(id)? else {
        return Ok(());
    };
    if !stored.user_disconnected {
        stored.user_disconnected = true;
        connection_store::update(conn_lock, &stored)?;
    }
    Ok(())
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
        if let Err(response) = require_admin_auth(
            auth_external_form.as_deref(),
            "enabling automatic startup of a global connection and its hooks as root at every boot",
        ) {
            return response;
        }
    }

    if stored.start_mode == start_mode {
        return PrivilegedResponse::Unit;
    }
    stored.start_mode = start_mode;
    // A mode change that lands on `Automatic` is an explicit request to have
    // this connection managed again, so it clears any earlier explicit
    // disconnect -- see `StoredConnection::user_disconnected`.
    if start_mode == ConnectionStartMode::Automatic {
        stored.user_disconnected = false;
    }
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
/// interfaces. Without this, any reachable `wgd`-group member could learn
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
fn require_admin_auth(
    form: Option<&[u8]>,
    cause: &str,
) -> std::result::Result<(), PrivilegedResponse> {
    match form {
        None => Err(auth_required(cause)),
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
        user_disconnected: conn.user_disconnected,
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

fn auth_required(cause: &str) -> PrivilegedResponse {
    PrivilegedResponse::Error {
        code: "AuthRequired".into(),
        message: format!("admin authentication required: {cause}"),
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
            "wgd-dispatch-test-{label}-{}-{:016x}",
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
            false,
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
    fn add_connection_resubmission_with_new_name_updates_it_without_auth() {
        with_test_store("dedup-rename", || {
            let first = handle_add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF.to_string(),
                false,
                ConnectionStartMode::Manual,
                Some("old-name".to_string()),
                None,
                false,
                valid_auth(),
            );
            let id = connection_id(&first);

            // No auth token: a plain rename on an identical resubmission must
            // not engage the admin-auth flow.
            let renamed = handle_add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF.to_string(),
                false,
                ConnectionStartMode::Manual,
                Some("new-name".to_string()),
                None,
                false,
                None,
            );
            assert_eq!(connection_id(&renamed), id);
            let stored = connection_store::load(id).unwrap().unwrap();
            assert_eq!(stored.name.as_deref(), Some("new-name"));
        });
    }

    #[test]
    fn add_connection_resubmission_rejects_colliding_name_unless_forced() {
        with_test_store("dedup-name-collision", || {
            let other_conf = SAMPLE_CONF.replace("10.0.0.2/32", "10.0.0.3/32");
            let first = handle_add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF.to_string(),
                false,
                ConnectionStartMode::Manual,
                Some("a".to_string()),
                None,
                false,
                valid_auth(),
            );
            let first_id = connection_id(&first);
            let second = handle_add_connection(
                PeerOrigin::Socket(501),
                other_conf.clone(),
                false,
                ConnectionStartMode::Manual,
                Some("b".to_string()),
                None,
                false,
                valid_auth(),
            );
            let second_id = connection_id(&second);
            assert_ne!(first_id, second_id);

            // Resubmitting the second connection's exact content but asking
            // for the first connection's name must be rejected without
            // `force`...
            let collision = handle_add_connection(
                PeerOrigin::Socket(501),
                other_conf.clone(),
                false,
                ConnectionStartMode::Manual,
                Some("a".to_string()),
                None,
                false,
                None,
            );
            assert_eq!(error_code(&collision), "NameInUse");

            // ...and succeed, replacing the name, with it.
            let forced = handle_add_connection(
                PeerOrigin::Socket(501),
                other_conf,
                false,
                ConnectionStartMode::Manual,
                Some("a".to_string()),
                None,
                true,
                None,
            );
            assert_eq!(connection_id(&forced), second_id);
            let stored = connection_store::load(second_id).unwrap().unwrap();
            assert_eq!(stored.name.as_deref(), Some("a"));
        });
    }

    #[test]
    fn add_connection_resubmission_elevating_global_start_mode_requires_auth() {
        with_test_store("dedup-elevate", || {
            let first = add_connection(PeerOrigin::Socket(0), SAMPLE_CONF, true, valid_auth());
            let id = connection_id(&first);
            assert_eq!(
                connection_store::load(id).unwrap().unwrap().start_mode,
                ConnectionStartMode::Manual
            );

            // Same content, but now asking to elevate the global connection
            // to auto-run as root at every future boot: must require auth,
            // exactly like `SetConnectionMode`'s own Manual -> Automatic gate
            // on a global connection.
            let without_token = handle_add_connection(
                PeerOrigin::Socket(0),
                SAMPLE_CONF.to_string(),
                true,
                ConnectionStartMode::Automatic,
                None,
                None,
                false,
                None,
            );
            assert_eq!(error_code(&without_token), "AuthRequired");
            assert_eq!(
                connection_store::load(id).unwrap().unwrap().start_mode,
                ConnectionStartMode::Manual,
                "must not elevate before a valid token is presented"
            );

            let with_token = handle_add_connection(
                PeerOrigin::Socket(0),
                SAMPLE_CONF.to_string(),
                true,
                ConnectionStartMode::Automatic,
                None,
                None,
                false,
                valid_auth(),
            );
            assert_eq!(connection_id(&with_token), id);
            assert_eq!(
                connection_store::load(id).unwrap().unwrap().start_mode,
                ConnectionStartMode::Automatic
            );
        });
    }

    #[test]
    fn add_connection_resubmission_non_elevating_start_mode_change_needs_no_auth() {
        with_test_store("dedup-non-elevate", || {
            // Per-user connections never require admin auth for `start_mode`
            // (only a *global* Manual -> Automatic transition does), so this
            // must succeed with no token at all.
            let first = handle_add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF.to_string(),
                false,
                ConnectionStartMode::Manual,
                None,
                None,
                false,
                valid_auth(),
            );
            let id = connection_id(&first);

            let updated = handle_add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF.to_string(),
                false,
                ConnectionStartMode::Automatic,
                None,
                None,
                false,
                None,
            );
            assert_eq!(connection_id(&updated), id);
            assert_eq!(
                connection_store::load(id).unwrap().unwrap().start_mode,
                ConnectionStartMode::Automatic
            );
        });
    }

    #[test]
    fn add_connection_resubmission_landing_on_automatic_clears_user_disconnected() {
        with_test_store("dedup-clears-intent", || {
            let id = connection_id(&handle_add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF.to_string(),
                false,
                ConnectionStartMode::Manual,
                None,
                None,
                false,
                valid_auth(),
            ));
            let conn_lock = connection_store::lock_connection(id).unwrap();
            let mut stored = connection_store::load(id).unwrap().unwrap();
            stored.user_disconnected = true;
            connection_store::update(&conn_lock, &stored).unwrap();
            drop(conn_lock);

            // `make install`'s `connection add --force --start-mode
            // automatic` shape: identical content, mode moving to Automatic.
            handle_add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF.to_string(),
                false,
                ConnectionStartMode::Automatic,
                None,
                None,
                false,
                None,
            );
            assert!(
                !connection_store::load(id)
                    .unwrap()
                    .unwrap()
                    .user_disconnected
            );
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
    fn remove_connection_refuses_while_active_without_engaging_auth() {
        with_test_store("remove-active", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));
            // `is_active` treats the marker as stale unless the recorded
            // socket path actually exists on disk, so the fixture needs a
            // real (if empty) file there.
            let socket = std::env::temp_dir().join(format!(
                "{}-{:016x}.sock",
                id.interface_name(),
                rand::random::<u64>()
            ));
            std::fs::write(&socket, b"").unwrap();
            let conn_lock = connection_store::lock_connection(id).unwrap();
            connection_store::save_active(
                &conn_lock,
                id,
                &connection_store::ActiveConnectionState {
                    fingerprint: "sha256:whatever".to_string(),
                    interface: id.interface_name(),
                    socket: socket.clone(),
                    device: 0,
                    inode: 0,
                    changed_sec: 0,
                    changed_nsec: 0,
                    connected_at: connection_store::now_unix(),
                },
            )
            .unwrap();
            drop(conn_lock);

            // No auth token: a `Busy` refusal must not even reach the
            // admin-auth check.
            let response = handle_remove_connection(PeerOrigin::Socket(501), id, None);
            assert_eq!(error_code(&response), "Busy");
            let _ = std::fs::remove_file(&socket);
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

            match handle_connect_connection(PeerOrigin::Socket(502), id, false, ConnectReason::User)
            {
                DispatchOutcome::Immediate(response) => assert_eq!(error_code(&response), "Auth"),
                DispatchOutcome::Pending(_) => {
                    panic!("unauthorized connect must not spawn a worker")
                }
            }
            match handle_disconnect_connection(PeerOrigin::Socket(502), id, DisconnectReason::User)
            {
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
            match handle_connect_connection(
                PeerOrigin::Socket(0),
                ConnectionId::new(),
                false,
                ConnectReason::User,
            ) {
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
            match handle_connect_connection(PeerOrigin::Socket(501), id, false, ConnectReason::User)
            {
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

    fn wait_for_worker(rx: std::sync::mpsc::Receiver<PrivilegedResponse>) {
        let _ = wait_for_worker_response(rx);
    }

    fn wait_for_worker_response(
        rx: std::sync::mpsc::Receiver<PrivilegedResponse>,
    ) -> PrivilegedResponse {
        rx.recv_timeout(std::time::Duration::from_secs(20))
            .expect("worker thread must eventually respond")
    }

    #[test]
    fn explicit_disconnect_records_user_intent_even_though_teardown_fails_here() {
        with_test_store("disconnect-marks-intent", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));
            // The intent must be recorded up front (see
            // `mark_user_disconnected`'s doc comment), not only after a
            // successful teardown -- the real `gotatun` teardown fails in
            // this test environment (no root networking access) exactly
            // like the `connect` worker test above.
            match handle_disconnect_connection(PeerOrigin::Socket(501), id, DisconnectReason::User)
            {
                DispatchOutcome::Pending(rx) => wait_for_worker(rx),
                DispatchOutcome::Immediate(response) => {
                    panic!("authorized disconnect must spawn a worker, got {response:?}")
                }
            }
            assert!(
                connection_store::load(id)
                    .unwrap()
                    .unwrap()
                    .user_disconnected
            );
        });
    }

    #[test]
    fn session_teardown_disconnect_does_not_record_user_intent() {
        with_test_store("disconnect-teardown-no-intent", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));
            match handle_disconnect_connection(
                PeerOrigin::Socket(501),
                id,
                DisconnectReason::SessionTeardown,
            ) {
                DispatchOutcome::Pending(rx) => wait_for_worker(rx),
                DispatchOutcome::Immediate(response) => {
                    panic!("authorized disconnect must spawn a worker, got {response:?}")
                }
            }
            assert!(
                !connection_store::load(id)
                    .unwrap()
                    .unwrap()
                    .user_disconnected
            );
        });
    }

    #[test]
    fn explicit_connect_clears_user_disconnected_before_bring_up_is_attempted() {
        with_test_store("connect-clears-intent", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));
            let conn_lock = connection_store::lock_connection(id).unwrap();
            let mut stored = connection_store::load(id).unwrap().unwrap();
            stored.user_disconnected = true;
            connection_store::update(&conn_lock, &stored).unwrap();
            drop(conn_lock);

            match handle_connect_connection(PeerOrigin::Socket(501), id, false, ConnectReason::User)
            {
                DispatchOutcome::Pending(rx) => wait_for_worker(rx),
                DispatchOutcome::Immediate(response) => {
                    panic!("authorized connect must spawn a worker, got {response:?}")
                }
            }
            assert!(
                !connection_store::load(id)
                    .unwrap()
                    .unwrap()
                    .user_disconnected
            );
        });
    }

    #[test]
    fn reconciliation_connect_backs_off_and_does_not_clear_a_fresh_user_disconnect() {
        // Regression test for the race Copilot's review flagged on this PR:
        // `session_agent::reconcile_connect_mine` (or boot reconciliation)
        // can snapshot a connection as eligible, then a user's brand-new
        // explicit disconnect commits (setting `user_disconnected`) before
        // this reconciliation-driven `ConnectConnection` acquires the lock.
        // The connect must back off -- re-checking the flag fresh under the
        // lock, not trusting whatever the caller observed earlier -- and
        // must never clear it, or the disconnect would be silently undone.
        with_test_store("reconciliation-connect-backs-off", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));
            let conn_lock = connection_store::lock_connection(id).unwrap();
            let mut stored = connection_store::load(id).unwrap().unwrap();
            stored.user_disconnected = true;
            connection_store::update(&conn_lock, &stored).unwrap();
            drop(conn_lock);

            let response = match handle_connect_connection(
                PeerOrigin::Socket(501),
                id,
                false,
                ConnectReason::Reconciliation,
            ) {
                DispatchOutcome::Pending(rx) => wait_for_worker_response(rx),
                DispatchOutcome::Immediate(response) => {
                    panic!("authorized connect must spawn a worker, got {response:?}")
                }
            };
            // A real connect attempt always fails in this test environment
            // (no gotatun/root networking access -- see the other worker
            // tests' comments), so `Unit` here proves `connect` itself was
            // never invoked, not just that the flag happened to survive.
            assert!(
                matches!(response, PrivilegedResponse::Unit),
                "expected the connect to be skipped, got {response:?}"
            );
            assert!(
                connection_store::load(id)
                    .unwrap()
                    .unwrap()
                    .user_disconnected,
                "a reconciliation connect must never clear an explicit user disconnect"
            );
        });
    }

    #[test]
    fn reconciliation_connect_proceeds_when_not_user_disconnected() {
        with_test_store("reconciliation-connect-proceeds", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));
            let response = match handle_connect_connection(
                PeerOrigin::Socket(501),
                id,
                false,
                ConnectReason::Reconciliation,
            ) {
                DispatchOutcome::Pending(rx) => wait_for_worker_response(rx),
                DispatchOutcome::Immediate(response) => {
                    panic!("authorized connect must spawn a worker, got {response:?}")
                }
            };
            // Not skipped: the worker actually attempted `connect`, which
            // fails in this test environment (no gotatun/root networking
            // access) -- an `Error` here proves it was attempted rather than
            // silently skipped.
            assert!(
                matches!(response, PrivilegedResponse::Error { .. }),
                "expected the connect to actually be attempted, got {response:?}"
            );
            assert!(
                !connection_store::load(id)
                    .unwrap()
                    .unwrap()
                    .user_disconnected
            );
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
    fn set_connection_mode_to_automatic_clears_user_disconnected() {
        with_test_store("mode-clears-intent", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));
            let conn_lock = connection_store::lock_connection(id).unwrap();
            let mut stored = connection_store::load(id).unwrap().unwrap();
            stored.user_disconnected = true;
            connection_store::update(&conn_lock, &stored).unwrap();
            drop(conn_lock);

            // Manual -> Automatic: an actual mode change landing on Automatic.
            let response = handle_set_connection_mode(
                PeerOrigin::Socket(501),
                id,
                ConnectionStartMode::Automatic,
                None,
            );
            assert!(matches!(response, PrivilegedResponse::Unit));
            assert!(
                !connection_store::load(id)
                    .unwrap()
                    .unwrap()
                    .user_disconnected
            );
        });
    }

    #[test]
    fn set_connection_mode_no_op_does_not_touch_user_disconnected() {
        with_test_store("mode-noop-keeps-intent", || {
            let id = connection_id(&add_connection(
                PeerOrigin::Socket(501),
                SAMPLE_CONF,
                false,
                valid_auth(),
            ));
            handle_set_connection_mode(
                PeerOrigin::Socket(501),
                id,
                ConnectionStartMode::Automatic,
                None,
            );
            let conn_lock = connection_store::lock_connection(id).unwrap();
            let mut stored = connection_store::load(id).unwrap().unwrap();
            stored.user_disconnected = true;
            connection_store::update(&conn_lock, &stored).unwrap();
            drop(conn_lock);

            // Already Automatic; re-requesting Automatic is a no-op and must
            // not clear the flag -- it did not represent an actual mode
            // change, so it is not the "mode change back to Automatic" the
            // clearing rule targets.
            let response = handle_set_connection_mode(
                PeerOrigin::Socket(501),
                id,
                ConnectionStartMode::Automatic,
                None,
            );
            assert!(matches!(response, PrivilegedResponse::Unit));
            assert!(
                connection_store::load(id)
                    .unwrap()
                    .unwrap()
                    .user_disconnected
            );
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
                false,
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

    // A different `Endpoint` port gives this a different fingerprint from
    // `SAMPLE_CONF` while still parsing, standing in for "the profile file
    // changed" between two `AddConnection` calls that reuse the same name.
    const SAMPLE_CONF_EDITED: &str = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.1:51821\n";

    #[test]
    fn add_connection_rejects_a_name_already_used_by_a_different_connection() {
        with_test_store("add-name-collision", || {
            let first = handle_add_connection(
                PeerOrigin::Socket(0),
                SAMPLE_CONF.to_string(),
                true,
                ConnectionStartMode::Manual,
                Some("direct".to_string()),
                None,
                false,
                valid_auth(),
            );
            let first_id = connection_id(&first);

            let second = handle_add_connection(
                PeerOrigin::Socket(0),
                SAMPLE_CONF_EDITED.to_string(),
                true,
                ConnectionStartMode::Manual,
                Some("direct".to_string()),
                None,
                false,
                valid_auth(),
            );
            assert_eq!(error_code(&second), "NameInUse");
            // The rejected call must not have replaced the original record.
            assert!(connection_store::load(first_id).unwrap().is_some());
        });
    }

    #[test]
    fn add_connection_with_force_allows_replacing_a_same_named_connection() {
        with_test_store("add-name-force", || {
            let first = handle_add_connection(
                PeerOrigin::Socket(0),
                SAMPLE_CONF.to_string(),
                true,
                ConnectionStartMode::Manual,
                Some("direct".to_string()),
                None,
                false,
                valid_auth(),
            );
            let first_id = connection_id(&first);

            let second = handle_add_connection(
                PeerOrigin::Socket(0),
                SAMPLE_CONF_EDITED.to_string(),
                true,
                ConnectionStartMode::Manual,
                Some("direct".to_string()),
                None,
                true,
                valid_auth(),
            );
            let second_id = connection_id(&second);
            assert_ne!(first_id, second_id);
            // `force` only waives the uniqueness check; it's still on the
            // caller (see `cmd_add`) to remove `first_id` afterwards.
            assert!(connection_store::load(first_id).unwrap().is_some());
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
