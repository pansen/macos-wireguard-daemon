mod transport;
mod util;

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tracing::{debug, warn};

use crate::config;
use crate::config::{PrivilegedAutostopMode, PrivilegedTransport};
use crate::error::{AppError, Result};
use crate::privileged_api::{
    ConnectionId, ConnectionScope, ConnectionStartMode, ConnectionSummary, DisconnectReason,
    PrivilegedRequest, PrivilegedResponse,
};

use self::transport::{is_transport_error, StdioSession};
use self::util::{build_lease_token, request_kind, resolve_client_authorized_group};

pub struct PrivilegedClient {
    socket_path: PathBuf,
    transport: PrivilegedTransport,
    autostart_enabled: bool,
    autostart_timeout: Duration,
    authorized_group: String,
    autostop_mode: PrivilegedAutostopMode,
    daemon_idle_timeout_ms: Option<u64>,
    request_timeout: Option<Duration>,
}

#[derive(Default)]
struct CommandSessionState {
    enabled_count: usize,
    lease_token: Option<String>,
    transport: Option<CommandSessionTransport>,
}

enum CommandSessionTransport {
    Socket(UnixStream),
    Stdio(StdioSession),
}

fn command_session_state() -> &'static Mutex<CommandSessionState> {
    static COMMAND_SESSION: OnceLock<Mutex<CommandSessionState>> = OnceLock::new();
    COMMAND_SESSION.get_or_init(|| Mutex::new(CommandSessionState::default()))
}

pub struct CommandScopeGuard {
    enabled: bool,
}

impl CommandScopeGuard {
    pub fn begin(_mode: PrivilegedAutostopMode) -> Self {
        if let Ok(mut state) = command_session_state().lock() {
            state.enabled_count = state.enabled_count.saturating_add(1);
        }
        Self { enabled: true }
    }
}

impl Drop for CommandScopeGuard {
    fn drop(&mut self) {
        if !self.enabled {
            return;
        }

        let mut token_to_release = None;
        let mut session_transport = None;
        if let Ok(mut state) = command_session_state().lock() {
            if state.enabled_count > 0 {
                state.enabled_count -= 1;
            }
            if state.enabled_count == 0 {
                token_to_release = state.lease_token.take();
                session_transport = state.transport.take();
            }
        }

        let client = PrivilegedClient::new();
        if let Some(mut transport) = session_transport.take() {
            debug!("privileged_command_scoped_transport_closing");
            if let Some(token) = token_to_release {
                debug!("privileged_daemon_release_command_lease_on_scoped_transport");
                let token_for_fallback = token.clone();
                if client
                    .send_on_transport(&mut transport, &PrivilegedRequest::LeaseRelease { token })
                    .is_err()
                    && matches!(client.transport, PrivilegedTransport::Socket)
                {
                    let _ = client.send_control_request_if_connected(
                        &PrivilegedRequest::LeaseRelease {
                            token: token_for_fallback,
                        },
                    );
                }
                debug!("privileged_daemon_request_shutdown_if_idle");
                if client
                    .send_on_transport(&mut transport, &PrivilegedRequest::ShutdownIfIdle)
                    .is_err()
                    && matches!(client.transport, PrivilegedTransport::Socket)
                {
                    let _ = client
                        .send_control_request_if_connected(&PrivilegedRequest::ShutdownIfIdle);
                }
            }
            client.close_transport(transport);
            return;
        }

        if let Some(token) = token_to_release {
            if matches!(client.transport, PrivilegedTransport::Socket) {
                debug!("privileged_daemon_release_command_lease");
                let _ = client
                    .send_control_request_if_connected(&PrivilegedRequest::LeaseRelease { token });
                debug!("privileged_daemon_request_shutdown_if_idle");
                let _ =
                    client.send_control_request_if_connected(&PrivilegedRequest::ShutdownIfIdle);
            }
        }
    }
}

impl PrivilegedClient {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let cfg = config::load_config();
        let autostop_mode = cfg.general.privileged_autostop_mode;
        let timeout_ms = cfg.general.privileged_autostart_timeout_ms.max(100);
        let daemon_idle_timeout_ms = if matches!(autostop_mode, PrivilegedAutostopMode::Timeout) {
            Some(cfg.general.privileged_autostop_timeout_ms.max(100))
        } else {
            None
        };
        Self {
            socket_path: config::privileged_socket_path(),
            transport: cfg.general.privileged_transport,
            autostart_enabled: cfg.general.privileged_autostart,
            autostart_timeout: Duration::from_millis(timeout_ms),
            authorized_group: resolve_client_authorized_group(
                cfg.general.privileged_authorized_group.as_str(),
            ),
            autostop_mode,
            daemon_idle_timeout_ms,
            request_timeout: None,
        }
    }

    /// Bound how long a single socket request may block, instead of waiting
    /// on the daemon indefinitely.
    ///
    /// Off by default: a connect or a config change legitimately takes as
    /// long as it takes (a WireGuard handshake, a patient lock wait, an admin
    /// prompt), and capping those would turn slow into broken. It exists for
    /// callers that are themselves on a deadline -- shell completion, which
    /// runs on a keystroke and must not leave the terminal hanging if the
    /// daemon accepted the connection but never answered.
    pub(crate) fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = Some(timeout);
        self
    }

    /// Apply [`Self::with_request_timeout`] to a freshly connected stream.
    /// A socket that rejects the timeout is unusable for a deadline-bound
    /// caller, so report that rather than silently blocking forever.
    fn apply_request_timeout(&self, stream: &UnixStream) -> Result<()> {
        let Some(timeout) = self.request_timeout else {
            return Ok(());
        };
        stream
            .set_read_timeout(Some(timeout))
            .and_then(|()| stream.set_write_timeout(Some(timeout)))
            .map_err(|e| AppError::Other(format!("failed to set privileged request timeout: {e}")))
    }

    /// Disable autostart on this client: a connect finding no socket just
    /// fails instead of spawning a fresh daemon. For callers (like `launchd
    /// uninstall`'s pre-bootout disconnect sweep) that run as root with no
    /// `CommandScopeGuard` in scope to ask a spawned daemon to shut back
    /// down afterward, and where "nothing is listening" already means
    /// "nothing to disconnect" -- autostarting one here would leave behind
    /// a daemon with no idle timeout (the default `privileged_autostop_mode`
    /// is `Never`) that `launchctl bootout` never touches, since it was
    /// spawned directly via `sudo`, not through launchd.
    pub(crate) fn without_autostart(mut self) -> Self {
        self.autostart_enabled = false;
        self
    }

    /// Run `wg show <interface>` as root and return the output.
    /// Works for both kernel and userspace (gotatun) backends.
    #[allow(dead_code)]
    pub fn wg_show(&self, interface: &str) -> Result<String> {
        match self.send(PrivilegedRequest::WgShow {
            interface: interface.to_string(),
        })? {
            PrivilegedResponse::Text(output) => Ok(output),
            _ => Err(AppError::Other(
                "invalid privileged response for WgShow".into(),
            )),
        }
    }

    /// Fetch the live route/DNS overview for a userspace tunnel, rendered by the
    /// helper that owns the interface. Returns `None` when the tunnel has no
    /// overview to show (kernel backend, or the helper isn't running).
    pub fn network_overview(&self, interface: &str) -> Result<Option<String>> {
        match self.send(PrivilegedRequest::NetworkOverview {
            interface: interface.to_string(),
        })? {
            PrivilegedResponse::Text(output) if output.is_empty() => Ok(None),
            PrivilegedResponse::Text(output) => Ok(Some(output)),
            _ => Err(AppError::Other(
                "invalid privileged response for NetworkOverview".into(),
            )),
        }
    }

    /// Ask the privileged service whether the userspace UAPI control socket for
    /// `interface` exists. Used for liveness checks that would otherwise be
    /// permission-blind from an unprivileged caller (the socket dir is
    /// `0750 root:daemon`).
    #[allow(dead_code)]
    pub fn interface_active(&self, interface: &str) -> Result<bool> {
        match self.send(PrivilegedRequest::InterfaceActive {
            interface: interface.to_string(),
        })? {
            PrivilegedResponse::Bool(active) => Ok(active),
            _ => Err(AppError::Other(
                "invalid privileged response for InterfaceActive".into(),
            )),
        }
    }

    /// Parse and store a WireGuard `.conf`, returning its (fresh or
    /// already-existing, on an exact-match resubmission) `ConnectionId`.
    /// Transparently drives the macOS admin-authentication two-phase
    /// protocol (see `privileged::authz`) when the daemon reports the
    /// change is real: the first attempt carries no token, and on
    /// `AuthRequired` this triggers the standard OS prompt and retries once
    /// with the resulting token attached.
    pub fn add_connection(
        &self,
        conf_text: &str,
        global: bool,
        start_mode: ConnectionStartMode,
        name: Option<String>,
        mtu_override: Option<u16>,
        force: bool,
    ) -> Result<ConnectionId> {
        match self.send_with_admin_auth_retry(|auth_external_form| {
            PrivilegedRequest::AddConnection {
                conf_text: conf_text.to_string(),
                global,
                start_mode,
                name: name.clone(),
                mtu_override,
                force,
                auth_external_form,
            }
        })? {
            PrivilegedResponse::ConnectionId(id) => Ok(id),
            _ => Err(AppError::Other(
                "invalid privileged response for AddConnection".into(),
            )),
        }
    }

    /// Remove a stored connection. Same admin-authentication protocol as
    /// [`Self::add_connection`].
    pub fn remove_connection(&self, id: ConnectionId) -> Result<()> {
        self.send_with_admin_auth_retry(|auth_external_form| PrivilegedRequest::RemoveConnection {
            id,
            auth_external_form,
        })
        .map(|_| ())
    }

    /// Bring up a stored connection. Ownership-gated only (see the design
    /// plan's authorization section) -- no admin-auth prompt for connecting
    /// an already-vetted connection.
    pub fn connect_connection(&self, id: ConnectionId, debug: bool) -> Result<()> {
        self.send_unit(PrivilegedRequest::ConnectConnection { id, debug })
    }

    /// Disconnect a connection on the user's explicit request. Persists
    /// "stay down" intent (`StoredConnection::user_disconnected`) that
    /// session/boot reconciliation then honors -- see
    /// `issues/session-agent-overrides-disconnect.md`. Callers tearing
    /// connections down for reasons *other* than the user asking this
    /// specific tunnel to stay down (session-agent logout, `wgd launchd
    /// reload`/`uninstall`) must use
    /// [`Self::disconnect_connection_for_teardown`] instead, or a fresh
    /// login/reinstall would no longer bring an `Automatic` connection back
    /// up.
    pub fn disconnect_connection(&self, id: ConnectionId) -> Result<()> {
        self.send_unit(PrivilegedRequest::DisconnectConnection {
            id,
            reason: DisconnectReason::User,
        })
    }

    /// Disconnect a connection as part of a system-initiated teardown that
    /// is restoring a known-good running state, not the user asking this
    /// specific tunnel to stay down -- see [`Self::disconnect_connection`]'s
    /// doc comment. Never persists "stay down" intent.
    pub fn disconnect_connection_for_teardown(&self, id: ConnectionId) -> Result<()> {
        self.send_unit(PrivilegedRequest::DisconnectConnection {
            id,
            reason: DisconnectReason::SessionTeardown,
        })
    }

    /// Change a stored connection's start mode. Only transitions a global
    /// connection from `Manual` to `Automatic` require admin authentication
    /// (see the design plan); every other transition is ownership-gated.
    pub fn set_connection_mode(
        &self,
        id: ConnectionId,
        start_mode: ConnectionStartMode,
    ) -> Result<()> {
        self.send_with_admin_auth_retry(|auth_external_form| PrivilegedRequest::SetConnectionMode {
            id,
            start_mode,
            auth_external_form,
        })
        .map(|_| ())
    }

    pub fn list_connections(&self, scope: ConnectionScope) -> Result<Vec<ConnectionSummary>> {
        match self.send(PrivilegedRequest::ListConnections { scope })? {
            PrivilegedResponse::ConnectionList(list) => Ok(list),
            _ => Err(AppError::Other(
                "invalid privileged response for ListConnections".into(),
            )),
        }
    }

    pub fn get_connection(&self, id: ConnectionId) -> Result<ConnectionSummary> {
        match self.send(PrivilegedRequest::GetConnection { id })? {
            PrivilegedResponse::Connection(summary) => Ok(summary),
            _ => Err(AppError::Other(
                "invalid privileged response for GetConnection".into(),
            )),
        }
    }

    /// Send a request built by `build_request(None)`; if the daemon reports
    /// `AuthRequired` (a genuine configuration change needing admin
    /// authentication -- see `privileged::authz`), trigger the OS prompt via
    /// `authz::client_authorize` and retry once with the resulting token.
    /// `build_request` is a closure rather than a plain request because the
    /// external form has to be threaded into the *same* request shape on retry.
    fn send_with_admin_auth_retry(
        &self,
        mut build_request: impl FnMut(Option<Vec<u8>>) -> PrivilegedRequest,
    ) -> Result<PrivilegedResponse> {
        let request = build_request(None);
        let action = request_kind(&request);
        match self.send(request) {
            Err(AppError::AuthRequired(cause)) => {
                warn!(
                    action,
                    method = "authorization_services",
                    cause = %cause,
                    "admin_authentication_requested"
                );
                eprintln!("wgd: admin authentication required for this change.");
                // The `ClientAuthorization` guard must outlive the retried
                // `send` call: freeing it (which happens automatically at
                // end of scope here) destroys the securityd session the
                // external form's rights live in, so the daemon's own
                // `AuthorizationCreateFromExternalForm` needs it to still be
                // alive when that call runs, not just the bytes to be well-formed.
                let authorization = crate::privileged::authz::client_authorize()?;
                self.send(build_request(Some(authorization.external_form().to_vec())))
            }
            other => other,
        }
    }

    fn send_unit(&self, request: PrivilegedRequest) -> Result<()> {
        self.send(request).map(|_| ())
    }

    fn send(&self, request: PrivilegedRequest) -> Result<PrivilegedResponse> {
        request.validate().map_err(AppError::Other)?;
        tracing::trace!( request = ?request_kind(&request), "privileged_ctl_request");
        if self.command_session_enabled()? {
            return self.send_with_command_session(&request);
        }

        match self.transport {
            PrivilegedTransport::Socket => {
                self.ensure_command_lease_if_enabled()?;
                let mut stream = self.connect_or_autostart()?;
                self.apply_request_timeout(&stream)?;
                self.send_on_stream(&mut stream, &request)
            }
            PrivilegedTransport::Stdio => {
                let mut session = self.spawn_privileged_stdio_session()?;
                let response = self.send_on_stdio_session(&mut session, &request);
                session.shutdown();
                response
            }
        }
    }

    fn command_session_enabled(&self) -> Result<bool> {
        let state = command_session_state()
            .lock()
            .map_err(|_| AppError::Other("command lease state lock poisoned".to_string()))?;
        Ok(state.enabled_count > 0)
    }

    fn send_with_command_session(&self, request: &PrivilegedRequest) -> Result<PrivilegedResponse> {
        let mut state = command_session_state()
            .lock()
            .map_err(|_| AppError::Other("command lease state lock poisoned".to_string()))?;
        self.ensure_command_lease_in_session(&mut state)?;
        let response = self.send_on_session_transport(&mut state, request);
        if let Err(err) = &response {
            if is_transport_error(err) {
                if let Some(transport) = state.transport.take() {
                    self.close_transport(transport);
                }
            }
        }
        response
    }

    fn ensure_command_lease_in_session(&self, state: &mut CommandSessionState) -> Result<()> {
        if !matches!(self.autostop_mode, PrivilegedAutostopMode::Command)
            || state.lease_token.is_some()
        {
            return Ok(());
        }
        let token = build_lease_token();
        self.send_on_session_transport(
            state,
            &PrivilegedRequest::LeaseAcquire {
                token: token.clone(),
            },
        )?;
        state.lease_token = Some(token);
        Ok(())
    }

    fn send_on_session_transport(
        &self,
        state: &mut CommandSessionState,
        request: &PrivilegedRequest,
    ) -> Result<PrivilegedResponse> {
        if state.transport.is_none() {
            state.transport = Some(self.open_transport()?);
        }
        let transport = state
            .transport
            .as_mut()
            .ok_or_else(|| AppError::Other("command-scoped transport unavailable".to_string()))?;
        self.send_on_transport(transport, request)
    }

    fn open_transport(&self) -> Result<CommandSessionTransport> {
        match self.transport {
            PrivilegedTransport::Socket => {
                debug!( mode = ?"socket", "privileged_command_transport_open");
                self.connect_or_autostart()
                    .map(CommandSessionTransport::Socket)
            }
            PrivilegedTransport::Stdio => {
                debug!( mode = ?"stdio", "privileged_command_transport_open");
                self.spawn_privileged_stdio_session()
                    .map(CommandSessionTransport::Stdio)
            }
        }
    }

    fn close_transport(&self, transport: CommandSessionTransport) {
        match transport {
            CommandSessionTransport::Socket(_) => {
                debug!( mode = ?"socket", "privileged_command_transport_closed");
            }
            CommandSessionTransport::Stdio(session) => {
                debug!(
                    mode = ?"stdio",
                    pid = ?session.pid(), "privileged_command_transport_closed");
                session.shutdown();
            }
        }
    }

    fn send_on_transport(
        &self,
        transport: &mut CommandSessionTransport,
        request: &PrivilegedRequest,
    ) -> Result<PrivilegedResponse> {
        match transport {
            CommandSessionTransport::Socket(stream) => self.send_on_stream(stream, request),
            CommandSessionTransport::Stdio(session) => self.send_on_stdio_session(session, request),
        }
    }

    fn ensure_command_lease_if_enabled(&self) -> Result<()> {
        if !matches!(self.autostop_mode, PrivilegedAutostopMode::Command) {
            return Ok(());
        }

        {
            let state = command_session_state()
                .lock()
                .map_err(|_| AppError::Other("command lease state lock poisoned".to_string()))?;
            if state.enabled_count == 0 || state.lease_token.is_some() {
                return Ok(());
            }
        }

        let token = build_lease_token();
        self.send_control_request_with_autostart(&PrivilegedRequest::LeaseAcquire {
            token: token.clone(),
        })?;

        let mut state = command_session_state()
            .lock()
            .map_err(|_| AppError::Other("command lease state lock poisoned".to_string()))?;
        if state.enabled_count > 0 {
            state.lease_token = Some(token);
        } else {
            drop(state);
            let _ =
                self.send_control_request_if_connected(&PrivilegedRequest::LeaseRelease { token });
        }
        Ok(())
    }

    fn send_control_request_with_autostart(&self, request: &PrivilegedRequest) -> Result<()> {
        let mut stream = self.connect_or_autostart()?;
        self.send_on_stream(&mut stream, request).map(|_| ())
    }

    fn send_control_request_if_connected(&self, request: &PrivilegedRequest) -> Result<()> {
        let mut stream = match self.try_connect_socket() {
            Ok(stream) => stream,
            Err(e) if transport::is_autostart_connect_error(&e) => return Ok(()),
            Err(e) => {
                return Err(AppError::Other(format!(
                    "failed to connect to privileged socket: {}",
                    e
                )))
            }
        };
        self.send_on_stream(&mut stream, request).map(|_| ())
    }
}

fn map_privileged_error(response: PrivilegedResponse) -> Result<PrivilegedResponse> {
    match response {
        PrivilegedResponse::Error { code, message } => Err(match code.as_str() {
            "WireGuard" => AppError::WireGuard(message),
            "Auth" => AppError::Auth(message),
            "AuthRequired" => AppError::AuthRequired(message),
            "Busy" => AppError::Busy(message),
            "NotFound" => AppError::NotFound(format!("not found: {message}")),
            _ => AppError::Other(message),
        }),
        other => Ok(other),
    }
}
