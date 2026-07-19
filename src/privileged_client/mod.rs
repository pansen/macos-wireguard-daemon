mod transport;
mod util;

use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use tracing::debug;

use crate::config;
use crate::config::{PrivilegedAutostopMode, PrivilegedTransport};
use crate::error::{AppError, Result};
use crate::privileged_api::{GotaTunAction, PrivilegedRequest, PrivilegedResponse, WgQuickAction};

use self::transport::{is_transport_error, StdioSession};
use self::util::{build_lease_token, request_kind, resolve_client_authorized_group};

/// Whether an error from a `PrivilegedClient` call is a transient
/// transport/cold-start error worth retrying, as opposed to an authoritative
/// failure. Exposed for callers outside this module (e.g.
/// `wireguard::userspace`) that implement their own retry/settle loops.
pub(crate) fn is_retryable_transport_error(err: &AppError) -> bool {
    is_transport_error(err)
}

pub struct PrivilegedClient {
    socket_path: PathBuf,
    transport: PrivilegedTransport,
    autostart_enabled: bool,
    autostart_timeout: Duration,
    authorized_group: String,
    autostop_mode: PrivilegedAutostopMode,
    daemon_idle_timeout_ms: Option<u64>,
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
        }
    }

    pub fn wg_quick_run(
        &self,
        action: WgQuickAction,
        interface: &str,
        provider: &str,
        config_content: &str,
        prefer_userspace: bool,
    ) -> Result<()> {
        self.send_unit(PrivilegedRequest::WgQuickRun {
            action,
            interface: interface.to_string(),
            provider: provider.to_string(),
            config_content: config_content.to_string(),
            prefer_userspace,
        })
    }

    pub fn gotatun_run(
        &self,
        action: GotaTunAction,
        interface: &str,
        config_content: &str,
        mtu_override: Option<u16>,
    ) -> Result<()> {
        self.send_unit(PrivilegedRequest::GotaTunRun {
            action,
            interface: interface.to_string(),
            config_content: config_content.to_string(),
            mtu_override,
            debug: crate::logging::debug_enabled(),
        })
    }

    /// Run `wg show <interface>` as root and return the output.
    /// Works for kernel, wg-quick, and userspace (gotatun) backends.
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

    /// Ask the privileged service whether the userspace UAPI control socket for
    /// `interface` exists. Used for liveness checks that would otherwise be
    /// permission-blind from an unprivileged caller (the socket dir is
    /// `0750 root:daemon`).
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
            _ => AppError::Other(message),
        }),
        other => Ok(other),
    }
}
