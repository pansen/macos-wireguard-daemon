use crate::config;
use crate::error::AppError;
use crate::privileged_api::{GotaTunAction, PrivilegedRequest, PrivilegedResponse};

use super::commands::{run_gotatun_down, run_gotatun_up, run_network_overview, run_wg_show};
use super::tunnel_state::{self, Identity};
use super::ControlState;
use tracing::debug;

/// How long a tunnel operation queues behind another privileged process before
/// the caller is told to retry. Short enough that the service keeps answering
/// other clients, long enough to absorb ordinary back-to-back requests.
const MUTATION_LOCK_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

pub(super) fn dispatch(
    request: PrivilegedRequest,
    control_state: &mut ControlState,
) -> PrivilegedResponse {
    // Finding 5 — Incorrect tunnel adoption and connection races: socket and
    // stdio daemons share one lock across identity check, mutation, and commit.
    // Bounded, because this runs on the thread that also accepts connections and
    // expires clients: report a busy daemon rather than freezing the loop.
    let _mutation_lock = if matches!(&request, PrivilegedRequest::GotaTunRun { .. }) {
        match crate::state_file::lock_with_timeout(
            &config::privileged_runtime_dir().join("tunnel-operation.lock"),
            MUTATION_LOCK_WAIT,
        ) {
            Ok(lock) => Some(lock),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                return PrivilegedResponse::Error {
                    code: "Busy".into(),
                    message: "another tunnel operation is in progress; retry once it finishes"
                        .into(),
                }
            }
            Err(error) => {
                return PrivilegedResponse::Error {
                    code: "IO".into(),
                    message: error.to_string(),
                }
            }
        }
    } else {
        None
    };
    match request {
        PrivilegedRequest::GotaTunRun {
            action,
            interface,
            config_content,
            mtu_override,
            debug,
        } => match action {
            GotaTunAction::Up => {
                let identity = Identity {
                    interface: interface.clone(),
                    config_content: config_content.clone(),
                    mtu_override,
                };
                let socket = std::path::PathBuf::from("/var/run/wireguard")
                    .join(format!("{interface}.sock"));
                match tunnel_state::connect(&tunnel_state::record_path(), identity, &socket, || {
                    run_gotatun_up(
                        interface.as_str(),
                        config_content.as_str(),
                        mtu_override,
                        debug,
                    )?;
                    Ok(socket.clone())
                }) {
                    Ok(()) => PrivilegedResponse::Unit,
                    Err(e) => PrivilegedResponse::Error {
                        code: categorize_error(&e),
                        message: e.to_string(),
                    },
                }
            }
            GotaTunAction::Down => match run_gotatun_down(interface.as_str())
                .and_then(|()| tunnel_state::clear(&tunnel_state::record_path(), &interface))
            {
                Ok(()) => PrivilegedResponse::Unit,
                Err(e) => PrivilegedResponse::Error {
                    code: categorize_error(&e),
                    message: e.to_string(),
                },
            },
        },

        PrivilegedRequest::LeaseAcquire { token } => {
            control_state.prune_stale_leases();
            control_state.leases.insert(token);
            debug!(
                lease_count = ?control_state.leases.len(), "privileged_lease_acquired");
            PrivilegedResponse::Unit
        }

        PrivilegedRequest::LeaseRelease { token } => {
            control_state.leases.remove(token.as_str());
            control_state.prune_stale_leases();
            debug!(
                lease_count = ?control_state.leases.len(), "privileged_lease_released");
            PrivilegedResponse::Unit
        }

        PrivilegedRequest::ShutdownIfIdle => {
            if !control_state.allow_shutdown {
                return PrivilegedResponse::Error {
                    code: "Control".into(),
                    message: "shutdown control is disabled for this daemon instance".into(),
                };
            }
            control_state.shutdown_requested = true;
            control_state.prune_stale_leases();
            debug!(
                remaining_leases = ?control_state.leases.len(), "privileged_shutdown_if_idle_requested");
            PrivilegedResponse::Bool(control_state.leases.is_empty())
        }

        PrivilegedRequest::WgShow { interface } => match run_wg_show(interface.as_str()) {
            Ok(output) => PrivilegedResponse::Text(output),
            Err(e) => PrivilegedResponse::Error {
                code: categorize_error(&e),
                message: format!("{}", e),
            },
        },

        PrivilegedRequest::NetworkOverview { interface } => {
            match run_network_overview(interface.as_str()) {
                // No query socket (kernel backend, or not up): empty text
                // tells the caller to render nothing rather than an error.
                Ok(overview) => PrivilegedResponse::Text(overview.unwrap_or_default()),
                Err(e) => PrivilegedResponse::Error {
                    code: categorize_error(&e),
                    message: format!("{}", e),
                },
            }
        }

        PrivilegedRequest::InterfaceActive { interface } => {
            // The userspace UAPI control socket. Checked here (as root) because
            // `/var/run/wireguard` is `0750 root:daemon` and unreachable from an
            // unprivileged caller; this mirrors the old local `exists()` probe
            // but from a context that can actually see the socket.
            let socket_path =
                std::path::Path::new("/var/run/wireguard").join(format!("{interface}.sock"));
            PrivilegedResponse::Bool(socket_path.exists())
        }
    }
}

pub(super) fn categorize_error(error: &AppError) -> String {
    if matches!(error, AppError::WireGuard(_)) {
        "WireGuard".into()
    } else {
        "Kernel".into()
    }
}
