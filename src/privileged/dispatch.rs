use crate::config;
use crate::error::AppError;
use crate::privileged_api::{GotaTunAction, PrivilegedRequest, PrivilegedResponse, WgQuickAction};

use super::commands::{
    run_gotatun_down, run_gotatun_up, run_wg_quick_down, run_wg_quick_up, run_wg_show,
};
use super::ControlState;
use tracing::debug;

pub(super) fn dispatch(
    request: PrivilegedRequest,
    control_state: &mut ControlState,
) -> PrivilegedResponse {
    match request {
        PrivilegedRequest::WgQuickRun {
            action,
            interface,
            provider,
            config_content,
            prefer_userspace,
        } => {
            let base = config::privileged_wg_dir().join(provider.as_str());
            if let Err(e) = config::ensure_privileged_directory(&base) {
                return PrivilegedResponse::Error {
                    code: "IO".into(),
                    message: format!("failed creating wg dir: {}", e),
                };
            }

            let config_path = base.join(format!("{interface}.conf"));
            match action {
                WgQuickAction::Up => {
                    match run_wg_quick_up(&config_path, config_content.as_bytes(), prefer_userspace)
                    {
                        Ok(()) => PrivilegedResponse::Unit,
                        Err(e) => PrivilegedResponse::Error {
                            code: categorize_error(&e),
                            message: format!("{}", e),
                        },
                    }
                }
                WgQuickAction::Down => {
                    let result = run_wg_quick_down(&config_path);
                    let _ = std::fs::remove_file(&config_path);
                    match result {
                        Ok(()) => PrivilegedResponse::Unit,
                        Err(e) => PrivilegedResponse::Error {
                            code: categorize_error(&e),
                            message: format!("{}", e),
                        },
                    }
                }
            }
        }

        PrivilegedRequest::GotaTunRun {
            action,
            interface,
            config_content,
            mtu_override,
            debug,
        } => match action {
            GotaTunAction::Up => {
                match run_gotatun_up(
                    interface.as_str(),
                    config_content.as_str(),
                    mtu_override,
                    debug,
                ) {
                    Ok(()) => PrivilegedResponse::Unit,
                    Err(e) => PrivilegedResponse::Error {
                        code: categorize_error(&e),
                        message: e.to_string(),
                    },
                }
            }
            GotaTunAction::Down => match run_gotatun_down(interface.as_str()) {
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

        PrivilegedRequest::InterfaceActive { interface } => {
            // The userspace UAPI control socket. Checked here (as root) because
            // `/var/run/wireguard` is `0750 root:daemon` and unreachable from an
            // unprivileged caller; this mirrors the old local `exists()` probe
            // but from a context that can actually see the socket.
            let socket_path =
                std::path::PathBuf::from("/var/run/wireguard").join(format!("{interface}.sock"));
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
