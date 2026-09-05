use crate::config;
use crate::error::AppError;
use crate::privileged_api::{GotaTunAction, PrivilegedRequest, PrivilegedResponse, WgQuickAction};

use super::commands::{
    run_gotatun_down, run_gotatun_up, run_network_overview, run_wg_quick_down, run_wg_quick_up,
    run_wg_show,
};
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
    let _mutation_lock = if matches!(
        &request,
        PrivilegedRequest::WgQuickRun { .. } | PrivilegedRequest::GotaTunRun { .. }
    ) {
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
                    let identity = Identity {
                        interface: interface.clone(),
                        config_content: config_content.clone(),
                        mtu_override: None,
                        wg_quick: true,
                    };
                    let socket = wg_quick_socket(&interface);
                    match tunnel_state::connect(
                        &tunnel_state::record_path(),
                        identity,
                        &socket,
                        || {
                            run_wg_quick_up(
                                &config_path,
                                config_content.as_bytes(),
                                prefer_userspace,
                            )?;
                            Ok(wg_quick_socket(&interface))
                        },
                    ) {
                        Ok(()) => PrivilegedResponse::Unit,
                        Err(e) => PrivilegedResponse::Error {
                            code: categorize_error(&e),
                            message: format!("{}", e),
                        },
                    }
                }
                WgQuickAction::Down => {
                    let result = run_wg_quick_down(&config_path).and_then(|()| {
                        tunnel_state::clear(&interface)?;
                        let _ = std::fs::remove_file(&config_path);
                        Ok(())
                    });
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
                let identity = Identity {
                    interface: interface.clone(),
                    config_content: config_content.clone(),
                    mtu_override,
                    wg_quick: false,
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
                .and_then(|()| tunnel_state::clear(&interface))
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
                // No query socket (kernel/wg-quick backend, or not up): empty text
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
            let socket_path = wg_quick_socket(&interface);
            PrivilegedResponse::Bool(socket_path.exists())
        }
    }
}

/// The UAPI control socket for `interface`, whichever backend owns it.
///
/// wg-quick names its socket after the kernel-assigned `utunN` and records that
/// name in `<interface>.name`; the gotatun helper names its socket after the
/// logical interface and uses a separate `<interface>.tunmux.name`. The mapping
/// is only honored when it resolves to a socket that exists, so a `.name` left
/// behind by a crashed wg-quick run cannot hide a live gotatun socket.
fn wg_quick_socket(interface: &str) -> std::path::PathBuf {
    resolve_socket(std::path::Path::new("/var/run/wireguard"), interface)
}

fn resolve_socket(base: &std::path::Path, interface: &str) -> std::path::PathBuf {
    let mapped = std::fs::read_to_string(base.join(format!("{interface}.name")))
        .ok()
        .map(|name| name.trim().to_owned())
        .filter(|name| name != interface)
        .filter(|name| crate::privileged_api::validate_interface_name(name).is_ok())
        .map(|name| base.join(format!("{name}.sock")))
        .filter(|socket| socket.exists());
    mapped.unwrap_or_else(|| base.join(format!("{interface}.sock")))
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
    use std::fs;

    fn runtime_dir(label: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tunmux-resolve-{label}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn wg_quick_name_maps_to_the_kernel_assigned_socket() {
        let dir = runtime_dir("mapped");
        fs::write(dir.join("wgconf0.name"), "utun5\n").unwrap();
        fs::write(dir.join("utun5.sock"), "socket").unwrap();
        assert_eq!(resolve_socket(&dir, "wgconf0"), dir.join("utun5.sock"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn stale_wg_quick_name_does_not_hide_a_live_gotatun_socket() {
        // A wg-quick run that dies before `del_if` leaves `<interface>.name`
        // behind. The gotatun helper keeps its socket under the logical name,
        // so following the stale mapping would report a live tunnel as down.
        let dir = runtime_dir("stale");
        fs::write(dir.join("wgconf0.name"), "utun5\n").unwrap();
        fs::write(dir.join("wgconf0.sock"), "socket").unwrap();
        assert_eq!(resolve_socket(&dir, "wgconf0"), dir.join("wgconf0.sock"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn absent_and_invalid_names_fall_back_to_the_logical_socket() {
        let dir = runtime_dir("fallback");
        assert_eq!(resolve_socket(&dir, "wgconf0"), dir.join("wgconf0.sock"));
        fs::write(dir.join("wgconf0.name"), "../../etc/passwd").unwrap();
        assert_eq!(resolve_socket(&dir, "wgconf0"), dir.join("wgconf0.sock"));
        fs::remove_dir_all(dir).unwrap();
    }
}
