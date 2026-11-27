//! Why a userspace helper ended, as the helper records it for the daemon.
//!
//! The helper writes one of these to `<interface>.wgd.exit` right before it
//! exits; the daemon's helper supervisor (`privileged::helper_supervisor`)
//! reads it once the process is gone to tell a shutdown somebody asked for
//! apart from a failure worth restarting. A missing file means the helper died
//! without reaching its exit path (SIGKILL, panic).
use std::path::PathBuf;

/// Shared with the privileged daemon, which owns the same directory.
const SOCK_DIR: &str = "/var/run/wireguard";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelperExitReason {
    /// SIGINT.
    Sigint,
    /// SIGTERM: launchd stopping the daemon's job, system shutdown, or the
    /// daemon's own fallback in `run_gotatun_down`.
    Sigterm,
    /// The UAPI socket was removed: the daemon's cooperative shutdown request.
    ControlSocketRemoved,
    /// gotatun reported an unrecoverable device error (for example a failed
    /// UDP receive after the network went away).
    DeviceError,
    /// Any other error ended the helper's run loop.
    Failed,
}

impl HelperExitReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sigint => "sigint",
            Self::Sigterm => "sigterm",
            Self::ControlSocketRemoved => "control_socket_removed",
            Self::DeviceError => "device_error",
            Self::Failed => "failed",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text.trim() {
            "sigint" => Some(Self::Sigint),
            "sigterm" => Some(Self::Sigterm),
            "control_socket_removed" => Some(Self::ControlSocketRemoved),
            "device_error" => Some(Self::DeviceError),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }

    /// Whether somebody asked the helper to stop. Those exits are never
    /// restarted: the asker owns what happens next.
    pub fn requested(self) -> bool {
        matches!(
            self,
            Self::Sigint | Self::Sigterm | Self::ControlSocketRemoved
        )
    }
}

/// `/var/run/wireguard/<interface>.wgd.exit`.
pub fn path(interface: &str) -> PathBuf {
    PathBuf::from(SOCK_DIR).join(format!("{interface}.wgd.exit"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_round_trip_and_only_failures_are_unrequested() {
        for reason in [
            HelperExitReason::Sigint,
            HelperExitReason::Sigterm,
            HelperExitReason::ControlSocketRemoved,
            HelperExitReason::DeviceError,
            HelperExitReason::Failed,
        ] {
            assert_eq!(HelperExitReason::parse(reason.as_str()), Some(reason));
            assert_eq!(
                HelperExitReason::parse(&format!("{}\n", reason.as_str())),
                Some(reason)
            );
        }
        assert_eq!(HelperExitReason::parse("bogus"), None);
        assert!(HelperExitReason::Sigterm.requested());
        assert!(HelperExitReason::ControlSocketRemoved.requested());
        assert!(!HelperExitReason::DeviceError.requested());
        assert!(!HelperExitReason::Failed.requested());
    }

    #[test]
    fn path_is_scoped_to_the_interface() {
        assert_eq!(
            path("wg-1ce3a4a1"),
            PathBuf::from("/var/run/wireguard/wg-1ce3a4a1.wgd.exit")
        );
    }
}
