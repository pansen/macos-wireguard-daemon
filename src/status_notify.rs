//! "Status changed" ping for the menu bar app, as a Darwin notification
//! (`notify(3)`).
//!
//! The daemon posts after a connection comes up, goes down, is added or
//! removed, or loses its helper; the helper posts when a reconcile pass
//! changed routes or DNS. The app then fetches the status over the
//! privileged socket as usual. The notification carries no data and anyone
//! on the machine can post the name, so a forged ping only costs the app one
//! extra fetch.

use std::ffi::{c_char, CStr};

use tracing::debug;

use crate::privileged_api::ConnectionId;

/// Also read by the app, through `wgd-bar-ffi`.
pub const NAME: &CStr = c"me.pansen.wgd.status-changed";

extern "C" {
    // libSystem, <notify.h>. Returns NOTIFY_STATUS_OK (0) on success.
    fn notify_post(name: *const c_char) -> u32;
}

/// Why a ping goes out. Each variant carries what the log line needs to tell
/// which connection or tunnel changed.
#[derive(Debug, Clone, Copy)]
pub enum Trigger<'a> {
    Connected {
        id: ConnectionId,
        interface: &'a str,
    },
    Disconnected {
        id: ConnectionId,
        interface: &'a str,
    },
    Added {
        id: ConnectionId,
    },
    Removed {
        id: ConnectionId,
    },
    /// The daemon saw a helper process exit, crash or not.
    HelperExited {
        interface: &'a str,
        pid: u32,
    },
    /// A helper reconcile pass changed routes or DNS.
    Reconciled {
        interface: &'a str,
        routes_changed: bool,
        dns_changed: bool,
    },
}

/// Best-effort: a failed post only delays the app until its fallback poll.
pub fn post(trigger: Trigger<'_>) {
    // SAFETY: `NAME` is a valid NUL-terminated string with static lifetime.
    let status = unsafe { notify_post(NAME.as_ptr()) };
    let name = NAME.to_str().unwrap_or_default();
    match trigger {
        Trigger::Connected { id, interface } => debug!(
            trigger = "connected", id = %id, interface, name, status, "status_notify_posted"
        ),
        Trigger::Disconnected { id, interface } => debug!(
            trigger = "disconnected", id = %id, interface, name, status, "status_notify_posted"
        ),
        Trigger::Added { id } => {
            debug!(trigger = "added", id = %id, name, status, "status_notify_posted")
        }
        Trigger::Removed { id } => {
            debug!(trigger = "removed", id = %id, name, status, "status_notify_posted")
        }
        Trigger::HelperExited { interface, pid } => debug!(
            trigger = "helper_exited",
            interface, pid, name, status, "status_notify_posted"
        ),
        Trigger::Reconciled {
            interface,
            routes_changed,
            dns_changed,
        } => debug!(
            trigger = "reconciled",
            interface, routes_changed, dns_changed, name, status, "status_notify_posted"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn post_reaches_a_registered_listener() {
        extern "C" {
            fn notify_register_check(name: *const c_char, token: *mut i32) -> u32;
            fn notify_check(token: i32, changed: *mut i32) -> u32;
        }
        let mut token = 0;
        let mut changed = 0;
        // SAFETY: valid name pointer and out-pointers for the duration of the calls.
        unsafe {
            assert_eq!(notify_register_check(NAME.as_ptr(), &mut token), 0);
            // The first check after registering always reports a change.
            assert_eq!(notify_check(token, &mut changed), 0);
            post(Trigger::Added {
                id: ConnectionId::new(),
            });
            // notifyd delivers asynchronously.
            for _ in 0..100 {
                assert_eq!(notify_check(token, &mut changed), 0);
                if changed == 1 {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        assert_eq!(changed, 1);
    }
}
