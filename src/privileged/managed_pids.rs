use nix::libc;
use serde::{Deserialize, Serialize};

/// Kernel start time of a process. Together with the pid it names one process
/// instance, which a bare pid cannot do once pids are reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessStart {
    pub sec: u64,
    pub usec: u64,
}

/// Whether an autostop lease token still refers to a live client process.
///
/// Tokens are `"<pid>:<start_ticks>"`. macOS has no `/proc` start-ticks, so the
/// client emits `start_ticks == 0` and liveness falls back to a plain signal-0
/// probe of the pid.
pub(super) fn lease_token_is_live(token: &str) -> bool {
    let mut parts = token.split(':');
    let pid = match parts.next().and_then(|p| p.parse::<u32>().ok()) {
        Some(pid) => pid,
        None => return false,
    };
    let start_ticks = match parts.next().and_then(|s| s.parse::<u64>().ok()) {
        Some(start) => start,
        None => return false,
    };
    // Tokens carry no usable start time (the client emits 0), so a nonzero
    // value can never be verified and counts as dead.
    start_ticks == 0 && pid_is_alive(pid)
}

pub(crate) fn pid_is_alive(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Path of the executable a pid runs, or `None` if the pid is gone or
/// unreadable.
pub(crate) fn process_executable(pid: u32) -> Option<std::path::PathBuf> {
    use std::os::unix::ffi::OsStrExt;

    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let length = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    if length <= 0 {
        return None;
    }
    Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
        &buffer[..length as usize],
    )))
}

/// Start time of `pid` via `proc_pidinfo(PROC_PIDTBSDINFO)`, or `None` if the
/// pid is gone or the kernel returns a short answer.
#[cfg(target_os = "macos")]
pub(crate) fn process_start_ticks(pid: u32) -> Option<ProcessStart> {
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let written = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    if written != size {
        return None;
    }
    Some(ProcessStart {
        sec: info.pbi_start_tvsec,
        usec: info.pbi_start_tvusec,
    })
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn process_start_ticks(_pid: u32) -> Option<ProcessStart> {
    None
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;

    #[test]
    fn process_start_is_stable_and_distinguishes_processes() {
        let own = std::process::id();
        let first = process_start_ticks(own).expect("own start time");
        assert_eq!(process_start_ticks(own), Some(first));
        // launchd (pid 1) is readable only as root; skip the comparison when
        // the kernel refuses, rather than asserting on sandbox policy.
        if let Some(init) = process_start_ticks(1) {
            assert_ne!(init, first);
        }
    }

    #[test]
    fn dead_pid_has_no_start_time() {
        let mut child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        assert_eq!(process_start_ticks(pid), None);
        assert!(!pid_is_alive(pid));
    }

    #[test]
    fn lease_tokens_with_start_time_are_never_live() {
        let own = std::process::id();
        assert!(lease_token_is_live(&format!("{own}:0")));
        assert!(!lease_token_is_live(&format!("{own}:12345")));
    }
}
