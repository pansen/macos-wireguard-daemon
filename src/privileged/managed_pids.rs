use nix::libc;

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
    match process_start_ticks(pid) {
        Some(current) => current == start_ticks,
        None => start_ticks == 0 && pid_is_alive(pid),
    }
}

pub(super) fn pid_is_alive(pid: u32) -> bool {
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

pub(super) fn process_start_ticks(_pid: u32) -> Option<u64> {
    None
}
