//! Finding 5 — Incorrect tunnel adoption and connection races.
//! Shared file primitives for root tunnel transactions and local state commits.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::{Duration, Instant};

/// How often a bounded acquisition retries a contended lock.
const POLL_INTERVAL: Duration = Duration::from_millis(20);

/// The descriptor owns the advisory lock; dropping it releases the lock even
/// on an error. Keep the lock file in place so all processes lock the same inode.
pub fn lock(path: &Path) -> io::Result<File> {
    acquire(path, None)
}

/// Same lock, but give up after `wait` with [`io::ErrorKind::WouldBlock`].
///
/// The privileged service runs its dispatcher on the same thread that accepts
/// connections and enforces client deadlines. An unbounded `flock` there stops
/// that thread entirely, so a second privileged process holding the lock would
/// stall every unrelated client instead of just the one that has to queue.
pub fn lock_with_timeout(path: &Path, wait: Duration) -> io::Result<File> {
    acquire(path, Some(wait))
}

fn acquire(path: &Path, wait: Option<Duration>) -> io::Result<File> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .open(path)?;
    let operation = match wait {
        Some(_) => nix::libc::LOCK_EX | nix::libc::LOCK_NB,
        None => nix::libc::LOCK_EX,
    };
    let deadline = wait.map(|wait| Instant::now() + wait);
    loop {
        if unsafe { nix::libc::flock(file.as_raw_fd(), operation) } == 0 {
            return Ok(file);
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted => {}
            io::ErrorKind::WouldBlock if deadline.is_some_and(|at| Instant::now() < at) => {
                std::thread::sleep(POLL_INTERVAL);
            }
            _ => return Err(error),
        }
    }
}

pub fn write_atomic(path: &Path, contents: &[u8]) -> io::Result<()> {
    let temp = path.with_extension(format!(
        "tmp.{}.{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    #[test]
    fn bounded_acquisition_reports_would_block_instead_of_waiting() {
        let dir = std::env::temp_dir().join(format!("tunmux-lock-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("busy.lock");
        let held = lock(&path).unwrap();
        let started = Instant::now();
        let error = lock_with_timeout(&path, Duration::from_millis(80)).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(started.elapsed() < Duration::from_secs(5));
        drop(held);
        lock_with_timeout(&path, Duration::from_millis(80)).unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_readers_never_observe_partial_state() {
        let dir = std::env::temp_dir().join(format!("tunmux-atomic-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("state.json");
        let old = vec![b'a'; 64 * 1024];
        let new = vec![b'b'; 128 * 1024];
        write_atomic(&path, &old).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let worker = {
            let barrier = barrier.clone();
            let path = path.clone();
            let new = new.clone();
            std::thread::spawn(move || {
                barrier.wait();
                write_atomic(&path, &new).unwrap();
            })
        };
        barrier.wait();
        for _ in 0..100 {
            let observed = fs::read(&path).unwrap();
            assert!(observed == old || observed == new);
        }
        worker.join().unwrap();
        fs::remove_dir_all(dir).unwrap();
    }
}
