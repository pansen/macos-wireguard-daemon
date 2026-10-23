//! Custody watch: notice a helper's death and heal DNS right away.
//!
//! Three layers (see `issues/dns-crash-recovery.md`, section 3a):
//!
//! 1. While the daemon runs, a kqueue `EVFILT_PROC`/`NOTE_EXIT` watch per live
//!    custody record runs the single-record sweep the moment its helper exits.
//! 2. The `dns-custody/watch` sentinel makes launchd keep the daemon alive
//!    (and start it at boot) while custody is pending.
//! 3. A retry loop re-runs the sweep every minute while a restore keeps
//!    failing, instead of letting the daemon idle-exit.
//!
//! Watches and the retry loop keep the daemon resident through a *resident
//! count* that `socket::serve` consults. It is separate from `background_work`
//! on purpose: that counter makes the accept loop poll every 20 ms, which a
//! daemon that stays up for the whole life of a tunnel must not do.
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::event::{EventFilter, EventFlag, FilterFlag, KEvent, Kqueue};
use tracing::{debug, info, warn};

use crate::dns_custody::DnsCustodyRecord;
use crate::macos_dns;
use crate::privileged_api::ConnectionId;

use super::connection_store;
use super::dns_sweep::{self, RecordStatus, Scope};
use super::managed_pids::ProcessStart;

/// How often the sweep is retried while a restore keeps failing.
const RETRY_INTERVAL: Duration = Duration::from_secs(60);

/// After `NOTE_EXIT`, how long to wait for the helper's socket to stop
/// accepting. The exit notification can arrive a moment before the kernel has
/// torn down the helper's descriptors.
const EXIT_GRACE: Duration = Duration::from_secs(2);

// ---- generic exit watcher ---------------------------------------------------

/// Why [`ExitWatcher::register`] did not start a watch.
#[derive(Debug)]
pub(super) enum RegisterError<T> {
    /// The process no longer exists (`ESRCH`); the token is handed back so the
    /// caller can act as if the exit notification had just arrived.
    Gone(T),
    /// This pid is already watched.
    AlreadyWatched,
    Io(Errno),
}

/// Calls `on_exit(pid, token)` once for every registered pid that exits.
///
/// Works for any pid, not just children, when the caller is root; helpers
/// daemonize, so they are not children of the daemon. Each registration adds
/// one to `hold` until its callback has returned.
pub(super) struct ExitWatcher<T> {
    kqueue: Arc<Kqueue>,
    entries: Arc<Mutex<HashMap<u32, T>>>,
    hold: Arc<AtomicUsize>,
}

impl<T: Send + 'static> ExitWatcher<T> {
    pub(super) fn new(
        hold: Arc<AtomicUsize>,
        on_exit: impl Fn(u32, T) + Send + 'static,
    ) -> io::Result<Self> {
        let kqueue = Arc::new(Kqueue::new().map_err(io::Error::from)?);
        let entries: Arc<Mutex<HashMap<u32, T>>> = Arc::new(Mutex::new(HashMap::new()));
        {
            let kqueue = Arc::clone(&kqueue);
            let entries = Arc::clone(&entries);
            let hold = Arc::clone(&hold);
            std::thread::Builder::new()
                .name("dns-custody-watch".into())
                .spawn(move || watch_loop(&kqueue, &entries, &hold, on_exit))?;
        }
        Ok(Self {
            kqueue,
            entries,
            hold,
        })
    }

    pub(super) fn register(&self, pid: u32, token: T) -> Result<(), RegisterError<T>> {
        {
            let mut entries = lock(&self.entries);
            if entries.contains_key(&pid) {
                return Err(RegisterError::AlreadyWatched);
            }
            // Insert first: the exit event may fire before `register` returns.
            entries.insert(pid, token);
        }
        self.hold.fetch_add(1, Ordering::SeqCst);

        let change = KEvent::new(
            pid as usize,
            EventFilter::EVFILT_PROC,
            EventFlag::EV_ADD | EventFlag::EV_ONESHOT | EventFlag::EV_RECEIPT,
            FilterFlag::NOTE_EXIT,
            0,
            0,
        );
        let mut receipt = [KEvent::new(
            0,
            EventFilter::EVFILT_PROC,
            EventFlag::empty(),
            FilterFlag::empty(),
            0,
            0,
        )];
        let zero = nix::libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let outcome = match self.kqueue.kevent(&[change], &mut receipt, Some(zero)) {
            // With EV_RECEIPT the kernel answers with EV_ERROR; `data` is 0 on
            // success and the errno otherwise.
            Ok(1) if receipt[0].flags().contains(EventFlag::EV_ERROR) => match receipt[0].data() {
                0 => Ok(()),
                errno => Err(Errno::from_raw(errno as i32)),
            },
            Ok(_) => Ok(()),
            Err(errno) => Err(errno),
        };
        match outcome {
            Ok(()) => Ok(()),
            Err(errno) => {
                self.hold.fetch_sub(1, Ordering::SeqCst);
                // The exit event may have raced in and consumed the entry.
                match lock(&self.entries).remove(&pid) {
                    Some(token) if errno == Errno::ESRCH => Err(RegisterError::Gone(token)),
                    _ => Err(RegisterError::Io(errno)),
                }
            }
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn watch_loop<T>(
    kqueue: &Kqueue,
    entries: &Mutex<HashMap<u32, T>>,
    hold: &AtomicUsize,
    on_exit: impl Fn(u32, T),
) {
    let blank = || {
        KEvent::new(
            0,
            EventFilter::EVFILT_PROC,
            EventFlag::empty(),
            FilterFlag::empty(),
            0,
            0,
        )
    };
    let mut events = [blank(), blank(), blank(), blank()];
    loop {
        let count = match kqueue.kevent(&[], &mut events, None) {
            Ok(count) => count,
            Err(Errno::EINTR) => continue,
            Err(errno) => {
                warn!(error = %errno, "privileged_dns_custody_watch_failed");
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        for event in &events[..count] {
            if event.filter() != Ok(EventFilter::EVFILT_PROC)
                || !event.fflags().contains(FilterFlag::NOTE_EXIT)
            {
                continue;
            }
            let pid = event.ident() as u32;
            let token = lock(entries).remove(&pid);
            if let Some(token) = token {
                on_exit(pid, token);
                hold.fetch_sub(1, Ordering::SeqCst);
            }
        }
    }
}

// ---- daemon wiring ----------------------------------------------------------

/// What the daemon remembers about a watched helper.
#[derive(Debug, Clone)]
pub(super) struct WatchedHelper {
    connection_id: ConnectionId,
    interface: String,
    start: ProcessStart,
}

static WATCHER: OnceLock<ExitWatcher<WatchedHelper>> = OnceLock::new();
static RESIDENT: OnceLock<Arc<AtomicUsize>> = OnceLock::new();
static RETRY_ACTIVE: AtomicBool = AtomicBool::new(false);

/// The count `socket::serve` checks before idle-exit. Created on first use.
pub(super) fn resident_count() -> Arc<AtomicUsize> {
    Arc::clone(RESIDENT.get_or_init(|| Arc::new(AtomicUsize::new(0))))
}

/// Start the exit watcher. Without it (stdio transport, a kqueue failure) the
/// sentinel and the retry loop still cover crash recovery, just not within
/// seconds.
pub(super) fn init() {
    let result = ExitWatcher::new(resident_count(), |pid, helper: WatchedHelper| {
        handle_exit(pid, helper);
    });
    match result {
        Ok(watcher) => {
            let _ = WATCHER.set(watcher);
        }
        Err(error) => warn!(error = %error, "privileged_dns_custody_watch_unavailable"),
    }
}

/// Run `work` on its own thread while holding one resident count.
fn spawn_held(work: impl FnOnce() + Send + 'static) {
    let resident = resident_count();
    resident.fetch_add(1, Ordering::SeqCst);
    std::thread::spawn(move || {
        work();
        resident.fetch_sub(1, Ordering::SeqCst);
    });
}

fn watch_record(record: &DnsCustodyRecord) {
    let Some(watcher) = WATCHER.get() else {
        return;
    };
    let helper = WatchedHelper {
        connection_id: record.connection_id,
        interface: record.interface.clone(),
        start: record.helper_start,
    };
    match watcher.register(record.helper_pid, helper) {
        Ok(()) => debug!(
            interface = %record.interface,
            pid = record.helper_pid,
            "privileged_dns_custody_watch_registered"
        ),
        Err(RegisterError::AlreadyWatched) => {}
        Err(RegisterError::Gone(helper)) => {
            // Already dead: behave as if the exit event had just arrived.
            let pid = record.helper_pid;
            spawn_held(move || handle_exit(pid, helper));
        }
        Err(RegisterError::Io(errno)) => warn!(
            interface = %record.interface,
            error = %errno,
            "privileged_dns_custody_watch_register_failed"
        ),
    }
}

/// A watched helper exited. Heal its DNS, unless teardown already did.
fn handle_exit(pid: u32, helper: WatchedHelper) {
    let deadline = std::time::Instant::now() + EXIT_GRACE;
    while connection_store::helper_is_live(
        helper.connection_id,
        &helper.interface,
        Some(pid),
        Some(helper.start),
    ) && std::time::Instant::now() < deadline
    {
        std::thread::sleep(Duration::from_millis(100));
    }
    // A crashed helper takes its tunnel down without any disconnect.
    crate::status_notify::post(crate::status_notify::Trigger::HelperExited {
        interface: &helper.interface,
        pid,
    });
    let recorded = crate::dns_custody::record_path(&helper.interface)
        .map(|path| path.exists())
        .unwrap_or(false);
    if recorded {
        warn!(
            interface = %helper.interface,
            pid,
            "privileged_dns_custody_helper_died"
        );
    } else {
        debug!(interface = %helper.interface, pid, "privileged_dns_custody_helper_exited");
    }
    if let Err(error) = dns_sweep::sweep_interface(&helper.interface) {
        warn!(interface = %helper.interface, error = %error, "privileged_dns_sweep_failed");
        // Keep trying: the record is still there.
        ensure_retry_loop();
    }
}

/// Create the sentinel before a helper that will promote DNS is spawned.
/// Caller holds the system network mutation lock.
pub(super) fn create_sentinel_locked() {
    if let Err(error) =
        crate::state_file::write_atomic(&crate::config::dns_custody_watch_path(), b"")
    {
        warn!(error = %error, "privileged_dns_custody_sentinel_failed");
    }
}

/// What is left in `dns-custody/` after a sweep or a connect.
#[derive(Debug, Default)]
pub(super) struct CustodyState {
    pub live: usize,
    pub restorable: usize,
    pub deferred: usize,
}

/// Bring the watch machinery in line with the records on disk: delete the
/// sentinel when nothing needs it (create it otherwise), watch every record
/// whose helper is live, and keep retrying records that could not be restored.
/// Caller holds the system network mutation lock.
pub(super) fn settle_locked() -> CustodyState {
    let states = match dns_sweep::read_record_states(&Scope::All) {
        Ok(states) => states,
        Err(error) => {
            // Cannot tell what is pending: leave the sentinel as it is.
            warn!(error = %error, "privileged_dns_custody_scan_failed");
            return CustodyState::default();
        }
    };
    // If the listing fails, assume every service is present so a pending
    // record keeps the sentinel rather than being written off as deferred.
    let listed = macos_dns::list_network_services().unwrap_or_else(|_| {
        states
            .iter()
            .flat_map(|(_, s)| s.record.services.iter().map(|svc| svc.service.clone()))
            .collect()
    });
    let mut custody = CustodyState::default();
    let mut statuses = Vec::with_capacity(states.len());
    for (_, state) in &states {
        let status = dns_sweep::classify_record(state.helper_live, &state.record.services, &listed);
        match status {
            RecordStatus::Live => {
                custody.live += 1;
                watch_record(&state.record);
            }
            RecordStatus::Restorable => custody.restorable += 1,
            RecordStatus::Deferred => custody.deferred += 1,
        }
        statuses.push(status);
    }

    let sentinel = crate::config::dns_custody_watch_path();
    if dns_sweep::sentinel_wanted(&statuses) {
        if !sentinel.exists() {
            create_sentinel_locked();
        }
    } else if let Err(error) = crate::state_file::remove_durable(&sentinel) {
        warn!(error = %error, "privileged_dns_custody_sentinel_failed");
    }
    if custody.restorable > 0 {
        ensure_retry_loop();
    }
    custody
}

/// While a restore keeps failing the sentinel stays and launchd would restart
/// an idle-exiting daemon right away, so stay resident and retry instead.
fn ensure_retry_loop() {
    if RETRY_ACTIVE
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    spawn_held(|| {
        loop {
            std::thread::sleep(RETRY_INTERVAL);
            warn!("privileged_dns_custody_retry");
            // The sweep settles, which may call back into `ensure_retry_loop`;
            // the flag is still set then, so that call is a no-op.
            match dns_sweep::sweep_dead_dns_custody() {
                Ok(summary) if summary.custody.restorable == 0 => break,
                Ok(_) => {}
                Err(error) => warn!(error = %error, "privileged_dns_sweep_failed"),
            }
        }
        RETRY_ACTIVE.store(false, Ordering::SeqCst);
        info!("privileged_dns_custody_retry_done");
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    use std::sync::mpsc;

    #[test]
    fn exit_watch_fires_when_the_process_is_killed() {
        let hold = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        let watcher = ExitWatcher::new(Arc::clone(&hold), move |pid, token: &'static str| {
            tx.lock().unwrap().send((pid, token)).unwrap();
        })
        .unwrap();

        let mut child = Command::new("/bin/sleep").arg("60").spawn().unwrap();
        watcher.register(child.id(), "helper").unwrap();
        assert_eq!(hold.load(Ordering::SeqCst), 1);

        child.kill().unwrap();
        let (pid, token) = rx.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!((pid, token), (child.id(), "helper"));
        child.wait().unwrap();

        // The hold is released right after the callback returns.
        for _ in 0..100 {
            if hold.load(Ordering::SeqCst) == 0 {
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(hold.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn registering_a_dead_pid_reports_gone_immediately() {
        let hold = Arc::new(AtomicUsize::new(0));
        let watcher = ExitWatcher::new(Arc::clone(&hold), |_, _: u8| {
            panic!("no exit event expected");
        })
        .unwrap();
        let mut child = Command::new("/usr/bin/true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();

        match watcher.register(pid, 7u8) {
            Err(RegisterError::Gone(token)) => assert_eq!(token, 7),
            other => panic!("expected Gone, got {other:?}"),
        }
        assert_eq!(hold.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn registering_the_same_pid_twice_is_ignored() {
        let hold = Arc::new(AtomicUsize::new(0));
        let watcher = ExitWatcher::new(Arc::clone(&hold), |_, _: u8| {}).unwrap();
        let mut child = Command::new("/bin/sleep").arg("60").spawn().unwrap();
        watcher.register(child.id(), 1).unwrap();
        assert!(matches!(
            watcher.register(child.id(), 2),
            Err(RegisterError::AlreadyWatched)
        ));
        assert_eq!(hold.load(Ordering::SeqCst), 1);
        child.kill().unwrap();
        child.wait().unwrap();
    }
}
