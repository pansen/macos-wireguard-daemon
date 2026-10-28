//! Owner of the connection's DNS key in the dynamic store (see
//! `crate::dns_dynamic_store` and `doc/dns-dynamic-store.md`, "Rollout").
//!
//! One dedicated thread holds a session-keys dynamic store session for the
//! life of the tunnel, so configd drops the key when the helper dies however
//! it dies. The thread publishes the key, withdraws it while the tunnel DNS
//! collides with a connected LAN, republishes it when it disappears, and
//! removes it at teardown. In shadow mode it only observes: every failure is
//! logged and nothing here can fail the tunnel, and the `networksetup` path
//! answers queries. In active mode this key is the tunnel's DNS.
use std::os::raw::c_int;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use core_foundation::array::CFArray;
use core_foundation::base::TCFType;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::runloop::{kCFRunLoopCommonModes, kCFRunLoopDefaultMode, CFRunLoop};
use core_foundation::string::CFString;
use system_configuration::dynamic_store::{
    SCDynamicStore, SCDynamicStoreBuilder, SCDynamicStoreCallBackContext,
};
use tracing::{debug, info, warn};

use crate::dns_dynamic_store::{dns_key, key_present, match_domain, StoreKeyMode, SEARCH_ORDER};
use crate::privileged_api::ConnectionId;

/// How long one run loop turn waits for a notification before the thread
/// looks at its command queue again. Bounds the latency of withdraw/remove.
const TURN: Duration = Duration::from_millis(200);

/// Safety net next to the notification: re-read the key this often. Whether
/// the notification alone catches every loss (configd restart) is one of the
/// things the shadow phase is meant to find out, see the `trigger` field.
const POLL_INTERVAL: Duration = Duration::from_secs(30);

/// How long teardown waits for the thread to remove the key.
const REMOVE_TIMEOUT: Duration = Duration::from_secs(2);

extern "C" {
    /// Status of the last SystemConfiguration call on this thread.
    fn SCError() -> c_int;
}

fn sc_status() -> c_int {
    unsafe { SCError() }
}

enum Command {
    /// Publish (`true`) or withdraw (`false`) the key.
    Want(bool),
    /// Remove the key, acknowledge and stop the thread.
    Remove(mpsc::Sender<()>),
}

pub(super) struct DnsStoreKey {
    connection_id: ConnectionId,
    mode: StoreKeyMode,
    commands: mpsc::Sender<Command>,
    /// Last state requested from the thread; `key_intact` compares against it.
    wanted: AtomicBool,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl DnsStoreKey {
    /// Start the owner thread. `None` (logged) when the thread cannot start.
    pub(super) fn start(
        interface: &str,
        connection_id: ConnectionId,
        mode: StoreKeyMode,
        dns_servers: &[String],
        wanted: bool,
    ) -> Option<Self> {
        let (commands, receiver) = mpsc::channel();
        let owner = Owner {
            interface: interface.to_string(),
            mode,
            key: dns_key(connection_id),
            match_domain: match_domain(connection_id, mode),
            dns_servers: dns_servers.to_vec(),
            wanted,
            published: false,
            failing: false,
        };
        let thread = std::thread::Builder::new()
            .name("wgd-dns-store".into())
            .spawn(move || owner.run(&receiver));
        match thread {
            Ok(thread) => Some(Self {
                connection_id,
                mode,
                commands,
                wanted: AtomicBool::new(wanted),
                thread: Mutex::new(Some(thread)),
            }),
            Err(error) => {
                warn!(
                    interface,
                    mode = mode.as_str(),
                    stage = "thread",
                    error = %error,
                    "userspace_helper_dns_store_key_failed"
                );
                None
            }
        }
    }

    /// Publish the key, or withdraw it (LAN collision). Cheap; the thread
    /// acts. Returns whether this changed the request.
    pub(super) fn set_wanted(&self, wanted: bool) -> bool {
        let changed = self.wanted.swap(wanted, Ordering::SeqCst) != wanted;
        if changed {
            let _ = self.commands.send(Command::Want(wanted));
        }
        changed
    }

    /// Whether the key is in the state the owner wants: present while
    /// published, absent while withdrawn. `None` when the read fails.
    pub(super) fn key_intact(&self) -> Option<bool> {
        let present = key_present(self.connection_id).ok()?;
        Some(present == self.wanted.load(Ordering::SeqCst))
    }

    /// What `wgd status` shows about the key. Reads the store, so call it off
    /// the async runtime.
    pub(super) fn overview(&self) -> crate::status_model::DynamicStoreKey {
        crate::status_model::DynamicStoreKey {
            key: dns_key(self.connection_id),
            mode: self.mode,
            match_domain: match_domain(self.connection_id, self.mode),
            wanted: self.wanted.load(Ordering::SeqCst),
            present: key_present(self.connection_id).ok(),
        }
    }

    /// Remove the key and stop the thread. Bounded by `REMOVE_TIMEOUT`; a
    /// key left behind still dies with the helper's session.
    pub(super) fn remove(&self) {
        let Some(thread) = self
            .thread
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        else {
            return;
        };
        let (ack, acked) = mpsc::channel();
        if self.commands.send(Command::Remove(ack)).is_ok()
            && acked.recv_timeout(REMOVE_TIMEOUT).is_ok()
        {
            let _ = thread.join();
        }
    }
}

/// State of the owner thread. Lives on that thread only, together with the
/// CoreFoundation objects, which are not `Send`.
struct Owner {
    interface: String,
    mode: StoreKeyMode,
    key: String,
    match_domain: String,
    dns_servers: Vec<String>,
    wanted: bool,
    published: bool,
    /// A publish failed and was logged at WARN; repeats go to DEBUG.
    failing: bool,
}

impl Owner {
    fn run(mut self, commands: &mpsc::Receiver<Command>) {
        let changed = Arc::new(AtomicBool::new(false));
        let Some(store) = SCDynamicStoreBuilder::new("wgd-dns-store")
            .session_keys(true)
            .callback_context(SCDynamicStoreCallBackContext {
                callout: on_change,
                info: Arc::clone(&changed),
            })
            .build()
        else {
            self.log_failed("session");
            return;
        };
        let watched = CFArray::from_CFTypes(&[CFString::new(&self.key)]);
        if !store.set_notification_keys(&watched, &CFArray::<CFString>::from_CFTypes(&[])) {
            self.log_failed("notification_keys");
        }
        match store.create_run_loop_source() {
            Some(source) => {
                CFRunLoop::get_current().add_source(&source, unsafe { kCFRunLoopCommonModes })
            }
            None => self.log_failed("run_loop_source"),
        }

        self.remove_stale();
        self.apply(&store);
        let mut next_poll = Instant::now() + POLL_INTERVAL;
        loop {
            CFRunLoop::run_in_mode(unsafe { kCFRunLoopDefaultMode }, TURN, true);
            loop {
                match commands.try_recv() {
                    Ok(Command::Want(wanted)) => self.wanted = wanted,
                    Ok(Command::Remove(ack)) => {
                        self.remove(&store);
                        let _ = ack.send(());
                        return;
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    // The handle is gone without a teardown; do not linger.
                    Err(mpsc::TryRecvError::Disconnected) => {
                        self.remove(&store);
                        return;
                    }
                }
            }
            self.apply(&store);
            if changed.swap(false, Ordering::SeqCst) {
                self.check(&store, "notification");
            }
            if Instant::now() >= next_poll {
                next_poll = Instant::now() + POLL_INTERVAL;
                if self.failing && self.wanted && !self.published {
                    self.publish(&store, None);
                }
                self.check(&store, "poll");
            }
        }
    }

    /// A previous owner may have left the key behind as a non-session key
    /// (configd refuses to `set` a key another session owns). Removing it
    /// takes a plain session; this is the only write outside the owner's.
    fn remove_stale(&self) {
        let Some(plain) = SCDynamicStoreBuilder::new("wgd-dns-store-cleanup").build() else {
            return;
        };
        if plain.get(self.key.as_str()).is_some() && plain.remove(self.key.as_str()) {
            warn!(
                interface = self.interface,
                mode = self.mode.as_str(),
                key = self.key,
                "userspace_helper_dns_store_key_stale_removed"
            );
        }
    }

    /// Bring the key in line with `wanted`. A failed publish is retried by
    /// the poll, not on every turn.
    fn apply(&mut self, store: &SCDynamicStore) {
        if self.wanted && !self.published && !self.failing {
            self.publish(store, None);
        } else if !self.wanted && self.published {
            self.published = false;
            if store.remove(self.key.as_str()) {
                info!(
                    interface = self.interface,
                    mode = self.mode.as_str(),
                    key = self.key,
                    "userspace_helper_dns_store_key_withdrawn"
                );
                self.flush_if_active();
            } else {
                self.log_failed("withdraw");
            }
        }
    }

    /// The key changed or a poll is due: republish if it went missing.
    fn check(&mut self, store: &SCDynamicStore, trigger: &'static str) {
        if !self.wanted || !self.published || store.get(self.key.as_str()).is_some() {
            return;
        }
        self.published = false;
        self.publish(store, Some(trigger));
    }

    /// `restored_by` is set when the key had disappeared under us.
    fn publish(&mut self, store: &SCDynamicStore, restored_by: Option<&'static str>) {
        let servers: Vec<CFString> = self.dns_servers.iter().map(|s| CFString::new(s)).collect();
        let value = CFDictionary::from_CFType_pairs(&[
            (
                CFString::from_static_string("ServerAddresses"),
                CFArray::from_CFTypes(&servers).as_CFType(),
            ),
            (
                CFString::from_static_string("SupplementalMatchDomains"),
                CFArray::from_CFTypes(&[CFString::new(&self.match_domain)]).as_CFType(),
            ),
            // Without it IPMonitor appends the match domain to the default
            // resolver's search list, so every short name would also be
            // tried as `<name>.wgd-shadow-….inactive`.
            (
                CFString::from_static_string("SupplementalMatchDomainsNoSearch"),
                CFNumber::from(1).as_CFType(),
            ),
            (
                CFString::from_static_string("SearchOrder"),
                CFNumber::from(SEARCH_ORDER).as_CFType(),
            ),
        ]);
        if !store.set(self.key.as_str(), value.to_untyped()) {
            self.log_failed("publish");
            return;
        }
        self.published = true;
        self.failing = false;
        self.flush_if_active();
        match restored_by {
            Some(trigger) => warn!(
                interface = self.interface,
                mode = self.mode.as_str(),
                key = self.key,
                trigger,
                "userspace_helper_dns_key_restored"
            ),
            None => info!(
                interface = self.interface,
                mode = self.mode.as_str(),
                key = self.key,
                match_domain = self.match_domain,
                dns_servers = ?self.dns_servers,
                "userspace_helper_dns_store_key_published"
            ),
        }
    }

    /// Whether mDNSResponder picks up a key change on its own is open
    /// ("Open questions"); in active mode, flush so stale answers go away.
    /// Shadow keys answer no real query, so there is nothing to flush.
    fn flush_if_active(&self) {
        if self.mode == StoreKeyMode::Active {
            crate::macos_dns::flush_resolver_cache();
        }
    }

    fn remove(&mut self, store: &SCDynamicStore) {
        // Remove even when not published: a withdraw may have failed.
        let removed = store.remove(self.key.as_str());
        let status = sc_status();
        let was_published = std::mem::take(&mut self.published);
        info!(
            interface = self.interface,
            mode = self.mode.as_str(),
            key = self.key,
            removed,
            sc_status = status,
            "userspace_helper_dns_store_key_removed"
        );
        if was_published {
            self.flush_if_active();
        }
    }

    /// Only the first of a run of failed publishes warns.
    fn log_failed(&mut self, stage: &'static str) {
        let status = sc_status();
        if self.failing && stage == "publish" {
            debug!(
                interface = self.interface,
                mode = self.mode.as_str(),
                stage,
                sc_status = status,
                "userspace_helper_dns_store_key_failed"
            );
            return;
        }
        self.failing |= stage == "publish";
        warn!(
            interface = self.interface,
            mode = self.mode.as_str(),
            key = self.key,
            stage,
            sc_status = status,
            "userspace_helper_dns_store_key_failed"
        );
    }
}

fn on_change(_store: SCDynamicStore, _keys: CFArray<CFString>, changed: &mut Arc<AtomicBool>) {
    changed.store(true, Ordering::SeqCst);
}
