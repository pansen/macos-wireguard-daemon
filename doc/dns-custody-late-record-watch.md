# A running daemon does not watch late custody records

**Status:** proposed
**Scope:** privileged daemon custody watch (`src/privileged/dns_watch.rs`), userspace helper custody record (`src/userspace_helper/macos/dns.rs`, `src/dns_custody.rs`)
**Related:** `issues/dns-crash-recovery.md` (the custody watch this extends), `issues/shutdown-teardown.md`

Line numbers below are as of `1c0202c`.

## Problem

The daemon only learns about a custody record when it runs `settle_locked`
(`src/privileged/dns_watch.rs:330`). That is the only place that calls
`watch_record` (`dns_watch.rs:239`), which registers the kqueue
`EVFILT_PROC`/`NOTE_EXIT` watch on the helper's pid. `settle_locked` runs:

- after a connect (`src/privileged/connection_ops.rs:191`),
- after every sweep: the startup sweep (`src/privileged/mod.rs:196`), the exit
  watch of an already watched helper (`handle_exit`, `dns_watch.rs:269`) and
  the retry loop (`ensure_retry_loop`, `dns_watch.rs:424`).

Nothing runs it when a helper writes a record on its own. Since `1c0202c` the
helper creates the `watch` sentinel after writing a record
(`dns_custody::ensure_watch_sentinel`, `src/dns_custody.rs:142`, called from
`persist_dns_custody`, `src/userspace_helper/macos/dns.rs:63`). That wakes a
daemon that is not running: launchd starts it, the startup sweep settles, and
the record gets its watch. It does nothing when the daemon is already running
and the sentinel already exists.

### Scenario

1. Tunnel X is up and promotes DNS. Its record is watched, so the daemon stays
   resident and the sentinel exists.
2. Tunnel Y connects on a LAN whose resolvers collide with its own, so it does
   not promote DNS and writes no record. The `settle_locked` after Y's connect
   finds no record for Y and registers no watch.
3. Y roams onto a hotspot and promotes DNS. Its helper writes the record;
   `ensure_watch_sentinel` sees the sentinel from X and does nothing.
4. Y's helper dies (SIGKILL, panic). Nobody gets a `NOTE_EXIT` for it, so
   Y's tunnel DNS stays on the service.

The DNS is repaired only at the next `settle_locked`: another connect, X's
helper exiting, a retry tick (only while some record is restorable) or a daemon
restart. Until then name resolution on that service points at resolvers that
are only reachable through a tunnel that no longer exists.

A daemon that is running but not resident (idle timer pending, no watches) is
not affected: the helper's write creates the missing sentinel, the daemon
idle-exits, launchd restarts it because of the sentinel, and the startup
sweep settles.

## Proposed work

### Watch the custody directory

Register an `EVFILT_VNODE` watch with `NOTE_WRITE` on an `O_EVTONLY`
descriptor of `dns-custody/`. A directory gets `NOTE_WRITE` whenever an entry
is created, renamed into it or unlinked, which covers the `rename` at the end
of `state_file::write_atomic`. On the event, take the network mutation lock and
run `settle_locked`, which already classifies every record, registers missing
watches (`AlreadyWatched` is a no-op) and keeps the sentinel consistent.

Points to settle during implementation:

- The event also fires for the daemon's own writes (sentinel, sweep rewrites,
  temp files) and for every record rewrite by the reconciler. Coalesce: one
  pending settle at a time, run on a worker thread, never on the kqueue
  thread, and skip it if the directory listing has not changed since the last
  settle.
- The existing `ExitWatcher` (`dns_watch.rs:63`) is generic over a per-pid
  token and its `watch_loop` (`dns_watch.rs:152`) only handles
  `EVFILT_PROC`. Either teach `watch_loop` a second filter or give the
  directory watch its own small kqueue thread; the second keeps
  `ExitWatcher` simple.
- The directory watch must not count towards the resident count. Otherwise a
  daemon with no live records could never idle-exit.
- `ensure_dns_custody_dir` may recreate the directory after someone deleted it
  (`connection_ops.rs`, connect path). A watch on the old descriptor then
  sees nothing; re-register it whenever the directory is (re)created, and on
  `NOTE_DELETE`/`NOTE_RENAME` of the directory itself.

### Alternatives considered

- **The helper notifies the daemon over the control socket.** The helper would
  become a client of the daemon, with a new request type and its own
  authorization path. It also fails exactly when the daemon is busy or
  restarting, which the sentinel already covers. More coupling for no gain.
- **Periodic rescan while resident.** Simple, but the detection delay equals
  the interval, and the daemon would wake up on a timer for the whole life of
  every tunnel.

## Verification

A unit test can cover the coalescing logic if it is a pure function. For the
kqueue part, a manual test as root on a machine with the daemon running and at
least one watched record:

1. Start a dummy process (`sleep 600`) and note its pid and start time.
2. Write a custody record for a fake interface with that pid and start time
   and a service name that does not exist in the current network location, so
   that no sweep can change real DNS (the record classifies as deferred once
   the process is gone).
3. Expect `privileged_dns_custody_watch_registered` for that pid in the daemon
   log within about a second.
4. Kill the dummy process and expect `privileged_dns_custody_helper_died` for
   the fake interface.
5. Remove the fake record.

## Non-goals

- Changing when the helper writes records or creates the sentinel.
- The session agent's 5 s wait on a refused daemon socket at shutdown; that
  belongs to `issues/shutdown-teardown.md` (item 4).
