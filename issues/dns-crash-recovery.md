# DNS crash recovery

**Status:** implemented, not committed; manual test on macOS pending (see "Implementation status")
**Scope:** macOS userspace helper DNS custody (`src/userspace_helper.rs`), privileged service startup (`src/privileged/mod.rs`, `src/privileged/connection_store.rs`)
**Related:** `issues/dns-ownership-edge-cases.md` (this note implements Finding B, solution paths B1 and B2, in a form that A2 can later extend)

## Problem

### Observed incident

On 2026-10-19 the connection `wg-1ce3a4a1` (interface `utun6`) was up and
promoting tunnel DNS `10.66.77.2, 100.64.1.1` onto the primary service
`Wi-Fi`. Its helper log ends mid-session:

```
2026-10-19T13:49:31Z  INFO userspace_helper_transfer_sample interface="wg-1ce3a4a1" ...
```

There is no `userspace_helper_shutdown_requested`, no
`userspace_helper_network_cleanup_dns` and no `userspace_helper_device_stop_complete`.
Every graceful shutdown path (SIGINT, SIGTERM, removal of the control socket;
`src/userspace_helper.rs:506-528`) logs the first of those lines, so the helper
died without running teardown: SIGKILL, a panic, or power loss during sleep.

Two days later (2026-10-21):

- no helper process was running and no `utun6` existed;
- the privileged daemon had been socket-activated several times and only
  served `ListConnections`;
- `Wi-Fi` still had the two tunnel resolvers set as manual DNS servers in
  System Settings. Every name lookup went to addresses that are only
  reachable through a tunnel that no longer existed, so name resolution was
  broken until the entries were removed by hand.

### Why the system does not heal itself

The helper writes tunnel DNS with `networksetup -setdnsservers <service> ...`
(`set_macos_dns_servers`, `src/userspace_helper.rs:1244`). That edits the
persistent network preferences of the current location. Unlike routes, which
disappear together with the utun, these settings survive process death and
reboots.

The original DNS of each owned service lives only in helper memory
(`MacosDnsState.services`, each a `MacosDnsServiceState` with the captured
`dns_servers` and `search_domains`). When the helper dies without teardown,
the originals are lost and nothing else knows that a service was modified.

The only healing mechanism is adoption at the **next connect**
(`capture_macos_dns_service`, `src/userspace_helper.rs:2163`): a service whose
live DNS exactly equals the connecting config's DNS list is captured with an
Empty original, so that tunnel's teardown resets it to DHCP. That does not
help here:

1. Nothing triggers it. The user may never reconnect, or reconnect only after
   noticing that DNS is broken. `reconcile_boot` only reconnects global
   `Automatic` connections, and only once per boot.
2. It only recognises the stray if the next connect uses the same DNS list.
   A different config captures the stray as the user's "original" and
   reinstalls it at teardown (Finding B.1 in the edge-case note).
3. Under `DnsPolicy::PrimaryOnly` it only inspects the current primary
   service. A stray on a service that is no longer primary is never examined
   (Finding B.2).
4. It cannot restore search domains. `configure_macos_dns` clears search domains
   (`set_macos_search_domains_empty`) after capturing them, so after a crash
   the user's search domains are gone even when DNS servers are healed.
5. `make uninstall.dns` only runs on uninstall and only touches the primary
   service.

`make check` does not surface the state either. The network overview has a
`stale tunnel DNS on LAN` status, but the overview is only produced while a
tunnel is coming up.

## Goals

- After any non-graceful helper death, wgd restores the exact pre-tunnel DNS
  servers and search domains of every service the dead helper owned, without
  any user action: within seconds if the daemon is running or can be
  restarted by launchd, and at boot after a power loss. Nobody has to notice
  the breakage or run a command.
- Strays without a custody record (left by builds that predate this change,
  or by a crash between the write to `networksetup` and the write to the
  record) are cleared to DHCP on every service, not only the primary one, as
  long as they exactly match the DNS list of some stored connection.
- Recovery never touches DNS owned by a live helper, and never touches DNS
  the user configured that does not exactly match a wgd tunnel DNS list.

## Non-goals

- Concurrent DNS-promoting tunnels (Finding A). The custody record is
  per connection; the shared stack from A2 is future work.
- Network locations (Finding C). Recovery addresses only the current
  location's services, like everything else that uses `networksetup`.
- Replacing `networksetup` with dynamic-store resolvers (A3).

## Known limitation: user DNS identical to a tunnel's DNS

The fallback (Design 3, step 2) cannot tell a stray from DNS the user set by
hand when both are the same list. Example: an office network where the user
manually configured the company resolvers, and the VPN config pushes exactly
the same resolvers. With no live helper for that connection, every daemon
start resets that service to DHCP.

This is accepted. It only hits a list that is byte-for-byte a wgd tunnel's
DNS, and that DNS is what the VPN provides anyway. The WARN line
`privileged_dns_stray_cleared` names the service and the servers, so the
behaviour is traceable.

## Design

### 1. Persistent custody record (written by the helper)

Add a per-connection file next to the existing active marker:

```
/Library/Application Support/wgd/dns-custody/<interface>.json   (root:wheel 0600)
```

`privileged_runtime_dir()` survives reboot, which is required: power loss is
one of the failure modes. The file name is the control interface name
(`wg-<id8>`), which the helper already knows. The record also carries the
full connection id, so the daemon does not have to map the interface back
through the stored connection list, and a record stays meaningful after its
connection was removed from the store.

The helper does not know its connection id today: the daemon passes only the
config and the interface (`spawn` env in `src/privileged/commands.rs:296`).
Add `WGD_CONNECTION_ID` to that env and read it next to `CONFIG_B64_ENV`.

#### Directory ownership

The privileged daemon creates `dns-custody/` transparently; the helper never
creates it. `config::ensure_privileged_runtime_dir()` creates it as
`root:wheel 0700` and validates it with
`trusted_exec::validate_root_owned_path(.., TrustedPath::Directory)`, the same
way it treats the runtime dir itself. The daemon calls this at startup (before
the sweep) and again right before spawning a helper, so the directory exists
even if someone deleted it while the daemon was running. If the directory is
missing or fails validation when the helper writes, the write fails and the
helper logs `userspace_helper_dns_custody_write_failed` (see write rules); it
does not try to create or repair it.

#### Durability

`state_file::write_atomic` already writes a `0600` temp file, `fsync`s it and
renames it over the target. It does not `fsync` the directory, so after power
loss the rename may be lost and the old record (or none) comes back. Add a
directory `fsync` after the rename in `write_atomic` (benefits every caller),
and after deleting a record. Without it, the "write-ahead" rule below is not
guaranteed across power loss, which is the failure mode this note exists for.

Schema (version it from the start so A2 can migrate it):

```rust
#[derive(Serialize, Deserialize)]
struct DnsCustodyRecord {
    version: u32,                 // 1
    connection_id: ConnectionId,  // full id, from WGD_CONNECTION_ID
    interface: String,            // "wg-1ce3a4a1"
    helper_pid: u32,
    helper_start: ProcessStart,   // start time of helper_pid, see Design 2
    tunnel_dns: Vec<String>,      // exactly what was written with -setdnsservers
    services: Vec<DnsCustodyService>,
}

#[derive(Serialize, Deserialize)]
struct DnsCustodyService {
    service: String,
    original_dns_servers: Option<Vec<String>>,    // None = Empty (DHCP)
    original_search_domains: Option<Vec<String>>, // None = Empty
}
```

`DnsCustodyService` is the serialised form of `MacosDnsServiceState`; derive
`Serialize`/`Deserialize` on that struct, or convert explicitly. Do not
introduce a second notion of "original".

Write rules. The record is write-ahead: it must already list a service on
disk before that service's DNS is modified.

- `configure_macos_dns` (`src/userspace_helper.rs:1138`): for each target
  service, capture, push onto `saved`, **persist the record**
  (`state_file::write_atomic`), then call `set_macos_dns_servers` /
  `set_macos_search_domains_empty`.
- The DNS reconciler (`macos_reconcile_dns`): whenever the owned set changes
  (take ownership, pull back on collision, drop a vanished service), persist
  the record after updating the in-memory list. On take-ownership, persist
  before writing DNS, as in `configure_macos_dns`. On release, persist after the
  restore succeeded.
- Teardown (`cleanup_network_macos`, `src/userspace_helper.rs:1077`, which
  logs `userspace_helper_network_cleanup_dns`): restore every owned service
  with `restore_macos_dns_service`, then delete the record. If any restore fails, rewrite the record
  with only the services that failed, so that the sweep retries them.
- If persisting fails, log `userspace_helper_dns_custody_write_failed` at
  WARN and continue. Losing crash recovery must not break connect.

Keep the write path in one function (`persist_dns_custody(&MacosDnsState,
interface, tunnel_dns)`) so the reconciler and the connect path cannot
diverge.

### 2. Liveness of the owning helper

The sweep must only act on records whose helper is dead. Do not rely on the
UAPI socket's existence: after SIGKILL the socket file stays behind, while
after a reboot `/var/run` is wiped.

Facts from the helper's startup order that the check relies on:

- The UAPI socket is bound in `start_device` (`src/userspace_helper.rs:459`)
  before `configure_network` (`:479`) writes any DNS. A helper that has
  touched DNS therefore always has a connectable socket until it exits.
- The pid file `/var/run/wireguard/<interface>.wgd.pid` is written only after
  `start_device` returns, i.e. after DNS was applied. It is not usable as a
  liveness signal during startup, and it is gone after a reboot.
- The helper daemonizes; the pid that writes the record
  (`std::process::id()` in the child) is the pid that owns DNS.

Signature:

```rust
fn helper_is_live(
    connection_id: ConnectionId,
    interface: &str,
    pid: Option<u32>,
    start: Option<ProcessStart>,
) -> bool
```

1. `UnixStream::connect(/var/run/wireguard/<interface>.sock)`. A successful
   connect means a helper is alive: return true.
2. `ECONNREFUSED` or `ENOENT` means nobody is listening. If `pid` is given,
   the process counts as alive only if all three hold:
   - `pid_is_alive(pid)`;
   - its executable (`process_executable`, today private in
     `src/privileged/commands.rs:527`) canonicalises to the daemon's own
     `current_exe()`, as in `ensure_gotatun_process_identity`. Do not
     hard-code `/usr/local/bin/wgd`;
   - its start time equals `start`.
3. Anything else: return false.

`connection_id` alone does not solve pid reuse. The interface is derived from
the id (`ConnectionId::interface_name`), so the id adds no information about
*which process* holds the pid. A different connection's helper can reuse the
pid and passes both the "alive" and the "is wgd" checks. The start time is
what pins the pid to one process instance. `managed_pids::process_start_ticks`
is a stub that returns `None` today; implement it on macOS with
`proc_pidinfo(PROC_PIDTBSDINFO)` (`pbi_start_tvsec`, `pbi_start_tvusec`) and
return that as `ProcessStart`. The helper records its own start time with the
same function. `connection_id` still belongs in the signature: it is the key
for logging and for `clear_active`, and the sweep needs it when the
connection was already removed from the store.

The fallback (Design 3, step 2) has no record and therefore no pid or start
time. It calls `helper_is_live(id, interface, None, None)`, which reduces to
the socket check. That is enough: a helper that has written DNS has a bound
socket (see above), and connect/sweep both hold the network mutation lock, so
no helper can be between "spawned" and "socket bound" while the sweep runs.

Move `pid_is_alive`, `process_executable` and `process_start_ticks` into
`managed_pids` (there are two copies of `pid_is_alive` today: `managed_pids`
and `commands.rs:498`) and put `helper_is_live` in `connection_store`, so
`is_active` can switch to the same check later. Today `is_active` reports a
SIGKILLed connection as active, because only the socket file is checked.

### 3. Sweep (run by the privileged daemon)

New function `connection_store::sweep_dead_dns_custody()`. It is the one
cleanup routine; section 3a decides *when* it runs. At daemon start it runs
on the same background thread as `reconcile_boot` and **before** it, so that
an automatic reconnect never captures a stray as an original.

Unlike `reconcile_boot`, the sweep is not gated by `boot_id`: it runs on every
daemon start. It is cheap when there is nothing to do (one `readdir` of an
empty directory).

#### DNS list equality

Every "live DNS equals X" comparison in this note uses one function,
`dns_lists_equal(live: Option<&[String]>, expected: &[String]) -> bool`:

- `get_macos_dns_servers` returns `None` for the "There aren't any DNS
  Servers set on ..." output (`src/userspace_helper.rs:1224`). `None` never
  equals a non-empty list. `expected` is never empty: a connection without DNS
  writes no record and contributes no list to the fallback.
- Each entry is parsed as `IpAddr` and compared as an address, so
  `fd00::1` and `fd00:0:0:0:0:0:0:1` are equal. Any entry that does not parse
  makes the comparison false (the conservative direction: no action).
- The comparison is ordered. `networksetup` returns servers in the order they
  were set, and the helper writes `tunnel_dns` in config order. A reordered list
  means someone edited it, which counts as "changed".
- Strict subsets and supersets are not equal.

Search domains are never compared. The sweep restores them from the record
when it restores servers, and the fallback leaves them alone.

#### Original equal to the tunnel list

If a service already carried exactly the tunnel's DNS when the helper
connected (a stray from an earlier crash), `capture_macos_dns_service`
adopts it with an Empty original. The record then holds `None` for that
service, and the sweep resets it to DHCP. A recorded original can therefore
never equal `tunnel_dns`, and "restore originals" can never re-install the
tunnel DNS.

#### Algorithm

Holding `lock_system_network_mutation()` for the whole pass. `clear_active`
additionally needs the connection's `ConnectionLock`; take it in the same
order `connection_ops::connect` takes both locks, and only for step 1.5.

1. For each `dns-custody/*.json`:
   1. Parse it. On error, log WARN, rename the file to `*.corrupt` and continue.
   2. If `helper_is_live(connection_id, interface, Some(helper_pid),
      Some(helper_start))`, skip it. Whether the connection still exists in
      the store does not matter: a record of a removed connection is restored
      the same way.
   3. For each service in the record, if the service exists in the current
      `-listallnetworkservices` output **and** its live DNS still equals
      `tunnel_dns`, restore the recorded originals (servers and search
      domains). If the live DNS differs, the user or something else changed it
      after the crash: leave it and log `privileged_dns_custody_service_changed`.
      If the service is not listed, keep it in the record (it may belong to
      another location; see Finding C) and log at DEBUG.
   4. Delete the record when every service was either restored or found
      changed. Otherwise rewrite it with the remaining services.
   5. Clear the connection's stale active marker (`clear_active`) if its socket
      is dead, so `ListConnections` stops reporting it as connected. Skip this
      if the connection no longer exists in the store.
2. Fallback for strays without a record: collect the DNS lists of all stored
   connections (`connection_config::parse_connection_config(&raw_conf).dns_servers`),
   excluding connections for which `helper_is_live(id, interface, None, None)`
   holds. For **every** current network
   service whose live DNS exactly equals one of those lists and which is not
   listed in any custody record, set DNS servers to Empty. Leave search
   domains alone; their original is unknown. Log each action at WARN as
   `privileged_dns_stray_cleared service=... servers=...`.
3. Log one INFO summary line: `privileged_dns_sweep_complete restored=N
   cleared=M skipped_live=K`.

Each `networksetup` call must use the same trusted path as the helper
(`trusted_exec`). Move `get_macos_dns_servers`, `set_macos_dns_servers`,
`set_macos_dns_servers_empty`, the search-domain variants and
`list_macos_network_services` out of `userspace_helper.rs` into a shared
`src/macos_dns.rs` so the helper and the daemon call one implementation.

`background_work` must cover the sweep the same way it covers
`reconcile_boot`, so the idle-exit check cannot stop the daemon mid-sweep.

### 3a. Custody watch: when the sweep runs

A sweep that only runs at daemon start is not enough. The daemon is
socket-activated (`RunAtLoad false` in `etc/me.pansen.wgd.privileged.plist`)
and idle-exits after 60s, so after a helper crash nothing would start it
until some client happens to connect. In the observed incident that was
luck: something ran `ListConnections`. The sweep has to run because the
helper died, not because the user ran a command.

Three triggers cover the cases, from fastest to slowest.

**1. Exit watch while the daemon runs.** For every custody record whose
helper is live, the daemon registers a kqueue `EVFILT_PROC` / `NOTE_EXIT`
watch on `helper_pid`. Helpers are not children of the daemon (they
daemonize), but `EVFILT_PROC` works for any pid when the watcher is root.
On `NOTE_EXIT` the daemon runs the single-record sweep from section 4 for
that connection, under the network mutation lock:

- graceful exit: teardown already deleted the record, so the sweep finds
  nothing and logs nothing above DEBUG;
- crash: the record is still there and the helper is dead, so the sweep
  restores DNS and clears the active marker. Log
  `privileged_dns_custody_helper_died interface=.. pid=..` at WARN before
  restoring.

Registration happens (a) after `connection_ops::connect` has seen the helper
become ready, and (b) at daemon start, after the startup sweep, for every
remaining record whose helper is live. If registration fails with `ESRCH`,
the helper is already gone: run the single-record sweep right away.

While at least one watch is registered, the daemon must not idle-exit:
each watch holds one `background_work` count and releases it after its
sweep. A DNS-promoting tunnel therefore keeps the daemon resident. That is
a sleeping process blocked in `kevent`, which costs nothing measurable, and
it is the only place that can notice the helper's death.

**2. launchd keeps the daemon alive while custody is pending.** Trigger 1
fails if the daemon itself dies (crash, SIGKILL, `launchctl kickstart -k`)
while a tunnel is up. Add to the daemon plist:

```xml
<key>KeepAlive</key>
<dict>
    <key>PathState</key>
    <dict>
        <key>/Library/Application Support/wgd/dns-custody/watch</key>
        <true/>
    </dict>
</dict>
```

launchd then starts the daemon whenever the sentinel `dns-custody/watch`
exists and the daemon is not running, including at boot. The restarted
daemon runs the startup sweep and re-registers the exit watches (trigger 1).
`RunAtLoad` stays `false`; socket activation is unchanged.

The daemon owns the sentinel:

- create it (`write_atomic`, empty) under the network mutation lock before
  spawning a helper whose config has DNS;
- after every sweep and every exit-watch event, delete it if no record with
  a live helper and no restorable record remains.

Records that are only kept because their service is not in the current
location (step 1.3) do not keep the sentinel. Otherwise the daemon would
stay resident for a service that may never reappear. They are retried on
every daemon start.

The daemon's idle-exit must honour the sentinel too: if the sentinel exists
but no watch is registered (e.g. a restore failed and must be retried),
launchd would restart the daemon right after each idle-exit. In that state,
the daemon retries the sweep every 60s instead of exiting, and logs
`privileged_dns_custody_retry` at WARN each time. launchd's default
`ThrottleInterval` (10s) limits restart loops if the daemon crashes on
startup.

**3. Boot.** After power loss or a reboot, `/var/run` is empty and no helper
runs, but the sentinel in `privileged_runtime_dir()` survived. launchd
starts the daemon at boot because of trigger 2, and the startup sweep
restores DNS before the user logs in.

Taken together: a helper SIGKILL or panic heals within seconds (trigger 1;
the daemon is resident while the tunnel is up, and launchd brings it back
if it is not). Power loss, as in the incident, heals during the next boot
(trigger 3).

Side effect: a daemon start through the sentinel also runs `reconcile_boot`,
so after a crash global `Automatic` connections come up at boot rather than
at the first client request. That is what `reconcile_boot` is meant for, and
it runs after the sweep, so it cannot adopt the stray.

### 4. Adoption at connect stays as is, with one change

`capture_macos_dns_service` keeps its exact-match adoption. Before it runs,
the connecting helper's own leftover custody record (same interface, dead
helper) must already be resolved. The startup sweep normally handles this,
because `ConnectConnection` always goes through the daemon. As a belt-and-braces
measure, `connection_ops::connect` calls a single-record variant of the sweep
for the connection it is about to start, under the network mutation lock it
already takes.

### 5. Visibility

Cleanup never depends on the user (section 3a). Visibility exists only to
explain what happened and to debug the cases where a restore keeps failing.

- `wgd status`: the daemon adds custody state to its status response
  (a new read-only privileged request `ListDnsCustody`, authorised like
  `ListConnections`). `wgd status` prints it only when something is not
  normal, so a healthy system shows nothing extra:
  - a record with a dead helper that could not be restored yet (retry state
    from 3a, trigger 2);
  - records kept because their service is not in the current location;
  - the last automatic restore since boot, as one line, e.g.
    `DNS restored on Wi-Fi after wg-1ce3a4a1 (office) exited without cleanup, 13:49`.
  Records whose helper is live are normal and not shown.
- `make check` / `make check.privileged`: add a step that prints every
  service's DNS and the custody state, without `sudo`:
  ```make
  @echo "==> DNS (expect: no tunnel DNS unless a tunnel is up)"
  networksetup -listallnetworkservices | tail -n +2 | while read -r s; do \
    printf '  %-24s %s\n' "$$s" "$$(networksetup -getdnsservers "$$s" | tr '\n' ' ')"; done
  wgd status || true
  ```
  Fix the pings in `check.privileged` (`Makefile:185-187`) while touching it:
  `-m1` sets TTL=1 on macOS, so `ping -c1 -m1` fails for any off-link host.
  Use `-t2` (timeout in seconds).
- `make uninstall.dns`: replace the shell logic with `wgd privileged
  --sweep-dns` (a hidden subcommand that runs `sweep_dead_dns_custody` once
  and exits), so uninstall gets exact restores and covers all services.
  Two ordering rules:
  - It needs the installed binary. Today `uninstall` runs
    `uninstall.autostart uninstall.privileged uninstall.dns`
    (`Makefile:163`), so the binary is gone before `uninstall.dns` runs. Run
    `uninstall.dns` after the helpers are stopped but before the binary is
    removed.
  - After the sweep, remove `dns-custody/` (including `*.corrupt` files and
    the `watch` sentinel) if no record is left. Remove the sentinel before
    `launchctl bootout` of the daemon; otherwise `KeepAlive` races the
    uninstall. Records kept because their service is not in the current
    location are printed with a hint to switch location and rerun; `purge`
    removes them unconditionally.

## Failure windows that remain

| Crash point | Result |
|---|---|
| After the record is written, before `-setdnsservers` | Sweep sees live DNS ≠ `tunnel_dns`, leaves the service, deletes the record. Correct. |
| After `-setdnsservers`, before `-setsearchdomains Empty` | Sweep restores servers and search domains from the record. Correct. |
| Reconciler took a new service, record write failed (WARN logged) | Covered by the fallback: DNS cleared to Empty, search domains lost. |
| Pre-upgrade leak, no record | Fallback: cleared to Empty on any service, as long as the DNS list still matches a stored connection. A leak from a since-removed connection is not recognised (needs the applied-list history from B1/A2). |
| Teardown restored all services, crash before the record is deleted | Sweep sees live DNS ≠ `tunnel_dns` on every service, treats them as changed, deletes the record. Correct, no double restore. |
| Daemon dies mid-sweep, some services restored | Restored services now differ from `tunnel_dns`; the next sweep drops them and restores the rest. The sweep is idempotent, so it does not need to rewrite the record after every service. |
| Connection removed from the store while its dead helper's record exists | Sweep restores from the record alone (step 1.2), skips `clear_active`. The fallback would not catch it, because it only knows stored connections. |
| Helper pid reused by another process, including another wgd helper | Start time differs, so `helper_is_live` is false and the record is swept. |
| Helper spawned, sweep runs before its socket is bound | Cannot happen: connect and sweep both hold the network mutation lock, and the helper binds the socket before it writes DNS. |
| Helper crashes while the daemon runs | Exit watch fires, single-record sweep restores within seconds. |
| Daemon crashes while a tunnel is up, helper crashes later | launchd restarts the daemon (sentinel exists), which re-registers the watch; then as above. |
| Power loss with a tunnel up | Sentinel survives; launchd starts the daemon at boot; startup sweep restores. |
| Restore fails (e.g. `networksetup` error) | Record and sentinel stay; daemon stays resident and retries every 60s, logging `privileged_dns_custody_retry`. |
| Crash after the sentinel is created, before the helper writes a record | Daemon starts at boot, finds no record, deletes the sentinel. Harmless. |
| Two DNS-promoting tunnels, one crashes | The record holds the crashed helper's view of the originals, which may be the other tunnel's DNS (Finding A.2). The live-helper check prevents touching DNS the surviving helper owns only if the DNS lists differ. Out of scope; A1 avoids this case. |

## Tests

Manual test on macOS:

1. Connect a DNS-promoting connection; note `networksetup -getdnsservers Wi-Fi`
   and `-getsearchdomains Wi-Fi` from before the connect.
2. `sudo kill -9 <helper pid>`. Do not run any wgd command afterwards.
3. Within a few seconds, verify without wgd (`networksetup` only) that Wi-Fi
   DNS and search domains are back to step 1, and that the privileged log has
   `privileged_dns_custody_helper_died` and
   `privileged_dns_sweep_complete restored=1`. Then `wgd status` shows the
   connection as disconnected plus the "DNS restored" line.
4. Connect again, `sudo kill -9 <daemon pid>`, check that launchd restarts
   the daemon (`launchctl print system/me.pansen.wgd.privileged`), then kill
   the helper and repeat step 3.
5. Connect again and hard power off (or `sudo halt -q`). After boot and
   before logging in to anything wgd-related, check DNS as in step 3.

## Implementation status (2026-10-21)

All rollout steps 1-8 are implemented in the working tree; nothing is
committed. `cargo test` passes (lib 230, bin 268), `cargo clippy
--all-targets` and `cargo fmt --check` are clean. Nothing has run against a
real helper, launchd or `networksetup` yet.

### Pending

- The manual test from the Tests section, all three cases: helper
  `kill -9`, daemon `kill -9` with launchd restart through `KeepAlive`, and
  power loss. Include a reconnect after each case.
- `make uninstall` on a real machine (sentinel removed before `bootout`,
  sweep runs before the binary is removed).

### New files

- `src/macos_dns.rs`: `networksetup` wrappers, `restore_service`,
  `dns_lists_equal`, `flush_resolver_cache`.
- `src/dns_custody.rs`: `DnsCustodyRecord` schema and paths.
- `src/privileged/dns_sweep.rs`: planner (`plan_dns_sweep`), executor,
  `sweep_dead_dns_custody`, connect-time `sweep_locked`.
- `src/privileged/dns_watch.rs`: kqueue `ExitWatcher`, sentinel, retry loop.
- `src/privileged/runtime_files.rs`: removal of stale runtime files.

### Deviations from the design above

- Watches hold a separate `resident` count in `socket::serve` (5s re-check)
  instead of `background_work`, which would make the accept loop poll every
  20ms for the whole life of a tunnel. A registered watch also blocks an
  explicit shutdown.
- `sweep_dead_dns_custody` lives in `dns_sweep.rs`, not `connection_store`.
- `clear_active` runs after the network mutation lock is released, to keep
  `connect`'s lock order and avoid a deadlock.
- `plan_dns_sweep` takes `RecordState { record, helper_live }`. The fallback
  also skips a service whose DNS equals the list of any connection with a live
  helper, even if a dead connection shares that list.
- `helper_is_live` treats connect errors other than `ECONNREFUSED`/`ENOENT`
  as live (conservative).
- If the helper cannot read its own start time or connection id, it writes no
  record and logs `userspace_helper_dns_custody_unavailable`; the fallback
  covers that case.
- `persist_dns_custody` takes the services slice plus reconcile inputs
  instead of `&MacosDnsState`, because the connect path has no
  `MacosDnsState` yet.
- After an exit event the daemon waits up to 2s for `helper_is_live` to turn
  false. Observed in tests as a briefly connectable socket after the listener
  closed; verify during the manual test whether this happens with a real
  helper.
- The last automatic restore shown by `wgd status` is stored in
  `/Library/Application Support/wgd/dns-last-restore.json`, outside
  `dns-custody/`.
- `lease_token_is_live` only accepts tokens with `start_ticks == 0`, because
  `process_start_ticks` now returns real values on macOS and the client
  always emits 0. Behaviour is unchanged.

### Additions beyond the design

- **Stale runtime files.** When the sweep confirms a helper dead, it removes
  `<iface>.sock`, `.wgd.pid`, `.wgd.name` and `.wgd.query.sock` from
  `/var/run/wireguard` (symlink-safe, liveness re-checked under the network
  lock), logging `privileged_stale_runtime_files_removed`. Without this,
  `connect` failed with `conflict()` after a helper SIGKILL. `connect` runs
  `clear_dead_helper_leftovers` whenever the socket file exists. Without a
  custody record it relies on the pid file (no start time), so a pid file
  naming a live wgd process counts as live. A socket that accepts connections
  still yields `conflict()` (Finding 5). `.wgd.cleanup` is left alone.
- **Resolver cache flush in the binary.** `macos_dns::flush_resolver_cache`
  runs `dscacheutil -flushcache` and `killall -HUP mDNSResponder` via
  `trusted_exec` after any sweep that restored or cleared a service, and
  after helper teardown. The Makefile no longer does this.

### Known gaps

- `is_active` still checks only the socket file (as planned; switch it to
  `helper_is_live` later).
- If the kqueue watcher cannot start, the sentinel can keep launchd
  restarting an idle-exiting daemon, at most every 10s (`ThrottleInterval`).
- Follow-up for the remaining Makefile-only diagnostics:
  `issues/makefile-diagnostics-into-binary.md`.
