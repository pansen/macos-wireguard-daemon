# Tunnels are not torn down at shutdown

**Status:** proposed
**Scope:** session agent teardown (`src/session_agent.rs`), privileged daemon lifecycle (`src/privileged/mod.rs`), userspace helper shutdown (`src/userspace_helper/`), helper log handling (`src/privileged/commands.rs`)
**Related:** `issues/dns-crash-recovery.md` (the custody sweep is what currently repairs the damage)

## Problem

A reboot or shutdown with a connected tunnel never runs a clean teardown. The
helper dies without restoring the DNS it promoted, and the next boot depends on
the DNS custody sweep to repair the network settings. That works today, but it
turns the crash recovery path into the normal shutdown path.

### Observed

Two reboots on 2026-10-21, both with `wg-1ce3a4a1` (`andi_split`) connected.
Session agent log (`~/Library/Logs/wgd-session-agent.err.log`):

```
2026-10-21T10:01:14Z WARN session_agent_teardown_list_failed error=privileged daemon is managed by launchd (/Library/LaunchDaemons/me.pansen.wgd.privileged.plist) but its socket /Library/Application Support/wgd/run/ctl.sock is unavailable: Connection refused (os error 61); ...
2026-10-21T10:39:41Z WARN session_agent_teardown_list_failed error=... Connection refused (os error 61); ...
```

The second reboot, in more detail:

- Before shutdown the tunnel had been up since 10:32:57Z on a phone tether
  (`local_subnets=192.0.0.2/32`), so `Wi-Fi` carried the tunnel DNS
  `10.66.77.2, 100.64.1.1` and the custody record listed it.
- 10:39:41Z: the session agent receives SIGTERM at logout, calls
  `reconcile_disconnect_mine()`, and cannot reach the daemon.
- The privileged daemon log shows no `DisconnectConnection` and no helper
  shutdown before the reboot.
- 10:40:12Z: the daemon starts after boot; 10:40:13Z
  `privileged_dns_custody_restored interface="wg-1ce3a4a1" service="Wi-Fi"`,
  `restored=1`.
- `wgd status` afterwards: `DNS restored on Wi-Fi after wg-1ce3a4a1 (andi_split) exited without cleanup, 10:40 UTC`.
- 10:40:43Z: the session agent reconnects. The connect deletes
  `/var/log/wgd/wg-1ce3a4a1.log`, so the helper log of the killed session,
  which would show whether the helper ever saw a SIGTERM, is gone.

A third reboot on 2026-10-27 (shutdown around 15:37Z, next boot 15:41Z) logged
the same `session_agent_teardown_list_failed ... Connection refused (os error
61)` at 15:36:56Z. This time the launchd log of the shutdown was collected
(log times are local CET, written here as Z):

- 15:36:51.236Z `committing to system shutdown`. Within 2 ms the shutdown state
  machine goes BEGIN_SHUTDOWN, INVALIDATE_UNMANAGED_ENDPOINTS,
  BOOTOUT_SEMI_ACTIVE_SERVICES, BOOTOUT_ACTIVE_SERVICES.
- 15:36:51.243Z `[system:] removing active service: me.pansen.wgd.privileged`.
- 15:36:52.280Z `gui/503/com.apple.peopled` exited due to SIGKILL sent by
  launchd during system shutdown. Its plist sets `ExitTimeOut` 1
  (`launchctl print` shows `exit timeout = 1`), and the kill came about 1.04 s
  after shutdown began.
- 15:36:53Z `Generating shutdown stall report...`. The log ends there; there
  are no exit lines for the wgd jobs or the helper.
- 15:36:56Z the session agent logs `session_agent_teardown_list_failed`, one
  `autostart_timeout` (5 s) after the daemon was removed. So the agent got
  SIGTERM at about the moment the daemon went away.

The earlier report "DNS broken after reboot in the LAN" had the same shape:
a helper that died at shutdown with tunnel DNS still on `Wi-Fi`.

## What is known and what is not

Known:

- The session agent's teardown is the only component that disconnects at
  logout (`src/session_agent.rs`, `run()` -> `reconcile_disconnect_mine()`).
  It needs the privileged daemon, and at shutdown the daemon socket refuses
  connections. Since `7b2f73f` the client waits up to `autostart_timeout` (5s)
  for a launchd-managed socket and then gives up instead of sudo-autostarting;
  before that commit it tried a sudo autostart without a TTY and failed too, so
  this is not a regression.
- The privileged daemon installs no SIGTERM handler (see the comment in
  `cmd_uninstall`, `src/launchd.rs`). When launchd stops it, it does nothing
  for the tunnels it started.
- launchd uses 5 s when `ExitTimeOut` is missing, in the system and in the gui
  domain: `launchctl print` shows `exit timeout = 5` for the privileged daemon
  and for every Apple agent without the key (2026-10-27), while `man
  launchd.plist` only says "system-defined". For agents launchd caps the value
  at 60 s, as far as one job shows: the session agent plist used to set 120 and
  `launchctl print` showed 60. Neither plist sets `ExitTimeOut` now: a logout
  teardown that needs more than 5 s counts as broken, and the daemon finishes
  a disconnect it has already received on its own worker thread even if the
  agent is killed (`src/privileged/dispatch.rs`).
- At shutdown launchd boots out system daemons and gui agents in the same
  phase (BOOTOUT_ACTIVE_SERVICES, right at the start). The privileged daemon is
  removed at the moment the session agent gets SIGTERM, so the agent can never
  reach it at shutdown, whatever the timeouts. The session agent teardown
  therefore cannot work at shutdown by design; only a daemon that tears down on
  its own SIGTERM (item 3) can.
- The helper is daemonized (`daemonize`, own session) and handles SIGTERM and
  SIGINT in `wait_for_shutdown` (`src/userspace_helper/mod.rs`), followed by the
  normal network cleanup including DNS restore.

Not known:

- Whether launchd honours `ExitTimeOut` during system shutdown. Probably yes:
  `com.apple.peopled` (`ExitTimeOut` 1) was SIGKILLed about 1.04 s after the
  shutdown began. That is inferred from one job. The reboot test in item 2
  would confirm it for the daemon.
- The agent spends its full `autostart_timeout` waiting for a socket that
  cannot come back at shutdown. Whether that is what triggered launchd's
  shutdown stall report 2 s in is not known.
- Why the helper did not clean up even though it handles SIGTERM. Candidates:
  shutdown delivers SIGKILL before cleanup finishes (each `networksetup` call
  takes tens to hundreds of milliseconds); `configd` is already gone so
  `networksetup` fails; or the helper only ever sees SIGKILL. The helper log
  would answer this, but it is deleted on the next connect (see above).

## Proposed work

### 1. Keep the previous helper session log

Rotate `/var/log/wgd/<interface>.log` to `<interface>.log.1` instead of
deleting it when a connect starts a fresh session log
(`src/privileged/commands.rs`, the `remove_file` loop before spawning the
helper). This costs nothing and is needed to diagnose the rest of this issue.
The connect output streaming relies on the log only containing the current
session, which rotation preserves.

### 2. Find out what the helper sees at shutdown

With item 1 in place, reboot with a tunnel up and read
`<interface>.log.1`: is there a `userspace_helper_shutdown_requested
trigger="sigterm"`, and does `userspace_helper_network_cleanup_dns` or
`userspace_helper_network_cleanup_complete` follow? Collect the launchd log for
the same window to see the order in which the agent, the daemon and the helper
are signalled.

### 3. Make the privileged daemon tear down on SIGTERM

The daemon is the one component that knows every live tunnel and does not
depend on its own socket. On SIGTERM it should stop every helper it manages
(the same path as `DisconnectConnection` with the teardown reason, which does
not set `user_disconnected`) and wait for their cleanup, bounded by the plist's
`ExitTimeOut`. The daemon plist sets none on purpose, so the bound is
launchd's 5 s default: a teardown that needs longer counts as broken, and
anything it misses is repaired by the custody sweep at the next boot. The
handler must therefore stop all helpers in parallel, not one after another.
If `ExitTimeOut` is honoured at shutdown, those 5 s are all the time the
helpers get. Open questions:

- `wgd launchd uninstall` and `launchctl bootout` also send SIGTERM. Uninstall
  already disconnects everything before `bootout`; a plain `bootout` or
  `launchd restart` (`kickstart -k`) would now also drop every tunnel. Restart
  probably must not do that; it may need a way to tell "system is shutting
  down" from "job is being restarted".
- An idle daemon (on-demand, `idle_timeout_ms=60000`) is not running when
  shutdown starts. While a DNS-promoting tunnel is up the custody `watch`
  file keeps it alive via `KeepAlive`/`PathState`, so that case is covered;
  tunnels without DNS are not, but they also leave nothing persistent behind
  (routes and the utun die with the helper).

### 4. Fall back cleanly if the daemon is unreachable

If item 2 shows that the helper does receive SIGTERM and only lacks time,
shortening its cleanup to the DNS restore alone (routes vanish with the utun
anyway) may be enough. If it shows that the helper is SIGKILLed, the custody
sweep at boot stays the only repair, and this issue reduces to items 1 and 3.

At shutdown the daemon is always unreachable for the agent (see Known), so the
agent should not wait `autostart_timeout` on a refused launchd socket during
teardown. That is a candidate follow-up, not decided.

## Non-goals

- Fast user switching: the session agent does not get SIGTERM there either.
  That is a known gap documented in `src/session_agent.rs` and is separate
  from shutdown.
