# Non-launchd daemon can take over the launchd control socket

**Status:** implemented (`self_bind_plan` in `src/privileged/mod.rs`, `launchd::daemon_installed`)
**Scope:** privileged daemon startup, self-bind path (`src/privileged/mod.rs`, `serve`, the `None` arm after `launchd_activated_listener()`)
**Related:** `7b2f73f` (client side of the same problem), `0065f7d` (introduced the stale-socket heuristic)

## Problem

A privileged daemon that was not started by launchd binds the control socket
itself. If the socket file already exists, it probes it and treats
`ECONNREFUSED` (or `ENOENT`) as "stale, left behind by a dead predecessor":
it unlinks the file and binds a new socket at the same path
(`src/privileged/mod.rs`, `if socket_path.exists()` in the self-bind arm).

On a launchd-managed install this heuristic is wrong in two situations, and in
both the ad hoc daemon replaces launchd's socket for good:

1. **During `launchd install`.** `launchctl bootout` closes launchd's
   listener but leaves the socket file on disk; `launchctl bootstrap` returns
   before launchd has recreated it. Measured on 2026-10-21 with a tight probe
   loop: `ECONNREFUSED` from `bootout` until about 400 ms after the install
   command returned, then `ENOENT` and `OK` within the same millisecond as
   launchd recreated the socket.
2. **Under load on a live daemon.** On macOS a Unix socket whose accept queue
   is full returns `ECONNREFUSED`, even with a running daemon behind it. The
   same probe loop showed `OK`/`ECONNREFUSED` alternating within one
   millisecond about 3 s after an install, same inode, no `ENOENT`.

A daemon that takes over the path this way:

- runs outside launchd, so `bootout`/`bootstrap` neither see nor stop it, and
  with the default `privileged_autostop_mode = Never` it runs until the next
  `launchd install` reaps it (`reap_stray_privileged_daemons`);
- leaves launchd's own listener orphaned, so socket activation no longer
  reaches the real job;
- if it was started from a non-root-owned binary (for example
  `/opt/homebrew/bin/wgd`), answers requests but refuses to spawn tunnel
  helpers (`self_executable_for_spawn`). That is exactly the incident of
  2026-10-21 09:32Z: `wgd launchd reload` autostarted such a daemon into the
  install window, and the session agent's `ConnectConnection` then failed with
  `untrusted privileged executable path /opt/homebrew/bin/wgd`.

## Current mitigation

The clients no longer create such daemons on a launchd install:

- `7b2f73f`: with the launchd plist present the client never sudo-autostarts;
  it retries the socket for `autostart_timeout` and then fails with a pointer
  to `launchd restart`. A sudo autostart from a binary that fails
  `validate_root_owned_path` is refused in every case.
- `launchd install` waits until launchd accepts on the socket before it
  returns (`wait_for_launchd_socket`), which closes the install window for the
  next command.

So today an ad hoc daemon on a launchd install only appears if someone starts
`wgd privileged --serve` by hand. The daemon side still accepts the takeover,
which makes the protection depend entirely on every client behaving.

## Proposal

In the self-bind arm, refuse to start when
`/Library/LaunchDaemons/me.pansen.wgd.privileged.plist` exists, regardless of
what the liveness probe returns:

```
privileged daemon is managed by launchd (<plist>); refusing to bind <socket> outside launchd.
Restart it with: sudo /usr/local/bin/wgd launchd restart
```

Keep the existing probe and stale-socket unlink for installs without the plist
(built from source and started by hand or by the client autostart). There it
remains the only way to recover from a crashed daemon, and the load case above
is an accepted risk.

Points to settle while implementing:

- **`--stdio` mode.** `wgd privileged --serve --stdio` never binds the socket
  and must keep working with the plist present.
- **The check itself.** Reuse one helper for "launchd manages the daemon" in
  both the client (`launchd_daemon_installed` in
  `src/privileged_client/transport.rs`) and the daemon, so the two cannot
  disagree about what counts as a launchd install.
- **Uninstall order.** `cmd_uninstall` removes the plist after `bootout`. A
  daemon started by hand between those two steps would still be refused; that
  is fine, the uninstall is in progress.
- **Tests.** The decision (plist present, activated or not, probe result) can
  be a pure function next to `launchd_activated_listener`, tested without
  touching the real socket path.
