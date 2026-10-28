# launchd socket activation for the privileged service

**Status:** implemented; the original proposal is in the git history.
**Scope:** macOS privileged control service (`wgd privileged --serve`), its
LaunchDaemon plist and how clients reach it

## Why

A root daemon that binds its own socket creates it as root and patches mode
and group afterwards. If that patch fails or races, the socket stays
root-only and no `wgd`-group client can connect after boot. With socket
activation launchd creates the socket from the plist before the process
starts and passes the listening fd in. It also makes the daemon on-demand:
launchd starts it on the first connect, and it exits again when idle.

## Socket contract

| Property | Value |
|---|---|
| Socket path | `/Library/Application Support/wgd/run/ctl.sock` (`config::privileged_socket_path()`) |
| Socket dir | `/Library/Application Support/wgd/run`, mode `0750`, group `wgd` |
| Socket file | mode `0660`, `root:wgd` |

The file permissions are the whole group gate. The daemon reads the caller's
uid with `getpeereid()` once per accepted socket and uses it for connection
ownership; the gid is only logged.

## The plist

`etc/me.pansen.wgd.privileged.plist`, rendered by `wgd launchd install`
(`src/launchd.rs`):

- `ProgramArguments`: `@WGD_BIN@ --debug privileged --serve --authorized-group
  wgd --autostarted --idle-timeout-ms 60000`. `@WGD_BIN@` is replaced with the
  trusted binary path, normally `/usr/local/bin/wgd`.
- `Sockets` → `Listeners`: `SockPathName` as above and `SockPathMode` `432`
  (0660 octal; plist `<integer>` is decimal). `SockPathGroup` needs an integer
  gid, which is not known when the plist is written, so the template carries a
  `@SOCK_PATH_GROUP@` marker comment that the installer replaces with
  `<key>SockPathGroup</key><integer>GID</integer>`.
- `RunAtLoad` `false`: launchd starts the daemon on the first connect.
- `KeepAlive` → `PathState` on `/Library/Application Support/wgd/dns-custody/watch`:
  while this sentinel exists, launchd keeps the daemon running, also at boot
  (see "DNS custody keeps the daemon resident").
- `EnvironmentVariables`: `PATH=/usr/bin:/bin:/usr/sbin:/sbin`, so nothing
  root runs is looked up in user-writable Homebrew directories, and
  `WGD_LOG_COLOR=always`.
- No `ExitTimeOut` (launchd's 5 s default; the daemon has no SIGTERM handler
  and exits at once) and no `ThrottleInterval` (launchd's default, about 10 s
  per `issues/dns-crash-recovery.md`).
- Logs: `/var/log/wgd/privileged.{out,err}.log`.

## Server startup (`privileged::serve`, `src/privileged/mod.rs`)

1. Register the authorization right (refuse to start on failure), ensure the
   directories, chown the socket dir to `wgd`.
2. `launch_activate_socket("Listeners")`: a launchd job gets its fd (extra fds
   are closed) and re-applies 0660 and the group in case the plist's gid is
   stale. A `sudo`-spawned daemon gets nothing and binds itself, after probing
   an existing socket file: a live listener means another daemon owns the
   path, so it refuses to start; a stale file is unlinked.
3. Start the DNS custody watch; on a background thread sweep DNS left by dead
   helpers and run `reconcile_boot()`.
4. Enter the accept loop.

## Idle exit

The daemon exits only with no clients, no background work, no DNS custody
residency, and either a shutdown request with no lease left or the idle
timeout (the plist's 60 s) passed since the last request. launchd starts it
again on the next connect.

## DNS custody keeps the daemon resident

On the `networksetup` DNS path a dead helper must be noticed, so the daemon
stays up while the sentinel `dns-custody/watch` exists (`KeepAlive`/`PathState`
also starts it at boot) and while it watches a helper (`resident`, re-checked
every 5 s). Details are in `doc/architecture.md`, "DNS crash recovery".
Connections on the dynamic store path write no custody record and keep the
daemon on-demand.

## How clients connect (`src/privileged_client/transport.rs`)

`connect_or_autostart()`:

- `PermissionDenied`: fail at once; the caller is probably not in `wgd` yet
  (log out and in after `wgd launchd install`).
- `NotFound`/`ConnectionRefused` while the LaunchDaemon plist exists: launchd
  owns socket and process, so the client only polls for up to
  `privileged_autostart_timeout_ms` (5 s) and then suggests `sudo wgd launchd
  restart`. It never starts a daemon via `sudo` here, because that one would
  unlink launchd's socket and take over the path.
- Without the plist (development): take a startup lock and start `sudo -n -b
  <exe> privileged --serve --autostarted ...`, unless `privileged_autostart =
  false`. The binary must be root-owned, so a Homebrew-prefix binary is never
  started as root.

`privileged_transport = stdio` runs `sudo -n <exe> privileged --serve --stdio`
per command instead of using the socket.

### Autostop modes

`privileged_autostop_mode` controls a daemon the client started via `sudo`:

| Mode | Behavior |
|---|---|
| `never` (default) | no idle timeout is passed; the daemon runs until stopped |
| `command` | the client takes a lease (`LeaseAcquire`/`LeaseRelease`) for the duration of a command and sends `ShutdownIfIdle` afterwards |
| `timeout` | the daemon gets `--idle-timeout-ms` from `privileged_autostop_timeout_ms` (default 30000) |

The launchd daemon ignores these and uses the plist's arguments.

## Install and lifecycle commands

- `sudo wgd launchd install`: copy the binary to a trusted path if needed,
  create the `wgd` group, register the authorization right, write the plist,
  `bootout`/`enable`/`bootstrap system/`, reap `sudo`-started daemons launchd
  does not track, wait up to 5 s for the socket (`bootstrap` returns before it
  is ready), reconnect the invoking user's `Automatic` connections.
- `sudo wgd launchd restart`: `launchctl kickstart -k system/me.pansen.wgd.privileged`.
- `sudo wgd launchd uninstall`: disconnect, drop the DNS sentinel (so launchd
  does not restart the daemon mid-`bootout`), boot out, remove the plist.
- `wgd launchd reload` (as your user): `launchd install` via `sudo`,
  disconnect your connections, reinstall the session agent.
- `wgd launchd purge`: `uninstall` plus the session agent, a DNS sweep, state,
  logs, the authorization right and the group.

## Checks

```bash
stat -f '%Sp %Su %Sg' "/Library/Application Support/wgd/run/ctl.sock"   # srw-rw---- root wgd
launchctl print system/me.pansen.wgd.privileged | grep -E 'state|exit timeout'
wgd launchd status
```

A user outside `wgd` gets `PermissionDenied` at connect.
