# tunmux

`tunmux` is a command-line WireGuard VPN client for macOS, written in Rust,
built around a privileged, multi-connection store.

## Why

Install once, forget about it.

tunmux's flagship use case is a split tunnel that permanently connects your
workstation to "home" (your LAN, your servers, your internal DNS) as a launchd
daemon that is simply always there and never gets in the way. Add your config
once; from then on the tunnel comes up at login, survives network roaming and
sleep/wake, and continuously reconciles routes and DNS against whatever
network you are currently on.

Because reconciliation is continuous, the tunnel does not need the conditional
on/off triggers ("On-Demand" rules, location-based activation) that split
tunnels usually require. It stays up everywhere and adapts instead of asking.
It is meant as a frictionless, dependable alternative to `WireGuard.app` from
the Apple App Store, for people who would rather manage the tunnel from the
command line, or not manage it at all.

Underneath that flagship case is a general privileged connection store: you
can add any number of WireGuard configs, each independently connected,
disconnected, and set to come up automatically or stay manual.

## Origins

This project is a fork of [CaddyGlow/tunmux](https://github.com/CaddyGlow/tunmux).
Thanks to the original author, who pursued a different goal with the project;
it serves here as the technical base.

## Install

```bash
make install TUNMUX_PROFILE=/path/to/your.conf CONNECTION_NAME=home
```

This does, in order:

- Builds the release binary and installs it to `/usr/local/bin/tunmux`.
- Runs `tunmux reload` (see below), which registers the privileged launchd
  daemon, disconnects anything already connected under your account, and
  installs the per-user session agent.
- Adds your config as a per-user connection named `CONNECTION_NAME` with
  `--force --start-mode automatic`, then connects it.

Re-running `make install` after editing the config file is safe: an
unmodified file is a silent no-op, and a changed one replaces the old
`CONNECTION_NAME` record instead of piling up a duplicate.

Access to the privileged daemon is limited to a dedicated `tunmux` group,
which the install creates and adds you to (a re-login may be needed for the
membership to take effect).

`make uninstall` stops the daemon and session agent and clears any DNS
override; it leaves stored connection records in place. `make purge` also
removes the daemon's state directory (including the store), the binary, and
the `tunmux` group.

Upgrading from a pre-connection-store tunmux (the old `wgconf`/`autoconnect`
design): there is no automatic migration of the old profile or state files;
run `connection add` once per existing config after upgrading.

A macOS update can leave the launchd services booted out or disabled. To put
both of them back and reconnect, run:

```bash
tunmux reload
```

It re-registers the privileged daemon (escalating via `sudo` for that one
step), disconnects every one of your currently-connected connections, and
reinstalls the session agent, which then reconnects whatever automatic
connections are stored for you. `make reload` is the same command.

Unlike the rest of the CLI, `reload` logs its own steps at debug level by
default; `tunmux reload -s` keeps only the step headers. The daemon's own
output goes to `/var/log/tunmux/privileged.{out,err}.log`, and each
connection's helper logs to `/var/log/tunmux/<interface>.log` (`tunmux
connection get <id>` prints the interface name).

## Connections

Every WireGuard config tunmux knows about is a **connection**: parsed and
fingerprinted at add time, then stored by the privileged daemon under an
opaque id (you can also refer to it by the name you gave it). Two kinds:

- Global connections are system-wide and root-owned; every operation on one
  requires root. If set to automatic, a global connection comes up the next
  time anything wakes the privileged daemon after a reboot (your login
  session agent, or a plain `tunmux status`), not immediately at boot: the
  daemon itself is socket-activated on demand, not a boot-time service.
- Per-user connections only live inside your session and don't need `sudo`
  for their owner to use. If set to automatic, the session agent brings them
  up at login and tears them down at logout (not on fast user switching to a
  different session; that case isn't handled yet).

```bash
tunmux connection add --file <path> [--global] [--name <label>] [--mtu <n>] [--start-mode manual|automatic] [--force]
tunmux connection list [--global | --all]   # alias: ls
tunmux connection get <id-or-name>
tunmux connection connect <id-or-name> [--gotatun-debug]
tunmux connection disconnect <id-or-name> | -a/--all
tunmux connection mode <id-or-name> <manual|automatic>
tunmux connection remove <id-or-name>
tunmux connection agent {install,status,uninstall}
```

Adding or removing a connection, and elevating a global connection's mode
from manual to automatic, each require real macOS admin authentication
(password or Touch ID): those are the only operations that let new
root-executed config content into the store, or make it run unattended at
every future boot. That content can include `PreUp`/`PostUp`/`PreDown`/
`PostDown` hooks from the `.conf`, which run as root on every connect and
disconnect. Connecting, disconnecting, or downgrading a connection you
already added only requires being its owner (or root for a global one), the
same way the macOS Network pane asks for admin credentials to add a VPN
profile but not to connect one that's already configured.

`--mtu` only applies at `add` time; changing it means re-adding the
connection (`--force` to replace a same-named record instead of creating a
second one).

## What it does while you forget about it

- Keeps each connected tunnel up across network roaming (Wi-Fi to Ethernet,
  Wi-Fi A to Wi-Fi B) and sleep/wake, without a manual reconnect.
- Continuously reconciles **routes** against the live network: tunnel routes
  that would hijack the currently active LAN are dropped, so a split tunnel
  behaves correctly whether you are at home, in the office, or tethered.
- Reconciles **DNS** as well as it can, so lookups for your internal names
  keep resolving through the tunnel as the network underneath changes.

## How it works

macOS has no in-kernel WireGuard. Every connection therefore runs on a
bundled userspace WireGuard engine, [gotatun](https://github.com/mullvad/gotatun),
through a built-in helper, so there is nothing extra to install.

tunmux is split into two parts. The command you run as your normal user
handles configuration and status. The privileged daemon, running as root,
owns the connection store and performs the operations that need elevated
permissions: bringing tunnels up and down, and talking to the WireGuard
control interface. Running a root service is a real privilege boundary, so
it is kept small and does only the operations that require it. Its
subprocesses run under a restricted PATH and resolve to a fixed set of
absolute system paths rather than searching for a tool by name; the daemon
itself refuses to install from a symlinked or non-root-owned location.

For the level below this one, how the CLI, the daemon, and the per-tunnel
helper actually talk to each other, see [doc/architecture.md](doc/architecture.md).

## Configuration

tunmux reads optional defaults from `$XDG_CONFIG_HOME/tunmux/config.toml`
(typically `~/.config/tunmux/config.toml`), under a `[general]` table. The
file is optional; without it, sensible defaults apply. It covers the
privileged daemon's transport (socket or stdio), its autostart/autostop
behavior, and the group used for socket permissions. It has nothing to do
with connections themselves, which live entirely in the privileged store and
are managed through `tunmux connection`.

## Running alongside the WireGuard app

Do not run tunmux at the same time as the official WireGuard app with
On-Demand enabled for the same tunnel. The two will compete over the
connection. Turn off On-Demand and deactivate matching tunnels in the app
first.

## Requirements

- macOS on Apple Silicon.
- A stable Rust toolchain to build from source.
- `sudo` access for the install and privileged operations.

## Building

```bash
cargo build
```

## Development

The repository includes git hooks that check formatting before each commit.
Enable them once per clone:

```bash
make hooks
```

## License

MIT

Copyright (c) 2026 Contributors to tunmux
