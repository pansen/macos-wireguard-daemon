# macOS WireGuard Daemon

`wgd` is a command-line WireGuard VPN client for macOS, written in Rust,
built around a privileged, multi-connection store.

## Why

Install once, forget about it.

Its flagship use case is a split tunnel that permanently connects your
workstation to "home" (your LAN, your servers, your internal DNS) as a launchd
daemon that is simply always there and never gets in the way. Add your config
once; from then on the tunnel comes up at login, survives network roaming and
sleep/wake, and continuously reconciles routes and DNS against whatever
network you are currently on.

Because reconciliation is continuous, the tunnel needs no On-Demand or
location-based triggers. It stays up everywhere and adapts. It is meant as a
dependable alternative to `WireGuard.app` from the App Store, for people who
would rather manage the tunnel from the command line, or not manage it at all.

Underneath is a general privileged connection store: you can add any number
of WireGuard configs, each independently connected, disconnected, and set to
come up automatically or stay manual.

## Origins

This project is a fork of [CaddyGlow/tunmux](https://github.com/CaddyGlow/tunmux).
Thanks to the original author, who pursued a different goal with the project;
it serves here as the technical base.

## Install

Via Homebrew (Apple Silicon only):

```bash
brew install --cask pansen/tap/macos-wireguard-daemon
```

If you installed `wgd` before the tap switched from a Formula to a Cask, run
`brew uninstall macos-wireguard-daemon` first: the old Formula's `bin/wgd`
collides with the Cask's binary symlink and the install fails until it's gone.

This installs `wgd` on your PATH and registers the privileged launchd
daemon, prompting for your password once (via `sudo`). `brew upgrade` prompts
again on every new release, to reinstall the daemon from the upgraded binary.

The release DMG is signed with a Developer ID certificate, notarized, and
stapled, so Gatekeeper accepts it without a quarantine workaround. Binaries
you build from source are not signed or notarized.

From source:

```bash
make install WGD_PROFILE=/path/to/your.conf CONNECTION_NAME=home
```

This builds the release binary into `/usr/local/bin/wgd`, runs
`wgd launchd reload` (see below), adds your config as a per-user connection
named `CONNECTION_NAME` (`--force --start-mode automatic`), connects it, and
installs bash completion. Re-running it after editing the config is safe: an
unmodified file is a no-op, a changed one replaces the old record.

Access to the privileged daemon is limited to a dedicated `wgd` group, which
the install creates and adds you to (a re-login may be needed for the
membership to take effect).

Upgrading from a pre-connection-store install (the old `wgconf`/`autoconnect`
design): there is no automatic migration; run `connection add` once per
existing config.

### Shell completion

```bash
wgd completion install [--shell bash|zsh|fish]   # default: bash
```

Writes a block between `# begin: wgd managed` and `# end: wgd managed` markers
into `~/.bashrc`, `~/.zshrc` or `~/.config/fish/config.fish`. Running it again
updates the block in place, and symlinked dotfiles are kept.

### Reload and restart

A macOS update can leave the launchd services booted out or disabled. To put
both back and reconnect, run as your normal user:

```bash
wgd launchd reload     # make reload does the same
```

It re-registers the privileged daemon (escalating via `sudo` for that step),
disconnects your connected connections, and reinstalls the session agent,
which then reconnects your automatic connections. It logs at debug level by
default; `-s` keeps only the step headers.

`sudo wgd launchd restart` only restarts the daemon with its existing
registration. It leaves the session agent alone and does not reconnect
anything.

### Uninstall

`make uninstall` (or `sudo /usr/local/bin/wgd launchd uninstall` plus
`wgd launchd agent uninstall`) stops the daemon and session agent. Run
`wgd dns repair` afterwards if a helper was killed and left tunnel DNS behind.
Stored connections stay.

`wgd launchd purge` removes everything else except the binary: it unregisters
both services, restores DNS, and deletes the state directory (including the
connection store), the logs, the authorization right, and the `wgd` group. It
also lists session-agent plists that other users still have in their home
directories. `brew uninstall --zap macos-wireguard-daemon` runs it and then
removes the binary; `make purge` does the same for a source install.

## Connections

Every WireGuard config `wgd` knows about is a **connection**: parsed and
fingerprinted at add time, then stored by the privileged daemon under an
opaque id (you can also refer to it by the name you gave it). Two kinds:

- Global connections are system-wide and root-owned; every operation on one
  requires root. If set to automatic, a global connection comes up the next
  time anything wakes the privileged daemon after a reboot (your login
  session agent, or a plain `wgd status`), not immediately at boot: the
  daemon itself is socket-activated on demand, not a boot-time service.
- Per-user connections only live inside your session and don't need `sudo`
  for their owner to use. If set to automatic, the session agent brings them
  up at login and tears them down at logout (not on fast user switching to a
  different session; that case isn't handled yet).

```bash
wgd connection add --file <path> [--global] [--name <label>] [--mtu <n>] [--start-mode manual|automatic] [--force]
wgd connection list [--global | --all]   # alias: ls
wgd connection get <id-or-name>
wgd connection connect <id-or-name> [--gotatun-debug]
wgd connection disconnect <id-or-name> | -a/--all
wgd connection mode <id-or-name> <manual|automatic>
wgd connection remove <id-or-name>
wgd launchd agent {install,status,uninstall}
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

## Troubleshooting

```bash
wgd status [--dns]                 # connections, wg show, routes, DNS custody notes
wgd launchd status                 # daemon state, socket permissions, group, helper pids
wgd logs [-f] [-n N] [--launchd] [--all] [<connection>]
wgd doctor [--report <file>]       # status, launchd status and logs in one report
wgd dns repair                     # restore DNS a killed helper left behind
```

`wgd status --dns` adds the live DNS servers of every network service. A
healthy system shows no tunnel DNS unless a tunnel is up.

`wgd launchd status`, `wgd logs`, `wgd doctor` and `wgd dns repair` need root
and ask for your password through `sudo` themselves; run them as your normal
user. They do not query the daemon: connecting to its socket would start it
and hide the very state you want to see.

`wgd logs` prints the last 150 lines (`-n`) of `/var/log/wgd/*.log`: the
daemon's `privileged.{out,err}.log` and one `<interface>.log` per connection
helper. Pass a connection name, id or interface (`wg-1ce3a4a1`) to filter.
Logs of connections untouched for 24 hours are skipped unless you pass
`--all`. `--launchd` shows what launchd logged about wgd in the last 10
minutes, which is where a daemon that fails to start shows up. `-f` follows.

`wgd doctor` runs the status, launchd status and log sections in a fixed order, then pings the DNS
servers and endpoints of your connected connections and 1.1.1.1 as an
internet control. A peer endpoint that does not answer ping is only
informational, since many drop ICMP. If you decline `sudo`, the sections that
need root say `skipped (needs sudo)` and the rest still runs.

To file a bug report, attach the output of:

```bash
wgd doctor --report wgd-report.txt
```

The file is created with mode 0600 and refuses to overwrite an existing one.
It is redacted: private and preshared keys are removed, public IPs keep only
their first and last octet, public keys and hostnames keep only their ends.
Private and tunnel address ranges stay readable so routes and DNS can still
be debugged. The terminal output is not redacted. Read the report before you
post it; hostnames on an uncommon TLD are only masked when they follow
`endpoint`.

## How it works

macOS has no in-kernel WireGuard. Every connection therefore runs on a
bundled userspace WireGuard engine, [gotatun](https://github.com/mullvad/gotatun),
through a built-in helper, so there is nothing extra to install.

`wgd` is split into two parts. The command you run as your normal user
handles configuration and status. The privileged daemon, running as root,
owns the connection store and does only what needs elevated permissions:
bringing tunnels up and down and talking to the WireGuard control interface.
Its subprocesses run under a restricted PATH and resolve to fixed absolute
system paths, and the daemon refuses to install from a symlinked or
non-root-owned location.

For the level below this one, how the CLI, the daemon, and the per-tunnel
helper actually talk to each other, see [doc/architecture.md](doc/architecture.md).

## Configuration

`wgd` reads optional defaults from `$XDG_CONFIG_HOME/wgd/config.toml`
(typically `~/.config/wgd/config.toml`), under a `[general]` table. The
file is optional; without it, sensible defaults apply. It covers the
privileged daemon's transport (socket or stdio), its autostart/autostop
behavior, and the group used for socket permissions. It has nothing to do
with connections themselves, which live entirely in the privileged store and
are managed through `wgd connection`.

## Running alongside the WireGuard app

Do not run `wgd` at the same time as the official WireGuard app with
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

The Makefile is for development only and just calls `wgd`; diagnostics and
cleanup live in the binary so Homebrew installs have them too. `make check`
writes a `wgd doctor` report to `target/`.

## License

MIT

Copyright (c) 2026 Contributors to macOS WireGuard Daemon
