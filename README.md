# tunmux

`tunmux` is a command-line WireGuard VPN client for macOS, written in Rust.

## Why

Install once, forget about it.

tunmux is built for one main use case: a split tunnel that permanently connects
your workstation to "home" — your LAN, your servers, your internal DNS — as a
launchd daemon that is simply always there and never gets in the way. You run
`make install` once; from then on the tunnel comes up at login, survives
network roaming and sleep/wake, and continuously reconciles routes and DNS
against whatever network you are currently on.

Because reconciliation is continuous, the tunnel does not need the conditional
on/off triggers ("On-Demand" rules, location-based activation) that split
tunnels usually require. It stays up everywhere and adapts instead of asking.
It is meant as a frictionless, dependable alternative to `WireGuard.app` from
the Apple App Store, for people who would rather manage the tunnel from the
command line — or not manage it at all.

## Origins

This project is a fork of [CaddyGlow/tunmux](https://github.com/CaddyGlow/tunmux).
Thanks to the original author, who pursued a different goal with the project —
it serves here as the technical base.

## Install

```bash
make install TUNMUX_PROFILE=/path/to/your.conf
```

This does three things:

- Builds the release binary and installs it to `/usr/local/bin/tunmux`.
- Registers a **privileged launchd daemon** (socket-activated, runs as root)
  that performs the operations needing elevation: bringing tunnels up and
  down and talking to the WireGuard control interface. It starts on demand
  and idles otherwise.
- Registers a **per-user login agent** that connects your profile at login
  and re-checks every 60 seconds. The connect is idempotent: if the tunnel
  is already up it is a no-op, if it dropped it is brought back.

Access to the privileged daemon is limited to a dedicated `tunmux` group,
which the install creates and adds you to (a re-login may be needed for the
membership to take effect).

After that there is nothing to babysit. `make uninstall` removes everything
cleanly, including any DNS override.

## What It Does While You Forget About It

- Keeps the tunnel connected across network roaming (Wi-Fi → Ethernet,
  Wi-Fi A → Wi-Fi B) and sleep/wake, without a manual reconnect.
- Continuously reconciles **routes** against the live network: tunnel routes
  that would hijack the currently active LAN are dropped, so the split tunnel
  behaves correctly whether you are at home, in the office, or tethered.
- Reconciles **DNS** as well as it can, so lookups for your internal names
  keep resolving through the tunnel as the network underneath changes.
- Can confirm that a connection is doing its job: basic connectivity over
  IPv4 and IPv6, traffic actually leaving through the tunnel, and DNS not
  leaking to other resolvers.

## How It Works

macOS has no in-kernel WireGuard. Every backend therefore runs on a bundled
userspace WireGuard engine, [gotatun](https://github.com/mullvad/gotatun),
through a built-in helper, so there is nothing extra to install.

tunmux is split into two parts. The command you run as your normal user handles
configuration and status. The separate privileged daemon, running as root,
performs the operations that need elevated permissions. Running a root service
is a real privilege boundary, so it is kept small and does only the operations
that require it.

Only one connection is active at a time. While it is up, routing and DNS
follow the current network.

## Backends

There are three ways to bring the tunnel up:

- `userspace` (default) and `wg-quick` use your config as written.
- `kernel` brings the tunnel up from a regenerated minimal config.

All three run on the same embedded userspace engine; the backend only changes
how the tunnel is set up.

## Configuration

tunmux reads optional defaults from `$XDG_CONFIG_HOME/tunmux/config.toml` (typically `~/.config/tunmux/config.toml`). The file is optional; without it, sensible defaults apply. It covers the default backend, the optional checks, and how the privileged daemon is started and stopped. Anything set in the config can be overridden per command on the command line.

## Running Alongside the WireGuard App

Do not run tunmux at the same time as the official WireGuard app with On-Demand
enabled for the same tunnel. The two will compete over the connection. Turn off
On-Demand and deactivate matching tunnels in the app first.

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
