# tunmux

`tunmux` is a WireGuard config-file VPN CLI written in Rust for **macOS**. It
connects from a standard WireGuard `.conf` file (or a saved profile) and routes
host traffic through the tunnel (direct mode).

## What It Does

- Connect/disconnect from WireGuard `.conf` files and saved profiles
- Save, list, and remove reusable profiles
- Run connect/disconnect hooks (connectivity, external-IP, DNS-leak checks)
- Support multiple WireGuard backends: `userspace` (default), `wg-quick`, `kernel`

On macOS there is no in-kernel WireGuard, so every backend runs on the embedded
`gotatun` userspace engine through a built-in helper; no separate `gotatun` CLI
install is required. The `kernel` backend brings the tunnel up from a regenerated
minimal config, while `userspace`/`wg-quick` use the `.conf` as-is.

## Platform And Requirements

- macOS (Apple Silicon or Intel)
- Rust (stable, edition 2021)
- `sudo` access for privileged operations (`tunmux privileged --serve`)

The privileged service runs as root and performs the operations that need
elevated permissions (bringing tunnels up/down, reading the WireGuard control
socket). It can be started on demand (autostart) or via `launchd` socket
activation (see `etc/me.pansen.tunmux.privileged.plist`).

## Build

```bash
cargo build
```

## Release CI (Tag-Based)

Pushing a `v*` tag (for example `v1.2.3`) triggers `.github/workflows/release.yml` to:
- run `cargo test --locked`
- build release binaries for macOS targets via `.github/workflows/manual-build.yml`
- upload tarballs and SHA256 files to a GitHub Release for that tag

Binary version output follows the tag in CI builds:

```bash
tunmux --version
```

## Quick Start

Connect from a config file, check status, disconnect:

```bash
tunmux connect wgconf --file ./my-tunnel.conf
tunmux status
tunmux disconnect --provider wgconf
```

Choose a backend (default is `userspace`):

```bash
tunmux connect wgconf --file ./my-tunnel.conf --backend wg-quick
```

Before testing the userspace data plane, disable WireGuard.app On-Demand and
deactivate matching tunnels. Verify `scutil --nc list` has no connected
`com.wireguard.macos` entry.

## Command Map

Top-level commands:

```bash
tunmux status
tunmux connect wgconf [flags]
tunmux disconnect [instance] [--provider wgconf] [--all]
tunmux wg
tunmux hook run <connectivity|external-ip|dns-detection>
tunmux hook debug [instance] [--provider wgconf] [--event ifup|ifdown]
tunmux wgconf <...>
```

`wgconf` flows:

```bash
tunmux connect wgconf --file ./my-tunnel.conf --backend wg-quick
tunmux connect wgconf --file ./my-tunnel.conf --save-as office
tunmux connect wgconf --profile office
tunmux connect wgconf --file ./ipv4-only.conf --backend kernel --disable-ipv6
tunmux connect wgconf --file ./my-tunnel.conf --backend kernel --mtu 1280
tunmux wgconf save --file ./my-tunnel.conf --name backup
tunmux wgconf list
tunmux wgconf remove backup
tunmux wgconf status
tunmux disconnect --provider wgconf
```

Both the top-level form (`tunmux connect wgconf ...`) and the provider-prefixed
form (`tunmux wgconf connect ...`) are supported.

Disconnect semantics:

```bash
tunmux disconnect --all                     # all active connections
tunmux disconnect --provider wgconf --all   # wgconf only
tunmux disconnect <instance>                # exact instance
tunmux disconnect --provider wgconf         # provider-scoped single/list behavior

# short forms
tunmux disconnect -a
tunmux disconnect -p wgconf -a
```

Common short forms:
- `connect`: `-b` (backend)
- `disconnect`: `-p` (provider), `-a` (all)

Use verbose logs when needed:

```bash
tunmux -v connect wgconf --file ./my-tunnel.conf
tunmux --debug wgconf disconnect
RUST_LOG=debug tunmux disconnect --all
```

Force or disable ANSI color in logs:

```bash
TUNMUX_LOG_COLOR=always tunmux status
TUNMUX_LOG_COLOR=never tunmux status
```

## Flags

`--disable-ipv6` is accepted only for the `kernel` backend, and only when the
selected WireGuard config has no IPv6 interface address.

`--mtu` applies to the `kernel` and `userspace` backends. `wgconf` reads `MTU =`
from `[Interface]`; an explicit `--mtu` overrides it.

`--if-missing` exits `0` without reconnecting when the same source is already the
live tunnel; a different live source still errors.

## Direct Mode Details

- one direct connection is active at a time
- host traffic is routed through that WireGuard tunnel
- stored internally as `_direct` connection state
- routing and DNS adapt live to network changes (roam, suspend/resume) without a
  reconnect

## Configuration

`tunmux` reads optional defaults from:

`~/.config/tunmux/config.toml`

Example:

```toml
[general]
backend = "userspace"             # userspace (default), wg-quick, or kernel
hooks = { ifup = ["builtin:connectivity", "builtin:external-ip"], ifdown = [] }
privileged_transport = "socket"   # socket or stdio
privileged_autostart = true
privileged_autostart_timeout_ms = 5000
privileged_authorized_group = "tunmux"
privileged_autostop_mode = "never"      # never, command, timeout
privileged_autostop_timeout_ms = 30000

[wgconf]
hooks = { ifup = [], ifdown = [] }
```

CLI flags override config values.

Hook behavior:
- `general.hooks` runs first, then `wgconf` hooks run after it.
- `ifup` runs after successful connect; `ifdown` runs after successful disconnect.
- Built-ins are opt-in via hook entries:
  - `builtin:connectivity`: ping IPv4 (`1.1.1.1`) and IPv6 (`2606:4700:4700::1111`)
  - `builtin:external-ip`: fetch external IP via `https://ipinfo.io` and `https://v6.ipinfo.io`
  - `builtin:dns-detection`: query `https://<random>-<n>.ipleak.net/dnsdetection/`
    with a 40-char random host label and incrementing probe number (`-1` to `-10`),
    then run reverse DNS lookup for each recovered resolver IP
- Hook commands run with env vars such as `TUNMUX_HOOK_EVENT`, `TUNMUX_PROVIDER`,
  `TUNMUX_INSTANCE`, `TUNMUX_BACKEND`, `TUNMUX_INTERFACE`, `TUNMUX_SERVER`,
  `TUNMUX_ENDPOINT`, plus `TUNMUX_DNS_SERVERS` when VPN DNS servers are known.
- `dns-detection` reverse DNS lookup prefers VPN-configured DNS servers first.
- Manual builtin checks: `tunmux hook run connectivity`, `tunmux hook run external-ip`,
  or `tunmux hook run dns-detection`.
- Debug helper: `tunmux hook debug <instance>` prints the exact env payload used for hooks
  (`--event ifup|ifdown`, default `ifup`).

## Privileged Service

Privileged operations are handled by:

```bash
sudo tunmux privileged --serve --authorized-group <group>
```

Supported transports:
- `socket` (default): Unix socket control channel (`/Library/Application Support/tunmux/run/ctl.sock`)
- `stdio`: one-shot helper process over stdin/stdout

Autostart can launch the privileged service when needed (if enabled in config),
or `launchd` can socket-activate it via `etc/me.pansen.tunmux.privileged.plist`.

Example sudoers entries (adjust binary path for your install):

```bash
<user-or-group> ALL=(root) NOPASSWD: /usr/local/bin/tunmux privileged --serve --authorized-group tunmux
<user-or-group> ALL=(root) NOPASSWD: /usr/local/bin/tunmux privileged --serve --autostarted --authorized-group tunmux
<user-or-group> ALL=(root) NOPASSWD: /usr/local/bin/tunmux privileged --serve --autostarted --authorized-group tunmux --idle-timeout-ms *
```

For stdio mode:

```bash
<user-or-group> ALL=(root) NOPASSWD: /usr/local/bin/tunmux privileged --serve --stdio --autostarted --authorized-group tunmux
```

## Data Layout

User data under `~/.config/tunmux/`:

```text
~/.config/tunmux/
  config.toml
  connections/
    _direct.json
    <instance>.json
  wgconf/
    profiles/
      <name>.conf
```

Privileged runtime state:

```text
/Library/Application Support/tunmux/
  run/
    ctl.sock
  wg/
    <provider>/<iface>.conf

/var/log/tunmux/
  <iface>.log
```

## License

MIT

Copyright (c) 2026 Contributors to tunmux
