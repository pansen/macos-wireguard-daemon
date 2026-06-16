# tunmux

`tunmux` is a WireGuard config-file VPN CLI written in Rust. It connects from a
standard WireGuard `.conf` file (or a saved profile) using several connectivity
modes.

Supported platforms:
- Linux: direct mode, `--proxy` mode, and `--local-proxy` mode
- macOS: direct mode and `--local-proxy` mode (`--proxy` is not available)

WireGuard connectivity modes:
- direct mode (system-wide routing)
- Linux namespace proxy mode (`--proxy`, isolated per-connection namespace)
- local-proxy mode (`--local-proxy`, userspace SOCKS5/HTTP proxy without root)

## What It Does

- Connect/disconnect from WireGuard `.conf` files and saved profiles
- Run multiple VPN exits side-by-side in proxy mode
- In proxy mode, keep host traffic unchanged unless an app explicitly uses a proxy
- Run rootless userspace local-proxy mode with `--local-proxy` (no `sudo` required)
- Support multiple WireGuard backends: `wg-quick`, `userspace`, `kernel`

## Platform And Requirements

- Rust (stable, edition 2021)
- Linux for full feature set (kernel backend + `--proxy` namespace isolation)
- macOS for direct mode and `--local-proxy` mode (`--proxy` is Linux-only)
- `sudo` access for privileged operations (`tunmux privileged --serve`) used by direct mode and `--proxy`

`userspace` mode uses the embedded `gotatun` library through a built-in helper; no separate `gotatun` CLI install is required.
`--local-proxy` uses that userspace engine to run a SOCKS5/HTTP proxy without root.

Optional:
- systemd socket activation via `systemd/tunmux-privileged.socket`

## Build

```bash
cargo build
```

## Release CI (Tag-Based)

Pushing a `v*` tag (for example `v1.2.3`) triggers `.github/workflows/release.yml` to:
- run `cargo test --locked`
- build release binaries for Linux and macOS targets via `.github/workflows/manual-build.yml`
- upload tarballs and SHA256 files to a GitHub Release for that tag

Publishing that GitHub Release then triggers `.github/workflows/docker.yml` (which calls `.github/workflows/docker-publish.yml`) to build and publish a multi-arch Docker image to GHCR.

Binary version output follows the tag in CI builds:

```bash
tunmux --version
```

Container tags:
- `ghcr.io/<owner>/tunmux:<tag>`
- `ghcr.io/<owner>/tunmux:latest` (only for non-prerelease tags)

## Quick Start

### 1) Connect from a config file (direct mode)

```bash
tunmux connect wgconf --file ./my-tunnel.conf --backend wg-quick
tunmux status
tunmux disconnect --provider wgconf
```

### 2) Start an isolated proxy exit (proxy mode, Linux)

```bash
# Userspace-isolated WireGuard exit with a local SOCKS5/HTTP proxy
tunmux connect wgconf --file ./my-tunnel.conf --proxy

# Use the proxy
curl --socks5 127.0.0.1:1080 https://api.ipify.org

# Host traffic remains unchanged unless using the proxy
curl https://api.ipify.org
```

### 3) Start local-proxy mode (no root)

```bash
# No sudo required; app traffic goes through SOCKS5/HTTP proxy
tunmux connect wgconf --file ./my-tunnel.conf --local-proxy

# Use the proxy from an app/tool
curl --socks5 127.0.0.1:1080 https://api.ipify.org

# Stop local-proxy instance(s)
tunmux disconnect --provider wgconf
```

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
tunmux connect wgconf --profile office --local-proxy
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

## Flags

`--disable-ipv6` is accepted only for direct kernel mode (no
`--proxy`/`--local-proxy`) and only when the selected WireGuard config has no
IPv6 interface address.

`--mtu` applies to direct kernel/userspace mode and kernel `--proxy`. `wgconf`
reads `MTU =` from `[Interface]`; an explicit `--mtu` overrides it. MTU is not
supported with `--local-proxy`, which does not create a host TUN interface.

`--if-missing` (direct mode) exits `0` without reconnecting when the same source
is already the live tunnel; a different live source still errors.

Before testing the macOS userspace data plane, disable WireGuard.app On-Demand
and deactivate matching tunnels. Verify `scutil --nc list` has no connected
`com.wireguard.macos` entry.

## Linux Namespace Proxy Mode (`--proxy`)

Each `--proxy` connection creates:
- a dedicated Linux network namespace
- a dedicated WireGuard interface in that namespace
- a local SOCKS5 and HTTP proxy bound on localhost

Multiple instances can run at once, each with different exits and ports.

## Local Proxy Mode (`--local-proxy`)

`--local-proxy` starts a userspace WireGuard tunnel and local SOCKS5/HTTP proxy without `sudo`.

- no root/privileged daemon required
- no host routing changes (only apps configured to use the proxy are tunneled)
- available on Linux and macOS
- supports multiple instances with auto-port behavior
- hostname resolution for proxy requests prefers the VPN-pushed DNS servers
- set `TUNMUX_LOCAL_PROXY_DNS_SERVERS` (or `TUNMUX_DNS_SERVERS`) to override local-proxy DNS resolver servers (comma or whitespace separated)

Port behavior:
- default scan starts at `1080` (SOCKS5) and `8118` (HTTP)
- each new instance picks the next available localhost ports
- override with `--socks-port` and `--http-port`

Instance naming is derived from the config source and used in status/disconnect commands.

## Direct Mode Details

Direct mode is the default when neither `--proxy` nor `--local-proxy` is used.
- one direct connection is active at a time
- host traffic is routed through that WireGuard tunnel
- stored internally as `_direct` connection state

Direct, `--proxy`, and `--local-proxy` sessions can coexist.

## Configuration

`tunmux` reads optional defaults from:

`~/.config/tunmux/config.toml`

Example:

```toml
[general]
backend = "kernel"                # default: kernel on unix (except macOS), userspace on macOS
proxy_access_log = false
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
  `TUNMUX_ENDPOINT`, plus optional proxy fields (`TUNMUX_NAMESPACE`, `TUNMUX_SOCKS_PORT`,
  `TUNMUX_HTTP_PORT`, `TUNMUX_PROXY_PID`).
- Hook env also includes `TUNMUX_DNS_SERVERS` when VPN DNS servers are known.
- When proxy ports are present, hook commands also receive standard proxy vars:
  `HTTP_PROXY`/`HTTPS_PROXY` and `ALL_PROXY` (plus lowercase variants).
- Builtin HTTP checks (`external-ip`, `dns-detection`, and proxy-mode `connectivity`) use
  the active connection proxy automatically when available.
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
- `socket` (default): Unix socket control channel (`/var/run/tunmux/ctl.sock`, typically `/run/tunmux/ctl.sock`)
- `stdio`: one-shot helper process over stdin/stdout

Autostart can launch the privileged service when needed (if enabled in config).

Example sudoers entries (adjust binary path for your install):

```bash
<user-or-group> ALL=(root) NOPASSWD: /usr/bin/tunmux privileged --serve --authorized-group tunmux
<user-or-group> ALL=(root) NOPASSWD: /usr/bin/tunmux privileged --serve --autostarted --authorized-group tunmux
<user-or-group> ALL=(root) NOPASSWD: /usr/bin/tunmux privileged --serve --autostarted --authorized-group tunmux --idle-timeout-ms *
```

For stdio mode:

```bash
<user-or-group> ALL=(root) NOPASSWD: /usr/bin/tunmux privileged --serve --stdio --autostarted --authorized-group tunmux
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

Runtime state (Linux):

```text
/var/run/tunmux/
  ctl.sock
  managed-pids/
    <pid>.start

/var/lib/tunmux/
  proxy/
    <instance>.pid
    <instance>.log
  wg/
    <provider>/<iface>.conf
```

Runtime state (macOS):

```text
/var/db/tunmux/
  proxy/
  wg/
```

## License

MIT

Copyright (c) 2026 Contributors to tunmux
