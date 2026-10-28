# Tunnel DNS through the SystemConfiguration dynamic store

**Status:** draft spec; the mechanism is verified in configd sources and in
other tools, and Verification 1 to 5 passed on macOS 27.2 (see
"Verification"). Rolled
out in phases, starting with an inert shadow key next to today's
`networksetup` path (see "Rollout")
**Scope:** macOS userspace helper DNS (`src/userspace_helper/macos/dns.rs`,
`dns_plan.rs`, `src/macos_dns.rs`), DNS custody and sweep
(`src/dns_custody.rs`, `src/privileged/dns_sweep.rs`, `dns_watch.rs`), status
(`src/status_model.rs`)
**Related:** `issues/dns-ownership-edge-cases.md` (this is A3, B3 and C3 there),
`issues/dns-crash-recovery.md`, `issues/shutdown-teardown.md`,
`doc/dns-custody-late-record-watch.md`

Line numbers and behaviour of the current code are as of `1c0202c`. Facts about
macOS are marked *verified* (with the source) or *unverified*.

## Problem

The helper promotes tunnel DNS with `networksetup -setdnsservers` and
`-setsearchdomains` on the primary network service (`DnsPolicy::PrimaryOnly`,
`src/userspace_helper/macos/dns_plan.rs:18`; `set_dns_servers`,
`src/macos_dns.rs:100`). These are the user's persistent `Setup:` preferences.
Everything that is hard about DNS in wgd follows from that:

- A helper that dies without cleanup (SIGKILL at shutdown, panic, power loss)
  leaves tunnel DNS on the service across reboots. Repairing it takes a
  write-ahead custody record per connection, a daemon sweep at boot and at
  helper exit, a kqueue exit watch, a launchd `KeepAlive`/`PathState` sentinel
  and `wgd dns repair` (`issues/dns-crash-recovery.md`).
- The helper must capture the "original" DNS of the service, and cannot see
  DHCP resolvers through `networksetup`, so a restore can only return the
  service to "Empty" (`capture_macos_dns_service`,
  `src/userspace_helper/macos/dns.rs:182`).
- DHCP renewals, user edits, primary-service changes and network locations make
  the override drift, which is what the 3 s polling reconciler exists for
  (`macos_reconcile_dns`, `dns.rs:205`; `MACOS_RECONCILE_INTERVAL`,
  `src/userspace_helper/mod.rs:84`).
- Two tunnels that promote DNS fight over the primary service and capture each
  other's tunnel DNS as "original" (Finding A in
  `issues/dns-ownership-edge-cases.md`; the single-owner guard A1 is not
  implemented).

## Proposal

Publish each tunnel's resolver as its own synthetic, State-only service in the
SystemConfiguration dynamic store, held by a session that dies with the
helper. Never touch the physical services' DNS again.

```
State:/Network/Service/<tunnel-service-id>/DNS
  ServerAddresses          = [<DNS = entries of the config>]
  SupplementalMatchDomains = [""]
  SearchOrder              = <see "Ordering">
```

No `IPv4` entity, no `Router`, no `OverridePrimary`. `<tunnel-service-id>` is a
UUID derived deterministically from the connection id, so a key can always be
attributed to its connection and removed by anyone who knows the id.

This is the target shape. During the shadow phase the key carries a probe
match domain instead of `""` and does not affect any real query (see
"Rollout").

### Why this shape

- **configd keeps `State:` in memory only.** *Verified*: `storeData` is a
  `CFMutableDictionary` built in `__SCDynamicStoreInit`
  (`configd.tproj/_SCD.c`, apple-oss-distributions/configd). Nothing survives
  a reboot, so the boot-time repair disappears by construction.
- **Session keys die with the process.** *Verified*: `SCDynamicStore.h`
  documents `kSCDynamicStoreUseSessionKeys` ("all keys added or set ... should
  be per-session keys") and `SCDynamicStoreAddTemporaryValue` ("removed
  automatically when the session is closed"). configd closes the session on
  `DISPATCH_MACH_NO_SENDERS` and removes its session keys
  (`configd_server.c`, `_configclose.c`); that this fires on SIGKILL of the
  owner is inferred from the dead mach port, not tested.
- **A State-only service is merged into the resolver configuration.**
  *Verified* in `Plugins/IPMonitor/ip_plugin.c` (`get_dns_changes`): services
  without `Setup:` content are processed, and a DNS dict without an IPv4
  entity is kept if it has `SupplementalMatchDomains`.
- **`""` as match domain makes a domain-less resolver.** *Verified* in
  `dns-configuration.c` (`add_supplemental` drops `DomainName` for `""`) and
  `ip_plugin.c` (`ALLOW_EMPTY_STRING` for `SupplementalMatchDomains`). Tailscale
  uses exactly this for tailscaled's global DNS on macOS
  (`net/dns/manager_darwin.go`, key
  `State:/Network/Service/FF457792-79C0-4A25-8392-D875BBEACCA6/DNS`,
  `SearchOrder 100000`, `SupplementalMatchDomains ""`, published and removed
  via `scutil`). wireguard-apple does the equivalent through NetworkExtension
  with `NEDNSSettings.matchDomains = [""]`.
- **No routing side effects.** *Verified* in `ip_plugin.c`: without an IPv4
  entity (and without `Router`) IPMonitor installs no default route for the
  service, and `OverridePrimary` only takes effect together with `Router`.
  wgd keeps managing its own routes (`0/1` + `128/1`,
  `src/userspace_helper/macos/routes.rs:19`).
- **No collision with DHCP or the user.** DHCP writes
  `State:/Network/Service/<physical-id>/DNS` (*verified* on this machine: the
  Wi-Fi service carries `10.66.77.2` there while `Setup:` has no DNS key), and
  manual DNS lives in `Setup:` of the same id, which wins over `State:` for that
  id (*verified*, `merge_dns_servers` in `ip_plugin.c`). Writing either of those
  is what Tunnelblick and Mullvad do, with backups and monitors. A separate id
  touches neither.

### Rejected alternatives

- **Overwrite the physical service's `State:` DNS** (Mullvad `talpid-dns`,
  Tunnelblick): races with DHCP, loses against manual `Setup:` DNS, and needs
  backups again.
- **`OverridePrimary` with an IPv4 entity** (vpnc-script): makes IPMonitor
  install a default route via the utun and reorder the other services' routes,
  which fights wgd's route management.
- **`/etc/resolver/<domain>` files** (tailscaled split DNS): files survive
  crashes and reboots, so the custody problem stays, and they cannot express a
  default resolver (*verified*, `man 5 resolver`; Tailscale's commit says so).

## Design

### Who holds the session

The helper. It already lives exactly as long as the tunnel
(`src/userspace_helper/mod.rs`, `wait_for_shutdown`), runs as root (required:
non-root writes fail with "Permission denied", *verified* on macOS 27.2) and is
where DNS is applied today. The privileged daemon is on-demand and idle-exits,
so it cannot own a key for the life of a tunnel.

Session creation: `SCDynamicStoreCreateWithOptions` with
`kSCDynamicStoreUseSessionKeys = true`, so every `set` creates a session key.
Two traps in `configd.tproj/_configset.c` (*verified*):

- On a session-keys store, `set` on an existing key that another session owns
  fails with `kSCStatusKeyExists`. Before the first publish, the helper removes
  the key through a plain (non-session) store.
- A plain `set` from a non-session store on a session key strips session
  ownership and makes it permanent. Nothing but the owning helper may write
  the key; diagnostics only read.

### Lifecycle

| Event | Action |
|---|---|
| Connect, after routes are up | remove a stale key for this id, then publish |
| Collision (a tunnel DNS server is inside a directly connected LAN subnet, `macos_dns_server_in_local_subnet`, `dns_plan.rs:76`) | remove the key; publish again when the collision clears |
| Teardown, before routes go | remove the key |
| Helper dies (any signal) | configd removes the session key |
| configd restarts | all `State:` is gone; the helper notices (see below) and republishes |
| Reboot | nothing to do |

The collision rule stays because it is about reachability, not about who owns
the setting: if the tunnel resolver sits inside the LAN, wgd drops its route
(`routes.rs:107-116`) and the query would go to the LAN host of that address.
Withdrawing a key is cheap and needs no capture/restore.

A primary-service change, DHCP renewal, user DNS edit, service appearing or
vanishing and network location switch need no reaction at all: none of them
touches the tunnel's key. `DnsDecision::Hold` (no primary) disappears with
them.

### Watching the own key

A small notification watch replaces the 3 s DNS reconcile tick:
`SCDynamicStoreSetNotificationKeys` on the tunnel's own key, with a run loop
source on a dedicated thread (the helper's tokio runtime is single-threaded,
`src/userspace_helper/mod.rs:219`; blocking SC calls go through
`spawn_blocking` like today). If the key disappears or changes while the
tunnel is up and no collision is active, republish and log
`userspace_helper_dns_key_restored`. The collision check stays on the existing
route/subnet reconcile tick, which already reads the connected subnets.

### Ordering

`scutil --dns` sorts resolvers by `SearchOrder`. The default resolver's order is
unverified; the research inferred 200000 from the mDNS resolvers' `300000`.
Tailscale uses 100000 for its domain-less resolver, which suggests it sorts
ahead of the default. That the tunnel resolver actually answers every query
ahead of the LAN resolver is **unverified** and is the central check of the
spike.

Several tunnels with full DNS publish several domain-less resolvers.
`compareDomain` treats domain-less resolvers as equal, so `SearchOrder` must
differ to make the outcome deterministic. Proposal: the most recently
connected tunnel wins, using `SearchOrder = 100000 - n`, where `n` is a
monotonic connect counter kept by the daemon and passed to the helper
(bounded, e.g. modulo 1000). Each tunnel still only ever touches its own key,
so the capture chain and same-DNS wipe of Finding A cannot happen. Whether the
losing tunnel's resolver is used as a fallback on timeouts is unverified.

### Search domains

Today the helper clears the primary service's search domains
(`set_search_domains_empty`, `src/macos_dns.rs:120`) and restores them later.
With a synthetic service the physical service's search domains stay in place,
and whether a domain-less supplemental resolver's (empty) `SearchDomains`
replaces, extends or ignores the global search list is **unverified**.

Proposal: publish no `SearchDomains` in the first version and accept that the
LAN's search domains stay active (a short name may be tried as
`name.pansen.lan` through the tunnel resolver). `DNS =` accepts IP addresses
only today (`src/wireguard/connection_config.rs:346-351`); accepting domain
names there as search domains, as wg-quick does, is a separate change.

### Split DNS (not in the first version)

The same key with real match domains (`SupplementalMatchDomains =
["corp.example"]`, plus `SupplementalMatchOrders` of the same length; a length
mismatch drops the resolver, *verified* in `dns-configuration.c`) gives split
DNS with the same crash behaviour. It needs a config syntax wgd does not have.
Recorded here because the key layout must not preclude it: one key per
connection, match domains as data.

### Access from Rust

`Cargo.toml` has no SystemConfiguration binding today. Options:

1. **`system-configuration`** (maintained by Mullvad, used by
   `talpid-dns`; the shadow phase uses 0.7 with `core-foundation` 0.9): `SCDynamicStoreBuilder::new(..).session_keys(true)`, `set`,
   `remove`, `set_notification_keys`, `create_run_loop_source` (*verified* on
   docs.rs). Pulls in `core-foundation`. `AddTemporaryValue` is only in
   `system-configuration-sys`, but `session_keys(true)` gives the same
   lifetime.
2. **A `scutil` co-process per helper**: `scutil` started through
   `trusted_exec`, fed `open temporary` and `d.init`/`d.add`/`set` over stdin
   and kept running. If the helper is killed, the pipe closes, `scutil` exits
   and its session keys vanish. No new dependency, but a text protocol without
   reliable error reporting and an extra process per tunnel.

Recommendation: option 2 for the manual spike (a few lines of shell), option 1
from the shadow phase on. The shadow code runs in production and stays as the
implementation, and its logs need the error codes that the `scutil` text
protocol does not report. The crate does not expose `SCError()`; the helper
declares it itself to log `sc_status` on failures.

### Status and diagnostics

`TunnelDnsState` and `DnsServiceStatus` (`src/status_model.rs`) shrink to
"published", "withdrawn (LAN collision)" and "failed". `wgd status` reads the
tunnel's key and the effective resolver order from `scutil --dns` instead of
per-service `networksetup` output. The menu bar (`src/menu_bar.rs`) keeps its
"DNS held/pulled back" wording mapped onto the new states.

## Migration

Migration starts once the dynamic store becomes the default (Rollout phase 3).
Until then the `networksetup` path and its custody machinery stay unchanged.

Machines that ran an older build may still carry tunnel DNS in `Setup:`, with
custody records describing it. The daemon's custody sweep keeps running for a
transition period, restricted to records that already exist: no new records
are written, and once `dns-custody/` is empty the sentinel and the directory
go away. After one or two releases, remove the sweep, the watch, the sentinel
`PathState` in `etc/me.pansen.wgd.privileged.plist`, `wgd dns repair` and the
purge sweep.

`ClearStray` (a service still carrying a dead stored connection's DNS) stays
until then as the only way to heal settings from builds before custody records
existed.

## What goes away

Once the migration window closes:

- `src/macos_dns.rs` (the `networksetup` layer), except `flush_resolver_cache` if
  still needed.
- In `src/userspace_helper/macos/`: `capture_macos_dns_service`,
  `restore_macos_dns_services`, `macos_current_dns_fingerprint`,
  `persist_dns_custody`, `MacosDnsState`, `MacosDnsServiceState`, the DNS part of
  rollback and `cleanup_network_macos`, `plan_dns_actions`,
  `dns_reconcile_forced`, `DnsPolicy`, `DnsDecision::Hold`.
- `src/dns_custody.rs`, `src/privileged/dns_sweep.rs`, `src/privileged/dns_watch.rs`
  and their call sites in `src/privileged/mod.rs` and `connection_ops.rs`.
- The sentinel handling in `src/launchd.rs` and the plist.
- `doc/dns-custody-late-record-watch.md` becomes moot.
- Of `issues/shutdown-teardown.md`: the DNS part of the shutdown problem. A
  killed helper leaves routes and the utun, which die with it, and no DNS.

## Risks

- **Scoped queries bypass the tunnel resolver.** Apps that bind a query to an
  interface use the scoped resolver of that interface (`scutil --dns`, "for
  scoped queries"). Today's override changes the physical service, so it
  affects those too. Whether this matters in practice (e.g. for captive
  portals it is desirable) is unverified.
- **Browsers.** vpnc-scripts issue #15 (Mojave era) reports scutil-only DNS
  that worked for `nslookup` but not in browsers; vpnc-script additionally
  sets `networksetup` DNS since. The cause is unverified, and vpnc-script used
  a service with `OverridePrimary`, not a domain-less supplemental resolver.
  Tailscale's current tailscaled using the latter suggests it works; the spike must
  test Safari and Chrome explicitly.
- **Encrypted DNS profiles and iCloud Private Relay** may take precedence over
  both today's override and the synthetic service. Unverified; not a
  regression either way.
- **macOS versions.** The cask requires macOS 14
  (`packaging/homebrew/macos-wireguard-daemon.rb.tmpl`). The configd sources
  read are from 2026 (`configd-1405.100.8`); 14 and 15 are untested.

## Verification

Manual spike, as root. Every step uses temporary keys or removes what it
creates. Steps 3 and 4 gate the shadow phase: if the domain-less resolver does
not win against the LAN resolver, or browsers ignore it, the approach is dead
and no shadow code gets built. Steps 1, 5, 7 and 8 can wait for the shadow
phase, which observes them on real machines (see "Rollout").

1. **Lifetime.** A key added with `add <key> temporary` (or `set` after
   `open temporary`) in a long-running `scutil` exists while that session
   lives and is gone after `scutil` exits. A plain `set` survives its session
   until `remove`.
2. **Match domain.** A State-only service with `SupplementalMatchDomains
   ["wgd-probe.test"]` shows up in `scutil --dns` as `domain : wgd-probe.test`.
3. **Default resolver.** With a tunnel up and its routes in place, publish
   `ServerAddresses [<tunnel DNS>]`, `SupplementalMatchDomains [""]`,
   `SearchOrder 100000`. Check the resolver order in `scutil --dns`, then
   resolve a name that only the tunnel resolver knows with
   `dscacheutil -q host -a name <name>`, in Safari and in Chrome.
4. **Manual DNS on the physical service.** Repeat 3 with manual DNS set on
   Wi-Fi (`Setup:`), to show that the synthetic resolver still wins.
5. **Crash.** Hold the key in a `scutil` co-process, `kill -9` the parent
   shell and check that the key and the resolver disappear.
6. **Two tunnels.** Two domain-less resolvers with different `SearchOrder`:
   which one answers, and is the other used when the first times out?
7. **configd restart** (`sudo killall configd`, disruptive, only on a test
   machine): the key is gone and the notification watch republishes it.
8. **macOS 14 and 15**, if a machine is available: steps 2, 3 and 5.

Results on macOS 27.2, 2026-10-28, with the shadow and opt-in builds instead
of a `scutil` co-process:

- 1 and 5 passed: after `kill -9` of the helper the key was gone within 2 s
  in both modes (`privileged_dns_store_key_after_exit died=true
  present=false`). A clean disconnect removes it too (`sc_status=0`).
- 2 passed: the shadow key shows up as a supplemental resolver. configd
  reports it with `order 103200`, not the 100000 that was set.
- 3 passed: the active key is resolver #1 (order 103200) ahead of the
  network's default resolver (order 200000), and a tunnel-only name
  resolves through it in `dscacheutil`, `curl` and Safari. Chrome is untested.
- 4 passed: the same with `1.1.1.1` set as manual DNS on Wi-Fi and the
  mDNSResponder cache flushed.
- The notification watch republished a key removed with `scutil` within 1 s
  (`trigger=notification`).
- 6, 7 and 8 are open.

## Rollout

| Phase | DNS that answers queries | Dynamic store key |
|---|---|---|
| 0. Spike | `networksetup` | manual, Verification 3 and 4 |
| 1. Shadow | `networksetup`, unchanged | inert probe key, every tunnel |
| 2. Opt-in | dynamic store, for opted-in connections only | target shape |
| 3. Default | dynamic store | target shape; Migration starts |

### Phase 1: shadow

The helper publishes the key with the full lifecycle of "Design" (publish
after routes, withdraw on LAN collision, remove on teardown, notification
watch, republish), but with a match domain no real name falls under:

```
State:/Network/Service/<tunnel-service-id>/DNS
  ServerAddresses          = [<DNS = entries of the config>]
  SupplementalMatchDomains = ["wgd-shadow-<tunnel-service-id>.inactive"]
  SupplementalMatchDomainsNoSearch = 1
  SearchOrder              = 100000
```

`<tunnel-service-id>` is a UUIDv8 built from the SHA-256 of the connection id
(`crate::dns_dynamic_store::tunnel_service_id`), uppercase in the key as configd
writes its own ids. `SearchOrder` is a constant: the match domain is unique per
connection, so the connect counter of "Ordering" is not needed yet.

The suffix `.inactive` says what the key is to anyone reading `scutil --dns`
(a reserved name like `.invalid` reads as "broken"). It is not a reserved TLD,
but the label in front contains the tunnel's UUID, so no real name falls under
the match domain and the resolver only ever sees probe queries. The key still
shows up in `scutil --dns`, which proves the merge (Verification 2).
Without `SupplementalMatchDomainsNoSearch` IPMonitor also appends the match
domain to the default resolver's search list (seen on 2026-10-28 as
`search domain[0] : wgd-shadow-….inactive` on resolver #1), so every short
name would cause an extra probe query. The active key sets it too; for `""`
it is harmless. If
`SupplementalMatchOrders` is set, it must have the same length as the match
domains.

The `networksetup` path, custody records, sweep, watch and reconciler run
exactly as today and stay authoritative. Rules for the shadow code:

- Every failure is logged and never fatal for the helper or the tunnel. One
  dedicated thread (`userspace_helper::macos::dns_store_key`) owns the session,
  the run loop source and all SC calls, so nothing blocks the tokio runtime.
  The reconciler only sends it "publish" or "withdraw"; teardown waits at
  most 2 s for the removal.
- The notification watch is backed by a re-read of the key every 30 s. The
  `trigger` field of `userspace_helper_dns_key_restored` (`notification` or
  `poll`) shows whether the notification alone would have been enough.
- Only the owning helper writes the key. The daemon, `wgd status` and
  `wgd doctor` only read it: a plain `set` from a non-session store would make
  the key permanent (see "Who holds the session"), and in shadow mode nobody
  would notice.

What the shadow phase measures, through log events:

| Event | Emitted by | Answers |
|---|---|---|
| `userspace_helper_dns_store_key_published`, `_withdrawn`, `_removed`, `_failed` (with `stage`, `sc_status`) | helper | the lifecycle works in the field |
| `userspace_helper_dns_store_key_stale_removed` | helper, before the first publish | a previous owner left a non-session key behind |
| `userspace_helper_dns_key_restored` (with `trigger`) | helper, notification watch or poll | configd restarts and foreign removals happen and are healed (Verification 7) |
| `privileged_dns_store_key_after_exit` with `died` and `present` | daemon, in `dns_watch.rs` after the exit grace, rechecked once after 1 s | session keys die with the helper, for clean exits and for real SIGKILLs and panics (`died = true`; Verification 1 and 5) |
| `shadow_key_intact` field on `userspace_helper_dns_reconcile_applied` | helper | how often the reconciler repairs drift the dynamic store would not have had; "intact" means present while published, absent while withdrawn |

All helper events carry `mode` (`shadow` or `active`). Machines on macOS 14
and 15 that run the shadow build cover Verification 8 for the lifecycle part.

`wgd status` shows the key under the DNS tables ("Dynamic store key
(shadow)=<key> match domain <domain>: published", or withdrawn, missing,
unreadable), read through the helper's overview. `wgd doctor` has a section
"dns dynamic store" with the opt-in file, every DNS-promoting connection's key
and whether it exists, and the full `scutil --dns`.

What the shadow phase cannot measure: resolver ordering against the default
resolver, browser behaviour, search-domain interaction and fallback between
tunnels (Verification 3, 4, 6). The shadow resolver never answers a real
query, so these need phase 2.

### Phase 2: opt-in

The switch is a root-only file, `/Library/Application Support/wgd/dns-dynamic-store`:
one connection id per line, `#` starts a comment, edited by hand with sudo.
There is no API or CLI for it on purpose: it exists only until phase 3, and a
root-owned file adds no authorization surface. The file must be root-owned
and not group/other writable (the same check as the runtime dir); otherwise
the daemon logs `privileged_dns_dynamic_store_opt_in_unreadable` and the
connection stays in shadow mode.

The daemon reads the file each time it spawns a helper and, for a listed
connection, sets `WGD_DNS_DYNAMIC_STORE=1` (`privileged_dns_via_dynamic_store`).
A change takes effect at the next connect. The helper then:

- publishes the target shape (`SupplementalMatchDomains [""]`) through the same
  owner thread, with the same lifecycle and log events (`mode = active`);
- skips the `networksetup` path entirely: no capture, no custody record, no
  DNS fingerprint, no reconcile of services. The 3 s tick only re-evaluates
  the LAN collision and withdraws or republishes the key;
- flushes the resolver cache after every publish, withdraw and removal (open
  question below; harmless if unnecessary).

`wgd status` reports the tunnel DNS as "active via the dynamic store" while
the key exists, and no network service as a target.

Known gaps of phase 2:

- No custody record means no kqueue exit watch, so
  `privileged_dns_store_key_after_exit` is not logged for active connections.
  The shadow phase measures the same session mechanism for every tunnel.
- `SearchOrder` is the constant 100000. Several active tunnels with DNS have
  no defined order yet (see "Ordering").
- Mixed setups, one connection on each path, are allowed, but the two paths do
  not coordinate: the primary service's tunnel DNS and the dynamic store
  resolver compete, which is the ordering question of Verification 6 again.
- The "System resolver" line of `wgd status` reads the first resolver of
  `scutil --dns`. If it shows the LAN resolver while the active key is
  published, that answers Verification 3 negatively.

### Phase 3: default

The dynamic store becomes the only path for new connections; "Migration" and
"What goes away" apply from here.

## Open questions

- Ordering and fallback among domain-less resolvers (Verification 3 and 6).
- Search-domain interaction (see "Search domains").
- Whether `flush_resolver_cache` is still needed after a key change, or
  whether mDNSResponder picks up the new configuration on its own.
- Whether the daemon should assign the connect counter for `SearchOrder`, or
  whether "last connected wins" should be replaced by an explicit priority in
  the connection config.
- How `transparent_dns.md`, referenced from `dns_plan.rs:17` and `dns.rs:178`
  but missing from the repo, relates to this; with this spec its phases are
  obsolete and the references should go.
