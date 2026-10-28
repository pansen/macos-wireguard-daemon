# Tunnel DNS through the SystemConfiguration dynamic store

**Status:** phases 1 (shadow key for every tunnel) and 2 (per-connection
opt-in) are implemented; phase 3 (default) is not started. Verification 1 to 5
passed on macOS 27.2; Chrome, 6, 7 and 8 are open.
**Scope:** helper DNS (`src/userspace_helper/macos/dns.rs`, `dns_store_key.rs`,
`dns_plan.rs`, `src/macos_dns.rs`), `src/dns_dynamic_store.rs`, the opt-in
(`StoredConnection::dns_dynamic_store`), DNS custody (`src/dns_custody.rs`,
`src/privileged/dns_sweep.rs`, `dns_watch.rs`), status and doctor
**Related:** `issues/dns-ownership-edge-cases.md` (A3, B3, C3),
`issues/dns-crash-recovery.md`, `issues/shutdown-teardown.md`,
`doc/dns-custody-late-record-watch.md`

Line numbers are as of `60c4c8f`. Facts about macOS are marked *verified*
(with the source) or *unverified*.

## Problem

The helper promotes tunnel DNS with `networksetup -setdnsservers` and
`-setsearchdomains` on the primary network service (`DnsPolicy::PrimaryOnly`,
`dns_plan.rs:18`; `set_dns_servers`, `src/macos_dns.rs:100`). These are the
user's persistent `Setup:` preferences, and everything hard about DNS in wgd
follows from that:

- A helper that dies without cleanup leaves tunnel DNS on the service across
  reboots. Repairing it takes a custody record per connection, daemon sweeps,
  a kqueue exit watch, a launchd `KeepAlive`/`PathState` sentinel and `wgd dns
  repair`.
- The helper must capture the "original" DNS and cannot see DHCP resolvers
  through `networksetup`, so a restore can only return the service to "Empty"
  (`capture_macos_dns_service`, `dns.rs:183`).
- DHCP renewals, user edits, primary-service changes and network locations
  make the override drift, hence the 3 s reconciler (`macos_reconcile_dns`,
  `dns.rs:206`).
- Two tunnels that promote DNS fight over the primary service and capture each
  other's tunnel DNS as "original" (Finding A in
  `issues/dns-ownership-edge-cases.md`).

## Proposal

Publish each tunnel's resolver as its own State-only service in the dynamic
store, held by a session that dies with the helper, and never touch the
physical services' DNS again:

```
State:/Network/Service/<tunnel-service-id>/DNS
  ServerAddresses                  = [<DNS = entries of the config>]
  SupplementalMatchDomains         = [""]
  SupplementalMatchDomainsNoSearch = 1
  SearchOrder                      = 100000
```

No `IPv4` entity, no `Router`, no `OverridePrimary`. `<tunnel-service-id>` is a
UUIDv8 from the SHA-256 of the connection id (`dns_dynamic_store::tunnel_service_id`),
uppercase as configd writes its own ids, so anyone who knows the connection id
finds the key.

### Why this shape

- **configd keeps `State:` in memory only.** *Verified*: `storeData` is a
  `CFMutableDictionary` built in `__SCDynamicStoreInit` (`configd.tproj/_SCD.c`,
  apple-oss-distributions/configd). Nothing survives a reboot.
- **Session keys die with the process.** *Verified*:
  `kSCDynamicStoreUseSessionKeys` in `SCDynamicStore.h`; configd closes the
  session on `DISPATCH_MACH_NO_SENDERS` and removes its keys
  (`configd_server.c`, `_configclose.c`). Confirmed for SIGKILL by Verification 5.
- **A State-only service is merged into the resolver configuration.**
  *Verified* in `Plugins/IPMonitor/ip_plugin.c` (`get_dns_changes`): a DNS dict
  without an IPv4 entity is kept if it has `SupplementalMatchDomains`.
- **`""` makes a domain-less resolver.** *Verified* in `dns-configuration.c`
  (`add_supplemental`) and `ip_plugin.c` (`ALLOW_EMPTY_STRING`). Tailscale uses
  exactly this for tailscaled's global DNS on macOS (`net/dns/manager_darwin.go`,
  `SearchOrder 100000`); wireguard-apple does the equivalent with
  `NEDNSSettings.matchDomains = [""]`.
- **`SupplementalMatchDomainsNoSearch = 1`.** Without it IPMonitor appends the
  match domain to the default resolver's search list (*verified* on macOS 27.2:
  `search domain[0] : wgd-shadow-….inactive` on resolver #1).
- **No routing side effects.** *Verified* in `ip_plugin.c`: without an IPv4
  entity and `Router` IPMonitor installs no default route, and `OverridePrimary`
  needs `Router`. wgd keeps managing its own routes.
- **No collision with DHCP or the user.** DHCP writes
  `State:/Network/Service/<physical-id>/DNS` and manual DNS lives in `Setup:`
  of the same id, which wins (*verified*, `merge_dns_servers`). A separate id
  touches neither.

### Rejected alternatives

- **Overwrite the physical service's `State:` DNS** (Mullvad `talpid-dns`,
  Tunnelblick): races with DHCP, loses against manual `Setup:` DNS, needs
  backups again.
- **`OverridePrimary` with an IPv4 entity** (vpnc-script): IPMonitor installs a
  default route via the utun, which fights wgd's route management.
- **`/etc/resolver/<domain>` files**: survive crashes and reboots, so the
  custody problem stays, and cannot express a default resolver (`man 5 resolver`).

## Design

### Who holds the session

The helper: it lives exactly as long as the tunnel, runs as root (non-root
writes fail with "Permission denied", *verified*), and is where DNS is applied.
The daemon idle-exits and cannot own a key for a tunnel's life.

The store is created with `kSCDynamicStoreUseSessionKeys` (crate
`system-configuration` 0.7, the helper declares `SCError()` itself to log
`sc_status`). Two traps in `configd.tproj/_configset.c` (*verified*):

- `set` on a key another session owns fails with `kSCStatusKeyExists`, so
  before the first publish the helper removes a stale key through a plain store.
- A plain `set` from a non-session store makes a session key permanent. Only
  the owning helper writes the key; the daemon, `wgd status` and `wgd doctor`
  only read it.

One thread per helper (`userspace_helper::macos::dns_store_key`) owns the
session, the run loop source and every SC call, so nothing blocks the tokio
runtime; the reconciler only sends "publish" or "withdraw". Every failure is
logged and never fatal.

### Lifecycle

| Event | Action |
|---|---|
| Connect, after routes are up | remove a stale key, then publish |
| A tunnel DNS server is inside a connected LAN subnet (`dns_plan.rs:76`) | withdraw; publish again when it clears |
| Key disappears or changes (notification, backed by a 30 s re-read) | republish, log `userspace_helper_dns_key_restored` with `trigger` |
| Teardown, before routes go | remove (bounded by 2 s) |
| Helper dies, configd restarts, reboot | configd drops the key; a running helper republishes after a configd restart |

The collision rule is about reachability: wgd drops the route to a tunnel
resolver inside the LAN (`routes.rs:107-116`), so the query would reach the LAN
host of that address. Primary-service changes, DHCP renewals, user edits and
location switches need no reaction, since none touches the tunnel's key.

### Ordering

`scutil --dns` sorts resolvers by `SearchOrder`; configd reports the key with
an offset that varies (101200 to 103200 observed), ahead of the default
resolver's 200000. Several tunnels with full DNS publish several domain-less
resolvers, which `compareDomain` treats as equal, so `SearchOrder` would have
to differ. Proposal: the most recently connected tunnel wins with `SearchOrder
= 100000 - n`, `n` a bounded connect counter from the daemon. Fallback to the
losing resolver on timeouts is unverified.

### Search domains

The `networksetup` path clears the primary service's search domains and
restores them later. With a synthetic service they stay in place; whether the
key's empty `SearchDomains` replaces, extends or ignores the global list is
**unverified**. The first version publishes no `SearchDomains`, so a short name
may be tried as `name.<lan-domain>` through the tunnel resolver. `DNS =`
accepts IP addresses only (`connection_config.rs:346-351`); search domains
there, as in wg-quick, would be a separate change.

### Split DNS (later)

The same key with real match domains (plus `SupplementalMatchOrders` of equal
length; a mismatch drops the resolver, *verified*) gives split DNS with the
same crash behaviour. It needs config syntax wgd does not have; the key layout
(one key per connection, match domains as data) keeps it possible.

## Rollout

| Phase | DNS that answers queries | Dynamic store key |
|---|---|---|
| 1. Shadow (every tunnel) | `networksetup`, unchanged | probe key `wgd-shadow-<id>.inactive` |
| 2. Opt-in | dynamic store for opted-in connections | target shape |
| 3. Default | dynamic store | target shape; Migration starts |

### Phase 1: shadow

The key has the full lifecycle but the match domain
`wgd-shadow-<tunnel-service-id>.inactive`: the UUID label means no real name
falls under it, and `.inactive` tells a reader of `scutil --dns` what it is
(`.invalid` would read as "broken"). `networksetup`, custody, sweep and
reconciler stay authoritative. The shadow key measures the mechanism in the
field:

| Event | Emitted by | Answers |
|---|---|---|
| `userspace_helper_dns_store_key_published`, `_withdrawn`, `_removed`, `_failed` (`stage`, `sc_status`) | helper | the lifecycle works |
| `userspace_helper_dns_store_key_stale_removed` | helper, before the first publish | a previous owner left a non-session key |
| `userspace_helper_dns_key_restored` (`trigger` = `notification` or `poll`) | helper | foreign removals and configd restarts are healed, and whether the notification alone suffices |
| `privileged_dns_store_key_after_exit` (`died`, `present`) | daemon, after a watched helper exits (custody record, so shadow mode only) | the key dies with the helper; `died = true` means no clean teardown |
| `shadow_key_intact` on `userspace_helper_dns_reconcile_applied` | helper | how often the reconciler repairs drift the key would not have had |

All helper events carry `mode` (`shadow` or `active`). `wgd status` shows the
key as a table (key, match domain, state), and `wgd doctor` lists each
connection's opt-in and key plus the full `scutil --dns`.

### Phase 2: opt-in

`wgd connection config --dns-dynamic-store <id or name>` sets
`StoredConnection::dns_dynamic_store` (request `SetConnectionDnsDynamicStore`,
ownership only, since it runs nothing new as root; logged as
`privileged_dns_dynamic_store_set`). `connection add --force` carries it over
to the replacing record. The daemon passes `WGD_DNS_DYNAMIC_STORE=1` to the
helper at the next connect (`privileged_dns_via_dynamic_store`), and the
helper:

- publishes the target shape through the same owner thread (`mode = active`);
- skips `networksetup` entirely: no capture, no custody record, no service
  reconcile; the 3 s tick only re-evaluates the LAN collision;
- flushes the resolver cache after every publish, withdraw and removal.

The key needs `DNS =` entries and a connection id; without
`WGD_CONNECTION_ID` the helper logs
`userspace_helper_dns_store_key_active_without_connection_id` and stays on
`networksetup`. Without a custody record there is no exit watch, so
`privileged_dns_store_key_after_exit` is not logged in active mode.

### Phase 3: default and migration

The dynamic store becomes the only path. Machines from older builds may still
carry tunnel DNS in `Setup:` with custody records, so the sweep keeps running
for a transition period on existing records only, and `ClearStray` stays as
the only repair for builds before custody records. After one or two releases
these go away:

- `src/macos_dns.rs` (except `flush_resolver_cache` if still needed);
- in `src/userspace_helper/macos/`: capture, restore, the DNS fingerprint,
  `persist_dns_custody`, `MacosDnsState`, the DNS part of rollback and
  cleanup, `plan_dns_actions`, `dns_reconcile_forced`, `DnsPolicy`,
  `DnsDecision::Hold`;
- `src/dns_custody.rs`, `src/privileged/dns_sweep.rs`, `dns_watch.rs` and
  their call sites, the sentinel in `src/launchd.rs` and the plist, `wgd dns
  repair` and the purge sweep;
- `doc/dns-custody-late-record-watch.md` and the DNS part of
  `issues/shutdown-teardown.md`.

`TunnelDnsState` and `DnsServiceStatus` then shrink to published, withdrawn
(LAN collision) and failed.

## Risks

- **Scoped queries bypass the tunnel resolver.** Apps that bind a query to an
  interface use that interface's scoped resolver. *Verified* on macOS 27.2: with
  `networksetup` the en0 scoped resolver carried the tunnel DNS, in active mode
  it keeps the network's own resolver. Harmless for split tunnels, a possible
  DNS leak for full tunnels (untested).
- **Browsers.** vpnc-scripts issue #15 (Mojave era) reports scutil-only DNS
  that worked for `nslookup` but not in browsers, with `OverridePrimary`
  rather than a domain-less resolver. Safari works (Verification 3); Chrome is
  untested.
- **Encrypted DNS profiles and iCloud Private Relay** may take precedence over
  both paths. Unverified; not a regression.
- **macOS versions.** The cask allows macOS 14; only 27.2 is tested.

## Verification

| # | Check | Result on macOS 27.2, 2026-10-28 |
|---|---|---|
| 1 | A session key lives as long as its session; a plain `set` survives it | passed for the session key (removed on disconnect with `sc_status=0`, and see 5); the plain `set` case was not tested |
| 2 | A State-only service shows up in `scutil --dns` | passed: supplemental resolver, order 101200 to 103200 |
| 3 | The domain-less key wins against the network's default resolver; a tunnel-only name resolves in `dscacheutil`, Safari, Chrome | passed for `dscacheutil`, `curl` and Safari (resolver #1 ahead of order 200000); Chrome open |
| 4 | Same with manual DNS on Wi-Fi (`Setup:`) | passed with `1.1.1.1` and a flushed mDNSResponder cache |
| 5 | `kill -9` of the owner removes key and resolver | passed in both modes within 2 s (shadow: `died=true present=false`; active: `scutil` "No such key") |
| 6 | Two domain-less resolvers with different `SearchOrder`: which answers, and is the other a fallback? | open |
| 7 | `sudo killall configd`: the key comes back (disruptive) | open; a key removed with `scutil` came back within 1 s (`trigger=notification`) |
| 8 | macOS 14 and 15: checks 2, 3 and 5 | open |

A reboot with a connection in active mode left nothing to repair (first sweep
`restored=0`, `dns-custody/` empty, Wi-Fi without DNS) and the session agent
reconnected in active mode; the same reboot from shadow mode needed the
custody sweep about 16 s after boot.

## Open questions

- **Chrome:** test with "Secure DNS" off and on, open a tunnel-only name, check
  `chrome://net-internals/#dns`.
- **Several tunnels** (Verification 6), including the mixed case of one
  connection per path, where the primary service's tunnel DNS and the key
  compete; and whether the daemon should assign the connect counter or the
  config should carry an explicit priority.
- **configd restart** (Verification 7): notification or only the 30 s poll.
- **macOS 14 and 15** (Verification 8).
- **Full-tunnel leak via scoped queries** (see "Risks").
- **Search domains** (see "Search domains").
- **Resolver cache:** whether the flush after a key change is needed.
- **`wgd status`:** the "System resolver" table reads only the first resolver
  block of `scutil --dns` (`src/userspace_helper/macos/foreign.rs`), not the
  full order.
- **No reconnect after a helper crash:** the session agent connects
  `Automatic` connections only at its own start. Not caused by this change,
  but in active mode a down tunnel is the only thing left to repair after a
  crash.
- **`transparent_dns.md`**, referenced from `dns_plan.rs:17` and `dns.rs:179`
  but missing from the repo: obsolete with this spec, the references should go.
