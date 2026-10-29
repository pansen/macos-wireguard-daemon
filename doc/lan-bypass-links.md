# LAN bypass links: take dependent prefixes off the tunnel

**Status:** phase 1 implemented (unit tested, not yet verified on a live
network). Phase 1b is specified for implementation; phases 2 to 4 are
sketches.
**Scope:** helper route planning (`src/userspace_helper/macos/routes.rs`,
`net.rs`, `system.rs`), the per-connection option
(`src/privileged/connection_store.rs`, `src/privileged_api.rs`,
`src/connection_cli.rs`), helper spawn (`src/privileged/commands.rs`), status
(`src/userspace_helper/macos/overview.rs`, `src/status_render.rs`)
**Related:** `doc/linked-networks.md` (alternative write-up of the same
request), `doc/architecture.md` ("Continuous reconciliation"),
`doc/dns-dynamic-store.md`

Line numbers are as of `ddaf9ab`. Facts about macOS are marked *verified*
(with date and how) or *unverified*.

## Problem

The helper drops an AllowedIPs route when that route lies inside a subnet the
Mac is directly attached to (`macos_route_excluded_by_local_subnet`,
`routes.rs:125`; containment in `macos_subnet_contains`, `net.rs:7`). At home
on `10.66.77.0/24` the LAN prefix therefore stays off the tunnel, which is
what the user wants.

The rule only sees connected subnets. A host that sits one NAT layer further
out is not connected, so it stays on the tunnel even though it is reachable
from the LAN:

```
[Peer]
AllowedIPs = 192.168.168.0/24, 100.64.1.0/24, 10.66.77.0/24, 192.168.188.1/32
```

```
Mac 10.66.77.x -> xi 10.66.77.1 (NAT) -> 192.168.188.1 (upstream router)
```

| Destination | Away | At home today | At home wanted |
| --- | --- | --- | --- |
| `192.168.168.0/24` | tunnel | tunnel | tunnel |
| `100.64.1.0/24` | tunnel | tunnel | tunnel |
| `10.66.77.0/24` | tunnel | LAN | LAN |
| `192.168.188.1/32` | tunnel | **tunnel** | LAN (via `10.66.77.1`) |

At home, traffic to `192.168.188.1` leaves the house through the VPN server
and comes back, or fails when the server cannot reach it.

The user confirmed on 2026-10-29 that `192.168.168.0/24` and `100.64.1.0/24`
must stay on the tunnel at home. Turning the whole VPN off on the home
network, as WireGuard.app does with SSID rules, is wanted as well at lower
priority. Phase 1b covers it without disconnecting: the helper keeps running
and withdraws all routes and DNS, so it stays the observer that notices when
the Mac leaves the network.

## Proposal

A **link** is a per-connection rule: *while anchor `A` is a connected subnet,
treat prefixes `P1..Pn` as if they were local too.* For the example:

```
wgd connection config home --link 10.66.77.0/24=192.168.188.1/32
```

The anchor is evaluated with exactly the rule the helper already uses for its
own LAN exclusion. A link adds no new way of recognising a network; it only
lets one recognised network carry more prefixes off the tunnel. Detection,
polling, ownership and teardown stay as they are.

### Why this shape

- **It reuses a detector that already works.** The anchor must be one of the
  connection's AllowedIPs entries, which makes it exactly the LAN the existing
  exclusion already takes off the tunnel, and it is "active" exactly when
  that entry would be excluded today. Users can predict it from the existing
  behaviour, and it inherits all past fixes to that detector. The same holds
  for the `*` bypass of phase 1b, which still needs an anchor from
  AllowedIPs.
- **The SSID is not available to wgd.** *Verified* on macOS 27.2,
  2026-10-29, unprivileged: `networksetup -getairportnetwork en0` reports
  "not associated", `ipconfig getsummary en0` shows `SSID`, `BSSID` and
  `NetworkID` as `<redacted>`, and `State:/Network/Interface/en0/AirPort`
  in the dynamic store carries an empty `SSID_STR` and BSSID
  `02:00:00:00:00:00`. Apple DTS states that a launchd daemon cannot obtain
  the Location privilege that CoreWLAN requires; only a LaunchAgent attached
  to a GUI app via `SMAppService` can
  ([forum 816619](https://developer.apple.com/forums/thread/816619),
  [forum 840513](https://developer.apple.com/forums/thread/840513)). The
  CoreWLAN `ssidDidChange` event has the same requirement.
- **WireGuard.app's SSID rules are not portable.** They are
  `NEOnDemandRule`s with `ssidMatch` that macOS evaluates for Network
  Extension VPNs. wgd runs its own `utun` through gotatun, so using them means
  rebuilding wgd as a packet tunnel system extension.
- **Directed and flat.** A link never makes its prefixes count as anchors for
  other links. Several NAT layers are one link with several prefixes, so there
  is no recursion, no cycle and no evaluation order.

### Rejected alternatives

- **SSID via WgdBar.** Needs Location Services on, WgdBar running, a stable
  Developer ID signature (authorisation is lost when the signature changes,
  which conflicts with local and Homebrew builds), a write path from WgdBar
  to the daemon (WgdBar is read-only today) and a freshness model for stale
  observations. Wi-Fi only. Revisit only if phases 2 and 3 prove insufficient.
- **traceroute to a fixed target** (for example 1.1.1.1) and bypassing every
  AllowedIPs entry that shows up as an early hop. It only sees routers on the
  path to that target (a NAS at `192.168.188.50` never appears), it cannot
  tell the prefix length of a hop, and late hops often do not answer. Phase 2
  keeps the useful part as a per-prefix probe.
- **Appending linked prefixes to `local_subnets`.** Tempting because the
  filter would then work unchanged, but `macos_restore_shadowed_lan_route`
  (`route_table.rs:314`) uses `local_subnets` to re-add interface-scoped
  connected routes. It would try to install `192.168.188.1/32` as on-link on
  `en0`. Connected subnets and link bypasses stay separate.
- **Network Extension with On Demand.** Full rewrite of the data path and
  packaging for one feature.

## Design (phase 1)

### Data model

```rust
/// While `anchor` is a connected subnet, `bypass` stays off the tunnel.
pub struct BypassLink {
    pub anchor: IpNet,      // canonical network address, any family, an AllowedIPs entry
    pub bypass: Vec<IpNet>, // canonical, non-empty, each one an AllowedIPs entry
}
```

`StoredConnection` (`connection_store.rs:28`) and its disk struct
(`connection_store.rs:121`) gain `bypass_links: Vec<BypassLink>` with
`#[serde(default)]`, following `dns_dynamic_store`. No links means today's
behaviour byte for byte.

The links do not go into the `.conf`. The parser rejects unknown keys
(`src/wireguard/connection_config.rs:309`), the file stays portable to
wg-quick and WireGuard.app, and `connection refresh` keeps the links.

### Validation

At `connection config`, and again at connect against the current AllowedIPs:

1. Every CIDR parses. Host bits are cleared and reported once
   (`10.66.77.5/24` is stored as `10.66.77.0/24`).
2. The anchor **equals** an AllowedIPs entry after normalisation. An anchor
   that is not listed, or only inside a broader entry, is rejected: the link
   would then hang off a network the exclusion does not take off the tunnel.
3. Every bypass prefix **equals** an AllowedIPs entry after normalisation.
   Phase 1 only removes routes the tunnel owns; it never installs routes on
   the physical side. That rules out three cases, each rejected with a
   specific message:
   - a prefix not in AllowedIPs (nothing to remove, almost always a typo),
   - a prefix inside a broader AllowedIPs entry (`192.168.188.1/32` with
     `192.168.0.0/16`), even if the prefix is also listed itself: the
     covering route still catches it once its own route is gone,
   - a prefix of a family whose default route is in AllowedIPs
     (`0.0.0.0/0` rejects IPv4 prefixes, `::/0` IPv6 prefixes), for the
     same reason.
4. A bypass prefix must not equal its own anchor (the anchor is excluded by
   the existing rule anyway).

If AllowedIPs change later, `connection refresh` prunes the links in the same
store update as the new config: bypass prefixes that no longer validate are
dropped, and a link goes entirely when its anchor no longer validates or no
prefix is left. The refresh output lists what was removed (and so does the
daemon log, `privileged_bypass_link_pruned`). `add --force`, which replaces a
connection under a new id, carries the links over with the same pruning and
reports the same way. If carrying them over fails, the command stops before
it removes the old record, so the links are not lost; running it again
returns the same new id and retries.

Connect checks the stored links again as a safety net (a record written by an
older version, a hand-edited store). A link that does not validate is ignored,
logged by the daemon as `connection_bypass_link_invalid` and shown in
`connection config` and `connection get`. Failing the connect would turn a
server-side config change into an outage.

### CLI

```
wgd connection config <id> --link <anchor>=<prefix>[,<prefix>...]   # repeatable, replaces all links
wgd connection config <id> --no-links
wgd connection get <id>                                              # lists links and their validation state
```

Replacing the full set on every `--link` call keeps the command idempotent
and avoids index-based removal. Both the connection and the `--link` value
complete with <TAB> from the connection's AllowedIPs (anchor and prefixes, in
bash, zsh and fish; bash needs wgd's own registration function, which joins
the words bash cuts at `=` and `:`). Like `--dns-dynamic-store`, changes take effect
at the next connect; `connection config` prints that hint when the connection
is up.

### Helper input

`run_gotatun_up` (`commands.rs:229`) passes the validated links as JSON in
`WGD_BYPASS_LINKS`, next to the existing `WGD_*` variables (`commands.rs:251`).
The helper parses them into `MacosReconcileInputs` (`macos/mod.rs:72`). An
unparsable value is a startup error: the daemon produced it, so a parse
failure is a bug, not user input.

### Evaluation

In `macos_desired_routes` (`routes.rs:84`), after the existing local-subnet
filter:

```
active_links = links where some s in fingerprint.local_subnets
               satisfies macos_subnet_contains(s, link.anchor)
for route in allowed routes:
    if excluded by local subnet: skip (existing)
    if route.destination equals or lies inside a bypass prefix of an active
        link: skip, log userspace_helper_route_excluded_linked {destination, anchor}
```

"Lies inside" is the containment the local-subnet rule uses: with AllowedIPs
`192.168.188.0/24, 192.168.188.7/32` and the bypass prefix `192.168.188.0/24`,
both routes go, so no part of the prefix stays on the tunnel. Validation is
unchanged: each bypass prefix still has to equal an AllowedIPs entry, and a
broader covering entry is still rejected.

Properties:

- The decision is a pure function of `local_subnets` and the static links.
  The existing fingerprint guard (`routes.rs:249`) therefore stays correct
  without new fields: if `local_subnets` did not change, neither did the set
  of active links.
- Initial connect (`configure_network_macos`, `macos/mod.rs:281`) and the
  3 s reconciler both go through `macos_desired_routes`, so arrival, departure
  and "connect while already at home" behave the same.
- Removal reuses the existing path (`del_macos_route`). The call to
  `macos_restore_shadowed_lan_route` is a no-op for linked prefixes because
  they are not inside any connected subnet.

### Forwarding after removal

With the tunnel route gone, `192.168.188.1` falls back to the default route,
which at home is `10.66.77.1` on the LAN interface. The validation rules
above guarantee there is no covering tunnel route. This assumes that the LAN
interface holds the default route. With Ethernet and Wi-Fi up on different
networks, the anchor might sit on the non-primary interface; the bypassed
traffic then leaves through the primary one. Phase 1 accepts this and reports
it (see Status); phase 4 fixes it.

### DNS

Unchanged. The existing rule withdraws tunnel DNS when a resolver lies in a
connected subnet (`macos_dns_server_in_local_subnet`, `dns_plan.rs:76`).
Links deliberately do not extend it: a resolver inside a bypassed prefix
stays reachable, only by a shorter path, so tunnel DNS keeps working and
there is no reason to change name resolution. This is a deliberate
difference from `doc/linked-networks.md`; see Open questions.

### Status

The helper already builds the `NetworkOverview` that `wgd status` renders
(`src/userspace_helper/macos/overview.rs`, `src/status_model.rs`), including a
per-route outcome for "excluded by connected subnet". Links extend that model
rather than being recomputed by the daemon, so status shows what the helper
decided.

- `wgd status` and the overview show each active link as
  `192.168.188.1/32 -> LAN (link 10.66.77.0/24 on en0)`, distinct from
  "connected subnet" and from "missing route".
- If the kernel still sends a bypassed prefix into the tunnel (the lookup
  answers with the tunnel interface, or fails while the tunnel still holds the
  route), the row says `link 10.66.77.0/24 active, but still routed through
  the tunnel (removal pending or failed)` instead of "kept off the tunnel",
  and is not muted. The lookup is the signal, not the helper's own route list.
- If the route lookup for a bypassed prefix (`route -n get`) resolves to an
  interface other than the anchor's, status shows a warning with both
  interface names. This is informational in phase 1.
- Invalid links are not listed in `status`: the helper only receives valid
  links. `connection config` and `connection get` list them with their
  reason.

## Rollout

### Phase 1: static links (this document)

Everything in Design. Small change set: one struct, one option through
store, API, CLI and spawn, one filter step, status lines.

### Phase 1b: dormant connection (`*` bypass)

`--link 10.66.77.0/24=*` turns the VPN off while the anchor is connected,
without disconnecting. The helper, `utun` and the WireGuard device keep
running; only what the helper owns is withdrawn.

- **Syntax.** `*` stands for "all AllowedIPs" and must be the only bypass
  entry of its link. It always validates, including for full tunnels, because
  nothing has to be routed over the physical side: with no tunnel routes,
  traffic falls back to the normal default route.
- **Routes.** While a `*` link is active, `macos_desired_routes` returns an
  empty list, including no endpoint pin (nothing captures the endpoint any
  more). The existing reconciler removes the owned routes and restores them
  when the anchor goes away. The decision is still a pure function of
  `local_subnets`, so the route fingerprint needs no new field.
- **DNS.** An active `*` link withdraws tunnel DNS in both modes, whatever the
  resolver address: `DnsDecision::RestoreAll` on the `networksetup` path,
  `DnsStoreKey::set_wanted(false)` in dynamic-store mode. It is a second
  reason next to the resolver collision and must be evaluated before the DNS
  fingerprint guard, like the collision (`dns.rs:234`), because entering the
  anchor LAN need not change the DNS fingerprint.
- **Status.** The connection stays "connected" for the daemon, the session
  agent, `start_mode` and `user_disconnected`. The overview gains a dormant
  marker naming the anchor and device; `wgd status` prints
  `dormant: link 10.66.77.0/24 on en0, all routes and DNS withdrawn` and
  WgdBar shows the connection as dormant instead of connected. The DNS state
  gets its own reason instead of reusing the resolver collision text.
- **What stays.** Keepalives continue if `PersistentKeepalive` is set.
  Packets from the server side still reach the tunnel address, but replies
  have no route back through the tunnel. Routes or settings created by
  PostUp hooks stay, because the helper does not own them; PreDown/PostDown
  do not run.
- **Keepalive (optional, not in 1b).** Setting the persistent keepalive to 0
  over the helper's UAPI while dormant and restoring it afterwards would stop
  the remaining traffic. Whether gotatun accepts that at runtime is
  *unverified*.

A true disconnect on the home network is not planned: it would need an
observer outside the helper and a "suspended" state that does not collide
with `user_disconnected`, and 1b gives the same user-visible result.

### Phase 2: reachability check (optional per link)

`--link 10.66.77.0/24=192.168.188.1/32@2`: bypass only if the host answers
within 2 hops over the anchor's interface, bound to it so the probe cannot
use the tunnel.

*Verified* on macOS 27.2, 2026-10-29, unprivileged, while
`route -n get 192.168.188.1` still pointed at `utun4`:

```
$ ping -c1 -t2 -m 1 -b en0 192.168.188.1   -> Time to live exceeded from 10.66.77.1
$ ping -c1 -t2 -m 2 -b en0 192.168.188.1   -> echo reply, ttl=63
```

This turns "the anchor is up" into "the bypass actually works". Constraints:

- Single hosts (`/32`, `/128`) only. A reply from one address says nothing
  about a prefix.
- Run on a fingerprint change and then every 60 s, not every 3 s tick.
- Hysteresis: two consecutive failures before a bypass is withdrawn, one
  success to apply it. Results become part of the route fingerprint.
- Until the first result arrives the prefix stays on the tunnel, which is the
  safe state.
- Implementation: `ping -c1 -t1 -m <n> -b <iface>` matches the helper's
  existing style of shelling out to `ifconfig` and `route`. A
  `SOCK_DGRAM`/`IPPROTO_ICMP` socket with `IP_TTL` and `IP_BOUND_IF` avoids
  the process spawn if that matters.

### Phase 3: stronger anchor identity

A second anchor type for networks with generic subnets such as
`192.168.1.0/24`, where a plain subnet match could fire in a hotel:
`--link dhcp-domain:pansen.lan=...` or `dhcp-server:10.66.77.1=...`.

*Verified* readable without Location authorization on macOS 27.2,
2026-10-29: `ipconfig getpacket en0` and
`State:/Network/Service/<primary>/DHCP` expose `server_identifier`,
`router` and `domain_name` (option 15). The documented API is
`SCDynamicStoreCopyDHCPInfo` plus `DHCPInfoGetOptionData`. Read it per
service of the anchor interface, not from the effective resolver
configuration that wgd itself changes. The values join the route fingerprint.

*Unverified* candidates: the `ProfileID` hash in
`State:/Network/Interface/en0/AirPort` (unredacted, stability across
networks and reconnects unknown) and the gateway MAC (`arp -n <gw>` showed
no entry inside the nono sandbox; root not tested).

### Phase 4: covering routes and non-primary anchors

Lift the "must equal an AllowedIPs entry" rule. For a bypass inside a
covering tunnel route, install an owned host route via the anchor interface's
gateway, scoped to that interface, using the same ownership bookkeeping as the
endpoint pin (`routes.rs:84`, `GatewayFallback`). The same mechanism fixes the
non-primary anchor case. Needs its own design for gateway changes, ownership
against other connections and cleanup; out of scope until phase 1 has been in
use.

## Risks

- **Spoofed or reused anchor.** A foreign network on `10.66.77.0/24` activates
  the link, and traffic to `192.168.188.1` goes unencrypted into that network.
  The existing LAN exclusion has the same exposure for `10.66.77.0/24` itself;
  a link widens it to the bypassed prefixes. Mitigations: phase 2 confirms
  the target answers on the expected hop count, phase 3 requires the DHCP
  identity. None of these is authentication; an attacker who copies the
  subnet, DHCP domain and host address defeats all of them. Users who need
  that guarantee should not use links.
- **Stale interface addresses.** An interface that is UP but has lost its
  link can keep its address and keep the anchor active. This already applies
  to the existing exclusion and is not made worse; it is tracked separately.
- **Wrong egress with two active networks.** Covered by the status warning in
  phase 1 and the scoped route in phase 4.

## Verification

Phase 1 acceptance, each in both DNS modes:

1. Away from home: all four example prefixes route via `utun`
   (`route -n get <dst>`).
2. Join the home LAN while connected: within one reconcile tick
   `192.168.188.1` and `10.66.77.0/24` resolve to `en0`, the other two stay
   on `utun`, and `ping 192.168.188.1` works.
3. Leave the LAN: `192.168.188.1/32` is back on `utun` within one tick.
4. Connect while already at home: same result as 2 without a transient
   tunnel route (check the helper log for `userspace_helper_route_excluded_linked`
   at connect).
5. Sleep and wake at home and away.
6. `connection refresh` with a config that drops `192.168.188.1/32`: the
   refresh output lists the removed prefix and link, `connection get` shows no
   link, and a connect afterwards succeeds. With a config that drops
   `10.66.77.0/24` the whole link goes.
7. Validation errors for an anchor outside AllowedIPs, a prefix outside
   AllowedIPs, a prefix under `192.168.0.0/16`, and a full tunnel.
8. Ethernet and Wi-Fi on different networks with the anchor on the
   non-primary one: status shows the egress warning.

Phase 1b acceptance, each in both DNS modes:

9. With `--link 10.66.77.0/24=*`, joining the home LAN removes every tunnel
   route and the tunnel DNS within one tick; `scutil --dns` shows no tunnel
   resolver; `wgd status` reports the connection as dormant; WgdBar shows it
   as dormant.
10. Leaving the LAN restores all routes and DNS within one tick, and traffic
    to `192.168.168.0/24` passes the tunnel again.
11. Same with a full-tunnel config: at home all traffic leaves via the LAN,
    away the `/1` routes and the endpoint pin come back.
12. Disconnect and reconnect while dormant, and reboot while dormant: no DNS
    custody record is left behind, and the connection comes up dormant.

Unit tests in `routes.rs` next to
`containment_matches_equal_and_more_specific_routes_only`: active and
inactive anchor, anchor broader than the connected subnet and vice versa,
IPv6, two links sharing a bypass prefix, a link whose prefix is also a
connected subnet.

## Open questions

1. **DNS for bypassed resolvers.** This spec keeps tunnel DNS when its
   resolver is only bypassed, `doc/linked-networks.md` withdraws it. Decide
   based on whether the home resolver should answer at home even when the
   tunnel resolver is a different host.
2. **Anchor match: containment or equality.** Containment (proposed) matches
   the existing rule. Equality is stricter when the LAN is a `/16` and the
   anchor a `/24`. Probably irrelevant for real setups.
3. **Live updates.** Phase 1 applies links at connect. Pushing changes to a
   running helper needs a control channel the helper does not have today.
