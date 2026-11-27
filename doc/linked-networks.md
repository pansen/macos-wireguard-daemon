Research and proposed design, 2026-10-29. Reviewed against wgd revision
`ddaf9ab`; this is a proposal, not an implemented configuration format.
The macOS API findings below were checked against Apple documentation and
WireGuard's source. A signed SSID helper and its permission flow have not been
tested on this machine (macOS 27.2).

The requested behavior is a directed dependency: when `10.66.77.0/24` is
directly connected, also take `192.168.188.1/32` out of this connection's VPN
routing. The other AllowedIPs, `192.168.168.0/24` and `100.64.1.0/24`, should
continue through the tunnel. Leaving the LAN restores the dependent route.
This assumes the LAN router can reach the dependent address; NAT alone does
not tell the Mac which destinations belong to that LAN.

The recommended first step is explicit local-network rules using the existing
LAN detector. SSID, gateway identity and probes can later provide additional
conditions to the same rule evaluator.

The current implementation provides useful integration points:

| Component | Current behavior | Proposed extension |
| --- | --- | --- |
| `src/userspace_helper/macos/system.rs`, `macos_connected_subnets_by_device` | Reads interface addresses; excludes the tunnel, loopback and point-to-point interfaces; requires UP | Retain device identity and distinguish a failed read from a valid empty snapshot; establish link/service eligibility for rule anchors |
| `src/userspace_helper/macos/routes.rs`, `macos_desired_routes` | Omits tunnel routes wholly contained in a directly connected subnet | Apply explicit dependent-prefix exclusions separately from real connected subnets |
| `src/userspace_helper/macos/routes.rs`, `macos_reconcile_routes` | Reconciles after the network fingerprint changes | Include rule revision, matching evidence and effective exclusions in change detection |
| `src/userspace_helper/macos/dns_plan.rs` and `dns.rs` | Withdraws tunnel DNS if any configured resolver lies in a directly connected subnet | Extend the same decision to dependent destinations in both DNS modes |
| `src/userspace_helper/mod.rs`, `wait_for_shutdown` | Serializes route and DNS reconciliation on a three-second interval | Evaluate one network snapshot and policy result for both consumers |
| `src/privileged/connection_store.rs`, `StoredConnection` | Stores connection configuration and wgd-specific options | Persist per-connection rules with backward-compatible defaults |
| `src/userspace_helper/macos/overview.rs`, `status_model.rs` | Explains direct LAN exclusions and reports live routing | Explain the matching rule, physical interface, dependent destination and actual routing outcome |

The current interface detector is a heuristic, not a complete inventory of
physical interfaces. It also does not check link status separately from UP.
A rule must not activate merely because a disconnected interface retains an
address or a virtual interface happens to use the same prefix.

Apple's SSID restrictions are narrower than “macOS prohibits APIs from reading
the Wi-Fi name.” Apple DTS says that SSID/BSSID access requires Location
authorization, which a LaunchDaemon cannot acquire. Its recommended design
uses an agent in a logged-in user session with that authorization. This makes
SSID-based behavior dependent on a user session and granted permission.
[Apple DTS](https://developer.apple.com/forums/thread/759044)

The event mechanism is real: register `CWEventType.ssidDidChange` through
`CWWiFiClient.startMonitoringEvent(with:)`; the delegate receives
`ssidDidChangeForWiFiInterface(withName:)`. That callback supplies the interface
name, such as `en0`. The SSID still requires a separate `ssid()` or `ssidData()`
read. Events therefore do not bypass the privacy restriction.
[Apple callback documentation](https://developer.apple.com/documentation/corewlan/cweventdelegate/ssiddidchangeforwifiinterface(withname:))

Apple's monitoring documentation also lists the `com.apple.wifi.events`
entitlement. Availability and signing behavior should be checked in a small
signed prototype before committing to that notification path. This entitlement
is not a substitute for Location authorization.
[Apple monitoring documentation](https://developer.apple.com/documentation/corewlan/cwwificlient/startmonitoringevent(with:))

An alternative notification source is `SCDynamicStoreSetNotificationKeys` for
network state changes. It can trigger a fresh snapshot without exposing a
protected SSID. The existing three-second reconciliation remains a useful
fallback; specific CoreWLAN callbacks can later handle SSID-only changes.
[Apple dynamic-store notifications](https://developer.apple.com/documentation/systemconfiguration/scdynamicstoresetnotificationkeys(_:_:_:))

WireGuard.app installs `NEOnDemandRuleConnect` and `NEOnDemandRuleDisconnect`
with `ssidMatch` on a `NETunnelProviderManager`. The system evaluates these
rules; their operation does not require the app to implement its own SSID
polling loop. Apple's matcher refers to the current primary connected network.
[WireGuard implementation](https://git.zx2c4.com/wireguard-apple/tree/Sources/WireGuardApp/Tunnel/ActivateOnDemandOption.swift),
[Apple ssidMatch](https://developer.apple.com/documentation/networkextension/neondemandrule/ssidmatch)

Those rules control a system-managed VPN. They are not a general callback API
for controlling wgd's existing external helper or selected AllowedIPs. Adopting
that model would require a Network Extension integration. For direct Developer
ID distribution, Apple's packet-tunnel deployment matrix requires system
extension packaging; the app-extension form is App Store only on macOS.
[Apple deployment matrix](https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment)

The options differ mainly in how they identify the local network:

| Option | How it works | Benefits | Limits and relative effort |
| --- | --- | --- | --- |
| Explicit LAN dependency | A real connected subnet activates a list of dependent prefixes | Fits the current architecture; Wi-Fi and Ethernet; works without Location access or a GUI session | Smallest change for explicit split-tunnel destinations; a reused subnet can match elsewhere |
| Network fingerprint | Require the subnet plus gateway identity, DHCP information or another stable attribute | Reduces accidental matches without reading the SSID | Medium effort; router replacements, missing neighbor entries and DHCP changes need defined behavior; not cryptographic authentication |
| SSID helper | Signed user-session app obtains Location authorization, reads CoreWLAN and reports observations | Familiar Wi-Fi-name rules; permits several SSIDs for one site | Medium to high effort; permission, app lifecycle, IPC and stale observations; Wi-Fi only |
| Local service probe | Contact a known service through the physical network, optionally verifying a pinned TLS identity | Can identify the site across different subnets and SSIDs | Medium to high effort; service outages, timeout policy and path selection matter |
| macOS network location / manual site profile | User selects a named network location or wgd site profile | Simple deterministic override without SSID access | Selection is a user action, not automatic physical-site detection |
| Native VPN On Demand | Move VPN management into Network Extension and use system SSID rules | Closest to WireGuard.app's whole-tunnel behavior | Largest architectural and packaging change; not justified solely by this example |

DHCP metadata has a documented access path through
`SCDynamicStoreCopyDHCPInfo` and `DHCPInfoGetOptionData`. Prefer underlying
per-service DHCP information over effective system DNS, which wgd may itself
have changed. A gateway MAC is the router's local link-layer identity, not
necessarily the access point's BSSID; it should only be an optional condition.
[Apple DHCP API](https://developer.apple.com/documentation/systemconfiguration/scdynamicstorecopydhcpinfo-apicollection)

For a probe, an ordinary ping to the VPN target is circular: its successful
response may have arrived through the tunnel. Bind the probe to the selected
physical interface, verify its actual path, use bounded timeouts and avoid
resolving its name through tunnel DNS. Apple's Network framework exposes
`NWParameters.requiredInterface` for interface constraints. A pinned response
proves service identity; the physical path constraint establishes local access.
[Apple interface constraint](https://developer.apple.com/documentation/network/nwparameters/requiredinterface)

The macOS network service name (often “Wi-Fi”) identifies configuration, not
the currently joined SSID. A network location is also a configured set with a
user-specified name. Both are available through System Configuration, but
neither by itself provides automatic site identification.
[Apple network configuration APIs](https://developer.apple.com/documentation/systemconfiguration/scnetworkconfiguration)

The proposed rule for the example is connection metadata, illustrated as JSON:

```json
{
  "name": "zuhause",
  "when": { "connected_subnet": "10.66.77.0/24" },
  "bypass": ["192.168.188.1/32"],
  "dns": "auto"
}
```

This is a schema sketch. It is not an additional WireGuard `[Peer]` field or
an existing CLI option. Keeping it in the connection store lets a future CLI
manage it without changing the portable WireGuard configuration. Rules should
survive source-config refresh, with revalidation against changed AllowedIPs.
The initial implementation may load rules at connect, like the existing DNS
mode option; runtime rule editing requires explicit helper update plumbing.

The matching semantics should be explicit:

- A connected-subnet condition matches an actual eligible interface's
  canonical subnet. Start with exact prefix equality; do not silently broaden
  the condition to any overlapping private network.
- All conditions within a rule must match on the same interface. Different
  rules provide alternative matches; active bypass destinations are combined.
- Rules are directed. Seeing `10.66.77.0/24` can imply bypassing
  `192.168.188.1/32`; seeing the latter does not imply the former.
- Only observed network facts activate rules. Derived exclusions never become
  new “connected subnet” evidence. A flat list of dependent destinations covers
  several NAT layers without recursive rules, cycles or mutual activation.
- Preserve the matching interface and its gateway. The current global default
  gateway may belong to another simultaneously active network.
- A failed snapshot or unavailable SSID is `Unknown`, not a positive match.
  Do not introduce new exceptions from unknown evidence. Previously matched
  evidence needs bounded validity and must be invalidated by a confirmed
  network/session change, rather than persisting indefinitely.

Expected behavior for the supplied AllowedIPs:

| Destination | Away from the matching LAN | On `10.66.77.0/24` |
| --- | --- | --- |
| `192.168.168.0/24` | VPN | VPN |
| `100.64.1.0/24` | VPN | VPN |
| `10.66.77.0/24` | VPN | Direct LAN, through existing detection |
| `192.168.188.1/32` | VPN | Physical path, through the new dependency |

For this split-tunnel example, removing the host route is sufficient when the
remaining system route already reaches the upstream router through the
matching LAN. That assumption must be validated. With a covering VPN route
such as `192.168.0.0/16` or `0.0.0.0/0`, the destination can still enter the
tunnel after removing its explicit host route. A different primary interface
can also send it through the wrong network.

A general implementation must therefore plan an explicit physical bypass
route via the matching LAN's gateway where necessary. It must handle more
specific routes inside a bypass range, route ownership, address family,
gateway changes and cleanup. It must not delete another connection's routes
or claim success when a foreign route wins. A small first release can instead
restrict support to explicit split-tunnel destinations and reject unsupported
covering-route configurations; unresolved runtime path conflicts must be
visible in status. This scope choice should be made before implementation.

Do not append dependent prefixes to `local_subnets`. The existing route
restoration code treats those as genuinely on-link networks. Pretending that
an upstream router is on-link could produce incorrect neighbor resolution or
route repair. Keep real connected subnets and policy bypasses distinct.

For `dns: auto`, preserve the existing direct-LAN collision rule and extend it
to resolver addresses inside active dependent exclusions. If any configured
tunnel resolver is affected, withdraw the connection's DNS set, matching
today's all-or-nothing behavior. Unrelated resolver addresses retain existing
behavior. An optional future `dns: restore` action can withdraw all tunnel DNS
whenever a site rule matches, regardless of resolver address.

Both DNS implementations must consume that same decision: restore owned
network-service settings in the `networksetup` path; withdraw the synthetic
key in active dynamic-store mode. On departure, establish VPN routes before
publishing VPN DNS again. On arrival, release affected VPN DNS before moving
its destinations to the physical path. Failed mutations must remain pending
for retry and must not be reported as completed solely because the planned
fingerprint was recorded.

The implementation sequence is:

1. Add backward-compatible rule metadata, CIDR validation and connection
   ownership checks across the store/API/CLI. Define the first-release overlap
   scope above. No rules means existing behavior.
2. Build a pure evaluator over one network snapshot. Return matched rules,
   evidence, effective bypass prefixes and DNS decision. Keep initial connect
   and ongoing reconciliation on the same evaluator.
3. Integrate the result into route planning and both DNS paths. Extend change
   detection, retain physical-interface evidence, and handle failed operations
   with retries and truthful applied state.
4. Extend status JSON, CLI and WgdBar with explanations such as
   “192.168.188.1/32 bypassed by zuhause: 10.66.77.0/24 on en0,” including the
   actual gateway or a conflict. Do not report this as a directly connected
   destination or an inexplicably missing tunnel route.
5. Test the transition matrix below. Event-driven reconciliation can follow
   after correctness, with coalesced dynamic-store notifications and the
   existing periodic fallback.
6. If SSIDs are wanted, prototype authorization and event delivery in a signed
   user-session app, then add SSID as another condition. WgdBar is a possible
   UI for permission requests, but quitting the menu must have a defined
   effect. For continuous detection, use an independent user-session helper.

An SSID observer should report only observations over authenticated IPC; the
daemon remains the policy and mutation authority. Include interface identity,
freshness and user-session identity. Permission revocation, helper death,
logout, fast user switching and system-wide connections require explicit
handling. Never keep an old “home SSID” exception after its evidence expires.

Whole-tunnel suspension can be an optional action of the same rule system.
It removes access to all of the connection's remote networks and should use a
separate runtime suppression state, preserving manual disconnect intent and
automatic-start configuration. Its observer must live outside the tunnel
helper: a stopped helper cannot detect that the network changed and restart
itself. That additional lifecycle work is unnecessary for selective bypass.

Meaningful acceptance checks cover:

- Start away, enter the anchor LAN, leave, reconnect while already on it, and
  sleep/wake. All four example prefixes must follow the table above.
- Verify the effective route and a real connection to the upstream target;
  absence of a VPN route alone does not demonstrate working local access.
- Run the same transitions in both DNS modes, with a resolver in the anchor
  subnet, in a dependent prefix, and outside all excluded destinations.
- Exercise two interfaces, a non-primary anchor LAN, gateway changes, stale
  interface addresses, snapshot failures and a second VPN.
- Test covering and nested prefixes, full-tunnel behavior or its deliberate
  rejection, IPv4/IPv6, overlapping rules and shared exclusions.
- Inject route/DNS mutation failures; verify retries, cleanup ownership and
  truthful status. Endpoint pins must remain functional.
- For optional SSID support, test permission granted/denied/revoked, SSID
  changes with unchanged IP configuration, helper restart/logout and stale
  observations.

No runtime networking or application code was changed for this research.
