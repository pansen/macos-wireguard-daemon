# DNS ownership edge cases: concurrent tunnels, crash adoption, location switches

**Status:** proposed
**Scope:** macOS userspace helper DNS reconciler (`src/userspace_helper.rs`)
**Author:** design note

## Background

The macOS helper promotes tunnel DNS by rewriting per-service resolver settings
via `networksetup -setdnsservers`. Ownership is tracked in process memory:
`MacosDnsState.services` holds each owned service together with the captured
original DNS, the reconciler re-asserts or releases ownership on a 3s tick
(`MACOS_RECONCILE_INTERVAL`), and teardown restores exactly the owned list.

Two robustness fixes already landed on this branch:

- a failed or empty `networksetup -listallnetworkservices` no longer
  masquerades as "all services vanished" (which used to `drop` the saved
  originals without restoring, leaking tunnel DNS on disconnect);
- a teardown that reports errors after the tunnel is already dead now prints a
  user-facing warning instead of only a structured log line.

Three remaining findings are **design-level**: they cannot be fixed by
hardening individual code paths, because they stem from the ownership model
itself — original-DNS custody lives in one process's memory, and the unit of
mutation (`networksetup` per-service DNS) is global, shared, current-location
state. This note describes each failure mode and the solution paths known so
far.

## Finding A — two concurrent DNS-promoting tunnels corrupt each other

### Failure mode

tunmux supports multiple simultaneous connections (provider instances plus the
direct slot). Each userspace helper runs its own independent DNS reconciler.
If more than one active config promotes DNS:

1. **Reconciler fight.** Helper A applies DNS `[a]`; helper B applies `[b]`.
   Each sees the other's write as drift on the next tick and re-asserts its
   own servers. System DNS flips every ~3s; logs fill with
   `userspace_helper_dns_reconcile_applied`.
2. **Capture chain leak.** B connects while A owns the primary service, so B
   captures A's tunnel DNS as the "original" (chain: user `X` → A → B).
   Disconnect A first (A restores `X`; B re-asserts `[b]` on its next tick),
   then disconnect B: B faithfully "restores" its saved original — **A's dead
   tunnel DNS**. The system is left pointing at an unreachable resolver after
   every tunnel is down.
3. **Same-DNS wipe.** If both configs carry the *same* DNS list (common with
   one provider), B's capture sees "already tunnel DNS" and adopts with an
   Empty original. Disconnect A then B: B restores Empty, silently wiping a
   user's static DNS `X` to DHCP.

### Solution paths

**A1 — single-owner guard (small, do first).** At connect, detect that another
tunmux tunnel already promotes DNS and refuse to promote for the second one
(connect proceeds; DNS promotion is skipped with a printed warning). Detection
needs a shared marker readable by all helpers, e.g.
`/var/run/wireguard/dns-owner` containing the owning interface + servers,
written on promotion and removed on release/teardown. Stale-marker handling:
the marker includes the helper pid; a dead pid means the marker is stale and
may be claimed (this dovetails with Finding B — see the ledger below). This
kills the fight and the capture chain at the cost of a documented limitation:
only the first DNS-promoting tunnel steers DNS.

**A2 — persistent DNS-custody ledger (the durable design).** Move
original-DNS custody out of helper memory into an on-disk ledger (e.g.
`/var/run/wireguard/dns-ledger.json`, or under
`/Library/Application Support/tunmux/` to survive reboot-cleaned tmpfs):

- On first promotion of a service, record the **true pre-VPN original** once.
- Later promoters push onto a per-service stack instead of capturing the live
  (already-VPN) value as "original".
- Release pops; the *last* DNS-promoting tunnel to exit restores the stack
  bottom — the real original — regardless of disconnect order.
- File locking (flock) serializes the reconcilers' read-modify-write.

The ledger fixes A2/A3 exactly, and because it survives process death it is
also the foundation for Finding B (crash adoption) and Finding C (parked
locations). Cost: schema + locking + lifecycle (when is the ledger considered
abandoned?), and the reconcile tick must consult it before re-asserting.

**A3 — stop mutating per-service DNS entirely (endgame).** The root cause is
that `networksetup -setdnsservers` edits *user-owned, persistent* settings.
macOS supports scoped/supplementary resolvers via the SystemConfiguration
dynamic store (`State:/Network/Service/<id>/DNS` entries, the mechanism behind
`scutil --dns` scoped resolvers — what Tailscale and the WireGuard app use).
Dynamic-store state is owned by the publishing process and evaporates on
process exit, so a crash cannot leak persistent settings and two tunnels
cannot clobber each other's saved originals — there is nothing to save. This
removes all three findings at the root. Cost: it is the largest change (new
privileged capability, different resolution semantics — supplementary match
domains vs. global override — and the existing "DHCP clobber" reconcile logic
becomes unnecessary rather than ported). The in-code `transparent_dns.md`
phase notes point the same direction; that document is not currently in the
repo and should be recovered or rewritten as part of this path.

## Finding B — crash-recovery adoption is narrower than it looks

### Failure mode

After a non-graceful death (SIGKILL, panic, power loss) tunnel DNS is left on
the system. The healing mechanism is adoption at the next connect:
`capture_macos_dns_service` treats a service whose live DNS **exactly equals
this run's tunnel DNS list** as a stray and adopts it with an Empty original.
Two gaps:

1. **Different-config strays are mistaken for user settings.** Reconnecting to
   a different server (different DNS list) captures the stray as the user's
   "original" and re-installs it at teardown — the leak is perpetuated
   forever, now laundered through the restore path.
2. **Only targeted services are examined.** Under `DnsPolicy::PrimaryOnly`,
   a stray on a service that is no longer primary is never looked at. (Even
   `make uninstall/dns` only clears the resolved primary service.)

### Solution paths

**B1 — remember what we ever applied.** Persist every DNS list tunmux applies
(the ledger from A2 covers this; a minimal standalone version is a small
append-only file of applied server lists). Adoption then matches the live DNS
against *any previously applied list*, not just the current config's, and
restores the recorded original — exact recovery instead of the Empty
heuristic. This directly fixes both gaps: recognition no longer depends on the
current config, and a startup sweep can check **all** services against the
recorded set, not just the targeted ones.

**B2 — sweep at privileged-service start.** The privileged daemon starts at
boot; have it (or the first `connect`) run a one-shot reconciliation of every
service against the ledger and heal strays before any tunnel work. Also the
natural home for a future `tunmux doctor`-style command (none exists today).

**B3 — endgame.** Under A3 (dynamic-store resolvers) crash leakage is
impossible by construction; B1/B2 become unnecessary.

## Finding C — network locations make "vanished" ambiguous

### Failure mode

`plan_dns_actions` drops an owned service **without restoring** when it
disappears from `-listallnetworkservices`, on the assumption that a vanished
service was deleted and there is nothing left to restore to. macOS network
locations break that assumption: switching location swaps the whole service
set, but each location's per-service DNS config **persists**. Sequence:

1. Connect in location Office; helper owns "Wi-Fi" (Office) with tunnel DNS.
2. User switches to location Home → Office's services vanish from the current
   listing → reconciler `drop`s the owned entry, discarding the original.
3. Teardown restores nothing for it (`networksetup` can only address the
   *current* location's services anyway).
4. Weeks later the user switches back to Office: its "Wi-Fi" still carries
   tunnel DNS — resurrected leak, with the original DNS long gone.

### Solution paths

**C1 — make the fingerprint location-aware, park instead of drop.** Read the
current location (`networksetup -getcurrentlocation`, or `scutil` prefix
`Setup:/`) and store it in `MacosDnsFingerprint`. When services vanish
*because the location changed*, keep the owned entries **parked** (owned but
inactive) instead of dropping them. A later tick that sees the old location
active again restores or re-asserts; teardown restores parked entries when
their location is current, and otherwise records them for later healing.
`drop` remains correct for a same-location disappearance (a genuinely deleted
service).

**C2 — persist parked entries.** Teardown while the other location is active
cannot restore (wrong location addressable) — without persistence the parked
originals die with the process. Writing parked entries to the ledger (A2)
lets a future run — the B2 startup sweep, or the next connect in that
location — heal on sight.

**C3 — endgame.** Under A3, per-location persistent config is never touched,
so locations stop being a special case.

## Recommended sequencing

1. **A1** single-owner guard — small, immediately removes the worst active
   corruption (the fight and the capture chain).
2. **A2 + B1/B2 + C1/C2** — one coherent piece of work around the persistent
   ledger: exact crash adoption, disconnect-order independence, parked
   location entries, startup sweep. The ledger is the shared foundation; the
   findings are three views of the same custody problem.
3. **A3** dynamic-store scoped resolvers — investigate as the long-term
   replacement; if it lands, most of (2) reduces to migration/cleanup code.
