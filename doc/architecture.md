# Architecture: how the pieces fit together

**Scope:** the whole `tunmux` binary, all three roles it runs in.

One binary, three roles. Which role a process takes is decided in
`main()` (`src/main.rs:26`) before the CLI is even parsed:

- **helper** if `TUNMUX_GOTATUN_HELPER` is set in the environment
  (`userspace_helper::maybe_run_from_env`, `src/userspace_helper.rs:235`),
- **privileged service** for the hidden `tunmux privileged --serve` subcommand,
- **user CLI** for everything else.

The user CLI never touches routes, DNS, or the WireGuard control socket. It
sends a JSON request to the privileged service over a Unix socket, and the
service either does the work itself or spawns a per-tunnel helper process that
owns the tunnel for its lifetime.

## Processes and the privilege boundary

```mermaid
flowchart TB
    subgraph user["User session (your uid)"]
        CLI["tunmux CLI<br/>main.rs · cli.rs · wgconf::handlers"]
        AGENT["LaunchAgent<br/>me.pansen.tunmux.autoconnect<br/>StartInterval 60s"]
        STATE[("~/.config/tunmux/<br/>connections/*.json<br/>wgconf/profiles/*.conf")]
    end

    subgraph root["Root (system domain)"]
        DAEMON["privileged service<br/>tunmux privileged --serve<br/>privileged::serve"]
        HELPER["gotatun helper (one per tunnel)<br/>TUNMUX_GOTATUN_HELPER=1<br/>userspace_helper"]
        RSTATE[("/Library/Application Support/tunmux/<br/>active-tunnel.json · tunnel-operation.lock")]
        RUN[("/var/run/wireguard/<br/>iface.sock · .tunmux.pid<br/>.tunmux.query.sock")]
    end

    LD["launchd<br/>me.pansen.tunmux.privileged<br/>socket-activated"]

    AGENT -->|"connect --if-missing"| CLI
    CLI -->|"JSON over<br/>ctl.sock (0660 root:tunmux)"| DAEMON
    CLI --> STATE
    LD -.->|"passes listening fd"| DAEMON
    DAEMON -->|"spawn, daemonize"| HELPER
    DAEMON --> RSTATE
    HELPER --> RUN
    DAEMON -->|"reads"| RUN
    HELPER -->|"ifconfig · route · networksetup · scutil"| SYS["macOS network stack"]
```

The boundary is the socket. Everything above it runs as you and is replaceable;
everything below it runs as root and is deliberately small. `trusted_exec`
(`src/trusted_exec.rs`) guards what root is allowed to execute: a fixed
allowlist of tool names, each resolved to an absolute path and validated for
root ownership before the `Command` is built.

## The main types

```mermaid
classDiagram
    class Cli {
        +TopCommand command
        +bool verbose
    }
    class TopCommand {
        <<enum>>
        Wgconf · Connect · Disconnect
        Status · Launchd · Autoconnect
        Reload · Privileged
    }
    class AppConfig {
        +GeneralConfig general
    }
    class ConnectionState {
        +String instance_name
        +String provider
        +String interface_name
        +WgBackend backend
        +String server_endpoint
        +Vec~String~ dns_servers
        +Option~String~ source_path
        +save() / load() / load_all() / remove()
        +lock() File
        +is_live() bool
    }
    class WgBackend {
        <<enum>>
        Userspace
        Kernel
    }
    class PrivilegedClient {
        +gotatun_run()
        +wg_show()
        +network_overview()
        +interface_active()
    }
    class PrivilegedRequest {
        <<enum>>
        GotaTunRun
        LeaseAcquire · LeaseRelease · ShutdownIfIdle
        InterfaceActive · WgShow · NetworkOverview
        +validate() Result
    }
    class PrivilegedResponse {
        <<enum>>
        Unit · Bool · Pid · Text · Error
    }
    class Identity {
        +String interface
        +String config_content
        +Option~u16~ mtu_override
    }
    class RunningDevice {
        +String interface_name
        +String control_interface_name
        +PathBuf control_socket_path
        +Device device
        +CleanupState cleanup
    }

    Cli *-- TopCommand
    ConnectionState --> WgBackend
    PrivilegedClient ..> PrivilegedRequest : sends
    PrivilegedClient ..> PrivilegedResponse : receives
    PrivilegedRequest ..> Identity : GotaTunRun becomes
    Identity --> RunningDevice : realized by a helper
```

`ConnectionState` is the user-side record of a connection, one JSON file per
instance under `~/.config/tunmux/connections/`. `Identity` is the root-side
record, one per host, and the two are deliberately independent: the daemon
never trusts what the CLI claims is running.

## One connect, end to end

This is `tunmux connect wgconf --file home.conf` with the default `userspace`
backend, which is also what the autoconnect agent runs every 60 seconds with
`--if-missing` appended.

```mermaid
sequenceDiagram
    autonumber
    actor U as user / LaunchAgent
    participant M as main.rs
    participant H as wgconf::handlers
    participant CS as ConnectionState
    participant US as wireguard::userspace
    participant PC as PrivilegedClient
    participant T as privileged_client::transport
    participant D as privileged (root)
    participant TS as tunnel_state
    participant HP as gotatun helper (root)
    participant OS as macOS

    U->>M: tunmux connect wgconf --file home.conf
    M->>M: Cli::parse, config::load_config
    M->>M: CommandScopeGuard::begin (lease scope)
    M->>H: dispatch(WgconfCommand::Connect)
    H->>H: resolve_connect_backend -> Userspace
    H->>H: resolve_source: read .conf, canonicalize path

    H->>CS: lock() flock .connection.lock
    H->>CS: direct_connection_active()
    CS->>US: is_interface_active("wgconf0")
    US->>PC: interface_active (retries transport errors)
    PC->>T: connect_or_autostart
    alt socket absent
        T->>D: autostart via sudo / launchd, wait_until_ready
    end
    T->>D: {"kind":"interface_active",...}\n
    D-->>T: {"kind":"bool","value":false}
    US-->>CS: false
    CS-->>H: DirectSlotStatus::Free

    H->>US: up_with_mtu(config_text, "wgconf0", mtu)
    US->>PC: gotatun_run(Up, iface, config, mtu)
    PC->>D: {"kind":"gota_tun_run","action":"Up",...}

    D->>D: validate(), begin_log_capture()
    D->>D: flock tunnel-operation.lock (2s cap)
    D->>TS: connect(record, Identity, socket, start)
    TS->>TS: read active-tunnel.json
    alt record matches identity and socket inode
        TS-->>D: Ok (idempotent no-op)
    else record present but different
        TS-->>D: Err conflict -> "disconnect first"
    else free
        TS->>HP: run_gotatun_up: spawn self with<br/>TUNMUX_GOTATUN_HELPER=1, config in env (base64)
        HP->>HP: daemonize, log to /var/log/tunmux/wgconf0.log
        HP->>OS: TunDevice::from_name, DeviceBuilder + UapiServer
        HP->>OS: apply_wireguard_config (keys, peer, endpoint)
        HP->>OS: configure_network_macos:<br/>ifconfig addr/mtu/up, add routes, set DNS
        HP->>HP: write .tunmux.pid and .tunmux.name
        HP-->>D: parent exits 0 after child signals READY_OK
        D->>D: verify pid alive + executable identity
        TS->>TS: stat socket, write active-tunnel.json atomically
    end
    D-->>PC: log frames {"log":"..."} then {"kind":"unit"}
    PC-->>US: Ok
    US-->>H: interface name

    H->>CS: ConnectionState.save() (atomic write)
    H->>CS: drop connection lock
    H-->>U: "Connected to home.conf [backend: userspace]"

    M->>PC: CommandScopeGuard::drop
    PC->>D: LeaseRelease + ShutdownIfIdle
    Note over HP,OS: helper keeps running:<br/>1s tick, reconcile routes/DNS every 3s,<br/>serves the overview query socket
```

The parts worth noticing:

The daemon, not the CLI, decides whether a tunnel already exists. The CLI's
`--if-missing` only skips its own "already connected" bail; the authoritative
check is `tunnel_state::connect` comparing the requested `Identity` against the
record plus the socket's device, inode, and ctime
(`src/privileged/tunnel_state.rs:40`). A config that differs by so much as
whitespace is a conflict, not a reconnect.

Log output flows backwards over the same connection. Before dispatching a
`GotaTunRun` the daemon starts a capture (`logging::begin_log_capture`) and
notes the helper log's size and inode; afterwards it merges its own captured
lines with the new tail of the helper log by timestamp and writes them as
`{"log": "..."}` frames ahead of the response frame
(`src/privileged/mod.rs:215`). The client prints those to stderr and only
returns on the response frame (`read_framed_response`,
`src/privileged_client/transport.rs`). That is why `tunmux reload -v` shows you
what the root side actually did.

## Command dispatch

```mermaid
flowchart LR
    MAIN["main()"] --> HELPERCHK{"TUNMUX_GOTATUN_HELPER<br/>set?"}
    HELPERCHK -->|yes| UH["userspace_helper::maybe_run_from_env"]
    HELPERCHK -->|no| PARSE["Cli::parse"]

    PARSE --> PRIV["Privileged --serve<br/>privileged::serve / serve_stdio"]
    PARSE --> STATUS["Status<br/>cmd_status (sync, no tokio)"]
    PARSE --> LAUNCHD["Launchd<br/>launchd::dispatch"]
    PARSE --> AUTO["Autoconnect<br/>autoconnect::dispatch"]
    PARSE --> RT["everything else:<br/>tokio runtime + CommandScopeGuard"]

    RT --> WGCONF["Wgconf / Connect / Disconnect<br/>wgconf::handlers::dispatch"]
    RT --> RELOAD["Reload<br/>reload::run"]

    WGCONF --> OPS["shared::connection_ops"]
    RELOAD --> WGCONF
    RELOAD --> AUTO
    RELOAD -.->|"sudo self"| LAUNCHD
```

`Status`, `Launchd`, and `Autoconnect` are synchronous and skip the tokio
runtime and the lease scope entirely, because none of them holds a privileged
session open. `reload::run` is unusual in that it calls three other commands in
sequence and re-executes the binary under `sudo` for the one step that needs
root (`src/reload.rs:52`).

`shared::connection_ops` holds the logic every provider-scoped command shares:
backend resolution, the disconnect fan-out (single instance, all of a provider,
all providers), and `direct_connection_active`, which clears stale state left
by a reboot instead of letting it wedge future connects.

## Backends

Both backends terminate at the same daemon and the same embedded gotatun
engine. What differs is what config they send with the `GotaTunRun` request.

```mermaid
flowchart TB
    H["wgconf::handlers::connect_direct"] --> B{"WgBackend"}

    B -->|Userspace| U["wireguard::userspace::up_with_mtu<br/>config passed through verbatim"]
    B -->|Kernel| K["wireguard::kernel::up<br/>parse -> WgConfigParams -> generate_config"]

    K --> U2["userspace::up_raw"]
    U --> GR["PrivilegedClient::gotatun_run"]
    U2 --> GR

    GR --> D1["dispatch: GotaTunRun"]
    D1 --> RG["commands::run_gotatun_up<br/>spawns the helper directly"]
    RG --> ENG["gotatun engine in a helper process"]
```

`kernel` is a misnomer inherited from Linux: macOS has no in-kernel WireGuard,
so `wireguard::kernel::up` regenerates a minimal config from the parsed one and
hands it to the same userspace path (`src/wireguard/kernel.rs:15`). Neither
backend needs externally installed tools; `trusted_exec` only ever resolves a
fixed set of system binaries.

`ConnectionState::is_live()` collapses back to one probe for all three: ask the
daemon whether `/var/run/wireguard/<iface>.sock` exists. A local `exists()`
would be permission-blind, since that directory is `0750 root:daemon`, and the
false negative used to drive a reconnect storm from the autoconnect agent
(`src/wireguard/userspace.rs:73`).

## Inside the privileged service

```mermaid
flowchart TB
    subgraph serve["privileged::serve"]
        ACT{"launchd socket<br/>activation?"}
        ACT -->|yes| FD["adopt inherited fd,<br/>chmod 0660, chown :tunmux"]
        ACT -->|no| BIND["bind ctl.sock itself"]
        FD --> LOOP
        BIND --> LOOP
    end

    LOOP["socket::serve<br/>nonblocking accept loop<br/>max 32 clients, 10s deadline"]
    LOOP --> PRP["process_request_payload"]
    PRP --> VAL["PrivilegedRequest::validate<br/>interface name, provider, mtu, token"]
    VAL --> CAP["gotatun_capture_for<br/>(log capture starts here)"]
    CAP --> DISP["dispatch"]

    DISP --> MUT{"mutating<br/>request?"}
    MUT -->|"GotaTunRun"| LOCK["flock tunnel-operation.lock<br/>2s, else Busy"]
    MUT -->|no| SKIP[" "]
    LOCK --> TS["tunnel_state::connect / clear"]
    TS --> CMD["commands::run_*"]
    SKIP --> CMD

    DISP --> CTRL["LeaseAcquire / LeaseRelease / ShutdownIfIdle<br/>-> ControlState"]
    CMD --> FIN["finish_gotatun_capture<br/>merge service lines + helper log tail"]
    FIN --> ENC["encode_response_frames<br/>log frames, then response"]
    CTRL --> ENC
```

The accept loop and the dispatcher share a thread, which is why the mutation
lock is bounded: an unbounded `flock` there would freeze every unrelated client
behind one slow tunnel operation, so a contended lock returns a `Busy` error
instead (`src/privileged/dispatch.rs:16`).

Lifetime is controlled by `ControlState`. Clients acquire a lease for the
duration of a command scope (`CommandScopeGuard`, `src/privileged_client/mod.rs:58`)
and release it on drop, followed by `ShutdownIfIdle`. The daemon exits only if
it was autostarted, shutdown was requested, and no live lease remains;
`prune_stale_leases` drops tokens whose owning process died.

There is a second transport, `stdio`, selected by config. It spawns a dedicated
daemon per caller over stdin/stdout instead of connecting to the shared socket.
Both paths reach the same `dispatch` and share the same on-disk lock, so a
stdio daemon cannot take over a tunnel a socket daemon owns.

## Inside the helper

One helper process per tunnel. It is spawned by the daemon, daemonizes, and
then owns the tunnel until its UAPI socket is removed or it is signalled.

```mermaid
flowchart TB
    START["maybe_run_from_env<br/>interface from argv, config from env (base64)"]
    START --> DAEMONIZE["daemonize; child signals READY_OK/ERR<br/>over a UnixDatagram pair"]
    DAEMONIZE --> LOGF["logging::init_file_sync<br/>/var/log/tunmux/iface.log"]
    LOGF --> SD["start_device"]

    SD --> TUN["TunDevice::from_name -> utunN"]
    SD --> UAPI["UapiServer::default_unix_socket<br/>/var/run/wireguard/iface.sock"]
    SD --> DEV["DeviceBuilder: uapi + udp + ip"]
    SD --> CFG["apply_wireguard_config: keys, peer, endpoint"]
    SD --> NET["configure_network_macos"]

    NET --> ADDR["ifconfig: mtu, addresses, up, -rxcsum -txcsum"]
    NET --> FP["macos_current_fingerprint"]
    NET --> ROUTES["macos_desired_routes -> add_macos_route"]
    NET --> DNS["configure_macos_dns"]

    SD --> RD["RunningDevice { device, cleanup: CleanupState::Macos(Arc) }"]
    RD --> QS["spawn_overview_query_server<br/>iface.tunmux.query.sock"]
    RD --> WAIT["wait_for_shutdown: 1s tick"]

    WAIT -->|"control socket gone,<br/>SIGINT or SIGTERM"| TEAR["cleanup_network_macos:<br/>delete routes, restore DNS"]
    TEAR --> STOP["device.stop() (5s timeout)"]
    STOP --> STATUS["write iface.tunmux.cleanup, remove pid/name/socket"]
```

Teardown is a handshake, not a kill. `run_gotatun_down` removes the UAPI socket,
which the helper's tick loop reads as a shutdown request, then waits up to 15
seconds for the helper to write `ok` into its cleanup-status file, falling back
to `SIGTERM` and a further 5 seconds. Only after a confirmed `ok` does it check
that the `utunN` interface is really gone (`src/privileged/commands.rs`, `run_gotatun_down`).

## Continuous reconciliation

This is the part that makes the tunnel survive roaming. Every 3 seconds the
helper re-snapshots the network and, if anything moved, re-applies routes and
DNS.

```mermaid
classDiagram
    class MacosCleanupState {
        +Mutex~MacosRoutingState~ routing
        +Mutex~MacosDnsState~ dns
        +MacosReconcileInputs reconcile
    }
    class MacosRoutingState {
        +Vec~MacosRoute~ routes_added
        +MacosNetworkFingerprint fingerprint
    }
    class MacosDnsState {
        +Vec~MacosDnsServiceState~ services
        +MacosDnsFingerprint fingerprint
    }
    class MacosReconcileInputs {
        +String interface
        +IpAddr endpoint
        +bool endpoint_needs_pin
        +Vec~String~ allowed_ips
        +Vec~String~ dns_servers
    }
    class MacosNetworkFingerprint {
        +Vec~(IpAddr,u8)~ local_subnets
        +Option~String~ endpoint_gateway
    }
    class MacosDnsFingerprint {
        +Option~String~ primary_service
        +Vec~String~ services
        +Vec~(String,Option~Vec~String~~)~ observed
    }
    class MacosDnsServiceState {
        +String service
        +Option~Vec~String~~ dns_servers
        +Option~Vec~String~~ search_domains
    }

    MacosCleanupState *-- MacosRoutingState
    MacosCleanupState *-- MacosDnsState
    MacosCleanupState *-- MacosReconcileInputs
    MacosRoutingState *-- MacosNetworkFingerprint
    MacosDnsState *-- MacosDnsFingerprint
    MacosDnsState *-- MacosDnsServiceState
```

Both reconcilers follow the same shape: snapshot the environment into a
fingerprint, compare it to the stored one, and act only on a difference. Both
run on `spawn_blocking` via `run_macos_maintenance`, awaited so ticks cannot
overlap and teardown cannot race a worker mid-change, and so the shelling out
to `ifconfig`/`scutil`/`networksetup` never stalls the single-threaded runtime
that is also moving packets.

Routes: `macos_desired_routes` is the endpoint pin (only when AllowedIPs would
otherwise capture the endpoint) plus the AllowedIPs routes, minus anything that
falls inside a directly-connected subnet. That subtraction is what keeps the
split tunnel from hijacking the LAN you are actually on.

The subtraction alone is not enough, because a prefix can only hold one entry.
Joining a LAN the tunnel already routes (roaming into a subnet that is also in
AllowedIPs) means the kernel cannot install that interface's connected route,
and the tunnel route it lost out to is removed on the next reconcile, leaving
the LAN with no route at all. Two rules close that gap. `add_macos_route`
checks who holds a prefix before touching it, clearing a stale entry only when
a tunnel device owns it and otherwise leaving the prefix alone and unowned, and
`macos_restore_shadowed_lan_route` re-adds the connected route, scoped to its
device, whenever removing a tunnel route leaves a local subnet uncovered.

DNS: `plan_dns_actions` is deliberately I/O-free and therefore unit-testable. It
takes the tunnel's DNS, the observed environment, the services currently owned,
and the services that should be owned, and returns what to apply, restore, or
drop. Under the active `PrimaryOnly` policy only the service owning global
resolution gets tunnel DNS. `dns_reconcile_forced` handles the case a
fingerprint cannot see: a DHCP-provided resolver on a LAN that shadows the
tunnel's own DNS server address, where nothing observable changes but ownership
still has to move.

## Locks and state files

```mermaid
flowchart LR
    subgraph userstate["User side"]
        CLK[".connection.lock<br/>flock, unbounded"]
        CJSON["connections/&lt;instance&gt;.json<br/>write_atomic 0600"]
    end
    subgraph rootstate["Root side"]
        MLK["tunnel-operation.lock<br/>flock, 2s bounded"]
        ATJ["active-tunnel.json<br/>identity + socket dev/ino/ctime"]
        SLK["startup lock<br/>serializes daemon autostart"]
    end
    subgraph runtime["/var/run/wireguard"]
        SOCK["&lt;iface&gt;.sock (UAPI)"]
        PID["&lt;iface&gt;.tunmux.pid"]
        NAME["&lt;iface&gt;.tunmux.name"]
        CLEAN["&lt;iface&gt;.tunmux.cleanup"]
        QRY["&lt;iface&gt;.tunmux.query.sock"]
    end

    CLK -->|"held across probe,<br/>bring-up, commit"| CJSON
    MLK -->|"held across identity check,<br/>mutation, commit"| ATJ
    ATJ -.->|"binds to"| SOCK
    PID -.->|"pid + executable check"| SOCK
    CLEAN -.->|"teardown handshake"| SOCK
```

`state_file` (`src/state_file.rs`) provides both primitives: `lock` /
`lock_with_timeout` over `flock` with `O_NOFOLLOW`, and `write_atomic`, which
writes a randomly named temp file at mode 0600 and renames it into place. Every
piece of state on both sides of the boundary goes through those two functions.

## Status

`tunmux status` is read-only and pulls from three places at once.

```mermaid
sequenceDiagram
    participant S as cmd_status
    participant CS as ConnectionState
    participant PC as PrivilegedClient
    participant D as privileged
    participant HP as helper

    S->>CS: load_all(), filter by is_live()
    CS->>PC: interface_active per connection
    Note over S: a live wgconf0 with no state file is<br/>still listed, as an adopted "_direct" row
    S->>S: render the summary table (color::table_frame)
    loop per connection
        S->>PC: wg_show(iface)
        PC->>D: WgShow
        D->>D: UAPI get=1 over iface.sock, format_wg_show
        D-->>S: text (color::wg_show)
        opt userspace backend
            S->>PC: network_overview(iface)
            PC->>D: NetworkOverview
            D->>HP: connect iface.tunmux.query.sock
            HP-->>D: freshly rendered route/DNS table
            D-->>S: text (color::tables)
        end
    end
```

Both detail fetches are best-effort: a failure prints to stderr and never makes
`status` fail. The overview exists only in the helper's memory, so the query
socket is the only way to see it, and it is proxied through the daemon because
the socket is root-only.

## Installation and lifecycle

```mermaid
flowchart TB
    MAKE["make install"] --> BUILD["cargo build --release<br/>-> /usr/local/bin/tunmux"]
    BUILD --> LI["sudo tunmux launchd install"]
    BUILD --> AI["tunmux autoconnect install --file/--profile"]

    LI --> GRP["ensure_group_with_member: create 'tunmux', add you"]
    LI --> VAL["validate_binary_location:<br/>reject home dirs, require root-owned path"]
    LI --> PL["render plist from etc/…privileged.plist<br/>@TUNMUX_BIN@, @SOCK_PATH_GROUP@"]
    PL --> BOOT["launchctl bootout, enable, bootstrap system/"]

    AI --> APL["render etc/…autoconnect.plist<br/>@TUNMUX_BIN@, @TUNMUX_HOME@,<br/>@CONNECT_FLAG@, @CONNECT_VALUE@"]
    APL --> ABOOT["launchctl bootstrap gui/&lt;uid&gt;<br/>StartInterval 60, LimitLoadToSessionType Aqua"]

    RELOAD["tunmux reload"] --> LI
    RELOAD --> DISC["tunmux disconnect --all"]
    RELOAD --> AI
```

`launchd` handles the root daemon in the system domain; `autoconnect` handles
the per-user agent in the GUI domain. They must not be crossed, which is why
`reload` refuses to run as root and escalates only the daemon step
(`src/reload.rs:80`), and why `autoconnect` has its own `refuse_if_root`.

`autoconnect::reinstall` reads the currently installed plist to recover the
`--file` or `--profile` it was registered with, so `tunmux reload` with no
arguments reconnects the same profile you already had
(`installed_connect_source`, `src/autoconnect.rs`).

## Where to start reading

| Question | File |
| --- | --- |
| What commands exist and what do they take? | `src/cli.rs` |
| What happens for a connect? | `src/wgconf/handlers.rs`, `connect_direct` |
| What crosses the privilege boundary? | `src/privileged_api.rs` |
| How does the client reach root? | `src/privileged_client/transport.rs` |
| What does root actually run? | `src/privileged/commands.rs`, `src/trusted_exec.rs` |
| How is tunnel identity decided? | `src/privileged/tunnel_state.rs` |
| How do routes and DNS stay correct? | `src/userspace_helper.rs`, `macos_reconcile_routes` / `macos_reconcile_dns` |
