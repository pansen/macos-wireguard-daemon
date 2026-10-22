//! Typed tunnel status shared by the daemon, the userspace helper and the CLI.
//!
//! These structs are pure data. The helper and the daemon fill them from the
//! live system, `wgd status --json` serializes them as they are, and
//! `status_render` turns them into the text `wgd status` prints.

use serde::{Deserialize, Serialize};

/// `wg show` state of one WireGuard interface.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WgDeviceStatus {
    pub interface: String,
    /// Base64 public key derived from the interface private key; `None` when
    /// the device reports no private key.
    pub public_key: Option<String>,
    /// `None` when the device has no fixed listen port (reported as 0).
    pub listen_port: Option<u16>,
    pub peers: Vec<WgPeerStatus>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WgPeerStatus {
    /// Base64 public key.
    pub public_key: String,
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    pub has_preshared_key: bool,
    /// Absolute Unix seconds of the last handshake; `None` when there was none.
    pub latest_handshake_unix: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// `None` when persistent keepalive is off (reported as 0).
    pub persistent_keepalive_secs: Option<u32>,
}

/// The helper's view of the routes, DNS and neighbouring tunnels of one
/// userspace tunnel.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NetworkOverview {
    pub interface: String,
    pub endpoint: String,
    pub endpoint_pin: bool,
    pub gateway: Option<String>,
    /// Directly connected LAN subnets, e.g. `10.66.77.0/24`.
    pub local_subnets: Vec<String>,
    pub routes: Vec<RouteRow>,
    pub dns: DnsOverview,
    pub system_resolver: SystemResolver,
    pub foreign_tunnels: Vec<ForeignTunnelRow>,
    pub tailscaled_running: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RouteRow {
    pub destination: String,
    pub via: RouteVia,
    pub family: IpFamily,
    pub live: LiveRoute,
    pub outcome: RouteOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpFamily {
    Ipv4,
    Ipv6,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouteVia {
    None,
    Interface {
        name: String,
    },
    Gateway {
        address: String,
    },
    /// Kept off the tunnel because the host sits in that LAN.
    Direct {
        device: Option<String>,
    },
    /// An owned route without interface or gateway.
    System,
}

/// What the kernel routing table holds for the destination right now.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LiveRoute {
    NotProbed,
    Absent,
    Present {
        interface: Option<String>,
        gateway: Option<String>,
        mtu: Option<u32>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouteOutcome {
    EndpointPinned,
    EndpointPinMissing,
    ExcludedLocalSubnet {
        subnet: String,
    },
    Owned,
    OwnedAbsentFromKernel,
    OwnedKernelDisagrees,
    /// A foreign route table entry keeps the prefix off the tunnel. `holder`
    /// is the device holding it, `None` for a bare gateway.
    Blocked {
        holder: Option<String>,
    },
    ReconcilePending,
    /// The tunnel has no address of the row's family.
    NoAddressForFamily,
    NoLongerDesired,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsOverview {
    pub tunnel_servers: Vec<String>,
    pub primary_service: Option<String>,
    pub unreachable: Option<DnsCollision>,
    /// DNS is pulled back or held, so no service carries the tunnel resolver.
    pub dormant: bool,
    pub services: Vec<DnsServiceRow>,
}

/// A tunnel DNS server that sits inside a directly connected LAN.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsCollision {
    pub server: String,
    pub local_subnet: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsServiceRow {
    pub service: String,
    pub primary: bool,
    /// `None` when the service has no DNS servers set.
    pub live_dns: Option<Vec<String>>,
    pub owned: bool,
    /// DNS servers saved before wgd took the service over; `None` when empty.
    pub original_dns: Option<Vec<String>>,
    pub status: DnsServiceStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsServiceStatus {
    TunnelDnsActive,
    OwnedPendingReapply,
    AlreadyTunnelDns,
    TargetNotOwned,
    OwnedHeldNoPrimary,
    OwnedPendingRestore,
    StaleTunnelDnsOnLan,
    NotTargeted,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemResolver {
    pub servers: Vec<String>,
    pub state: ResolverState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResolverState {
    Unset,
    MatchesTunnel,
    PartiallyTunnel,
    Foreign,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForeignTunnelRow {
    pub interface: String,
    pub mtu: Option<u32>,
    /// Routable addresses; empty means link-local only.
    pub addresses: Vec<String>,
    /// Carries an address of one of wgd's own stored connections.
    pub own: bool,
    /// Carries a 100.64.0.0/10 address, the Tailscale tailnet signature.
    pub cgnat: bool,
}
