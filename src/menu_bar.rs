//! What the menu bar app (`macos/WgdBar`) shows: one verdict over all
//! connections for the icon, plus a line per connection for the flyout.
//!
//! [`snapshot`] fetches through the same [`collect_status`] as `wgd status`;
//! [`from_report`] is the pure part. The app reaches this through the
//! `wgd-bar-ffi` crate and never talks to the privileged daemon itself.

use std::time::Duration;

use crate::privileged_client::PrivilegedClient;
use crate::status::{collect_status, StatusReport};
use crate::status_model::TunnelDnsState;
use crate::status_render::tunnel_dns_status;

/// A wedged daemon must not freeze the menu bar's refresh loop.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// The icon's state. Ordered from best to worst for a connected tunnel;
/// with several connections the best one wins, since a single working
/// tunnel is what "the VPN is active" means to the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Overall {
    /// Tunnel DNS is in effect, or the tunnel sets none and only routes.
    Active,
    /// Tunnel DNS is off because its server sits inside the local LAN.
    PulledBack,
    /// Connected, but tunnel DNS is held or pending, or the caller may not
    /// inspect the tunnel (a global connection seen by a non-root user).
    Inactive,
    /// Connections exist, none is connected.
    Disconnected,
    /// No connections stored.
    NoConnections,
    /// The daemon could not be asked.
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub overall: Overall,
    pub connections: Vec<ConnectionLine>,
    /// Why the daemon could not be asked; set only for `Unavailable`.
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionLine {
    /// The connection's name, or its id when it has none.
    pub title: String,
    pub interface: String,
    pub global: bool,
    pub connected: bool,
    pub state: Overall,
    /// The same text `wgd status` prints in its "Tunnel DNS" table.
    pub detail: String,
}

/// Ask the daemon for the current state. Never fails: an unreachable daemon
/// is a state the icon shows.
pub fn snapshot() -> Snapshot {
    // Without autostart a missing socket fails fast instead of trying to
    // spawn a daemon via `sudo`, which a GUI process cannot answer.
    let client = PrivilegedClient::new()
        .without_autostart()
        .with_request_timeout(REQUEST_TIMEOUT);
    match collect_status(&client) {
        Ok(report) => from_report(&report),
        Err(e) => Snapshot {
            overall: Overall::Unavailable,
            connections: Vec::new(),
            error: Some(format!("{e:#}")),
        },
    }
}

pub fn from_report(report: &StatusReport) -> Snapshot {
    let connections: Vec<ConnectionLine> = report
        .connections
        .iter()
        .map(|conn| {
            let title = conn.name.clone().unwrap_or_else(|| conn.id.to_string());
            let overview = report
                .details
                .iter()
                .find(|d| d.connection_id == conn.id)
                .and_then(|d| d.network_overview.as_ref());
            let (state, detail) = match (conn.connected, overview) {
                (false, _) => (Overall::Disconnected, "disconnected".to_string()),
                (true, None) => (
                    Overall::Inactive,
                    "connected, no detail available".to_string(),
                ),
                (true, Some(ov)) => {
                    let dns_state = ov.dns.tunnel_dns_state();
                    let state = match dns_state {
                        TunnelDnsState::Active | TunnelDnsState::NoServers => Overall::Active,
                        TunnelDnsState::PulledBack(_) => Overall::PulledBack,
                        TunnelDnsState::Held | TunnelDnsState::Pending => Overall::Inactive,
                    };
                    (state, tunnel_dns_status(&ov.dns, &dns_state))
                }
            };
            ConnectionLine {
                title,
                interface: conn.interface.clone(),
                global: conn.global,
                connected: conn.connected,
                state,
                detail,
            }
        })
        .collect();

    let overall = connections
        .iter()
        .map(|line| line.state)
        .min_by_key(|state| *state as u8)
        .unwrap_or(Overall::NoConnections);

    Snapshot {
        overall,
        connections,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privileged_api::{ConnectionId, ConnectionStartMode, ConnectionSummary};
    use crate::status::ConnectionDetail;
    use crate::status_model::{
        DnsCollision, DnsOverview, DnsServiceRow, DnsServiceStatus, NetworkOverview, ResolverState,
        SystemResolver,
    };

    fn conn(name: &str, connected: bool) -> ConnectionSummary {
        ConnectionSummary {
            id: ConnectionId::new(),
            global: false,
            owner_uid: Some(501),
            start_mode: ConnectionStartMode::Automatic,
            name: Some(name.to_string()),
            interface: format!("wg-{name}"),
            connected,
            user_disconnected: false,
            addresses: Vec::new(),
            dns_servers: Vec::new(),
            mtu: None,
            peers: Vec::new(),
            fingerprint: None,
            source_path: None,
            dns_dynamic_store: false,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn overview(dns: DnsOverview) -> NetworkOverview {
        NetworkOverview {
            interface: "wg-home".to_string(),
            endpoint: "203.0.113.1".to_string(),
            endpoint_pin: false,
            gateway: None,
            local_subnets: Vec::new(),
            routes: Vec::new(),
            dns,
            system_resolver: SystemResolver {
                servers: Vec::new(),
                state: ResolverState::Unset,
            },
            foreign_tunnels: Vec::new(),
            tailscaled_running: false,
        }
    }

    fn dns(unreachable: Option<DnsCollision>, status: DnsServiceStatus) -> DnsOverview {
        DnsOverview {
            dynamic_store: None,
            tunnel_servers: vec!["10.66.77.2".to_string(), "100.64.1.1".to_string()],
            primary_service: Some("Wi-Fi".to_string()),
            dormant: unreachable.is_some(),
            unreachable,
            services: vec![DnsServiceRow {
                service: "Wi-Fi".to_string(),
                primary: true,
                live_dns: None,
                owned: true,
                original_dns: None,
                status,
            }],
        }
    }

    fn report(entries: Vec<(ConnectionSummary, Option<NetworkOverview>)>) -> StatusReport {
        let details = entries
            .iter()
            .filter(|(c, _)| c.connected)
            .map(|(c, ov)| ConnectionDetail {
                connection_id: c.id,
                interface: c.interface.clone(),
                wg: None,
                network_overview: ov.clone(),
            })
            .collect();
        StatusReport {
            connections: entries.into_iter().map(|(c, _)| c).collect(),
            details,
            ..Default::default()
        }
    }

    fn collision() -> DnsCollision {
        DnsCollision {
            server: "10.66.77.2".to_string(),
            local_subnet: "10.66.77.0/24".to_string(),
        }
    }

    #[test]
    fn pulled_back_dns_shows_the_status_table_text() {
        let snap = from_report(&report(vec![(
            conn("home", true),
            Some(overview(dns(
                Some(collision()),
                DnsServiceStatus::OwnedPendingRestore,
            ))),
        )]));
        assert_eq!(snap.overall, Overall::PulledBack);
        assert_eq!(
            snap.connections[0].detail,
            "pulled back: 10.66.77.2 is inside local LAN 10.66.77.0/24"
        );
    }

    #[test]
    fn applied_dns_is_active() {
        let snap = from_report(&report(vec![(
            conn("home", true),
            Some(overview(dns(None, DnsServiceStatus::TunnelDnsActive))),
        )]));
        assert_eq!(snap.overall, Overall::Active);
        assert_eq!(snap.connections[0].detail, "active via Wi-Fi");
    }

    #[test]
    fn best_connection_wins() {
        let snap = from_report(&report(vec![
            (conn("off", false), None),
            (
                conn("lan", true),
                Some(overview(dns(
                    Some(collision()),
                    DnsServiceStatus::OwnedPendingRestore,
                ))),
            ),
            (
                conn("home", true),
                Some(overview(dns(None, DnsServiceStatus::TunnelDnsActive))),
            ),
        ]));
        assert_eq!(snap.overall, Overall::Active);
    }

    #[test]
    fn connected_without_detail_is_inactive() {
        let snap = from_report(&report(vec![(conn("global", true), None)]));
        assert_eq!(snap.overall, Overall::Inactive);
    }

    #[test]
    fn nothing_connected_or_stored() {
        let snap = from_report(&report(vec![(conn("home", false), None)]));
        assert_eq!(snap.overall, Overall::Disconnected);
        assert_eq!(
            from_report(&report(Vec::new())).overall,
            Overall::NoConnections
        );
    }
}
