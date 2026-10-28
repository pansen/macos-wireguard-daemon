//! `wgd status`, shared by the `status` command and `wgd doctor`.
//!
//! [`collect_status`] gathers everything from the privileged service into a
//! typed [`StatusReport`]; [`render_status`] turns that report into text and
//! does no I/O of its own. `wgd status --json` prints the report itself.
//! `doctor` uses the same pair, so its report shows exactly what `status`
//! prints. Fetch failures that `status` has always sent to stderr travel in
//! [`StatusReport::diagnostics`]; `doctor` folds them into its report.

use std::fmt::Write;

use serde::Serialize;

use crate::macos_dns;
use crate::privileged_api::{ConnectionId, ConnectionScope, ConnectionSummary, DnsCustodyStatus};
use crate::privileged_client::PrivilegedClient;
use crate::status_model::{NetworkOverview, WgDeviceStatus};
use crate::status_render;
use crate::ui::{self, Component, RenderCtx, Span, Table};

/// Everything `wgd status` shows, as fetched from the privileged service.
#[derive(Debug, Clone, Default, Serialize)]
pub struct StatusReport {
    /// This user's connections first, then the global ones.
    pub connections: Vec<ConnectionSummary>,
    /// One entry per connected interface the caller may inspect, in the
    /// order of `connections`.
    pub details: Vec<ConnectionDetail>,
    /// `None` when the daemon could not report DNS custody; that only costs
    /// the custody notes, so it is not a diagnostic.
    pub dns_custody: Option<DnsCustodyStatus>,
    /// Best-effort fetches that failed, one line each. `status` prints them to
    /// stderr, or includes them in the JSON with `--json`.
    pub diagnostics: Vec<String>,
}

/// Live detail of one connected interface. Both parts are best-effort and
/// `None` when there is nothing to show or the fetch failed.
#[derive(Debug, Clone, Serialize)]
pub struct ConnectionDetail {
    pub connection_id: ConnectionId,
    pub interface: String,
    /// `wg show` state of the tunnel.
    pub wg: Option<WgDeviceStatus>,
    /// The helper's route/DNS overview.
    pub network_overview: Option<NetworkOverview>,
}

/// `wgd status`: built entirely from the privileged connection store --
/// this user's own connections plus every global one (global connections
/// have no owner to match `Mine`, so it's fetched as a second, disjoint
/// scope and appended). With `json`, prints the whole report, diagnostics
/// included, as JSON instead of text.
pub fn cmd_status(json: bool) -> anyhow::Result<()> {
    let report = collect_status(&PrivilegedClient::new())?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print!("{}", render_status(&report, &RenderCtx::stdout()));
        for line in &report.diagnostics {
            eprintln!("{line}");
        }
    }
    // Stderr only, so stdout stays parseable. `doctor` reports the same
    // condition in its own session agent section instead.
    if let Some(warning) = session_agent_warning(&report.connections) {
        eprintln!("{}", ui::warning(&warning));
    }
    Ok(())
}

/// Warning for per-user `Automatic` connections of the caller (the `sudo`
/// invoker under root) whose session agent is not loaded, `None` when all is
/// well. Read-only: it never installs or enables anything.
fn session_agent_warning(connections: &[ConnectionSummary]) -> Option<String> {
    let (uid, home) = crate::session_agent::target_user()?;
    let names: Vec<String> = crate::session_agent::agent_dependents(connections, uid)
        .iter()
        .map(|conn| conn.label())
        .collect();
    if names.is_empty() {
        return None;
    }
    let state = crate::session_agent::agent_state(uid, &home);
    (state != crate::session_agent::AgentState::Loaded).then(|| {
        format!(
            "Warning: {}",
            crate::session_agent::agent_problem_message(state, &names)
        )
    })
}

/// `wgd status --dns`: the live DNS servers of every macOS network service,
/// as `make check` used to print with `networksetup -getdnsservers`.
pub fn print_service_dns() {
    let mut out = String::new();
    let mut diag = String::new();
    render_service_dns(&RenderCtx::stdout(), &mut out, &mut diag);
    println!();
    print!("{out}");
    eprint!("{diag}");
}

/// Fetch everything `wgd status` shows. Only listing the connections can
/// fail; the per-interface detail and DNS custody are best-effort.
pub fn collect_status(client: &PrivilegedClient) -> anyhow::Result<StatusReport> {
    let is_root = nix::unistd::geteuid().is_root();
    let connections = if is_root {
        let all = client.list_connections(ConnectionScope::All)?;
        let sudo_uid = std::env::var("SUDO_UID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .filter(|&uid| uid != 0);
        select_root_status_connections(all, sudo_uid)
    } else {
        let mut connections = client.list_connections(ConnectionScope::Mine)?;
        connections.extend(client.list_connections(ConnectionScope::Global)?);
        connections
    };

    // Per-connected-interface detail: the WireGuard tunnel state from
    // `wg show`, and the live route/DNS overview. Both live behind the
    // privileged service and are best-effort: a fetch failure becomes a
    // diagnostic but never fails `status`. A non-root caller is denied these
    // two calls for a *global* connection by the daemon's own
    // `legacy_interface_access_denied` (global detail is root-only, matching
    // every other global mutation/read), so skip them here rather than
    // reporting an `Auth` error for every global connection on every plain
    // `wgd status` a non-admin user runs.
    let mut details = Vec::new();
    let mut diagnostics = Vec::new();
    for conn in connections
        .iter()
        .filter(|c| c.connected && (is_root || !c.global))
    {
        let wg = match client.wg_show(&conn.interface) {
            Ok(device) => Some(device),
            Err(e) => {
                diagnostics.push(format!("wg show {} failed: {}", conn.interface, e));
                None
            }
        };
        let network_overview = match client.network_overview(&conn.interface) {
            Ok(overview) => overview,
            Err(e) => {
                diagnostics.push(format!(
                    "network overview for {} unavailable: {}",
                    conn.interface, e
                ));
                None
            }
        };
        details.push(ConnectionDetail {
            connection_id: conn.id,
            interface: conn.interface.clone(),
            wg,
            network_overview,
        });
    }

    // An older daemon that does not know the request, or a failed call, only
    // costs the custody notes.
    let dns_custody = client
        .list_dns_custody()
        .inspect_err(|e| tracing::debug!(error = %e, "dns_custody_status_unavailable"))
        .ok();

    Ok(StatusReport {
        connections,
        details,
        dns_custody,
        diagnostics,
    })
}

/// Render the stdout part of `wgd status`. Diagnostics are left to the
/// caller, which sends them to stderr (`status`) or into its report (`doctor`).
pub fn render_status(report: &StatusReport, ctx: &RenderCtx) -> String {
    let now_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    render_status_at(report, now_unix, ctx)
}

/// [`render_status`] with the current time given, so handshake ages are
/// reproducible.
fn render_status_at(report: &StatusReport, now_unix: u64, ctx: &RenderCtx) -> String {
    let mut out = String::new();
    if report.connections.is_empty() {
        let _ = writeln!(
            out,
            "No stored connections. Add one with: wgd connection add --file <path>"
        );
    } else {
        connection_table(&report.connections).render(ctx, &mut out);
        for detail in &report.details {
            if let Some(device) = &detail.wg {
                let _ = writeln!(out);
                let _ = writeln!(
                    out,
                    "{}",
                    status_render::render_wg_device(device, now_unix, ctx)
                );
            }
            if let Some(overview) = &detail.network_overview {
                let _ = writeln!(out);
                let _ = writeln!(
                    out,
                    "{}",
                    status_render::render_network_overview(overview, ctx)
                );
            }
        }
    }
    if let Some(custody) = &report.dns_custody {
        let notes = crate::connection_cli::format_dns_custody_notes(custody);
        if !notes.is_empty() {
            let _ = writeln!(out);
            for note in notes {
                note.render(ctx, &mut out);
            }
        }
    }
    out
}

fn connection_table(connections: &[ConnectionSummary]) -> Table {
    let mut table = Table::new(&["Id", "Name", "Global", "Mode", "Connected", "Interface"]);
    for conn in connections {
        table.row(vec![
            Span::plain(conn.id.to_string()),
            Span::plain(conn.name.clone().unwrap_or_else(|| "-".to_string())),
            Span::plain(conn.global.to_string()),
            Span::plain(format!("{:?}", conn.start_mode)),
            Span::plain(conn.connected.to_string()),
            Span::plain(conn.interface.as_str()),
        ]);
    }
    table
}

/// The live DNS servers of every macOS network service, one row each.
pub fn render_service_dns(ctx: &RenderCtx, out: &mut String, diag: &mut String) {
    let _ = writeln!(out, "DNS per network service:");
    let services = match macos_dns::list_network_services() {
        Ok(services) => services,
        Err(e) => {
            let _ = writeln!(diag, "  listing network services failed: {e:#}");
            return;
        }
    };
    let mut table = Table::new(&["Service", "DNS servers"]).indent(2);
    for service in services {
        let servers = match macos_dns::get_dns_servers(&service) {
            Ok(Some(servers)) => servers.join(" "),
            Ok(None) => "(dhcp/default)".to_string(),
            Err(e) => format!("(failed: {e:#})"),
        };
        table.row(vec![Span::plain(service), Span::plain(servers)]);
    }
    table.render(ctx, out);
}

/// Under `sudo` (including the root child `wgd doctor` spawns), the socket
/// peer has UID 0, so `ConnectionScope::Mine` would match `owner_uid == Some(0)`
/// and miss every per-user connection of the invoking user. Filter `All` to
/// the invoking user's connections (`SUDO_UID`) plus globals (or keep all
/// connections when `SUDO_UID` is absent), preserving the per-user-then-global
/// ordering of the unprivileged path.
fn select_root_status_connections(
    all: Vec<ConnectionSummary>,
    sudo_uid: Option<u32>,
) -> Vec<ConnectionSummary> {
    let (mut per_user, globals): (Vec<_>, Vec<_>) = all
        .into_iter()
        .filter(|conn| match sudo_uid {
            Some(uid) => conn.global || conn.owner_uid == Some(uid),
            None => true,
        })
        .partition(|conn| !conn.global);
    per_user.extend(globals);
    per_user
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privileged_api::ConnectionStartMode;
    use crate::status_model::{DnsOverview, ResolverState, SystemResolver};

    fn sample_conn(name: &str, global: bool, owner_uid: Option<u32>) -> ConnectionSummary {
        ConnectionSummary {
            id: ConnectionId::new(),
            global,
            owner_uid,
            start_mode: ConnectionStartMode::Manual,
            name: Some(name.to_string()),
            interface: format!("wg-{name}"),
            connected: true,
            user_disconnected: false,
            addresses: vec![],
            dns_servers: vec![],
            mtu: None,
            peers: vec![],
            fingerprint: None,
            source_path: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn sample_device(interface: &str) -> WgDeviceStatus {
        WgDeviceStatus {
            interface: interface.to_string(),
            public_key: None,
            listen_port: None,
            peers: vec![],
        }
    }

    fn sample_overview(interface: &str) -> NetworkOverview {
        NetworkOverview {
            interface: interface.to_string(),
            endpoint: "203.0.113.7".to_string(),
            endpoint_pin: false,
            gateway: None,
            local_subnets: vec![],
            routes: vec![],
            dns: DnsOverview {
                dynamic_store: None,
                tunnel_servers: vec![],
                primary_service: None,
                unreachable: None,
                dormant: false,
                services: vec![],
            },
            system_resolver: SystemResolver {
                servers: vec![],
                state: ResolverState::Unset,
            },
            foreign_tunnels: vec![],
            tailscaled_running: false,
        }
    }

    #[test]
    fn empty_report_points_at_connection_add() {
        let rendered = render_status(&StatusReport::default(), &RenderCtx::plain());
        assert_eq!(
            rendered,
            "No stored connections. Add one with: wgd connection add --file <path>\n"
        );
    }

    #[test]
    fn report_renders_table_then_detail_per_interface_then_custody_notes() {
        let report = StatusReport {
            connections: vec![sample_conn("office", false, Some(501))],
            details: vec![ConnectionDetail {
                connection_id: ConnectionId::new(),
                interface: "wg-office".to_string(),
                wg: Some(sample_device("wg-office")),
                network_overview: Some(sample_overview("wg-office")),
            }],
            dns_custody: Some(DnsCustodyStatus {
                pending: vec![crate::privileged_api::DnsCustodyEntry {
                    id: None,
                    interface: "wg-office".to_string(),
                    name: None,
                    services: vec!["Wi-Fi".to_string()],
                }],
                ..DnsCustodyStatus::default()
            }),
            diagnostics: vec!["wg show wg-other failed: boom".to_string()],
        };
        let rendered = render_status(&report, &RenderCtx::plain());

        let row = rendered.find("| office |").expect("connection row");
        let wg = rendered
            .find("interface: wg-office\n")
            .expect("wg show block");
        let overview = rendered.find("wgd network overview").expect("overview");
        let custody = rendered.find("not restored yet").expect("custody note");
        assert!(row < wg && wg < overview && overview < custody);
        // Diagnostics belong to stderr, never to the rendered stdout.
        assert!(!rendered.contains("boom"));
    }

    #[test]
    fn detail_is_rendered_from_the_typed_data_at_the_given_time() {
        let mut device = sample_device("wg-office");
        device.peers.push(crate::status_model::WgPeerStatus {
            public_key: "peerkey=".to_string(),
            endpoint: None,
            allowed_ips: vec![],
            has_preshared_key: false,
            latest_handshake_unix: Some(1_000),
            rx_bytes: 0,
            tx_bytes: 2048,
            persistent_keepalive_secs: None,
        });
        let report = StatusReport {
            connections: vec![sample_conn("office", false, Some(501))],
            details: vec![ConnectionDetail {
                connection_id: ConnectionId::new(),
                interface: "wg-office".to_string(),
                wg: Some(device),
                network_overview: None,
            }],
            ..StatusReport::default()
        };
        let rendered = render_status_at(&report, 1_130, &RenderCtx::plain());
        assert!(rendered.contains("  latest handshake: 2 minutes\n"));
        assert!(rendered.contains("  transfer: 0 B received, 2.00 KiB sent\n"));
    }

    #[test]
    fn report_serializes_with_typed_detail_and_diagnostics() {
        let report = StatusReport {
            connections: vec![sample_conn("office", false, Some(501))],
            details: vec![ConnectionDetail {
                connection_id: ConnectionId::new(),
                interface: "wg-office".to_string(),
                wg: Some(sample_device("wg-office")),
                network_overview: Some(sample_overview("wg-office")),
            }],
            dns_custody: None,
            diagnostics: vec!["wg show wg-other failed: boom".to_string()],
        };
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["details"][0]["wg"]["interface"], "wg-office");
        assert_eq!(
            json["details"][0]["network_overview"]["system_resolver"]["state"],
            "unset"
        );
        assert_eq!(json["diagnostics"][0], "wg show wg-other failed: boom");
    }

    #[test]
    fn root_status_selects_sudo_users_per_user_connections_and_globals_in_order() {
        let global = sample_conn("corp", true, None);
        let alice = sample_conn("alice_vpn", false, Some(501));
        let bob = sample_conn("bob_vpn", false, Some(502));

        let selected = select_root_status_connections(
            vec![global.clone(), alice.clone(), bob.clone()],
            Some(501),
        );
        let names: Vec<&str> = selected
            .iter()
            .map(|c| c.name.as_deref().unwrap())
            .collect();
        assert_eq!(names, vec!["alice_vpn", "corp"]);

        let all_for_direct_root = select_root_status_connections(vec![global, alice, bob], None);
        let all_names: Vec<&str> = all_for_direct_root
            .iter()
            .map(|c| c.name.as_deref().unwrap())
            .collect();
        assert_eq!(all_names, vec!["alice_vpn", "bob_vpn", "corp"]);
    }
}
