//! `wgd status`, shared by the `status` command and `wgd doctor`.
//!
//! [`collect_status`] gathers everything from the privileged service into a
//! [`StatusReport`]; [`render_status`] turns that report into text and does no
//! I/O of its own. `doctor` uses the same pair, so its report shows exactly
//! what `status` prints. Fetch failures that `status` has always sent to
//! stderr travel in [`StatusReport::diagnostics`]; `doctor` folds them into
//! its report.

use std::fmt::Write;

use crate::color;
use crate::macos_dns;
use crate::privileged_api::{ConnectionScope, ConnectionSummary, DnsCustodyStatus};
use crate::privileged_client::PrivilegedClient;

/// Everything `wgd status` shows, as fetched from the privileged service.
#[derive(Debug, Clone, Default)]
pub struct StatusReport {
    /// This user's connections first, then the global ones.
    pub connections: Vec<ConnectionSummary>,
    /// One entry per connected interface the caller may inspect, in the
    /// order of `connections`.
    pub details: Vec<ConnectionDetail>,
    /// `None` when the daemon could not report DNS custody; that only costs
    /// the custody notes, so it is not a diagnostic.
    pub dns_custody: Option<DnsCustodyStatus>,
    /// Best-effort fetches that failed, one line each, for stderr.
    pub diagnostics: Vec<String>,
}

/// Live detail of one connected interface. Both parts are best-effort and
/// `None` when there is nothing to show or the fetch failed.
#[derive(Debug, Clone, Default)]
pub struct ConnectionDetail {
    /// `wg show` style tunnel state, without trailing whitespace.
    pub wg_show: Option<String>,
    /// The helper's route/DNS overview, without trailing whitespace.
    pub network_overview: Option<String>,
}

/// `wgd status`: built entirely from the privileged connection store --
/// this user's own connections plus every global one (global connections
/// have no owner to match `Mine`, so it's fetched as a second, disjoint
/// scope and appended).
pub fn cmd_status() -> anyhow::Result<()> {
    let report = collect_status(&PrivilegedClient::new())?;
    print!("{}", render_status(&report));
    for line in &report.diagnostics {
        eprintln!("{line}");
    }
    // Stderr only, so stdout stays parseable. `doctor` reports the same
    // condition in its own session agent section instead.
    if let Some(warning) = session_agent_warning(&report.connections) {
        eprintln!("{}", color::warning(&warning));
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
    render_service_dns(&mut out, &mut diag);
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
        let wg_show = match client.wg_show(&conn.interface) {
            Ok(output) if !output.trim().is_empty() => Some(output.trim_end().to_string()),
            Ok(_) => None,
            Err(e) => {
                diagnostics.push(format!("wg show {} failed: {}", conn.interface, e));
                None
            }
        };
        let network_overview = match client.network_overview(&conn.interface) {
            Ok(overview) => overview.map(|text| text.trim_end().to_string()),
            Err(e) => {
                diagnostics.push(format!(
                    "network overview for {} unavailable: {}",
                    conn.interface, e
                ));
                None
            }
        };
        details.push(ConnectionDetail {
            wg_show,
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
pub fn render_status(report: &StatusReport) -> String {
    let mut out = String::new();
    if report.connections.is_empty() {
        let _ = writeln!(
            out,
            "No stored connections. Add one with: wgd connection add --file <path>"
        );
    } else {
        render_connection_table(&report.connections, &mut out);
        for detail in &report.details {
            if let Some(wg_show) = &detail.wg_show {
                let _ = writeln!(out);
                let _ = writeln!(out, "{}", color::wg_show(wg_show));
            }
            if let Some(overview) = &detail.network_overview {
                let _ = writeln!(out);
                let _ = writeln!(out, "{}", color::tables(overview));
            }
        }
    }
    if let Some(custody) = &report.dns_custody {
        render_dns_custody_notes(custody, &mut out);
    }
    out
}

fn render_connection_table(connections: &[ConnectionSummary], out: &mut String) {
    let headers = ["Id", "Name", "Global", "Mode", "Connected", "Interface"];
    let rows: Vec<[String; 6]> = connections
        .iter()
        .map(|conn| {
            [
                conn.id.to_string(),
                conn.name.clone().unwrap_or_else(|| "-".to_string()),
                conn.global.to_string(),
                format!("{:?}", conn.start_mode),
                conn.connected.to_string(),
                conn.interface.clone(),
            ]
        })
        .collect();

    // Size each column to the widest of its header and cells so long values
    // don't push the table out of alignment.
    let mut widths = headers.map(str::len);
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.len());
        }
    }

    let render_row = |cells: &[String]| {
        cells
            .iter()
            .enumerate()
            .map(|(i, c)| format!("{:<width$}", c, width = widths[i]))
            .collect::<Vec<_>>()
            .join(" | ")
    };

    let header_cells: Vec<String> = headers.iter().map(|h| (*h).to_string()).collect();
    let _ = writeln!(
        out,
        "{}",
        color::table_frame(render_row(&header_cells).trim_end())
    );
    let rule = widths
        .iter()
        .map(|w| "-".repeat(*w))
        .collect::<Vec<_>>()
        .join("-+-");
    let _ = writeln!(out, "{}", color::table_frame(&rule));
    for row in &rows {
        let _ = writeln!(out, "{}", render_row(row).trim_end());
    }
}

/// The live DNS servers of every macOS network service, one per line.
pub fn render_service_dns(out: &mut String, diag: &mut String) {
    let _ = writeln!(out, "DNS per network service:");
    let services = match macos_dns::list_network_services() {
        Ok(services) => services,
        Err(e) => {
            let _ = writeln!(diag, "  listing network services failed: {e:#}");
            return;
        }
    };
    for service in services {
        let servers = match macos_dns::get_dns_servers(&service) {
            Ok(Some(servers)) => servers.join(" "),
            Ok(None) => "(dhcp/default)".to_string(),
            Err(e) => format!("(failed: {e:#})"),
        };
        let _ = writeln!(out, "  {service:<24} {servers}");
    }
}

/// DNS custody state that is not normal; a healthy system renders nothing.
fn render_dns_custody_notes(custody: &DnsCustodyStatus, out: &mut String) {
    let lines = crate::connection_cli::format_dns_custody_notes(custody);
    if !lines.is_empty() {
        let _ = writeln!(out);
        for line in lines {
            let _ = writeln!(out, "{line}");
        }
    }
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
    use crate::privileged_api::{ConnectionId, ConnectionStartMode};

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

    #[test]
    fn empty_report_points_at_connection_add() {
        let rendered = render_status(&StatusReport::default());
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
                wg_show: Some("interface: wg-office".to_string()),
                network_overview: Some("wgd network overview".to_string()),
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
        let rendered = render_status(&report);

        let row = rendered.find("| office |").expect("connection row");
        let wg = rendered.find("wg-office\n\n").expect("wg show block");
        let overview = rendered.find("wgd network overview").expect("overview");
        let custody = rendered.find("not restored yet").expect("custody note");
        assert!(row < wg && wg < overview && overview < custody);
        // Diagnostics belong to stderr, never to the rendered stdout.
        assert!(!rendered.contains("boom"));
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
