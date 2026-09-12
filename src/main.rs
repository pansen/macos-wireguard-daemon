mod autoconnect;
mod cli;
mod color;
mod config;
mod error;
mod launchctl;
mod launchd;
mod logging;
mod privileged;
mod privileged_api;
mod privileged_client;
mod reload;
mod shared;
mod state_file;
mod trusted_exec;
mod userspace_helper;
mod wgconf;
mod wireguard;

use clap::Parser;
use tracing::error;

use cli::{Cli, ConnectProviderCommand, ProviderArg, TopCommand};
use wireguard::connection::ConnectionState;

fn main() {
    if userspace_helper::maybe_run_from_env() {
        return;
    }

    let cli = Cli::parse();
    if cli.verbose || defaults_to_debug(&cli.command) {
        logging::enable_debug();
    }

    match cli.command {
        // Privileged control server.
        TopCommand::Privileged {
            serve,
            stdio,
            authorized_group,
            idle_timeout_ms,
            autostarted,
        } => {
            // The privileged service captures per-request log output so it can be streamed back
            // to the calling CLI (see logging::begin_log_capture / privileged::process_request).
            logging::init_service(cli.verbose);
            if !serve {
                eprintln!("privileged mode requires --serve");
                std::process::exit(1);
            }
            let run = if stdio {
                privileged::serve_stdio(idle_timeout_ms, autostarted)
            } else {
                privileged::serve(authorized_group, idle_timeout_ms, autostarted)
            };
            if let Err(e) = run {
                eprintln!("privileged service error: {}", e);
                std::process::exit(1);
            }
        }
        // Status is a quick sync command, no tokio needed.
        TopCommand::Status => {
            init_logging(cli.verbose);
            if let Err(e) = cmd_status() {
                error!( command = ?"status", error = ?e.to_string(), "command_failed");
                std::process::exit(1);
            }
        }

        TopCommand::Launchd { command } => {
            init_logging(cli.verbose);
            if let Err(e) = launchd::dispatch(command) {
                error!(command = ?"launchd", error = %format!("{e:#}"), "command_failed");
                std::process::exit(1);
            }
        }

        TopCommand::Autoconnect { command } => {
            init_logging(cli.verbose);
            if let Err(e) = autoconnect::dispatch(command) {
                error!(command = ?"autoconnect", error = %format!("{e:#}"), "command_failed");
                std::process::exit(1);
            }
        }

        // All other commands use the multi-threaded tokio runtime.
        other => {
            init_logging(cli.verbose);
            let config = config::load_config();
            let _command_scope = privileged_client::CommandScopeGuard::begin(
                config.general.privileged_autostop_mode,
            );

            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            if let Err(e) = rt.block_on(run(other, config)) {
                error!( error = ?e.to_string(), "command_failed");
                std::process::exit(1);
            }
        }
    }
}

fn init_logging(verbose: bool) {
    logging::init_terminal(verbose);
}

/// Commands that log at debug level without being asked. `reload` is the one:
/// you run it because something is off, so the daemon and helper detail is the
/// point. `-s` opts back out.
fn defaults_to_debug(command: &TopCommand) -> bool {
    matches!(command, TopCommand::Reload(args) if !args.silent)
}

async fn run(command: TopCommand, config: config::AppConfig) -> anyhow::Result<()> {
    match command {
        TopCommand::Wgconf { command } => wgconf::handlers::dispatch(command, &config).await,
        TopCommand::Connect { provider } => run_connect(provider, &config).await,
        TopCommand::Disconnect {
            instance,
            provider,
            all,
        } => run_disconnect(instance, provider, all, &config).await,
        TopCommand::Reload(args) => reload::run(args, &config).await,
        TopCommand::Status
        | TopCommand::Launchd { .. }
        | TopCommand::Autoconnect { .. }
        | TopCommand::Privileged { .. } => {
            unreachable!()
        }
    }
}

async fn run_connect(
    provider: ConnectProviderCommand,
    config: &config::AppConfig,
) -> anyhow::Result<()> {
    match provider {
        ConnectProviderCommand::Wgconf(args) => {
            wgconf::handlers::dispatch(cli::WgconfCommand::Connect(args), config).await
        }
    }
}

async fn run_disconnect(
    instance: Option<String>,
    provider: Option<ProviderArg>,
    all: bool,
    config: &config::AppConfig,
) -> anyhow::Result<()> {
    if all {
        if let Some(provider) = provider {
            return dispatch_provider_disconnect(provider, None, true, config).await;
        }

        let connections = ConnectionState::load_all()?;
        if connections.is_empty() {
            println!("Not connected.");
            return Ok(());
        }

        for conn in connections {
            let resolved = config::Provider::from_dir_name(&conn.provider).ok_or_else(|| {
                anyhow::anyhow!(
                    "unsupported provider in connection state: {}",
                    conn.provider
                )
            })?;
            dispatch_provider_disconnect(resolved, Some(conn.instance_name), false, config).await?;
        }

        return Ok(());
    }

    if let Some(instance_name) = instance {
        let conn = ConnectionState::load(&instance_name)?
            .ok_or_else(|| anyhow::anyhow!("no connection with instance {:?}", instance_name))?;
        let resolved = config::Provider::from_dir_name(&conn.provider).ok_or_else(|| {
            anyhow::anyhow!(
                "unsupported provider in connection state: {}",
                conn.provider
            )
        })?;

        if let Some(requested) = provider {
            if requested != resolved {
                anyhow::bail!(
                    "instance {:?} belongs to provider {:?}, not {:?}",
                    instance_name,
                    resolved.label(),
                    requested.label()
                );
            }
        }

        return dispatch_provider_disconnect(resolved, Some(instance_name), false, config).await;
    }

    if let Some(provider) = provider {
        return dispatch_provider_disconnect(provider, None, false, config).await;
    }

    let connections = ConnectionState::load_all()?;
    match connections.len() {
        0 => {
            println!("Not connected.");
        }
        1 => {
            let conn = &connections[0];
            let resolved = config::Provider::from_dir_name(&conn.provider).ok_or_else(|| {
                anyhow::anyhow!(
                    "unsupported provider in connection state: {}",
                    conn.provider
                )
            })?;
            dispatch_provider_disconnect(resolved, Some(conn.instance_name.clone()), false, config)
                .await?;
        }
        _ => {
            println!("Multiple active connections. Specify which to disconnect:\n");
            for conn in &connections {
                println!(
                    "  {:<12} {:<9} {}",
                    conn.instance_name, conn.provider, conn.server_display_name
                );
            }
            println!("\nUsage: tunmux disconnect <instance>");
            println!("       tunmux disconnect --provider <provider> --all");
            println!("       tunmux disconnect --all");
        }
    }

    Ok(())
}

async fn dispatch_provider_disconnect(
    provider: ProviderArg,
    instance: Option<String>,
    all: bool,
    config: &config::AppConfig,
) -> anyhow::Result<()> {
    match provider {
        ProviderArg::Wgconf => {
            wgconf::handlers::dispatch(cli::WgconfCommand::Disconnect { instance, all }, config)
                .await
        }
    }
}

fn cmd_status() -> anyhow::Result<()> {
    // Probe liveness across every backend, not just userspace: a reboot/crash
    // leaves stale kernel/wg-quick state behind too, and `is_live()` already
    // knows the right probe per backend.
    let mut connections: Vec<ConnectionState> = ConnectionState::load_all()?
        .into_iter()
        .filter(ConnectionState::is_live)
        .collect();

    let have_wgconf_direct = connections
        .iter()
        .any(|c| c.provider == "wgconf" && c.interface_name == "wgconf0");
    // Use the higher-level probe (not the raw client call) so a cold-starting
    // privileged daemon doesn't make a live wgconf0 tunnel look inactive.
    if !have_wgconf_direct && wireguard::userspace::is_interface_active("wgconf0") {
        connections.push(wireguard::connection::ConnectionState {
            instance_name: wireguard::connection::DIRECT_INSTANCE.to_string(),
            provider: "wgconf".to_string(),
            interface_name: "wgconf0".to_string(),
            backend: wireguard::backend::WgBackend::Userspace,
            server_endpoint: "(unknown)".to_string(),
            server_display_name: "(unknown)".to_string(),
            dns_servers: Vec::new(),
            source_path: None,
        });
    }

    if connections.is_empty() {
        println!("No active connections.");
        return Ok(());
    }

    let headers = ["Instance", "Provider", "Server", "Endpoint", "Backend"];
    let rows: Vec<[String; 5]> = connections
        .iter()
        .map(|conn| {
            [
                conn.instance_name.clone(),
                conn.provider.clone(),
                conn.server_display_name.clone(),
                conn.server_endpoint.clone(),
                conn.backend.to_string(),
            ]
        })
        .collect();

    // Size each column to the widest of its header and cells so long values
    // (e.g. a `.conf` filename in Server) don't push the table out of alignment.
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
    println!(
        "{}",
        color::table_frame(render_row(&header_cells).trim_end())
    );
    let rule = widths
        .iter()
        .map(|w| "-".repeat(*w))
        .collect::<Vec<_>>()
        .join("-+-");
    println!("{}", color::table_frame(&rule));
    for row in &rows {
        println!("{}", render_row(row).trim_end());
    }

    // Beneath the summary table, print per-interface detail: the WireGuard
    // tunnel state from `wg show`, and for userspace tunnels the live route/DNS
    // overview. Both live behind the privileged service (the helper's query
    // socket is root-only), and both are best-effort: a fetch failure prints to
    // stderr but never fails `status`.
    let client = privileged_client::PrivilegedClient::new();
    for conn in &connections {
        match client.wg_show(&conn.interface_name) {
            Ok(output) if !output.trim().is_empty() => {
                println!();
                println!("{}", color::wg_show(output.trim_end()));
            }
            Ok(_) => {}
            Err(e) => eprintln!("wg show {} failed: {}", conn.interface_name, e),
        }

        if conn.backend != wireguard::backend::WgBackend::Userspace {
            continue;
        }
        match client.network_overview(&conn.interface_name) {
            Ok(Some(overview)) => {
                println!();
                println!("{}", color::tables(overview.trim_end()));
            }
            Ok(None) => {}
            Err(e) => eprintln!(
                "network overview for {} unavailable: {}",
                conn.interface_name, e
            ),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::defaults_to_debug;
    use crate::cli::{Cli, ReloadArgs, TopCommand};
    use crate::config;
    use clap::Parser;

    #[test]
    fn reload_logs_at_debug_unless_silenced() {
        assert!(defaults_to_debug(&TopCommand::Reload(ReloadArgs {
            file: None,
            profile: None,
            silent: false,
        })));
        assert!(!defaults_to_debug(&TopCommand::Reload(ReloadArgs {
            file: None,
            profile: None,
            silent: true,
        })));
        assert!(!defaults_to_debug(&TopCommand::Status));
    }

    #[test]
    fn parsed_reload_command_asks_for_debug_logging() {
        let cli = Cli::try_parse_from(["tunmux", "reload"]).expect("parse reload");
        assert!(defaults_to_debug(&cli.command));

        let quiet = Cli::try_parse_from(["tunmux", "reload", "-s"]).expect("parse silent reload");
        assert!(!defaults_to_debug(&quiet.command));
    }

    #[test]
    fn provider_mapping_includes_wgconf() {
        assert_eq!(
            config::Provider::from_dir_name("wgconf"),
            Some(config::Provider::Wgconf)
        );
        assert_eq!(config::Provider::Wgconf.label(), "wgconf");
    }
}
