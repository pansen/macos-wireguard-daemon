mod autoconnect;
mod cli;
mod config;
mod error;
mod launchctl;
mod launchd;
mod logging;
mod privileged;
mod privileged_api;
mod privileged_client;
mod shared;
mod userspace_helper;
mod wgconf;
mod wireguard;

use clap::Parser;
use tracing::error;

use cli::{
    Cli, ConnectProviderCommand, HookBuiltinArg, HookCommand, HookEventArg, ProviderArg, TopCommand,
};
use wireguard::connection::ConnectionState;

fn main() {
    if userspace_helper::maybe_run_from_env() {
        return;
    }

    let cli = Cli::parse();
    if cli.verbose {
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
        // Status and Wg are quick sync commands, no tokio needed.
        TopCommand::Status => {
            init_logging(cli.verbose);
            if let Err(e) = cmd_status() {
                error!( command = ?"status", error = ?e.to_string(), "command_failed");
                std::process::exit(1);
            }
        }

        TopCommand::Wg => {
            init_logging(cli.verbose);
            if let Err(e) = cmd_wg() {
                error!( command = ?"wg", error = ?e.to_string(), "command_failed");
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

async fn run(command: TopCommand, config: config::AppConfig) -> anyhow::Result<()> {
    match command {
        TopCommand::Wgconf { command } => wgconf::handlers::dispatch(command, &config).await,
        TopCommand::Connect { provider } => run_connect(provider, &config).await,
        TopCommand::Disconnect {
            instance,
            provider,
            all,
        } => run_disconnect(instance, provider, all, &config).await,
        TopCommand::Hook { command } => run_hook_command(command),
        TopCommand::Status
        | TopCommand::Wg
        | TopCommand::Launchd { .. }
        | TopCommand::Autoconnect { .. }
        | TopCommand::Privileged { .. } => {
            unreachable!()
        }
    }
}

fn run_hook_command(command: HookCommand) -> anyhow::Result<()> {
    match command {
        HookCommand::Run { builtin } => cmd_hook_run(builtin),
        HookCommand::Debug {
            instance,
            provider,
            event,
        } => cmd_hook_debug(instance, provider, event),
    }
}

fn cmd_hook_run(builtin: HookBuiltinArg) -> anyhow::Result<()> {
    let entry = match builtin {
        HookBuiltinArg::Connectivity => "builtin:connectivity",
        HookBuiltinArg::ExternalIp => "builtin:external-ip",
        HookBuiltinArg::DnsDetection => "builtin:dns-detection",
    };

    let connections = ConnectionState::load_all()?;
    if connections.len() == 1 {
        return shared::hooks::run_builtin_for_state(entry, &connections[0]);
    }

    if connections.len() > 1 {
        tracing::warn!(
            active_connections = connections.len(),
            "hook_run_multiple_connections_no_proxy_context"
        );
    }

    shared::hooks::run_builtin(entry)
}

fn cmd_hook_debug(
    instance: Option<String>,
    provider: Option<ProviderArg>,
    event: HookEventArg,
) -> anyhow::Result<()> {
    let state = resolve_connection_for_hook_debug(instance, provider)?;
    let provider_cfg = config::Provider::from_dir_name(&state.provider).ok_or_else(|| {
        anyhow::anyhow!(
            "unsupported provider in connection state: {}",
            state.provider
        )
    })?;

    let env = match event {
        HookEventArg::Ifup => shared::hooks::debug_ifup_env(provider_cfg, &state),
        HookEventArg::Ifdown => shared::hooks::debug_ifdown_env(provider_cfg, &state),
    };

    println!(
        "Hook env payload [{}] for {} ({})",
        hook_event_label(event),
        state.instance_name,
        state.provider
    );
    for (key, value) in env {
        println!("{}={}", key, value);
    }

    Ok(())
}

fn resolve_connection_for_hook_debug(
    instance: Option<String>,
    provider: Option<ProviderArg>,
) -> anyhow::Result<ConnectionState> {
    if let Some(instance_name) = instance {
        let conn = ConnectionState::load(&instance_name)?
            .ok_or_else(|| anyhow::anyhow!("no connection with instance {:?}", instance_name))?;

        if let Some(requested) = provider {
            if conn.provider != requested.label() {
                anyhow::bail!(
                    "instance {:?} belongs to provider {:?}, not {:?}",
                    instance_name,
                    conn.provider,
                    requested.label()
                );
            }
        }

        return Ok(conn);
    }

    let mut connections = ConnectionState::load_all()?;
    if let Some(requested) = provider {
        let requested_label = requested.label();
        connections.retain(|conn| conn.provider == requested_label);
    }

    match connections.len() {
        0 => anyhow::bail!("no active connections{}", provider_hint(provider)),
        1 => Ok(connections.remove(0)),
        _ => {
            println!("Multiple active connections. Specify instance for hook debug:\n");
            for conn in &connections {
                println!(
                    "  {:<12} {:<9} {}",
                    conn.instance_name, conn.provider, conn.server_display_name
                );
            }
            println!("\nUsage: tunmux hook debug <instance>");
            println!("       tunmux hook debug --provider <provider>");
            anyhow::bail!("hook debug requires an unambiguous active connection")
        }
    }
}

fn hook_event_label(event: HookEventArg) -> &'static str {
    match event {
        HookEventArg::Ifup => "ifup",
        HookEventArg::Ifdown => "ifdown",
    }
}

fn provider_hint(provider: Option<ProviderArg>) -> &'static str {
    if provider.is_some() {
        " for selected provider"
    } else {
        ""
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
    let mut connections: Vec<ConnectionState> = ConnectionState::load_all()?
        .into_iter()
        .filter(|c| match c.backend {
            wireguard::backend::WgBackend::Userspace => c.is_live(),
            _ => true,
        })
        .collect();

    let have_wgconf_direct = connections
        .iter()
        .any(|c| c.provider == "wgconf" && c.interface_name == "wgconf0");
    if !have_wgconf_direct
        && privileged_client::PrivilegedClient::new()
            .interface_active("wgconf0")
            .unwrap_or(false)
    {
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
    println!("{}", render_row(&header_cells).trim_end());
    println!(
        "{}",
        widths
            .iter()
            .map(|w| "-".repeat(*w))
            .collect::<Vec<_>>()
            .join("-+-")
    );
    for row in &rows {
        println!("{}", render_row(row).trim_end());
    }

    Ok(())
}

fn cmd_wg() -> anyhow::Result<()> {
    use wireguard::connection::ConnectionState;

    let connections = ConnectionState::load_all()?;
    if connections.is_empty() {
        println!("No active connections.");
        return Ok(());
    }

    let mut first = true;
    for conn in &connections {
        if !first {
            println!();
        }
        first = false;

        match privileged_client::PrivilegedClient::new().wg_show(&conn.interface_name) {
            Ok(output) => print!("{}", output),
            Err(e) => eprintln!("wg show {} failed: {}", conn.interface_name, e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config;

    #[test]
    fn provider_mapping_includes_wgconf() {
        assert_eq!(
            config::Provider::from_dir_name("wgconf"),
            Some(config::Provider::Wgconf)
        );
        assert_eq!(config::Provider::Wgconf.label(), "wgconf");
    }
}
