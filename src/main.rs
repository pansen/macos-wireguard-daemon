mod cli;
mod color;
mod config;
mod connection_cli;
mod error;
mod launchctl;
mod launchd;
mod logging;
mod privileged;
mod privileged_api;
mod privileged_client;
mod reload;
mod session_agent;
mod state_file;
mod trusted_exec;
mod userspace_helper;
mod wireguard;

use clap::Parser;
use tracing::error;

use cli::{Cli, TopCommand};
use privileged_api::ConnectionScope;

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

        TopCommand::Connection { command } => {
            init_logging(cli.verbose);
            if let Err(e) = connection_cli::dispatch(command) {
                error!(command = ?"connection", error = %format!("{e:#}"), "command_failed");
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
        TopCommand::Reload(args) => reload::run(args, &config).await,
        TopCommand::Status
        | TopCommand::Launchd { .. }
        | TopCommand::Connection { .. }
        | TopCommand::Privileged { .. } => {
            unreachable!()
        }
    }
}

/// `tunmux status`: built entirely from the privileged connection store --
/// this user's own connections plus every global one (global connections
/// have no owner to match `Mine`, so it's fetched as a second, disjoint
/// scope and appended).
fn cmd_status() -> anyhow::Result<()> {
    let client = privileged_client::PrivilegedClient::new();
    let mut connections = client.list_connections(ConnectionScope::Mine)?;
    connections.extend(client.list_connections(ConnectionScope::Global)?);

    if connections.is_empty() {
        println!("No stored connections. Add one with: tunmux connection add --file <path>");
        return Ok(());
    }

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

    // Beneath the summary table, print per-connected-interface detail: the
    // WireGuard tunnel state from `wg show`, and the live route/DNS overview.
    // Both live behind the privileged service and are best-effort: a fetch
    // failure prints to stderr but never fails `status`.
    for conn in connections.iter().filter(|c| c.connected) {
        match client.wg_show(&conn.interface) {
            Ok(output) if !output.trim().is_empty() => {
                println!();
                println!("{}", color::wg_show(output.trim_end()));
            }
            Ok(_) => {}
            Err(e) => eprintln!("wg show {} failed: {}", conn.interface, e),
        }

        match client.network_overview(&conn.interface) {
            Ok(Some(overview)) => {
                println!();
                println!("{}", color::tables(overview.trim_end()));
            }
            Ok(None) => {}
            Err(e) => eprintln!(
                "network overview for {} unavailable: {}",
                conn.interface, e
            ),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::defaults_to_debug;
    use crate::cli::{Cli, ReloadArgs, TopCommand};
    use clap::Parser;

    #[test]
    fn reload_logs_at_debug_unless_silenced() {
        assert!(defaults_to_debug(&TopCommand::Reload(ReloadArgs {
            silent: false,
        })));
        assert!(!defaults_to_debug(&TopCommand::Reload(ReloadArgs {
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
}
