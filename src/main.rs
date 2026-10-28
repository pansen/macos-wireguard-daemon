mod cli;
mod completion;
mod config;
mod connection_cli;
mod dns_custody;
mod dns_dynamic_store;
mod doctor;
mod error;
mod launchctl;
mod launchd;
mod logging;
mod logs;
mod macos_dns;
mod privileged;
mod privileged_api;
mod privileged_client;
mod reload;
mod session_agent;
mod state_file;
mod status;
mod status_model;
mod status_notify;
mod status_render;
mod trusted_exec;
mod ui;
mod userspace_helper;
mod wireguard;

use clap::{CommandFactory, Parser};
use tracing::error;

use anyhow::Context;
use cli::{Cli, DnsCommand, LaunchdCommand, TopCommand};

fn main() {
    if userspace_helper::maybe_run_from_env() {
        return;
    }

    // Shell completion: when the shell invokes us with COMPLETE=<shell> set,
    // emit candidates and exit. This has to come before any dispatch so a
    // <TAB> keystroke can never fall through into daemon-spawning or
    // privileged code paths. The command tree is introspected fresh from
    // `Cli` on every request, so completions track `--help` automatically.
    clap_complete::CompleteEnv::with_factory(cli::Cli::command).complete();

    let cli = Cli::parse();
    if cli.verbose || defaults_to_debug(&cli.command) {
        logging::enable_debug();
    }

    match cli.command {
        // Privileged control server.
        TopCommand::Privileged {
            serve,
            sweep_dns,
            stdio,
            authorized_group,
            idle_timeout_ms,
            autostarted,
        } => {
            if sweep_dns {
                init_logging(cli.verbose);
                if let Err(e) = privileged::sweep_dns_once() {
                    error!(command = ?"privileged --sweep-dns", error = %format!("{e:#}"), "command_failed");
                    std::process::exit(1);
                }
                return;
            }
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
        TopCommand::Status { dns, json } => {
            init_logging(cli.verbose);
            let result = status::cmd_status(json);
            // Printed even when the daemon is unreachable: live DNS is read
            // straight from `networksetup` and matters most exactly then.
            if dns {
                status::print_service_dns();
            }
            if let Err(e) = result {
                error!( command = ?"status", error = ?e.to_string(), "command_failed");
                std::process::exit(1);
            }
        }

        TopCommand::Doctor {
            report,
            caller_in_wgd_group,
        } => {
            init_logging(cli.verbose);
            if let Err(e) = doctor::dispatch(report, caller_in_wgd_group) {
                error!(command = ?"doctor", error = %format!("{e:#}"), "command_failed");
                std::process::exit(1);
            }
        }

        TopCommand::Logs(args) => {
            init_logging(cli.verbose);
            if let Err(e) = logs::dispatch(args) {
                error!(command = ?"logs", error = %format!("{e:#}"), "command_failed");
                std::process::exit(1);
            }
        }

        TopCommand::Dns {
            command: DnsCommand::Repair,
        } => {
            init_logging(cli.verbose);
            if let Err(e) = cmd_dns_repair() {
                error!(command = ?"dns repair", error = %format!("{e:#}"), "command_failed");
                std::process::exit(1);
            }
        }

        TopCommand::Completion { command } => {
            init_logging(cli.verbose);
            if let Err(e) = completion::dispatch(command) {
                error!(command = ?"completion", error = %format!("{e:#}"), "command_failed");
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
    }
}

fn init_logging(verbose: bool) {
    logging::init_terminal(verbose);
}

/// Commands that log at debug level without being asked. `launchd reload` is the one:
/// you run it because something is off, so the daemon and helper detail is the
/// point. `-s` opts back out.
fn defaults_to_debug(command: &TopCommand) -> bool {
    matches!(command, TopCommand::Launchd { command: LaunchdCommand::Reload(args) } if !args.silent)
}

/// `wgd dns repair`: the visible name for `wgd privileged --sweep-dns`.
/// Re-invokes itself through `sudo` when not root, like `launchd purge`.
fn cmd_dns_repair() -> anyhow::Result<()> {
    if nix::unistd::geteuid().is_root() {
        return privileged::sweep_dns_once();
    }
    let exe = std::env::current_exe().context("failed to determine the running wgd binary path")?;
    let mut cmd = std::process::Command::new("sudo");
    cmd.arg(&exe);
    if logging::debug_enabled() {
        cmd.arg("--debug");
    }
    cmd.args(["dns", "repair"]);
    tracing::warn!(
        action = "dns_repair",
        method = "sudo",
        cause = "restoring DNS on macOS network services requires root",
        "admin_authentication_requested"
    );
    let status = cmd
        .status()
        .context("failed to run sudo for wgd dns repair")?;
    anyhow::ensure!(status.success(), "sudo wgd dns repair failed ({status})");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::defaults_to_debug;
    use crate::cli::{Cli, LaunchdCommand, ReloadArgs, TopCommand};
    use clap::Parser;

    #[test]
    fn reload_logs_at_debug_unless_silenced() {
        assert!(defaults_to_debug(&TopCommand::Launchd {
            command: LaunchdCommand::Reload(ReloadArgs { silent: false }),
        }));
        assert!(!defaults_to_debug(&TopCommand::Launchd {
            command: LaunchdCommand::Reload(ReloadArgs { silent: true }),
        }));
        assert!(!defaults_to_debug(&TopCommand::Status {
            dns: false,
            json: false
        }));
    }

    #[test]
    fn parsed_reload_command_asks_for_debug_logging() {
        let cli = Cli::try_parse_from(["wgd", "launchd", "reload"]).expect("parse reload");
        assert!(defaults_to_debug(&cli.command));

        let quiet =
            Cli::try_parse_from(["wgd", "launchd", "reload", "-s"]).expect("parse silent reload");
        assert!(!defaults_to_debug(&quiet.command));
    }
}
