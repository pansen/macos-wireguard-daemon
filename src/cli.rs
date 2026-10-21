use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "wgd",
    about = "WireGuard config-file VPN CLI",
    version = env!("WGD_BUILD_VERSION")
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: TopCommand,

    /// Enable verbose logging
    #[arg(short, long, visible_alias = "debug", global = true)]
    pub verbose: bool,
}

#[derive(Subcommand)]
pub enum TopCommand {
    /// Show active VPN connections, including WireGuard tunnel state
    Status {
        /// Also show live DNS servers configured on each macOS network service
        #[arg(long)]
        dns: bool,
    },

    /// Run system and connection diagnostics (and optionally write a redacted report file)
    Doctor {
        /// Write a redacted diagnostic report to this file in addition to terminal output
        #[arg(long, value_name = "FILE")]
        report: Option<PathBuf>,

        /// Internal: whether the invoking user's shell had the wgd group active before sudo
        #[arg(long, hide = true)]
        caller_in_wgd_group: Option<bool>,
    },

    /// Show or follow wgd daemon, helper, and launchd logs
    Logs(LogsArgs),

    /// Inspect or repair macOS DNS state managed by wgd
    Dns {
        #[command(subcommand)]
        command: DnsCommand,
    },

    /// Install shell tab-completion into the user's shell rc file
    Completion {
        #[command(subcommand)]
        command: CompletionCommand,
    },

    /// Manage the privileged launchd daemon, the per-user session-
    /// reconciliation agent (`launchd agent ...`), and reload both launchd
    /// services
    Launchd {
        #[command(subcommand)]
        command: LaunchdCommand,
    },

    /// Manage privileged connection-store records: add/list/remove stored
    /// WireGuard configs and connect/disconnect them
    Connection {
        #[command(subcommand)]
        command: ConnectionCommand,
    },

    /// Internal privileged service mode (hidden)
    #[command(hide = true)]
    Privileged {
        #[arg(long)]
        serve: bool,

        /// Restore DNS left behind by dead helpers once and exit (root; alias
        /// for `wgd dns repair`).
        #[arg(long, hide = true, conflicts_with = "serve")]
        sweep_dns: bool,

        /// Use stdin/stdout request transport instead of Unix socket.
        #[arg(long, hide = true)]
        stdio: bool,

        /// Optional group name for privileged socket authorization.
        #[arg(long)]
        authorized_group: Option<String>,

        /// Exit after this many idle milliseconds without requests.
        #[arg(long)]
        idle_timeout_ms: Option<u64>,

        /// Internal marker: daemon was launched by client autostart logic.
        #[arg(long, hide = true)]
        autostarted: bool,
    },
}

#[derive(Args, Clone, Debug, PartialEq, Eq)]
pub struct LogsArgs {
    /// Follow log output as new lines are written (like `tail -f`)
    #[arg(short = 'f', long)]
    pub follow: bool,

    /// Number of trailing lines to show per log file
    #[arg(short = 'n', long, default_value_t = 150)]
    pub lines: usize,

    /// Show recent launchd unified-log entries for wgd instead of `/var/log/wgd/*.log`
    #[arg(long)]
    pub launchd: bool,

    /// Also show connection logs not written to in the last 24 hours
    /// (removed or long idle connections)
    #[arg(long, conflicts_with = "launchd")]
    pub all: bool,

    /// Optional connection id, connection name, or log stem (`wg-...`, `privileged`) to filter to
    #[arg(add = clap_complete::engine::ArgValueCompleter::new(
        crate::connection_cli::complete_connection_id
    ))]
    pub connection: Option<String>,
}

#[derive(Subcommand, Clone, Copy, Debug, PartialEq, Eq)]
pub enum DnsCommand {
    /// Restore DNS left behind on network services by a crashed or force-killed helper
    Repair,
}

#[derive(Subcommand, Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionCommand {
    /// Write or update the managed completion block in the shell's rc file
    Install {
        /// Target shell
        #[arg(long, value_enum, default_value_t = CompletionShell::Bash)]
        shell: CompletionShell,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CompletionShell {
    #[default]
    Bash,
    Zsh,
    Fish,
}

#[derive(Subcommand)]
pub enum LaunchdCommand {
    /// Register and start the privileged daemon with launchd (run with sudo)
    ///
    /// If the running binary isn't already at a trusted, root-owned location
    /// (e.g. a plain `brew install` or a Cask's staged copy, wherever
    /// Homebrew's prefix happens to be on this machine), it is first copied
    /// into /usr/local/bin/wgd (root:wheel) before anything else runs, since
    /// launchd daemons cannot run out of an admin-writable location.
    ///
    /// The launchd plist is rendered from a template. By default this is the
    /// template baked into the binary at build time; pass --plist-template to
    /// supply your own.
    ///
    /// Template placeholders substituted at install time:
    ///   @WGD_BIN@       absolute path of the wgd binary launchd runs
    ///   @SOCK_PATH_GROUP@  marker comment replaced with the SockPathGroup key
    ///                      (integer GID of the wgd group)
    #[command(verbatim_doc_comment)]
    Install {
        /// Path to a custom plist template (defaults to the template baked
        /// into the binary at build time). Must contain the @WGD_BIN@
        /// and @SOCK_PATH_GROUP@ placeholders described above.
        #[arg(long, value_name = "PATH")]
        plist_template: Option<PathBuf>,
    },
    /// Restart only the privileged daemon using its existing registration (run with sudo); use when the daemon hangs or misbehaves but its registration is intact
    ///
    /// Runs launchctl kickstart -k. Use this to restart an already-registered
    /// daemon. It does not re-register either service, restart the session
    /// agent, or explicitly reconnect stored connections.
    /// For service recovery and reconnection, use wgd launchd reload.
    Restart,
    /// Re-register the daemon and session agent, then reconnect automatic connections; use after an upgrade or when services are disabled, unregistered, or broken
    ///
    /// Use this after an upgrade or when services are disabled, unregistered,
    /// or behaving unexpectedly. Rebuilds both launchd registrations and clears
    /// stale connections before the session agent reconnects automatic connections.
    ///
    /// Runs, in order:
    ///   sudo wgd launchd install         (re-registers the privileged daemon)
    ///   wgd connection disconnect --all  (drops this user's active connections)
    ///   wgd launchd agent install -f     (re-registers the session agent, reconnects)
    ///
    /// Run as your normal user, without sudo; only the daemon step escalates.
    /// Logs at debug level unless -s is given.
    #[command(verbatim_doc_comment)]
    Reload(ReloadArgs),
    /// Stop and unregister the privileged daemon (keeps binary, group, logs)
    Uninstall,

    /// Show privileged daemon state, socket/directory permissions, group membership, and helper pids
    Status {
        /// Internal: whether the invoking user's shell had the wgd group active before sudo
        #[arg(long, hide = true)]
        caller_in_wgd_group: Option<bool>,
    },

    /// Unregister services and remove all wgd runtime state, logs, and the wgd group (keeps the binary)
    Purge,

    /// Manage the per-user session-reconciliation LaunchAgent
    ///
    /// Installs a long-lived, per-user LaunchAgent that connects this
    /// user's `automatic` connections on login and disconnects them again
    /// on logout, so a per-user tunnel never outlives the session that
    /// started it.
    #[command(verbatim_doc_comment)]
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum StartModeArg {
    Manual,
    Automatic,
}

#[derive(Subcommand)]
pub enum ConnectionCommand {
    /// Parse and store a WireGuard .conf under the privileged daemon
    ///
    /// A byte-for-byte-identical resubmission of an already-stored config
    /// (same file content, same --global) is a no-op that returns the
    /// existing connection's id without prompting again. A new or changed
    /// config -- different fingerprint, e.g. after editing the .conf -- is a
    /// *distinct* connection: fingerprint identity has nothing to do with
    /// --name, so without --force it is added alongside any older,
    /// same-named record rather than replacing it. Each of add/remove
    /// individually triggers its own macOS admin-authentication prompt
    /// (password or Touch ID) when it represents a real change.
    #[command(verbatim_doc_comment)]
    Add {
        /// WireGuard .conf file path
        #[arg(long)]
        file: String,

        /// Store as a global (system-wide, root-owned, live as soon as the
        /// daemon is) connection instead of a per-user one
        #[arg(long)]
        global: bool,

        /// Display name. Required by --force (it's what --force matches on).
        #[arg(long)]
        name: Option<String>,

        /// Override the config's own MTU
        #[arg(long)]
        mtu: Option<u16>,

        /// Before adding, remove any existing connection (same scope) with
        /// the same --name, so re-running `add` after editing the .conf
        /// replaces the old record instead of accumulating a new one
        /// alongside it. Requires --name. A no-op (nothing to remove) if no
        /// same-named connection exists yet.
        #[arg(long, requires = "name")]
        force: bool,

        /// Bring this connection up automatically (global: at daemon boot;
        /// per-user: on login via `launchd agent`). Defaults to manual.
        /// Setting a *global* connection's mode to automatic (whether here
        /// or via `connection mode`) requires admin authentication.
        #[arg(long, value_enum, default_value_t = StartModeArg::Manual)]
        start_mode: StartModeArg,
    },

    /// List stored connections (alias: ls)
    #[command(visible_alias = "ls")]
    List {
        /// List every user's connections (root only)
        #[arg(long, conflicts_with = "global")]
        all: bool,

        /// List only global connections
        #[arg(long)]
        global: bool,
    },

    /// Remove a stored connection by id (must not be currently connected)
    Remove {
        /// Connection id or name, as printed by `add` or `list`
        #[arg(add = clap_complete::engine::ArgValueCompleter::new(
            crate::connection_cli::complete_connection_id
        ))]
        id: String,
    },

    /// Bring a stored connection up
    Connect {
        /// Connection id or name, as printed by `add` or `list`
        #[arg(add = clap_complete::engine::ArgValueCompleter::new(
            crate::connection_cli::complete_connection_id
        ))]
        id: String,

        /// Enable gotatun debug logging for this connect
        #[arg(long = "gotatun-debug")]
        debug: bool,
    },

    /// Tear a stored connection down
    Disconnect {
        /// Connection id or name, as printed by `add` or `list`
        #[arg(add = clap_complete::engine::ArgValueCompleter::new(
            crate::connection_cli::complete_connection_id
        ))]
        #[arg(required_unless_present = "all", conflicts_with = "all")]
        id: Option<String>,

        /// Disconnect every one of the caller's currently-connected connections
        #[arg(short = 'a', long)]
        all: bool,
    },

    /// Set a stored connection's start mode
    ///
    /// Setting a *global* connection from manual to automatic requires
    /// admin authentication (it's what makes a hook-bearing config
    /// auto-run as root at every future boot). Every other transition
    /// (per-user, or downgrading global back to manual) proceeds on
    /// ownership alone.
    #[command(verbatim_doc_comment)]
    Mode {
        /// Connection id or name, as printed by `add` or `list`
        #[arg(add = clap_complete::engine::ArgValueCompleter::new(
            crate::connection_cli::complete_connection_id
        ))]
        id: String,

        /// New start mode
        #[arg(value_enum)]
        start_mode: StartModeArg,
    },

    /// Show full detail for one stored connection (owner or root only)
    Get {
        /// Connection id or name, as printed by `add` or `list`
        #[arg(add = clap_complete::engine::ArgValueCompleter::new(
            crate::connection_cli::complete_connection_id
        ))]
        id: String,
    },
}

#[derive(Subcommand)]
pub enum AgentCommand {
    /// Install and start the per-user session-reconciliation LaunchAgent (run WITHOUT sudo)
    Install {
        /// Overwrite and reload an existing installation
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// Show whether the session agent is installed/loaded
    Status,
    /// Stop and unregister the session agent
    Uninstall,
    /// Internal: the long-lived agent body launchd actually executes (hidden)
    #[command(hide = true)]
    Run,
}

#[derive(Args, Clone)]
pub struct ReloadArgs {
    /// Log at the usual level instead of debug, leaving only the step headers
    /// and anything the steps report at info level or above.
    #[arg(short = 's', long, conflicts_with = "verbose")]
    pub silent: bool,
}

#[cfg(test)]
mod tests {
    use super::{
        AgentCommand, Cli, CompletionCommand, CompletionShell, ConnectionCommand, DnsCommand,
        LaunchdCommand, LogsArgs, StartModeArg, TopCommand,
    };
    use clap::Parser;

    #[test]
    fn parse_global_debug_alias_enables_verbose_logging() {
        let before =
            Cli::try_parse_from(["wgd", "--debug", "status"]).expect("parse debug before command");
        assert!(before.verbose);

        let after =
            Cli::try_parse_from(["wgd", "status", "--debug"]).expect("parse debug after command");
        assert!(after.verbose);
    }

    #[test]
    fn parse_status_with_and_without_dns_flag() {
        let bare = Cli::try_parse_from(["wgd", "status"]).expect("parse bare status");
        assert!(matches!(bare.command, TopCommand::Status { dns: false }));

        let with_dns = Cli::try_parse_from(["wgd", "status", "--dns"]).expect("parse status --dns");
        assert!(matches!(with_dns.command, TopCommand::Status { dns: true }));
    }

    #[test]
    fn parse_doctor_and_report_flag() {
        use std::path::Path;

        let bare = Cli::try_parse_from(["wgd", "doctor"]).expect("parse bare doctor");
        match bare.command {
            TopCommand::Doctor {
                report,
                caller_in_wgd_group,
            } => {
                assert!(report.is_none());
                assert!(caller_in_wgd_group.is_none());
            }
            _ => panic!("expected doctor command"),
        }

        let with_report = Cli::try_parse_from(["wgd", "doctor", "--report", "/tmp/report.log"])
            .expect("parse doctor --report");
        match with_report.command {
            TopCommand::Doctor {
                report: Some(path), ..
            } => assert_eq!(path, Path::new("/tmp/report.log")),
            _ => panic!("expected doctor --report"),
        }
    }

    #[test]
    fn parse_logs_subcommand_flags() {
        let bare = Cli::try_parse_from(["wgd", "logs"]).expect("parse bare logs");
        match bare.command {
            TopCommand::Logs(args) => assert_eq!(
                args,
                LogsArgs {
                    follow: false,
                    lines: 150,
                    launchd: false,
                    all: false,
                    connection: None,
                }
            ),
            _ => panic!("expected logs command"),
        }

        let full = Cli::try_parse_from(["wgd", "logs", "-f", "-n", "50", "andi_split"])
            .expect("parse logs -f -n 50 andi_split");
        match full.command {
            TopCommand::Logs(args) => assert_eq!(
                args,
                LogsArgs {
                    follow: true,
                    lines: 50,
                    launchd: false,
                    all: false,
                    connection: Some("andi_split".to_string()),
                }
            ),
            _ => panic!("expected logs command"),
        }

        let launchd =
            Cli::try_parse_from(["wgd", "logs", "--launchd"]).expect("parse logs --launchd");
        match launchd.command {
            TopCommand::Logs(args) => assert!(args.launchd),
            _ => panic!("expected logs --launchd"),
        }
    }

    #[test]
    fn parse_dns_repair_and_completion_install() {
        let dns = Cli::try_parse_from(["wgd", "dns", "repair"]).expect("parse dns repair");
        assert!(matches!(
            dns.command,
            TopCommand::Dns {
                command: DnsCommand::Repair
            }
        ));

        let comp_default = Cli::try_parse_from(["wgd", "completion", "install"])
            .expect("parse completion install");
        assert!(matches!(
            comp_default.command,
            TopCommand::Completion {
                command: CompletionCommand::Install {
                    shell: CompletionShell::Bash
                }
            }
        ));

        let comp_zsh = Cli::try_parse_from(["wgd", "completion", "install", "--shell", "zsh"])
            .expect("parse completion install --shell zsh");
        assert!(matches!(
            comp_zsh.command,
            TopCommand::Completion {
                command: CompletionCommand::Install {
                    shell: CompletionShell::Zsh
                }
            }
        ));
    }

    #[test]
    fn parse_launchd_subcommands() {
        for (arg, want) in [
            (
                "install",
                std::mem::discriminant(&LaunchdCommand::Install {
                    plist_template: None,
                }),
            ),
            ("restart", std::mem::discriminant(&LaunchdCommand::Restart)),
            (
                "uninstall",
                std::mem::discriminant(&LaunchdCommand::Uninstall),
            ),
            (
                "status",
                std::mem::discriminant(&LaunchdCommand::Status {
                    caller_in_wgd_group: None,
                }),
            ),
            ("purge", std::mem::discriminant(&LaunchdCommand::Purge)),
        ] {
            let cli = Cli::try_parse_from(["wgd", "launchd", arg]).expect("parse launchd");
            match cli.command {
                TopCommand::Launchd { command } => {
                    assert_eq!(std::mem::discriminant(&command), want)
                }
                _ => panic!("expected launchd command"),
            }
        }
    }

    #[test]
    fn parse_launchd_install_with_template() {
        use std::path::Path;

        let cli = Cli::try_parse_from([
            "wgd",
            "launchd",
            "install",
            "--plist-template",
            "/tmp/custom.plist",
        ])
        .expect("parse launchd install with template");

        match cli.command {
            TopCommand::Launchd {
                command:
                    LaunchdCommand::Install {
                        plist_template: Some(p),
                    },
            } => {
                assert_eq!(p, Path::new("/tmp/custom.plist"));
            }
            _ => panic!("expected launchd install with template"),
        }
    }

    #[test]
    fn parse_launchd_reload_silent_flag() {
        let bare = Cli::try_parse_from(["wgd", "launchd", "reload"]).expect("parse bare reload");
        match bare.command {
            TopCommand::Launchd {
                command: LaunchdCommand::Reload(args),
            } => assert!(!args.silent),
            _ => panic!("expected reload command"),
        }

        for arg in ["-s", "--silent"] {
            let cli = Cli::try_parse_from(["wgd", "launchd", "reload", arg])
                .expect("parse reload silent");
            match cli.command {
                TopCommand::Launchd {
                    command: LaunchdCommand::Reload(args),
                } => assert!(args.silent),
                _ => panic!("expected reload command"),
            }
        }

        assert!(Cli::try_parse_from(["wgd", "reload"]).is_err());

        // Asking for both quiet and verbose has no sensible reading.
        assert!(Cli::try_parse_from(["wgd", "launchd", "reload", "-s", "-v"]).is_err());
    }

    #[test]
    fn parse_connection_add() {
        let cli = Cli::try_parse_from([
            "wgd",
            "connection",
            "add",
            "--file",
            "/tmp/test.conf",
            "--name",
            "direct",
            "--mtu",
            "1360",
        ])
        .expect("parse connection add");

        match cli.command {
            TopCommand::Connection {
                command:
                    ConnectionCommand::Add {
                        file,
                        global,
                        name,
                        mtu,
                        force,
                        start_mode,
                    },
            } => {
                assert_eq!(file, "/tmp/test.conf");
                assert!(!global);
                assert_eq!(name.as_deref(), Some("direct"));
                assert_eq!(mtu, Some(1360));
                assert!(!force);
                assert!(matches!(start_mode, StartModeArg::Manual));
            }
            _ => panic!("expected connection add command"),
        }
    }

    #[test]
    fn parse_connection_add_start_mode_automatic() {
        let cli = Cli::try_parse_from([
            "wgd",
            "connection",
            "add",
            "--file",
            "/tmp/test.conf",
            "--start-mode",
            "automatic",
        ])
        .expect("parse connection add --start-mode automatic");

        match cli.command {
            TopCommand::Connection {
                command: ConnectionCommand::Add { start_mode, .. },
            } => assert!(matches!(start_mode, StartModeArg::Automatic)),
            _ => panic!("expected connection add command"),
        }
    }

    #[test]
    fn parse_connection_connect_and_disconnect() {
        let cli =
            Cli::try_parse_from(["wgd", "connection", "connect", "some-id", "--gotatun-debug"])
                .expect("parse connection connect");
        match cli.command {
            TopCommand::Connection {
                command: ConnectionCommand::Connect { id, debug },
            } => {
                assert_eq!(id, "some-id");
                assert!(debug);
            }
            _ => panic!("expected connection connect command"),
        }

        let cli = Cli::try_parse_from(["wgd", "connection", "disconnect", "some-id"])
            .expect("parse connection disconnect by id");
        match cli.command {
            TopCommand::Connection {
                command: ConnectionCommand::Disconnect { id, all },
            } => {
                assert_eq!(id.as_deref(), Some("some-id"));
                assert!(!all);
            }
            _ => panic!("expected connection disconnect command"),
        }

        let cli = Cli::try_parse_from(["wgd", "connection", "disconnect", "--all"])
            .expect("parse connection disconnect --all");
        match cli.command {
            TopCommand::Connection {
                command: ConnectionCommand::Disconnect { id, all },
            } => {
                assert!(id.is_none());
                assert!(all);
            }
            _ => panic!("expected connection disconnect command"),
        }

        assert!(Cli::try_parse_from(["wgd", "connection", "disconnect"]).is_err());
        assert!(
            Cli::try_parse_from(["wgd", "connection", "disconnect", "some-id", "--all"]).is_err()
        );
    }

    #[test]
    fn parse_connection_mode_and_get() {
        let cli = Cli::try_parse_from(["wgd", "connection", "mode", "some-id", "automatic"])
            .expect("parse connection mode");
        match cli.command {
            TopCommand::Connection {
                command: ConnectionCommand::Mode { id, start_mode },
            } => {
                assert_eq!(id, "some-id");
                assert!(matches!(start_mode, StartModeArg::Automatic));
            }
            _ => panic!("expected connection mode command"),
        }

        let cli = Cli::try_parse_from(["wgd", "connection", "get", "some-id"])
            .expect("parse connection get");
        match cli.command {
            TopCommand::Connection {
                command: ConnectionCommand::Get { id },
            } => assert_eq!(id, "some-id"),
            _ => panic!("expected connection get command"),
        }
    }

    #[test]
    fn parse_launchd_agent_subcommands() {
        for (args, want) in [
            (
                vec!["wgd", "launchd", "agent", "install"],
                std::mem::discriminant(&AgentCommand::Install { force: false }),
            ),
            (
                vec!["wgd", "launchd", "agent", "status"],
                std::mem::discriminant(&AgentCommand::Status),
            ),
            (
                vec!["wgd", "launchd", "agent", "uninstall"],
                std::mem::discriminant(&AgentCommand::Uninstall),
            ),
            (
                vec!["wgd", "launchd", "agent", "run"],
                std::mem::discriminant(&AgentCommand::Run),
            ),
        ] {
            let cli = Cli::try_parse_from(args).expect("parse launchd agent subcommand");
            match cli.command {
                TopCommand::Launchd {
                    command: LaunchdCommand::Agent { command },
                } => assert_eq!(std::mem::discriminant(&command), want),
                _ => panic!("expected launchd agent command"),
            }
        }
    }

    #[test]
    fn parse_connection_list_and_ls_alias() {
        for arg in ["list", "ls"] {
            let cli =
                Cli::try_parse_from(["wgd", "connection", arg]).expect("parse connection list");
            match cli.command {
                TopCommand::Connection {
                    command: ConnectionCommand::List { all, global },
                } => {
                    assert!(!all);
                    assert!(!global);
                }
                _ => panic!("expected connection list command"),
            }
        }
    }

    #[test]
    fn parse_connection_list_rejects_all_with_global() {
        let result = Cli::try_parse_from(["wgd", "connection", "list", "--all", "--global"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_connection_add_force_requires_name() {
        let missing_name = Cli::try_parse_from([
            "wgd",
            "connection",
            "add",
            "--file",
            "/tmp/test.conf",
            "--force",
        ]);
        assert!(missing_name.is_err());

        let with_name = Cli::try_parse_from([
            "wgd",
            "connection",
            "add",
            "--file",
            "/tmp/test.conf",
            "--name",
            "direct",
            "--force",
        ])
        .expect("parse connection add --force --name");
        match with_name.command {
            TopCommand::Connection {
                command: ConnectionCommand::Add { force, .. },
            } => assert!(force),
            _ => panic!("expected connection add command"),
        }
    }

    #[test]
    fn parse_connection_remove() {
        let cli = Cli::try_parse_from(["wgd", "connection", "remove", "some-id"])
            .expect("parse connection remove");
        match cli.command {
            TopCommand::Connection {
                command: ConnectionCommand::Remove { id },
            } => assert_eq!(id, "some-id"),
            _ => panic!("expected connection remove command"),
        }
    }
}
