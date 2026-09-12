use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "tunmux",
    about = "WireGuard config-file VPN CLI",
    version = env!("TUNMUX_BUILD_VERSION")
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
    Status,

    /// Manage the privileged launchd daemon (system domain)
    Launchd {
        #[command(subcommand)]
        command: LaunchdCommand,
    },

    /// Manage privileged connection-store records: add/list/remove stored
    /// WireGuard configs and connect/disconnect them, plus the per-user
    /// session-reconciliation agent (`connection agent ...`)
    Connection {
        #[command(subcommand)]
        command: ConnectionCommand,
    },

    /// Re-bootstrap both launchd services and bring stored connections back up
    ///
    /// Runs, in order:
    ///   sudo tunmux launchd install         (re-registers the privileged daemon)
    ///   tunmux connection disconnect --all  (drops tunnels left over from before)
    ///   tunmux connection agent install -f  (re-registers the session agent, reconnects)
    ///
    /// Run as your normal user; only the daemon step escalates via sudo.
    /// Logs at debug level unless -s is given.
    #[command(verbatim_doc_comment)]
    Reload(ReloadArgs),

    /// Internal privileged service mode (hidden)
    #[command(hide = true)]
    Privileged {
        #[arg(long)]
        serve: bool,

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

#[derive(Subcommand)]
pub enum LaunchdCommand {
    /// Register and start the privileged daemon with launchd (run with sudo)
    ///
    /// The launchd plist is rendered from a template. By default this is the
    /// template baked into the binary at build time; pass --plist-template to
    /// supply your own.
    ///
    /// Template placeholders substituted at install time:
    ///   @TUNMUX_BIN@       absolute path of the tunmux binary launchd runs
    ///   @SOCK_PATH_GROUP@  marker comment replaced with the SockPathGroup key
    ///                      (integer GID of the tunmux group)
    #[command(verbatim_doc_comment)]
    Install {
        /// Path to a custom plist template (defaults to the template baked
        /// into the binary at build time). Must contain the @TUNMUX_BIN@
        /// and @SOCK_PATH_GROUP@ placeholders described above.
        #[arg(long, value_name = "PATH")]
        plist_template: Option<PathBuf>,
    },
    /// Restart the privileged daemon (launchctl kickstart -k)
    Restart,
    /// Stop and unregister the privileged daemon (keeps binary, group, logs)
    Uninstall,
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
        /// per-user: on login via `connection agent`). Defaults to manual.
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
        /// Connection id, as printed by `add` or `list`
        id: String,
    },

    /// Bring a stored connection up
    Connect {
        /// Connection id, as printed by `add` or `list`
        id: String,

        /// Enable gotatun debug logging for this connect
        #[arg(long = "gotatun-debug")]
        debug: bool,
    },

    /// Tear a stored connection down
    Disconnect {
        /// Connection id, as printed by `add` or `list`
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
        /// Connection id, as printed by `add` or `list`
        id: String,

        /// New start mode
        #[arg(value_enum)]
        start_mode: StartModeArg,
    },

    /// Show full detail for one stored connection (owner or root only)
    Get {
        /// Connection id, as printed by `add` or `list`
        id: String,
    },

    /// Manage the per-user session-reconciliation LaunchAgent
    ///
    /// Installs a long-lived, per-user LaunchAgent that connects this
    /// user's `automatic` connections on login and disconnects them again
    /// on logout, so a per-user tunnel never outlives the session that
    /// started it.
    #[command(verbatim_doc_comment)]
    Agent {
        #[command(subcommand)]
        command: ConnectionAgentCommand,
    },
}

#[derive(Subcommand)]
pub enum ConnectionAgentCommand {
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
        Cli, ConnectionAgentCommand, ConnectionCommand, LaunchdCommand, StartModeArg, TopCommand,
    };
    use clap::Parser;

    #[test]
    fn parse_global_debug_alias_enables_verbose_logging() {
        let before = Cli::try_parse_from(["tunmux", "--debug", "status"])
            .expect("parse debug before command");
        assert!(before.verbose);

        let after = Cli::try_parse_from(["tunmux", "status", "--debug"])
            .expect("parse debug after command");
        assert!(after.verbose);
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
        ] {
            let cli = Cli::try_parse_from(["tunmux", "launchd", arg]).expect("parse launchd");
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
            "tunmux",
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
    fn parse_reload_silent_flag() {
        let bare = Cli::try_parse_from(["tunmux", "reload"]).expect("parse bare reload");
        match bare.command {
            TopCommand::Reload(args) => assert!(!args.silent),
            _ => panic!("expected reload command"),
        }

        for arg in ["-s", "--silent"] {
            let cli = Cli::try_parse_from(["tunmux", "reload", arg]).expect("parse reload silent");
            match cli.command {
                TopCommand::Reload(args) => assert!(args.silent),
                _ => panic!("expected reload command"),
            }
        }

        // Asking for both quiet and verbose has no sensible reading.
        assert!(Cli::try_parse_from(["tunmux", "reload", "-s", "-v"]).is_err());
    }

    #[test]
    fn parse_connection_add() {
        let cli = Cli::try_parse_from([
            "tunmux",
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
                command: ConnectionCommand::Add {
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
            "tunmux",
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
        let cli = Cli::try_parse_from([
            "tunmux",
            "connection",
            "connect",
            "some-id",
            "--gotatun-debug",
        ])
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

        let cli = Cli::try_parse_from(["tunmux", "connection", "disconnect", "some-id"])
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

        let cli = Cli::try_parse_from(["tunmux", "connection", "disconnect", "--all"])
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

        assert!(Cli::try_parse_from(["tunmux", "connection", "disconnect"]).is_err());
        assert!(Cli::try_parse_from([
            "tunmux",
            "connection",
            "disconnect",
            "some-id",
            "--all"
        ])
        .is_err());
    }

    #[test]
    fn parse_connection_mode_and_get() {
        let cli = Cli::try_parse_from(["tunmux", "connection", "mode", "some-id", "automatic"])
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

        let cli = Cli::try_parse_from(["tunmux", "connection", "get", "some-id"])
            .expect("parse connection get");
        match cli.command {
            TopCommand::Connection {
                command: ConnectionCommand::Get { id },
            } => assert_eq!(id, "some-id"),
            _ => panic!("expected connection get command"),
        }
    }

    #[test]
    fn parse_connection_agent_subcommands() {
        for (args, want) in [
            (
                vec!["tunmux", "connection", "agent", "install"],
                std::mem::discriminant(&ConnectionAgentCommand::Install { force: false }),
            ),
            (
                vec!["tunmux", "connection", "agent", "status"],
                std::mem::discriminant(&ConnectionAgentCommand::Status),
            ),
            (
                vec!["tunmux", "connection", "agent", "uninstall"],
                std::mem::discriminant(&ConnectionAgentCommand::Uninstall),
            ),
            (
                vec!["tunmux", "connection", "agent", "run"],
                std::mem::discriminant(&ConnectionAgentCommand::Run),
            ),
        ] {
            let cli = Cli::try_parse_from(args).expect("parse connection agent subcommand");
            match cli.command {
                TopCommand::Connection {
                    command: ConnectionCommand::Agent { command },
                } => assert_eq!(std::mem::discriminant(&command), want),
                _ => panic!("expected connection agent command"),
            }
        }
    }

    #[test]
    fn parse_connection_list_and_ls_alias() {
        for arg in ["list", "ls"] {
            let cli = Cli::try_parse_from(["tunmux", "connection", arg])
                .expect("parse connection list");
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
        let result = Cli::try_parse_from(["tunmux", "connection", "list", "--all", "--global"]);
        assert!(result.is_err());
    }

    #[test]
    fn parse_connection_add_force_requires_name() {
        let missing_name = Cli::try_parse_from([
            "tunmux",
            "connection",
            "add",
            "--file",
            "/tmp/test.conf",
            "--force",
        ]);
        assert!(missing_name.is_err());

        let with_name = Cli::try_parse_from([
            "tunmux",
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
        let cli = Cli::try_parse_from(["tunmux", "connection", "remove", "some-id"])
            .expect("parse connection remove");
        match cli.command {
            TopCommand::Connection {
                command: ConnectionCommand::Remove { id },
            } => assert_eq!(id, "some-id"),
            _ => panic!("expected connection remove command"),
        }
    }
}
