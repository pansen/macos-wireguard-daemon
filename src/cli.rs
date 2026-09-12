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
    /// WireGuard config file/profile commands
    Wgconf {
        #[command(subcommand)]
        command: WgconfCommand,
    },

    /// Connect to a VPN server (`tunmux connect <provider> ...`)
    Connect {
        #[command(subcommand)]
        provider: ConnectProviderCommand,
    },

    /// Disconnect VPN connection(s)
    Disconnect {
        /// Instance name to disconnect (from `tunmux status`)
        instance: Option<String>,

        /// Provider to scope disconnect operations
        #[arg(short = 'p', long, value_enum)]
        provider: Option<ProviderArg>,

        /// Disconnect all active connections (all providers unless --provider is set)
        #[arg(short = 'a', long, conflicts_with = "instance")]
        all: bool,
    },

    /// Show active VPN connections, including WireGuard tunnel state
    Status,

    /// Manage the privileged launchd daemon (system domain)
    Launchd {
        #[command(subcommand)]
        command: LaunchdCommand,
    },

    /// Manage the per-user autoconnect LaunchAgent (GUI domain)
    Autoconnect {
        #[command(subcommand)]
        command: AutoconnectCommand,
    },

    /// Re-bootstrap both launchd services and bring the tunnel back up
    ///
    /// Runs, in order:
    ///   sudo tunmux launchd install   (re-registers the privileged daemon)
    ///   tunmux disconnect --all       (drops tunnels left over from before)
    ///   tunmux autoconnect install -f (re-registers the agent, reconnects)
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

#[derive(Subcommand)]
pub enum AutoconnectCommand {
    /// Install and start the per-user autoconnect LaunchAgent (run WITHOUT sudo)
    Install {
        /// WireGuard .conf file path
        #[arg(long, required_unless_present = "profile", conflicts_with = "profile")]
        file: Option<String>,

        /// Saved profile name
        #[arg(long, required_unless_present = "file", conflicts_with = "file")]
        profile: Option<String>,

        /// Overwrite and reload an existing installation
        #[arg(short = 'f', long)]
        force: bool,
    },
    /// List installed autoconnect LaunchAgent files (alias: ls)
    #[command(visible_alias = "ls")]
    List,
    /// Reload (kickstart) the autoconnect LaunchAgent
    Reload,
    /// Stop and unregister the autoconnect LaunchAgent
    Uninstall,
}

#[derive(Args, Clone)]
pub struct ReloadArgs {
    /// WireGuard .conf file the autoconnect agent should use. Defaults to the
    /// source of the installed agent, so an existing setup needs no argument.
    #[arg(long, conflicts_with = "profile")]
    pub file: Option<String>,

    /// Saved profile the autoconnect agent should use. Defaults to the source
    /// of the installed agent.
    #[arg(long, conflicts_with = "file")]
    pub profile: Option<String>,

    /// Log at the usual level instead of debug, leaving only the step headers
    /// and anything the steps report at info level or above.
    #[arg(short = 's', long, conflicts_with = "verbose")]
    pub silent: bool,
}

pub type ProviderArg = crate::config::Provider;

#[derive(Subcommand)]
pub enum ConnectProviderCommand {
    /// Connect using a WireGuard config file/profile
    Wgconf(WgconfConnectArgs),
}

#[derive(Args, Clone)]
pub struct WgconfConnectArgs {
    /// WireGuard .conf file path
    #[arg(long, required_unless_present = "profile", conflicts_with = "profile")]
    pub file: Option<String>,

    /// Saved profile name
    #[arg(long, required_unless_present = "file", conflicts_with = "file")]
    pub profile: Option<String>,

    /// Save loaded config as a reusable profile name
    #[arg(long)]
    pub save_as: Option<String>,

    /// WireGuard backend: userspace, kernel
    #[arg(short = 'b', long)]
    pub backend: Option<String>,

    /// Disable host IPv6 egress while connected (only valid for direct kernel mode with IPv4-only config)
    #[arg(long)]
    pub disable_ipv6: bool,

    /// Set WireGuard interface MTU (direct kernel or userspace mode)
    #[arg(long)]
    pub mtu: Option<u16>,

    /// Exit 0 without reconnecting if this same source is already the live tunnel
    /// (direct mode). A different live source still errors. Checks presence only,
    /// not whether the config changed on disk.
    #[arg(long)]
    pub if_missing: bool,
}

#[derive(Subcommand)]
pub enum WgconfCommand {
    /// Connect from a WireGuard config file or saved profile
    Connect(WgconfConnectArgs),

    /// Disconnect from VPN
    Disconnect {
        /// Instance name to disconnect (from `tunmux status`). If omitted,
        /// disconnects the sole active connection or lists choices.
        instance: Option<String>,

        /// Disconnect all active connections for this provider
        #[arg(short = 'a', long, conflicts_with = "instance")]
        all: bool,
    },

    /// Show wgconf connection status (and `wg show` transfer/handshake)
    Status,

    /// Save a WireGuard config file as a named profile
    Save {
        /// WireGuard .conf file path
        #[arg(long)]
        file: String,

        /// Profile name
        #[arg(long)]
        name: String,
    },

    /// List saved profiles
    List,

    /// Remove a saved profile
    Remove {
        /// Profile name
        name: String,
    },
}

#[cfg(test)]
mod tests {
    use super::{
        AutoconnectCommand, Cli, ConnectProviderCommand, LaunchdCommand, ProviderArg, TopCommand,
        WgconfCommand,
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
    fn parse_connect_wgconf_with_file() {
        let cli = Cli::try_parse_from([
            "tunmux",
            "connect",
            "wgconf",
            "--file",
            "/tmp/test.conf",
            "--backend",
            "userspace",
            "--disable-ipv6",
        ])
        .expect("parse connect wgconf file");

        match cli.command {
            TopCommand::Connect {
                provider: ConnectProviderCommand::Wgconf(args),
            } => assert!(args.disable_ipv6),
            other => panic!("unexpected command: {:?}", std::mem::discriminant(&other)),
        }
    }

    #[test]
    fn parse_connect_wgconf_with_profile() {
        let cli = Cli::try_parse_from([
            "tunmux",
            "connect",
            "wgconf",
            "--profile",
            "work",
            "--save-as",
            "saved-work",
        ])
        .expect("parse connect wgconf profile");

        match cli.command {
            TopCommand::Connect {
                provider: ConnectProviderCommand::Wgconf(args),
            } => {
                assert_eq!(args.profile.as_deref(), Some("work"));
                assert_eq!(args.save_as.as_deref(), Some("saved-work"));
            }
            _ => panic!("expected wgconf connect provider"),
        }
    }

    #[test]
    fn parse_connect_wgconf_requires_exactly_one_source() {
        let missing = Cli::try_parse_from(["tunmux", "connect", "wgconf"]);
        assert!(missing.is_err());

        let both = Cli::try_parse_from([
            "tunmux",
            "connect",
            "wgconf",
            "--file",
            "/tmp/a.conf",
            "--profile",
            "a",
        ]);
        assert!(both.is_err());
    }

    #[test]
    fn parse_provider_prefixed_wgconf_commands() {
        let cli = Cli::try_parse_from(["tunmux", "wgconf", "connect", "--profile", "home"])
            .expect("parse wgconf connect");
        match cli.command {
            TopCommand::Wgconf {
                command: WgconfCommand::Connect(args),
            } => assert_eq!(args.profile.as_deref(), Some("home")),
            _ => panic!("expected wgconf connect command"),
        }

        let cli = Cli::try_parse_from(["tunmux", "disconnect", "--provider", "wgconf"])
            .expect("parse disconnect provider wgconf");
        match cli.command {
            TopCommand::Disconnect {
                provider: Some(ProviderArg::Wgconf),
                ..
            } => {}
            _ => panic!("expected disconnect provider wgconf"),
        }
    }

    #[test]
    fn parse_mtu_for_wgconf_connect_command() {
        let wgconf = Cli::try_parse_from([
            "tunmux",
            "connect",
            "wgconf",
            "--file",
            "/tmp/test.conf",
            "--backend",
            "kernel",
            "--mtu",
            "1360",
        ])
        .expect("parse wgconf mtu");
        match wgconf.command {
            TopCommand::Connect {
                provider: ConnectProviderCommand::Wgconf(args),
            } => assert_eq!(args.mtu, Some(1360)),
            _ => panic!("expected wgconf connect provider"),
        }
    }

    #[test]
    fn parse_provider_disconnect_rejects_instance_with_all() {
        let wgconf = Cli::try_parse_from(["tunmux", "wgconf", "disconnect", "x", "--all"]);
        assert!(wgconf.is_err());
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
    fn parse_autoconnect_install_with_file() {
        let cli =
            Cli::try_parse_from(["tunmux", "autoconnect", "install", "--file", "/tmp/x.conf"])
                .expect("parse autoconnect install --file");

        match cli.command {
            TopCommand::Autoconnect {
                command:
                    AutoconnectCommand::Install {
                        file,
                        profile,
                        force,
                    },
            } => {
                assert_eq!(file.as_deref(), Some("/tmp/x.conf"));
                assert!(profile.is_none());
                assert!(!force);
            }
            _ => panic!("expected autoconnect install command"),
        }
    }

    #[test]
    fn parse_autoconnect_install_with_profile_and_force() {
        let cli = Cli::try_parse_from([
            "tunmux",
            "autoconnect",
            "install",
            "--profile",
            "work",
            "--force",
        ])
        .expect("parse autoconnect install --profile --force");

        match cli.command {
            TopCommand::Autoconnect {
                command:
                    AutoconnectCommand::Install {
                        file,
                        profile,
                        force,
                    },
            } => {
                assert!(file.is_none());
                assert_eq!(profile.as_deref(), Some("work"));
                assert!(force);
            }
            _ => panic!("expected autoconnect install command"),
        }
    }

    #[test]
    fn parse_autoconnect_install_requires_exactly_one_source() {
        let missing = Cli::try_parse_from(["tunmux", "autoconnect", "install"]);
        assert!(missing.is_err());

        let both = Cli::try_parse_from([
            "tunmux",
            "autoconnect",
            "install",
            "--file",
            "/tmp/a.conf",
            "--profile",
            "a",
        ]);
        assert!(both.is_err());
    }

    #[test]
    fn parse_autoconnect_reload_and_uninstall() {
        for (arg, want) in [
            (
                "reload",
                std::mem::discriminant(&AutoconnectCommand::Reload),
            ),
            (
                "uninstall",
                std::mem::discriminant(&AutoconnectCommand::Uninstall),
            ),
        ] {
            let cli =
                Cli::try_parse_from(["tunmux", "autoconnect", arg]).expect("parse autoconnect");
            match cli.command {
                TopCommand::Autoconnect { command } => {
                    assert_eq!(std::mem::discriminant(&command), want)
                }
                _ => panic!("expected autoconnect command"),
            }
        }
    }

    #[test]
    fn parse_reload_with_optional_source() {
        let bare = Cli::try_parse_from(["tunmux", "reload"]).expect("parse bare reload");
        match bare.command {
            TopCommand::Reload(args) => {
                assert!(args.file.is_none());
                assert!(args.profile.is_none());
            }
            _ => panic!("expected reload command"),
        }

        let with_profile =
            Cli::try_parse_from(["tunmux", "reload", "--profile", "work"]).expect("parse reload");
        match with_profile.command {
            TopCommand::Reload(args) => assert_eq!(args.profile.as_deref(), Some("work")),
            _ => panic!("expected reload command"),
        }

        let both = Cli::try_parse_from([
            "tunmux",
            "reload",
            "--file",
            "/tmp/a.conf",
            "--profile",
            "work",
        ]);
        assert!(both.is_err());
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
    fn parse_autoconnect_list_and_ls_alias() {
        for arg in ["list", "ls"] {
            let cli = Cli::try_parse_from(["tunmux", "autoconnect", arg])
                .expect("parse autoconnect list");
            match cli.command {
                TopCommand::Autoconnect { command } => assert_eq!(
                    std::mem::discriminant(&command),
                    std::mem::discriminant(&AutoconnectCommand::List)
                ),
                _ => panic!("expected autoconnect list command"),
            }
        }
    }
}
