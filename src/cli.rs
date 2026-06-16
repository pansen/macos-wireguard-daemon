use clap::{Args, Parser, Subcommand, ValueEnum};

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

    /// Show active VPN connections and proxy instances
    Status,

    /// Show WireGuard tunnel state for active direct connection(s)
    Wg,

    /// Hook utilities
    Hook {
        #[command(subcommand)]
        command: HookCommand,
    },

    /// Internal: proxy daemon process (hidden)
    #[command(hide = true)]
    ProxyDaemon {
        #[arg(long)]
        netns: String,
        #[arg(long)]
        interface: String,
        #[arg(long)]
        socks_port: u16,
        #[arg(long)]
        http_port: u16,
        #[arg(long)]
        proxy_access_log: bool,
        #[arg(long)]
        pid_file: String,
        #[arg(long)]
        log_file: String,
        #[arg(long)]
        startup_status_file: String,
    },

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
pub enum HookCommand {
    /// Run a predefined hook check now
    Run {
        /// Builtin hook entry
        #[arg(value_enum)]
        builtin: HookBuiltinArg,
    },

    /// Print the hook environment payload for an active instance
    Debug {
        /// Instance name (from `tunmux status`)
        instance: Option<String>,

        /// Provider to scope instance selection when `instance` is omitted
        #[arg(short = 'p', long, value_enum)]
        provider: Option<ProviderArg>,

        /// Hook event payload to print
        #[arg(long, value_enum, default_value = "ifup")]
        event: HookEventArg,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HookEventArg {
    Ifup,
    Ifdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum HookBuiltinArg {
    Connectivity,
    ExternalIp,
    DnsDetection,
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

    /// WireGuard backend: wg-quick, userspace, kernel
    #[arg(short = 'b', long)]
    pub backend: Option<String>,

    /// Start a SOCKS5/HTTP proxy (Linux only; VPN traffic isolated in network namespace)
    #[arg(long)]
    pub proxy: bool,

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
        Cli, ConnectProviderCommand, HookBuiltinArg, HookCommand, ProviderArg, TopCommand,
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
    fn parse_hook_debug_command() {
        let cli = Cli::try_parse_from([
            "tunmux",
            "hook",
            "debug",
            "test-instance",
            "--event",
            "ifdown",
        ])
        .expect("parse hook debug");

        match cli.command {
            TopCommand::Hook {
                command:
                    HookCommand::Debug {
                        instance, provider, ..
                    },
            } => {
                assert_eq!(instance.as_deref(), Some("test-instance"));
                assert!(provider.is_none());
            }
            _ => panic!("expected hook debug command"),
        }
    }

    #[test]
    fn parse_hook_run_builtin_command() {
        let cli = Cli::try_parse_from(["tunmux", "hook", "run", "external-ip"])
            .expect("parse hook run builtin");

        match cli.command {
            TopCommand::Hook {
                command: HookCommand::Run { builtin },
            } => assert_eq!(builtin, HookBuiltinArg::ExternalIp),
            _ => panic!("expected hook run command"),
        }

        let cli = Cli::try_parse_from(["tunmux", "hook", "run", "dns-detection"])
            .expect("parse hook run dns-detection builtin");

        match cli.command {
            TopCommand::Hook {
                command: HookCommand::Run { builtin },
            } => assert_eq!(builtin, HookBuiltinArg::DnsDetection),
            _ => panic!("expected hook run command"),
        }
    }
}
