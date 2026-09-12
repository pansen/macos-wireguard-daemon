use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::Context;
use base64::Engine;

use crate::cli::{WgconfCommand, WgconfConnectArgs};
use crate::config::{self, AppConfig, Provider};
use crate::shared::connection_ops;
use crate::wireguard;
use crate::wireguard::connection_config::ConnectionPeer;

const PROVIDER: Provider = Provider::Wgconf;
const INTERFACE_NAME: &str = "wgconf0";
const PROFILE_DIR: &str = "profiles";

struct ConfigSource {
    display_name: String,
    config_text: String,
    /// Canonicalized path of the source `.conf` (both `--file` and `--profile`
    /// resolve to a concrete file). Informational; the daemon verifies contents.
    source_path: Option<String>,
}

#[derive(Debug)]
struct RoutedConfig {
    private_key: String,
    addresses: Vec<String>,
    dns_servers: Vec<String>,
    mtu: Option<u16>,
    server_public_key: String,
    server_ip: String,
    server_port: u16,
    preshared_key: Option<String>,
    allowed_ips: String,
}

pub async fn dispatch(command: WgconfCommand, config: &AppConfig) -> anyhow::Result<()> {
    match command {
        WgconfCommand::Connect(args) => cmd_connect(args, config),
        WgconfCommand::Disconnect { instance, all } => cmd_disconnect(instance, all),
        WgconfCommand::Status => cmd_status(),
        WgconfCommand::Save { file, name } => cmd_save(&file, &name),
        WgconfCommand::List => cmd_list(),
        WgconfCommand::Remove { name } => cmd_remove(&name),
    }
}

fn cmd_connect(args: WgconfConnectArgs, config: &AppConfig) -> anyhow::Result<()> {
    let backend =
        connection_ops::resolve_connect_backend(args.backend.as_deref(), &config.general.backend)?;
    connection_ops::validate_disable_ipv6_direct_kernel(args.disable_ipv6, backend)?;
    if args.mtu.is_some()
        && !matches!(
            backend,
            wireguard::backend::WgBackend::Kernel | wireguard::backend::WgBackend::Userspace
        )
    {
        anyhow::bail!("--mtu for wgconf is supported only with kernel or userspace backends");
    }
    if let Some(mtu) = args.mtu {
        wireguard::config::validate_mtu(mtu)?;
    }

    let source = resolve_source(args.file.as_deref(), args.profile.as_deref())?;

    if let Some(save_as) = args.save_as.as_deref() {
        save_profile_content(save_as, &source.config_text)?;
        println!("Saved profile {}", save_as);
    }

    let needs_routed_parse = backend == wireguard::backend::WgBackend::Kernel;
    let routed = if needs_routed_parse {
        Some(parse_routed_config(&source.config_text)?)
    } else {
        None
    };

    if args.disable_ipv6 {
        let routed = routed
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing parsed routed config"))?;
        if has_ipv6_interface_address(&routed.addresses) {
            anyhow::bail!(
                "--disable-ipv6 can only be used when Interface.Address has no IPv6 entry"
            );
        }
    }

    connect_direct(
        &source,
        backend,
        routed.as_ref(),
        args.disable_ipv6,
        args.mtu,
        args.if_missing,
    )?;

    Ok(())
}

fn cmd_save(file: &str, name: &str) -> anyhow::Result<()> {
    let text = fs::read_to_string(file).with_context(|| format!("failed to read {}", file))?;
    save_profile_content(name, &text)?;
    println!("Saved profile {} from {}", name, file);
    Ok(())
}

fn cmd_list() -> anyhow::Result<()> {
    let profiles = list_profiles()?;
    if profiles.is_empty() {
        println!("No saved wgconf profiles.");
        return Ok(());
    }

    for name in profiles {
        println!("{}", name);
    }
    Ok(())
}

fn cmd_status() -> anyhow::Result<()> {
    use crate::privileged_client::PrivilegedClient;
    use crate::wireguard::connection::ConnectionState;

    let connections: Vec<ConnectionState> = ConnectionState::load_all()?
        .into_iter()
        .filter(|conn| conn.provider == "wgconf" && conn.is_live())
        .collect();

    if connections.is_empty() {
        println!("Not connected.");
        return Ok(());
    }

    let client = PrivilegedClient::new();
    for (index, conn) in connections.iter().enumerate() {
        if index > 0 {
            println!();
        }
        println!("Connected: {}", conn.server_display_name);
        println!("  instance:  {}", conn.instance_name);
        println!("  interface: {}", conn.interface_name);
        println!("  endpoint:  {}", conn.server_endpoint);
        println!("  backend:   {}", conn.backend);
        if !conn.dns_servers.is_empty() {
            println!("  dns:       {}", conn.dns_servers.join(", "));
        }

        // Live handshake/transfer via `wg show` (through the privileged service). The service is
        // already running while connected, so this does not trigger a new sudo prompt.
        match client.wg_show(&conn.interface_name) {
            Ok(output) if !output.trim().is_empty() => {
                println!();
                println!("{}", crate::color::wg_show(output.trim_end()));
            }
            Ok(_) => {}
            Err(e) => eprintln!("wg show {} failed: {}", conn.interface_name, e),
        }
    }

    Ok(())
}

fn cmd_remove(name: &str) -> anyhow::Result<()> {
    remove_profile(name)?;
    println!("Removed profile {}", name);
    Ok(())
}

fn connect_direct(
    source: &ConfigSource,
    backend: wireguard::backend::WgBackend,
    routed: Option<&RoutedConfig>,
    disable_ipv6: bool,
    mtu: Option<u16>,
    if_missing: bool,
) -> anyhow::Result<()> {
    use wireguard::connection::DIRECT_INSTANCE;

    let _connection_lock = wireguard::connection::ConnectionState::lock()?;
    let already_active = match connection_ops::direct_connection_active()? {
        connection_ops::DirectSlotStatus::Active => {
            if !if_missing {
                anyhow::bail!("Already connected via direct VPN. Disconnect first.");
            }
            // Finding 5 — Incorrect tunnel adoption and connection races:
            // even a matching source path can have changed contents. Continue
            // to the daemon's atomic configuration check before claiming success.
            true
        }
        connection_ops::DirectSlotStatus::ClearedStale(message) => {
            println!("{}", message);
            false
        }
        connection_ops::DirectSlotStatus::Free => false,
    };
    // Finding 5 — Incorrect tunnel adoption and connection races: never
    // invent metadata for an orphan. The privileged up operation verifies its
    // persisted identity (or returns a conflict) before we save local state.

    if !already_active {
        println!("Connecting to {}...", source.display_name);
    }

    let state_endpoint = routed
        .map(|cfg| format_endpoint(&cfg.server_ip, cfg.server_port))
        .unwrap_or_else(|| best_effort_endpoint(&source.config_text));
    let state_dns_servers: Vec<String> =
        wireguard::connection_config::parse_connection_config(&source.config_text)
            .map(|parsed| parsed.dns_servers.iter().map(ToString::to_string).collect())
            .unwrap_or_default();

    match backend {
        wireguard::backend::WgBackend::Userspace => {
            let effective_iface = wireguard::userspace::up_with_mtu(
                &source.config_text,
                INTERFACE_NAME,
                PROVIDER,
                mtu,
            )?;
            let state = wireguard::connection::ConnectionState {
                instance_name: DIRECT_INSTANCE.to_string(),
                provider: PROVIDER.dir_name().to_string(),
                interface_name: effective_iface,
                backend,
                server_endpoint: state_endpoint,
                server_display_name: source.display_name.clone(),
                dns_servers: state_dns_servers.clone(),
                source_path: source.source_path.clone(),
            };
            state.save()?;
        }
        wireguard::backend::WgBackend::Kernel => {
            let routed = routed.ok_or_else(|| anyhow::anyhow!("missing parsed routed config"))?;
            let endpoint_ip: IpAddr = routed
                .server_ip
                .parse()
                .with_context(|| format!("invalid endpoint IP {}", routed.server_ip))?;
            if endpoint_ip.is_ipv6() {
                anyhow::bail!(
                    "kernel direct mode currently supports IPv4 endpoints only (got {})",
                    routed.server_ip
                );
            }
            let (addresses, dns_servers) = routed_param_refs(routed);
            let params = wireguard::config::WgConfigParams {
                private_key: &routed.private_key,
                addresses: &addresses,
                dns_servers: &dns_servers,
                mtu: mtu.or(routed.mtu),
                server_public_key: &routed.server_public_key,
                server_ip: &routed.server_ip,
                server_port: routed.server_port,
                preshared_key: routed.preshared_key.as_deref(),
                allowed_ips: &routed.allowed_ips,
            };
            wireguard::kernel::up(
                &params,
                INTERFACE_NAME,
                PROVIDER.dir_name(),
                &source.display_name,
                disable_ipv6,
            )?;
            // kernel::up builds and saves the _direct state internally, so stamp
            // the informational source path onto it afterwards.
            if source.source_path.is_some() {
                if let Some(mut state) =
                    wireguard::connection::ConnectionState::load(DIRECT_INSTANCE)?
                {
                    state.source_path = source.source_path.clone();
                    state.save()?;
                }
            }
        }
    }

    // Release the state transaction before returning. Verified --if-missing must
    // not rerun connection side effects.
    drop(_connection_lock);
    if already_active {
        println!("Already connected to {}.", source.display_name);
        return Ok(());
    }

    println!(
        "Connected to {} [backend: {}]",
        source.display_name, backend
    );
    Ok(())
}

fn cmd_disconnect(instance: Option<String>, all: bool) -> anyhow::Result<()> {
    connection_ops::cmd_disconnect_provider(PROVIDER, instance, all)
}

/// Reset the privileged daemon's own tunnel record for the direct interface,
/// independent of whatever this process's local `ConnectionState` currently
/// believes. Used by `tunmux reload`, whose whole point is discarding
/// pre-reload state: a desynced privileged-side record must not be able to
/// survive a reload untouched just because the local connection state was
/// already stale or missing. Idempotent when nothing is up.
pub(crate) fn force_reset_direct_interface() -> anyhow::Result<()> {
    wireguard::userspace::down_raw(INTERFACE_NAME).map_err(Into::into)
}

fn resolve_source(file: Option<&str>, profile: Option<&str>) -> anyhow::Result<ConfigSource> {
    match (file, profile) {
        (Some(path), None) => {
            let config_text = fs::read_to_string(path)
                .with_context(|| format!("failed to read WireGuard config file {}", path))?;
            let source_path = Path::new(path);
            let file_name = source_path
                .file_name()
                .and_then(|v| v.to_str())
                .filter(|v| !v.is_empty())
                .unwrap_or(path)
                .to_string();
            Ok(ConfigSource {
                display_name: file_name,
                config_text,
                source_path: canonicalize_source(source_path),
            })
        }
        (None, Some(name)) => {
            let profile_name = validate_profile_name(name)?;
            let config_text = load_profile_content(&profile_name)?;
            let profile_path = profile_path_in(&provider_dir(), &profile_name)?;
            Ok(ConfigSource {
                display_name: format!("profile:{}", profile_name),
                source_path: canonicalize_source(&profile_path),
                config_text,
            })
        }
        (Some(_), Some(_)) => anyhow::bail!("use either --file or --profile, not both"),
        (None, None) => anyhow::bail!("one of --file or --profile is required"),
    }
}

/// Canonicalize a source `.conf` path to a stable identity key for `--if-missing`.
/// Best-effort: a path that can't be resolved (e.g. removed after read) yields
/// `None`, which simply means a later `--if-missing` can't match it and so will
/// fall through to the normal already-connected guard rather than no-op.
fn canonicalize_source(path: &Path) -> Option<String> {
    fs::canonicalize(path)
        .ok()
        .map(|p| p.to_string_lossy().into_owned())
}

fn parse_routed_config(config_text: &str) -> anyhow::Result<RoutedConfig> {
    let parsed = wireguard::connection_config::parse_connection_config(config_text)
        .context("invalid WireGuard configuration for kernel path")?;

    if parsed.dns_servers.is_empty() {
        anyhow::bail!(
            "Interface.DNS is required for kernel mode (direct userspace mode can use as-is config)"
        );
    }

    let peer = select_peer_with_endpoint(&parsed.peers)?;
    let endpoint = peer
        .endpoint
        .ok_or_else(|| anyhow::anyhow!("peer endpoint missing"))?;

    Ok(RoutedConfig {
        private_key: base64_encode(parsed.private_key.as_bytes()),
        addresses: parsed.addresses.iter().map(ToString::to_string).collect(),
        dns_servers: parsed.dns_servers.iter().map(ToString::to_string).collect(),
        mtu: parsed.mtu,
        server_public_key: base64_encode(peer.public_key.as_bytes()),
        server_ip: endpoint.ip().to_string(),
        server_port: endpoint.port(),
        preshared_key: peer.preshared_key.as_ref().map(|psk| base64_encode(psk.as_bytes())),
        allowed_ips: peer
            .allowed_ips
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
    })
}

fn select_peer_with_endpoint(peers: &[ConnectionPeer]) -> anyhow::Result<&ConnectionPeer> {
    peers
        .iter()
        .find(|peer| peer.endpoint.is_some())
        .ok_or_else(|| anyhow::anyhow!("no usable peer found: require a valid Endpoint"))
}

fn base64_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn routed_param_refs(routed: &RoutedConfig) -> (Vec<&str>, Vec<&str>) {
    (
        routed.addresses.iter().map(String::as_str).collect(),
        routed.dns_servers.iter().map(String::as_str).collect(),
    )
}

fn has_ipv6_interface_address(addresses: &[String]) -> bool {
    addresses.iter().any(|cidr| {
        let ip = cidr.split('/').next().unwrap_or_default().trim();
        ip.parse::<IpAddr>().is_ok_and(|addr| addr.is_ipv6())
    })
}

fn best_effort_endpoint(config_text: &str) -> String {
    if let Ok(parsed) = wireguard::connection_config::parse_connection_config(config_text) {
        for peer in parsed.peers {
            if let Some(endpoint) = peer.endpoint {
                return format_endpoint(&endpoint.ip().to_string(), endpoint.port());
            }
        }
    }
    "unknown".to_string()
}

fn format_endpoint(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

fn validate_profile_name(name: &str) -> anyhow::Result<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        anyhow::bail!("profile name cannot be empty");
    }
    if trimmed.len() > 64 {
        anyhow::bail!("profile name is too long (max 64 characters)");
    }
    if !trimmed
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_' || c == '.')
    {
        anyhow::bail!(
            "invalid profile name {:?}; use only lowercase letters, digits, '-', '_' or '.'",
            name
        );
    }
    Ok(trimmed.to_string())
}

fn provider_dir() -> PathBuf {
    config::config_dir(PROVIDER)
}

fn profile_dir_in(provider: &Path) -> PathBuf {
    provider.join(PROFILE_DIR)
}

fn ensure_profile_dirs_in(provider: &Path) -> anyhow::Result<()> {
    if !provider.exists() {
        fs::create_dir_all(provider).with_context(|| {
            format!("failed to create provider directory {}", provider.display())
        })?;
    }
    fs::set_permissions(provider, fs::Permissions::from_mode(0o700)).with_context(|| {
        format!(
            "failed to set provider directory permissions {}",
            provider.display()
        )
    })?;

    let dir = profile_dir_in(provider);
    if !dir.exists() {
        fs::create_dir_all(&dir)
            .with_context(|| format!("failed to create profile directory {}", dir.display()))?;
    }
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).with_context(|| {
        format!(
            "failed to set profile directory permissions {}",
            dir.display()
        )
    })?;
    Ok(())
}

fn profile_path_in(provider: &Path, name: &str) -> anyhow::Result<PathBuf> {
    let valid = validate_profile_name(name)?;
    Ok(profile_dir_in(provider).join(format!("{}.conf", valid)))
}

fn save_profile_content(name: &str, content: &str) -> anyhow::Result<()> {
    save_profile_content_in(&provider_dir(), name, content)
}

fn save_profile_content_in(provider: &Path, name: &str, content: &str) -> anyhow::Result<()> {
    ensure_profile_dirs_in(provider)?;
    let path = profile_path_in(provider, name)?;
    fs::write(&path, content)
        .with_context(|| format!("failed to write profile file {}", path.display()))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).with_context(|| {
        format!(
            "failed to set profile file permissions for {}",
            path.display()
        )
    })?;
    Ok(())
}

fn load_profile_content(name: &str) -> anyhow::Result<String> {
    load_profile_content_in(&provider_dir(), name)
}

fn load_profile_content_in(provider: &Path, name: &str) -> anyhow::Result<String> {
    let path = profile_path_in(provider, name)?;
    fs::read_to_string(&path)
        .with_context(|| format!("profile {:?} not found at {}", name, path.display()))
}

fn list_profiles() -> anyhow::Result<Vec<String>> {
    list_profiles_in(&provider_dir())
}

fn list_profiles_in(provider: &Path) -> anyhow::Result<Vec<String>> {
    let dir = profile_dir_in(provider);
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut names = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|v| v.to_str()) != Some("conf") {
            continue;
        }
        if let Some(stem) = path.file_stem().and_then(|v| v.to_str()) {
            names.push(stem.to_string());
        }
    }
    names.sort();
    Ok(names)
}

fn remove_profile(name: &str) -> anyhow::Result<()> {
    remove_profile_in(&provider_dir(), name)
}

fn remove_profile_in(provider: &Path, name: &str) -> anyhow::Result<()> {
    let path = profile_path_in(provider, name)?;
    if !path.exists() {
        anyhow::bail!("profile {:?} does not exist", name);
    }
    fs::remove_file(&path)
        .with_context(|| format!("failed to remove profile {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        has_ipv6_interface_address, list_profiles_in, parse_routed_config, remove_profile_in,
        save_profile_content_in, validate_profile_name,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_test_dir(name: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "tunmux-wgconf-test-{}-{}-{}",
            name,
            std::process::id(),
            now
        ))
    }

    #[test]
    fn profile_name_validation_rejects_invalid_values() {
        assert!(validate_profile_name("ok.name-1").is_ok());
        assert!(validate_profile_name("UPPER").is_err());
        assert!(validate_profile_name("../bad").is_err());
        assert!(validate_profile_name("bad/name").is_err());
        assert!(validate_profile_name("").is_err());
    }

    const PRIVATE_KEY_B64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    const PUBLIC_KEY_B64: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=";

    #[test]
    fn routed_parse_requires_dns_and_valid_peer_endpoint() {
        let no_dns = format!("[Interface]\nPrivateKey = {PRIVATE_KEY_B64}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {PUBLIC_KEY_B64}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.10:51820\n");
        let err = parse_routed_config(&no_dns).expect_err("dns should be required");
        assert!(err.to_string().contains("Interface.DNS"));

        let with_dns = format!("[Interface]\nPrivateKey = {PRIVATE_KEY_B64}\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = {PUBLIC_KEY_B64}\nAllowedIPs = 0.0.0.0/0\nEndpoint = [2001:db8::1]:51820\n");
        let parsed = parse_routed_config(&with_dns).expect("parse routed config");
        assert_eq!(parsed.server_ip, "2001:db8::1");
        assert_eq!(parsed.server_port, 51820);
        assert_eq!(parsed.mtu, None);

        let with_dns_hostname = format!("[Interface]\nPrivateKey = {PRIVATE_KEY_B64}\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = {PUBLIC_KEY_B64}\nAllowedIPs = 0.0.0.0/0\nEndpoint = localhost:51820\n");
        let parsed = parse_routed_config(&with_dns_hostname).expect("parse hostname endpoint");
        assert_eq!(parsed.server_port, 51820);
    }

    #[test]
    fn routed_parse_retains_interface_mtu() {
        let config = format!("[Interface]\nPrivateKey = {PRIVATE_KEY_B64}\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\nMTU = 1280\n[Peer]\nPublicKey = {PUBLIC_KEY_B64}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.10:51820\n");
        let parsed = parse_routed_config(&config).expect("parse routed config");
        assert_eq!(parsed.mtu, Some(1280));
    }

    #[test]
    fn ipv6_address_detection_works() {
        assert!(!has_ipv6_interface_address(&["10.0.0.2/32".to_string()]));
        assert!(has_ipv6_interface_address(&[
            "10.0.0.2/32".to_string(),
            "fd7d:76ee:e68f:a993::2/128".to_string()
        ]));
    }

    #[test]
    fn profile_storage_permissions_and_listing() {
        let provider_dir = unique_test_dir("profile-storage").join("wgconf");
        std::fs::create_dir_all(&provider_dir).expect("create provider dir");

        save_profile_content_in(&provider_dir, "work", "[Interface]\nPrivateKey = a\n")
            .expect("save work profile");
        save_profile_content_in(&provider_dir, "home", "[Interface]\nPrivateKey = b\n")
            .expect("save home profile");

        let profiles_dir = provider_dir.join("profiles");
        let profile_file = profiles_dir.join("work.conf");

        assert_eq!(
            std::fs::metadata(&provider_dir)
                .expect("provider dir metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&profiles_dir)
                .expect("profiles dir metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert_eq!(
            std::fs::metadata(&profile_file)
                .expect("profile file metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        let names = list_profiles_in(&provider_dir).expect("list profiles");
        assert_eq!(names, vec!["home".to_string(), "work".to_string()]);

        remove_profile_in(&provider_dir, "work").expect("remove profile");
        let names = list_profiles_in(&provider_dir).expect("list profiles after remove");
        assert_eq!(names, vec!["home".to_string()]);

        let _ = std::fs::remove_dir_all(
            provider_dir
                .parent()
                .expect("provider dir should have parent"),
        );
    }
}
