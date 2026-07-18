use crate::config::{AppConfig, Provider};
use crate::shared::hooks;
use crate::wireguard;
use crate::wireguard::backend::WgBackend;
use crate::wireguard::connection::ConnectionState;

/// Standard provider disconnect: delegates to `disconnect_provider_connections`
/// with `disconnect_one_provider_connection`.
pub fn cmd_disconnect_provider(
    provider: Provider,
    instance: Option<String>,
    all: bool,
    config: &AppConfig,
) -> anyhow::Result<()> {
    disconnect_provider_connections(provider.dir_name(), instance, all, |conn| {
        disconnect_one_provider_connection(conn, provider, config)
    })
}

pub fn resolve_connect_backend(
    backend_arg: Option<&str>,
    default_backend: &str,
) -> anyhow::Result<WgBackend> {
    let backend_str = backend_arg.unwrap_or(default_backend);
    WgBackend::from_str_arg(backend_str)
}

pub fn validate_disable_ipv6_direct_kernel(
    disable_ipv6: bool,
    backend: WgBackend,
) -> anyhow::Result<()> {
    if disable_ipv6 && backend != WgBackend::Kernel {
        anyhow::bail!("--disable-ipv6 is supported only for direct kernel mode");
    }

    Ok(())
}

pub fn disconnect_provider_connections<F>(
    provider_name: &str,
    instance: Option<String>,
    all: bool,
    mut disconnect_one: F,
) -> anyhow::Result<()>
where
    F: FnMut(&ConnectionState) -> anyhow::Result<()>,
{
    if all {
        let connections = ConnectionState::load_all()?;
        let mine: Vec<_> = connections
            .into_iter()
            .filter(|c| c.provider == provider_name)
            .collect();
        if mine.is_empty() {
            println!("No active {} connections.", provider_name);
            return Ok(());
        }
        for conn in mine {
            disconnect_one(&conn)?;
            println!("Disconnected {}", conn.instance_name);
        }
        return Ok(());
    }

    if let Some(ref name) = instance {
        let conn = ConnectionState::load(name)?
            .ok_or_else(|| anyhow::anyhow!("no connection with instance {:?}", name))?;
        if conn.provider != provider_name {
            anyhow::bail!(
                "instance {:?} belongs to provider {:?}, not {}",
                name,
                conn.provider,
                provider_name
            );
        }
        disconnect_one(&conn)?;
        println!("Disconnected {}", name);
        return Ok(());
    }

    let connections = ConnectionState::load_all()?;
    let mine: Vec<_> = connections
        .into_iter()
        .filter(|c| c.provider == provider_name)
        .collect();

    match mine.len() {
        0 => {
            println!("Not connected.");
        }
        1 => {
            let conn = &mine[0];
            disconnect_one(conn)?;
            println!("Disconnected {}", conn.instance_name);
        }
        _ => {
            println!("Multiple active connections. Specify which to disconnect:\n");
            for conn in &mine {
                println!("  {}  {}", conn.instance_name, conn.server_display_name);
            }
            println!("\nUsage: tunmux disconnect <instance>");
            println!(
                "       tunmux disconnect --provider {} --all",
                provider_name
            );
        }
    }

    Ok(())
}

pub fn disconnect_one_provider_connection(
    state: &ConnectionState,
    provider: Provider,
    config: &AppConfig,
) -> anyhow::Result<()> {
    let teardown = match state.backend {
        WgBackend::Kernel => wireguard::kernel::down(state),
        WgBackend::WgQuick => wireguard::wg_quick::down(&state.interface_name, provider),
        WgBackend::Userspace => wireguard::userspace::down(&state.interface_name, provider),
    };
    if let Err(error) = teardown {
        // A failed teardown shouldn't strand the state file and wedge future
        // connects -- but only when the tunnel is genuinely gone (interface
        // already removed after a reboot, an unreachable privileged helper for
        // an already-dead tunnel, etc.). If the tunnel is still live, dropping
        // the state would orphan it: the routes/DNS stay in place with no state
        // file left to disconnect it. Surface the error and keep the state.
        if state.is_live() {
            return Err(anyhow::Error::new(error).context(format!(
                "failed to tear down still-live connection {:?}; leaving state intact",
                state.instance_name
            )));
        }
        tracing::warn!(
            instance = %state.instance_name,
            interface = %state.interface_name,
            backend = ?state.backend,
            error = %error,
            "connection teardown failed but tunnel is no longer live; removing stale state"
        );
        eprintln!(
            "Warning: teardown of {} ({}) reported errors; system DNS or routes may not be fully restored: {}",
            state.instance_name, state.interface_name, error
        );
    }
    ConnectionState::remove(&state.instance_name)?;

    hooks::run_ifdown(config, provider, state);
    Ok(())
}

/// Outcome of probing the direct (`_direct`) connection slot.
pub enum DirectSlotStatus {
    /// A real, still-active tunnel occupies the slot; the caller should refuse
    /// to start a new one.
    Active,
    /// The slot is free.
    Free,
    /// Stale state was found (a reboot/crash left it behind) and removed. Carries
    /// a user-facing message the CLI layer may choose to print.
    ClearedStale(String),
}

/// Detect whether a live direct (`_direct`) tunnel currently exists, clearing
/// stale state left behind by a reboot or crash.
///
/// Returns [`DirectSlotStatus::Active`] when a real, still-active tunnel occupies
/// the direct slot, and otherwise frees the slot -- removing any orphaned
/// `_direct` state file so a dead connection can never permanently wedge
/// `connect`. This is a shared helper with no stdout side-effects; callers decide
/// whether and how to surface [`DirectSlotStatus::ClearedStale`] to the user.
pub fn direct_connection_active() -> anyhow::Result<DirectSlotStatus> {
    use crate::wireguard::connection::DIRECT_INSTANCE;

    match ConnectionState::load(DIRECT_INSTANCE) {
        Ok(Some(state)) => {
            if state.is_live() {
                return Ok(DirectSlotStatus::Active);
            }
            tracing::warn!(
                interface = %state.interface_name,
                backend = ?state.backend,
                server = %state.server_display_name,
                "clearing stale direct connection state (no live tunnel; likely a reboot or crash)"
            );
            let message = format!(
                "Clearing stale connection state for '{}' (previous tunnel no longer active).",
                state.server_display_name
            );
            ConnectionState::remove(DIRECT_INSTANCE)?;
            Ok(DirectSlotStatus::ClearedStale(message))
        }
        Ok(None) => Ok(DirectSlotStatus::Free),
        // A corrupt/unreadable state file would otherwise wedge connect forever.
        Err(error) => {
            tracing::warn!(error = %error, "removing unreadable direct connection state");
            ConnectionState::remove(DIRECT_INSTANCE)?;
            Ok(DirectSlotStatus::ClearedStale(
                "Clearing unreadable connection state (previous tunnel no longer active)."
                    .to_string(),
            ))
        }
    }
}

/// Returns the live [`ConnectionState`] for the direct slot, or `None` when no
/// active tunnel exists. Does not prune stale state; callers that also need
/// cleanup should call [`direct_connection_active`] first.
pub fn live_direct_connection() -> anyhow::Result<Option<ConnectionState>> {
    use crate::wireguard::connection::DIRECT_INSTANCE;
    Ok(ConnectionState::load(DIRECT_INSTANCE)?.filter(|s| s.is_live()))
}
