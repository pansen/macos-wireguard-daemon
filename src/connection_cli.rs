//! `tunmux connection ...`: the CLI surface over the privileged
//! connection-store RPCs (`AddConnection`/`ListConnections`/
//! `RemoveConnection`/`ConnectConnection`/`DisconnectConnection`/
//! `SetConnectionMode`/`GetConnection`), plus `agent` (Phase 4's per-user
//! session-reconciliation LaunchAgent, see `session_agent.rs`). This is the
//! Phase 5 CLI: the legacy `wgconf`/`connect`/`disconnect`/`autoconnect`
//! surface has been retired in favor of it (see
//! `doc/connection-store-plan.md`'s Phase 5 addendum for the mapping).
use anyhow::Context;

use crate::cli::{ConnectionCommand, StartModeArg};
use crate::privileged_api::{
    ConnectionId, ConnectionScope, ConnectionStartMode, ConnectionSummary,
};
use crate::privileged_client::PrivilegedClient;

impl From<StartModeArg> for ConnectionStartMode {
    fn from(value: StartModeArg) -> Self {
        match value {
            StartModeArg::Manual => ConnectionStartMode::Manual,
            StartModeArg::Automatic => ConnectionStartMode::Automatic,
        }
    }
}

pub fn dispatch(command: ConnectionCommand) -> anyhow::Result<()> {
    match command {
        ConnectionCommand::Add {
            file,
            global,
            name,
            mtu,
            force,
            start_mode,
        } => cmd_add(&file, global, name, mtu, force, start_mode.into()),
        ConnectionCommand::List { all, global } => cmd_list(all, global),
        ConnectionCommand::Remove { id } => cmd_remove(&id),
        ConnectionCommand::Connect { id, debug } => cmd_connect(&id, debug),
        ConnectionCommand::Disconnect { id, all } => cmd_disconnect(id.as_deref(), all),
        ConnectionCommand::Mode { id, start_mode } => cmd_mode(&id, start_mode.into()),
        ConnectionCommand::Get { id } => cmd_get(&id),
        ConnectionCommand::Agent { command } => crate::session_agent::dispatch(command),
    }
}

/// Resolve `id_or_name` to a [`ConnectionId`], accepting either a literal id
/// or a connection's `--name`. Tried as an id first (so a name that happens
/// to look like a UUID is a validation error at `add` time, not a silent
/// shadowing here -- see `validate_name_charset`'s id-shaped-name check).
///
/// A name is looked up among the caller's own connections first and only
/// among `Global` ones if that comes up empty, rather than across both at
/// once: otherwise an unrelated global connection sharing a name with one of
/// the caller's own would turn an everyday, unambiguous name into a
/// false-positive "ambiguous" error. `AddConnection` rejects a name
/// collision within a given scope outside of `--force`, so a lookup that
/// does search a scope normally resolves to exactly one connection; a
/// leftover ambiguity (e.g. a `--force` cleanup that didn't finish) is
/// reported rather than silently picking one.
fn resolve_id(client: &PrivilegedClient, id_or_name: &str) -> anyhow::Result<ConnectionId> {
    if let Ok(id) = id_or_name.parse() {
        return Ok(id);
    }
    let by_name = |scope: ConnectionScope| -> anyhow::Result<Vec<ConnectionSummary>> {
        Ok(client
            .list_connections(scope)?
            .into_iter()
            .filter(|conn| conn.name.as_deref() == Some(id_or_name))
            .collect())
    };
    let mut matches = by_name(ConnectionScope::Mine)?;
    if matches.is_empty() {
        matches = by_name(ConnectionScope::Global)?;
    }
    match matches.len() {
        0 => anyhow::bail!(
            "no connection named {id_or_name:?} (and it is not a valid connection id)"
        ),
        1 => Ok(matches.remove(0).id),
        _ => anyhow::bail!(
            "connection name {id_or_name:?} is ambiguous ({} matches); use the connection id instead",
            matches.len()
        ),
    }
}

fn cmd_add(
    file: &str,
    global: bool,
    name: Option<String>,
    mtu: Option<u16>,
    force: bool,
    start_mode: ConnectionStartMode,
) -> anyhow::Result<()> {
    let conf_text =
        std::fs::read_to_string(file).with_context(|| format!("failed to read {file}"))?;
    let client = PrivilegedClient::new();
    let id = client.add_connection(&conf_text, global, start_mode, name.clone(), mtu, force)?;
    println!("Connection id: {id}");
    println!(
        "  (byte-for-byte-identical resubmissions of this file will return the same id \
         without prompting again)"
    );

    // `add_connection` above already returned the *current* id for this
    // content, whether that meant creating a new record or (on an unmodified
    // resubmission) matching an existing one -- so anything else sharing
    // `name` is genuinely stale, not just an older copy of what we now have.
    // Comparing ids like this instead of recomputing a fingerprint client-side
    // means an unmodified re-run never needlessly removes-then-recreates the
    // very record it just matched.
    if force {
        let name = name.expect("clap enforces --force requires --name");
        let scope = if global {
            ConnectionScope::Global
        } else {
            ConnectionScope::Mine
        };
        let stale: Vec<_> = client
            .list_connections(scope)?
            .into_iter()
            .filter(|conn| conn.id != id && conn.name.as_deref() == Some(name.as_str()))
            .collect();
        for conn in stale {
            println!(
                "Removing stale connection {} (same name {name:?}, superseded by {id})",
                conn.id
            );
            client.remove_connection(conn.id)?;
        }
    }
    Ok(())
}

fn cmd_list(all: bool, global: bool) -> anyhow::Result<()> {
    let scope = if all {
        ConnectionScope::All
    } else if global {
        ConnectionScope::Global
    } else {
        ConnectionScope::Mine
    };
    print_connections(scope)
}

/// Print stored connections for `scope`, or "No stored connections." if
/// there are none.
fn print_connections(scope: ConnectionScope) -> anyhow::Result<()> {
    let client = PrivilegedClient::new();
    let connections = client.list_connections(scope)?;
    if connections.is_empty() {
        println!("No stored connections.");
        return Ok(());
    }

    for conn in connections {
        println!(
            "{id}  {name:<20}  global={global:<5}  owner={owner:<6}  mode={mode:<9}  \
             connected={connected:<5}  interface={interface}",
            id = conn.id,
            name = conn.name.as_deref().unwrap_or("-"),
            global = conn.global,
            owner = conn
                .owner_uid
                .map(|uid| uid.to_string())
                .unwrap_or_else(|| "-".to_string()),
            mode = format!("{:?}", conn.start_mode),
            connected = conn.connected,
            interface = conn.interface,
        );
    }
    Ok(())
}

fn cmd_remove(id: &str) -> anyhow::Result<()> {
    let client = PrivilegedClient::new();
    let id = resolve_id(&client, id)?;
    client.remove_connection(id)?;
    println!("Removed connection {id}");
    Ok(())
}

fn cmd_connect(id: &str, debug: bool) -> anyhow::Result<()> {
    let client = PrivilegedClient::new();
    let id = resolve_id(&client, id)?;
    client.connect_connection(id, debug)?;
    println!("Connected {id}");
    Ok(())
}

fn cmd_disconnect(id: Option<&str>, all: bool) -> anyhow::Result<()> {
    let client = PrivilegedClient::new();
    if all {
        let connected: Vec<_> = client
            .list_connections(ConnectionScope::Mine)?
            .into_iter()
            .filter(|conn| conn.connected)
            .collect();
        if connected.is_empty() {
            println!("Not connected.");
            return Ok(());
        }
        // Best-effort: one stuck connection must not prevent tearing down
        // the rest. Report failures but keep going, then fail the command
        // overall if any of them failed.
        let mut failed = false;
        for conn in connected {
            match client.disconnect_connection(conn.id) {
                Ok(()) => println!("Disconnected {}", conn.id),
                Err(error) => {
                    eprintln!("Failed to disconnect {}: {error:#}", conn.id);
                    failed = true;
                }
            }
        }
        anyhow::ensure!(!failed, "one or more connections failed to disconnect");
        return Ok(());
    }

    // clap enforces exactly one of `id`/`--all` at parse time.
    let id = resolve_id(&client, id.expect("clap enforces id is set without --all"))?;
    client.disconnect_connection(id)?;
    println!("Disconnected {id}");
    Ok(())
}

fn cmd_mode(id: &str, start_mode: ConnectionStartMode) -> anyhow::Result<()> {
    let client = PrivilegedClient::new();
    let id = resolve_id(&client, id)?;
    client.set_connection_mode(id, start_mode)?;
    println!("Set {id} start mode to {start_mode:?}");
    Ok(())
}

fn cmd_get(id: &str) -> anyhow::Result<()> {
    let client = PrivilegedClient::new();
    let id = resolve_id(&client, id)?;
    let conn = client.get_connection(id)?;
    println!("id:          {}", conn.id);
    println!("name:        {}", conn.name.as_deref().unwrap_or("-"));
    println!("global:      {}", conn.global);
    println!(
        "owner_uid:   {}",
        conn.owner_uid
            .map(|uid| uid.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    println!("start_mode:  {:?}", conn.start_mode);
    println!("interface:   {}", conn.interface);
    println!("connected:   {}", conn.connected);
    println!("addresses:   {}", conn.addresses.join(", "));
    println!("dns_servers: {}", conn.dns_servers.join(", "));
    println!(
        "mtu:         {}",
        conn.mtu
            .map(|m| m.to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    if let Some(fingerprint) = &conn.fingerprint {
        println!("fingerprint: {fingerprint}");
    }
    println!("peers:");
    for peer in &conn.peers {
        println!(
            "  {}  allowed_ips=[{}]  endpoint={}  has_preshared_key={}",
            peer.public_key,
            peer.allowed_ips.join(", "),
            peer.endpoint.as_deref().unwrap_or("-"),
            peer.has_preshared_key,
        );
    }
    println!("created_at:  {}", conn.created_at);
    println!("updated_at:  {}", conn.updated_at);
    Ok(())
}
