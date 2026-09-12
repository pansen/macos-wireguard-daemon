//! `tunmux connection ...`: a minimal, additive CLI surface over the new
//! privileged connection-store RPCs (`AddConnection`/`ListConnections`/
//! `RemoveConnection`). Deliberately thin -- this is not the Phase 5 CLI
//! rework (`wgconf connect`/`disconnect` still own the actual tunnel
//! lifecycle); it exists so the new backend can be exercised for real
//! instead of only through unit tests, per the design plan's own suggestion
//! to add "a temporary debug CLI flag" for this.
use anyhow::Context;

use crate::cli::ConnectionCommand;
use crate::privileged_api::{ConnectionId, ConnectionScope, ConnectionStartMode};
use crate::privileged_client::PrivilegedClient;

pub fn dispatch(command: ConnectionCommand) -> anyhow::Result<()> {
    match command {
        ConnectionCommand::Add {
            file,
            global,
            name,
            mtu,
            force,
        } => cmd_add(&file, global, name, mtu, force),
        ConnectionCommand::List { all, global } => cmd_list(all, global),
        ConnectionCommand::Remove { id } => cmd_remove(&id),
    }
}

fn cmd_add(
    file: &str,
    global: bool,
    name: Option<String>,
    mtu: Option<u16>,
    force: bool,
) -> anyhow::Result<()> {
    let conf_text =
        std::fs::read_to_string(file).with_context(|| format!("failed to read {file}"))?;
    let client = PrivilegedClient::new();
    let id = client.add_connection(&conf_text, global, ConnectionStartMode::Manual, name.clone(), mtu)?;
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
/// there are none. Shared by `tunmux connection list` and `tunmux status`
/// (which shows the caller's own stored connections alongside the legacy
/// per-provider connection table while the new backend has no CLI-driven
/// connect/disconnect of its own yet).
pub fn print_connections(scope: ConnectionScope) -> anyhow::Result<()> {
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
    let id: ConnectionId = id
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid connection id {id:?}"))?;
    let client = PrivilegedClient::new();
    client.remove_connection(id)?;
    println!("Removed connection {id}");
    Ok(())
}
