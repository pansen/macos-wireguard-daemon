//! `wgd connection ...`: the CLI surface over the privileged
//! connection-store RPCs (`AddConnection`/`ListConnections`/
//! `RemoveConnection`/`ConnectConnection`/`DisconnectConnection`/
//! `SetConnectionMode`/`GetConnection`/`RefreshConnection`). This is the Phase 5 CLI: the legacy
//! `wgconf`/`connect`/`disconnect`/`autoconnect` surface has been retired in
//! favor of it (see `doc/connection-store-plan.md`'s Phase 5 addendum for the
//! mapping). The per-user session-reconciliation LaunchAgent lives under
//! `wgd launchd agent ...` instead (see `session_agent.rs`).
use std::time::Duration;

use anyhow::Context;

use crate::cli::{ConnectionCommand, StartModeArg};
use crate::error::AppError;
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
        ConnectionCommand::Refresh { id, file } => cmd_refresh(&id, file.as_deref()),
        ConnectionCommand::Remove { id } => cmd_remove(&id),
        ConnectionCommand::Connect { id, debug } => cmd_connect(&id, debug),
        ConnectionCommand::Disconnect { id, all } => cmd_disconnect(id.as_deref(), all),
        ConnectionCommand::Mode { id, start_mode } => cmd_mode(&id, start_mode.into()),
        ConnectionCommand::Get { id } => cmd_get(&id),
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
    if matches.is_empty() && nix::unistd::geteuid().is_root() {
        // Under `sudo`, `Mine` only matches `owner_uid == Some(0)`. Check the
        // invoking user's connections (`SUDO_UID`) and then all connections so
        // `sudo wgd ... <name>` works for per-user connections too.
        let all = by_name(ConnectionScope::All)?;
        let sudo_uid = std::env::var("SUDO_UID")
            .ok()
            .and_then(|s| s.parse::<u32>().ok());
        if let Some(uid) = sudo_uid {
            matches = all
                .iter()
                .filter(|conn| conn.owner_uid == Some(uid))
                .cloned()
                .collect();
        }
        if matches.is_empty() {
            matches = all;
        }
    }
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

/// Resolve a connection id or `--name` to its interface name (`wg-xxxxxxxx`).
/// Used by `wgd logs <connection>` to map a user-facing connection identifier
/// to `/var/log/wgd/<interface>.log`.
pub fn resolve_interface(client: &PrivilegedClient, id_or_name: &str) -> anyhow::Result<String> {
    let id = resolve_id(client, id_or_name)?;
    match client.get_connection(id) {
        Ok(conn) => Ok(conn.interface),
        Err(_) => Ok(id.interface_name()),
    }
}

/// Id plus name for output. Best effort: falls back to the bare id if the
/// lookup fails, since the action being reported has already succeeded.
fn label_for(client: &PrivilegedClient, id: ConnectionId) -> String {
    match client.get_connection(id) {
        Ok(conn) => conn.label(),
        Err(_) => id.to_string(),
    }
}

/// How long a completion lookup will wait on the daemon before giving up.
///
/// A <TAB> that hangs the terminal is worse than one that offers nothing, and
/// the daemon can accept a connection and then stall (a connect holding the
/// connection lock, a wedged helper). The plain `connection` subcommands
/// deliberately have no such cap -- they are allowed to wait -- so this bound
/// lives here rather than on the client's default.
const COMPLETION_TIMEOUT: Duration = Duration::from_millis(750);

/// Completion candidates for the `<ID>` positional of `remove`/`connect`/
/// `disconnect`/`mode`/`get`/`refresh`: every connection the caller can name, offered
/// both by id and by `--name`, since `resolve_id` accepts either.
///
/// This runs on every <TAB>, so it stays quiet and bounded. Every failure --
/// no daemon, no socket, a timeout, a denied scope -- collapses to "no
/// candidates" rather than printing an error into the shell's completion
/// buffer.
///
/// It does *not* promise to leave the daemon alone. Completion never
/// escalates (see the autostart and transport guards below), but the control
/// socket is held by launchd with `RunAtLoad` false, so merely connecting to
/// it can start the daemon on demand, exactly as any other `wgd` command
/// does. That daemon exits on the idle timeout its plist sets.
pub fn complete_connection_id(
    current: &std::ffi::OsStr,
) -> Vec<clap_complete::engine::CompletionCandidate> {
    let Some(current) = current.to_str() else {
        return Vec::new();
    };
    // The stdio transport reaches the daemon by running
    // `sudo wgd privileged --serve --stdio` for *every* request, which
    // would put a password prompt behind every <TAB>. `without_autostart`
    // below does not cover it: it only gates the socket transport's own
    // spawn-a-daemon fallback. So don't complete at all under stdio.
    if !matches!(
        crate::config::load_config().general.privileged_transport,
        crate::config::PrivilegedTransport::Socket
    ) {
        return Vec::new();
    }
    let client = PrivilegedClient::new()
        .without_autostart()
        .with_request_timeout(COMPLETION_TIMEOUT);
    let mine = client
        .list_connections(ConnectionScope::Mine)
        .unwrap_or_default();
    let global = client
        .list_connections(ConnectionScope::Global)
        .unwrap_or_default();

    // Ids are unique, so every connection contributes one. Names are not:
    // `resolve_id` searches `Mine` first and only falls back to `Global`, so
    // a global connection sharing a name with one of the caller's own can
    // never be selected by that name. Offering it would both duplicate the
    // entry in the picker and point at a record the name doesn't reach.
    let mut offered_names: Vec<&str> = Vec::new();
    let mut candidates = Vec::new();
    for conn in mine.iter().chain(global.iter()) {
        // Shells that render candidate help (zsh, fish) show the same fields
        // `connection list` prints, so the picker is readable on its own.
        // bash discards it.
        let help = format!(
            "name={name} global={global} mode={mode:?} connected={connected} interface={interface}",
            name = conn.name.as_deref().unwrap_or("-"),
            global = conn.global,
            mode = conn.start_mode,
            connected = conn.connected,
            interface = conn.interface,
        );
        let mut push = |value: String| {
            if value.starts_with(current) {
                candidates.push(
                    clap_complete::engine::CompletionCandidate::new(value)
                        .help(Some(help.clone().into())),
                );
            }
        };
        push(conn.id.to_string());
        if let Some(name) = conn.name.as_deref() {
            if !offered_names.contains(&name) {
                offered_names.push(name);
                push(name.to_string());
            }
        }
    }
    candidates
}

/// Read a `.conf` as the invoking user and return its text with its
/// absolute path. Symlinks are deliberately not resolved, so `refresh`
/// follows a symlink that is later retargeted. The daemon only ever receives
/// the text; the path is recorded as metadata so `refresh` can find the file
/// again.
fn read_conf(file: &str) -> anyhow::Result<(String, String)> {
    let path = std::path::absolute(file).with_context(|| format!("failed to resolve {file}"))?;
    let conf_text = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let source_path = path
        .to_str()
        .with_context(|| format!("{} is not valid UTF-8", path.display()))?
        .to_string();
    Ok((conf_text, source_path))
}

fn cmd_add(
    file: &str,
    global: bool,
    name: Option<String>,
    mtu: Option<u16>,
    force: bool,
    start_mode: ConnectionStartMode,
) -> anyhow::Result<()> {
    let (conf_text, source_path) = read_conf(file)?;
    let client = PrivilegedClient::new();
    let id = client.add_connection(
        &conf_text,
        global,
        start_mode,
        name.clone(),
        mtu,
        force,
        Some(source_path),
    )?;
    println!("Connection id: {}", id.label(name.as_deref()));
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
                "Removing stale connection {} (same name {name:?}, superseded by {})",
                conn.label(),
                id.label(Some(name.as_str()))
            );
            disconnect_and_remove_stale(&client, conn.id)?;
        }
    }
    // Last, after the stale-record cleanup: a freshly installed agent
    // reconnects `Automatic` records right away and would race that cleanup.
    if !global && start_mode == ConnectionStartMode::Automatic {
        crate::session_agent::ensure_for_automatic(&client);
    }
    Ok(())
}

/// Disconnect and remove a stale same-name connection record, retrying the
/// whole disconnect-then-remove sequence while the daemon reports `Busy`.
///
/// The race this guards against is wider than a single check-then-act gap:
/// `wgd launchd reload` reinstalls the per-user session agent with `RunAtLoad`,
/// and the agent's one-shot startup reconcile (`session_agent::run` ->
/// `reconcile_connect_mine`) can reconnect this exact `Automatic` record via
/// a full `ConnectConnection` round trip (WireGuard handshake, routes, DNS)
/// at any point while this function is running, including between our own
/// disconnect and the daemon committing the removal. A single
/// disconnect-then-remove pair can still lose that race; since the agent
/// only ever attempts that one reconnect per start, retrying the pair
/// converges as soon as it has.
///
/// The 12-second retry budget limits retries, not total wall-clock time:
/// a blocking RPC can exceed it. In particular, `disconnect_connection`
/// waits up to `PATIENT_LOCK_TIMEOUT` (30s) for an in-progress connect to
/// release its lock, then performs teardown. `NotFound` from either call
/// is treated as success: something else already removed the record.
fn disconnect_and_remove_stale(client: &PrivilegedClient, id: ConnectionId) -> anyhow::Result<()> {
    const RETRY_BUDGET: Duration = Duration::from_secs(12);
    const RETRY_DELAY: Duration = Duration::from_millis(150);
    let deadline = std::time::Instant::now() + RETRY_BUDGET;
    loop {
        let result = (|| -> crate::error::Result<()> {
            // Setup (including PostUp hooks) holds the connection lock while
            // `connected` is still false. Always disconnect so the daemon's
            // patient lock waits for setup before tearing the connection down.
            client.disconnect_connection(id)?;
            client.remove_connection(id)
        })();
        match result {
            Ok(()) | Err(AppError::NotFound(_)) => return Ok(()),
            Err(AppError::Busy(_)) if std::time::Instant::now() < deadline => {
                std::thread::sleep(RETRY_DELAY);
            }
            Err(error) => return Err(error.into()),
        }
    }
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

fn cmd_refresh(id: &str, file: Option<&str>) -> anyhow::Result<()> {
    let client = PrivilegedClient::new();
    let id = resolve_id(&client, id)?;
    let file = match file {
        Some(file) => file.to_string(),
        None => client.get_connection(id)?.source_path.with_context(|| {
            format!(
                "{} has no recorded source file (it was added before refresh existed); \
                 pass --file <path>",
                label_for(&client, id)
            )
        })?,
    };
    let (conf_text, source_path) = read_conf(&file)?;
    let outcome = client.refresh_connection(id, &conf_text, Some(source_path))?;
    let label = label_for(&client, id);
    match (outcome.changed, outcome.reconnected) {
        (false, _) => println!("Unchanged {label}"),
        (true, false) => println!("Updated {label}"),
        (true, true) => println!("Updated and reconnected {label}"),
    }
    if needs_session_agent(&client, id) {
        crate::session_agent::ensure_for_automatic(&client);
    }
    Ok(())
}

fn cmd_remove(id: &str) -> anyhow::Result<()> {
    let client = PrivilegedClient::new();
    let id = resolve_id(&client, id)?;
    let label = label_for(&client, id);
    client.remove_connection(id)?;
    println!("Removed connection {label}");
    Ok(())
}

fn cmd_connect(id: &str, debug: bool) -> anyhow::Result<()> {
    let client = PrivilegedClient::new();
    let id = resolve_id(&client, id)?;
    client.connect_connection(id, debug)?;
    println!("Connected {}", label_for(&client, id));
    // Already up, so an agent installed here skips it on its startup reconcile.
    if needs_session_agent(&client, id) {
        crate::session_agent::ensure_for_automatic(&client);
    }
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
                Ok(()) => println!("Disconnected {}", conn.label()),
                Err(error) => {
                    eprintln!("Failed to disconnect {}: {error:#}", conn.label());
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
    println!("Disconnected {}", label_for(&client, id));
    Ok(())
}

fn cmd_mode(id: &str, start_mode: ConnectionStartMode) -> anyhow::Result<()> {
    let client = PrivilegedClient::new();
    let id = resolve_id(&client, id)?;
    client.set_connection_mode(id, start_mode)?;
    println!(
        "Set {} start mode to {start_mode:?}",
        label_for(&client, id)
    );
    if start_mode == ConnectionStartMode::Automatic && needs_session_agent(&client, id) {
        crate::session_agent::ensure_for_automatic(&client);
    }
    Ok(())
}

/// Whether `id` is a per-user `Automatic` connection, i.e. one that only
/// comes up at login through the session agent. A failed lookup counts as no.
fn needs_session_agent(client: &PrivilegedClient, id: ConnectionId) -> bool {
    client
        .get_connection(id)
        .is_ok_and(|conn| !conn.global && conn.start_mode == ConnectionStartMode::Automatic)
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
    if let Some(source_path) = &conn.source_path {
        println!("source:      {source_path}");
    }
    println!("connected:   {}", conn.connected);
    println!("user_disconnected: {}", conn.user_disconnected);
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

/// Lines `wgd status` prints about DNS custody. Empty on a healthy system:
/// records whose helper is live are normal and never reach this function.
#[must_use]
pub fn format_dns_custody_notes(
    status: &crate::privileged_api::DnsCustodyStatus,
) -> Vec<crate::ui::Note> {
    use crate::privileged_api::DnsCustodyEntry;
    use crate::ui::Note;

    let label = |entry: &DnsCustodyEntry| match &entry.name {
        Some(name) => format!("{} ({name})", entry.interface),
        None => entry.interface.clone(),
    };
    let services = |entry: &DnsCustodyEntry| entry.services.join(", ");

    let mut lines = Vec::new();
    for entry in &status.pending {
        lines.push(Note::warn(format!(
            "DNS left by {} on {} is not restored yet; wgd keeps retrying.",
            label(entry),
            services(entry)
        )));
    }
    for entry in &status.deferred {
        lines.push(Note::warn(format!(
            "DNS left by {} on {} cannot be restored from this network location; \
             switch back to that location to restore it.",
            label(entry),
            services(entry)
        )));
    }
    if let Some(last) = &status.last_restore {
        let seconds = last.at % 86_400;
        lines.push(Note::info(format!(
            "DNS restored on {} after {} exited without cleanup, {:02}:{:02} UTC",
            services(&last.entry),
            label(&last.entry),
            seconds / 3600,
            seconds % 3600 / 60
        )));
    }
    lines
}

#[cfg(test)]
mod dns_custody_note_tests {
    use super::*;
    use crate::privileged_api::{DnsCustodyEntry, DnsCustodyStatus, DnsRestoreEvent};

    fn entry(name: Option<&str>) -> DnsCustodyEntry {
        DnsCustodyEntry {
            id: None,
            interface: "wg-1ce3a4a1".into(),
            name: name.map(str::to_string),
            services: vec!["Wi-Fi".into()],
        }
    }

    #[test]
    fn healthy_system_prints_nothing() {
        assert!(format_dns_custody_notes(&DnsCustodyStatus::default()).is_empty());
    }

    #[test]
    fn last_restore_names_service_connection_and_time() {
        let status = DnsCustodyStatus {
            last_restore: Some(DnsRestoreEvent {
                entry: entry(Some("office")),
                at: 13 * 3600 + 49 * 60 + 7,
            }),
            ..DnsCustodyStatus::default()
        };
        assert_eq!(
            format_dns_custody_notes(&status),
            vec![crate::ui::Note::info(
                "DNS restored on Wi-Fi after wg-1ce3a4a1 (office) exited without cleanup, 13:49 UTC"
            )]
        );
    }

    #[test]
    fn pending_and_deferred_records_are_reported() {
        let status = DnsCustodyStatus {
            pending: vec![entry(None)],
            deferred: vec![entry(Some("office"))],
            last_restore: None,
        };
        let lines = format_dns_custody_notes(&status);
        assert_eq!(lines.len(), 2);
        assert!(lines
            .iter()
            .all(|note| note.level == crate::ui::NoteLevel::Warn));
        assert!(lines[0].text.contains("not restored yet"));
        assert!(lines[1].text.contains("wg-1ce3a4a1 (office)"));
        assert!(lines[1].text.contains("network location"));
    }

    #[test]
    fn read_conf_keeps_symlink_path() {
        let dir = std::env::temp_dir().join(format!("wgd-readconf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let target = dir.join("real.conf");
        let link = dir.join("link.conf");
        std::fs::write(&target, "[Interface]\n").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let (text, source) = read_conf(link.to_str().unwrap()).unwrap();
        assert_eq!(text, "[Interface]\n");
        assert_eq!(source, link.to_str().unwrap());

        let missing = dir.join("missing.conf");
        assert!(read_conf(missing.to_str().unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
