//! On-disk store for privileged connections: one `StoredConnection` record
//! per `AddConnection`-created identity, plus a per-connection
//! `ActiveConnectionState` that exists only while that connection is up.
//!
//! Every accessor has a production entry point (using
//! `config::privileged_runtime_dir()`) that forwards to a `..._in(root, ...)`
//! twin taking an explicit root directory, so tests can point the whole store
//! at a temp directory without touching the real root-owned runtime dir.
use std::fs;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::config;
use crate::error::{AppError, Result};
pub use crate::privileged_api::{ConnectionId, ConnectionStartMode};
use crate::wireguard::connection_config::{self, ConnectionConfig, ConnectionPeer};

/// A stored connection: the parsed configuration, the raw text it was parsed
/// from, and the ownership/lifecycle metadata `AddConnection`/`ListConnections`/
/// etc. operate on. Persisted as `connections/<id>.json`, mode 0600,
/// root-owned only -- it contains the connection's private key.
#[derive(Debug)]
pub struct StoredConnection {
    pub id: ConnectionId,
    pub fingerprint: String,
    pub global: bool,
    pub owner_uid: Option<u32>,
    pub start_mode: ConnectionStartMode,
    pub name: Option<String>,
    pub config: ConnectionConfig,
    pub raw_conf: String,
    pub interface: String,
    pub created_at: u64,
    pub updated_at: u64,
}

/// Connection lifecycle state that exists only while the connection is up.
/// Generalizes `tunnel_state::ActiveTunnel` to be per-connection-id instead of
/// singleton; the anti-adoption check (real UAPI socket device/inode/ctime)
/// is unchanged and is what actually prevents adoption confusion, not the id.
#[derive(Debug, Serialize, Deserialize)]
pub struct ActiveConnectionState {
    pub fingerprint: String,
    pub interface: String,
    pub socket: PathBuf,
    pub device: u64,
    pub inode: u64,
    pub changed_sec: i64,
    pub changed_nsec: i64,
    pub connected_at: u64,
}

#[must_use]
pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---- on-disk wire format --------------------------------------------------
//
// `ConnectionConfig` deliberately has no `Serialize`/`Deserialize` of its own
// (see its doc comment): its key fields are typed wrappers around
// `x25519-dalek` types chosen specifically to avoid an incidental derive
// putting private key bytes into a format this module doesn't control. This
// disk DTO is the one place that turns the typed config into text and back,
// reusing the same encode/decode helpers `connection_config` exposes for
// exactly this purpose.

#[derive(Serialize, Deserialize)]
struct StoredConnectionDisk {
    id: ConnectionId,
    fingerprint: String,
    global: bool,
    owner_uid: Option<u32>,
    start_mode: ConnectionStartMode,
    name: Option<String>,
    config: ConnectionConfigDisk,
    raw_conf: String,
    interface: String,
    created_at: u64,
    updated_at: u64,
}

#[derive(Serialize, Deserialize)]
struct ConnectionConfigDisk {
    private_key_b64: String,
    addresses: Vec<String>,
    dns_servers: Vec<String>,
    mtu: Option<u16>,
    pre_up: Vec<String>,
    post_up: Vec<String>,
    pre_down: Vec<String>,
    post_down: Vec<String>,
    peers: Vec<ConnectionPeerDisk>,
}

#[derive(Serialize, Deserialize)]
struct ConnectionPeerDisk {
    public_key_b64: String,
    preshared_key_b64: Option<String>,
    allowed_ips: Vec<String>,
    endpoint: Option<String>,
    endpoint_literal: Option<String>,
    persistent_keepalive: Option<u16>,
}

fn corrupt(what: &str, value: &str) -> AppError {
    AppError::WireGuard(format!(
        "corrupt stored connection: invalid {what} {value:?}"
    ))
}

fn parse_ipnet_field(what: &str, value: &str) -> Result<IpNet> {
    value.parse().map_err(|_| corrupt(what, value))
}

fn parse_ip_field(what: &str, value: &str) -> Result<IpAddr> {
    value.parse().map_err(|_| corrupt(what, value))
}

fn config_to_disk(config: &ConnectionConfig) -> ConnectionConfigDisk {
    ConnectionConfigDisk {
        private_key_b64: connection_config::private_key_to_base64(&config.private_key),
        addresses: config.addresses.iter().map(ToString::to_string).collect(),
        dns_servers: config.dns_servers.iter().map(ToString::to_string).collect(),
        mtu: config.mtu,
        pre_up: config.pre_up.clone(),
        post_up: config.post_up.clone(),
        pre_down: config.pre_down.clone(),
        post_down: config.post_down.clone(),
        peers: config.peers.iter().map(peer_to_disk).collect(),
    }
}

fn peer_to_disk(peer: &ConnectionPeer) -> ConnectionPeerDisk {
    ConnectionPeerDisk {
        public_key_b64: connection_config::public_key_to_base64(&peer.public_key),
        preshared_key_b64: peer
            .preshared_key
            .as_ref()
            .map(connection_config::preshared_key_to_base64),
        allowed_ips: peer.allowed_ips.iter().map(ToString::to_string).collect(),
        endpoint: peer.endpoint.map(|e| e.to_string()),
        endpoint_literal: peer.endpoint_literal.clone(),
        persistent_keepalive: peer.persistent_keepalive,
    }
}

fn config_from_disk(disk: ConnectionConfigDisk) -> Result<ConnectionConfig> {
    Ok(ConnectionConfig {
        private_key: connection_config::private_key_from_base64(&disk.private_key_b64)?,
        addresses: disk
            .addresses
            .iter()
            .map(|s| parse_ipnet_field("address", s))
            .collect::<Result<_>>()?,
        dns_servers: disk
            .dns_servers
            .iter()
            .map(|s| parse_ip_field("dns server", s))
            .collect::<Result<_>>()?,
        mtu: disk.mtu,
        pre_up: disk.pre_up,
        post_up: disk.post_up,
        pre_down: disk.pre_down,
        post_down: disk.post_down,
        peers: disk
            .peers
            .into_iter()
            .map(peer_from_disk)
            .collect::<Result<_>>()?,
    })
}

fn peer_from_disk(disk: ConnectionPeerDisk) -> Result<ConnectionPeer> {
    Ok(ConnectionPeer {
        public_key: connection_config::public_key_from_base64(&disk.public_key_b64)?,
        preshared_key: disk
            .preshared_key_b64
            .as_deref()
            .map(connection_config::preshared_key_from_base64)
            .transpose()?,
        allowed_ips: disk
            .allowed_ips
            .iter()
            .map(|s| parse_ipnet_field("allowed IP", s))
            .collect::<Result<_>>()?,
        endpoint: disk
            .endpoint
            .as_deref()
            .map(|s| s.parse::<SocketAddr>().map_err(|_| corrupt("endpoint", s)))
            .transpose()?,
        endpoint_literal: disk.endpoint_literal,
        persistent_keepalive: disk.persistent_keepalive,
    })
}

fn to_disk(conn: &StoredConnection) -> StoredConnectionDisk {
    StoredConnectionDisk {
        id: conn.id,
        fingerprint: conn.fingerprint.clone(),
        global: conn.global,
        owner_uid: conn.owner_uid,
        start_mode: conn.start_mode,
        name: conn.name.clone(),
        config: config_to_disk(&conn.config),
        raw_conf: conn.raw_conf.clone(),
        interface: conn.interface.clone(),
        created_at: conn.created_at,
        updated_at: conn.updated_at,
    }
}

fn from_disk(disk: StoredConnectionDisk) -> Result<StoredConnection> {
    Ok(StoredConnection {
        id: disk.id,
        fingerprint: disk.fingerprint,
        global: disk.global,
        owner_uid: disk.owner_uid,
        start_mode: disk.start_mode,
        name: disk.name,
        config: config_from_disk(disk.config)?,
        raw_conf: disk.raw_conf,
        interface: disk.interface,
        created_at: disk.created_at,
        updated_at: disk.updated_at,
    })
}

// ---- directory layout ------------------------------------------------------

fn connections_dir_in(root: &Path) -> PathBuf {
    root.join("connections")
}

fn active_dir_in(root: &Path) -> PathBuf {
    root.join("active")
}

fn locks_dir_in(root: &Path) -> PathBuf {
    root.join("locks")
}

fn index_lock_path_in(root: &Path) -> PathBuf {
    root.join("connections-index.lock")
}

fn stored_path_in(root: &Path, id: ConnectionId) -> PathBuf {
    connections_dir_in(root).join(format!("{id}.json"))
}

fn active_path_in(root: &Path, id: ConnectionId) -> PathBuf {
    active_dir_in(root).join(format!("{id}.json"))
}

fn lock_path_in(root: &Path, id: ConnectionId) -> PathBuf {
    locks_dir_in(root).join(format!("{id}.lock"))
}

fn ensure_dir_0700(dir: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn ensure_store_dirs_in(root: &Path) -> Result<()> {
    for dir in [
        connections_dir_in(root),
        active_dir_in(root),
        locks_dir_in(root),
    ] {
        ensure_dir_0700(&dir)?;
    }
    Ok(())
}

// Tests need every `pub` accessor here (which always target the real,
// root-owned system path) to instead operate on a throwaway temp directory,
// without threading a root path through every call site the way the `_in`
// helpers do for this module's own unit tests. A thread-local override does
// that transparently: each `#[test]` fn runs on its own thread by default, so
// setting it at the top of a test isolates that test without touching any
// other concurrently running test.
#[cfg(test)]
thread_local! {
    static TEST_ROOT: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_test_root(path: PathBuf) {
    TEST_ROOT.with(|cell| *cell.borrow_mut() = Some(path));
}

/// The override is thread-local, so a worker thread spawned for
/// `ConnectConnection`/`DisconnectConnection` (see `dispatch.rs`) does not
/// automatically inherit its parent's test root. Callers that spawn such a
/// thread from a test propagate it explicitly: `let root =
/// connection_store::current_test_root();` on the parent, then
/// `connection_store::set_test_root(root)` inside the spawned closure.
#[cfg(test)]
pub(crate) fn current_test_root() -> Option<PathBuf> {
    TEST_ROOT.with(|cell| cell.borrow().clone())
}

fn root_dir() -> PathBuf {
    #[cfg(test)]
    {
        if let Some(path) = TEST_ROOT.with(|cell| cell.borrow().clone()) {
            return path;
        }
    }
    config::privileged_runtime_dir()
}

pub fn ensure_store_dirs() -> Result<()> {
    ensure_store_dirs_in(&root_dir())
}

// ---- CRUD -------------------------------------------------------------------

pub fn load(id: ConnectionId) -> Result<Option<StoredConnection>> {
    load_in(&root_dir(), id)
}

fn load_in(root: &Path, id: ConnectionId) -> Result<Option<StoredConnection>> {
    let path = stored_path_in(root, id);
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(from_disk_checked(
            id,
            serde_json::from_slice(&bytes)?,
        )?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Deserialize a record loaded *by id* (the filename) and cross-check that
/// the id and interface name encoded inside the JSON actually agree with it.
/// Both are always derivable from `id` alone (`allocate_unique_interface`
/// only ever creates records that way), so a mismatch means either on-disk
/// corruption or a file that was renamed/tampered with -- either way, the
/// record must not be silently treated as belonging to `id`, or a caller
/// could end up locking/removing/connecting a different logical connection
/// than the one it thinks it resolved.
fn from_disk_checked(id: ConnectionId, disk: StoredConnectionDisk) -> Result<StoredConnection> {
    if disk.id != id {
        return Err(corrupt("id", &format!("{} (expected {id})", disk.id)));
    }
    if disk.interface != disk.id.interface_name() {
        return Err(corrupt("interface", &disk.interface));
    }
    from_disk(disk)
}

/// Load every stored connection, individually best-effort: a corrupt record
/// is logged and skipped rather than failing the whole listing. Only for
/// **display** paths (`ListConnections`) -- never for uniqueness or dedup
/// checks, where silently treating an unreadable record as absent would let
/// a second connection claim its interface name or fingerprint identity (see
/// [`load_all_strict`]).
pub fn load_all() -> Result<Vec<StoredConnection>> {
    load_all_in(&root_dir())
}

/// Look up the stored connection (if any) whose derived interface name is
/// `interface`. Used to gate the legacy `WgShow`/`NetworkOverview`/
/// `InterfaceActive` ops by the same ownership rule as the connection-store
/// ops whenever the interface they name happens to belong to one: those
/// legacy ops predate per-connection ownership and, left ungated, would let
/// any reachable caller act on (or read from) a connection's interface it
/// does not own, once that interface name is known (e.g. from a
/// `ListConnections{Global}` response).
pub fn find_by_interface(interface: &str) -> Result<Option<StoredConnection>> {
    Ok(load_all()?
        .into_iter()
        .find(|conn| conn.interface == interface))
}

fn load_all_in(root: &Path) -> Result<Vec<StoredConnection>> {
    for_each_stored_entry(root, |_path, result| match result {
        Ok(conn) => Some(conn),
        Err(error) => {
            tracing::warn!(error = %error, "stored_connection_entry_skipped");
            None
        }
    })
}

/// Like [`load_all`], but any record that fails to parse is a hard error
/// instead of being skipped. Used by [`find_by_identity`] and
/// [`interface_name_in_use`]/[`allocate_unique_interface`]: those exist to
/// prevent two connections from colliding on identity or interface name, so
/// they must fail closed on a record they can't read rather than silently
/// treating it as if it didn't exist.
fn load_all_strict_in(root: &Path) -> Result<Vec<StoredConnection>> {
    let mut error = None;
    let connections = for_each_stored_entry(root, |path, result| match result {
        Ok(conn) => Some(conn),
        Err(err) => {
            error.get_or_insert_with(|| {
                AppError::Other(format!(
                    "cannot verify connection-store uniqueness: {} is unreadable: {err}",
                    path.display()
                ))
            });
            None
        }
    })?;
    match error {
        Some(error) => Err(error),
        None => Ok(connections),
    }
}

fn for_each_stored_entry<T>(
    root: &Path,
    mut on_entry: impl FnMut(&Path, Result<StoredConnection>) -> Option<T>,
) -> Result<Vec<T>> {
    let dir = connections_dir_in(root);
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let id = path
            .file_stem()
            .and_then(|s| s.to_str())
            .and_then(|s| s.parse::<ConnectionId>().ok());
        let result = (|| -> Result<StoredConnection> {
            let id = id.ok_or_else(|| corrupt("filename", &path.display().to_string()))?;
            let bytes = fs::read(&path)?;
            from_disk_checked(id, serde_json::from_slice(&bytes)?)
        })();
        if let Some(value) = on_entry(&path, result) {
            out.push(value);
        }
    }
    Ok(out)
}

/// Token proving [`lock_index`] is held. Required by every operation that
/// creates a record or otherwise needs the interface-name/identity
/// uniqueness check to be atomic with the write -- a compile-time reminder of
/// the "must hold the index lock" rule a doc comment alone can't enforce.
#[derive(Debug)]
pub struct IndexLock(#[allow(dead_code)] fs::File);

/// Token proving [`lock_connection`] is held for one connection id.
#[derive(Debug)]
pub struct ConnectionLock(#[allow(dead_code)] fs::File);

/// The privileged dispatcher runs on the same thread that accepts
/// connections and enforces client deadlines (see `state_file::lock_with_timeout`'s
/// doc comment); an unbounded `flock` here would freeze every other client
/// behind one slow operation. Also bounds the self-deadlock a caller would
/// otherwise hit by re-acquiring the same lock twice on one thread (`flock`
/// is per open-file-description, so a second, distinct open of the same lock
/// path blocks against the first rather than succeeding) -- a caller must
/// never do that, but a bounded wait turns a would-be hang into a clear error
/// instead of freezing the daemon.
const LOCK_TIMEOUT: Duration = Duration::from_secs(2);

/// Guards interface-name allocation and connection creation/removal. Callers
/// must take this lock for the full duration of an `AddConnection`/
/// `RemoveConnection` operation and release it before taking a per-connection
/// lock for a *different* operation (always index-then-per-id, never the
/// reverse, to avoid deadlocking against a concurrent `Connect`/`Disconnect`).
pub fn lock_index() -> Result<IndexLock> {
    lock_index_in(&root_dir())
}

fn lock_index_in(root: &Path) -> Result<IndexLock> {
    ensure_store_dirs_in(root)?;
    Ok(IndexLock(crate::state_file::lock_with_timeout(
        &index_lock_path_in(root),
        LOCK_TIMEOUT,
    )?))
}

/// Guards `Connect`/`Disconnect`/`SetConnectionMode` on one connection id.
pub fn lock_connection(id: ConnectionId) -> Result<ConnectionLock> {
    lock_connection_in(&root_dir(), id)
}

fn lock_connection_in(root: &Path, id: ConnectionId) -> Result<ConnectionLock> {
    ensure_dir_0700(&locks_dir_in(root))?;
    Ok(ConnectionLock(crate::state_file::lock_with_timeout(
        &lock_path_in(root, id),
        LOCK_TIMEOUT,
    )?))
}

/// Persist a brand-new connection record. Requires the caller to hold
/// [`IndexLock`], so the identity/interface-name uniqueness check that
/// produced `conn.id`/`conn.interface` and this write are atomic with respect
/// to a concurrent `AddConnection`.
pub fn create(_index: &IndexLock, conn: &StoredConnection) -> Result<()> {
    create_in(&root_dir(), conn)
}

fn create_in(root: &Path, conn: &StoredConnection) -> Result<()> {
    save_in(root, conn)
}

/// Persist an update to an existing record's mutable fields (`start_mode`,
/// `name`). Requires the caller to hold that connection's [`ConnectionLock`].
pub fn update(_conn_lock: &ConnectionLock, conn: &StoredConnection) -> Result<()> {
    save_in(&root_dir(), conn)
}

fn save_in(root: &Path, conn: &StoredConnection) -> Result<()> {
    ensure_store_dirs_in(root)?;
    let bytes = serde_json::to_vec_pretty(&to_disk(conn))?;
    crate::state_file::write_atomic(&stored_path_in(root, conn.id), &bytes)?;
    Ok(())
}

/// Delete a connection record. Requires both locks, taken in that order (see
/// [`lock_index`]'s doc comment) -- `RemoveConnection` must hold the index
/// lock for the whole operation and the target's own lock so it cannot race
/// a concurrent `Connect`/`Disconnect` on the same id.
pub fn remove(_index: &IndexLock, _conn_lock: &ConnectionLock, id: ConnectionId) -> Result<()> {
    remove_in(&root_dir(), id)
}

fn remove_in(root: &Path, id: ConnectionId) -> Result<()> {
    let path = stored_path_in(root, id);
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

/// Look up an existing record with the same identity, for `AddConnection`'s
/// exact-match dedup (see the design plan's fingerprint section): a
/// byte-for-byte-identical resubmission of a `.conf` must return the existing
/// id rather than creating a new record or engaging the admin-auth flow.
/// Requires [`IndexLock`]: fails closed (see [`load_all_strict_in`]) rather
/// than risking a false "no match" against a record it can't read.
pub fn find_by_identity(
    _index: &IndexLock,
    fingerprint: &str,
    global: bool,
    owner_uid: Option<u32>,
) -> Result<Option<StoredConnection>> {
    find_by_identity_in(&root_dir(), fingerprint, global, owner_uid)
}

fn find_by_identity_in(
    root: &Path,
    fingerprint: &str,
    global: bool,
    owner_uid: Option<u32>,
) -> Result<Option<StoredConnection>> {
    for conn in load_all_strict_in(root)? {
        if conn.fingerprint == fingerprint && conn.global == global && conn.owner_uid == owner_uid {
            return Ok(Some(conn));
        }
    }
    Ok(None)
}

fn interface_name_in_use_in(root: &Path, interface: &str) -> Result<bool> {
    Ok(load_all_strict_in(root)?
        .iter()
        .any(|conn| conn.interface == interface))
}

/// Allocate a fresh [`ConnectionId`] with a not-currently-used interface
/// name. Requires [`IndexLock`] so the uniqueness check and the eventual
/// [`create`] of the new record are atomic with respect to a concurrent
/// `AddConnection`. Fails closed if any existing record can't be read (see
/// [`load_all_strict_in`]) rather than risking a name collision.
pub fn allocate_unique_interface(_index: &IndexLock) -> Result<(ConnectionId, String)> {
    allocate_unique_interface_in(&root_dir())
}

fn allocate_unique_interface_in(root: &Path) -> Result<(ConnectionId, String)> {
    const ATTEMPTS: usize = 8;
    for _ in 0..ATTEMPTS {
        let id = ConnectionId::new();
        let interface = id.interface_name();
        if !interface_name_in_use_in(root, &interface)? {
            return Ok((id, interface));
        }
    }
    Err(AppError::Other(
        "failed to allocate a unique connection interface name".into(),
    ))
}

// ---- active state -----------------------------------------------------------

pub fn load_active(id: ConnectionId) -> Result<Option<ActiveConnectionState>> {
    load_active_in(&root_dir(), id)
}

fn load_active_in(root: &Path, id: ConnectionId) -> Result<Option<ActiveConnectionState>> {
    let path = active_path_in(root, id);
    match fs::read(&path) {
        Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Requires the connection's [`ConnectionLock`] (held by `Connect`/`Disconnect`).
pub fn save_active(
    _conn_lock: &ConnectionLock,
    id: ConnectionId,
    state: &ActiveConnectionState,
) -> Result<()> {
    save_active_in(&root_dir(), id, state)
}

fn save_active_in(root: &Path, id: ConnectionId, state: &ActiveConnectionState) -> Result<()> {
    ensure_dir_0700(&active_dir_in(root))?;
    let bytes = serde_json::to_vec(state)?;
    crate::state_file::write_atomic(&active_path_in(root, id), &bytes)?;
    Ok(())
}

/// Requires the connection's [`ConnectionLock`] (held by `Connect`/`Disconnect`).
pub fn clear_active(_conn_lock: &ConnectionLock, id: ConnectionId) -> Result<()> {
    clear_active_in(&root_dir(), id)
}

fn clear_active_in(root: &Path, id: ConnectionId) -> Result<()> {
    let path = active_path_in(root, id);
    if path.exists() {
        fs::remove_file(&path)?;
    }
    Ok(())
}

/// Whether `id` is genuinely connected right now -- not just whether an
/// `active/<id>.json` marker exists. That marker is written under
/// `config::privileged_runtime_dir()`, which (unlike the actual gotatun
/// helper process and its `/var/run/wireguard/<iface>.sock`) survives a
/// reboot or crash untouched, so a bare file-exists check would report a
/// connection as connected forever after the machine restarts -- exactly the
/// case boot/session reconciliation exists to fix. This mirrors the "recorded
/// socket is gone: stale marker" branch `connection_ops::connect` already
/// has for its own idempotency check.
pub fn is_active(id: ConnectionId) -> Result<bool> {
    match load_active(id)? {
        Some(active) => Ok(active.socket.try_exists().unwrap_or(false)),
        None => Ok(false),
    }
}

// ---- boot reconciliation (Phase 3) -----------------------------------------

/// Boot-time reconciliation for global `Automatic` connections. Called on a
/// background thread every time the daemon's socket listener is bound and
/// accepting (see `mod.rs::serve`) -- but the daemon is on-demand
/// (socket-activated, idle-exits) rather than a long-lived boot service, so
/// that can happen many times within one machine boot, not just once. Gated
/// by [`boot_id`] to actually run at most once per real boot: without this,
/// an unprivileged `tunmux`-group member merely running e.g. `tunmux status`
/// after the daemon has idled out would re-trigger a root-only
/// `ConnectConnection` on every global `Automatic` record, silently undoing
/// an admin's explicit `disconnect` within the idle timeout. If the boot
/// identity can't be determined, fails open to reconciling (matching this
/// function's behavior before the gate existed) rather than silently never
/// reconciling. Iterating every candidate serially *before* the daemon starts
/// serving would delay every client behind N helper-startup handshakes, so
/// this runs after the listener is already accepting. Best-effort per
/// connection: a broken or unreachable global config logs a warning and does
/// not block the others or the daemon's availability. Per-user connections
/// are out of scope here -- they are only ever brought up by that user's own
/// session (the per-user session agent), never by the daemon at boot.
pub fn reconcile_boot() {
    let root = root_dir();
    if let Some(boot_id) = boot_id() {
        if already_reconciled_this_boot_in(&root, &boot_id) {
            return;
        }
        reconcile_boot_once();
        mark_reconciled_this_boot_in(&root, &boot_id);
    } else {
        tracing::warn!("boot_reconciliation_boot_id_unavailable_reconciling_anyway");
        reconcile_boot_once();
    }
}

fn reconcile_boot_once() {
    let connections = match load_all() {
        Ok(connections) => connections,
        Err(error) => {
            tracing::warn!(error = %error, "boot_reconciliation_listing_failed");
            return;
        }
    };
    for id in boot_reconcile_candidates(&connections) {
        if let Err(error) = reconcile_connect(id) {
            tracing::warn!(id = %id, error = %error, "boot_reconciliation_connect_failed");
        }
    }
}

fn boot_marker_path_in(root: &Path) -> PathBuf {
    root.join("boot-reconcile.marker")
}

fn already_reconciled_this_boot_in(root: &Path, boot_id: &str) -> bool {
    fs::read_to_string(boot_marker_path_in(root))
        .map(|contents| contents.trim() == boot_id)
        .unwrap_or(false)
}

fn mark_reconciled_this_boot_in(root: &Path, boot_id: &str) {
    if let Err(error) =
        crate::state_file::write_atomic(&boot_marker_path_in(root), boot_id.as_bytes())
    {
        tracing::warn!(error = %error, "boot_reconciliation_marker_write_failed");
    }
}

/// A value that's stable for the whole current boot session and changes
/// across reboots (`sysctl kern.boottime`, the same mechanism `uptime` uses),
/// used to gate [`reconcile_boot`] to run at most once per boot. `None` if
/// the sysctl call fails for any reason.
fn boot_id() -> Option<String> {
    use nix::libc;
    use std::mem;
    let mut mib = [libc::CTL_KERN, libc::KERN_BOOTTIME];
    let mut boottime: libc::timeval = unsafe { mem::zeroed() };
    let mut size = mem::size_of::<libc::timeval>();
    // SAFETY: `mib`/`boottime`/`size` are correctly sized for a `KERN_BOOTTIME`
    // query per `sysctl(3)`; `size` is initialized to the buffer's actual size.
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as u32,
            &mut boottime as *mut libc::timeval as *mut libc::c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if ret != 0 {
        return None;
    }
    Some(format!("{}.{}", boottime.tv_sec, boottime.tv_usec))
}

/// Which stored connections boot reconciliation should attempt to bring up:
/// global, `Automatic`, and not already active. Split out from
/// [`reconcile_boot`] so the selection criteria can be unit tested without
/// touching the real network/gotatun layer.
fn boot_reconcile_candidates(connections: &[StoredConnection]) -> Vec<ConnectionId> {
    connections
        .iter()
        .filter(|c| c.global && c.start_mode == ConnectionStartMode::Automatic)
        .filter(|c| !is_active(c.id).unwrap_or(false))
        .map(|c| c.id)
        .collect()
}

fn reconcile_connect(id: ConnectionId) -> Result<()> {
    let conn_lock = lock_connection(id)?;
    super::connection_ops::connect(&conn_lock, id, false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn temp_root(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tunmux-connstore-{label}-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample_config() -> ConnectionConfig {
        let text = "[Interface]\nPrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\nAddress = 10.0.0.2/32\nDNS = 1.1.1.1\n[Peer]\nPublicKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=\nAllowedIPs = 0.0.0.0/0\nEndpoint = 198.51.100.1:51820\n";
        connection_config::parse_connection_config(text).unwrap()
    }

    fn sample(id: ConnectionId, global: bool, owner_uid: Option<u32>) -> StoredConnection {
        let config = sample_config();
        let fingerprint = connection_config::fingerprint(&config);
        StoredConnection {
            interface: id.interface_name(),
            id,
            fingerprint,
            global,
            owner_uid,
            start_mode: ConnectionStartMode::Manual,
            name: None,
            raw_conf: "raw".to_string(),
            config,
            created_at: now_unix(),
            updated_at: now_unix(),
        }
    }

    #[test]
    fn save_load_roundtrips_including_key_material() {
        let root = temp_root("roundtrip");
        let id = ConnectionId::new();
        let conn = sample(id, true, None);
        let original_fingerprint = conn.fingerprint.clone();
        save_in(&root, &conn).unwrap();

        let loaded = load_in(&root, id)
            .unwrap()
            .expect("saved connection exists");
        assert_eq!(loaded.id, id);
        assert!(loaded.global);
        assert_eq!(loaded.interface, id.interface_name());
        // Re-derive the fingerprint from the round-tripped config: this only
        // matches if every field (including the private key) survived.
        assert_eq!(
            connection_config::fingerprint(&loaded.config),
            original_fingerprint
        );

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stored_connection_file_is_mode_0600() {
        use std::os::unix::fs::PermissionsExt;
        let root = temp_root("perms");
        let id = ConnectionId::new();
        save_in(&root, &sample(id, false, Some(501))).unwrap();
        let path = stored_path_in(&root, id);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn load_all_skips_corrupt_entries_and_keeps_the_rest() {
        let root = temp_root("load-all");
        let good = ConnectionId::new();
        save_in(&root, &sample(good, true, None)).unwrap();
        fs::write(connections_dir_in(&root).join("garbage.json"), b"not json").unwrap();

        let loaded = load_all_in(&root).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, good);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn strict_listing_fails_closed_instead_of_hiding_a_corrupt_record() {
        // Unlike `load_all`/`load_all_in` (best-effort, for display), the
        // strict path backing uniqueness/dedup must never treat an unreadable
        // record as simply absent -- that would let a second connection
        // silently claim its interface name or fingerprint identity.
        let root = temp_root("strict");
        save_in(&root, &sample(ConnectionId::new(), true, None)).unwrap();
        let corrupt_id = ConnectionId::new();
        fs::write(
            connections_dir_in(&root).join(format!("{corrupt_id}.json")),
            b"{ not valid json",
        )
        .unwrap();

        assert!(load_all_strict_in(&root).is_err());
        assert!(interface_name_in_use_in(&root, "wg-doesnotexist").is_err());
        assert!(find_by_identity_in(&root, "sha256:whatever", true, None).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn tampered_interface_field_is_rejected_on_load() {
        // `interface` must always equal `id.interface_name()`; a record where
        // they disagree (corruption or tampering) must not be adopted as if
        // it belonged to the id its filename claims.
        let root = temp_root("tamper");
        let id = ConnectionId::new();
        let mut conn = sample(id, true, None);
        save_in(&root, &conn).unwrap();
        conn.interface = "wg-deadbeef".to_string();
        // Overwrite with a self-inconsistent record, bypassing `create`'s
        // normal invariant (only reachable via disk tampering in practice).
        let bytes = serde_json::to_vec_pretty(&to_disk(&conn)).unwrap();
        crate::state_file::write_atomic(&stored_path_in(&root, id), &bytes).unwrap();

        let err = load_in(&root, id).unwrap_err();
        assert!(err.to_string().contains("interface"));
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lock_index_is_bounded_not_unbounded() {
        let root = temp_root("lock-timeout");
        let held = lock_index_in(&root).unwrap();
        let started = std::time::Instant::now();
        let err = lock_index_in(&root).unwrap_err();
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert!(
            matches!(err, AppError::Io(ref e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "{err}"
        );
        drop(held);
        lock_index_in(&root).unwrap();
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn find_by_identity_matches_on_fingerprint_global_and_owner() {
        let root = temp_root("identity");
        let conn = sample(ConnectionId::new(), false, Some(501));
        let fingerprint = conn.fingerprint.clone();
        save_in(&root, &conn).unwrap();

        assert!(find_by_identity_in(&root, &fingerprint, false, Some(501))
            .unwrap()
            .is_some());
        assert!(find_by_identity_in(&root, &fingerprint, true, Some(501))
            .unwrap()
            .is_none());
        assert!(find_by_identity_in(&root, &fingerprint, false, Some(502))
            .unwrap()
            .is_none());
        assert!(
            find_by_identity_in(&root, "sha256:deadbeef", false, Some(501))
                .unwrap()
                .is_none()
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn allocate_unique_interface_avoids_existing_names() {
        let root = temp_root("alloc");
        // Chosen so `taken.interface_name()` is exactly "wg-aaaaaaaa", keeping
        // id and interface self-consistent (required by `from_disk_checked`).
        let taken: ConnectionId = "aaaaaaaa-0000-0000-0000-000000000000".parse().unwrap();
        assert_eq!(taken.interface_name(), "wg-aaaaaaaa");
        let conn = sample(taken, true, None);
        save_in(&root, &conn).unwrap();

        for _ in 0..50 {
            let (id, interface) = allocate_unique_interface_in(&root).unwrap();
            assert_ne!(interface, "wg-aaaaaaaa");
            assert_eq!(interface, id.interface_name());
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn remove_deletes_the_record() {
        let root = temp_root("remove");
        let id = ConnectionId::new();
        save_in(&root, &sample(id, true, None)).unwrap();
        assert!(load_in(&root, id).unwrap().is_some());
        remove_in(&root, id).unwrap();
        assert!(load_in(&root, id).unwrap().is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn active_state_roundtrips_and_clears() {
        let root = temp_root("active");
        let id = ConnectionId::new();
        let state = ActiveConnectionState {
            fingerprint: "sha256:abc".to_string(),
            interface: id.interface_name(),
            socket: PathBuf::from("/var/run/wireguard/wg-aaaaaaaa.sock"),
            device: 1,
            inode: 2,
            changed_sec: 3,
            changed_nsec: 4,
            connected_at: now_unix(),
        };
        assert!(load_active_in(&root, id).unwrap().is_none());
        save_active_in(&root, id, &state).unwrap();
        let loaded = load_active_in(&root, id).unwrap().unwrap();
        assert_eq!(loaded.interface, state.interface);
        clear_active_in(&root, id).unwrap();
        assert!(load_active_in(&root, id).unwrap().is_none());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn boot_reconcile_candidates_selects_only_global_automatic_and_inactive() {
        let root = temp_root("boot-candidates");
        set_test_root(root.clone());

        let global_auto = ConnectionId::new();
        let mut c1 = sample(global_auto, true, None);
        c1.start_mode = ConnectionStartMode::Automatic;
        save_in(&root, &c1).unwrap();

        let global_manual = ConnectionId::new();
        save_in(&root, &sample(global_manual, true, None)).unwrap();

        let user_auto = ConnectionId::new();
        let mut c3 = sample(user_auto, false, Some(501));
        c3.start_mode = ConnectionStartMode::Automatic;
        save_in(&root, &c3).unwrap();

        // Genuinely active: the recorded socket actually exists, so `is_active`
        // (which now verifies that, not just the marker file -- see its doc
        // comment) correctly excludes it.
        let global_auto_active = ConnectionId::new();
        let mut c4 = sample(global_auto_active, true, None);
        c4.start_mode = ConnectionStartMode::Automatic;
        save_in(&root, &c4).unwrap();
        let live_socket = root.join("live.sock");
        fs::write(&live_socket, b"").unwrap();
        save_active_in(
            &root,
            global_auto_active,
            &ActiveConnectionState {
                fingerprint: c4.fingerprint.clone(),
                interface: c4.interface.clone(),
                socket: live_socket,
                device: 0,
                inode: 0,
                changed_sec: 0,
                changed_nsec: 0,
                connected_at: now_unix(),
            },
        )
        .unwrap();

        let connections = load_all_in(&root).unwrap();
        let candidates = boot_reconcile_candidates(&connections);
        assert_eq!(candidates, vec![global_auto]);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn is_active_treats_a_stale_marker_with_a_missing_socket_as_inactive() {
        // Regression test: `active/<id>.json` is written under the
        // privileged runtime dir, which survives a reboot untouched, while
        // the real gotatun helper and its UAPI socket do not. Without this,
        // a connection that was up when the machine last shut down would
        // report `connected` forever and never be a boot/session
        // reconciliation candidate again.
        let root = temp_root("stale-active-after-reboot");
        set_test_root(root.clone());
        let id = ConnectionId::new();
        save_active_in(
            &root,
            id,
            &ActiveConnectionState {
                fingerprint: "sha256:whatever".to_string(),
                interface: id.interface_name(),
                socket: root.join("gone.sock"), // never created
                device: 0,
                inode: 0,
                changed_sec: 0,
                changed_nsec: 0,
                connected_at: now_unix(),
            },
        )
        .unwrap();

        assert!(!is_active(id).unwrap());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn reconcile_boot_does_not_panic_with_a_corrupt_record_present() {
        let root = temp_root("boot-smoke");
        set_test_root(root.clone());

        let global_auto = ConnectionId::new();
        let mut c1 = sample(global_auto, true, None);
        c1.start_mode = ConnectionStartMode::Automatic;
        save_in(&root, &c1).unwrap();

        fs::write(connections_dir_in(&root).join("garbage.json"), b"not json").unwrap();

        // Must not panic: the corrupt record is skipped by `load_all`'s
        // existing best-effort behavior, and the real one is attempted (and,
        // without real gotatun/root privileges in a test process, expected to
        // fail fast rather than hang or block the caller indefinitely).
        reconcile_boot();

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn concurrent_saves_of_distinct_connections_never_corrupt_the_index() {
        let root = temp_root("concurrent");
        let barrier = Arc::new(Barrier::new(9));
        let workers: Vec<_> = (0..8)
            .map(|i| {
                let root = root.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let _lock = lock_index_in(&root).unwrap();
                    let (id, _interface) = allocate_unique_interface_in(&root).unwrap();
                    save_in(&root, &sample(id, i % 2 == 0, Some(i as u32))).unwrap();
                    id
                })
            })
            .collect();
        barrier.wait();
        let ids: Vec<ConnectionId> = workers.into_iter().map(|w| w.join().unwrap()).collect();

        let loaded = load_all_in(&root).unwrap();
        assert_eq!(loaded.len(), 8);
        let interfaces: std::collections::HashSet<_> =
            loaded.iter().map(|c| c.interface.clone()).collect();
        assert_eq!(
            interfaces.len(),
            8,
            "every connection got a distinct interface"
        );
        for id in ids {
            assert!(loaded.iter().any(|c| c.id == id));
        }
        let _ = fs::remove_dir_all(root);
    }
}
