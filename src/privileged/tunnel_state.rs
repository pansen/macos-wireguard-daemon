//! Finding 5 — Incorrect tunnel adoption and connection races.
//!
//! The daemon's private record binds configuration to the socket inode of the
//! running tunnel. Never infer its identity from a caller's requested profile.
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::error::{AppError, Result};
use serde::{Deserialize, Serialize};

// `deny_unknown_fields` rejects legacy `active-tunnel.json` records that still
// carry the removed `wg_quick` discriminator instead of silently dropping it
// and letting an old externally-managed tunnel be adopted as a match.
#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Identity {
    pub interface: String,
    pub config_content: String,
    pub mtu_override: Option<u16>,
}

#[derive(Serialize, Deserialize)]
struct ActiveTunnel {
    identity: Identity,
    socket: PathBuf,
    device: u64,
    inode: u64,
    changed_sec: i64,
    changed_nsec: i64,
}

// The same on-disk shape, but tolerant of an unrecognized identity (e.g. a
// record written by a since-removed backend generation, which still carries
// fields serde's `deny_unknown_fields` on `Identity` now rejects). Used only
// to find the socket a record we can no longer trust once named, so we can
// tell a merely stale record apart from one describing a tunnel that might
// still be running -- never to compare identities.
#[derive(Deserialize)]
struct UnrecognizedRecord {
    identity: UnrecognizedIdentity,
    socket: PathBuf,
}

#[derive(Deserialize)]
struct UnrecognizedIdentity {
    interface: String,
}

pub(super) fn record_path() -> PathBuf {
    crate::config::privileged_runtime_dir().join("active-tunnel.json")
}

fn conflict() -> AppError {
    AppError::WireGuard("active tunnel has a different or unverified configuration; disconnect it before connecting this profile".into())
}

/// Called under the global mutation lock, including by stdio daemon instances.
/// A matching request is idempotent. An unmatched live tunnel is never replaced.
pub(super) fn connect<F>(record: &Path, identity: Identity, socket: &Path, start: F) -> Result<()>
where
    F: FnOnce() -> Result<PathBuf>,
{
    let existing = match fs::read(record) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    if let Some(bytes) = existing {
        match serde_json::from_slice::<ActiveTunnel>(&bytes) {
            Ok(active) => {
                // A corrupt private record must not permit taking over an unknown tunnel.
                let metadata = match fs::metadata(&active.socket) {
                    Ok(metadata) => Some(metadata),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => return Err(error.into()),
                };
                if let Some(metadata) = metadata {
                    if metadata.dev() != active.device
                        || metadata.ino() != active.inode
                        || metadata.ctime() != active.changed_sec
                        || metadata.ctime_nsec() != active.changed_nsec
                    {
                        return Err(conflict());
                    }
                    return if active.identity == identity {
                        Ok(())
                    } else {
                        Err(conflict())
                    };
                }
                // The recorded socket is gone: stale record, fall through to start a fresh tunnel.
            }
            Err(_) => {
                // The record doesn't match the current shape (e.g. it was written
                // by a since-removed backend generation). Its identity can never
                // be trusted again, so it can never be adopted -- but if the
                // socket it names is gone, the tunnel it described no longer
                // exists either, and the record is safe to discard instead of
                // wedging every future connect forever.
                let legacy: UnrecognizedRecord =
                    serde_json::from_slice(&bytes).map_err(|_| conflict())?;
                if legacy.socket.try_exists()? {
                    return Err(conflict());
                }
            }
        }
    }
    if socket.try_exists()? {
        return Err(conflict());
    }
    let socket = start()?;
    let metadata = fs::metadata(&socket)?;
    let active = ActiveTunnel {
        identity,
        socket: socket.to_owned(),
        device: metadata.dev(),
        inode: metadata.ino(),
        changed_sec: metadata.ctime(),
        changed_nsec: metadata.ctime_nsec(),
    };
    // Contains private configuration: private from creation, atomic on publish,
    // and never included in a response or log. Survives daemon idle restarts.
    crate::state_file::write_atomic(record, &serde_json::to_vec(&active)?)?;
    Ok(())
}

pub(super) fn clear(path: &Path, interface: &str) -> Result<()> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(()),
    };
    let should_remove = match serde_json::from_slice::<ActiveTunnel>(&bytes) {
        Ok(active) => active.identity.interface == interface,
        Err(_) => match serde_json::from_slice::<UnrecognizedRecord>(&bytes) {
            Ok(legacy) if legacy.identity.interface == interface => !legacy.socket.try_exists()?,
            _ => false,
        },
    };
    if should_remove {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn identity(config: &str) -> Identity {
        Identity {
            interface: "wgconf0".into(),
            config_content: config.into(),
            mtu_override: None,
        }
    }

    fn directory(label: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tunmux-identity-{label}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn missing_local_state_cannot_relabel_profile_a_as_b() {
        let dir = directory("recover");
        let record = dir.join("active.json");
        let socket = dir.join("wgconf0.sock");
        connect(&record, identity("A"), &socket, || {
            fs::write(&socket, "socket")?;
            Ok(socket.clone())
        })
        .unwrap();
        assert!(connect(&record, identity("B"), &socket, || panic!(
            "must not replace A"
        ))
        .is_err());
        connect(&record, identity("A"), &socket, || {
            panic!("must not restart A")
        })
        .unwrap();
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_wg_quick_record_is_not_adopted() {
        let dir = directory("legacy");
        let record = dir.join("active.json");
        let socket = dir.join("wgconf0.sock");
        fs::write(&socket, "socket").unwrap();
        let metadata = fs::metadata(&socket).unwrap();
        let legacy = serde_json::json!({
            "identity": {
                "interface": "wgconf0",
                "config_content": "A",
                "mtu_override": null,
                "wg_quick": true
            },
            "socket": socket,
            "device": metadata.dev(),
            "inode": metadata.ino(),
            "changed_sec": metadata.ctime(),
            "changed_nsec": metadata.ctime_nsec(),
        });
        fs::write(&record, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert!(connect(&record, identity("A"), &socket, || panic!(
            "legacy wg-quick record must not be silently adopted"
        ))
        .is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_record_with_missing_socket_is_recovered() {
        let dir = directory("legacy-stale");
        let record = dir.join("active.json");
        let socket = dir.join("wgconf0.sock");
        let legacy = serde_json::json!({
            "identity": { "interface": "wgconf0", "wg_quick": true },
            "socket": socket,
        });
        fs::write(&record, serde_json::to_vec(&legacy).unwrap()).unwrap();
        let mut started = false;
        connect(&record, identity("A"), &socket, || {
            started = true;
            fs::write(&socket, "socket")?;
            Ok(socket.clone())
        })
        .unwrap();
        assert!(
            started,
            "a stale legacy record must not block a fresh connect"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_record_is_cleared_by_clear_once_stale() {
        let dir = directory("legacy-clear");
        let record = dir.join("active.json");
        let socket = dir.join("wgconf0.sock");
        let legacy = serde_json::json!({
            "identity": { "interface": "wgconf0", "wg_quick": true },
            "socket": socket,
        });
        fs::write(&record, serde_json::to_vec(&legacy).unwrap()).unwrap();

        clear(&record, "wgconf0").unwrap();
        assert!(!record.exists(), "a stale legacy record must be cleared");
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn legacy_record_with_live_socket_is_still_rejected() {
        let dir = directory("legacy-live");
        let record = dir.join("active.json");
        let socket = dir.join("wgconf0.sock");
        fs::write(&socket, "socket").unwrap();
        let legacy = serde_json::json!({
            "identity": { "interface": "wgconf0", "wg_quick": true },
            "socket": socket,
        });
        fs::write(&record, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert!(connect(&record, identity("A"), &socket, || panic!(
            "a live but unverifiable tunnel must not be adopted"
        ))
        .is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn unknown_live_tunnel_is_not_adopted() {
        let dir = directory("unknown");
        let socket = dir.join("wgconf0.sock");
        fs::write(&socket, "socket").unwrap();
        assert!(
            connect(&dir.join("active.json"), identity("B"), &socket, || panic!(
                "unknown tunnel replaced"
            ))
            .is_err()
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn changed_mtu_and_replaced_socket_are_not_a_match() {
        let dir = directory("changed");
        let record = dir.join("active.json");
        let socket = dir.join("wgconf0.sock");
        connect(&record, identity("A"), &socket, || {
            fs::write(&socket, "socket")?;
            Ok(socket.clone())
        })
        .unwrap();
        let mut changed = identity("A");
        changed.mtu_override = Some(1280);
        assert!(connect(&record, changed, &socket, || panic!(
            "must not change MTU silently"
        ))
        .is_err());
        let replacement = dir.join("replacement.sock");
        fs::write(&replacement, "new socket").unwrap();
        fs::rename(replacement, &socket).unwrap();
        assert!(connect(&record, identity("A"), &socket, || panic!(
            "must not trust replaced socket"
        ))
        .is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_profiles_have_one_winner_and_matching_record() {
        let dir = directory("race");
        let barrier = Arc::new(Barrier::new(3));
        let workers: Vec<_> = ["A", "B"]
            .into_iter()
            .map(|config| {
                let dir = dir.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    let _lock = crate::state_file::lock(&dir.join("mutation.lock")).unwrap();
                    let socket = dir.join("wgconf0.sock");
                    connect(&dir.join("active.json"), identity(config), &socket, || {
                        fs::write(&socket, config)?;
                        Ok(socket.clone())
                    })
                    .is_ok()
                })
            })
            .collect();
        barrier.wait();
        assert_eq!(
            workers
                .into_iter()
                .map(|worker| worker.join().unwrap() as usize)
                .sum::<usize>(),
            1
        );
        let active: ActiveTunnel =
            serde_json::from_slice(&fs::read(dir.join("active.json")).unwrap()).unwrap();
        assert_eq!(
            active.identity.config_content,
            fs::read_to_string(dir.join("wgconf0.sock")).unwrap()
        );
        fs::remove_dir_all(dir).unwrap();
    }
}
