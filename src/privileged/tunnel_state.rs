//! Finding 5 — Incorrect tunnel adoption and connection races.
//!
//! The daemon's private record binds configuration to the socket inode of the
//! running tunnel. Never infer its identity from a caller's requested profile.
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use crate::error::{AppError, Result};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, PartialEq, Eq)]
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
        // A corrupt private record must not permit taking over an unknown tunnel.
        let active: ActiveTunnel = serde_json::from_slice(&bytes).map_err(|_| conflict())?;
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

pub(super) fn clear(interface: &str) -> Result<()> {
    let path = record_path();
    if let Ok(bytes) = fs::read(&path) {
        if let Ok(active) = serde_json::from_slice::<ActiveTunnel>(&bytes) {
            if active.identity.interface == interface {
                fs::remove_file(path)?;
            }
        }
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
