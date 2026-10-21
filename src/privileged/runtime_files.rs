//! Stale helper runtime files under `/var/run/wireguard`.
//!
//! A helper that dies without teardown (SIGKILL, panic) leaves its UAPI socket,
//! pid/name files and query socket behind. `connection_ops::connect` treats a
//! lingering socket as "interface already in an unverified state", so the
//! next connect would fail until someone deleted the files by hand. Once a
//! helper is confirmed dead the daemon removes them itself.
//!
//! The `.wgd.cleanup` status file is deliberately not touched here: it is the
//! result of a graceful teardown that `disconnect` may still be waiting to
//! read, and `commands::run_gotatun_up` already clears it (with the pid, name
//! and log files) before it spawns the next helper.
use std::os::unix::fs::FileTypeExt;
use std::path::PathBuf;

use tracing::{info, warn};

use super::commands::{
    gotatun_name_path, gotatun_pid_path, gotatun_query_socket_path, gotatun_socket_path,
};

/// The files a dead helper leaves behind, in the order they are removed.
pub(super) fn stale_runtime_paths(interface: &str) -> Vec<PathBuf> {
    vec![
        gotatun_socket_path(interface),
        gotatun_pid_path(interface),
        gotatun_name_path(interface),
        gotatun_query_socket_path(interface),
    ]
}

/// Unlink the regular files and sockets among `paths` and return the ones
/// removed. Anything else (a symlink, a directory, a device) is left alone
/// with a WARN: the directory is root-owned, so such an entry is not ours.
/// `symlink_metadata` is used so a symlink is never followed.
pub(super) fn remove_regular_files(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut removed = Vec::new();
    for path in paths {
        let file_type = match std::fs::symlink_metadata(path) {
            Ok(metadata) => metadata.file_type(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                warn!(path = %path.display(), error = %error, "privileged_stale_runtime_file_stat_failed");
                continue;
            }
        };
        if !(file_type.is_file() || file_type.is_socket()) {
            warn!(path = %path.display(), "privileged_stale_runtime_file_skipped_not_regular");
            continue;
        }
        match std::fs::remove_file(path) {
            Ok(()) => removed.push(path.clone()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                warn!(path = %path.display(), error = %error, "privileged_stale_runtime_file_remove_failed");
            }
        }
    }
    removed
}

/// Remove `interface`'s stale runtime files if `helper_is_live` says no.
/// Callers hold the system network mutation lock, and the liveness check runs
/// here, right before removing, so a helper that came up since the caller's
/// own check is never touched. Returns the removed file names.
pub(super) fn remove_if_dead_locked(
    interface: &str,
    helper_is_live: impl FnOnce() -> bool,
) -> Vec<String> {
    if helper_is_live() {
        return Vec::new();
    }
    let removed = remove_regular_files(&stale_runtime_paths(interface));
    let files: Vec<String> = removed
        .iter()
        .filter_map(|path| path.file_name())
        .map(|name| name.to_string_lossy().into_owned())
        .collect();
    if !files.is_empty() {
        info!(interface, files = ?files, "privileged_stale_runtime_files_removed");
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    fn temp_dir(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wgd-stale-{label}-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn paths_cover_socket_pid_name_and_query_socket_but_not_cleanup() {
        let names: Vec<String> = stale_runtime_paths("wg-aaaaaaaa")
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            [
                "wg-aaaaaaaa.sock",
                "wg-aaaaaaaa.wgd.pid",
                "wg-aaaaaaaa.wgd.name",
                "wg-aaaaaaaa.wgd.query.sock"
            ]
        );
    }

    #[test]
    fn live_helper_keeps_its_files_without_touching_the_filesystem() {
        let removed = remove_if_dead_locked("wg-live-never-exists", || true);
        assert!(removed.is_empty());
    }

    #[test]
    fn removal_unlinks_files_and_sockets_but_never_follows_symlinks() {
        let dir = temp_dir("remove");
        let file = dir.join("a.wgd.pid");
        std::fs::write(&file, "123").unwrap();
        let socket = dir.join("a.sock");
        drop(UnixListener::bind(&socket).unwrap());
        let target = dir.join("precious");
        std::fs::write(&target, "keep").unwrap();
        let link = dir.join("a.wgd.name");
        symlink(&target, &link).unwrap();
        let subdir = dir.join("a.wgd.query.sock");
        std::fs::create_dir(&subdir).unwrap();
        let missing = dir.join("never-created");

        let removed = remove_regular_files(&[
            socket.clone(),
            file.clone(),
            link.clone(),
            subdir.clone(),
            missing,
        ]);

        assert_eq!(removed, vec![socket.clone(), file.clone()]);
        assert!(!socket.exists() && !file.exists());
        // The symlink and its target survive, as does the directory.
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
        assert!(subdir.is_dir());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
