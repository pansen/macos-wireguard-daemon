//! Finding 3 — Executable substitution through PATH.
//!
//! Root operations only execute system tools. An absolute Homebrew path is
//! insufficient: its owner can replace it.
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{fs, io};

pub const SYSTEM_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
const LOCAL_BIN: &str = "/usr/local/bin";

/// What is being checked, so a rejection can name the right thing to fix.
/// `validate_root_owned_path` guards the tunmux binary that root re-executes
/// and root-only state directories; the remedy differs.
#[derive(Clone, Copy)]
pub enum TrustedPath {
    /// The tunmux binary itself, wherever it happens to be installed.
    Executable,
    /// A directory holding root-only state.
    Directory,
}

impl TrustedPath {
    fn subject(self) -> &'static str {
        match self {
            TrustedPath::Executable => "privileged executable path",
            TrustedPath::Directory => "privileged directory",
        }
    }

    fn remedy(self) -> String {
        match self {
            TrustedPath::Executable => "install tunmux where it and every parent directory are \
                 root-owned, are not symlinks, and have no group/other write access"
                .into(),
            TrustedPath::Directory => "chown it to root and remove group/other write access, \
                 including on every parent directory"
                .into(),
        }
    }
}

fn trusted_local_bin() -> Option<&'static str> {
    // Finding 3 — Executable substitution through PATH: /usr/local/bin is
    // also tunmux's installation directory. Allow it after system tools only
    // when it and its ancestors are root-controlled; do not assume every
    // machine has the same ownership.
    validate_root_owned_path(Path::new(LOCAL_BIN), TrustedPath::Directory)
        .ok()
        .filter(|()| Path::new(LOCAL_BIN).is_dir())
        .map(|()| LOCAL_BIN)
}

fn search_path() -> String {
    let mut path = SYSTEM_PATH.to_owned();
    if let Some(local_bin) = trusted_local_bin() {
        path.push(':');
        path.push_str(local_bin);
    }
    path
}

pub fn command(name: &str) -> io::Result<Command> {
    let path = match name {
        "ifconfig" | "route" => PathBuf::from("/sbin").join(name),
        "networksetup" | "scutil" => PathBuf::from("/usr/sbin").join(name),
        "id" => PathBuf::from("/usr/bin/id"),
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unapproved privileged executable",
            ))
        }
    };
    let mut command = Command::new(path);
    sanitize(&mut command);
    Ok(command)
}

pub fn sanitize(command: &mut Command) {
    command.env("PATH", search_path());
    // Shell startup files must not redirect execution.
    for name in ["BASH_ENV", "ENV", "CDPATH"] {
        command.env_remove(name);
    }
}

pub fn validate_root_owned_path(path: &Path, kind: TrustedPath) -> io::Result<()> {
    // Check both spellings: a root-owned target can still be swapped through
    // a symlink in a user-writable parent. Root-owned, non-writable ancestors
    // keep the checked path stable until exec. Reject symlinks in the bundle.
    for ancestor in path.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0
        {
            return Err(io::Error::other(format!(
                "untrusted {} {}; {}",
                kind.subject(),
                ancestor.display(),
                kind.remedy()
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    #[test]
    fn system_command_ignores_substitute_on_path() {
        let dir = std::env::temp_dir().join(format!("tunmux-path-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("id");
        fs::write(&fake, "#!/bin/sh\necho substituted\n").unwrap();
        fs::set_permissions(&fake, fs::Permissions::from_mode(0o755)).unwrap();
        let mut command = command("id").unwrap();
        assert!(command
            .get_envs()
            .any(|(key, value)| key == "PATH" && value == Some(search_path().as_ref())));
        let output = command.env("PATH", &dir).output().unwrap();
        assert!(output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("substituted"));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn symlinked_privileged_directory_is_rejected() {
        let path = std::env::temp_dir().join(format!("tunmux-dir-link-{}", std::process::id()));
        symlink("/usr/bin", &path).unwrap();
        assert!(validate_root_owned_path(&path, TrustedPath::Directory).is_err());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn unapproved_executable_is_rejected() {
        assert!(command("./ifconfig").is_err());
    }

    #[test]
    fn local_bin_is_conditional_and_follows_trusted_tools() {
        let expected = if trusted_local_bin().is_some() {
            format!("{SYSTEM_PATH}:{LOCAL_BIN}")
        } else {
            SYSTEM_PATH.to_owned()
        };
        assert_eq!(search_path(), expected);
        assert!(!search_path().contains("/opt/homebrew"));
    }

    #[test]
    fn writable_directory_cannot_be_a_trusted_search_path() {
        let path =
            std::env::temp_dir().join(format!("tunmux-writable-path-{}", std::process::id()));
        fs::create_dir_all(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(validate_root_owned_path(&path, TrustedPath::Directory).is_err());
        fs::remove_dir(path).unwrap();
    }
}
