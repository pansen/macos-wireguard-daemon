//! `wgd completion install`: writes or updates the managed tab-completion block
//! in the user's shell rc file.
//!
//! `wgd` serves its own completions via `clap_complete::CompleteEnv`: when the
//! shell runs `COMPLETE=<shell> wgd`, `wgd` prints the registration script, and
//! on `<TAB>` the shell calls back into the binary for candidates.
//!
//! The rc block is bracketed by `# begin: wgd managed` / `# end: wgd managed`
//! markers so repeated runs replace an older block in place rather than
//! stacking duplicates. Writing back truncates the target in place rather than
//! renaming a temp file over it, preserving symlinked dotfiles (e.g.
//! `~/.bashrc -> ~/dotfiles/.bashrc`) and the target's permissions.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use nix::unistd::geteuid;

use crate::cli::{CompletionCommand, CompletionShell};

const BEGIN_MARKER: &str = "# begin: wgd managed";
const END_MARKER: &str = "# end: wgd managed";

pub fn dispatch(command: CompletionCommand) -> anyhow::Result<()> {
    match command {
        CompletionCommand::Install { shell } => cmd_install(shell),
    }
}

fn cmd_install(shell: CompletionShell) -> anyhow::Result<()> {
    if geteuid().is_root() {
        anyhow::bail!(
            "run `wgd completion install` as your normal user, not with sudo \
             (shell completion is installed into your user rc file)"
        );
    }

    let home = std::env::var("HOME").context("could not determine $HOME")?;
    let bin = std::env::current_exe().context("failed to determine the running wgd binary path")?;
    let rc_path = rc_file_path(Path::new(&home), shell);

    install_to_file(&rc_path, shell, &bin)?;
    println!(
        "Installed {:?} completion for {} in {}.",
        shell,
        bin.display(),
        rc_path.display()
    );
    Ok(())
}

fn rc_file_path(home: &Path, shell: CompletionShell) -> PathBuf {
    match shell {
        CompletionShell::Bash => home.join(".bashrc"),
        CompletionShell::Zsh => home.join(".zshrc"),
        CompletionShell::Fish => home.join(".config/fish/config.fish"),
    }
}

pub(crate) fn install_to_file(
    rc_path: &Path,
    shell: CompletionShell,
    bin_path: &Path,
) -> anyhow::Result<()> {
    if let Some(parent) = rc_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let existing = match fs::read_to_string(rc_path) {
        Ok(content) => content,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to read {}", rc_path.display()))
        }
    };

    let block = render_managed_block(shell, bin_path)?;
    let updated = update_rc_contents(&existing, &block);

    // Truncate and write in place rather than temp-rename so a symlinked
    // dotfile (`~/.bashrc -> ~/dotfiles/.bashrc`) stays a symlink and keeps its
    // target's permissions.
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(rc_path)
        .with_context(|| format!("failed to open {} for writing", rc_path.display()))?;
    file.write_all(updated.as_bytes())
        .with_context(|| format!("failed to write {}", rc_path.display()))?;
    Ok(())
}

fn render_managed_block(shell: CompletionShell, bin_path: &Path) -> anyhow::Result<String> {
    let bin = bin_path.to_str().ok_or_else(|| {
        anyhow::anyhow!("wgd binary path is not valid UTF-8: {}", bin_path.display())
    })?;
    let quoted = shell_quote(bin);

    // `eval "$(...)"` rather than `source <(COMPLETE=bash wgd)`: process
    // substitution loses the script under macOS's system bash 3.2 (/bin/bash),
    // leaving the completion function undefined. The `[ -f ... ]` guard and
    // `2>/dev/null` make a removed binary a silent no-op on new shells.
    let body = match shell {
        CompletionShell::Bash => format!(
            "{BEGIN_MARKER}\n\
             if [ -f {quoted} ]; then\n\
             \x20 eval \"$(COMPLETE=bash {quoted} 2>/dev/null)\"\n\
             fi\n\
             {END_MARKER}\n"
        ),
        CompletionShell::Zsh => format!(
            "{BEGIN_MARKER}\n\
             if [ -f {quoted} ]; then\n\
             \x20 eval \"$(COMPLETE=zsh {quoted} 2>/dev/null)\"\n\
             fi\n\
             {END_MARKER}\n"
        ),
        CompletionShell::Fish => format!(
            "{BEGIN_MARKER}\n\
             if test -f {quoted}\n\
             \x20 COMPLETE=fish {quoted} 2>/dev/null | source\n\
             end\n\
             {END_MARKER}\n"
        ),
    };
    Ok(body)
}

fn shell_quote(path: &str) -> String {
    if path
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '/' | '-' | '_' | '.'))
    {
        path.to_string()
    } else {
        format!("'{}'", path.replace('\'', "'\\''"))
    }
}

fn update_rc_contents(existing: &str, managed_block: &str) -> String {
    let mut kept = Vec::new();
    let mut inside_managed = false;

    for line in existing.lines() {
        if line.trim() == BEGIN_MARKER {
            inside_managed = true;
            continue;
        }
        if inside_managed {
            if line.trim() == END_MARKER {
                inside_managed = false;
            }
            continue;
        }
        kept.push(line);
    }

    let mut out = kept.join("\n");
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    out.push_str(managed_block);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    #[test]
    fn renders_bash_block_matching_makefile_format() {
        let block =
            render_managed_block(CompletionShell::Bash, Path::new("/usr/local/bin/wgd")).unwrap();
        assert_eq!(
            block,
            "# begin: wgd managed\n\
             if [ -f /usr/local/bin/wgd ]; then\n\
             \x20 eval \"$(COMPLETE=bash /usr/local/bin/wgd 2>/dev/null)\"\n\
             fi\n\
             # end: wgd managed\n"
        );
    }

    #[test]
    fn update_rc_replaces_existing_block_without_stacking_duplicates() {
        let initial = "export PATH=/usr/local/bin:$PATH\n";
        let old_block =
            render_managed_block(CompletionShell::Bash, Path::new("/old/path/wgd")).unwrap();
        let new_block =
            render_managed_block(CompletionShell::Bash, Path::new("/usr/local/bin/wgd")).unwrap();

        let once = update_rc_contents(initial, &old_block);
        let twice = update_rc_contents(&once, &new_block);

        assert!(twice.starts_with("export PATH=/usr/local/bin:$PATH\n"));
        assert!(!twice.contains("/old/path/wgd"));
        assert!(twice.contains("/usr/local/bin/wgd"));
        assert_eq!(twice.matches(BEGIN_MARKER).count(), 1);
        assert_eq!(twice.matches(END_MARKER).count(), 1);
    }

    #[test]
    fn install_to_file_preserves_symlink() {
        let dir = std::env::temp_dir().join(format!(
            "wgd-completion-test-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        fs::create_dir_all(&dir).unwrap();
        let target = dir.join("dotfiles_bashrc");
        let link = dir.join(".bashrc");
        fs::write(&target, "# user config\n").unwrap();
        symlink(&target, &link).unwrap();

        install_to_file(
            &link,
            CompletionShell::Bash,
            Path::new("/usr/local/bin/wgd"),
        )
        .unwrap();

        assert!(fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        let content = fs::read_to_string(&target).unwrap();
        assert!(content.contains("# user config"));
        assert!(content.contains("COMPLETE=bash /usr/local/bin/wgd"));

        fs::remove_dir_all(dir).unwrap();
    }
}
