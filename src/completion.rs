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

/// The shells `COMPLETE=<shell> wgd` serves: `clap_complete`'s own, except
/// bash, whose registration script is [`WgdBash`].
#[must_use]
pub fn shells() -> clap_complete::env::Shells<'static> {
    use clap_complete::env::{Elvish, Fish, Powershell, Shells, Zsh};
    Shells(&[&WgdBash, &Elvish, &Fish, &Powershell, &Zsh])
}

/// bash completion with a registration script of our own.
///
/// `clap_complete` hands bash's `COMP_WORDS` to the binary as they are, and
/// bash cuts those at `=` and `:`, so `connection config --set-link A=p1,p2`
/// arrives in pieces and cannot be completed. Our script
/// (`completion_bash.sh`) joins the pieces again and trims the candidates to
/// what bash replaces. Everything on the binary side stays `clap_complete`'s:
/// [`write_complete`](EnvCompleter::write_complete) delegates to its `Bash`, so
/// the engine, the candidate output and its reading of the `_CLAP_*`
/// variables follow the library. Only the shell side of that protocol is ours;
/// a test compares its variables with the ones `clap_complete`'s script uses,
/// which is what a `clap_complete` update could change.
pub struct WgdBash;

const BASH_REGISTRATION: &str = include_str!("completion_bash.sh");

impl clap_complete::env::EnvCompleter for WgdBash {
    fn name(&self) -> &'static str {
        clap_complete::env::Bash.name()
    }

    fn is(&self, name: &str) -> bool {
        clap_complete::env::Bash.is(name)
    }

    fn write_registration(
        &self,
        var: &str,
        name: &str,
        bin: &str,
        completer: &str,
        buf: &mut dyn Write,
    ) -> std::io::Result<()> {
        writeln!(
            buf,
            "{}",
            render_bash_registration(var, name, bin, completer)
        )
    }

    fn write_complete(
        &self,
        cmd: &mut clap::Command,
        args: Vec<std::ffi::OsString>,
        current_dir: Option<&Path>,
        buf: &mut dyn Write,
    ) -> std::io::Result<()> {
        clap_complete::env::Bash.write_complete(cmd, args, current_dir, buf)
    }
}

fn render_bash_registration(var: &str, name: &str, bin: &str, completer: &str) -> String {
    BASH_REGISTRATION
        .replace("@NAME@", &name.replace('-', "_"))
        .replace("@BIN@", bin)
        .replace("@COMPLETER@", &shell_quote(completer))
        .replace("@VAR@", var)
}

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

    // ---- bash registration ---------------------------------------------------

    /// Names of the `_CLAP_*` variables a script mentions.
    fn clap_vars(script: &str) -> std::collections::BTreeSet<String> {
        let mut vars = std::collections::BTreeSet::new();
        let mut rest = script;
        while let Some(at) = rest.find("_CLAP_") {
            let tail = &rest[at..];
            let len = tail
                .find(|c: char| !(c.is_ascii_uppercase() || c == '_'))
                .unwrap_or(tail.len());
            vars.insert(tail[..len].to_string());
            rest = &tail[len..];
        }
        vars
    }

    #[test]
    fn bash_registration_speaks_the_protocol_of_the_clap_script() {
        use clap_complete::env::EnvCompleter;
        let mut theirs = Vec::new();
        clap_complete::env::Bash
            .write_registration("COMPLETE", "wgd", "wgd", "/bin/wgd", &mut theirs)
            .unwrap();
        let theirs = String::from_utf8(theirs).unwrap();
        let ours = render_bash_registration("COMPLETE", "wgd", "wgd", "/bin/wgd");

        // A clap_complete update that renames or drops a variable the shell
        // side hands to the binary must fail here, not at the first <TAB>.
        let (theirs_vars, ours_vars) = (clap_vars(&theirs), clap_vars(&ours));
        assert!(
            ours_vars.is_subset(&theirs_vars),
            "ours {ours_vars:?} vs clap_complete's {theirs_vars:?}"
        );
        for needed in [
            "_CLAP_IFS",
            "_CLAP_COMPLETE_INDEX",
            "_CLAP_COMPLETE_COMP_TYPE",
            "_CLAP_COMPLETE_SPACE",
        ] {
            assert!(ours_vars.contains(needed), "{needed}");
        }
        for script in [&theirs, &ours] {
            assert!(script.contains("COMPLETE=\"bash\""));
            assert!(script.contains("-- \"${words[@]}\""));
        }
    }

    #[test]
    fn bash_registration_fills_every_placeholder() {
        let script = render_bash_registration("COMPLETE", "my-wgd", "wgd", "/opt/my dir/wgd");
        for placeholder in ["@NAME@", "@BIN@", "@COMPLETER@", "@VAR@"] {
            assert!(!script.contains(placeholder), "{placeholder}");
        }
        assert!(script.contains("_clap_complete_my_wgd() {"));
        assert!(script.contains("-F _clap_complete_my_wgd wgd"));
        assert!(script.contains("COMPLETE=\"bash\""));
        assert!(script.contains("'/opt/my dir/wgd' -- "));
    }

    #[test]
    fn shell_table_keeps_the_other_shells() {
        let table = shells();
        for shell in ["bash", "zsh", "fish", "elvish", "pwsh"] {
            assert!(table.completer(shell).is_some(), "{shell}");
        }
        assert_eq!(table.names().filter(|name| *name == "bash").count(), 1);
    }

    /// What a run of the bash registration saw and produced.
    struct BashRun {
        /// Index and words the completer was called with: `5|a b c`.
        asked: String,
        reply: Vec<String>,
    }

    /// Runs the bash registration in a real `bash` the way a completion
    /// calls it: `comp_words` are the words bash cut `comp_line` into, with
    /// the cursor at its end. The completer is a stub that logs what it is
    /// asked and offers those of `candidates` that start with the last word.
    fn run_bash_completion(
        bash: &str,
        wordbreaks: &str,
        comp_line: &str,
        comp_words: &[&str],
        comp_cword: usize,
        candidates: &[&str],
    ) -> BashRun {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "wgd-bash-completion-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let stub = dir.join("stub");
        let log = dir.join("log");
        let list: String = candidates.iter().map(|c| format!("'{c}' ")).collect();
        std::fs::write(
            &stub,
            format!(
                "#!/bin/bash\n\
                 shift\n\
                 printf '%s|%s\\n' \"$_CLAP_COMPLETE_INDEX\" \"$*\" > '{log}'\n\
                 cur=\"${{@: -1}}\"\n\
                 out=\n\
                 for c in {list}; do\n\
                 \x20 case \"$c\" in \"$cur\"*) out=\"$out${{out:+$_CLAP_IFS}}$c\";; esac\n\
                 done\n\
                 printf '%s' \"$out\"\n",
                log = log.display(),
            ),
        )
        .unwrap();
        std::fs::set_permissions(&stub, std::fs::Permissions::from_mode(0o755)).unwrap();

        let registration =
            render_bash_registration("COMPLETE", "wgd", "wgd", stub.to_str().unwrap());
        let words: String = comp_words.iter().map(|w| format!("'{w}' ")).collect();
        let program = format!(
            "{registration}\n\
             COMP_WORDBREAKS=$TEST_WORDBREAKS\n\
             COMP_LINE='{comp_line}'\n\
             COMP_POINT={point}\n\
             COMP_TYPE=9\n\
             COMP_WORDS=({words})\n\
             COMP_CWORD={comp_cword}\n\
             _clap_complete_wgd wgd '' ''\n\
             for r in \"${{COMPREPLY[@]}}\"; do printf 'REPLY:%s\\n' \"$r\"; done\n",
            point = comp_line.len(),
        );
        let output = std::process::Command::new(bash)
            .arg("-c")
            .arg(&program)
            .env("TEST_WORDBREAKS", wordbreaks)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{bash}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let reply = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .filter_map(|line| line.strip_prefix("REPLY:").map(str::to_string))
            .collect();
        let asked = std::fs::read_to_string(&log)
            .unwrap_or_default()
            .trim_end_matches('\n')
            .to_string();
        let _ = std::fs::remove_dir_all(&dir);
        BashRun { asked, reply }
    }

    /// The bashes to test with: macOS ships 3.2 as `/bin/bash`, Homebrew's is
    /// current.
    fn bashes() -> Vec<&'static str> {
        ["/bin/bash", "/opt/homebrew/bin/bash", "/usr/local/bin/bash"]
            .into_iter()
            .filter(|path| Path::new(path).exists())
            .collect()
    }

    const DEFAULT_WORDBREAKS: &str = " \t\n\"'><=;|&(:";
    const CANDIDATES: &[&str] = &[
        "10.66.77.0/24=",
        "10.66.77.0/24=192.168.188.1/32",
        "10.66.77.0/24=192.168.188.1/32,100.64.1.0/24",
        "--set-link=10.66.77.0/24=",
        "fd00::/64=",
        "fd00::/64=fd01::1/128",
        "fd00::/64=fd01::1/128,fd01::2/128",
        "connect",
        "config",
    ];

    fn link_line(text: &str) -> String {
        format!("wgd connection config home --set-link {text}")
    }

    fn strings(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn bash_completion_rejoins_words_cut_at_equals_and_colon() {
        let head = ["wgd", "connection", "config", "home", "--set-link"];
        let words = |tail: &[&'static str]| -> Vec<&'static str> {
            let mut all = head.to_vec();
            all.extend_from_slice(tail);
            all
        };
        assert!(!bashes().is_empty());
        for bash in bashes() {
            let run = |line: &str, words: &[&str], cword: usize| {
                run_bash_completion(bash, DEFAULT_WORDBREAKS, line, words, cword, CANDIDATES)
            };

            // Nothing was cut: nothing to trim.
            let r = run(&link_line("10."), &words(&["10."]), 5);
            assert_eq!(
                r.asked, "5|wgd connection config home --set-link 10.",
                "{bash}"
            );
            assert_eq!(
                r.reply,
                strings(&[
                    "10.66.77.0/24=",
                    "10.66.77.0/24=192.168.188.1/32",
                    "10.66.77.0/24=192.168.188.1/32,100.64.1.0/24"
                ]),
                "{bash}"
            );

            // bash 5 cuts `A=` into `A` and `=`; bash 3.2 leaves it whole.
            let after_equals = strings(&["", "192.168.188.1/32", "192.168.188.1/32,100.64.1.0/24"]);
            let cut = run(
                &link_line("10.66.77.0/24="),
                &words(&["10.66.77.0/24", "="]),
                6,
            );
            assert_eq!(
                cut.asked, "5|wgd connection config home --set-link 10.66.77.0/24=",
                "{bash}"
            );
            assert_eq!(cut.reply, after_equals, "{bash}");
            let whole = run(&link_line("10.66.77.0/24="), &words(&["10.66.77.0/24="]), 5);
            assert_eq!(whole.asked, cut.asked, "{bash}");
            assert_eq!(whole.reply, after_equals, "{bash}");

            // A second prefix: only what follows the `=` is given back.
            let r = run(
                &link_line("10.66.77.0/24=192.168.188.1/32,1"),
                &words(&["10.66.77.0/24", "=", "192.168.188.1/32,1"]),
                7,
            );
            assert_eq!(
                r.asked, "5|wgd connection config home --set-link 10.66.77.0/24=192.168.188.1/32,1",
                "{bash}"
            );
            assert_eq!(
                r.reply,
                strings(&["192.168.188.1/32,100.64.1.0/24"]),
                "{bash}"
            );

            // IPv6: `:` cuts as well, and the last break is the second `:`.
            let r = run(
                &link_line("fd00::/64=fd01::1"),
                &words(&["fd00", "::", "/64", "=", "fd01", "::", "1"]),
                11,
            );
            assert_eq!(
                r.asked, "5|wgd connection config home --set-link fd00::/64=fd01::1",
                "{bash}"
            );
            assert_eq!(r.reply, strings(&["1/128", "1/128,fd01::2/128"]), "{bash}");

            // `--set-link=VALUE` form.
            let r = run(
                "wgd connection config home --set-link=10.",
                &[
                    "wgd",
                    "connection",
                    "config",
                    "home",
                    "--set-link",
                    "=",
                    "10.",
                ],
                6,
            );
            assert_eq!(
                r.asked, "4|wgd connection config home --set-link=10.",
                "{bash}"
            );
            assert_eq!(r.reply, strings(&["10.66.77.0/24="]), "{bash}");
        }
    }

    #[test]
    fn bash_completion_leaves_ordinary_words_alone() {
        for bash in bashes() {
            let run = |line: &str, words: &[&str], cword: usize| {
                run_bash_completion(bash, DEFAULT_WORDBREAKS, line, words, cword, CANDIDATES)
            };
            let r = run("wgd connection con", &["wgd", "connection", "con"], 2);
            assert_eq!(r.asked, "2|wgd connection con", "{bash}");
            assert_eq!(r.reply, strings(&["connect", "config"]), "{bash}");

            // The cursor after a space is a new, empty word, not joined to the
            // one before it.
            let r = run("wgd connection ", &["wgd", "connection", ""], 2);
            assert_eq!(r.asked, "2|wgd connection ", "{bash}");
            assert_eq!(r.reply.len(), CANDIDATES.len(), "{bash}");
        }
    }

    #[test]
    fn bash_completion_follows_the_users_word_breaks() {
        // `:` removed from COMP_WORDBREAKS (a common setting): bash keeps IPv6
        // addresses whole, so nothing is rejoined or trimmed for `:`.
        let breaks = " \t\n\"'><=;|&(";
        for bash in bashes() {
            let r = run_bash_completion(
                bash,
                breaks,
                &link_line("fd00::/64=fd01::1"),
                &[
                    "wgd",
                    "connection",
                    "config",
                    "home",
                    "--set-link",
                    "fd00::/64",
                    "=",
                    "fd01::1",
                ],
                7,
                CANDIDATES,
            );
            assert_eq!(
                r.asked, "5|wgd connection config home --set-link fd00::/64=fd01::1",
                "{bash}"
            );
            assert_eq!(
                r.reply,
                strings(&["fd01::1/128", "fd01::1/128,fd01::2/128"]),
                "{bash}"
            );
        }
    }
}
