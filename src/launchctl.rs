//! Shared `launchctl`/plist-rendering helpers used by both the privileged
//! (system-domain) launchd daemon installer (`src/launchd.rs`) and the
//! per-user (GUI-domain) autoconnect agent installer (`src/autoconnect.rs`).
//! Generic — no privileged/GUI-domain assumptions.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use anyhow::Context;

pub(crate) fn run_checked(program: &str, args: &[&str]) -> anyhow::Result<()> {
    let output = std::process::Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run {program} {}", args.join(" ")))?;
    if !output.status.success() {
        anyhow::bail!(
            "{program} {} failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

pub(crate) fn run_ignore_failure(program: &str, args: &[&str]) {
    match std::process::Command::new(program).args(args).output() {
        Ok(output) if !output.status.success() => {
            tracing::debug!(
                program,
                args = ?args,
                status = ?output.status,
                stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                "launchd_command_ignored_failure"
            );
        }
        Err(err) => {
            tracing::debug!(program, args = ?args, error = %err, "launchd_command_failed_to_run");
        }
        Ok(_) => {}
    }
}

pub(crate) fn remove_file_ignore_missing(path: &Path) -> anyhow::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("failed to remove {}", path.display())),
    }
}

/// Escape the five XML special characters so a path with e.g. `&` in it
/// still produces a well-formed plist.
pub(crate) fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Inverse of [`xml_escape`], for reading a value back out of a rendered
/// plist. `&amp;` is decoded last so an escaped `&amp;lt;` round-trips.
pub(crate) fn xml_unescape(s: &str) -> String {
    s.replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&amp;", "&")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_escape_escapes_specials() {
        assert_eq!(xml_escape("/a&b/<c>"), "/a&amp;b/&lt;c&gt;");
    }

    #[test]
    fn xml_unescape_reverses_escape() {
        let raw = "/a&b/<c>\"d'e";
        assert_eq!(xml_unescape(&xml_escape(raw)), raw);
    }
}
