//! `wgd logs`: view or follow `/var/log/wgd/*.log` and launchd unified logs.
//!
//! Works with or without `sudo`: when invoked as a normal user it escalates on
//! demand via `sudo` because `/var/log/wgd` is `0700 root:wheel` (Finding 2 —
//! Protected log disclosure).

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use anyhow::Context;
use nix::unistd::geteuid;

use crate::cli::LogsArgs;
use crate::config;
use crate::connection_cli;
use crate::privileged_api::ConnectionId;
use crate::privileged_client::PrivilegedClient;

/// Connection logs untouched for longer than this are skipped unless a
/// connection is named or `--all` is given. Nothing deletes the log of a
/// removed connection, so without this cut-off `wgd logs` mostly shows
/// tunnels that no longer exist.
const RECENT_LOG_AGE: Duration = Duration::from_secs(24 * 60 * 60);

pub fn dispatch(mut args: LogsArgs) -> anyhow::Result<()> {
    // Resolve a connection name/UUID to its interface stem before escalating so
    // `Mine` lookup uses the invoking user's own UID when the daemon is up.
    if !args.launchd {
        if let Some(target) = args.connection.as_deref() {
            if let Some(stem) = try_resolve_log_stem(target) {
                args.connection = Some(stem);
            }
        }
    }

    if !geteuid().is_root() {
        return escalate_logs(&args);
    }

    if args.launchd {
        if args.follow {
            return follow_launchd_logs();
        }
        let output = collect_launchd_logs(args.lines);
        if output.trim().is_empty() {
            println!("No launchd log entries for wgd in the last 10m.");
        } else {
            print!("{output}");
            if !output.ends_with('\n') {
                println!();
            }
        }
        return Ok(());
    }

    let filter = match args.connection.as_deref() {
        Some(target) => Some(resolve_log_stem_required(target)?),
        None => None,
    };

    let log_dir = config::root_log_dir();
    let mut files = matching_log_files_in(&log_dir, filter.as_deref())?;
    let mut skipped = 0;
    if filter.is_none() && !args.all {
        (files, skipped) = keep_recent_logs(files, SystemTime::now());
    }
    if skipped > 0 {
        println!(
            "({skipped} connection log(s) older than 24h skipped; name a connection or pass --all)"
        );
    }
    if files.is_empty() {
        match filter {
            Some(stem) => println!("No log files for {stem} in {}.", log_dir.display()),
            None => println!("No log files in {}.", log_dir.display()),
        }
        return Ok(());
    }

    if args.follow {
        let mut cmd = Command::new("/usr/bin/tail");
        cmd.arg("-n").arg(args.lines.to_string()).arg("-f");
        for file in &files {
            cmd.arg(file);
        }
        let status = cmd.status().context("failed to run /usr/bin/tail -f")?;
        anyhow::ensure!(status.success(), "/usr/bin/tail exited with {status}");
        return Ok(());
    }

    let rendered = format_log_files_tail(&files, args.lines);
    if !rendered.is_empty() {
        print!("{rendered}");
    }
    Ok(())
}

/// Collect the last `lines` lines of every `/var/log/wgd/*.log` file, formatted
/// with `==> <path> <==` headers. Used by `wgd doctor`.
/// Connection logs older than 24 hours are left out, as in `wgd logs`.
pub(crate) fn collect_log_tails(lines: usize) -> String {
    let log_dir = config::root_log_dir();
    match matching_log_files_in(&log_dir, None) {
        Ok(files) => {
            let (files, skipped) = keep_recent_logs(files, SystemTime::now());
            let mut out = if files.is_empty() {
                format!("No log files in {}.\n", log_dir.display())
            } else {
                format_log_files_tail(&files, lines)
            };
            if skipped > 0 {
                out.push_str(&format!(
                    "({skipped} connection log(s) older than 24h skipped)\n"
                ));
            }
            out
        }
        Err(err) => format!("Unable to read {}: {err}\n", log_dir.display()),
    }
}

/// Keep the daemon's own logs and every log modified within
/// [`RECENT_LOG_AGE`] of `now`; returns the kept files and how many were
/// dropped. A file whose mtime cannot be read is kept.
fn keep_recent_logs(files: Vec<PathBuf>, now: SystemTime) -> (Vec<PathBuf>, usize) {
    let total = files.len();
    let kept: Vec<PathBuf> = files
        .into_iter()
        .filter(|path| {
            let is_daemon_log = path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("privileged."));
            is_daemon_log
                || fs::metadata(path)
                    .and_then(|m| m.modified())
                    .map(|modified| is_recent(modified, now))
                    .unwrap_or(true)
        })
        .collect();
    let skipped = total - kept.len();
    (kept, skipped)
}

fn is_recent(modified: SystemTime, now: SystemTime) -> bool {
    // A clock step can put `modified` in the future; treat that as recent.
    now.duration_since(modified)
        .map(|age| age <= RECENT_LOG_AGE)
        .unwrap_or(true)
}

/// Query unified logging for `sender == "launchd"` entries mentioning `wgd` in
/// the last 10 minutes, capped at the last `max_lines` matching lines.
pub(crate) fn collect_launchd_logs(max_lines: usize) -> String {
    let output = Command::new("/usr/bin/log")
        .args([
            "show",
            "--predicate",
            "sender == \"launchd\"",
            "--last",
            "10m",
            "--info",
        ])
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            filter_launchd_wgd_lines(&stdout, max_lines)
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
            format!("log show failed ({}): {stderr}\n", out.status)
        }
        Err(err) => format!("failed to run /usr/bin/log: {err}\n"),
    }
}

fn filter_launchd_wgd_lines(log_output: &str, max_lines: usize) -> String {
    let matching: Vec<&str> = log_output
        .lines()
        .filter(|line| line.to_ascii_lowercase().contains("wgd"))
        .collect();
    let start = matching.len().saturating_sub(max_lines);
    let mut out = matching[start..].join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

fn follow_launchd_logs() -> anyhow::Result<()> {
    let status = Command::new("/usr/bin/log")
        .args([
            "stream",
            "--predicate",
            "sender == \"launchd\" AND eventMessage CONTAINS[c] \"wgd\"",
            "--info",
        ])
        .status()
        .context("failed to run /usr/bin/log stream")?;
    anyhow::ensure!(status.success(), "/usr/bin/log stream exited with {status}");
    Ok(())
}

/// Best-effort resolution of a user-supplied `<connection>` string to a log
/// filename stem (`wg-xxxxxxxx` or `privileged`) without failing if the daemon
/// is unreachable.
fn try_resolve_log_stem(target: &str) -> Option<String> {
    if let Some(stem) = direct_log_stem(target) {
        return Some(stem);
    }
    let client = PrivilegedClient::new().without_autostart();
    connection_cli::resolve_interface(&client, target).ok()
}

fn resolve_log_stem_required(target: &str) -> anyhow::Result<String> {
    if let Some(stem) = direct_log_stem(target) {
        return Ok(stem);
    }
    let client = PrivilegedClient::new();
    connection_cli::resolve_interface(&client, target)
}

fn direct_log_stem(target: &str) -> Option<String> {
    let trimmed = target.strip_suffix(".log").unwrap_or(target);
    if matches!(
        trimmed,
        "privileged" | "daemon" | "privileged.out" | "privileged.err"
    ) {
        return Some("privileged".to_string());
    }
    if trimmed.starts_with("wg-") {
        return Some(trimmed.to_string());
    }
    if let Ok(id) = trimmed.parse::<ConnectionId>() {
        return Some(id.interface_name());
    }
    None
}

fn matching_log_files_in(
    log_dir: &Path,
    filter_stem: Option<&str>,
) -> anyhow::Result<Vec<PathBuf>> {
    let entries = match fs::read_dir(log_dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err).with_context(|| format!("failed to read {}", log_dir.display()))
        }
    };

    let mut files = Vec::new();
    for entry in entries {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("log") {
            continue;
        }
        let Some(file_name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if let Some(stem) = filter_stem {
            let matches = if stem == "privileged" {
                file_name == "privileged.log"
                    || file_name == "privileged.out.log"
                    || file_name == "privileged.err.log"
            } else {
                file_name == format!("{stem}.log")
            };
            if !matches {
                continue;
            }
        }
        files.push(path);
    }
    files.sort();
    Ok(files)
}

fn format_log_files_tail(files: &[PathBuf], max_lines: usize) -> String {
    let mut out = String::new();
    let show_headers = files.len() > 1;
    for (idx, path) in files.iter().enumerate() {
        if show_headers {
            if idx > 0 {
                out.push('\n');
            }
            out.push_str(&format!("==> {} <==\n", path.display()));
        }
        match fs::read_to_string(path) {
            Ok(content) => {
                let tailed = tail_lines(&content, max_lines);
                out.push_str(&tailed);
            }
            Err(err) => {
                out.push_str(&format!("(unable to read {}: {err})\n", path.display()));
            }
        }
    }
    out
}

fn tail_lines(content: &str, max_lines: usize) -> String {
    if max_lines == 0 || content.is_empty() {
        return String::new();
    }
    let all: Vec<&str> = content.lines().collect();
    let start = all.len().saturating_sub(max_lines);
    let mut out = all[start..].join("\n");
    if !out.is_empty() {
        out.push('\n');
    }
    out
}

fn escalate_logs(args: &LogsArgs) -> anyhow::Result<()> {
    let exe = std::env::current_exe().context("failed to determine the running wgd binary path")?;
    let mut cmd = Command::new("sudo");
    cmd.arg(&exe);
    if crate::logging::debug_enabled() {
        cmd.arg("--debug");
    }
    cmd.arg("logs");
    if args.follow {
        cmd.arg("--follow");
    }
    cmd.arg("--lines").arg(args.lines.to_string());
    if args.launchd {
        cmd.arg("--launchd");
    }
    if args.all {
        cmd.arg("--all");
    }
    if let Some(conn) = &args.connection {
        cmd.arg(conn);
    }

    tracing::warn!(
        action = "logs",
        method = "sudo",
        cause = "reading /var/log/wgd and launchd system logs requires root",
        "admin_authentication_requested"
    );
    let status = cmd.status().context("failed to run sudo for wgd logs")?;
    anyhow::ensure!(status.success(), "sudo wgd logs failed ({status})");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_stem_recognizes_interfaces_uuids_and_privileged() {
        assert_eq!(
            direct_log_stem("wg-1ce3a4a1"),
            Some("wg-1ce3a4a1".to_string())
        );
        assert_eq!(
            direct_log_stem("wg-1ce3a4a1.log"),
            Some("wg-1ce3a4a1".to_string())
        );
        assert_eq!(
            direct_log_stem("privileged"),
            Some("privileged".to_string())
        );
        assert_eq!(direct_log_stem("daemon"), Some("privileged".to_string()));
        assert_eq!(
            direct_log_stem("1ce3a4a1-0000-4000-8000-000000000000"),
            Some("wg-1ce3a4a1".to_string())
        );
        assert_eq!(direct_log_stem("andi_split"), None);
    }

    #[test]
    fn recent_logs_cut_off_after_a_day_and_tolerate_clock_steps() {
        let now = SystemTime::UNIX_EPOCH + Duration::from_secs(10 * 24 * 60 * 60);
        assert!(is_recent(now - Duration::from_secs(60), now));
        assert!(is_recent(now - RECENT_LOG_AGE, now));
        assert!(!is_recent(
            now - RECENT_LOG_AGE - Duration::from_secs(1),
            now
        ));
        assert!(is_recent(now + Duration::from_secs(60), now));
    }

    #[test]
    fn keep_recent_logs_always_keeps_daemon_logs() {
        let dir = std::env::temp_dir().join(format!("wgd-logs-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let daemon = dir.join("privileged.err.log");
        let conn = dir.join("wg-1ce3a4a1.log");
        fs::write(&daemon, "d\n").unwrap();
        fs::write(&conn, "c\n").unwrap();
        // Evaluated a week from now, both files are old; only the daemon log stays.
        let later = SystemTime::now() + Duration::from_secs(7 * 24 * 60 * 60);
        let (kept, skipped) = keep_recent_logs(vec![daemon.clone(), conn], later);
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(kept, vec![daemon]);
        assert_eq!(skipped, 1);
    }

    #[test]
    fn tail_lines_keeps_last_n_lines() {
        let text = "one\ntwo\nthree\nfour\nfive\n";
        assert_eq!(tail_lines(text, 2), "four\nfive\n");
        assert_eq!(tail_lines(text, 10), "one\ntwo\nthree\nfour\nfive\n");
        assert_eq!(tail_lines("", 5), "");
    }

    #[test]
    fn filter_launchd_lines_matches_case_insensitively_and_caps_tail() {
        let sample = "2026-01-01 launchd[1]: something unrelated\n\
                      2026-01-01 launchd[1]: system/me.pansen.wgd.privileged spawned\n\
                      2026-01-01 launchd[1]: WGD exited\n";
        assert_eq!(
            filter_launchd_wgd_lines(sample, 1),
            "2026-01-01 launchd[1]: WGD exited\n"
        );
        assert_eq!(
            filter_launchd_wgd_lines(sample, 10),
            "2026-01-01 launchd[1]: system/me.pansen.wgd.privileged spawned\n\
             2026-01-01 launchd[1]: WGD exited\n"
        );
    }

    #[test]
    fn matching_log_files_filters_by_interface_and_privileged() {
        let dir = std::env::temp_dir().join(format!(
            "wgd-logs-test-{}-{:08x}",
            std::process::id(),
            rand::random::<u32>()
        ));
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("privileged.err.log"), "err\n").unwrap();
        fs::write(dir.join("privileged.out.log"), "out\n").unwrap();
        fs::write(dir.join("wg-1ce3a4a1.log"), "helper\n").unwrap();
        fs::write(dir.join("wg-1ce3a4a1.1.log"), "previous helper session\n").unwrap();
        fs::write(dir.join("ignore.txt"), "ignore\n").unwrap();

        let all = matching_log_files_in(&dir, None).unwrap();
        assert_eq!(all.len(), 4);
        assert!(all.contains(&dir.join("wg-1ce3a4a1.1.log")));

        // An explicit connection filter still selects just its current log.
        let helper = matching_log_files_in(&dir, Some("wg-1ce3a4a1")).unwrap();
        assert_eq!(helper, vec![dir.join("wg-1ce3a4a1.log")]);

        let priv_logs = matching_log_files_in(&dir, Some("privileged")).unwrap();
        assert_eq!(
            priv_logs,
            vec![
                dir.join("privileged.err.log"),
                dir.join("privileged.out.log")
            ]
        );

        fs::remove_dir_all(dir).unwrap();
    }
}
