//! `wgd doctor`: one command that gathers what a bug report needs.
//!
//! Run without root, it re-invokes itself through `sudo` (the root child
//! prints the report to stdout, the unprivileged parent tees, redacts and
//! writes `--report <file>`, so root never opens a user-chosen path). When
//! `sudo` is unavailable or declined it falls back to the sections that work
//! unprivileged. Run directly under `sudo`, it builds the report itself.
//!
//! Every section is best-effort: an error is printed into its section and
//! the next one still runs.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Write as _};
use std::net::IpAddr;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::Context;
use nix::unistd::{geteuid, Gid, Uid};

use crate::privileged_api::ConnectionSummary;

/// Report sections, in output order. The launchd status report has to run
/// before anything connects to `ctl.sock`: connecting socket-activates the
/// daemon and would falsify its `state = not running` check.
const SECTIONS: [&str; 7] = [
    "header",
    "launchd status",
    "dns per network service",
    "wgd status",
    "reachability",
    "launchd log (last 10m)",
    "/var/log/wgd tails",
];

/// Lines of each `/var/log/wgd/*.log` and of the launchd unified log.
const LOG_LINES: usize = 60;

const SKIPPED_NEEDS_SUDO: &str = "skipped (needs sudo)\n";

pub fn dispatch(report: Option<PathBuf>, caller_in_wgd_group: Option<bool>) -> anyhow::Result<()> {
    // Created before the run so a taken file name fails right away instead
    // of after the password prompt and all the pings.
    let report_file = report
        .as_deref()
        .map(|path| create_report_file(path).map(|file| (path, file)))
        .transpose()?;

    if geteuid().is_root() {
        let text = build_report(true, caller_in_wgd_group);
        print!("{text}");
        // Directly under sudo `--report` is handled here; the escalated
        // child never receives it.
        if let Some((path, file)) = report_file {
            write_report_file(path, file, &text)?;
        }
        return Ok(());
    }

    // Capture this before escalating: the root child cannot see the
    // caller's shell groups.
    let in_group = crate::launchd::caller_has_wgd_gid_in_process();
    let text = match escalate_doctor(in_group) {
        Ok(text) => text,
        Err(e) => {
            tracing::warn!(error = %format!("{e:#}"), "doctor_escalation_failed");
            eprintln!("sudo unavailable or declined; running the unprivileged sections only");
            let text = build_report(false, Some(in_group));
            print!("{text}");
            text
        }
    };
    if let Some((path, file)) = report_file {
        write_report_file(path, file, &text)?;
    }
    Ok(())
}

/// Re-invoke `sudo <wgd> doctor`, teeing the child's stdout to the terminal
/// line by line while collecting it. Fails (so the caller falls back) when
/// `sudo` cannot run or exits non-zero without having produced a report.
fn escalate_doctor(caller_in_wgd_group: bool) -> anyhow::Result<String> {
    let exe = std::env::current_exe().context("failed to determine the running wgd binary path")?;
    let mut cmd = Command::new("sudo");
    cmd.arg(&exe);
    if crate::logging::debug_enabled() {
        cmd.arg("--debug");
    }
    cmd.args([
        "doctor",
        &format!("--caller-in-wgd-group={caller_in_wgd_group}"),
    ]);
    cmd.stdout(Stdio::piped());
    tracing::warn!(
        action = "doctor",
        method = "sudo",
        cause = "inspecting system launchd state, root-owned logs and runtime paths requires root",
        "admin_authentication_requested"
    );
    let mut child = cmd.spawn().context("failed to run sudo for wgd doctor")?;
    let stdout = child.stdout.take().context("sudo child has no stdout")?;

    let mut collected = Vec::new();
    let mut reader = BufReader::new(stdout);
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let mut term = std::io::stdout().lock();
                let _ = term.write_all(&line);
                let _ = term.flush();
                collected.extend_from_slice(&line);
            }
        }
    }
    let status = child.wait().context("failed to wait for sudo")?;
    let text = String::from_utf8_lossy(&collected).into_owned();
    if !status.success() {
        anyhow::ensure!(!text.is_empty(), "sudo wgd doctor failed ({status})");
        eprintln!("warning: sudo wgd doctor exited with {status}; the report may be incomplete");
    }
    Ok(text)
}

fn render_section(name: &str, body: &str) -> String {
    let mut out = format!("==> {name}\n");
    out.push_str(body);
    if !body.ends_with('\n') {
        out.push('\n');
    }
    out.push('\n');
    out
}

/// Build the whole report. `privileged` is false in the unprivileged
/// fallback, where root-only sections print `skipped (needs sudo)`.
fn build_report(privileged: bool, caller_in_wgd_group: Option<bool>) -> String {
    let mut out = String::new();
    // Listed by the `wgd status` section, consumed by `reachability`.
    let mut connections: Option<Vec<ConnectionSummary>> = None;
    for name in SECTIONS {
        let body = match name {
            "header" => header_section(),
            "launchd status" => crate::launchd::collect_status_report(caller_in_wgd_group),
            "dns per network service" => {
                let mut body = String::new();
                let mut diag = String::new();
                crate::status::render_service_dns(&mut body, &mut diag);
                body.push_str(&diag);
                body
            }
            "wgd status" => {
                let client = crate::privileged_client::PrivilegedClient::new();
                match crate::status::collect_status(&client) {
                    Ok(report) => {
                        let mut body = crate::status::render_status(&report);
                        for line in &report.diagnostics {
                            let _ = writeln!(body, "{line}");
                        }
                        connections = Some(report.connections);
                        body
                    }
                    Err(e) => format!("wgd status failed: {e:#}\n"),
                }
            }
            "reachability" => reachability_section(connections.as_deref()),
            "launchd log (last 10m)" if privileged => crate::logs::collect_launchd_logs(LOG_LINES),
            "/var/log/wgd tails" if privileged => crate::logs::collect_log_tails(LOG_LINES),
            _ => SKIPPED_NEEDS_SUDO.to_string(),
        };
        out.push_str(&render_section(name, &body));
    }
    out
}

fn run_capture(program: &str, args: &[&str]) -> String {
    match Command::new(program).args(args).output() {
        Ok(out) => String::from_utf8_lossy(&out.stdout).trim_end().to_string(),
        Err(e) => format!("failed to run {program}: {e}"),
    }
}

fn header_section() -> String {
    let mut out = String::new();
    let _ = writeln!(out, "wgd {}", env!("WGD_BUILD_LABEL"));
    let _ = writeln!(
        out,
        "date: {}",
        run_capture("/bin/date", &["+%Y-%m-%d %H:%M:%S %Z"])
    );
    let _ = writeln!(out, "sw_vers:");
    for line in run_capture("/usr/bin/sw_vers", &[]).lines() {
        let _ = writeln!(out, "  {line}");
    }
    let sudo_user = std::env::var("SUDO_USER").unwrap_or_else(|_| "-".to_string());
    let _ = writeln!(
        out,
        "uid: {} (euid {}), SUDO_USER: {sudo_user}",
        nix::unistd::getuid(),
        geteuid()
    );
    out
}

// ---------------------------------------------------------------------
// Reachability
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PingRole {
    Dns,
    HostRoute,
    Endpoint,
    InternetControl,
}

impl PingRole {
    fn label(self) -> &'static str {
        match self {
            PingRole::Dns => "dns server",
            PingRole::HostRoute => "peer host route",
            PingRole::Endpoint => "peer endpoint",
            PingRole::InternetControl => "internet control",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PingTarget {
    host: String,
    role: PingRole,
    /// The connection the target came from, for the report line.
    via: Option<String>,
}

/// The ping targets for all connected connections, deduplicated by address
/// (the first role that names an address wins), ending with the internet
/// control.
fn collect_ping_targets(connections: &[ConnectionSummary]) -> Vec<PingTarget> {
    let mut targets: Vec<PingTarget> = Vec::new();
    let mut add = |host: String, role: PingRole, via: Option<&str>| {
        if host.is_empty() || host.starts_with('-') || targets.iter().any(|t| t.host == host) {
            return;
        }
        targets.push(PingTarget {
            host,
            role,
            via: via.map(str::to_string),
        });
    };
    for conn in connections.iter().filter(|c| c.connected) {
        let via = conn.name.as_deref().unwrap_or(&conn.interface);
        for dns in &conn.dns_servers {
            add(dns.trim().to_string(), PingRole::Dns, Some(via));
        }
        for peer in &conn.peers {
            for allowed in &peer.allowed_ips {
                if let Some(host) = host_route(allowed) {
                    add(host, PingRole::HostRoute, Some(via));
                }
            }
            if let Some(endpoint) = &peer.endpoint {
                add(endpoint_host(endpoint), PingRole::Endpoint, Some(via));
            }
        }
    }
    add("1.1.1.1".to_string(), PingRole::InternetControl, None);
    targets
}

/// `a.b.c.d/32` or `x::y/128` (or a bare address) -> the address.
fn host_route(allowed_ip: &str) -> Option<String> {
    let allowed_ip = allowed_ip.trim();
    let (addr, prefix) = match allowed_ip.split_once('/') {
        Some((a, p)) => (a, Some(p.parse::<u8>().ok()?)),
        None => (allowed_ip, None),
    };
    let ip: IpAddr = addr.parse().ok()?;
    let full = if ip.is_ipv4() { 32 } else { 128 };
    (prefix.unwrap_or(full) == full).then(|| ip.to_string())
}

/// `host:port`, `[v6]:port` or a bare host -> the host without port.
fn endpoint_host(endpoint: &str) -> String {
    let endpoint = endpoint.trim();
    if let Some(rest) = endpoint.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest).to_string();
    }
    match endpoint.rsplit_once(':') {
        // A second colon means an unbracketed IPv6 literal without port.
        Some((host, port)) if !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) => {
            host.to_string()
        }
        _ => endpoint.to_string(),
    }
}

/// One ping, bounded to a few seconds regardless of the tool's own timeout.
fn ping(host: &str) -> bool {
    let (program, args): (&str, Vec<&str>) = if host.contains(':') {
        ("/sbin/ping6", vec!["-c1", host])
    } else {
        ("/sbin/ping", vec!["-c1", "-t2", host])
    };
    let Ok(mut child) = Command::new(program)
        .args(&args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_secs(4);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status.success(),
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(25)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return false;
            }
        }
    }
}

fn reachability_section(connections: Option<&[ConnectionSummary]>) -> String {
    let Some(connections) = connections else {
        return "no connection list available (daemon unreachable?); pinging the internet control only\n"
            .to_string()
            + &format_ping_lines(&collect_ping_targets(&[]));
    };
    if !connections.iter().any(|c| c.connected) {
        return format!(
            "no connected connections\n{}",
            format_ping_lines(&collect_ping_targets(&[]))
        );
    }
    format_ping_lines(&collect_ping_targets(connections))
}

fn format_ping_lines(targets: &[PingTarget]) -> String {
    let mut out = String::new();
    for target in targets {
        let ok = ping(&target.host);
        let via = target
            .via
            .as_deref()
            .map(|v| format!(" ({v})"))
            .unwrap_or_default();
        let role = target.role.label();
        let _ = match (ok, target.role) {
            (true, _) => writeln!(out, "ok    {}  {role}{via}", target.host),
            (false, PingRole::Endpoint) => writeln!(
                out,
                "info  {}  {role}{via}: no ICMP reply (many endpoints drop ICMP; see handshake in wg show)",
                target.host
            ),
            (false, _) => writeln!(out, "FAIL  {}  {role}{via}", target.host),
        };
    }
    out
}

// ---------------------------------------------------------------------
// Report file
// ---------------------------------------------------------------------

/// Create the report file, refusing to touch an existing one. Under direct
/// `sudo` it is handed to the invoking user.
fn create_report_file(path: &Path) -> anyhow::Result<std::fs::File> {
    let owner = if geteuid().is_root() {
        let uid = std::env::var("SUDO_UID")
            .ok()
            .and_then(|v| v.parse::<u32>().ok());
        let gid = std::env::var("SUDO_GID")
            .ok()
            .and_then(|v| v.parse::<u32>().ok());
        uid.map(|u| (Uid::from_raw(u), gid.map(Gid::from_raw)))
    } else {
        None
    };

    let file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(nix::libc::O_NOFOLLOW)
        .mode(0o600)
        .open(path)
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                anyhow::anyhow!(
                    "{} already exists; refusing to overwrite it (choose a new file name)",
                    path.display()
                )
            } else {
                anyhow::Error::new(e).context(format!("failed to create {}", path.display()))
            }
        })?;
    if let Some((uid, gid)) = owner {
        nix::unistd::fchown(file.as_raw_fd(), Some(uid), gid)
            .with_context(|| format!("failed to chown {} to the invoking user", path.display()))?;
    }
    Ok(file)
}

/// Redact `report` and write it into the file [`create_report_file`] opened.
fn write_report_file(path: &Path, mut file: std::fs::File, report: &str) -> anyhow::Result<()> {
    let text = redact_report(&strip_ansi(report));
    file.write_all(text.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;

    println!("report written to {}", path.display());
    println!(
        "Only the report file is redacted and safe to attach publicly; the terminal output above is not."
    );
    Ok(())
}

/// Remove ANSI escape sequences (CSI and OSC) from `text`.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some('[') => {
                chars.next();
                // Parameters and intermediates, then one final byte.
                for n in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&n) {
                        break;
                    }
                }
            }
            Some(']') => {
                chars.next();
                // Up to BEL or ESC \.
                while let Some(n) = chars.next() {
                    if n == '\u{7}' {
                        break;
                    }
                    if n == '\u{1b}' {
                        chars.next();
                        break;
                    }
                }
            }
            Some(_) => {
                chars.next();
            }
            None => {}
        }
    }
    out
}

// ---------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------

/// TLDs a hostname must end in to be masked. A closed list keeps dotted
/// identifiers, file names and launchd labels readable.
const TLDS: &[&str] = &[
    "com", "net", "org", "io", "de", "me", "dev", "cloud", "info", "eu", "uk", "us", "fr", "nl",
    "ch", "at", "ru", "cn", "jp", "xyz", "vpn", "biz", "co", "ai", "se", "no", "fi", "it", "es",
    "pl", "cz", "ca", "au", "tv", "cc", "ws", "online", "site", "tech", "link", "network",
    "systems", "local", "lan", "home", "internal", "edu", "gov", "be", "dk", "pt", "gr", "hu",
    "ro", "ua", "kr", "br", "mx", "nz", "za", "sg", "hk", "tk", "top", "club", "pro", "host", "pw",
    "one", "ninja", "fun", "store", "space", "live", "email", "world",
];

/// Mask the sensitive parts of a report so it can be shared publicly while
/// staying correlatable: private keys are removed, public IPs keep their
/// outer octets/hextets, public keys and hostnames keep their ends. Private
/// and tunnel address ranges, paths and module names are left alone.
pub fn redact_report(text: &str) -> String {
    text.split('\n')
        .map(redact_line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn redact_line(line: &str) -> String {
    let line = redact_secret_values(line);
    // Reachability lines (`ok    <host>  peer endpoint ...`) always name an
    // endpoint, even when the hostname uses a TLD outside `TLDS`.
    let line_has_peer_endpoint = line.contains("  peer endpoint");
    let mut out = String::with_capacity(line.len());
    let mut token = String::new();
    let mut next_is_endpoint = false;
    for c in line.chars() {
        if is_token_char(c) {
            token.push(c);
        } else {
            if !token.is_empty() {
                let is_ep_label = matches!(
                    token.to_ascii_lowercase().as_str(),
                    "endpoint:" | "endpoint="
                );
                out.push_str(&redact_token_with_context(
                    &token,
                    next_is_endpoint || line_has_peer_endpoint,
                ));
                next_is_endpoint = is_ep_label;
                token.clear();
            }
            out.push(c);
        }
    }
    if !token.is_empty() {
        out.push_str(&redact_token_with_context(
            &token,
            next_is_endpoint || line_has_peer_endpoint,
        ));
    }
    out
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(c, '.' | ':' | '-' | '_' | '/' | '%' | '+' | '=' | '[' | ']')
}

/// Replace the value following a private/preshared key label.
fn redact_secret_values(line: &str) -> String {
    const LABELS: [&str; 6] = [
        "privatekey",
        "private key",
        "private_key",
        "presharedkey",
        "preshared key",
        "preshared_key",
    ];
    // ASCII lowercasing keeps byte offsets, so indices carry over.
    let lower = line.to_ascii_lowercase();
    let mut out = String::new();
    let mut pos = 0;
    while pos < line.len() {
        let next = LABELS
            .iter()
            .filter_map(|l| lower[pos..].find(l).map(|i| (pos + i, l.len())))
            .min();
        let Some((start, len)) = next else { break };
        let label_end = start + len;
        let rest = &line[label_end..];
        let sep = rest
            .find(|c: char| !matches!(c, ' ' | '\t' | '=' | ':' | '"' | '\''))
            .unwrap_or(rest.len());
        let value_start = label_end + sep;
        let value_len = line[value_start..]
            .find(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ','))
            .unwrap_or(line.len() - value_start);
        let value = &line[value_start..value_start + value_len];
        let is_flag = matches!(
            value,
            "true" | "false" | "yes" | "no" | "none" | "<redacted>"
        );
        out.push_str(&line[pos..value_start]);
        if sep > 0 && !value.is_empty() && !is_flag {
            out.push_str("<redacted>");
        } else {
            out.push_str(value);
        }
        pos = value_start + value_len;
    }
    out.push_str(&line[pos..]);
    out
}

fn redact_token_with_context(token: &str, endpoint_context: bool) -> String {
    // `key=value`: keep the key, treat the value as its own token.
    if let Some(i) = token.find('=') {
        if i + 1 < token.len() && !is_wg_key(token) {
            let key = &token[..i];
            let is_ep = key.eq_ignore_ascii_case("endpoint");
            return format!(
                "{}{}",
                &token[..=i],
                redact_token_with_context(&token[i + 1..], endpoint_context || is_ep)
            );
        }
    }
    if is_wg_key(token) {
        let stars = "*".repeat(token.len() - 8);
        return format!("{}{stars}{}", &token[..4], &token[token.len() - 4..]);
    }
    let core = token.trim_end_matches('.');
    let trail = &token[core.len()..];
    if let Some(masked) = mask_ip_token(core).or_else(|| mask_domain_token(core, endpoint_context))
    {
        return format!("{masked}{trail}");
    }
    // Unquoted bracketed lists (`allowed_ips=[203.0.113.42/32, 198.51.100.7/32]`,
    // `[vpn.example.com:51820]`): strip outer `[` / `]` and retry so `[` and `]`
    // in `is_token_char` (kept for `[v6]:port`) don't shield list elements.
    let inner = core.trim_start_matches('[').trim_end_matches(']');
    if inner.len() != core.len() && !inner.is_empty() {
        let lead_len = core.len() - core.trim_start_matches('[').len();
        let end_pos = lead_len + inner.len();
        let lead = &core[..lead_len];
        let close = &core[end_pos..];
        if let Some(masked) =
            mask_ip_token(inner).or_else(|| mask_domain_token(inner, endpoint_context))
        {
            return format!("{lead}{masked}{close}{trail}");
        }
    }
    token.to_string()
}

/// A 44-character base64 string ending in `=` (a WireGuard key).
fn is_wg_key(s: &str) -> bool {
    s.len() == 44
        && s.ends_with('=')
        && s[..43]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// IPv4/IPv6 with optional `[ ]`, `:port`, `%zone` and `/prefix`.
fn mask_ip_token(core: &str) -> Option<String> {
    if let Some(rest) = core.strip_prefix('[') {
        let (inner, after) = rest.split_once(']')?;
        let masked = mask_ip_addr(inner)?;
        return Some(format!("[{masked}]{after}"));
    }
    let (addr, cidr) = match core.split_once('/') {
        Some((a, c)) if !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit()) => {
            (a, format!("/{c}"))
        }
        Some(_) => return None,
        None => (core, String::new()),
    };
    let (addr, zone) = match addr.split_once('%') {
        Some((a, z)) => (a, format!("%{z}")),
        None => (addr, String::new()),
    };
    // IPv4 with a port.
    let (addr, port) = match addr.rsplit_once(':') {
        Some((a, p))
            if a.contains('.') && !a.contains(':') && p.bytes().all(|b| b.is_ascii_digit()) =>
        {
            (a, format!(":{p}"))
        }
        _ => (addr, String::new()),
    };
    let masked = mask_ip_addr(addr)?;
    Some(format!("{masked}{port}{zone}{cidr}"))
}

fn mask_ip_addr(addr: &str) -> Option<String> {
    if let Ok(v4) = addr.parse::<std::net::Ipv4Addr>() {
        // Well-known public resolvers (the internet control ping) say
        // nothing about the user, and masking them hides the control.
        let well_known = ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"];
        if !is_public_v4(v4) || well_known.contains(&addr) {
            return Some(addr.to_string());
        }
        let o = v4.octets();
        return Some(format!("{}.*.*.{}", o[0], o[3]));
    }
    let v6 = addr.parse::<std::net::Ipv6Addr>().ok()?;
    let first = v6.segments()[0];
    let keep = v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || (first & 0xffc0) == 0xfe80
        || (first & 0xfe00) == 0xfc00;
    if keep {
        return Some(addr.to_string());
    }
    // Embedded IPv4 tail (`::ffff:1.2.3.4`): mask it as IPv4.
    if let Some((head, tail)) = addr.rsplit_once(':') {
        if tail.contains('.') {
            let tail = mask_ip_addr(tail)?;
            return Some(format!("{head}:{tail}"));
        }
    }
    // Keep the first and last group as written, star out the groups between
    // while preserving the colons.
    let first_end = addr.find(':').unwrap_or(addr.len());
    let last_start = addr.rfind(':').map_or(0, |i| i + 1).max(first_end);
    let middle: String = addr[first_end..last_start]
        .chars()
        .map(|c| if c == ':' { ':' } else { '*' })
        .collect();
    Some(format!(
        "{}{middle}{}",
        &addr[..first_end],
        &addr[last_start..]
    ))
}

fn is_public_v4(ip: std::net::Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.is_multicast()
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || o[0] >= 240)
}

/// A hostname ending in a known TLD (or any alphabetic TLD when in an explicit
/// `endpoint` context), with an optional `:port`.
fn mask_domain_token(core: &str, allow_any_tld: bool) -> Option<String> {
    let (host, port) = match core.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
            (h, format!(":{p}"))
        }
        _ => (core, String::new()),
    };
    if host.contains(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '-')) {
        return None;
    }
    // wgd's own launchd labels (`me.pansen.wgd.privileged`).
    if host.starts_with("me.pansen.wgd") {
        return None;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    if labels
        .iter()
        .any(|l| l.is_empty() || l.starts_with('-') || l.ends_with('-'))
    {
        return None;
    }
    let tld = labels[labels.len() - 1].to_ascii_lowercase();
    let valid_tld = if allow_any_tld {
        tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())
    } else {
        TLDS.contains(&tld.as_str())
    };
    if !valid_tld {
        return None;
    }
    let n = host.len();
    Some(format!(
        "{}{}{}{port}",
        &host[..1],
        "*".repeat(n - 2),
        &host[n - 1..]
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::privileged_api::{ConnectionId, ConnectionStartMode, PeerSummary};

    fn conn(connected: bool, dns: &[&str], peers: Vec<PeerSummary>) -> ConnectionSummary {
        ConnectionSummary {
            id: ConnectionId::new(),
            global: false,
            owner_uid: Some(501),
            start_mode: ConnectionStartMode::Manual,
            name: Some("home".to_string()),
            interface: "wg-test".to_string(),
            connected,
            user_disconnected: false,
            addresses: vec![],
            dns_servers: dns.iter().map(|s| s.to_string()).collect(),
            mtu: None,
            peers,
            fingerprint: None,
            source_path: None,
            created_at: 0,
            updated_at: 0,
        }
    }

    fn peer(allowed: &[&str], endpoint: Option<&str>) -> PeerSummary {
        PeerSummary {
            public_key: "k".to_string(),
            allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
            endpoint: endpoint.map(str::to_string),
            has_preshared_key: false,
        }
    }

    #[test]
    fn ping_targets_dedupe_and_filter_host_routes() {
        let a = conn(
            true,
            &["10.0.0.1", "fd00::1"],
            vec![peer(
                &[
                    "10.0.0.1/32",
                    "192.168.1.0/24",
                    "10.9.0.5/32",
                    "fd00::7/128",
                    "0.0.0.0/0",
                    "::/0",
                ],
                Some("203.0.113.9:51820"),
            )],
        );
        let b = conn(
            true,
            &["10.0.0.1"],
            vec![peer(&["10.9.0.5/32"], Some("[2001:db8::1]:51820"))],
        );
        let off = conn(
            false,
            &["10.77.0.1"],
            vec![peer(&["10.77.0.2/32"], Some("1.2.3.4:1"))],
        );
        let targets = collect_ping_targets(&[a, off, b]);
        let hosts: Vec<&str> = targets.iter().map(|t| t.host.as_str()).collect();
        assert_eq!(
            hosts,
            [
                "10.0.0.1",
                "fd00::1",
                "10.9.0.5",
                "fd00::7",
                "203.0.113.9",
                "2001:db8::1",
                "1.1.1.1"
            ]
        );
        assert_eq!(targets[0].role, PingRole::Dns);
        assert_eq!(targets[2].role, PingRole::HostRoute);
        assert_eq!(targets[4].role, PingRole::Endpoint);
        assert_eq!(targets.last().unwrap().role, PingRole::InternetControl);
    }

    #[test]
    fn ping_targets_without_connections_is_only_control() {
        let targets = collect_ping_targets(&[]);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "1.1.1.1");
    }

    #[test]
    fn endpoint_host_variants() {
        assert_eq!(endpoint_host("vpn.example.com:51820"), "vpn.example.com");
        assert_eq!(endpoint_host("[2001:db8::1]:51820"), "2001:db8::1");
        assert_eq!(endpoint_host("1.2.3.4:5"), "1.2.3.4");
        assert_eq!(endpoint_host("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn section_order_runs_launchd_before_daemon_contact() {
        let pos = |n: &str| SECTIONS.iter().position(|s| *s == n).unwrap();
        assert_eq!(SECTIONS[0], "header");
        assert!(pos("launchd status") < pos("wgd status"));
        assert!(pos("launchd status") < pos("dns per network service"));
        assert!(pos("wgd status") < pos("reachability"));
        assert_eq!(*SECTIONS.last().unwrap(), "/var/log/wgd tails");
        assert_eq!(render_section("x", "a"), "==> x\na\n\n");
    }

    #[test]
    fn strips_ansi() {
        let s = "\u{1b}[2m2026\u{1b}[0m \u{1b}[32m INFO\u{1b}[0m ok\u{1b}]0;title\u{7}!";
        assert_eq!(strip_ansi(s), "2026  INFO ok!");
    }

    #[test]
    fn redacts_private_and_preshared_keys() {
        let key = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/abcde=";
        assert_eq!(key.len(), 44);
        assert_eq!(
            redact_report(&format!("PrivateKey = {key}")),
            "PrivateKey = <redacted>"
        );
        assert_eq!(
            redact_report(&format!("private key: {key}\npreshared key: (hidden)")),
            "private key: <redacted>\npreshared key: <redacted>"
        );
        assert_eq!(
            redact_report(&format!("PresharedKey={key}")),
            "PresharedKey=<redacted>"
        );
        assert_eq!(
            redact_report("has_preshared_key=true"),
            "has_preshared_key=true"
        );
    }

    #[test]
    fn masks_public_keys() {
        let key = "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/abcde=";
        let out = redact_report(&format!("  peer: {key}"));
        assert_eq!(out, format!("  peer: aBcD{}cde=", "*".repeat(36)));
    }

    #[test]
    fn masks_public_ips_keeps_private_ranges() {
        assert_eq!(
            redact_report("endpoint: 203.0.113.42:51820"),
            "endpoint: 203.*.*.42:51820"
        );
        assert_eq!(
            redact_report("endpoint=23.88.101.22 x"),
            "endpoint=23.*.*.22 x"
        );
        assert_eq!(
            redact_report("endpoint: [2001:db8:1:2::42]:51820"),
            "endpoint: [2001:***:*:*::42]:51820"
        );
        assert_eq!(redact_report("2001:db8::1"), "2001:***::1");
        for keep in [
            "10.66.77.0/24",
            "172.16.0.1",
            "192.168.188.1",
            "100.64.1.0/24",
            "127.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "255.255.255.255",
            "255.255.255.0",
            "192.0.0.2/32",
            "::1",
            "fe80::%utun2",
            "fe80::1%lo0",
            "fd7d:76ee:e68f:a993::1",
            "ff00::/8",
            "fe80::882:6d9b:20a0:49b8%en0",
        ] {
            assert_eq!(redact_report(keep), keep);
        }
        assert_eq!(redact_report("a 1.1.1.1."), "a 1.1.1.1.");
        assert_eq!(redact_report("a 1.2.3.4."), "a 1.*.*.4.");
        assert_eq!(redact_report("::ffff:8.8.4.5"), "::ffff:8.*.*.5");
    }

    #[test]
    fn masks_hostnames_but_not_paths_or_modules() {
        assert_eq!(
            redact_report("endpoint: vpn.example.com:51820"),
            "endpoint: v*************m:51820"
        );
        // Unlisted TLDs are still masked in explicit endpoint contexts
        // (`endpoint:`, `endpoint=`, reachability `peer endpoint`).
        assert_eq!(
            redact_report("  endpoint: gw.corp.ovh:51820"),
            "  endpoint: g*********h:51820"
        );
        assert_eq!(
            redact_report("endpoint=gw.corp.hetzner:51820"),
            "endpoint=g*************r:51820"
        );
        assert_eq!(
            redact_report("info  gw.corp.ovh  peer endpoint (home): no ICMP reply"),
            "info  g*********h  peer endpoint (home): no ICMP reply"
        );
        // Unquoted bracketed lists (`allowed_ips=[...]`) still mask public IPs
        // and hostnames at the list boundaries.
        assert_eq!(
            redact_report("allowed_ips=[203.0.113.42/32, 10.0.0.1/32, 198.51.100.7/32]"),
            "allowed_ips=[203.*.*.42/32, 10.0.0.1/32, 198.*.*.7/32]"
        );
        for keep in [
            "/var/log/wgd/wg-ca40dce0.log",
            "wgd::privileged",
            "wgd::privileged::commands:",
            "me.pansen.wgd.session-agent",
            "me.pansen.wgd.privileged",
            "ctl.sock",
            "main.rs",
            "Cargo.toml",
            "Xcode.app",
            "2026-10-21T09:53:07Z",
            "12:02:28.377939+0200",
            "e.g.",
            "version 0.3.1",
            "82:a:f7:ef:36:dd",
        ] {
            assert_eq!(redact_report(keep), keep);
        }
    }

    #[test]
    fn real_log_lines_stay_readable() {
        let line = "interface=utun4 endpoint=23.88.101.22 endpoint_pin=disabled gateway=none local_subnets=192.0.0.2/32, 2a01:599:80a:ab63::/64";
        assert_eq!(
            redact_report(line),
            "interface=utun4 endpoint=23.*.*.22 endpoint_pin=disabled gateway=none local_subnets=192.0.0.2/32, 2a01:***:***:****::/64"
        );
        let launchd = "2026-10-21 12:02:01.671897+0200 0xde3      Default     0x0                  1      0    launchd: [gui/503 [100020]:] pending spawn, domain in on-demand-only mode: me.pansen.wgd.session-agent";
        assert_eq!(redact_report(launchd), launchd);
        let ctl = "  srw-rw----  root:wgd  /Library/Application Support/wgd/run/ctl.sock";
        assert_eq!(redact_report(ctl), ctl);
        assert_eq!(
            redact_report(
                "  endpoint: 23.88.101.22:51821\n  allowed ips: 10.66.77.0/24, 100.64.1.0/24"
            ),
            "  endpoint: 23.*.*.22:51821\n  allowed ips: 10.66.77.0/24, 100.64.1.0/24"
        );
    }
}
