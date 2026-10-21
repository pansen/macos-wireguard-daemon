//! `networksetup` DNS primitives shared by the userspace helper (which applies
//! tunnel DNS) and the privileged daemon (which sweeps it after a helper
//! crash). One implementation, so both sides run the same trusted binary and
//! parse the output the same way.
use std::net::IpAddr;
use std::process::Output;

use anyhow::Context;
use tracing::{debug, trace, warn};

pub fn list_network_services() -> anyhow::Result<Vec<String>> {
    let output = run_networksetup_capture(&["-listallnetworkservices"])?;
    if !output.status.success() {
        anyhow::bail!("networksetup -listallnetworkservices failed");
    }
    Ok(parse_network_services(&String::from_utf8_lossy(
        &output.stdout,
    )))
}

fn parse_network_services(text: &str) -> Vec<String> {
    let mut services = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("An asterisk") {
            continue;
        }
        let service = trimmed.strip_prefix('*').map(str::trim).unwrap_or(trimmed);
        if !service.is_empty() {
            services.push(service.to_string());
        }
    }
    services
}

/// Whether a service's live DNS equals an expected tunnel DNS list. The one
/// comparison behind every "this looks like a stray" decision:
///
/// * `None` (nothing set) never equals a list, and `expected` is never empty.
/// * Entries compare as addresses, so `fd00::1` equals `fd00:0:0:0:0:0:0:1`.
///   An entry that does not parse makes the result false, the conservative
///   direction (no action).
/// * Order matters: `networksetup` returns servers in the order they were
///   set, so a reordered list was edited by someone else.
/// * Strict subsets and supersets are not equal.
#[must_use]
pub fn dns_lists_equal(live: Option<&[String]>, expected: &[String]) -> bool {
    let Some(live) = live else {
        return false;
    };
    if expected.is_empty() || live.len() != expected.len() {
        return false;
    }
    live.iter().zip(expected).all(|(a, b)| {
        match (a.trim().parse::<IpAddr>(), b.trim().parse::<IpAddr>()) {
            (Ok(a), Ok(b)) => a == b,
            _ => false,
        }
    })
}

pub fn get_dns_servers(service: &str) -> anyhow::Result<Option<Vec<String>>> {
    get_networksetup_values(service, "-getdnsservers", "DNS Servers")
}

pub fn get_search_domains(service: &str) -> anyhow::Result<Option<Vec<String>>> {
    get_networksetup_values(service, "-getsearchdomains", "Search Domains")
}

fn get_networksetup_values(
    service: &str,
    flag: &str,
    value_label: &str,
) -> anyhow::Result<Option<Vec<String>>> {
    let output = run_networksetup_capture(&[flag, service])?;
    if !output.status.success() {
        anyhow::bail!("networksetup {} {} failed", flag, service);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let marker = format!("There aren't any {} set", value_label);
    if stdout.lines().any(|line| line.contains(&marker)) {
        return Ok(None);
    }

    let values: Vec<String> = stdout
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect();

    if values.is_empty() || values == ["Empty".to_string()] {
        Ok(None)
    } else {
        Ok(Some(values))
    }
}

pub fn set_dns_servers(service: &str, dns_servers: &[String]) -> anyhow::Result<()> {
    let mut args: Vec<&str> = Vec::with_capacity(2 + dns_servers.len());
    args.push("-setdnsservers");
    args.push(service);
    args.extend(dns_servers.iter().map(String::as_str));
    run_networksetup(&args)
}

pub fn set_dns_servers_empty(service: &str) -> anyhow::Result<()> {
    run_networksetup(&["-setdnsservers", service, "Empty"])
}

pub fn set_search_domains(service: &str, domains: &[String]) -> anyhow::Result<()> {
    let mut args: Vec<&str> = Vec::with_capacity(2 + domains.len());
    args.push("-setsearchdomains");
    args.push(service);
    args.extend(domains.iter().map(String::as_str));
    run_networksetup(&args)
}

pub fn set_search_domains_empty(service: &str) -> anyhow::Result<()> {
    run_networksetup(&["-setsearchdomains", service, "Empty"])
}

/// Flush the resolver caches so restored DNS takes effect immediately.
/// Best effort: a failure only delays the effect until the caches expire.
pub fn flush_resolver_cache() {
    for (name, args) in [
        ("dscacheutil", &["-flushcache"][..]),
        ("killall", &["-HUP", "mDNSResponder"][..]),
    ] {
        let result =
            crate::trusted_exec::command(name).and_then(|mut command| command.args(args).output());
        match result {
            Ok(output) if output.status.success() => {}
            Ok(output) => warn!(
                command = name,
                status = %output.status,
                stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                "macos_dns_flush_failed"
            ),
            Err(error) => warn!(command = name, error = %error, "macos_dns_flush_failed"),
        }
    }
}

/// Put a service back to a recorded original. `None` means Empty (DHCP).
pub fn restore_service(
    service: &str,
    dns_servers: Option<&[String]>,
    search_domains: Option<&[String]>,
) -> anyhow::Result<()> {
    match dns_servers {
        Some(servers) => set_dns_servers(service, servers)?,
        None => set_dns_servers_empty(service)?,
    }
    match search_domains {
        Some(domains) => set_search_domains(service, domains)?,
        None => set_search_domains_empty(service)?,
    }
    Ok(())
}

fn run_networksetup(args: &[&str]) -> anyhow::Result<()> {
    let output = run_networksetup_capture(args)?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let detail = if !stderr.is_empty() { stderr } else { stdout };
    anyhow::bail!("networksetup {} failed: {}", args.join(" "), detail);
}

fn run_networksetup_capture(args: &[&str]) -> anyhow::Result<Output> {
    trace!(command = %format!("networksetup {}", args.join(" ")), "macos_dns_command");
    let output = crate::trusted_exec::command("networksetup")?
        .args(args)
        .output()
        .with_context(|| format!("failed to run networksetup {}", args.join(" ")))?;
    if !output.status.success() {
        debug!(
            command = %format!("networksetup {}", args.join(" ")),
            status = %output.status,
            stdout = %String::from_utf8_lossy(&output.stdout).trim(),
            stderr = %String::from_utf8_lossy(&output.stderr).trim(),
            "macos_dns_command_failed"
        );
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list(items: &[&str]) -> Vec<String> {
        items.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn dns_lists_equal_requires_a_set_list() {
        let expected = list(&["10.66.77.2", "100.64.1.1"]);
        assert!(!dns_lists_equal(None, &expected));
        assert!(dns_lists_equal(Some(&expected), &expected));
        assert!(!dns_lists_equal(Some(&[]), &[]));
        assert!(!dns_lists_equal(None, &[]));
    }

    #[test]
    fn dns_lists_equal_compares_addresses_not_spellings() {
        assert!(dns_lists_equal(
            Some(&list(&["fd00:0:0:0:0:0:0:1"])),
            &list(&["fd00::1"])
        ));
        assert!(!dns_lists_equal(
            Some(&list(&["fd00::2"])),
            &list(&["fd00::1"])
        ));
    }

    #[test]
    fn dns_lists_equal_is_ordered_and_exact() {
        let expected = list(&["10.0.0.1", "10.0.0.2"]);
        assert!(!dns_lists_equal(
            Some(&list(&["10.0.0.2", "10.0.0.1"])),
            &expected
        ));
        assert!(!dns_lists_equal(Some(&list(&["10.0.0.1"])), &expected));
        assert!(!dns_lists_equal(
            Some(&list(&["10.0.0.1", "10.0.0.2", "10.0.0.3"])),
            &expected
        ));
    }

    #[test]
    fn dns_lists_equal_rejects_unparseable_entries() {
        assert!(!dns_lists_equal(
            Some(&list(&["not-an-ip"])),
            &list(&["not-an-ip"])
        ));
    }

    #[test]
    fn network_service_listing_skips_header_and_strips_disabled_marker() {
        let text = "An asterisk (*) denotes that a network service is disabled.\nWi-Fi\n*Thunderbolt Bridge\n\n";
        assert_eq!(
            parse_network_services(text),
            vec!["Wi-Fi".to_string(), "Thunderbolt Bridge".to_string()]
        );
    }
}
