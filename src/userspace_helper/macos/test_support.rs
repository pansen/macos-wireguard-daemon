use super::net::macos_network_base;
use super::net::parse_cidr;
use super::MacosDnsFingerprint;
use super::MacosReconcileInputs;
use std::net::IpAddr;

pub(super) fn subnet(value: &str) -> (IpAddr, u8) {
    let (ip, prefix) = parse_cidr(value).expect("valid cidr");
    (macos_network_base(ip, prefix), prefix)
}

pub(super) fn split_inputs() -> MacosReconcileInputs {
    MacosReconcileInputs {
        interface: "utun6".to_string(),
        endpoint: "23.88.101.22".parse().unwrap(),
        endpoint_is_ipv6: false,
        endpoint_needs_pin: false,
        allowed_ips: vec!["55.56.57.0/24".to_string(), "100.64.0.0/24".to_string()],
        dns_servers: vec!["100.64.1.1".to_string()],
        has_ipv4_address: true,
        has_ipv6_address: false,
        custody: None,
    }
}

pub(super) fn dns_fp(
    primary: Option<&str>,
    observed: &[(&str, Option<&[&str]>)],
) -> MacosDnsFingerprint {
    let observed: Vec<(String, Option<Vec<String>>)> = observed
        .iter()
        .map(|(svc, dns)| {
            (
                svc.to_string(),
                dns.map(|servers| servers.iter().map(|s| s.to_string()).collect()),
            )
        })
        .collect();
    let mut services: Vec<String> = observed.iter().map(|(s, _)| s.clone()).collect();
    services.sort();
    services.dedup();
    MacosDnsFingerprint {
        primary_service: primary.map(str::to_string),
        services,
        observed,
    }
}
