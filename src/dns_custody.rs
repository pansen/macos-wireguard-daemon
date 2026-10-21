//! On-disk DNS custody records (see `issues/dns-crash-recovery.md`).
//!
//! The userspace helper writes one record per DNS-promoting connection before
//! it touches a service's DNS, and deletes it after teardown restored every
//! service. The privileged daemon reads the records of dead helpers and
//! restores the recorded originals. Both sides share this one schema.
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::privileged::managed_pids::ProcessStart;
use crate::privileged_api::ConnectionId;

/// Schema version written by this build. Bump when the layout changes; readers
/// skip (and keep) records with a version they do not know.
pub const DNS_CUSTODY_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsCustodyRecord {
    pub version: u32,
    /// Full connection id, from `WGD_CONNECTION_ID`.
    pub connection_id: ConnectionId,
    /// Control interface name (`wg-<id8>`), also the file name.
    pub interface: String,
    pub helper_pid: u32,
    /// Start time of `helper_pid`; pins the pid to one process instance.
    pub helper_start: ProcessStart,
    /// Exactly what was written with `-setdnsservers`.
    pub tunnel_dns: Vec<String>,
    pub services: Vec<DnsCustodyService>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsCustodyService {
    pub service: String,
    /// `None` means Empty (DHCP).
    pub original_dns_servers: Option<Vec<String>>,
    /// `None` means Empty.
    pub original_search_domains: Option<Vec<String>>,
}

/// Who a helper is, as far as the custody record is concerned. Built once at
/// helper startup and carried in the reconcile inputs.
#[derive(Debug, Clone)]
pub struct DnsCustodyIdentity {
    pub connection_id: ConnectionId,
    pub interface: String,
    pub helper_pid: u32,
    pub helper_start: ProcessStart,
}

impl DnsCustodyIdentity {
    #[must_use]
    pub fn record(
        &self,
        tunnel_dns: &[String],
        services: Vec<DnsCustodyService>,
    ) -> DnsCustodyRecord {
        DnsCustodyRecord {
            version: DNS_CUSTODY_VERSION,
            connection_id: self.connection_id,
            interface: self.interface.clone(),
            helper_pid: self.helper_pid,
            helper_start: self.helper_start,
            tunnel_dns: tunnel_dns.to_vec(),
            services,
        }
    }
}

/// Result of reading one record file.
#[derive(Debug, PartialEq, Eq)]
pub enum RecordRead {
    Record(DnsCustodyRecord),
    /// Written by a newer build. Not corrupt: leave it alone.
    UnsupportedVersion(u32),
    Corrupt(String),
}

pub fn parse_record(raw: &[u8]) -> RecordRead {
    let value: serde_json::Value = match serde_json::from_slice(raw) {
        Ok(value) => value,
        Err(error) => return RecordRead::Corrupt(error.to_string()),
    };
    match value.get("version").and_then(serde_json::Value::as_u64) {
        Some(version) if version == u64::from(DNS_CUSTODY_VERSION) => {}
        Some(version) => {
            return RecordRead::UnsupportedVersion(version.min(u64::from(u32::MAX)) as u32)
        }
        None => return RecordRead::Corrupt("missing version".into()),
    }
    match serde_json::from_value::<DnsCustodyRecord>(value) {
        Ok(record) => RecordRead::Record(record),
        Err(error) => RecordRead::Corrupt(error.to_string()),
    }
}

pub fn read_record(path: &Path) -> io::Result<RecordRead> {
    Ok(parse_record(&std::fs::read(path)?))
}

/// `dns-custody/<interface>.json`. Rejects names that could leave the directory.
pub fn record_path(interface: &str) -> io::Result<PathBuf> {
    if interface.is_empty() || interface.contains('/') || interface.starts_with('.') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid interface name for a DNS custody record",
        ));
    }
    Ok(crate::config::dns_custody_dir().join(format!("{interface}.json")))
}

/// Write the record durably. The directory must already exist: only the
/// privileged daemon creates it.
pub fn write_record(record: &DnsCustodyRecord) -> io::Result<()> {
    let path = record_path(&record.interface)?;
    let json = serde_json::to_vec(record).map_err(io::Error::other)?;
    crate::state_file::write_atomic(&path, &json)
}

pub fn remove_record(interface: &str) -> io::Result<()> {
    crate::state_file::remove_durable(&record_path(interface)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DnsCustodyRecord {
        DnsCustodyRecord {
            version: DNS_CUSTODY_VERSION,
            connection_id: ConnectionId::new(),
            interface: "wg-1ce3a4a1".into(),
            helper_pid: 4242,
            helper_start: ProcessStart { sec: 10, usec: 20 },
            tunnel_dns: vec!["10.66.77.2".into(), "100.64.1.1".into()],
            services: vec![
                DnsCustodyService {
                    service: "Wi-Fi".into(),
                    original_dns_servers: Some(vec!["192.168.1.1".into()]),
                    original_search_domains: Some(vec!["lan".into()]),
                },
                DnsCustodyService {
                    service: "Ethernet".into(),
                    original_dns_servers: None,
                    original_search_domains: Some(Vec::new()),
                },
            ],
        }
    }

    #[test]
    fn record_round_trips_and_keeps_none_distinct_from_empty() {
        let record = sample();
        let json = serde_json::to_vec(&record).unwrap();
        match parse_record(&json) {
            RecordRead::Record(read) => {
                assert_eq!(read, record);
                assert_eq!(read.services[1].original_dns_servers, None);
                assert_eq!(read.services[1].original_search_domains, Some(Vec::new()));
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn unknown_future_version_is_skipped_not_corrupt() {
        let mut value = serde_json::to_value(sample()).unwrap();
        value["version"] = serde_json::json!(2);
        value["something_new"] = serde_json::json!(true);
        let json = serde_json::to_vec(&value).unwrap();
        assert_eq!(parse_record(&json), RecordRead::UnsupportedVersion(2));
    }

    #[test]
    fn garbage_and_missing_version_are_corrupt() {
        assert!(matches!(parse_record(b"not json"), RecordRead::Corrupt(_)));
        assert!(matches!(parse_record(b"{}"), RecordRead::Corrupt(_)));
        assert!(matches!(
            parse_record(br#"{"version":1,"interface":"x"}"#),
            RecordRead::Corrupt(_)
        ));
    }

    #[test]
    fn record_path_rejects_traversal() {
        assert!(record_path("../x").is_err());
        assert!(record_path("a/b").is_err());
        assert!(record_path("").is_err());
        assert!(record_path("wg-1ce3a4a1")
            .unwrap()
            .ends_with("dns-custody/wg-1ce3a4a1.json"));
    }
}
