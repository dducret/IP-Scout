//! Portable scan records and deliberately conservative comparisons.
//! A missing reply or banner never proves that a device or service is offline.
use crate::{
    fetchers::Fetcher,
    scanner::{HostResult, HostStatus},
    targets::TargetRange,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::Ipv4Addr,
    path::Path,
};

pub const SCHEMA_VERSION: u32 = 1;
pub const MAX_SNAPSHOT_BYTES: u64 = 128 * 1024 * 1024;
const MAX_HOSTS: usize = 65_536;
const MAX_STRING_BYTES: usize = 16_384;
const MAX_HOST_STRING_BYTES: usize = 65_536;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanSnapshot {
    pub schema_version: u32,
    pub recorded_unix_secs: u64,
    pub app_version: String,
    pub label: String,
    pub target_text: String,
    /// Actual included ranges, after exclusions, rather than the editable input.
    pub targets: Vec<TargetRange>,
    pub tcp_ports: Vec<u16>,
    pub udp_ports: Vec<u16>,
    pub fetchers: Vec<Fetcher>,
    /// Deterministic, secret-free description of actual discovery/probe settings.
    #[serde(default)]
    pub probe_policy: String,
    pub complete: bool,
    pub cancelled: bool,
    pub hosts: Vec<HostResult>,
    pub elapsed_ms: u64,
}

impl ScanSnapshot {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != SCHEMA_VERSION {
            return Err(format!(
                "Unsupported scan history schema {} (expected {SCHEMA_VERSION})",
                self.schema_version
            ));
        }
        if self.hosts.len() > MAX_HOSTS || self.targets.len() > MAX_HOSTS {
            return Err(format!(
                "A scan record may contain at most {MAX_HOSTS} hosts/ranges"
            ));
        }
        for text in [
            &self.app_version,
            &self.label,
            &self.target_text,
            &self.probe_policy,
        ] {
            if text.len() > MAX_STRING_BYTES {
                return Err("Scan record text is too long".into());
            }
        }
        let mut ranges = self.targets.clone();
        ranges.sort_by_key(|range| range.first);
        let mut merged: Vec<TargetRange> = Vec::new();
        for range in ranges {
            if range.first > range.last
                || u64::from(range.last) - u64::from(range.first) + 1 > MAX_HOSTS as u64
            {
                return Err("Invalid or oversized target range in scan record".into());
            }
            if let Some(last) = merged
                .last_mut()
                .filter(|last| u64::from(range.first) <= u64::from(last.last) + 1)
            {
                last.last = last.last.max(range.last);
            } else {
                merged.push(range);
            }
        }
        let count: u64 = merged
            .iter()
            .map(|range| u64::from(range.last) - u64::from(range.first) + 1)
            .sum();
        if count > MAX_HOSTS as u64 {
            return Err("Scan record target coverage exceeds 65536 addresses".into());
        }
        let mut target_ips = BTreeSet::new();
        for range in &merged {
            for ip in range.first..=range.last {
                target_ips.insert(ip);
            }
        }
        validate_ports(&self.tcp_ports)?;
        validate_ports(&self.udp_ports)?;
        let fetchers: HashSet<_> = self.fetchers.iter().copied().collect();
        if fetchers.len() != self.fetchers.len() || self.fetchers.len() > Fetcher::ALL.len() + 1 {
            return Err("Duplicate or excessive fetchers in scan record".into());
        }
        let mut seen = HashSet::new();
        for host in &self.hosts {
            if !seen.insert(host.ip) {
                return Err(format!("Duplicate host {} in scan record", host.ip));
            }
            if !target_ips.contains(&u32::from(host.ip)) {
                return Err(format!(
                    "Host {} lies outside recorded target coverage",
                    host.ip
                ));
            }
            validate_ports(&host.open_ports)?;
            validate_ports(&host.extra.udp.open_ports)?;
            if host
                .ping_ms
                .is_some_and(|value| !value.is_finite() || value < 0.0)
                || host
                    .extra
                    .packet_loss
                    .is_some_and(|value| !value.is_finite() || !(0.0..=100.0).contains(&value))
            {
                return Err("Invalid timing/packet loss in scan record".into());
            }
            let value = serde_json::to_value(host).map_err(|error| error.to_string())?;
            let mut string_bytes = 0;
            validate_metadata(&value, 0, &mut string_bytes, "host")?;
        }
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, String> {
        let file = File::open(path.as_ref())
            .map_err(|error| format!("Cannot open scan record: {error}"))?;
        let mut bytes = Vec::new();
        file.take(MAX_SNAPSHOT_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| format!("Cannot read scan record: {error}"))?;
        if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err("Scan record exceeds the 128 MiB limit".into());
        }
        let record: Self = serde_json::from_slice(&bytes)
            .map_err(|error| format!("Invalid scan record JSON: {error}"))?;
        record.validate()?;
        Ok(record)
    }

    /// Write beside the destination, then atomically install the completed file.
    /// An unsuccessful replacement preserves the previous destination.
    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), String> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|error| error.to_string())?;
        if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
            return Err("Scan record exceeds the 128 MiB limit".into());
        }
        let path = path.as_ref();
        let parent = path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let temporary = parent.join(format!(".ip-scout-history-{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            install_file(&temporary, path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.map_err(|error| format!("Cannot save scan record: {error}"))
    }

    pub fn covers(&self, ip: Ipv4Addr) -> bool {
        let ip = u32::from(ip);
        self.targets
            .iter()
            .any(|range| range.first <= ip && ip <= range.last)
    }

    pub fn finished(&self) -> bool {
        self.complete && !self.cancelled
    }
}

fn validate_ports(ports: &[u16]) -> Result<(), String> {
    let unique: HashSet<_> = ports.iter().copied().collect();
    if ports.contains(&0) || ports.len() > u16::MAX as usize || unique.len() != ports.len() {
        return Err("Port lists must contain unique ports between 1 and 65535".into());
    }
    Ok(())
}

fn validate_metadata(
    value: &serde_json::Value,
    depth: usize,
    bytes: &mut usize,
    key: &str,
) -> Result<(), String> {
    if depth > 16 {
        return Err("Scan metadata is nested too deeply".into());
    }
    match value {
        serde_json::Value::String(text) => {
            *bytes = bytes.saturating_add(text.len());
            if text.len() > MAX_STRING_BYTES || *bytes > MAX_HOST_STRING_BYTES {
                return Err("Host metadata exceeds its text limit".into());
            }
        }
        serde_json::Value::Array(values) => {
            let limit = if key == "open_ports" {
                u16::MAX as usize
            } else {
                1024
            };
            if values.len() > limit {
                return Err("Too many metadata entries for one host".into());
            }
            for value in values {
                validate_metadata(value, depth + 1, bytes, key)?;
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                validate_metadata(value, depth + 1, bytes, key)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(not(windows))]
fn install_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)
}

#[cfg(windows)]
fn install_file(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn ReplaceFileW(
            replaced: *const u16,
            replacement: *const u16,
            backup: *const u16,
            flags: u32,
            exclude: *mut std::ffi::c_void,
            reserved: *mut std::ffi::c_void,
        ) -> i32;
    }
    if !destination.exists() {
        match fs::rename(source, destination) {
            Ok(()) => return Ok(()),
            Err(error) if !destination.exists() => return Err(error),
            Err(_) => {} // A destination created concurrently needs replacement.
        }
    }
    // ReplaceFileW can rename the previous file before a later step fails.
    // Supplying a backup prevents that failure from discarding the old record.
    let backup_path = source.with_extension("bak");
    let backup: Vec<u16> = backup_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let destination_wide: Vec<u16> = destination
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let source_wide: Vec<u16> = source.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: all terminated path buffers live for the call; unused parameters are null.
    let result = unsafe {
        ReplaceFileW(
            destination_wide.as_ptr(),
            source_wide.as_ptr(),
            backup.as_ptr(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if result == 0 {
        let error = std::io::Error::last_os_error();
        if backup_path.exists() {
            if !destination.exists() {
                if let Err(restore_error) = fs::rename(&backup_path, destination) {
                    return Err(std::io::Error::other(format!(
                        "{error}; previous record retained at {} (restore failed: {restore_error})",
                        backup_path.display()
                    )));
                }
            } else {
                return Err(std::io::Error::other(format!(
                    "{error}; previous record retained at {}",
                    backup_path.display()
                )));
            }
        }
        Err(error)
    } else {
        let _ = fs::remove_file(backup_path);
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    NewDevice,
    LostResponse,
    Changed,
    Uncertain,
}

impl ChangeKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::NewDevice => "New response",
            Self::LostResponse => "Lost response",
            Self::Changed => "Changed",
            Self::Uncertain => "Uncertain",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostChange {
    pub ip: Ipv4Addr,
    pub kind: ChangeKind,
    pub details: Vec<String>,
}

/// Compare only common target coverage. Timings, packet loss and free-form notes
/// are intentionally ignored. Negative findings always retain their uncertainty.
pub fn compare(previous: &ScanSnapshot, current: &ScanSnapshot) -> Vec<HostChange> {
    let previous_ranges = coverage_index(&previous.targets);
    let current_ranges = coverage_index(&current.targets);
    let ports = PortCoverage::new(previous, current);
    let same_discovery = previous.probe_policy == current.probe_policy
        && same_ports(&previous.tcp_ports, &current.tcp_ports)
        && same_ports(&previous.udp_ports, &current.udp_ports)
        && [
            Fetcher::Ping,
            Fetcher::Ports,
            Fetcher::ArpResponse,
            Fetcher::UdpPorts,
            Fetcher::DnsInfo,
            Fetcher::NtpInfo,
            Fetcher::SnmpInfo,
        ]
        .iter()
        .all(|fetcher| previous.fetchers.contains(fetcher) == current.fetchers.contains(fetcher));
    let before: BTreeMap<_, _> = previous.hosts.iter().map(|host| (host.ip, host)).collect();
    let after: BTreeMap<_, _> = current.hosts.iter().map(|host| (host.ip, host)).collect();
    let ips: BTreeSet<_> = before.keys().chain(after.keys()).copied().collect();
    let mut changes = Vec::new();
    for ip in ips {
        if !index_covers(&previous_ranges, ip) || !index_covers(&current_ranges, ip) {
            continue;
        }
        let (old, new) = match (before.get(&ip), after.get(&ip)) {
            (Some(old), Some(new)) => (*old, *new),
            (old, new) => {
                if old
                    .or(new)
                    .is_some_and(|host| host.status == HostStatus::Alive)
                {
                    changes.push(HostChange { ip, kind: ChangeKind::Uncertain, details: vec!["A responding device lacks a record in one scan; missing coverage cannot establish a new or missing device.".into()] });
                }
                continue;
            }
        };
        let reliable = previous.finished()
            && current.finished()
            && old.discovery_complete()
            && new.discovery_complete()
            && old.status != HostStatus::Incomplete
            && new.status != HostStatus::Incomplete;
        let mut details = Vec::new();
        let mut kind = ChangeKind::Changed;
        if old.status != new.status {
            if !reliable || !same_discovery {
                kind = ChangeKind::Uncertain;
                details.push("Response differs, but incomplete/cancelled discovery or changed discovery selections cannot establish device appearance or disappearance.".into());
            } else if old.status == HostStatus::Alive {
                kind = ChangeKind::LostResponse;
                details.push("Previously responding device now has no response; this is not proof that it is offline.".into());
            } else if new.status == HostStatus::Alive {
                kind = ChangeKind::NewDevice;
                details.push("Newly responding device; the previous scan recorded no response, not confirmed absence.".into());
            }
        }
        if old.status == HostStatus::Alive && new.status == HostStatus::Alive {
            compare_identity(previous, current, old, new, &mut details);
            compare_ports(&ports, old, new, reliable, &mut details);
            compare_services(previous, current, old, new, &mut details);
        }
        if !details.is_empty() {
            changes.push(HostChange { ip, kind, details });
        }
    }
    changes
}

fn enabled(previous: &ScanSnapshot, current: &ScanSnapshot, fetcher: Fetcher) -> bool {
    previous.fetchers.contains(&fetcher) && current.fetchers.contains(&fetcher)
}

fn same_ports(before: &[u16], after: &[u16]) -> bool {
    before.iter().copied().collect::<BTreeSet<_>>()
        == after.iter().copied().collect::<BTreeSet<_>>()
}

fn coverage_index(ranges: &[TargetRange]) -> Vec<TargetRange> {
    let mut ranges: Vec<_> = ranges
        .iter()
        .filter(|range| range.first <= range.last)
        .cloned()
        .collect();
    ranges.sort_by_key(|range| range.first);
    let mut merged: Vec<TargetRange> = Vec::new();
    for range in ranges {
        if let Some(last) = merged
            .last_mut()
            .filter(|last| u64::from(range.first) <= u64::from(last.last) + 1)
        {
            last.last = last.last.max(range.last);
        } else {
            merged.push(range);
        }
    }
    merged
}

fn index_covers(ranges: &[TargetRange], ip: Ipv4Addr) -> bool {
    let ip = u32::from(ip);
    let next = ranges.partition_point(|range| range.first <= ip);
    next > 0 && ip <= ranges[next - 1].last
}

struct PortCoverage {
    tcp: HashSet<u16>,
    udp: HashSet<u16>,
    tcp_enabled: bool,
    udp_enabled: bool,
}

impl PortCoverage {
    fn new(previous: &ScanSnapshot, current: &ScanSnapshot) -> Self {
        fn intersection(before: &[u16], after: &[u16]) -> HashSet<u16> {
            let after: HashSet<_> = after.iter().copied().collect();
            before
                .iter()
                .copied()
                .filter(|port| after.contains(port))
                .collect()
        }
        Self {
            tcp: intersection(&previous.tcp_ports, &current.tcp_ports),
            udp: intersection(&previous.udp_ports, &current.udp_ports),
            tcp_enabled: enabled(previous, current, Fetcher::Ports),
            udp_enabled: enabled(previous, current, Fetcher::UdpPorts),
        }
    }
}

fn compare_identity(
    previous: &ScanSnapshot,
    current: &ScanSnapshot,
    old: &HostResult,
    new: &HostResult,
    details: &mut Vec<String>,
) {
    for (fetcher, label, before, after) in [
        (Fetcher::Hostname, "Hostname", &old.hostname, &new.hostname),
        (Fetcher::MacAddress, "MAC", &old.mac, &new.mac),
        (
            Fetcher::Manufacturer,
            "Manufacturer",
            &old.vendor,
            &new.vendor,
        ),
        (
            Fetcher::ProbableBrand,
            "Probable brand",
            &old.probable_brand,
            &new.probable_brand,
        ),
    ] {
        if enabled(previous, current, fetcher)
            && !before.is_empty()
            && !after.is_empty()
            && !before.eq_ignore_ascii_case(after)
        {
            details.push(format!("{label}: {before} → {after}"));
        }
    }
}

fn compare_ports(
    coverage: &PortCoverage,
    old: &HostResult,
    new: &HostResult,
    reliable: bool,
    details: &mut Vec<String>,
) {
    for (protocol, before, after, ports, enabled) in [
        (
            "TCP",
            &old.open_ports,
            &new.open_ports,
            &coverage.tcp,
            coverage.tcp_enabled,
        ),
        (
            "UDP",
            &old.extra.udp.open_ports,
            &new.extra.udp.open_ports,
            &coverage.udp,
            coverage.udp_enabled,
        ),
    ] {
        if !enabled {
            continue;
        }
        let completed = reliable
            && (protocol == "TCP"
                || (old.extra.udp.completed == old.extra.udp.requested
                    && new.extra.udp.completed == new.extra.udp.requested));
        if !completed {
            continue;
        }
        for port in after
            .iter()
            .filter(|port| ports.contains(port) && !before.contains(port))
        {
            details.push(format!("{protocol} {port} newly observed open (previous non-response did not establish closure)"));
        }
        for port in before
            .iter()
            .filter(|port| ports.contains(port) && !after.contains(port))
        {
            details.push(format!("{protocol} {port} no longer observed open; closed versus filtered/unresponsive is unknown"));
        }
    }
}

fn compare_services(
    previous: &ScanSnapshot,
    current: &ScanSnapshot,
    old: &HostResult,
    new: &HostResult,
    details: &mut Vec<String>,
) {
    for (fetcher, label) in [
        (Fetcher::ServiceBanners, "Service banners"),
        (Fetcher::ServiceDetails, "Identified services"),
        (Fetcher::TlsCertificates, "TLS certificates"),
        (Fetcher::WebDetect, "Web services"),
    ] {
        let selected = enabled(previous, current, fetcher)
            || (fetcher == Fetcher::WebDetect
                && [Fetcher::WebTitle, Fetcher::HttpStatus, Fetcher::WebUrl]
                    .iter()
                    .any(|fetcher| enabled(previous, current, *fetcher)));
        if !selected {
            continue;
        }
        let (before, after) = match fetcher {
            Fetcher::ServiceBanners => (
                serde_json::to_value(&old.extra.banners),
                serde_json::to_value(&new.extra.banners),
            ),
            Fetcher::TlsCertificates => (
                serde_json::to_value(&old.extra.certificates),
                serde_json::to_value(&new.extra.certificates),
            ),
            Fetcher::ServiceDetails => (
                serde_json::to_value(&old.extra.services),
                serde_json::to_value(&new.extra.services),
            ),
            _ => (
                serde_json::to_value(&old.extra.web),
                serde_json::to_value(&new.extra.web),
            ),
        };
        if let (Ok(before), Ok(after)) = (before, after) {
            // Compare identities at endpoints observed in both scans. A probe that
            // returned nothing does not establish removal of a service.
            let before = service_map(before);
            let after = service_map(after);
            let mut changed_ports = BTreeSet::new();
            for (key, value) in &before {
                if after.get(key).is_some_and(|after| value != after) {
                    changed_ports.insert(key.0);
                }
            }
            if !changed_ports.is_empty() {
                details.push(format!(
                    "{label} changed on port(s) {} (reported identity is unverified)",
                    changed_ports
                        .iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
    }
}

fn service_map(value: serde_json::Value) -> BTreeMap<(u16, String), BTreeSet<String>> {
    let mut result: BTreeMap<(u16, String), BTreeSet<String>> = BTreeMap::new();
    if let serde_json::Value::Array(values) = value {
        for mut value in values {
            let Some(port) = value
                .get("port")
                .and_then(|port| port.as_u64())
                .and_then(|port| u16::try_from(port).ok())
                .or_else(|| {
                    value
                        .get("url")
                        .and_then(|url| url.as_str())
                        .and_then(|url| reqwest::Url::parse(url).ok())
                        .and_then(|url| url.port_or_known_default())
                })
            else {
                continue;
            };
            let endpoint = value
                .get("url")
                .or_else(|| value.get("server_name"))
                .and_then(|value| value.as_str())
                .unwrap_or("")
                .to_owned();
            // Evidence can contain changing greetings or request IDs; the
            // recognized protocol and product are the stable observations.
            if let serde_json::Value::Object(fields) = &mut value {
                fields.remove("evidence");
            }
            // SAN order has no semantic significance.
            if let Some(serde_json::Value::Array(names)) = value.get_mut("names") {
                names.sort_by_key(serde_json::Value::to_string);
            }
            result
                .entry((port, endpoint))
                .or_default()
                .insert(value.to_string());
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn host(ip: &str, status: HostStatus) -> HostResult {
        serde_json::from_value(json!({
            "ip": ip, "status": status, "ping_ms": 1.0, "hostname": "router",
            "mac": "00:11:22:33:44:55", "vendor": "Example", "open_ports": [22,80],
            "refused_ports": 0, "notes": "initial", "extra": {"discovery_complete": true}
        }))
        .unwrap()
    }

    fn snapshot() -> ScanSnapshot {
        ScanSnapshot {
            schema_version: SCHEMA_VERSION,
            recorded_unix_secs: 1,
            app_version: "0.15.0".into(),
            label: "Office".into(),
            target_text: "192.0.2.1-3".into(),
            targets: vec![TargetRange::parse("192.0.2.1-3").unwrap()],
            tcp_ports: vec![22, 80, 443],
            udp_ports: vec![53, 123],
            fetchers: vec![
                Fetcher::Ping,
                Fetcher::Ports,
                Fetcher::Hostname,
                Fetcher::MacAddress,
                Fetcher::Manufacturer,
                Fetcher::UdpPorts,
                Fetcher::ServiceBanners,
                Fetcher::TlsCertificates,
                Fetcher::WebDetect,
            ],
            probe_policy: String::new(),
            complete: true,
            cancelled: false,
            hosts: vec![host("192.0.2.1", HostStatus::Alive)],
            elapsed_ms: 300,
        }
    }

    fn temporary() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "ip-scout-history-test-{}.json",
            uuid::Uuid::new_v4()
        ))
    }

    #[test]
    fn round_trip_and_atomic_replacement() {
        let path = temporary();
        let mut record = snapshot();
        record.save(&path).unwrap();
        record.label = "Updated office".into();
        record.save(&path).unwrap();
        let loaded = ScanSnapshot::load(&path).unwrap();
        assert_eq!(loaded.label, record.label);
        assert_eq!(loaded.hosts, record.hosts);
        record.schema_version = 900;
        assert!(record.save(&path).is_err());
        assert_eq!(ScanSnapshot::load(&path).unwrap().label, "Updated office");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn malformed_and_future_json_are_rejected() {
        let path = temporary();
        fs::write(&path, "{ malformed }").unwrap();
        assert!(ScanSnapshot::load(&path).unwrap_err().contains("JSON"));
        let mut record = snapshot();
        record.schema_version = SCHEMA_VERSION + 1;
        fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(ScanSnapshot::load(&path).unwrap_err().contains("schema"));
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn oversized_files_and_metadata_are_rejected() {
        let path = temporary();
        let file = File::create(&path).unwrap();
        file.set_len(MAX_SNAPSHOT_BYTES + 1).unwrap();
        drop(file);
        assert!(ScanSnapshot::load(&path).unwrap_err().contains("128 MiB"));
        fs::remove_file(path).unwrap();
        let mut record = snapshot();
        record.hosts[0].notes = "x".repeat(MAX_STRING_BYTES + 1);
        assert!(record.validate().unwrap_err().contains("text limit"));
        record.hosts[0].notes.clear();
        record.hosts[0].extra.banners =
            serde_json::from_value(json!(vec![json!({"port": 22, "text":"SSH"}); 1025])).unwrap();
        assert!(record.validate().unwrap_err().contains("metadata entries"));
    }

    #[test]
    fn bounds_duplicates_and_outside_targets_are_rejected() {
        let mut record = snapshot();
        record.hosts.push(record.hosts[0].clone());
        assert!(record.validate().unwrap_err().contains("Duplicate host"));
        record.hosts.pop();
        record.tcp_ports.push(0);
        assert!(record.validate().is_err());
        record.tcp_ports.pop();
        record.tcp_ports.push(22);
        assert!(record.validate().is_err());
        record.tcp_ports.pop();
        record.targets[0].last = record.targets[0].first - 1;
        assert!(record.validate().is_err());
        record.targets = vec![TargetRange::parse("198.51.100.1").unwrap()];
        assert!(record.validate().unwrap_err().contains("outside"));
    }

    #[test]
    fn overlapping_targets_are_bounded_by_union_without_repeated_enumeration() {
        let mut record = snapshot();
        record.targets = vec![TargetRange::parse("192.0.2.0/24").unwrap(); MAX_HOSTS];
        record.validate().unwrap();
        record.targets = vec![
            TargetRange {
                first: 0,
                last: 65_535,
            },
            TargetRange {
                first: 65_536,
                last: 65_536,
            },
        ];
        assert!(record.validate().unwrap_err().contains("coverage"));
    }

    #[test]
    fn records_have_no_settings_or_community_secrets() {
        let record = snapshot();
        let value = serde_json::to_value(&record).unwrap();
        assert!(value.get("settings").is_none());
        assert!(value.get("community").is_none());
        assert!(
            !serde_json::to_string(&record)
                .unwrap()
                .contains("snmp_community")
        );
        let mut value = value;
        value["settings"] = json!({"snmp_community": "private-secret"});
        assert!(serde_json::from_value::<ScanSnapshot>(value).is_err());
    }

    #[test]
    fn jitter_packet_loss_notes_and_order_are_not_changes() {
        let previous = snapshot();
        let mut current = previous.clone();
        current.hosts[0].ping_ms = Some(400.0);
        current.hosts[0].extra.packet_loss = Some(50.0);
        current.hosts[0].notes = "different transport notes".into();
        current.hosts[0].open_ports.reverse();
        current.tcp_ports.reverse();
        assert!(compare(&previous, &current).is_empty());
    }

    #[test]
    fn new_and_lost_responses_never_claim_offline() {
        let mut previous = snapshot();
        previous.hosts[0].status = HostStatus::NoResponse;
        let mut current = snapshot();
        let changes = compare(&previous, &current);
        assert_eq!(changes[0].kind, ChangeKind::NewDevice);
        assert!(changes[0].details[0].contains("not confirmed absence"));
        previous.hosts[0].status = HostStatus::Alive;
        current.hosts[0].status = HostStatus::NoResponse;
        let changes = compare(&previous, &current);
        assert_eq!(changes[0].kind, ChangeKind::LostResponse);
        assert!(changes[0].details[0].contains("not proof"));
    }

    #[test]
    fn incomplete_cancelled_missing_records_and_changed_settings_are_uncertain() {
        let previous = snapshot();
        let mut current = previous.clone();
        current.hosts[0].status = HostStatus::NoResponse;
        current.complete = false;
        assert_eq!(compare(&previous, &current)[0].kind, ChangeKind::Uncertain);
        current.complete = true;
        current.cancelled = true;
        assert_eq!(compare(&previous, &current)[0].kind, ChangeKind::Uncertain);
        current.cancelled = false;
        current.hosts[0].extra.discovery_complete = Some(false);
        assert_eq!(compare(&previous, &current)[0].kind, ChangeKind::Uncertain);
        current.hosts[0].extra.discovery_complete = Some(true);
        current.tcp_ports.push(445);
        assert_eq!(compare(&previous, &current)[0].kind, ChangeKind::Uncertain);
        current.hosts.clear();
        assert_eq!(compare(&previous, &current)[0].kind, ChangeKind::Uncertain);
    }

    #[test]
    fn actual_probe_policy_mismatch_makes_response_change_uncertain() {
        let mut previous = snapshot();
        previous.probe_policy = "mode=Fast;arp=true".into();
        let mut current = previous.clone();
        current.hosts[0].status = HostStatus::NoResponse;
        assert_eq!(
            compare(&previous, &current)[0].kind,
            ChangeKind::LostResponse
        );
        current.probe_policy = "mode=Fast;arp=false".into();
        assert_eq!(compare(&previous, &current)[0].kind, ChangeKind::Uncertain);
        let mut legacy = serde_json::to_value(&previous).unwrap();
        legacy.as_object_mut().unwrap().remove("probe_policy");
        assert!(
            serde_json::from_value::<ScanSnapshot>(legacy)
                .unwrap()
                .probe_policy
                .is_empty()
        );
    }

    #[test]
    fn excluded_and_newly_added_targets_are_not_device_changes() {
        let previous = snapshot();
        let mut current = previous.clone();
        current.targets = vec![TargetRange::parse("192.0.2.2-4").unwrap()];
        current.hosts = vec![
            host("192.0.2.1", HostStatus::Alive),
            host("192.0.2.4", HostStatus::Alive),
        ];
        assert!(compare(&previous, &current).is_empty());
    }

    #[test]
    fn ports_use_only_common_coverage_and_never_claim_closure() {
        let previous = snapshot();
        let mut current = previous.clone();
        current.hosts[0].open_ports = vec![443, 445];
        current.tcp_ports = vec![22, 443, 445];
        let changes = compare(&previous, &current);
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].details.len(), 2);
        assert!(
            changes[0]
                .details
                .iter()
                .any(|detail| detail.contains("TCP 443 newly observed"))
        );
        assert!(changes[0].details.iter().any(
            |detail| detail.contains("TCP 22 no longer observed") && detail.contains("unknown")
        ));
        assert!(
            !changes[0]
                .details
                .iter()
                .any(|detail| detail.contains("TCP 80") || detail.contains("TCP 445"))
        );
        current.complete = false;
        assert!(compare(&previous, &current).is_empty());
    }

    #[test]
    fn udp_missing_reply_and_partial_probe_counters_are_conservative() {
        let mut previous = snapshot();
        previous.hosts[0].extra.udp.open_ports = vec![53];
        previous.hosts[0].extra.udp.requested = 2;
        previous.hosts[0].extra.udp.completed = 2;
        let mut current = previous.clone();
        current.hosts[0].extra.udp.open_ports.clear();
        let changes = compare(&previous, &current);
        assert!(changes[0].details[0].contains("UDP 53 no longer observed"));
        assert!(changes[0].details[0].contains("unknown"));
        current.hosts[0].extra.udp.completed = 1;
        assert!(compare(&previous, &current).is_empty());
    }

    #[test]
    fn identity_and_observed_service_changes_require_shared_fetchers() {
        let mut previous = snapshot();
        previous.hosts[0].extra.banners =
            serde_json::from_value(json!([{"port":22,"text":"SSH-2.0-old"}])).unwrap();
        previous.hosts[0].extra.web = serde_json::from_value(json!([{"url":"http://192.0.2.1/", "server":"old", "status":200,"tls_unverified":false}])).unwrap();
        let mut current = previous.clone();
        current.hosts[0].hostname = "router-new".into();
        current.hosts[0].extra.banners[0].text = "SSH-2.0-new".into();
        current.hosts[0].extra.web[0].server = "new".into();
        let changes = compare(&previous, &current);
        assert_eq!(changes[0].details.len(), 3);
        assert!(
            changes[0]
                .details
                .iter()
                .any(|detail| detail.contains("port(s) 80"))
        );
        current.fetchers.retain(|fetcher| {
            ![
                Fetcher::Hostname,
                Fetcher::ServiceBanners,
                Fetcher::WebDetect,
            ]
            .contains(fetcher)
        });
        assert!(compare(&previous, &current).is_empty());
    }

    #[test]
    fn certificate_serial_changes_but_san_reordering_does_not() {
        let mut previous = snapshot();
        previous.hosts[0].extra.certificates = serde_json::from_value(json!([{
            "port":443,"server_name":"router.example", "common_name":"router.example", "subject":"CN=router", "issuer":"CN=CA",
            "names":["router.example","router.local"], "valid_from":"2026-01-01", "valid_until":"2027-01-01", "serial":"01"
        }])).unwrap();
        let mut current = previous.clone();
        current.hosts[0].extra.certificates[0].names.reverse();
        assert!(compare(&previous, &current).is_empty());
        current.hosts[0].extra.certificates[0].serial = "02".into();
        assert!(compare(&previous, &current)[0].details[0].contains("TLS certificates changed"));
        current.hosts[0].extra.certificates.clear();
        assert!(compare(&previous, &current).is_empty());
    }

    #[test]
    fn identified_protocol_and_product_changes_ignore_evidence_and_route() {
        let mut previous = snapshot();
        previous.fetchers.push(Fetcher::ServiceDetails);
        previous.hosts[0].extra.services = serde_json::from_value(json!([
            {"port":22,"protocol":"SSH","product":"OpenSSH 9.0","evidence":"old greeting"}
        ]))
        .unwrap();
        let mut current = previous.clone();
        current.hosts[0].extra.services[0].evidence = "new greeting".into();
        current.hosts[0].extra.route = Some(crate::network::RoutePath {
            interface_index: 12,
            source: Ipv4Addr::LOCALHOST,
            next_hop: Ipv4Addr::LOCALHOST,
        });
        assert!(compare(&previous, &current).is_empty());
        current.hosts[0].extra.services[0].product = "OpenSSH 10.0".into();
        assert!(compare(&previous, &current)[0].details[0].contains("Identified services changed"));
        current.hosts[0].extra.services[0].product =
            previous.hosts[0].extra.services[0].product.clone();
        current.hosts[0].extra.services[0].protocol = "SSH2".into();
        assert_eq!(compare(&previous, &current).len(), 1);
        current
            .fetchers
            .retain(|fetcher| *fetcher != Fetcher::ServiceDetails);
        assert!(compare(&previous, &current).is_empty());
    }

    #[test]
    fn multiple_protocols_per_port_compare_as_an_unordered_set() {
        let mut previous = snapshot();
        previous.fetchers.push(Fetcher::ServiceDetails);
        previous.hosts[0].extra.services = serde_json::from_value(json!([
            {"port":80,"protocol":"HTTP","product":"web","evidence":"first"},
            {"port":80,"protocol":"RTSP","product":"camera","evidence":"second"}
        ]))
        .unwrap();
        let mut current = previous.clone();
        current.hosts[0].extra.services.reverse();
        assert!(compare(&previous, &current).is_empty());
        current.hosts[0].extra.services[1].product = "new web".into();
        assert!(compare(&previous, &current)[0].details[0].contains("Identified services changed"));
    }

    #[test]
    fn full_supported_host_count_round_trips_with_compact_json() {
        let path = temporary();
        let mut record = snapshot();
        let mut template = host("192.0.2.1", HostStatus::NoResponse);
        template.hostname.clear();
        template.mac.clear();
        template.vendor.clear();
        template.notes.clear();
        template.open_ports.clear();
        template.ping_ms = None;
        record.targets = vec![TargetRange {
            first: 0,
            last: MAX_HOSTS as u32 - 1,
        }];
        record.hosts = (0..MAX_HOSTS as u32)
            .map(|ip| {
                let mut host = template.clone();
                host.ip = Ipv4Addr::from(ip);
                host
            })
            .collect();
        record.save(&path).unwrap();
        assert!(fs::metadata(&path).unwrap().len() <= MAX_SNAPSHOT_BYTES);
        let loaded = ScanSnapshot::load(&path).unwrap();
        assert_eq!(loaded.hosts.len(), MAX_HOSTS);
        assert_eq!(
            loaded.hosts.last().unwrap().ip,
            Ipv4Addr::from(MAX_HOSTS as u32 - 1)
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn coverage_index_handles_unsorted_overlapping_and_scattered_ranges() {
        let ranges = vec![
            TargetRange {
                first: 100,
                last: 105,
            },
            TargetRange { first: 1, last: 3 },
            TargetRange { first: 3, last: 4 },
            TargetRange {
                first: 104,
                last: 110,
            },
        ];
        let index = coverage_index(&ranges);
        assert_eq!(
            index,
            vec![
                TargetRange { first: 1, last: 4 },
                TargetRange {
                    first: 100,
                    last: 110
                }
            ]
        );
        assert!(index_covers(&index, Ipv4Addr::from(4)));
        assert!(!index_covers(&index, Ipv4Addr::from(5)));
        let scattered: Vec<_> = (0..MAX_HOSTS as u32)
            .map(|ip| TargetRange {
                first: ip * 2,
                last: ip * 2,
            })
            .collect();
        let index = coverage_index(&scattered);
        assert_eq!(index.len(), MAX_HOSTS);
        for ip in 0..MAX_HOSTS as u32 {
            assert!(index_covers(&index, Ipv4Addr::from(ip * 2)));
            assert!(!index_covers(&index, Ipv4Addr::from(ip * 2 + 1)));
        }
    }
}
