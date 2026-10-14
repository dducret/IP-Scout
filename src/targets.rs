use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, net::Ipv4Addr};

pub const MAX_HOSTS: usize = 65_536;
pub const MAX_PORTS: usize = u16::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetRange {
    pub first: u32,
    pub last: u32,
}

impl TargetRange {
    pub fn parse(input: &str) -> Result<Self, String> {
        let range = parse_interval(input)?;
        if range.len_u64() > MAX_HOSTS as u64 {
            return Err(format!("Choose a range with at most {MAX_HOSTS} addresses"));
        }
        Ok(range)
    }

    fn len_u64(&self) -> u64 {
        if self.is_empty() {
            0
        } else {
            u64::from(self.last) - u64::from(self.first) + 1
        }
    }

    pub fn len(&self) -> usize {
        self.len_u64() as usize
    }

    pub fn is_empty(&self) -> bool {
        self.first > self.last
    }
}

/// Membership is deliberately independent of the bounding range: exclusions and
/// gaps must also apply to multicast discovery and directed metadata requests.
pub trait TargetScope: Send + Sync {
    fn bounds(&self) -> TargetRange;
    fn contains_ip(&self, ip: Ipv4Addr) -> bool;
    fn overlaps_range(&self, first: u32, last: u32) -> bool;
}

impl TargetScope for TargetRange {
    fn bounds(&self) -> TargetRange {
        self.clone()
    }

    fn contains_ip(&self, ip: Ipv4Addr) -> bool {
        (self.first..=self.last).contains(&u32::from(ip))
    }

    fn overlaps_range(&self, first: u32, last: u32) -> bool {
        !self.is_empty() && first <= last && self.first <= last && self.last >= first
    }
}

/// Sorted, disjoint, nonadjacent IPv4 intervals, bounded by selected host count.
/// Only intervals are persisted; derived indexes are rebuilt and validated when
/// loading a saved profile or scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TargetSet {
    intervals: Vec<TargetRange>,
    #[serde(skip)]
    offsets: Vec<usize>,
    #[serde(skip)]
    length: usize,
}

impl<'de> Deserialize<'de> for TargetSet {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct StoredTargets {
            intervals: Vec<TargetRange>,
        }
        let stored = StoredTargets::deserialize(deserializer)?;
        Self::from_intervals(stored.intervals).map_err(serde::de::Error::custom)
    }
}

const MAX_TARGET_INPUT_BYTES: usize = 1_048_576;
const MAX_TARGET_TOKENS: usize = 65_536;

impl TargetSet {
    /// Accept addresses, CIDRs, full/short ranges, and !exclusions separated by
    /// commas, semicolons or whitespace. Included CIDRs retain TargetRange host
    /// semantics; excluded CIDRs remove the whole subnet, including boundaries.
    /// Interval subtraction happens before size checks without enumerating hosts.
    pub fn parse(input: &str) -> Result<Self, String> {
        if input.len() > MAX_TARGET_INPUT_BYTES {
            return Err("Target input is too large; use at most 1 MiB of addresses".into());
        }
        let mut includes = Vec::new();
        let mut excludes = Vec::new();
        for (index, token) in input
            .split(|ch: char| ch.is_whitespace() || ch == ',' || ch == ';')
            .filter(|token| !token.is_empty())
            .enumerate()
        {
            if index >= MAX_TARGET_TOKENS {
                return Err(format!("Use at most {MAX_TARGET_TOKENS} target entries"));
            }
            let (excluded, token) = match token.strip_prefix('!') {
                Some(token) => (true, token),
                None => (false, token),
            };
            let range = parse_interval_with_boundaries(token, excluded)
                .map_err(|error| format!("{token}: {error}"))?;
            if excluded {
                excludes.push(range);
            } else {
                includes.push(range);
            }
        }
        if includes.is_empty() {
            return Err(
                "Enter at least one IPv4 address, range or subnet before exclusions".into(),
            );
        }
        let includes = merge_intervals(includes);
        let excludes = merge_intervals(excludes);
        let mut selected = Vec::new();
        let mut exclusion_index = 0;
        for include in includes {
            let mut cursor = u64::from(include.first);
            let last = u64::from(include.last);
            while exclusion_index < excludes.len()
                && u64::from(excludes[exclusion_index].last) < cursor
            {
                exclusion_index += 1;
            }
            let mut index = exclusion_index;
            while let Some(exclude) = excludes.get(index) {
                if u64::from(exclude.first) > last {
                    break;
                }
                let excluded_first = u64::from(exclude.first);
                if cursor < excluded_first {
                    selected.push(TargetRange {
                        first: cursor as u32,
                        last: (excluded_first - 1) as u32,
                    });
                }
                cursor = cursor.max(u64::from(exclude.last) + 1);
                if cursor > last {
                    break;
                }
                index += 1;
            }
            if cursor <= last {
                selected.push(TargetRange {
                    first: cursor as u32,
                    last: include.last,
                });
            }
            exclusion_index = index;
        }
        Self::from_intervals(selected)
    }

    /// Convert a range already validated by TargetRange::parse.
    pub fn from_range(range: TargetRange) -> Self {
        Self::from_intervals(vec![range]).expect("TargetRange must contain 1..=MAX_HOSTS addresses")
    }

    pub fn from_ips(ips: impl IntoIterator<Item = Ipv4Addr>) -> Result<Self, String> {
        let mut addresses = BTreeSet::new();
        for ip in ips {
            addresses.insert(u32::from(ip));
            if addresses.len() > MAX_HOSTS {
                return Err(format!("Select at most {MAX_HOSTS} unique addresses"));
            }
        }
        Self::from_intervals(
            addresses
                .into_iter()
                .map(|ip| TargetRange {
                    first: ip,
                    last: ip,
                })
                .collect(),
        )
    }

    fn from_intervals(intervals: Vec<TargetRange>) -> Result<Self, String> {
        if intervals.len() > MAX_TARGET_TOKENS {
            return Err(format!("Use at most {MAX_TARGET_TOKENS} target intervals"));
        }
        if intervals.iter().any(TargetRange::is_empty) {
            return Err("Target intervals must be in ascending order".into());
        }
        let intervals = merge_intervals(intervals);
        let length: u64 = intervals.iter().map(TargetRange::len_u64).sum();
        if length == 0 {
            return Err("No targets remain; add an address or reduce the exclusions".into());
        }
        if length > MAX_HOSTS as u64 {
            return Err(format!(
                "Select at most {MAX_HOSTS} addresses after exclusions"
            ));
        }
        let mut offset = 0;
        let offsets = intervals
            .iter()
            .map(|range| {
                let start = offset;
                offset += range.len();
                start
            })
            .collect();
        Ok(Self {
            intervals,
            offsets,
            length: length as usize,
        })
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn ranges(&self) -> &[TargetRange] {
        &self.intervals
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        let address = u32::from(ip);
        let index = self.intervals.partition_point(|range| range.last < address);
        self.intervals
            .get(index)
            .is_some_and(|range| range.first <= address)
    }

    pub fn ip_at(&self, index: usize) -> Option<Ipv4Addr> {
        if index >= self.length {
            return None;
        }
        let interval = self.offsets.partition_point(|offset| *offset <= index) - 1;
        Some(Ipv4Addr::from(
            self.intervals[interval].first + (index - self.offsets[interval]) as u32,
        ))
    }

    pub fn bounds(&self) -> TargetRange {
        TargetRange {
            first: self.intervals[0].first,
            last: self.intervals[self.intervals.len() - 1].last,
        }
    }

    pub fn canonical_text(&self) -> String {
        self.intervals
            .iter()
            .map(|range| {
                if range.first == range.last {
                    Ipv4Addr::from(range.first).to_string()
                } else {
                    format!(
                        "{}-{}",
                        Ipv4Addr::from(range.first),
                        Ipv4Addr::from(range.last)
                    )
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl TargetScope for TargetSet {
    fn bounds(&self) -> TargetRange {
        self.bounds()
    }

    fn contains_ip(&self, ip: Ipv4Addr) -> bool {
        self.contains(ip)
    }

    fn overlaps_range(&self, first: u32, last: u32) -> bool {
        if first > last {
            return false;
        }
        let index = self.intervals.partition_point(|range| range.last < first);
        self.intervals
            .get(index)
            .is_some_and(|range| range.first <= last)
    }
}

fn merge_intervals(mut intervals: Vec<TargetRange>) -> Vec<TargetRange> {
    intervals.sort_unstable_by_key(|range| range.first);
    let mut merged: Vec<TargetRange> = Vec::new();
    for range in intervals {
        if let Some(previous) = merged.last_mut()
            && u64::from(range.first) <= u64::from(previous.last) + 1
        {
            previous.last = previous.last.max(range.last);
        } else {
            merged.push(range);
        }
    }
    merged
}

fn parse_interval(input: &str) -> Result<TargetRange, String> {
    parse_interval_with_boundaries(input, false)
}

fn parse_interval_with_boundaries(
    input: &str,
    include_boundaries: bool,
) -> Result<TargetRange, String> {
    let input = input.trim();
    let (first, last) = if let Some((address, prefix)) = input.split_once('/') {
        let address = parse_ip(address)?;
        let prefix: u32 = prefix.trim().parse().map_err(|_| "Invalid CIDR prefix")?;
        if prefix > 32 {
            return Err("CIDR prefix must be between 0 and 32".into());
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let network = address & mask;
        let broadcast = network | !mask;
        if prefix < 31 && !include_boundaries {
            (network + 1, broadcast - 1)
        } else {
            (network, broadcast)
        }
    } else if let Some((start, end)) = input.split_once('-') {
        let first = parse_ip(start)?;
        let end = end.trim();
        let last = if end.contains('.') {
            parse_ip(end)?
        } else {
            let octet: u8 = end.parse().map_err(|_| "Invalid last IP octet")?;
            (first & 0xffff_ff00) | u32::from(octet)
        };
        (first, last)
    } else {
        let ip = parse_ip(input)?;
        (ip, ip)
    };
    if first > last {
        return Err("The end address must be at or after the start address".into());
    }
    Ok(TargetRange { first, last })
}

fn parse_ip(input: &str) -> Result<u32, String> {
    input
        .trim()
        .parse::<Ipv4Addr>()
        .map(u32::from)
        .map_err(|_| format!("Invalid IPv4 address: {}", input.trim()))
}

pub fn parse_ports(input: &str) -> Result<Vec<u16>, String> {
    let mut ports = BTreeSet::new();
    if input.trim().is_empty() {
        return Ok(Vec::new());
    }
    for part in input.split(',') {
        let part = part.trim();
        let (first, last) = if let Some((first, last)) = part.split_once('-') {
            (port(first)?, port(last)?)
        } else {
            let value = port(part)?;
            (value, value)
        };
        if first > last {
            return Err("Port ranges must be in ascending order".into());
        }
        for value in first..=last {
            ports.insert(value);
        }
    }
    Ok(ports.into_iter().collect())
}

/// Compact the sorted, unique output of `parse_ports` for the editable port field.
pub fn format_ports(ports: &[u16]) -> String {
    let mut parts = Vec::new();
    let mut values = ports.iter().copied().peekable();
    while let Some(first) = values.next() {
        let mut last = first;
        while values.peek().copied() == last.checked_add(1) {
            let Some(next) = values.next() else {
                break;
            };
            last = next;
        }
        parts.push(if first == last {
            first.to_string()
        } else {
            format!("{first}-{last}")
        });
    }
    parts.join(",")
}

fn port(input: &str) -> Result<u16, String> {
    match input.trim().parse::<u16>() {
        Ok(value) if value != 0 => Ok(value),
        _ => Err(format!("Invalid port: {}", input.trim())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_lists_merge_duplicates_and_apply_exclusions_independent_of_order() {
        let targets =
            TargetSet::parse("!192.0.2.3-4; 192.0.2.1-5,192.0.2.4-8\n192.0.2.1\t10.0.0.1").unwrap();
        assert_eq!(targets.len(), 7);
        assert_eq!(
            targets.canonical_text(),
            "10.0.0.1, 192.0.2.1-192.0.2.2, 192.0.2.5-192.0.2.8"
        );
        assert_eq!(
            TargetSet::parse(&targets.canonical_text()).unwrap(),
            targets
        );
        assert!(targets.contains("192.0.2.5".parse().unwrap()));
        assert!(!targets.contains("192.0.2.3".parse().unwrap()));
        assert!(!targets.contains("172.16.0.1".parse().unwrap()));
        assert_eq!(targets.ip_at(0), Some("10.0.0.1".parse().unwrap()));
        assert_eq!(targets.ip_at(3), Some("192.0.2.5".parse().unwrap()));
        assert_eq!(targets.ip_at(6), Some("192.0.2.8".parse().unwrap()));
        assert_eq!(targets.ip_at(7), None);
        assert_eq!(targets.ip_at(usize::MAX), None);
    }

    #[test]
    fn host_limit_applies_after_interval_subtraction_without_enumerating_the_ipv4_space() {
        let targets = TargetSet::parse("0.0.0.0-255.255.255.255,!0.0.0.0-255.254.255.255").unwrap();
        assert_eq!(targets.len(), MAX_HOSTS);
        assert_eq!(targets.ip_at(MAX_HOSTS - 1), Some(Ipv4Addr::BROADCAST));
        assert!(TargetSet::parse("0.0.0.0/0").is_err());
        assert!(TargetSet::parse("10.0.0.0-10.1.0.0").is_err());
        assert!(TargetSet::parse("10.0.0.0/16, 192.0.2.1-3").is_err());
        assert_eq!(
            TargetSet::parse("10.0.0.0/16, 10.0.0.1-20").unwrap().len(),
            65534
        );
    }

    #[test]
    fn exclusions_split_spanning_intervals_and_match_explicit_membership() {
        for first in 0..16 {
            for last in first..16 {
                let input = format!("0.0.0.0-4,0.0.0.8-12,0.0.0.15,!0.0.0.{first}-{last}");
                let expected: Vec<Ipv4Addr> = (0..16)
                    .filter(|ip| {
                        (*ip <= 4 || (8..=12).contains(ip) || *ip == 15)
                            && !((first..=last).contains(ip))
                    })
                    .map(Ipv4Addr::from)
                    .collect();
                let actual = TargetSet::parse(&input);
                if expected.is_empty() {
                    assert!(actual.is_err());
                } else {
                    let actual = actual.unwrap();
                    assert_eq!(actual.len(), expected.len(), "{input}");
                    assert_eq!(
                        (0..actual.len())
                            .map(|i| actual.ip_at(i).unwrap())
                            .collect::<Vec<_>>(),
                        expected,
                        "{input}"
                    );
                }
            }
        }
    }

    #[test]
    fn target_lists_handle_ipv4_endpoints_cidrs_and_empty_input() {
        let targets =
            TargetSet::parse("0.0.0.0,255.255.255.254-255.255.255.255,!255.255.255.255").unwrap();
        assert_eq!(targets.len(), 2);
        assert_eq!(
            targets.bounds(),
            TargetRange {
                first: 0,
                last: u32::MAX - 1
            }
        );
        let cidr = TargetSet::parse("192.0.2.0/24,!192.0.2.0/25").unwrap();
        assert_eq!(cidr.len(), 127);
        assert!(!cidr.contains("192.0.2.127".parse().unwrap()));
        assert!(!cidr.contains("192.0.2.126".parse().unwrap()));
        assert!(cidr.contains("192.0.2.128".parse().unwrap()));
        assert!(TargetSet::parse("192.0.2.0,192.0.2.255,!192.0.2.0/24").is_err());
        for input in [
            "",
            " , ; \n",
            "!192.0.2.1",
            "192.0.2.1,!192.0.2.1",
            "!",
            "192.0.2.1,::1",
        ] {
            assert!(TargetSet::parse(input).is_err(), "{input}");
        }
        assert!(TargetSet::parse(&" ".repeat(MAX_TARGET_INPUT_BYTES + 1)).is_err());
        assert!(TargetSet::parse(&"1.1.1.1 ".repeat(MAX_TARGET_TOKENS + 1)).is_err());
        assert!(TargetSet::from_ips([]).is_err());
    }

    #[test]
    fn selected_ip_sets_sort_merge_and_serde_loads_validate_and_rebuild_indexes() {
        let targets = TargetSet::from_ips(
            ["192.0.2.3", "192.0.2.1", "192.0.2.2", "192.0.2.1"].map(|ip| ip.parse().unwrap()),
        )
        .unwrap();
        assert_eq!(targets.canonical_text(), "192.0.2.1-192.0.2.3");
        assert_eq!(targets.ranges().len(), 1);
        let json = serde_json::to_string(&targets).unwrap();
        assert_eq!(serde_json::from_str::<TargetSet>(&json).unwrap(), targets);
        for json in [
            r#"{"intervals":[]}"#,
            r#"{"intervals":[{"first":2,"last":1}]}"#,
            r#"{"intervals":[{"first":0,"last":4294967295}]}"#,
        ] {
            assert!(serde_json::from_str::<TargetSet>(json).is_err(), "{json}");
        }
        let reordered: TargetSet =
            serde_json::from_str(r#"{"intervals":[{"first":3,"last":4},{"first":1,"last":3}]}"#)
                .unwrap();
        assert_eq!(reordered.canonical_text(), "0.0.0.1-0.0.0.4");
        assert_eq!(reordered.ip_at(3), Some(Ipv4Addr::from(4)));
        let range = TargetRange::parse("192.0.2.1-3").unwrap();
        assert_eq!(TargetSet::from_range(range), targets);
    }

    #[test]
    fn target_scope_overlap_uses_selected_intervals_instead_of_bounding_gaps() {
        let targets = TargetSet::parse("10.0.0.1,192.0.2.1-10,!192.0.2.4-8").unwrap();
        assert!(targets.overlaps_range(
            u32::from("10.0.0.0".parse::<Ipv4Addr>().unwrap()),
            u32::from("10.0.0.255".parse::<Ipv4Addr>().unwrap())
        ));
        assert!(!targets.overlaps_range(
            u32::from("172.16.0.0".parse::<Ipv4Addr>().unwrap()),
            u32::from("172.16.0.255".parse::<Ipv4Addr>().unwrap())
        ));
        assert!(!targets.overlaps_range(
            u32::from("192.0.2.4".parse::<Ipv4Addr>().unwrap()),
            u32::from("192.0.2.8".parse::<Ipv4Addr>().unwrap())
        ));
        assert!(!targets.overlaps_range(2, 1));
    }

    #[test]
    fn cidr_host_boundaries_and_small_networks() {
        let range = TargetRange::parse("192.168.1.42/24").unwrap();
        assert_eq!(Ipv4Addr::from(range.first), Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(Ipv4Addr::from(range.last), Ipv4Addr::new(192, 168, 1, 254));
        assert_eq!(range.len(), 254);
        assert_eq!(TargetRange::parse("10.0.0.0/31").unwrap().len(), 2);
        assert_eq!(TargetRange::parse("255.255.255.255/32").unwrap().len(), 1);
    }

    #[test]
    fn ranges_validate_size_and_order() {
        assert_eq!(TargetRange::parse("10.0.0.1-20").unwrap().len(), 20);
        assert_eq!(TargetRange::parse("10.0.0.254-10.0.1.1").unwrap().len(), 4);
        for invalid in [
            "10.0.0.2-1",
            "0.0.0.0/0",
            "10.0.0.1/33",
            "::1",
            "abc",
            "10.0.0.1-",
        ] {
            assert!(TargetRange::parse(invalid).is_err(), "{invalid}");
        }
        assert_eq!(TargetRange::parse("10.0.0.0/16").unwrap().len(), 65534);
    }

    #[test]
    fn ports_are_sorted_unique_and_bounded() {
        assert_eq!(
            parse_ports("443, 80, 80, 20-22").unwrap(),
            vec![20, 21, 22, 80, 443]
        );
        assert!(parse_ports("").unwrap().is_empty());
        for invalid in ["0", "65536", "80-1", "0-65535", "1-65536", "80,", "ssh"] {
            assert!(parse_ports(invalid).is_err(), "{invalid}");
        }
    }

    #[test]
    fn full_tcp_range_is_valid_unique_sorted_and_stays_compact() {
        let ports = parse_ports("1-65535,1024,65535,1-1025").unwrap();
        assert_eq!(ports.len(), MAX_PORTS);
        assert_eq!(ports.first(), Some(&1));
        assert_eq!(ports.last(), Some(&65535));
        assert!(ports.windows(2).all(|pair| pair[0] < pair[1]));
        assert_eq!(format_ports(&ports), "1-65535");
        for input in ["", "65535", "1-1025", "80,443,8000-8002,65534-65535"] {
            let ports = parse_ports(input).unwrap();
            assert_eq!(parse_ports(&format_ports(&ports)).unwrap(), ports);
        }
    }
}
