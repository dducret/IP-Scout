use std::{collections::BTreeSet, net::Ipv4Addr};

pub const MAX_HOSTS: usize = 65_536;
pub const MAX_PORTS: usize = u16::MAX as usize;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRange {
    pub first: u32,
    pub last: u32,
}

impl TargetRange {
    pub fn parse(input: &str) -> Result<Self, String> {
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
            if prefix < 31 {
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
        if u64::from(last) - u64::from(first) + 1 > MAX_HOSTS as u64 {
            return Err(format!("Choose a range with at most {MAX_HOSTS} addresses"));
        }
        Ok(Self { first, last })
    }

    pub fn len(&self) -> usize {
        (u64::from(self.last) - u64::from(self.first) + 1) as usize
    }

    pub fn is_empty(&self) -> bool {
        self.first > self.last
    }
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
