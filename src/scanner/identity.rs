use super::{hostname::DnsResolver, model::*, probes::TcpProber};
use crate::network;
use std::{
    collections::HashMap,
    io::{self, Read},
    net::Ipv4Addr,
    sync::OnceLock,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Default, Clone)]
pub(super) struct Identity {
    pub(super) hostname: String,
    pub(super) mac: String,
    pub(super) vendor: String,
    pub(super) probable_brand: String,
}

pub(super) fn identity(
    ip: Ipv4Addr,
    options: &ScanOptions,
    resolver: Option<&DnsResolver>,
    prober: &TcpProber,
    cancel: &CancellationToken,
) -> Identity {
    prober.runtime.block_on(identity_async(
        ip,
        options,
        resolver,
        !prober.routed(ip),
        cancel,
    ))
}

pub(super) async fn identity_async(
    ip: Ipv4Addr,
    options: &ScanOptions,
    resolver: Option<&DnsResolver>,
    on_link: bool,
    cancel: &CancellationToken,
) -> Identity {
    let mut result = Identity::default();
    if cancel.is_cancelled() {
        return result;
    }
    // Read the local neighbor table before waiting for name resolution.
    let mac = (options.fetch_mac && on_link)
        .then(|| network::mac_address(ip))
        .flatten();
    if let Some(resolver) = resolver {
        result.hostname = resolver.host_name(ip, cancel).await.unwrap_or_default();
    } else if options.resolve_names {
        result.hostname = cancel
            .run_until_cancelled(tokio::time::timeout(
                Duration::from_millis(u64::from(options.timeout_ms.max(1000))),
                network::native_hostname(ip, cancel),
            ))
            .await
            .and_then(Result::ok)
            .flatten()
            .unwrap_or_default();
    }
    if let Some(mac) = mac {
        result.mac = network::format_mac(mac);
        if options.fetch_vendor {
            result.vendor = vendor(mac).unwrap_or_default().to_owned();
            if result.vendor.is_empty() {
                result.probable_brand = probable_brand(mac, &result.hostname);
            }
        }
    }
    result
}

pub(super) fn apply_identity(host: &mut HostResult, identity: Identity) {
    if !identity.hostname.is_empty() {
        host.hostname = identity.hostname;
    }
    if !identity.mac.is_empty() {
        host.mac = identity.mac;
    }
    if !identity.vendor.is_empty() {
        host.vendor = identity.vendor;
    }
    if !identity.probable_brand.is_empty() {
        host.probable_brand = identity.probable_brand;
    }
}

pub(super) fn is_alive(ping: Option<f64>, open: &[u16], refused: usize, arp: bool) -> bool {
    ping.is_some() || !open.is_empty() || refused > 0 || arp
}

pub(super) fn vendors() -> &'static HashMap<(u8, u64), String> {
    static VENDORS: OnceLock<HashMap<(u8, u64), String>> = OnceLock::new();
    VENDORS.get_or_init(|| {
        decode_vendors(include_bytes!(concat!(
            env!("OUT_DIR"),
            "/ieee-vendors.zlib"
        )))
        .expect("the build-time IEEE registry must be valid")
    })
}

fn decode_vendors(data: &[u8]) -> io::Result<HashMap<(u8, u64), String>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid embedded IEEE registry");
    let mut input = flate2::read::ZlibDecoder::new(data);
    let mut header = [0u8; 12];
    input.read_exact(&mut header)?;
    if &header[..8] != b"IPSCIE01" {
        return Err(invalid());
    }
    let count = u32::from_be_bytes(header[8..].try_into().unwrap()) as usize;
    if count > 1_000_000 {
        return Err(invalid());
    }
    let mut table = HashMap::with_capacity(count);
    for _ in 0..count {
        let mut entry = [0u8; 13];
        input.read_exact(&mut entry)?;
        let bits = entry[0];
        let prefix = u64::from_be_bytes(entry[1..9].try_into().unwrap());
        let length = u32::from_be_bytes(entry[9..13].try_into().unwrap()) as usize;
        if !matches!(bits, 24 | 28 | 36) || prefix >= 1u64 << bits || length > 16_384 {
            return Err(invalid());
        }
        let mut name = vec![0; length];
        input.read_exact(&mut name)?;
        let name = String::from_utf8(name).map_err(|_| invalid())?;
        if table.insert((bits, prefix), name).is_some() {
            return Err(invalid());
        }
    }
    // Consume the stream to validate its checksum and reject extra decoded records.
    if input.read(&mut [0])? != 0 {
        return Err(invalid());
    }
    Ok(table)
}

pub(super) fn vendor(mac: [u8; 6]) -> Option<&'static str> {
    if mac[0] & 0x02 != 0 {
        return None;
    }
    lookup_vendor(mac, vendors())
}

pub(super) fn lookup_vendor(mac: [u8; 6], table: &HashMap<(u8, u64), String>) -> Option<&str> {
    let value = u64::from_be_bytes([0, 0, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]]);
    [36, 28, 24]
        .into_iter()
        .find_map(|bits| table.get(&(bits, value >> (48 - bits))).map(String::as_str))
}

pub(super) fn probable_brand(mac: [u8; 6], hostname: &str) -> String {
    let name = hostname.to_ascii_lowercase();
    let label = name.split('.').next().unwrap_or_default();
    let brand = [
        (
            "Samsung",
            &["samsung", "galaxy-s", "galaxy-a", "galaxy-z", "galaxy-note"][..],
        ),
        ("Apple", &["iphone", "ipad", "macbook"][..]),
        ("Xiaomi", &["xiaomi", "redmi"][..]),
        ("Huawei", &["huawei"][..]),
    ]
    .into_iter()
    .find_map(|(brand, prefixes)| {
        prefixes
            .iter()
            .any(|prefix| {
                label == *prefix
                    || label.strip_prefix(prefix).is_some_and(|suffix| {
                        suffix.starts_with('-')
                            || suffix.starts_with('_')
                            || suffix.starts_with(|c: char| c.is_ascii_digit())
                    })
            })
            .then_some(brand)
    });
    match brand {
        Some(brand) => format!("{brand} (hostname hint, unverified)"),
        None if mac[0] & 2 != 0 => "Unknown (randomized/local MAC)".into(),
        None => "Unknown (MAC assignment not listed)".into(),
    }
}

#[cfg(test)]
mod asset_tests {
    use super::*;

    #[test]
    fn compact_registry_matches_every_original_ieee_entry() {
        // Recreate the previous reader independently, including its duplicate handling.
        let mut original = HashMap::new();
        let mut counts = Vec::new();
        for (bits, data) in [
            (24, include_bytes!("../../assets/oui.csv").as_slice()),
            (28, include_bytes!("../../assets/mam.csv").as_slice()),
            (36, include_bytes!("../../assets/oui36.csv").as_slice()),
        ] {
            let mut rows = 0;
            for record in csv::Reader::from_reader(data).records() {
                let record = record.unwrap();
                let prefix = u64::from_str_radix(&record[1], 16).unwrap();
                original.insert((bits, prefix), record[2].to_owned());
                rows += 1;
            }
            counts.push((bits, rows));
        }
        assert_eq!(
            vendors(),
            &original,
            "no prefix, Unicode character or organization name may change"
        );
        assert!(counts.iter().all(|&(_, rows)| rows > 1000));
        println!(
            "IEEE lossless comparison: {} unique entries; source rows by prefix: {counts:?}",
            original.len()
        );

        // For every assignment, check both ends of its MAC range against the old lookup,
        // including overlaps where a more specific 28-/36-bit assignment takes priority.
        for &(bits, prefix) in original.keys() {
            let first = prefix << (48 - bits);
            let last = first | ((1u64 << (48 - bits)) - 1);
            for value in [first, last] {
                let mac: [u8; 6] = value.to_be_bytes()[2..].try_into().unwrap();
                assert_eq!(lookup_vendor(mac, vendors()), lookup_vendor(mac, &original));
            }
        }
    }

    #[test]
    fn compact_registry_rejects_incomplete_or_invalid_records() {
        fn compressed(bytes: &[u8]) -> Vec<u8> {
            use std::io::Write;
            let mut output =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
            output.write_all(bytes).unwrap();
            output.finish().unwrap()
        }
        let data = include_bytes!(concat!(env!("OUT_DIR"), "/ieee-vendors.zlib"));
        assert!(decode_vendors(&data[..data.len() / 2]).is_err());
        assert!(decode_vendors(&compressed(b"wrong format")).is_err());
        let mut unfinished = b"IPSCIE01".to_vec();
        unfinished.extend_from_slice(&1u32.to_be_bytes());
        assert!(decode_vendors(&compressed(&unfinished)).is_err());
        let mut empty = b"IPSCIE01".to_vec();
        empty.extend_from_slice(&0u32.to_be_bytes());
        assert!(decode_vendors(&compressed(&empty)).unwrap().is_empty());
        empty.push(0);
        assert!(decode_vendors(&compressed(&empty)).is_err());
    }
}
