use super::{hostname::DnsResolver, model::*, probes::TcpProber};
use crate::network;
use std::{collections::HashMap, net::Ipv4Addr, sync::OnceLock, time::Duration};
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
        let mut table = HashMap::new();
        for (bits, data) in [
            (24, include_bytes!("../../assets/oui.csv").as_slice()),
            (28, include_bytes!("../../assets/mam.csv").as_slice()),
            (36, include_bytes!("../../assets/oui36.csv").as_slice()),
        ] {
            let mut reader = csv::Reader::from_reader(data);
            for record in reader.records().flatten() {
                if let (Some(prefix), Some(name)) = (record.get(1), record.get(2))
                    && let Ok(prefix) = u64::from_str_radix(prefix, 16)
                {
                    table.insert((bits, prefix), name.to_owned());
                }
            }
        }
        table
    })
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
