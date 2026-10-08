use crate::{discovery::Snapshot, targets::TargetRange};
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, time::Duration};
use tokio_util::sync::CancellationToken;

mod llmnr;
mod ssdp;
mod transport;
mod vendor;

pub use llmnr::llmnr;
#[cfg(test)]
use llmnr::{llmnr_at, parse_llmnr};
use ssdp::enrich_upnp;
#[cfg(test)]
use ssdp::{parse_description, parse_ssdp, safe_location};
use transport::{Kind, udp_on};
#[cfg(test)]
use transport::{broadcast_for, receive};
#[cfg(test)]
use vendor::{parse_mndp, parse_ubiquiti};
const MAX_HOSTS: usize = 2048;
const MAX_ITEMS: usize = 16;
const MAX_PACKETS: usize = 8192;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Options {
    pub ssdp: bool,
    pub mndp: bool,
    pub ubiquiti: bool,
}

impl Options {
    pub fn enabled(self) -> bool {
        self.ssdp || self.mndp || self.ubiquiti
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Advertisements {
    pub ssdp: Vec<UpnpDevice>,
    pub mndp: Vec<VendorDevice>,
    pub ubiquiti: Vec<VendorDevice>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpnpDevice {
    pub usn: String,
    pub device_type: String,
    pub server: String,
    pub location: String,
    pub name: String,
    pub manufacturer: String,
    pub model: String,
}

impl UpnpDevice {
    pub fn summary(&self) -> String {
        [
            self.name.as_str(),
            &self.manufacturer,
            &self.model,
            &self.server,
            &self.device_type,
            &self.usn,
            &self.location,
        ]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" | ")
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorDevice {
    pub name: String,
    pub model: String,
    pub firmware: String,
    pub platform: String,
    pub interface: String,
    pub mac: String,
}

impl VendorDevice {
    pub fn summary(&self) -> String {
        [
            &self.name,
            &self.model,
            &self.firmware,
            &self.platform,
            &self.interface,
            &self.mac,
        ]
        .into_iter()
        .filter(|s| !s.is_empty())
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(" | ")
    }
}

pub(crate) fn clean(value: &str) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(256)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn text(bytes: &[u8]) -> String {
    clean(&String::from_utf8_lossy(bytes))
}
fn in_range(ip: Ipv4Addr, targets: &TargetRange) -> bool {
    (targets.first..=targets.last).contains(&u32::from(ip))
}

fn push_unique<T: PartialEq>(items: &mut Vec<T>, item: T) {
    if items.len() < MAX_ITEMS && !items.contains(&item) {
        items.push(item);
    }
}

fn merge(target: &mut Snapshot, other: Snapshot) {
    for (ip, info) in other.hosts {
        if target.hosts.len() >= MAX_HOSTS && !target.hosts.contains_key(&ip) {
            continue;
        }
        let ads = &mut target.hosts.entry(ip).or_default().advertisements;
        for item in info.advertisements.ssdp {
            push_unique(&mut ads.ssdp, item);
        }
        for item in info.advertisements.mndp {
            push_unique(&mut ads.mndp, item);
        }
        for item in info.advertisements.ubiquiti {
            push_unique(&mut ads.ubiquiti, item);
        }
    }
    target.warnings.extend(other.warnings);
}

pub async fn collect(
    targets: &TargetRange,
    interfaces: &[Ipv4Addr],
    options: Options,
    budget: Duration,
    cancel: &CancellationToken,
) -> Snapshot {
    if !options.enabled() || cancel.is_cancelled() {
        return Snapshot::default();
    }
    if interfaces.is_empty() {
        return Snapshot {
            warnings: vec![
                "Local advertisements: no directly connected IPv4 network overlaps the scan range"
                    .into(),
            ],
            ..Default::default()
        };
    }
    let udp = async {
        let jobs = interfaces.iter().copied().flat_map(|ip| {
            [Kind::Ssdp, Kind::Ubiquiti]
                .into_iter()
                .filter(move |kind| match kind {
                    Kind::Ssdp => options.ssdp,
                    Kind::Ubiquiti => options.ubiquiti,
                    Kind::Mndp => false,
                })
                .map(move |kind| (ip, kind))
        });
        stream::iter(jobs)
            .map(|(ip, kind)| udp_on(ip, kind, targets, budget, cancel))
            .buffer_unordered(16)
            .collect::<Vec<_>>()
            .await
    };
    let mndp = async {
        if options.mndp {
            udp_on(Ipv4Addr::UNSPECIFIED, Kind::Mndp, targets, budget, cancel).await
        } else {
            Snapshot::default()
        }
    };
    let (udp, mndp) = futures_util::future::join(udp, mndp).await;
    let mut snapshot = Snapshot::default();
    for result in udp {
        merge(&mut snapshot, result);
    }
    merge(&mut snapshot, mndp);
    if options.ssdp && !cancel.is_cancelled() {
        enrich_upnp(&mut snapshot, cancel).await;
    }
    snapshot
}

#[cfg(test)]
mod tests;
