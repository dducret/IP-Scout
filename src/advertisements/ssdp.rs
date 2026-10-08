use super::{UpnpDevice, clean};
use crate::discovery::{self, Snapshot};
use futures_util::{StreamExt, stream};
use std::collections::HashMap;
use std::{net::Ipv4Addr, time::Duration};
use tokio_util::sync::CancellationToken;

pub(super) fn safe_location(location: &str, peer: Ipv4Addr) -> Option<String> {
    if location.len() > 2048 {
        return None;
    }
    let url = reqwest::Url::parse(location).ok()?;
    (matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
        && url.host_str()?.parse::<Ipv4Addr>().ok()? == peer)
        .then(|| url.to_string())
}

pub(super) fn parse_ssdp(data: &[u8], peer: Ipv4Addr) -> Option<UpnpDevice> {
    if data.len() > 16_384 {
        return None;
    }
    let data = std::str::from_utf8(data).ok()?;
    if !data.contains("\r\n\r\n") {
        return None;
    }
    let mut lines = data.split("\r\n");
    if lines.next()? != "HTTP/1.1 200 OK" {
        return None;
    }
    let mut headers = HashMap::new();
    for line in lines.take(64) {
        if line.is_empty() {
            break;
        }
        let (key, value) = line.split_once(':')?;
        if headers
            .insert(key.trim().to_ascii_lowercase(), value.trim())
            .is_some()
        {
            return None;
        }
    }
    let usn = headers.get("usn")?;
    let device_type = headers.get("st")?;
    if usn.is_empty() || device_type.is_empty() {
        return None;
    }
    Some(UpnpDevice {
        usn: clean(usn),
        device_type: clean(device_type),
        server: clean(headers.get("server").unwrap_or(&"")),
        location: headers
            .get("location")
            .and_then(|url| safe_location(url, peer))
            .unwrap_or_default(),
        ..Default::default()
    })
}

pub(super) async fn enrich_upnp(snapshot: &mut Snapshot, cancel: &CancellationToken) {
    if !snapshot.hosts.values().any(|info| {
        info.advertisements
            .ssdp
            .iter()
            .any(|device| !device.location.is_empty())
    }) {
        return;
    }
    let Ok(client) = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_millis(800))
        .user_agent(concat!("IP-Scout/", env!("CARGO_PKG_VERSION")))
        .build()
    else {
        return;
    };
    let mut locations: HashMap<String, Vec<(Ipv4Addr, usize)>> = HashMap::new();
    for (&ip, info) in &snapshot.hosts {
        for (index, device) in info.advertisements.ssdp.iter().enumerate() {
            if device.location.is_empty()
                || locations.len() >= 128 && !locations.contains_key(&device.location)
            {
                continue;
            }
            locations
                .entry(device.location.clone())
                .or_default()
                .push((ip, index));
        }
    }
    let work = stream::iter(locations.keys().cloned().collect::<Vec<_>>())
        .map(|url| {
            let client = &client;
            async move {
                let result = async {
                    let mut response = client.get(&url).send().await.ok()?;
                    if !response.status().is_success()
                        || response.content_length().is_some_and(|n| n > 16_384)
                    {
                        return None;
                    }
                    let mut body = Vec::new();
                    while let Some(chunk) = response.chunk().await.ok()? {
                        if body.len() + chunk.len() > 16_384 {
                            return None;
                        }
                        body.extend_from_slice(&chunk);
                    }
                    parse_description(&body)
                }
                .await;
                (url, result)
            }
        })
        .buffer_unordered(16);
    let mut work = std::pin::pin!(work);
    let apply = async {
        while let Some((url, result)) = work.next().await {
            let Some((name, manufacturer, model)) = result else {
                continue;
            };
            if let Some(devices) = locations.get(&url) {
                for &(ip, index) in devices {
                    if let Some(device) = snapshot
                        .hosts
                        .get_mut(&ip)
                        .and_then(|info| info.advertisements.ssdp.get_mut(index))
                    {
                        device.name.clone_from(&name);
                        device.manufacturer.clone_from(&manufacturer);
                        device.model.clone_from(&model);
                    }
                }
            }
        }
    };
    let _ = cancel
        .run_until_cancelled(tokio::time::timeout(Duration::from_secs(2), apply))
        .await;
}

pub(super) fn parse_description(data: &[u8]) -> Option<(String, String, String)> {
    let root = discovery::parse_xml(data)?;
    let ns = "urn:schemas-upnp-org:device-1-0";
    if root.name != "root" || root.ns != ns {
        return None;
    }
    let device = root.child(ns, "device")?;
    let value = |field| {
        device
            .child(ns, field)
            .map(|node| clean(&node.text))
            .unwrap_or_default()
    };
    Some((
        value("friendlyName"),
        value("manufacturer"),
        value("modelName"),
    ))
}
