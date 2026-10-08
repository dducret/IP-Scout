use crate::{network::LocalNetwork, targets::TargetRange};
use futures_util::{StreamExt, stream};
use mdns_sd::{DaemonEvent, IfKind, ResolvedService, ServiceDaemon, ServiceEvent};
use quick_xml::{NsReader, events::Event, name::ResolveResult};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

const MAX_HOSTS: usize = 2048;
const MAX_SERVICES: usize = 16;
const MAX_TYPES: usize = 32;
const META_TYPE: &str = "_services._dns-sd._udp.local.";
const SOAP: &str = "http://www.w3.org/2003/05/soap-envelope";
const DISCOVERY_2005: &str = "http://schemas.xmlsoap.org/ws/2005/04/discovery";
const DISCOVERY_2009: &str = "http://docs.oasis-open.org/ws-dd/ns/discovery/2009/01";
const ADDRESSING_2004: &str = "http://schemas.xmlsoap.org/ws/2004/08/addressing";
const ADDRESSING_2005: &str = "http://www.w3.org/2005/08/addressing";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BonjourService {
    pub instance: String,
    pub service_type: String,
    pub hostname: String,
    pub port: u16,
    pub properties: Vec<String>,
}

impl BonjourService {
    pub fn summary(&self) -> String {
        let mut text = format!(
            "{} [{}] {}:{}",
            self.instance, self.service_type, self.hostname, self.port
        );
        if !self.properties.is_empty() {
            text.push_str(&format!(" ({})", self.properties.join(", ")));
        }
        text
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WsdDevice {
    pub endpoint: String,
    pub types: Vec<String>,
    pub scopes: Vec<String>,
    pub addresses: Vec<String>,
}

impl WsdDevice {
    pub fn summary(&self) -> String {
        let mut parts = self.types.clone();
        if !self.endpoint.is_empty() {
            parts.push(self.endpoint.clone());
        }
        parts.extend(self.scopes.iter().cloned());
        parts.extend(self.addresses.iter().cloned());
        parts.join(" | ")
    }
}

#[derive(Debug, Clone, Default)]
pub struct LocalInfo {
    pub bonjour: Vec<BonjourService>,
    pub wsd: Vec<WsdDevice>,
    pub advertisements: crate::advertisements::Advertisements,
}

#[derive(Default)]
pub struct Snapshot {
    pub hosts: HashMap<Ipv4Addr, LocalInfo>,
    pub warnings: Vec<String>,
}

fn in_range(ip: Ipv4Addr, targets: &TargetRange) -> bool {
    let ip = u32::from(ip);
    (targets.first..=targets.last).contains(&ip)
}

pub fn interfaces_for(networks: &[LocalNetwork], targets: &TargetRange) -> Vec<Ipv4Addr> {
    let mut addresses = Vec::new();
    for network in networks {
        let Some((base, prefix)) = network.cidr.split_once('/') else {
            continue;
        };
        let (Ok(base), Ok(prefix)) = (base.parse::<Ipv4Addr>(), prefix.parse::<u32>()) else {
            continue;
        };
        if prefix > 32 {
            continue;
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let first = u32::from(base) & mask;
        let last = first | !mask;
        if targets.first <= last && targets.last >= first && !addresses.contains(&network.address) {
            addresses.push(network.address);
        }
    }
    addresses.truncate(8);
    addresses
}

pub async fn collect(
    targets: &TargetRange,
    interfaces: &[Ipv4Addr],
    bonjour: bool,
    wsd: bool,
    budget: Duration,
    cancel: &CancellationToken,
) -> Snapshot {
    if (!bonjour && !wsd) || cancel.is_cancelled() {
        return Snapshot::default();
    }
    if interfaces.is_empty() {
        return Snapshot {
            warnings: vec![
                "Bonjour/WSD: no directly connected IPv4 network overlaps the scan range".into(),
            ],
            ..Default::default()
        };
    }
    let (mut mdns, ws) = futures_util::future::join(
        async {
            if bonjour {
                collect_bonjour(targets, interfaces, budget, cancel).await
            } else {
                Snapshot::default()
            }
        },
        async {
            if wsd {
                collect_wsd(targets, interfaces, budget, cancel).await
            } else {
                Snapshot::default()
            }
        },
    )
    .await;
    for (ip, info) in ws.hosts {
        if mdns.hosts.len() < MAX_HOSTS || mdns.hosts.contains_key(&ip) {
            mdns.hosts.entry(ip).or_default().wsd = info.wsd;
        }
    }
    mdns.warnings.extend(ws.warnings);
    mdns
}

struct MdnsGuard(ServiceDaemon);

impl Drop for MdnsGuard {
    fn drop(&mut self) {
        // Handles do not stop the library's thread automatically.
        let _ = self.0.shutdown();
    }
}

fn add_bonjour(snapshot: &mut Snapshot, service: &ResolvedService, targets: &TargetRange) {
    let hostname = clean(service.get_hostname().trim_end_matches('.'), 256);
    let instance = service
        .get_fullname()
        .strip_suffix(&service.ty_domain)
        .unwrap_or(service.get_fullname())
        .trim_end_matches('.');
    let mut properties = Vec::new();
    // Do not retain arbitrary TXT records: they can contain credentials or tokens.
    for key in ["model", "ty", "product", "manufacturer", "note"] {
        if let Some(value) = service.get_property_val_str(key) {
            let value = clean(value, 128);
            if !value.is_empty() {
                properties.push(format!("{key}={value}"));
            }
        }
    }
    let value = BonjourService {
        instance: clean(instance, 256),
        service_type: clean(&service.ty_domain, 128),
        hostname,
        port: service.get_port(),
        properties,
    };
    let addresses = service.get_addresses_v4();
    for (ip, info) in &mut snapshot.hosts {
        if !addresses.contains(ip) {
            info.bonjour.retain(|old| {
                old.instance != value.instance || old.service_type != value.service_type
            });
        }
    }
    snapshot
        .hosts
        .retain(|_, info| !info.bonjour.is_empty() || !info.wsd.is_empty());
    for ip in addresses {
        if !in_range(ip, targets)
            || (snapshot.hosts.len() >= MAX_HOSTS && !snapshot.hosts.contains_key(&ip))
        {
            continue;
        }
        let services = &mut snapshot.hosts.entry(ip).or_default().bonjour;
        if let Some(old) = services
            .iter_mut()
            .find(|old| old.instance == value.instance && old.service_type == value.service_type)
        {
            *old = value.clone();
        } else if services.len() < MAX_SERVICES {
            services.push(value.clone());
        }
        services
            .sort_by(|a, b| (&a.service_type, &a.instance).cmp(&(&b.service_type, &b.instance)));
    }
}

async fn collect_bonjour(
    targets: &TargetRange,
    interfaces: &[Ipv4Addr],
    budget: Duration,
    cancel: &CancellationToken,
) -> Snapshot {
    match ServiceDaemon::new() {
        Ok(daemon) => collect_bonjour_on(daemon, targets, interfaces, budget, cancel).await,
        Err(error) => Snapshot {
            warnings: vec![format!("Bonjour unavailable: {error}")],
            ..Default::default()
        },
    }
}

async fn collect_bonjour_on(
    daemon: ServiceDaemon,
    targets: &TargetRange,
    interfaces: &[Ipv4Addr],
    budget: Duration,
    cancel: &CancellationToken,
) -> Snapshot {
    let mut snapshot = Snapshot::default();
    let daemon = MdnsGuard(daemon);
    let setup = (|| {
        daemon.0.disable_interface(IfKind::All)?;
        for ip in interfaces {
            daemon.0.enable_interface(IpAddr::V4(*ip))?;
        }
        daemon.0.disable_interface(IfKind::IPv6)?;
        daemon.0.set_ip_check_interval(0)?;
        daemon.0.monitor()
    })();
    let monitor = match setup {
        Ok(monitor) => monitor,
        Err(error) => {
            snapshot
                .warnings
                .push(format!("Bonjour setup failed: {error}"));
            return snapshot;
        }
    };
    let mut receivers = Vec::new();
    for kind in [
        META_TYPE,
        "_airplay._tcp.local.",
        "_raop._tcp.local.",
        "_ipp._tcp.local.",
        "_ipps._tcp.local.",
        "_printer._tcp.local.",
        "_http._tcp.local.",
        "_https._tcp.local.",
        "_smb._tcp.local.",
        "_workstation._tcp.local.",
        "_device-info._tcp.local.",
        "_googlecast._tcp.local.",
        "_ssh._tcp.local.",
        "_rfb._tcp.local.",
        "_scanner._tcp.local.",
        "_uscan._tcp.local.",
    ] {
        if let Ok(receiver) = daemon.0.browse(kind) {
            receivers.push((kind.to_owned(), receiver));
        }
    }
    let work = async {
        loop {
            let mut new_types = Vec::new();
            for (kind, receiver) in &receivers {
                for _ in 0..32 {
                    let Ok(event) = receiver.try_recv() else {
                        break;
                    };
                    match event {
                        ServiceEvent::ServiceFound(_, fullname) if kind == META_TYPE => {
                            if fullname.len() <= 128
                                && (fullname.ends_with("._tcp.local.")
                                    || fullname.ends_with("._udp.local."))
                            {
                                new_types.push(fullname);
                            }
                        }
                        ServiceEvent::ServiceResolved(service) => {
                            add_bonjour(&mut snapshot, &service, targets)
                        }
                        ServiceEvent::ServiceRemoved(_, fullname) => {
                            for info in snapshot.hosts.values_mut() {
                                info.bonjour.retain(|service| {
                                    format!("{}.{}", service.instance, service.service_type)
                                        != fullname
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
            for kind in new_types {
                if receivers.len() < MAX_TYPES
                    && !receivers.iter().any(|(old, _)| old == &kind)
                    && let Ok(receiver) = daemon.0.browse(&kind)
                {
                    receivers.push((kind, receiver));
                }
            }
            for _ in 0..8 {
                let Ok(event) = monitor.try_recv() else {
                    break;
                };
                if let DaemonEvent::Error(error) = event {
                    let warning = format!("Bonjour: {error}");
                    if snapshot.warnings.len() < 8 && !snapshot.warnings.contains(&warning) {
                        snapshot.warnings.push(warning);
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    let _ = cancel
        .run_until_cancelled(tokio::time::timeout(budget, work))
        .await;
    snapshot
}

fn clean(value: &str, limit: usize) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(limit)
        .collect::<String>()
        .trim()
        .to_owned()
}

#[derive(Debug)]
pub(crate) struct XmlNode {
    pub(crate) ns: String,
    pub(crate) name: String,
    pub(crate) text: String,
    pub(crate) children: Vec<XmlNode>,
}

impl XmlNode {
    pub(crate) fn child(&self, ns: &str, name: &str) -> Option<&Self> {
        let mut matches = self
            .children
            .iter()
            .filter(|node| node.ns == ns && node.name == name);
        let first = matches.next()?;
        matches.next().is_none().then_some(first)
    }
}

pub(crate) fn parse_xml(bytes: &[u8]) -> Option<XmlNode> {
    if bytes.len() > 16_384 {
        return None;
    }
    let mut reader = NsReader::from_reader(bytes);
    let mut stack: Vec<XmlNode> = Vec::new();
    let mut root = None;
    let mut count = 0;
    loop {
        let (namespace, event) = reader.read_resolved_event().ok()?;
        let empty = matches!(&event, Event::Empty(_));
        match event {
            Event::Start(start) | Event::Empty(start) => {
                let ns = match namespace {
                    ResolveResult::Bound(ns) => std::str::from_utf8(ns.as_ref()).ok()?.to_owned(),
                    ResolveResult::Unbound => String::new(),
                    ResolveResult::Unknown(_) => return None,
                };
                for attribute in start.attributes() {
                    attribute.ok()?;
                }
                count += 1;
                if count > 512 || stack.len() >= 24 {
                    return None;
                }
                let node = XmlNode {
                    ns,
                    name: std::str::from_utf8(start.local_name().as_ref())
                        .ok()?
                        .to_owned(),
                    text: String::new(),
                    children: Vec::new(),
                };
                if empty {
                    if let Some(parent) = stack.last_mut() {
                        parent.children.push(node);
                    } else if root.replace(node).is_some() {
                        return None;
                    }
                } else {
                    stack.push(node);
                }
            }
            Event::End(_) => {
                let node = stack.pop()?;
                if let Some(parent) = stack.last_mut() {
                    parent.children.push(node);
                } else if root.replace(node).is_some() {
                    return None;
                }
            }
            Event::Text(text) => {
                let text = text.xml_content().ok()?;
                if let Some(node) = stack.last_mut() {
                    node.text.push_str(&text);
                } else if !text.trim().is_empty() {
                    return None;
                }
            }
            Event::CData(text) => {
                stack.last_mut()?.text.push_str(&text.xml_content().ok()?);
            }
            Event::GeneralRef(reference) => {
                let entity = format!("&{};", reference.decode().ok()?);
                stack
                    .last_mut()?
                    .text
                    .push_str(&quick_xml::escape::unescape(&entity).ok()?);
            }
            Event::DocType(_) | Event::PI(_) => return None,
            Event::Eof => return stack.is_empty().then_some(root).flatten(),
            _ => {}
        }
    }
}

fn words(node: Option<&XmlNode>) -> Vec<String> {
    node.map(|node| {
        node.text
            .split_whitespace()
            .take(16)
            .map(|word| clean(word, 512))
            .collect()
    })
    .unwrap_or_default()
}

fn parse_wsd(bytes: &[u8], peer: Ipv4Addr, ids: &[String]) -> Option<Vec<WsdDevice>> {
    let envelope = parse_xml(bytes)?;
    if envelope.ns != SOAP || envelope.name != "Envelope" {
        return None;
    }
    let header = envelope.child(SOAP, "Header")?;
    let body = envelope.child(SOAP, "Body")?;
    let mut selected = None;
    for (discovery, addressing) in [
        (DISCOVERY_2005, ADDRESSING_2004),
        (DISCOVERY_2009, ADDRESSING_2005),
    ] {
        if header
            .child(addressing, "Action")
            .is_some_and(|node| node.text.trim() == format!("{discovery}/ProbeMatches"))
            && header
                .child(addressing, "RelatesTo")
                .is_some_and(|node| ids.iter().any(|id| id == node.text.trim()))
        {
            selected = Some((discovery, addressing));
            break;
        }
    }
    let (discovery, addressing) = selected?;
    let matches = body.child(discovery, "ProbeMatches")?;
    let mut devices = Vec::new();
    for node in matches
        .children
        .iter()
        .filter(|node| node.ns == discovery && node.name == "ProbeMatch")
        .take(8)
    {
        let endpoint = clean(
            &node
                .child(addressing, "EndpointReference")?
                .child(addressing, "Address")?
                .text,
            256,
        );
        if endpoint.is_empty() {
            continue;
        }
        let addresses = words(node.child(discovery, "XAddrs"))
            .into_iter()
            .filter(|address| {
                reqwest::Url::parse(address).ok().is_some_and(|url| {
                    matches!(url.scheme(), "http" | "https")
                        && url.username().is_empty()
                        && url.password().is_none()
                        && url
                            .host_str()
                            .and_then(|host| host.parse::<Ipv4Addr>().ok())
                            == Some(peer)
                })
            })
            .collect();
        let device = WsdDevice {
            endpoint,
            types: words(node.child(discovery, "Types")),
            scopes: words(node.child(discovery, "Scopes")),
            addresses,
        };
        if !devices.contains(&device) {
            devices.push(device);
        }
    }
    Some(devices)
}

fn probes() -> Vec<(String, String)> {
    let mut messages = Vec::new();
    for (d, a, to, anonymous, types) in [
        (
            DISCOVERY_2005,
            ADDRESSING_2004,
            "urn:schemas-xmlsoap-org:ws:2005:04:discovery",
            "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous",
            &[
                ("http://schemas.xmlsoap.org/ws/2006/02/devprof", "Device"),
                (
                    "http://schemas.microsoft.com/windows/pub/2005/07",
                    "Computer",
                ),
                (
                    "http://www.onvif.org/ver10/network/wsdl",
                    "NetworkVideoTransmitter",
                ),
            ][..],
        ),
        (
            DISCOVERY_2009,
            ADDRESSING_2005,
            "urn:docs-oasis-open-org:ws-dd:ns:discovery:2009:01",
            "http://www.w3.org/2005/08/addressing/anonymous",
            &[
                ("http://docs.oasis-open.org/ws-dd/ns/dpws/2009/01", "Device"),
                (
                    "http://www.onvif.org/ver10/network/wsdl",
                    "NetworkVideoTransmitter",
                ),
            ][..],
        ),
    ] {
        for (namespace, kind) in types {
            let id = format!("urn:uuid:{}", uuid::Uuid::new_v4());
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="{SOAP}" xmlns:a="{a}" xmlns:d="{d}" xmlns:t="{namespace}"><s:Header><a:MessageID>{id}</a:MessageID><a:To>{to}</a:To><a:Action>{d}/Probe</a:Action><a:ReplyTo><a:Address>{anonymous}</a:Address></a:ReplyTo></s:Header><s:Body><d:Probe><d:Types>t:{kind}</d:Types></d:Probe></s:Body></s:Envelope>"#
            );
            messages.push((id, xml));
        }
    }
    messages
}

async fn wsd_on_interface(
    ip: Ipv4Addr,
    targets: &TargetRange,
    budget: Duration,
    cancel: &CancellationToken,
) -> Snapshot {
    let mut snapshot = Snapshot::default();
    let socket = (|| -> std::io::Result<tokio::net::UdpSocket> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        socket.bind(&SocketAddr::from((ip, 0)).into())?;
        socket.set_multicast_if_v4(&ip)?;
        socket.set_multicast_ttl_v4(1)?;
        socket.set_nonblocking(true)?;
        tokio::net::UdpSocket::from_std(socket.into())
    })();
    let socket = match socket {
        Ok(socket) => socket,
        Err(error) => {
            snapshot.warnings.push(format!("WSD on {ip}: {error}"));
            return snapshot;
        }
    };
    let messages = probes();
    let ids = messages
        .iter()
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    let work = async {
        for (_, xml) in &messages {
            if let Err(error) = socket.send_to(xml.as_bytes(), "239.255.255.250:3702").await {
                snapshot.warnings.push(format!("WSD on {ip}: {error}"));
                return;
            }
        }
        receive_wsd(&socket, targets, &ids, &mut snapshot).await;
    };
    let _ = cancel
        .run_until_cancelled(tokio::time::timeout(budget, work))
        .await;
    snapshot
}

async fn receive_wsd(
    socket: &tokio::net::UdpSocket,
    targets: &TargetRange,
    ids: &[String],
    snapshot: &mut Snapshot,
) {
    let mut bytes = [0u8; 16_385];
    while let Ok((length, peer)) = socket.recv_from(&mut bytes).await {
        let IpAddr::V4(ip) = peer.ip() else {
            continue;
        };
        if !in_range(ip, targets)
            || (snapshot.hosts.len() >= MAX_HOSTS && !snapshot.hosts.contains_key(&ip))
        {
            continue;
        }
        if let Some(devices) =
            parse_wsd(&bytes[..length], ip, ids).filter(|devices| !devices.is_empty())
        {
            let known = &mut snapshot.hosts.entry(ip).or_default().wsd;
            for device in devices {
                if let Some(old) = known.iter_mut().find(|old| old.endpoint == device.endpoint) {
                    *old = device;
                } else if known.len() < 8 {
                    known.push(device);
                }
            }
            known.sort_by(|a, b| a.endpoint.cmp(&b.endpoint));
        }
    }
}

async fn collect_wsd(
    targets: &TargetRange,
    interfaces: &[Ipv4Addr],
    budget: Duration,
    cancel: &CancellationToken,
) -> Snapshot {
    let results = stream::iter(interfaces.iter().copied())
        .map(|ip| wsd_on_interface(ip, targets, budget, cancel))
        .buffer_unordered(8)
        .collect::<Vec<_>>()
        .await;
    let mut snapshot = Snapshot::default();
    for result in results {
        snapshot.warnings.extend(result.warnings);
        for (ip, info) in result.hosts {
            if snapshot.hosts.len() >= MAX_HOSTS && !snapshot.hosts.contains_key(&ip) {
                continue;
            }
            let known = &mut snapshot.hosts.entry(ip).or_default().wsd;
            for device in info.wsd {
                if known.len() < 8 && !known.contains(&device) {
                    known.push(device);
                }
            }
        }
    }
    snapshot
}

#[cfg(test)]
mod tests {
    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    fn wsd_response(id: &str, modern: bool) -> String {
        let (d, a) = if modern {
            (DISCOVERY_2009, ADDRESSING_2005)
        } else {
            (DISCOVERY_2005, ADDRESSING_2004)
        };
        format!(
            r#"<e:Envelope xmlns:e="{SOAP}" xmlns:w="{d}" xmlns:a="{a}" xmlns:p="urn:printer"><e:Header><a:Action>{d}/ProbeMatches</a:Action><a:RelatesTo>{id}</a:RelatesTo></e:Header><e:Body><w:ProbeMatches><w:ProbeMatch><a:EndpointReference><a:Address>urn:uuid:printer-1</a:Address></a:EndpointReference><w:Types>p:Printer p:Device</w:Types><w:Scopes>urn:name:Lab&#32;Printer</w:Scopes><w:XAddrs>http://127.0.0.1:5357/metadata?x=1&amp;y=2 http://192.0.2.99/unsafe http://name.local/ http://user:pass@127.0.0.1/</w:XAddrs><w:MetadataVersion>1</w:MetadataVersion></w:ProbeMatch></w:ProbeMatches></e:Body></e:Envelope>"#
        )
    }

    #[test]
    fn wsd_parses_versions_namespaces_and_validates_reply_correlation_and_addresses() {
        for modern in [false, true] {
            let xml = wsd_response("urn:uuid:test", modern);
            let devices = parse_wsd(
                xml.as_bytes(),
                Ipv4Addr::LOCALHOST,
                &["urn:uuid:test".into()],
            )
            .unwrap();
            assert_eq!(devices.len(), 1);
            assert_eq!(devices[0].types, ["p:Printer", "p:Device"]);
            assert_eq!(devices[0].endpoint, "urn:uuid:printer-1");
            assert_eq!(
                devices[0].addresses,
                ["http://127.0.0.1:5357/metadata?x=1&y=2"]
            );
            assert!(
                parse_wsd(
                    xml.as_bytes(),
                    Ipv4Addr::LOCALHOST,
                    &["urn:uuid:other".into()]
                )
                .is_none()
            );
            let spoof = xml.replace("xmlns:a=", "xmlns:wrong=");
            assert!(
                parse_wsd(
                    spoof.as_bytes(),
                    Ipv4Addr::LOCALHOST,
                    &["urn:uuid:test".into()]
                )
                .is_none()
            );
        }
    }

    #[test]
    fn xml_rejects_truncation_dtds_multiple_roots_and_excessive_depth() {
        let xml = wsd_response("id", false);
        for end in 0..xml.len() {
            assert!(
                parse_wsd(&xml.as_bytes()[..end], Ipv4Addr::LOCALHOST, &["id".into()]).is_none(),
                "Accepted truncated prefix {end}"
            );
        }
        assert!(
            parse_xml(b"<!DOCTYPE a [<!ENTITY file SYSTEM 'file:///secret'>]><a>&file;</a>")
                .is_none()
        );
        assert!(parse_xml(b"<a/><b/>").is_none());
        assert!(parse_xml(b"<a><b></a></b>").is_none());
        assert!(parse_xml(b"<a x='1' x='2'/>").is_none());
        assert!(
            parse_xml(format!("{}{}", "<a>".repeat(25), "</a>".repeat(25)).as_bytes()).is_none()
        );
        assert!(parse_xml(&[b' '; 16_385]).is_none());
        assert!(parse_xml(b"<a/>").is_some());
    }

    #[test]
    fn wsd_probes_are_well_formed_typed_and_have_unique_ids() {
        let messages = probes();
        assert_eq!(messages.len(), 5);
        let mut ids = std::collections::HashSet::new();
        for (id, xml) in messages {
            assert!(ids.insert(id.clone()));
            assert!(uuid::Uuid::parse_str(id.trim_start_matches("urn:uuid:")).is_ok());
            let root = parse_xml(xml.as_bytes()).unwrap();
            assert_eq!(root.ns, SOAP);
            let body = root.child(SOAP, "Body").unwrap();
            assert!(
                body.children[0]
                    .child(&body.children[0].ns, "Types")
                    .is_some_and(|types| !types.text.is_empty())
            );
        }
    }

    #[test]
    fn wsd_udp_collection_matches_sender_and_range_and_deduplicates() {
        runtime().block_on(async {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = socket.local_addr().unwrap();
            let targets = TargetRange::parse("127.0.0.1").unwrap();
            let ids = vec!["test".into()];
            let mut snapshot = Snapshot::default();
            for xml in [
                wsd_response("test", false),
                wsd_response("test", false),
                wsd_response("other", true),
            ] {
                sender.send_to(xml.as_bytes(), address).await.unwrap();
            }
            assert!(
                tokio::time::timeout(
                    Duration::from_millis(50),
                    receive_wsd(&socket, &targets, &ids, &mut snapshot)
                )
                .await
                .is_err()
            );
            assert_eq!(snapshot.hosts[&Ipv4Addr::LOCALHOST].wsd.len(), 1);
            sender
                .send_to(wsd_response("test", false).as_bytes(), address)
                .await
                .unwrap();
            let mut outside = Snapshot::default();
            let targets = TargetRange::parse("192.0.2.1").unwrap();
            let _ = tokio::time::timeout(
                Duration::from_millis(50),
                receive_wsd(&socket, &targets, &ids, &mut outside),
            )
            .await;
            assert!(outside.hosts.is_empty());
        });
    }

    #[test]
    fn bonjour_records_are_bounded_deduplicated_filtered_and_do_not_retain_secrets() {
        let service = mdns_sd::ServiceInfo::new(
            "_ipp._tcp.local.",
            "Lab Printer",
            "printer.local.",
            "192.0.2.4,192.0.2.5,10.0.0.1",
            631,
            &[
                ("ty", "Laser printer"),
                ("model", "Printer 123"),
                ("password", "secret"),
            ][..],
        )
        .unwrap()
        .as_resolved_service();
        let targets = TargetRange::parse("192.0.2.0/24").unwrap();
        let mut snapshot = Snapshot::default();
        for _ in 0..3 {
            add_bonjour(&mut snapshot, &service, &targets);
        }
        assert_eq!(snapshot.hosts.len(), 2);
        let services = &snapshot.hosts[&Ipv4Addr::new(192, 0, 2, 4)].bonjour;
        assert_eq!(services.len(), 1);
        assert_eq!(services[0].instance, "Lab Printer");
        assert_eq!(services[0].port, 631);
        assert_eq!(
            services[0].properties,
            ["model=Printer 123", "ty=Laser printer"]
        );
        assert!(!services[0].summary().contains("secret"));
        for index in 0..100 {
            let mut more = service.clone();
            more.fullname = format!("Printer{index}._ipp._tcp.local.");
            add_bonjour(&mut snapshot, &more, &targets);
        }
        assert_eq!(
            snapshot.hosts[&Ipv4Addr::new(192, 0, 2, 4)].bonjour.len(),
            MAX_SERVICES
        );
    }

    #[test]
    fn discovery_selects_only_overlapping_interfaces_and_skips_disabled_or_cancelled_work() {
        let networks = vec![
            LocalNetwork {
                address: "192.168.1.5".parse().unwrap(),
                cidr: "192.168.1.0/24".into(),
            },
            LocalNetwork {
                address: "10.0.0.5".parse().unwrap(),
                cidr: "10.0.0.0/24".into(),
            },
        ];
        let targets = TargetRange::parse("192.168.1.106").unwrap();
        assert_eq!(
            interfaces_for(&networks, &targets),
            ["192.168.1.5".parse::<Ipv4Addr>().unwrap()]
        );
        let rt = runtime();
        let disabled = rt.block_on(collect(
            &targets,
            &[],
            false,
            false,
            Duration::from_secs(4),
            &CancellationToken::new(),
        ));
        assert!(disabled.hosts.is_empty() && disabled.warnings.is_empty());
        let unavailable = rt.block_on(collect(
            &targets,
            &[],
            true,
            true,
            Duration::from_secs(4),
            &CancellationToken::new(),
        ));
        assert_eq!(unavailable.warnings.len(), 1);
        let cancel = CancellationToken::new();
        cancel.cancel();
        let cancelled = rt.block_on(collect(
            &targets,
            &[Ipv4Addr::LOCALHOST],
            true,
            true,
            Duration::from_secs(4),
            &cancel,
        ));
        assert!(cancelled.hosts.is_empty() && cancelled.warnings.is_empty());
    }

    #[test]
    fn bonjour_resolves_an_actual_service_on_isolated_loopback() {
        // Port 5353 preserves multicast reply semantics. Only loopback is enabled.
        let port = 5353;
        let server = MdnsGuard(ServiceDaemon::new_with_port(port).unwrap());
        server.0.disable_interface(IfKind::All).unwrap();
        server
            .0
            .enable_interface(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .unwrap();
        server.0.disable_interface(IfKind::IPv6).unwrap();
        let service = mdns_sd::ServiceInfo::new(
            "_ipp._tcp.local.",
            "IP Scout test printer",
            "scout-test.local.",
            "127.0.0.1",
            631,
            &[("ty", "Local test printer")][..],
        )
        .unwrap();
        server.0.register(service).unwrap();
        server
            .0
            .register(
                mdns_sd::ServiceInfo::new(
                    "_ip-scout-test._tcp.local.",
                    "Custom test service",
                    "scout-test.local.",
                    "127.0.0.1",
                    9999,
                    &[("model", "Test device")][..],
                )
                .unwrap(),
            )
            .unwrap();
        let client = ServiceDaemon::new_with_port(port).unwrap();
        let snapshot = runtime().block_on(collect_bonjour_on(
            client,
            &TargetRange::parse("127.0.0.1").unwrap(),
            &[Ipv4Addr::LOCALHOST],
            Duration::from_secs(3),
            &CancellationToken::new(),
        ));
        assert!(
            snapshot
                .hosts
                .get(&Ipv4Addr::LOCALHOST)
                .is_some_and(|info| info
                    .bonjour
                    .iter()
                    .any(|service| service.instance == "IP Scout test printer"
                        && service.port == 631)),
            "Bonjour did not resolve the loopback fixture: {:?}",
            snapshot.warnings
        );
        assert!(
            snapshot.hosts[&Ipv4Addr::LOCALHOST]
                .bonjour
                .iter()
                .any(
                    |service| service.service_type == "_ip-scout-test._tcp.local."
                        && service.port == 9999
                ),
            "Service-type enumeration did not discover the custom service"
        );
    }

    #[test]
    fn running_bonjour_and_wsd_collection_cancel_promptly() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let client = ServiceDaemon::new_with_port(port).unwrap();
        let targets = TargetRange::parse("127.0.0.1").unwrap();
        let cancel = CancellationToken::new();
        let start = std::time::Instant::now();
        runtime().block_on(async {
            let stop = async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                cancel.cancel();
            };
            let mut snapshot = Snapshot::default();
            let ids = vec!["test".into()];
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let work = futures_util::future::join(
                collect_bonjour_on(
                    client,
                    &targets,
                    &[Ipv4Addr::LOCALHOST],
                    Duration::from_secs(10),
                    &cancel,
                ),
                cancel.run_until_cancelled(receive_wsd(&socket, &targets, &ids, &mut snapshot)),
            );
            let _ = tokio::time::timeout(
                Duration::from_secs(2),
                futures_util::future::join(work, stop),
            )
            .await
            .unwrap();
        });
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}
