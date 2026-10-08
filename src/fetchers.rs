use crate::scanner::HostResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Fetcher {
    Ping,
    Hostname,
    Ports,
    MacAddress,
    Manufacturer,
    RefusedPorts,
    ArpResponse,
    ProbableBrand,
    Notes,
    Ttl,
    Netbios,
    WebDetect,
    PacketLoss,
    HttpStatus,
    WebUrl,
    Bonjour,
    Wsd,
    Ssdp,
    Mndp,
    Ubiquiti,
    // Deserialize the retired choice so upgrades preserve other preferences.
    #[serde(rename = "LinkNeighbors")]
    RetiredLinkNeighbors,
    Llmnr,
    ServiceBanners,
    TlsCertificates,
    WebTitle,
    DeviceIdentity,
    UdpPorts,
    UdpStatus,
    DnsInfo,
    NtpInfo,
    SnmpInfo,
}

impl Fetcher {
    pub const ALL: [Self; 30] = [
        Self::Ping,
        Self::Hostname,
        Self::Ports,
        Self::MacAddress,
        Self::Manufacturer,
        Self::RefusedPorts,
        Self::ArpResponse,
        Self::ProbableBrand,
        Self::Notes,
        Self::Ttl,
        Self::Netbios,
        Self::WebDetect,
        Self::PacketLoss,
        Self::HttpStatus,
        Self::WebUrl,
        Self::Bonjour,
        Self::Wsd,
        Self::Ssdp,
        Self::Mndp,
        Self::Ubiquiti,
        Self::Llmnr,
        Self::ServiceBanners,
        Self::TlsCertificates,
        Self::WebTitle,
        Self::DeviceIdentity,
        Self::UdpPorts,
        Self::UdpStatus,
        Self::DnsInfo,
        Self::NtpInfo,
        Self::SnmpInfo,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Ping => "Ping",
            Self::Hostname => "Hostname",
            Self::Ports => "Open TCP ports",
            Self::MacAddress => "MAC address",
            Self::Manufacturer => "Manufacturer",
            Self::RefusedPorts => "Refused TCP ports",
            Self::ArpResponse => "ARP response",
            Self::ProbableBrand => "Probable brand",
            Self::Notes => "Notes",
            Self::Ttl => "TTL",
            Self::Netbios => "NetBIOS info",
            Self::WebDetect => "Web detect",
            Self::PacketLoss => "Packet loss",
            Self::HttpStatus => "HTTP status",
            Self::WebUrl => "Web URL",
            Self::Bonjour => "Bonjour / mDNS",
            Self::Wsd => "WSD info",
            Self::Ssdp => "SSDP / UPnP",
            Self::Mndp => "MikroTik MNDP",
            Self::Ubiquiti => "Ubiquiti discovery",
            Self::RetiredLinkNeighbors => "Unavailable",
            Self::Llmnr => "LLMNR hostname",
            Self::ServiceBanners => "Service banners",
            Self::TlsCertificates => "TLS certificates",
            Self::WebTitle => "Web page title",
            Self::DeviceIdentity => "Device identity",
            Self::UdpPorts => "Open UDP ports",
            Self::UdpStatus => "UDP scan status",
            Self::DnsInfo => "DNS service",
            Self::NtpInfo => "NTP service",
            Self::SnmpInfo => "SNMP info",
        }
    }

    pub fn width(self) -> f32 {
        match self {
            Self::Ping => 85.0,
            Self::Hostname => 190.0,
            Self::Ports | Self::RefusedPorts => 155.0,
            Self::MacAddress | Self::Manufacturer => 210.0,
            Self::ArpResponse => 150.0,
            Self::ProbableBrand | Self::Notes => 240.0,
            Self::Ttl => 65.0,
            Self::PacketLoss => 110.0,
            Self::Netbios => 300.0,
            Self::WebDetect | Self::WebUrl => 270.0,
            Self::HttpStatus => 190.0,
            Self::Bonjour | Self::Wsd | Self::Ssdp | Self::Mndp | Self::Ubiquiti => 360.0,
            Self::RetiredLinkNeighbors => 0.0,
            Self::Llmnr => 190.0,
            Self::ServiceBanners | Self::TlsCertificates | Self::DeviceIdentity => 360.0,
            Self::WebTitle => 280.0,
            Self::UdpPorts => 160.0,
            Self::UdpStatus | Self::DnsInfo | Self::NtpInfo | Self::SnmpInfo => 360.0,
        }
    }

    pub fn value(self, host: &HostResult) -> String {
        match self {
            Self::Ping => host
                .ping_ms
                .map(|ping| format!("{ping:.1}"))
                .unwrap_or_default(),
            Self::Hostname => host.hostname.clone(),
            Self::Ports => host
                .open_ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            Self::MacAddress => host.mac.clone(),
            Self::Manufacturer => host.brand_label().to_owned(),
            Self::RefusedPorts => host.refused_ports.to_string(),
            Self::ArpResponse => if host.arp_response {
                "Yes"
            } else {
                "Not confirmed"
            }
            .into(),
            Self::ProbableBrand => host.probable_brand.clone(),
            Self::Notes => host.notes.clone(),
            Self::Ttl => host
                .extra
                .ttl
                .map(|ttl| ttl.to_string())
                .unwrap_or_default(),
            Self::PacketLoss => host
                .extra
                .packet_loss
                .map(|loss| format!("{loss:.1}%"))
                .unwrap_or_default(),
            Self::Netbios => host.extra.netbios.clone(),
            Self::Llmnr => host.extra.llmnr.clone(),
            Self::ServiceBanners => host
                .extra
                .banners
                .iter()
                .map(|banner| format!("{}: {}", banner.port, banner.text))
                .collect::<Vec<_>>()
                .join("; "),
            Self::TlsCertificates => host
                .extra
                .certificates
                .iter()
                .map(|certificate| certificate.summary())
                .collect::<Vec<_>>()
                .join("; "),
            Self::WebTitle => host
                .extra
                .web
                .iter()
                .filter(|service| !service.title.is_empty())
                .map(|service| {
                    format!(
                        "{}: {}{}",
                        service.url,
                        service.title,
                        if service.tls_unverified {
                            " [TLS unverified]"
                        } else {
                            ""
                        }
                    )
                })
                .collect::<Vec<_>>()
                .join("; "),
            Self::DeviceIdentity => crate::inventory::device_identity(host),
            Self::UdpPorts => host
                .extra
                .udp
                .open_ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", "),
            Self::UdpStatus => host.extra.udp.summary(),
            Self::DnsInfo => host.extra.udp.dns.clone(),
            Self::NtpInfo => host.extra.udp.ntp.clone(),
            Self::SnmpInfo => host.extra.udp.snmp.clone(),
            Self::Ssdp => host
                .extra
                .advertisements
                .ssdp
                .iter()
                .map(|device| device.summary())
                .collect::<Vec<_>>()
                .join("; "),
            Self::Mndp => host
                .extra
                .advertisements
                .mndp
                .iter()
                .map(|device| device.summary())
                .collect::<Vec<_>>()
                .join("; "),
            Self::Ubiquiti => host
                .extra
                .advertisements
                .ubiquiti
                .iter()
                .map(|device| device.summary())
                .collect::<Vec<_>>()
                .join("; "),
            Self::RetiredLinkNeighbors => String::new(),
            Self::Bonjour => host
                .extra
                .bonjour
                .iter()
                .map(|service| service.summary())
                .collect::<Vec<_>>()
                .join("; "),
            Self::Wsd => host
                .extra
                .wsd
                .iter()
                .map(|device| device.summary())
                .collect::<Vec<_>>()
                .join("; "),
            Self::WebDetect | Self::HttpStatus | Self::WebUrl => host
                .extra
                .web
                .iter()
                .map(|service| {
                    let value = match self {
                        Self::WebDetect => format!(
                            "{}: {}",
                            service.endpoint(),
                            if service.server.is_empty() {
                                "Server header hidden"
                            } else {
                                &service.server
                            }
                        ),
                        Self::HttpStatus => format!("{}: {}", service.endpoint(), service.status),
                        _ => service.url.clone(),
                    };
                    if service.tls_unverified {
                        format!("{value} [TLS unverified]")
                    } else {
                        value
                    }
                })
                .collect::<Vec<_>>()
                .join("; "),
        }
    }

    pub fn help(self) -> &'static str {
        match self {
            Self::Ttl => "TTL observed in an ICMP echo reply; blank when ping does not respond.",
            Self::Netbios => {
                "Unicast UDP 137 node status: computer names, groups and services. Many devices disable NetBIOS."
            }
            Self::WebDetect => {
                "Independently checks HTTP and HTTPS on common web ports, including 8080, and up to 26 additional open TCP ports. Reported Server headers are not verified."
            }
            Self::PacketLoss => {
                "Lost ICMP replies as a percentage of samples. Set the sample count in Scan settings; extra samples take longer."
            }
            Self::HttpStatus => {
                "HTTP response code, including redirects and authentication errors. Redirects are not followed."
            }
            Self::WebUrl => "Detected HTTP/HTTPS endpoints, including custom ports.",
            Self::Bonjour => {
                "Local multicast DNS-SD service names, .local hostnames, ports and selected TXT properties. Advertisements do not confirm host reachability."
            }
            Self::Wsd => {
                "Local WS-Discovery device types, scopes and endpoints. No metadata URLs are fetched. Multicast can be blocked by firewalls or Wi-Fi isolation."
            }
            Self::Ssdp => {
                "Local SSDP discovery and bounded UPnP descriptions: name, manufacturer, model and reported server. Only same-device literal IPv4 URLs are fetched; no redirects or credentials."
            }
            Self::Mndp => {
                "Passive UDP 5678 MikroTik advertisements: identity, board, firmware, interface and reported MAC. Longer discovery windows may be needed."
            }
            Self::Ubiquiti => {
                "Read-only UDP 10001 v1/v2 local discovery: reported name, model, firmware and MAC. No adoption or configuration commands."
            }
            Self::Llmnr => {
                "Unicast TCP 5355 reverse-name query on directly connected IPv4 networks, with TTL 1. Many devices disable LLMNR. No multicast enumeration, authentication or network setting changes."
            }
            Self::ServiceBanners => {
                "Reads server greetings on open FTP, SSH, SMTP, POP3, IMAP, VNC and eligible custom ports. Up to 16 ports; no commands or credentials. Known printer and binary protocol ports are excluded. Reported software is unverified."
            }
            Self::TlsCertificates => {
                "Reads public TLS certificate subject, issuer, SAN names, validity and serial on common TLS ports and detected HTTPS endpoints. Handshake is deliberately aborted; identity is unverified."
            }
            Self::WebTitle => {
                "Reads up to 16 KiB of HTML from the root page on HTTP and HTTPS endpoints. No scripts, authentication, links or redirects. Self-signed HTTPS page titles require the existing unverified-TLS setting."
            }
            Self::DeviceIdentity => {
                "Source-labeled names and models from the selected fetchers. Advertisements, titles and certificate names are hints, not verified device identity. Does not replace the resolved Hostname."
            }
            Self::UdpPorts => {
                "Confirmed UDP responses on selected ports. DNS/NTP use protocol requests; other ports use an empty datagram. No response is not proof of a closed port."
            }
            Self::UdpStatus => {
                "Checked/selected counts, confirmed responses, OS-reported closed ports, open-or-filtered timeouts, and local errors. Pending work is labeled incomplete. Protocol adapters may not expose ICMP errors."
            }
            Self::DnsInfo => {
                "Read-only, non-recursive root SOA query to UDP 53. Shows response code, advertised recursion and SOA server. Request ID and question are validated; no external DNS recursion."
            }
            Self::NtpInfo => {
                "SNTPv4 time request on UDP 123. Shows stratum, server Unix time, clock offset and round-trip time. Does not change the computer clock; no NTP control or monitoring requests."
            }
            Self::SnmpInfo => {
                "Read-only SNMPv2c GET on UDP 161 for sysDescr, sysObjectID, sysUpTime and sysName. Requires an entered community in Scan settings; no guessing, SET, walks, traps or SNMPv3. Community is not saved and is sent unencrypted."
            }
            _ => self.label(),
        }
    }
}

pub fn defaults() -> Vec<Fetcher> {
    vec![
        Fetcher::Ping,
        Fetcher::Hostname,
        Fetcher::Ports,
        Fetcher::MacAddress,
        Fetcher::Manufacturer,
    ]
}

pub const INVENTORY_PORTS: &str = "21,22,25,53,80,110,135,139,143,389,443,445,465,587,631,636,853,993,995,1883,3389,5357,5900,5985,5986,8000,8080,8443,8888,9100";

pub fn inventory() -> Vec<Fetcher> {
    Fetcher::ALL
        .into_iter()
        .filter(|fetcher| {
            !matches!(
                fetcher,
                Fetcher::PacketLoss | Fetcher::RefusedPorts | Fetcher::ArpResponse
            )
        })
        .collect()
}

pub fn normalize(fetchers: &mut Vec<Fetcher>) {
    let mut seen = Vec::new();
    fetchers.retain(|fetcher| {
        if !Fetcher::ALL.contains(fetcher) || seen.contains(fetcher) {
            false
        } else {
            seen.push(*fetcher);
            true
        }
    });
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Requirements {
    pub udp: bool,
    pub dns_info: bool,
    pub ntp_info: bool,
    pub snmp_info: bool,
    pub tcp: bool,
    pub dns: bool,
    pub mac: bool,
    pub vendor: bool,
    pub netbios: bool,
    pub web: bool,
    pub packet_loss: bool,
    pub bonjour: bool,
    pub wsd: bool,
    pub advertisements: crate::advertisements::Options,
    pub llmnr: bool,
    pub banners: bool,
    pub certificates: bool,
    pub web_titles: bool,
}

pub fn requirements(fetchers: &[Fetcher]) -> Requirements {
    let brand = fetchers.contains(&Fetcher::ProbableBrand);
    let vendor = fetchers.contains(&Fetcher::Manufacturer) || brand;
    Requirements {
        udp: fetchers
            .iter()
            .any(|fetcher| matches!(fetcher, Fetcher::UdpPorts | Fetcher::UdpStatus)),
        dns_info: fetchers.contains(&Fetcher::DnsInfo),
        ntp_info: fetchers.contains(&Fetcher::NtpInfo),
        snmp_info: fetchers.contains(&Fetcher::SnmpInfo),
        tcp: fetchers.iter().any(|fetcher| {
            matches!(
                fetcher,
                Fetcher::Ports
                    | Fetcher::RefusedPorts
                    | Fetcher::ServiceBanners
                    | Fetcher::TlsCertificates
            )
        }),
        dns: fetchers.contains(&Fetcher::Hostname)
            || fetchers.contains(&Fetcher::DeviceIdentity)
            || brand,
        mac: fetchers.contains(&Fetcher::MacAddress) || vendor,
        vendor,
        netbios: fetchers.contains(&Fetcher::Netbios),
        web: fetchers.iter().any(|fetcher| {
            matches!(
                fetcher,
                Fetcher::WebDetect | Fetcher::HttpStatus | Fetcher::WebUrl | Fetcher::WebTitle
            )
        }),
        packet_loss: fetchers.contains(&Fetcher::PacketLoss),
        bonjour: fetchers.contains(&Fetcher::Bonjour),
        wsd: fetchers.contains(&Fetcher::Wsd),
        advertisements: crate::advertisements::Options {
            ssdp: fetchers.contains(&Fetcher::Ssdp),
            mndp: fetchers.contains(&Fetcher::Mndp),
            ubiquiti: fetchers.contains(&Fetcher::Ubiquiti),
        },
        llmnr: fetchers.contains(&Fetcher::Llmnr),
        banners: fetchers.contains(&Fetcher::ServiceBanners),
        certificates: fetchers.contains(&Fetcher::TlsCertificates),
        web_titles: fetchers.contains(&Fetcher::WebTitle),
    }
}

#[derive(Clone)]
pub struct FetcherDraft {
    pub selected: Vec<Fetcher>,
    pub selected_row: Option<Fetcher>,
    pub available_row: Option<Fetcher>,
}

impl FetcherDraft {
    pub fn new(mut selected: Vec<Fetcher>) -> Self {
        normalize(&mut selected);
        let selected_row = selected.first().copied();
        let available_row = Fetcher::ALL
            .into_iter()
            .find(|fetcher| !selected.contains(fetcher));
        Self {
            selected,
            selected_row,
            available_row,
        }
    }

    pub fn available(&self) -> Vec<Fetcher> {
        Fetcher::ALL
            .into_iter()
            .filter(|fetcher| !self.selected.contains(fetcher))
            .collect()
    }

    pub fn selected_index(&self) -> Option<usize> {
        self.selected_row.and_then(|selected| {
            self.selected
                .iter()
                .position(|fetcher| *fetcher == selected)
        })
    }

    pub fn add(&mut self) {
        if let Some(fetcher) = self.available_row
            && !self.selected.contains(&fetcher)
        {
            self.selected.push(fetcher);
            self.selected_row = Some(fetcher);
            self.available_row = self.available().first().copied();
        }
    }

    pub fn remove(&mut self) {
        if let Some(index) = self.selected_index() {
            self.available_row = Some(self.selected.remove(index));
            self.selected_row = self
                .selected
                .get(index.min(self.selected.len().saturating_sub(1)))
                .copied();
        }
    }

    pub fn move_selected(&mut self, direction: isize) {
        if let Some(index) = self.selected_index()
            && let Some(next) = index.checked_add_signed(direction)
            && next < self.selected.len()
        {
            self.selected.swap(index, next);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn udp_fetchers_enable_only_the_selected_probes() {
        let required = requirements(&[
            Fetcher::UdpPorts,
            Fetcher::UdpStatus,
            Fetcher::DnsInfo,
            Fetcher::NtpInfo,
            Fetcher::SnmpInfo,
        ]);
        assert!(required.udp && required.dns_info && required.ntp_info && required.snmp_info);
        assert!(!required.tcp && !required.dns && !required.web && !required.mac);
        assert!(!requirements(&defaults()).udp);
        let required = requirements(&[Fetcher::DnsInfo]);
        assert!(required.dns_info && !required.udp && !required.ntp_info && !required.snmp_info);
        assert!(requirements(&inventory()).udp);
    }

    #[test]
    fn inventory_preset_enables_new_fetchers_without_extra_ping_sampling() {
        let selected = inventory();
        let required = requirements(&selected);
        assert!(
            required.banners
                && required.certificates
                && required.web_titles
                && required.web
                && required.dns
        );
        assert!(!required.packet_loss);
        assert!(!selected.contains(&Fetcher::RetiredLinkNeighbors));
        assert!(
            crate::targets::parse_ports(INVENTORY_PORTS)
                .unwrap()
                .contains(&8080)
        );
        assert!(requirements(&[Fetcher::ServiceBanners]).banners);
    }

    #[test]
    fn dependencies_enable_only_required_metadata_and_tcp() {
        assert_eq!(requirements(&[]), Requirements::default());
        let mac = requirements(&[Fetcher::MacAddress]);
        assert!(mac.mac && !mac.vendor && !mac.dns && !mac.tcp);
        let vendor = requirements(&[Fetcher::Manufacturer]);
        assert!(vendor.mac && vendor.vendor && !vendor.dns);
        let brand = requirements(&[Fetcher::ProbableBrand]);
        assert!(brand.mac && brand.vendor && brand.dns);
        assert!(requirements(&[Fetcher::RefusedPorts]).tcp);
        let ttl = requirements(&[Fetcher::Ttl]);
        assert_eq!(ttl, Requirements::default());
        for fetcher in [Fetcher::WebDetect, Fetcher::HttpStatus, Fetcher::WebUrl] {
            let required = requirements(&[fetcher]);
            assert!(
                required.web
                    && !required.dns
                    && !required.mac
                    && !required.netbios
                    && !required.packet_loss
            );
        }
        assert!(requirements(&[Fetcher::Netbios]).netbios);
        assert!(requirements(&[Fetcher::PacketLoss]).packet_loss);
        let bonjour = requirements(&[Fetcher::Bonjour]);
        assert!(
            bonjour.bonjour
                && !bonjour.wsd
                && !bonjour.web
                && !bonjour.tcp
                && !bonjour.dns
                && !bonjour.mac
        );
        let wsd = requirements(&[Fetcher::Wsd]);
        assert!(wsd.wsd && !wsd.bonjour && !wsd.web && !wsd.tcp && !wsd.dns && !wsd.mac);
        for fetcher in [Fetcher::Ssdp, Fetcher::Mndp, Fetcher::Ubiquiti] {
            let requirements = requirements(&[fetcher]);
            assert!(requirements.advertisements.enabled());
            assert!(
                !requirements.tcp && !requirements.dns && !requirements.mac && !requirements.web
            );
        }
        assert_eq!(
            requirements(&[Fetcher::RetiredLinkNeighbors]),
            Requirements::default()
        );
        let llmnr = requirements(&[Fetcher::Llmnr]);
        assert!(llmnr.llmnr && !llmnr.dns && !llmnr.advertisements.enabled() && !llmnr.tcp);
    }

    #[test]
    fn transfer_and_order_controls_preserve_a_partition() {
        let mut draft = FetcherDraft::new(defaults());
        draft.available_row = Some(Fetcher::ArpResponse);
        draft.add();
        draft.add();
        assert_eq!(
            draft.selected.len() + draft.available().len(),
            Fetcher::ALL.len()
        );
        draft.selected_row = Some(Fetcher::ArpResponse);
        draft.move_selected(-1);
        assert_eq!(draft.selected[4], Fetcher::ArpResponse);
        draft.remove();
        assert!(!draft.selected.contains(&Fetcher::ArpResponse));
        assert!(draft.available().contains(&Fetcher::ArpResponse));
    }

    #[test]
    fn empty_selection_and_boundary_moves_are_valid() {
        let mut draft = FetcherDraft::new(vec![Fetcher::Ping, Fetcher::Ping]);
        assert_eq!(draft.selected, vec![Fetcher::Ping]);
        draft.move_selected(-1);
        draft.move_selected(1);
        assert_eq!(draft.selected, vec![Fetcher::Ping]);
        draft.remove();
        draft.remove();
        assert!(draft.selected.is_empty());
        assert_eq!(draft.available().len(), Fetcher::ALL.len());
        draft.add();
        assert_eq!(draft.selected, vec![Fetcher::Ping]);
    }

    #[test]
    fn retired_choices_are_not_selectable_and_do_not_reset_other_fetchers() {
        let draft = FetcherDraft::new(vec![
            Fetcher::Ssdp,
            Fetcher::RetiredLinkNeighbors,
            Fetcher::Llmnr,
        ]);
        assert_eq!(draft.selected, vec![Fetcher::Ssdp, Fetcher::Llmnr]);
        assert!(!draft.available().contains(&Fetcher::RetiredLinkNeighbors));
        assert!(!Fetcher::ALL.contains(&Fetcher::RetiredLinkNeighbors));
    }
}
