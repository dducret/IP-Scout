use std::net::Ipv4Addr;

/// These operations need platform-specific neighbor/route support. Historical data may
/// still contain them, so the result model and export format remain platform-independent.
pub const ARP_SUPPORTED: bool = cfg!(windows);
pub const ROUTE_SUPPORTED: bool = cfg!(windows);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct RoutePath {
    pub interface_index: u32,
    pub source: Ipv4Addr,
    pub next_hop: Ipv4Addr,
}

impl RoutePath {
    pub fn summary(&self) -> String {
        if self.next_hop.is_unspecified() {
            format!(
                "Interface {} | source {} | directly connected",
                self.interface_index, self.source
            )
        } else {
            format!(
                "Interface {} | source {} | via {}",
                self.interface_index, self.source, self.next_hop
            )
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct EchoReply {
    pub round_trip_ms: f64,
    pub ttl: Option<u8>,
}

pub fn ping(ip: Ipv4Addr, timeout_ms: u32) -> Result<Option<f64>, String> {
    ping_reply(ip, timeout_ms).map(|reply| reply.map(|reply| reply.round_trip_ms))
}

#[derive(Clone, Debug)]
pub struct LocalNetwork {
    pub address: Ipv4Addr,
    pub cidr: String,
}

pub fn is_local_target(ip: Ipv4Addr, networks: &[LocalNetwork]) -> bool {
    ip.is_loopback()
        || networks.iter().any(|network| {
            let Some(prefix) = network
                .cidr
                .split_once('/')
                .and_then(|(_, prefix)| prefix.parse::<u32>().ok())
            else {
                return false;
            };
            if prefix > 32 {
                return false;
            }
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            u32::from(ip) & mask == u32::from(network.address) & mask
        })
}

#[cfg(windows)]
#[path = "network/windows.rs"]
mod platform;

#[cfg(target_os = "linux")]
#[path = "network/linux.rs"]
mod platform;

#[cfg(any(windows, target_os = "linux"))]
pub use platform::{
    discover_arp, discover_arp_bounded, local_networks, mac_address, native_hostname, ping_reply,
    route_path,
};

#[cfg(not(any(windows, target_os = "linux")))]
pub fn route_path(_ip: Ipv4Addr) -> Option<RoutePath> {
    None
}

#[cfg(not(any(windows, target_os = "linux")))]
pub async fn discover_arp_bounded(
    _ip: Ipv4Addr,
    _timeout: std::time::Duration,
    _cancel: &tokio_util::sync::CancellationToken,
) -> Option<[u8; 6]> {
    None
}

#[cfg(not(any(windows, target_os = "linux")))]
pub async fn native_hostname(
    _ip: Ipv4Addr,
    _cancel: &tokio_util::sync::CancellationToken,
) -> Option<String> {
    None
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn discover_arp(_ip: Ipv4Addr) -> Option<[u8; 6]> {
    None
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn ping_reply(_ip: Ipv4Addr, _timeout_ms: u32) -> Result<Option<EchoReply>, String> {
    Err("Native ICMP is only supported on Windows".into())
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn mac_address(_ip: Ipv4Addr) -> Option<[u8; 6]> {
    None
}

#[cfg(not(any(windows, target_os = "linux")))]
pub fn local_networks() -> Vec<LocalNetwork> {
    Vec::new()
}

pub fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[cfg(any(windows, test))]
fn valid_mac(mac: [u8; 6]) -> bool {
    mac != [0; 6] && mac[0] & 1 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_targets_are_separate_from_routed_vpn_addresses() {
        let networks = vec![LocalNetwork {
            address: Ipv4Addr::new(192, 168, 1, 73),
            cidr: "192.168.1.0/24".into(),
        }];
        assert!(is_local_target(Ipv4Addr::LOCALHOST, &[]));
        assert!(is_local_target(Ipv4Addr::new(192, 168, 1, 106), &networks));
        assert!(!is_local_target(
            Ipv4Addr::new(192, 168, 213, 50),
            &networks
        ));
        assert!(!is_local_target(Ipv4Addr::new(192, 168, 2, 1), &networks));
        assert!(!is_local_target(Ipv4Addr::new(192, 168, 213, 50), &[]));
    }

    #[test]
    fn bounded_arp_skips_loopback_and_cancelled_work() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let cancel = tokio_util::sync::CancellationToken::new();
            let started = std::time::Instant::now();
            assert!(
                discover_arp_bounded(
                    Ipv4Addr::LOCALHOST,
                    std::time::Duration::from_secs(5),
                    &cancel
                )
                .await
                .is_none()
            );
            cancel.cancel();
            assert!(
                discover_arp_bounded(
                    Ipv4Addr::new(192, 0, 2, 1),
                    std::time::Duration::from_secs(5),
                    &cancel
                )
                .await
                .is_none()
            );
            assert!(started.elapsed() < std::time::Duration::from_secs(1));
        });
    }

    #[test]
    fn only_valid_unicast_macs_are_discovery_candidates() {
        assert!(valid_mac([0xCA, 0xC7, 0xCC, 0x87, 0xCC, 0xE2]));
        assert!(!valid_mac([0; 6]));
        assert!(!valid_mac([0xFF; 6]));
        assert!(!valid_mac([1, 0, 0, 0, 0, 1]));
    }

    #[test]
    fn loopback_is_not_an_arp_target() {
        assert!(discover_arp(Ipv4Addr::LOCALHOST).is_none());
        assert!(mac_address(Ipv4Addr::LOCALHOST).is_none());
    }
}
