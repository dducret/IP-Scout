use super::{
    MAX_HOSTS, MAX_PACKETS, in_range, push_unique,
    ssdp::parse_ssdp,
    vendor::{parse_mndp, parse_ubiquiti},
};
use crate::{discovery::Snapshot, targets::TargetRange};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Ssdp,
    Mndp,
    Ubiquiti,
}
impl Kind {
    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Ssdp => "SSDP/UPnP",
            Self::Mndp => "MNDP",
            Self::Ubiquiti => "Ubiquiti",
        }
    }
}

pub(super) fn socket(ip: Ipv4Addr, kind: Kind) -> std::io::Result<tokio::net::UdpSocket> {
    let sock = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    // MNDP broadcasts are addressed to the fixed listening port. Do not reuse it:
    // competing listeners on Windows can steal each other's datagrams.
    sock.bind(&SocketAddr::from((ip, if matches!(kind, Kind::Mndp) { 5678 } else { 0 })).into())?;
    sock.set_broadcast(true)?;
    if matches!(kind, Kind::Ssdp) {
        sock.set_multicast_if_v4(&ip)?;
        sock.set_multicast_ttl_v4(1)?;
    }
    sock.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(sock.into())
}

pub(super) async fn udp_on(
    ip: Ipv4Addr,
    kind: Kind,
    targets: &TargetRange,
    budget: Duration,
    cancel: &CancellationToken,
) -> Snapshot {
    let mut snapshot = Snapshot::default();
    let sock = match socket(ip, kind) {
        Ok(sock) => sock,
        Err(error) => {
            snapshot
                .warnings
                .push(format!("{} on {ip}: {error}", kind.name()));
            return snapshot;
        }
    };
    let broadcast = if matches!(kind, Kind::Ubiquiti) {
        format!(
            "{}:10001",
            broadcast_for(&crate::network::local_networks(), ip)
        )
    } else {
        String::new()
    };
    let work = async {
        let probes: Vec<(&[u8], &str)> = match kind {
            Kind::Ssdp => vec![(b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n", "239.255.255.250:1900")],
            Kind::Ubiquiti => vec![(&[1,0,0,0], broadcast.as_str()), (&[2,8,0,0], broadcast.as_str())],
            Kind::Mndp => Vec::new(),
        };
        for (probe, address) in probes {
            if let Err(error) = sock.send_to(probe, address).await {
                snapshot
                    .warnings
                    .push(format!("{} on {ip}: {error}", kind.name()));
                return;
            }
        }
        receive(&sock, kind, targets, &mut snapshot).await;
    };
    let _ = cancel
        .run_until_cancelled(tokio::time::timeout(budget, work))
        .await;
    snapshot
}

pub(super) fn broadcast_for(
    networks: &[crate::network::LocalNetwork],
    address: Ipv4Addr,
) -> Ipv4Addr {
    for network in networks.iter().filter(|network| network.address == address) {
        if let Some((_, prefix)) = network.cidr.split_once('/')
            && let Ok(prefix) = prefix.parse::<u32>()
            && (1..31).contains(&prefix)
        {
            return Ipv4Addr::from(u32::from(address) | (u32::MAX >> prefix));
        }
    }
    Ipv4Addr::BROADCAST
}

pub(super) async fn receive(
    sock: &tokio::net::UdpSocket,
    kind: Kind,
    targets: &TargetRange,
    snapshot: &mut Snapshot,
) {
    let mut buffer = [0u8; 16_385];
    for _ in 0..MAX_PACKETS {
        let Ok((len, peer)) = sock.recv_from(&mut buffer).await else {
            return;
        };
        let IpAddr::V4(ip) = peer.ip() else {
            continue;
        };
        if !in_range(ip, targets)
            || len > 16_384
            || (matches!(kind, Kind::Mndp) && peer.port() != 5678)
            || (matches!(kind, Kind::Ubiquiti) && peer.port() != 10001)
        {
            continue;
        }
        if snapshot.hosts.len() >= MAX_HOSTS && !snapshot.hosts.contains_key(&ip) {
            continue;
        }
        let data = &buffer[..len];
        match kind {
            Kind::Ssdp => {
                if let Some(device) = parse_ssdp(data, ip) {
                    let devices = &mut snapshot.hosts.entry(ip).or_default().advertisements.ssdp;
                    if !devices
                        .iter()
                        .any(|old| old.usn == device.usn && old.location == device.location)
                    {
                        push_unique(devices, device);
                    }
                }
            }
            Kind::Mndp => {
                if let Some(device) = parse_mndp(data) {
                    push_unique(
                        &mut snapshot.hosts.entry(ip).or_default().advertisements.mndp,
                        device,
                    );
                }
            }
            Kind::Ubiquiti => {
                if let Some(device) = parse_ubiquiti(data) {
                    push_unique(
                        &mut snapshot
                            .hosts
                            .entry(ip)
                            .or_default()
                            .advertisements
                            .ubiquiti,
                        device,
                    );
                }
            }
        }
    }
}
