//! Initial Linux backend: native unprivileged ICMP and local IPv4 interface discovery.
//! Route selection and fresh ARP confirmation deliberately remain unavailable until ported.
use super::*;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    io,
    net::SocketAddrV4,
    os::fd::AsRawFd,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

fn ping_socket() -> io::Result<Socket> {
    // Linux ping sockets are governed by net.ipv4.ping_group_range; unlike raw sockets,
    // they do not require root or CAP_NET_RAW when the user's group is permitted.
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::ICMPV4))?;
    socket.bind(&SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0).into())?;
    Ok(socket)
}

pub fn ping_reply(ip: Ipv4Addr, timeout_ms: u32) -> Result<Option<EchoReply>, String> {
    echo(ip, Duration::from_millis(u64::from(timeout_ms.max(1))))
        .map_err(|error| if error.kind() == io::ErrorKind::PermissionDenied {
            format!("Linux ICMP unavailable: {error}. Unprivileged ping requires a permitted net.ipv4.ping_group_range.")
        } else { format!("Linux ICMP error: {error}") })
}

fn echo(ip: Ipv4Addr, timeout: Duration) -> io::Result<Option<EchoReply>> {
    let socket = ping_socket()?;
    socket.connect(&SocketAddrV4::new(ip, 0).into())?;
    let identifier = socket
        .local_addr()?
        .as_socket_ipv4()
        .ok_or_else(|| io::Error::other("ping socket has no IPv4 identifier"))?
        .port();
    let enabled: libc::c_int = 1;
    // SAFETY: fd belongs to socket; enabled is an initialized c_int of the declared size.
    let ttl_enabled = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::IPPROTO_IP,
            libc::IP_RECVTTL,
            (&enabled as *const libc::c_int).cast(),
            std::mem::size_of_val(&enabled) as libc::socklen_t,
        )
    } == 0;
    let nonce = uuid::Uuid::new_v4();
    let mut packet = [0u8; 24];
    packet[0] = 8; // Echo request, code 0.
    packet[4..6].copy_from_slice(&identifier.to_be_bytes());
    packet[6..8].copy_from_slice(&1u16.to_be_bytes());
    packet[8..].copy_from_slice(nonce.as_bytes());
    let checksum = checksum(&packet);
    packet[2..4].copy_from_slice(&checksum.to_be_bytes());
    socket.set_write_timeout(Some(timeout))?;
    let started = Instant::now();
    socket.send(&packet)?;
    while let Some(remaining) = timeout
        .checked_sub(started.elapsed())
        .filter(|time| !time.is_zero())
    {
        socket.set_read_timeout(Some(remaining))?;
        let mut reply = [0u8; 512];
        // usize keeps the ancillary buffer correctly aligned for cmsghdr.
        let mut control = [0usize; 16];
        let mut iov = libc::iovec {
            iov_base: reply.as_mut_ptr().cast(),
            iov_len: reply.len(),
        };
        // SAFETY: all-zero msghdr has null optional pointers; its writable buffers below
        // remain alive for recvmsg and for the subsequent ancillary traversal.
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = std::mem::size_of_val(&control);
        // Connected sockets accept only the selected peer. Linux returns an ICMP header
        // plus payload for SOCK_DGRAM, without an IPv4 header.
        let length = unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) };
        if length < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut
                    | io::ErrorKind::WouldBlock
                    | io::ErrorKind::ConnectionRefused
            ) || matches!(
                error.raw_os_error(),
                Some(libc::EHOSTUNREACH | libc::ENETUNREACH)
            ) {
                return Ok(None);
            }
            return Err(error);
        }
        let length = length as usize;
        if message.msg_flags & libc::MSG_TRUNC != 0
            || length != packet.len()
            || reply[0] != 0
            || reply[1] != 0
            || reply[4..length] != packet[4..]
        {
            continue;
        }
        let mut ttl = None;
        if ttl_enabled && message.msg_flags & libc::MSG_CTRUNC == 0 {
            // SAFETY: message contains only recvmsg-produced ancillary records inside the
            // aligned control buffer. Check cmsg_len before reading its integer payload.
            unsafe {
                let mut header = libc::CMSG_FIRSTHDR(&message);
                while !header.is_null() {
                    if (*header).cmsg_level == libc::IPPROTO_IP
                        && (*header).cmsg_type == libc::IP_TTL
                        && (*header).cmsg_len
                            >= libc::CMSG_LEN(std::mem::size_of::<libc::c_int>() as u32) as usize
                    {
                        let value =
                            std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::c_int>());
                        ttl = u8::try_from(value).ok();
                    }
                    header = libc::CMSG_NXTHDR(&message, header);
                }
            }
        }
        return Ok(Some(EchoReply {
            round_trip_ms: started.elapsed().as_secs_f64() * 1000.0,
            ttl,
        }));
    }
    Ok(None)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|chunk| u32::from(u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)])))
        .sum();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn local_networks() -> Vec<LocalNetwork> {
    let mut networks = Vec::new();
    for interface in if_addrs::get_if_addrs().unwrap_or_default() {
        if interface.is_loopback() || !interface.is_oper_up() {
            continue;
        }
        let if_addrs::IfAddr::V4(address) = interface.addr else {
            continue;
        };
        let mask = u32::from(address.netmask);
        let prefix = mask.leading_ones();
        if prefix == 0 || mask != u32::MAX << (32 - prefix) {
            continue;
        }
        let cidr = format!(
            "{}/{}",
            Ipv4Addr::from(u32::from(address.ip) & mask),
            prefix
        );
        if !networks
            .iter()
            .any(|network: &LocalNetwork| network.cidr == cidr)
        {
            networks.push(LocalNetwork {
                address: address.ip,
                cidr,
            });
        }
    }
    networks.sort_unstable_by(|a, b| a.cidr.cmp(&b.cidr).then(a.address.cmp(&b.address)));
    networks
}

pub fn route_path(_ip: Ipv4Addr) -> Option<RoutePath> {
    None
}
pub fn mac_address(_ip: Ipv4Addr) -> Option<[u8; 6]> {
    None
}
pub fn discover_arp(_ip: Ipv4Addr) -> Option<[u8; 6]> {
    None
}
pub async fn discover_arp_bounded(
    _ip: Ipv4Addr,
    _timeout: Duration,
    _cancel: &CancellationToken,
) -> Option<[u8; 6]> {
    None
}
pub async fn native_hostname(_ip: Ipv4Addr, _cancel: &CancellationToken) -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn unprivileged_ping_reaches_loopback_and_reports_ttl() {
        let reply = ping_reply(Ipv4Addr::LOCALHOST, 1000)
            .expect("Linux ping sockets must be permitted for the test user")
            .expect("loopback echo reply");
        assert!(reply.round_trip_ms >= 0.0);
        assert!(reply.ttl.is_some_and(|ttl| ttl > 0));
    }
    #[test]
    fn checksum_validates_odd_and_even_echo_payloads() {
        for mut packet in [
            vec![8, 0, 0, 0, 0, 1, 0, 1],
            vec![8, 0, 0, 0, 0, 2, 0, 1, 65],
        ] {
            let value = checksum(&packet);
            packet[2..4].copy_from_slice(&value.to_be_bytes());
            assert_eq!(checksum(&packet), 0);
        }
    }
    #[test]
    fn local_interfaces_are_valid_ipv4_networks() {
        for network in local_networks() {
            assert!(!network.address.is_loopback());
            assert!(is_local_target(
                network.address,
                std::slice::from_ref(&network)
            ));
        }
    }
}
