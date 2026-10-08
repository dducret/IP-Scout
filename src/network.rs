use std::net::Ipv4Addr;

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
mod platform {
    use super::*;
    use std::{
        cell::RefCell,
        mem::size_of,
        ptr,
        sync::{Arc, Mutex, OnceLock, mpsc},
        thread,
    };
    use windows_sys::Win32::{
        Foundation::{ERROR_BUFFER_OVERFLOW, GetLastError, HANDLE, INVALID_HANDLE_VALUE},
        NetworkManagement::IpHelper::{
            GetAdaptersInfo, GetBestRoute2, GetIpNetEntry2, ICMP_ECHO_REPLY, IP_ADAPTER_INFO,
            IP_ADDR_STRING, IcmpCloseHandle, IcmpCreateFile, IcmpSendEcho, MIB_IPFORWARD_ROW2,
            MIB_IPNET_ROW2, ResolveIpNetEntry2,
        },
        Networking::WinSock::{
            AF_INET, GetNameInfoW, NI_NAMEREQD, SOCKADDR_IN, SOCKADDR_INET, WSADATA, WSAStartup,
        },
    };

    struct NameRequest {
        ip: Ipv4Addr,
        reply: tokio::sync::oneshot::Sender<Option<String>>,
    }

    fn name_pool() -> &'static mpsc::SyncSender<NameRequest> {
        static POOL: OnceLock<mpsc::SyncSender<NameRequest>> = OnceLock::new();
        POOL.get_or_init(|| {
            let (sender, receiver) = mpsc::sync_channel::<NameRequest>(8);
            let receiver = Arc::new(Mutex::new(receiver));
            for _ in 0..8 {
                let receiver = receiver.clone();
                thread::spawn(move || {
                    // Keep one Winsock reference for each process-lifetime worker.
                    let ready = unsafe { WSAStartup(0x0202, &mut WSADATA::default()) == 0 };
                    loop {
                        let Ok(request) = receiver.lock().unwrap().recv() else {
                            break;
                        };
                        if request.reply.is_closed() {
                            continue;
                        }
                        let name = ready.then(|| reverse_name(request.ip)).flatten();
                        let _ = request.reply.send(name);
                    }
                });
            }
            sender
        })
    }

    pub async fn native_hostname(
        ip: Ipv4Addr,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Option<String> {
        cancel
            .run_until_cancelled(async {
                let (reply, receiver) = tokio::sync::oneshot::channel();
                let mut request = NameRequest { ip, reply };
                loop {
                    match name_pool().try_send(request) {
                        Ok(()) => break,
                        Err(mpsc::TrySendError::Disconnected(_)) => return None,
                        Err(mpsc::TrySendError::Full(returned)) => {
                            request = returned;
                            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                        }
                    }
                }
                receiver.await.ok().flatten()
            })
            .await
            .flatten()
    }

    fn reverse_name(ip: Ipv4Addr) -> Option<String> {
        unsafe {
            let mut address = SOCKADDR_IN {
                sin_family: AF_INET,
                ..Default::default()
            };
            address.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
            let mut hostname = [0u16; 1025];
            if GetNameInfoW(
                (&address as *const SOCKADDR_IN).cast(),
                size_of::<SOCKADDR_IN>() as i32,
                hostname.as_mut_ptr(),
                hostname.len() as u32,
                ptr::null_mut(),
                0,
                NI_NAMEREQD as i32,
            ) != 0
            {
                return None;
            }
            let length = hostname.iter().position(|&c| c == 0)?;
            let name = String::from_utf16(&hostname[..length]).ok()?;
            let name = name.trim_end_matches('.');
            (!name.is_empty() && name.parse::<std::net::IpAddr>().is_err()).then(|| name.to_owned())
        }
    }

    const ICMP_PAYLOAD: &[u8] = b"abcdefghijklmnopqrstuvwabcdefghi";
    const REPLY_WORDS: usize =
        (size_of::<ICMP_ECHO_REPLY>() + ICMP_PAYLOAD.len() + 8).div_ceil(size_of::<usize>());

    struct IcmpChannel {
        handle: HANDLE,
        reply: [usize; REPLY_WORDS],
    }

    impl Drop for IcmpChannel {
        fn drop(&mut self) {
            unsafe {
                IcmpCloseHandle(self.handle);
            }
        }
    }

    thread_local! {
        // Each blocking worker owns its handle and aligned reply buffer; no cross-thread sharing.
        static ICMP: RefCell<Option<IcmpChannel>> = const { RefCell::new(None) };
    }

    pub fn ping_reply(ip: Ipv4Addr, timeout_ms: u32) -> Result<Option<EchoReply>, String> {
        ICMP.with(|slot| {
            let mut channel = slot.borrow_mut();
            if channel.is_none() {
                let handle = unsafe { IcmpCreateFile() };
                if handle == INVALID_HANDLE_VALUE {
                    return Err(format!("ICMP unavailable (Windows error {})", unsafe {
                        GetLastError()
                    }));
                }
                *channel = Some(IcmpChannel {
                    handle,
                    reply: [0; REPLY_WORDS],
                });
            }
            let channel = channel.as_mut().unwrap();
            send_echo(channel, ip, timeout_ms)
        })
    }

    fn send_echo(
        channel: &mut IcmpChannel,
        ip: Ipv4Addr,
        timeout_ms: u32,
    ) -> Result<Option<EchoReply>, String> {
        // Windows supplies ICMP without raw sockets or administrator privileges.
        unsafe {
            // Match the conventional Windows ping payload for ICMP interoperability.
            let payload = ICMP_PAYLOAD;
            let reply = &mut channel.reply;
            reply.fill(0);
            let count = IcmpSendEcho(
                channel.handle,
                u32::from_ne_bytes(ip.octets()),
                payload.as_ptr().cast(),
                payload.len() as u16,
                ptr::null(),
                reply.as_mut_ptr().cast(),
                (reply.len() * size_of::<usize>()) as u32,
                timeout_ms,
            );
            let error = if count == 0 { GetLastError() } else { 0 };
            if count != 0 {
                let reply = &*reply.as_ptr().cast::<ICMP_ECHO_REPLY>();
                if reply.Status == 0 {
                    return Ok(Some(EchoReply {
                        round_trip_ms: f64::from(reply.RoundTripTime),
                        ttl: (reply.Options.Ttl != 0).then_some(reply.Options.Ttl),
                    }));
                }
                return Ok(None);
            }
            // Timeout and destination/network/host unreachable are normal scan outcomes.
            if matches!(error, 11002..=11005 | 11010 | 11013 | 1231 | 1232) {
                Ok(None)
            } else {
                Err(format!("ICMP error {error}"))
            }
        }
    }

    fn local_neighbor(ip: Ipv4Addr) -> Option<(MIB_IPNET_ROW2, SOCKADDR_INET)> {
        if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || ip.is_broadcast() {
            return None;
        }
        unsafe {
            let mut address = SOCKADDR_IN {
                sin_family: AF_INET,
                ..Default::default()
            };
            address.sin_addr.S_un.S_addr = u32::from_ne_bytes(ip.octets());
            let destination = SOCKADDR_INET { Ipv4: address };
            let mut route = MIB_IPFORWARD_ROW2::default();
            let mut source = SOCKADDR_INET::default();
            if GetBestRoute2(
                ptr::null(),
                0,
                ptr::null(),
                &destination,
                0,
                &mut route,
                &mut source,
            ) != 0
                || route.NextHop.si_family != AF_INET
                || route.NextHop.Ipv4.sin_addr.S_un.S_addr != 0
                || source.si_family != AF_INET
                || source.Ipv4.sin_addr.S_un.S_addr == address.sin_addr.S_un.S_addr
            {
                return None;
            }
            let mut row = MIB_IPNET_ROW2 {
                Address: destination,
                InterfaceIndex: route.InterfaceIndex,
                ..Default::default()
            };
            if GetIpNetEntry2(&mut row) != 0 || row.PhysicalAddressLength != 6 {
                return None;
            }
            valid_mac(row.PhysicalAddress[..6].try_into().unwrap()).then_some((row, source))
        }
    }

    pub fn mac_address(ip: Ipv4Addr) -> Option<[u8; 6]> {
        let (row, _) = local_neighbor(ip)?;
        Some(row.PhysicalAddress[..6].try_into().unwrap())
    }

    pub fn discover_arp(ip: Ipv4Addr) -> Option<[u8; 6]> {
        // Ping/TCP first populate neighbors. Only retry known on-link candidates;
        // never count a stale cache entry or a gateway MAC as proof of liveness.
        let (mut row, source) = local_neighbor(ip)?;
        unsafe {
            if ResolveIpNetEntry2(&mut row, &source) != 0 || row.PhysicalAddressLength != 6 {
                return None;
            }
        }
        let mac = row.PhysicalAddress[..6].try_into().unwrap();
        valid_mac(mac).then_some(mac)
    }

    struct ArpRequest {
        ip: Ipv4Addr,
        reply: tokio::sync::oneshot::Sender<Option<[u8; 6]>>,
    }

    fn arp_pool() -> &'static mpsc::SyncSender<ArpRequest> {
        static POOL: OnceLock<mpsc::SyncSender<ArpRequest>> = OnceLock::new();
        POOL.get_or_init(|| {
            let (sender, receiver) = mpsc::sync_channel::<ArpRequest>(128);
            let receiver = Arc::new(Mutex::new(receiver));
            for _ in 0..32 {
                let receiver = receiver.clone();
                thread::spawn(move || {
                    loop {
                        let Ok(request) = receiver.lock().unwrap().recv() else {
                            break;
                        };
                        if !request.reply.is_closed() {
                            let _ = request.reply.send(discover_arp(request.ip));
                        }
                    }
                });
            }
            sender
        })
    }

    pub async fn discover_arp_bounded(
        ip: Ipv4Addr,
        timeout: std::time::Duration,
        cancel: &tokio_util::sync::CancellationToken,
    ) -> Option<[u8; 6]> {
        // ResolveIpNetEntry2 has no cancellable deadline. Keep its OS calls in a fixed,
        // process-lifetime pool so slow stale neighbors cannot hold up scan completion.
        cancel
            .run_until_cancelled(tokio::time::timeout(timeout, async {
                local_neighbor(ip)?;
                let (reply, receiver) = tokio::sync::oneshot::channel();
                let mut request = ArpRequest { ip, reply };
                loop {
                    match arp_pool().try_send(request) {
                        Ok(()) => break,
                        Err(mpsc::TrySendError::Disconnected(_)) => return None,
                        Err(mpsc::TrySendError::Full(returned)) => {
                            request = returned;
                            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                        }
                    }
                }
                receiver.await.ok().flatten()
            }))
            .await?
            .ok()?
    }

    pub fn local_networks() -> Vec<LocalNetwork> {
        unsafe {
            let mut length = 0;
            if GetAdaptersInfo(ptr::null_mut(), &mut length) != ERROR_BUFFER_OVERFLOW {
                return Vec::new();
            }
            let mut memory = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
            let mut adapter = memory.as_mut_ptr().cast::<IP_ADAPTER_INFO>();
            if GetAdaptersInfo(adapter, &mut length) != 0 {
                return Vec::new();
            }
            let mut networks = Vec::new();
            while let Some(current) = adapter.as_ref() {
                let mut address: *const IP_ADDR_STRING = &current.IpAddressList;
                while let Some(current_address) = address.as_ref() {
                    let ip = std::ffi::CStr::from_ptr(current_address.IpAddress.String.as_ptr())
                        .to_str()
                        .ok()
                        .and_then(|s| s.parse::<Ipv4Addr>().ok());
                    let mask = std::ffi::CStr::from_ptr(current_address.IpMask.String.as_ptr())
                        .to_str()
                        .ok()
                        .and_then(|s| s.parse::<Ipv4Addr>().ok());
                    if let (Some(ip), Some(mask)) = (ip, mask)
                        && !ip.is_unspecified()
                        && !ip.is_loopback()
                    {
                        let mask = u32::from(mask);
                        let prefix = mask.leading_ones();
                        let expected = if prefix == 0 {
                            0
                        } else {
                            u32::MAX << (32 - prefix)
                        };
                        if mask == expected && prefix >= 16 {
                            let network = Ipv4Addr::from(u32::from(ip) & mask);
                            let cidr = format!("{network}/{prefix}");
                            if !networks.iter().any(|n: &LocalNetwork| n.cidr == cidr) {
                                networks.push(LocalNetwork { address: ip, cidr });
                            }
                        }
                    }
                    address = current_address.Next;
                }
                adapter = current.Next;
            }
            networks
        }
    }
}

#[cfg(windows)]
pub use platform::{
    discover_arp, discover_arp_bounded, local_networks, mac_address, native_hostname, ping_reply,
};

#[cfg(not(windows))]
pub async fn discover_arp_bounded(
    _ip: Ipv4Addr,
    _timeout: std::time::Duration,
    _cancel: &tokio_util::sync::CancellationToken,
) -> Option<[u8; 6]> {
    None
}

#[cfg(not(windows))]
pub async fn native_hostname(
    _ip: Ipv4Addr,
    _cancel: &tokio_util::sync::CancellationToken,
) -> Option<String> {
    None
}

#[cfg(not(windows))]
pub fn discover_arp(_ip: Ipv4Addr) -> Option<[u8; 6]> {
    None
}

#[cfg(not(windows))]
pub fn ping_reply(_ip: Ipv4Addr, _timeout_ms: u32) -> Result<Option<EchoReply>, String> {
    Err("Native ICMP is only supported on Windows".into())
}

#[cfg(not(windows))]
pub fn mac_address(_ip: Ipv4Addr) -> Option<[u8; 6]> {
    None
}

#[cfg(not(windows))]
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
