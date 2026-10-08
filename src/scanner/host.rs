use super::{
    hostname::DnsResolver,
    identity::{
        Identity, apply_identity, identity, identity_async, is_alive, probable_brand, vendor,
    },
    model::*,
    pipeline::ResultPublisher,
    probes::{PingResult, TcpProber},
};
use crate::{
    adaptive::Observation,
    advertisements, discovery,
    metadata::{self, WebProber},
    network,
    targets::TargetRange,
};
use futures_util::future::join;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Mutex,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[cfg(test)]
pub(super) fn scan_host(
    ip: Ipv4Addr,
    options: &ScanOptions,
    prober: &TcpProber,
    cancel: &CancellationToken,
) -> Option<HostResult> {
    scan_host_with_progress(ip, options, prober, cancel, None)
}

pub(super) fn scan_host_with_progress(
    ip: Ipv4Addr,
    options: &ScanOptions,
    prober: &TcpProber,
    cancel: &CancellationToken,
    publisher: Option<&ResultPublisher<'_>>,
) -> Option<HostResult> {
    let _budget = if prober.routed(ip) {
        None
    } else {
        Some(
            prober
                .runtime
                .block_on(prober.local_adaptive.acquire(cancel))?,
        )
    };
    let mut result = HostResult {
        ip,
        status: HostStatus::NoResponse,
        ping_ms: None,
        hostname: String::new(),
        mac: String::new(),
        vendor: String::new(),
        open_ports: Vec::new(),
        refused_ports: 0,
        notes: String::new(),
        arp_response: false,
        probable_brand: String::new(),
        extra: ExtraResult::default(),
    };
    let partial = Mutex::new(result.clone());
    let (ping, ports) = prober.probe_progress(
        ip,
        &options.ports,
        options.timeout_ms,
        1,
        cancel,
        (
            |ping| {
                if let Some(publisher) = publisher
                    && ping.received > 0
                {
                    let mut host = partial.lock().unwrap();
                    host.status = HostStatus::Alive;
                    host.ping_ms = ping.ping_ms;
                    host.extra.ttl = ping.ttl;
                    host.extra.icmp_sent = ping.sent;
                    host.extra.icmp_received = ping.received;
                    host.extra.discovery_complete = Some(false);
                    publisher.publish(host.clone());
                }
            },
            |ports| {
                if let Some(publisher) = publisher {
                    let mut host = partial.lock().unwrap();
                    host.status = HostStatus::Alive;
                    host.open_ports.clone_from(&ports.open);
                    host.open_ports.sort_unstable();
                    host.refused_ports = ports.refused;
                    host.extra.discovery_complete = Some(false);
                    publisher.publish(host.clone());
                }
            },
        ),
    )?;
    result.ping_ms = ping.ping_ms;
    result.extra.ttl = ping.ttl;
    result.extra.icmp_sent = ping.sent;
    result.extra.icmp_received = ping.received;
    if options.extra.packet_loss
        && options.extra.icmp_samples <= 1
        && ping.sent > 0
        && ping.error.is_none()
    {
        result.extra.packet_loss =
            Some(100.0 * f64::from(ping.sent - ping.received) / f64::from(ping.sent));
    }
    if let Some(error) = ping.error {
        result.notes = error;
    }
    result.open_ports = ports.open;
    result.refused_ports = ports.refused;
    let probes_complete =
        ports.checked == options.ports.len() && (ping.sent > 0 || !result.notes.is_empty());
    if is_alive(
        result.ping_ms,
        &result.open_ports,
        result.refused_ports,
        false,
    ) {
        result.status = HostStatus::Alive;
    }
    if result.status == HostStatus::Alive && prober.routed(ip) {
        result.extra.retry_tcp = ports.unanswered;
    }
    if cancel.is_cancelled() {
        let complete =
            probes_complete && (result.status == HostStatus::Alive || !options.discover_arp);
        finish_host_discovery(&mut result, complete);
        return Some(result);
    }
    let arp_mac =
        if options.discover_arp && result.status == HostStatus::NoResponse && !prober.routed(ip) {
            if options.mode == ScanMode::Fast {
                prober.runtime.block_on(network::discover_arp_bounded(
                    ip,
                    Duration::from_millis(u64::from(options.timeout_ms.max(1))),
                    cancel,
                ))
            } else {
                network::discover_arp(ip)
            }
        } else {
            None
        };
    result.arp_response = arp_mac.is_some();
    if options.fetch_mac
        && let Some(mac) = arp_mac
    {
        result.mac = network::format_mac(mac);
    }
    if is_alive(
        result.ping_ms,
        &result.open_ports,
        result.refused_ports,
        result.arp_response,
    ) {
        result.status = HostStatus::Alive;
    }
    if cancel.is_cancelled() {
        finish_host_discovery(&mut result, false);
        return Some(result);
    }
    if result.status == HostStatus::Alive
        && !prober.routed(ip)
        && options.fetch_mac
        && let Some(mac) = arp_mac.or_else(|| network::mac_address(ip))
    {
        result.mac = network::format_mac(mac);
        if options.fetch_vendor {
            result.vendor = vendor(mac).unwrap_or_default().to_owned();
            if result.vendor.is_empty() {
                result.probable_brand = probable_brand(mac, "");
            }
        }
    }
    finish_host_discovery(&mut result, probes_complete);
    if !cancel.is_cancelled() && !prober.routed(ip) {
        prober
            .local_adaptive
            .observe(if result.status == HostStatus::Alive {
                Observation::Reply {
                    rtt_ms: result.ping_ms,
                    timeout_ms: options.timeout_ms,
                }
            } else {
                Observation::Silent
            });
    }
    Some(result)
}

pub(super) fn finish_host_discovery(result: &mut HostResult, complete: bool) {
    result.extra.discovery_complete = Some(complete);
    if !complete {
        if result.status == HostStatus::NoResponse {
            result.status = HostStatus::Incomplete;
        }
        if !result.notes.is_empty() {
            result.notes.push_str("; ");
        }
        result
            .notes
            .push_str("Scan stopped before host discovery finished");
    }
}

pub(super) fn merge_ping(result: &mut HostResult, ping: PingResult, packet_loss: bool) {
    let previous = result.extra.icmp_received;
    let received = previous.saturating_add(ping.received);
    if ping.received > 0 {
        result.ping_ms = Some(
            (result.ping_ms.unwrap_or_default() * f64::from(previous)
                + ping.ping_ms.unwrap_or_default() * f64::from(ping.received))
                / f64::from(received),
        );
        result.status = HostStatus::Alive;
    }
    result.extra.ttl = result.extra.ttl.or(ping.ttl);
    result.extra.icmp_sent = result.extra.icmp_sent.saturating_add(ping.sent);
    result.extra.icmp_received = received;
    if packet_loss && result.extra.icmp_sent > 0 && ping.error.is_none() {
        result.extra.packet_loss = Some(
            100.0 * f64::from(result.extra.icmp_sent - received)
                / f64::from(result.extra.icmp_sent),
        );
    }
    if let Some(error) = ping.error
        && !result.notes.contains(&error)
    {
        if !result.notes.is_empty() {
            result.notes.push_str("; ");
        }
        result.notes.push_str(&error);
    }
}

pub(super) fn confirm_host(
    mut result: HostResult,
    options: &ScanOptions,
    prober: &TcpProber,
    cancel: &CancellationToken,
    publisher: &ResultPublisher<'_>,
) -> Option<HostResult> {
    if cancel.is_cancelled() {
        return None;
    }
    let was_alive = result.status == HostStatus::Alive;
    let routed = prober.routed(result.ip);
    let timeout_ms = options.timeout_ms.max(if routed {
        if options.mode == ScanMode::Fast {
            750
        } else {
            1500
        }
    } else {
        options.timeout_ms
    });
    let attempts = if options.mode == ScanMode::Fast { 1 } else { 2 };
    for attempt in 0..attempts {
        if cancel.is_cancelled() {
            break;
        }
        if attempt > 0
            && !prober.runtime.block_on(async {
                cancel
                    .run_until_cancelled(tokio::time::sleep(Duration::from_millis(100)))
                    .await
                    .is_some()
            })
        {
            break;
        }
        let ping = prober
            .runtime
            .block_on(prober.echo(result.ip, timeout_ms, 1, cancel));
        merge_ping(&mut result, ping, options.extra.packet_loss);
        if result.ping_ms.is_some() {
            prober.controller(result.ip).observe(Observation::LostReply);
            break;
        }
    }
    if result.ping_ms.is_some() && !was_alive {
        // Reveal recovered liveness before port/identity work, including when Stop is pressed.
        publisher.publish(result.clone());
        if !cancel.is_cancelled()
            && let Some(ports) =
                prober
                    .runtime
                    .block_on(prober.ports(result.ip, &options.ports, timeout_ms, cancel))
        {
            result.open_ports = ports.open;
            result.extra.retry_tcp = ports.unanswered;
            result.refused_ports = ports.refused;
            if ports.checked < options.ports.len() {
                if !result.notes.is_empty() {
                    result.notes.push_str("; ");
                }
                result
                    .notes
                    .push_str("Scan stopped during TCP confirmation");
            }
        }
    }
    Some(result)
}

pub(super) fn enrich_host(
    mut result: HostResult,
    options: &ScanOptions,
    resolver: Option<&DnsResolver>,
    prober: &TcpProber,
    web: Option<&WebProber>,
    cancel: &CancellationToken,
    publisher: &ResultPublisher<'_>,
) -> Option<HostResult> {
    if cancel.is_cancelled() {
        return None;
    }
    let ip = result.ip;
    let initial_alive = result.status == HostStatus::Alive;
    if options.mode == ScanMode::Fast && !initial_alive && !options.extra.udp.enabled() {
        return None;
    }
    let retry_tcp = initial_alive && prober.routed(ip) && !result.extra.retry_tcp.is_empty();
    if retry_tcp {
        let timeout_ms = options.timeout_ms.max(if options.mode == ScanMode::Fast {
            750
        } else {
            1500
        });
        if let Some(ports) =
            prober
                .runtime
                .block_on(prober.ports(ip, &result.extra.retry_tcp, timeout_ms, cancel))
        {
            result.open_ports.extend(ports.open);
            result.open_ports.sort_unstable();
            result.open_ports.dedup();
            result.refused_ports += ports.refused;
            result.extra.retry_tcp = ports.unanswered;
            publisher.publish(result.clone());
        }
        if cancel.is_cancelled() {
            return Some(result);
        }
    }
    if !(options.extra.udp.enabled()
        || options.extra.netbios
        || web.is_some()
        || options.extra.llmnr
        || options.extra.banners
        || options.extra.certificates
        || options.extra.packet_loss && options.extra.icmp_samples > 1
        || initial_alive && (options.resolve_names || options.fetch_mac))
    {
        return retry_tcp.then_some(result);
    }
    let initial_ping = PingResult {
        ping_ms: result.ping_ms,
        ttl: result.extra.ttl,
        sent: result.extra.icmp_sent,
        received: result.extra.icmp_received,
        error: (!result.notes.is_empty()).then(|| result.notes.clone()),
    };
    let probe_extra = options.mode == ScanMode::Thorough || initial_alive;
    let identity = prober.runtime.block_on(async {
        let identity = async {
            if initial_alive {
                let info = identity_async(ip, options, resolver, !prober.routed(ip), cancel).await;
                if !cancel.is_cancelled() {
                    publisher.identity(ip, info.clone());
                }
                info
            } else {
                Identity::default()
            }
        };
        let measurements = async {
            if probe_extra && options.extra.packet_loss && options.extra.icmp_samples > 1 {
                let (samples, timeout_ms) = (options.extra.icmp_samples, options.timeout_ms);
                prober
                    .sample_echo(ip, initial_ping, samples, timeout_ms, cancel)
                    .await
            } else {
                initial_ping
            }
        };
        let open_ports = &result.open_ports;
        let banners = async {
            if probe_extra && options.extra.banners {
                prober
                    .inventory
                    .banners(
                        ip,
                        open_ports,
                        Duration::from_millis(u64::from(options.timeout_ms.max(1))),
                        cancel,
                    )
                    .await
            } else {
                Vec::new()
            }
        };
        let certificates = async {
            if probe_extra && options.extra.certificates && web.is_none() {
                prober
                    .inventory
                    .certificates(
                        ip,
                        &options.ports,
                        open_ports,
                        &[],
                        Duration::from_millis(u64::from(options.timeout_ms.max(1))),
                        cancel,
                    )
                    .await
            } else {
                Vec::new()
            }
        };
        let metadata = async {
            if probe_extra && (options.extra.netbios || web.is_some() || options.extra.llmnr) {
                let timeout = Duration::from_millis(u64::from(options.timeout_ms.max(1)));
                let ((netbios, services), llmnr) = async {
                    let source = if options.extra.llmnr {
                        discovery::interfaces_for(
                            &prober.networks,
                            &TargetRange {
                                first: u32::from(ip),
                                last: u32::from(ip),
                            },
                        )
                        .first()
                        .copied()
                    } else {
                        None
                    };
                    join(
                        join(
                            async {
                                if options.extra.netbios {
                                    metadata::netbios(
                                        SocketAddr::new(IpAddr::V4(ip), 137),
                                        timeout,
                                        cancel,
                                    )
                                    .await
                                } else {
                                    None
                                }
                            },
                            async {
                                if let Some(web) = web {
                                    web.probe_scanned(
                                        ip,
                                        &options.ports,
                                        &result.open_ports,
                                        timeout,
                                        cancel,
                                    )
                                    .await
                                } else {
                                    Vec::new()
                                }
                            },
                        ),
                        async {
                            if options.extra.llmnr
                                && let Some(source) = source
                            {
                                advertisements::llmnr(ip, source, timeout, cancel).await
                            } else {
                                None
                            }
                        },
                    )
                    .await
                }
                .await;
                result.extra.netbios = netbios.unwrap_or_default();
                result.extra.web = services;
                result.extra.llmnr = llmnr.unwrap_or_default();
                if !result.extra.netbios.is_empty()
                    || !result.extra.web.is_empty()
                    || !result.extra.llmnr.is_empty()
                {
                    result.status = HostStatus::Alive;
                }
            }
        };
        let udp = prober.udp.scan(
            ip,
            &options.extra.udp,
            Duration::from_millis(u64::from(options.timeout_ms.max(1))),
            options.mode == ScanMode::Thorough,
            cancel,
            |udp| publisher.udp(ip, udp),
        );
        let (certificates, (udp, (identity, (ping, ((), banners))))) = join(
            certificates,
            join(
                udp,
                join(identity, join(measurements, join(metadata, banners))),
            ),
        )
        .await;
        result.extra.udp = udp;
        if !result.extra.udp.open_ports.is_empty() {
            result.status = HostStatus::Alive;
        }
        result.extra.banners = banners;
        result.extra.certificates = certificates;
        if !result.extra.certificates.is_empty() {
            result.status = HostStatus::Alive;
        }
        if !result.extra.banners.is_empty() {
            result.status = HostStatus::Alive;
        }
        result.ping_ms = ping.ping_ms;
        result.extra.ttl = ping.ttl;
        result.extra.icmp_sent = ping.sent;
        result.extra.icmp_received = ping.received;
        if options.extra.packet_loss && ping.sent > 0 && ping.error.is_none() {
            result.extra.packet_loss =
                Some(100.0 * f64::from(ping.sent - ping.received) / f64::from(ping.sent));
        }
        if let Some(error) = ping.error {
            result.notes = error;
        }
        if ping.received > 0 {
            result.status = HostStatus::Alive;
        }
        identity
    });
    if probe_extra && options.extra.certificates && web.is_some() && !cancel.is_cancelled() {
        // Web detection supplies confirmed HTTPS custom ports; keep the primary rows visible
        // while the certificate-only handshake runs afterward.
        publisher.publish(result.clone());
        result.extra.certificates = prober.runtime.block_on(prober.inventory.certificates(
            ip,
            &options.ports,
            &result.open_ports,
            &result.extra.web,
            Duration::from_millis(u64::from(options.timeout_ms.max(1))),
            cancel,
        ));
        if !result.extra.certificates.is_empty() {
            result.status = HostStatus::Alive;
        }
    }
    if cancel.is_cancelled() {
        if initial_alive {
            apply_identity(&mut result, identity);
        }
        return Some(result);
    }
    if result.status == HostStatus::Alive {
        let identity = if initial_alive {
            identity
        } else {
            self::identity(ip, options, resolver, prober, cancel)
        };
        apply_identity(&mut result, identity);
    }
    Some(result)
}
