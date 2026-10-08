use super::*;
use super::{
    hostname::DnsResolver,
    identity::{Identity, is_alive, probable_brand, vendor},
    probes::PingResult,
};
use crate::{
    discovery::{LocalInfo, WsdDevice},
    network,
    targets::TargetRange,
    udp::{self, UdpResult},
};
use futures_util::{StreamExt, stream};
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use std::{collections::HashMap, net::SocketAddr, sync::Mutex};

#[test]
fn buffered_publication_coalesces_updates_and_flushes_after_cancel() {
    let (sender, events) = mpsc::sync_channel(1);
    let cancel = CancellationToken::new();
    sender
        .send(ScanEvent::Phase("occupy channel".into()))
        .unwrap();
    let mut publisher = ResultPublisher::buffered(&sender, &cancel, None);
    for index in 0..10_000 {
        let mut host = fixture(0);
        host.notes = index.to_string();
        publisher.publish(host);
        assert!(publisher.host(fixture(0).ip).is_some());
    }
    cancel.cancel();
    let reader = thread::spawn(move || {
        let mut revisions = Vec::new();
        while let Ok(event) = events.recv_timeout(Duration::from_secs(5)) {
            match event {
                ScanEvent::Host(host) => revisions.push(host.notes.parse::<usize>().unwrap()),
                ScanEvent::Finished { .. } => break,
                _ => {}
            }
        }
        revisions
    });
    publisher.finish();
    sender
        .send(ScanEvent::Finished {
            elapsed: Duration::ZERO,
            cancelled: true,
        })
        .unwrap();
    let revisions = reader.join().unwrap();
    assert_eq!(revisions.last(), Some(&9_999));
    assert!(revisions.len() <= 2);
    assert!(revisions.windows(2).all(|pair| pair[0] <= pair[1]));
}

#[test]
fn buffered_delivery_disconnect_cancels_without_holding_the_publisher() {
    let (sender, events) = mpsc::sync_channel(1);
    let cancel = CancellationToken::new();
    let mut publisher = ResultPublisher::buffered(&sender, &cancel, None);
    drop(events);
    publisher.publish(fixture(0));
    publisher.finish();
    assert!(cancel.is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn long_port_lists_publish_liveness_before_slow_ports_finish() {
    let cancel = CancellationToken::new();
    let mut partial = None;
    let started = tokio::time::Instant::now();
    let result = probes::collect_port_probes_with_progress(
        &[80, 443],
        2,
        &cancel,
        |port| async move {
            if port == 443 {
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Ok(())
        },
        |ports| {
            if partial.is_none() {
                partial = Some((ports.open.clone(), tokio::time::Instant::now() - started));
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(partial.unwrap(), (vec![80], Duration::ZERO));
    assert_eq!(result.open, vec![80, 443]);
}

#[cfg(windows)]
#[test]
fn native_echo_publishes_an_incomplete_live_row_while_tcp_is_queued() {
    let prober = TcpProber::with_mode(ScanMode::Fast).unwrap();
    let held = prober
        .connections
        .try_acquire_many(FAST_TCP_CONNECTIONS as u32)
        .unwrap();
    let options = ScanOptions {
        mode: ScanMode::Fast,
        targets: TargetRange::parse("127.0.0.1").unwrap(),
        ports: vec![80],
        timeout_ms: 200,
        workers: 1,
        adaptive_concurrency: false,
        resolve_names: false,
        fetch_mac: false,
        fetch_vendor: false,
        discover_arp: false,
        extra: ExtraOptions::default(),
    };
    let cancel = CancellationToken::new();
    let (sender, events) = mpsc::sync_channel(8);
    let publisher = ResultPublisher::new(&sender, &cancel);
    thread::scope(|scope| {
        let worker = scope.spawn(|| {
            scan_host_with_progress(
                Ipv4Addr::LOCALHOST,
                &options,
                &prober,
                &cancel,
                Some(&publisher),
            )
            .unwrap()
        });
        let ScanEvent::Host(partial) = events.recv_timeout(Duration::from_secs(2)).unwrap() else {
            panic!("Expected early row");
        };
        assert_eq!(partial.status, HostStatus::Alive);
        assert!(partial.ping_ms.is_some());
        assert!(!partial.discovery_complete());
        cancel.cancel();
        let stopped = worker.join().unwrap();
        assert_eq!(stopped.status, HostStatus::Alive);
        assert!(!stopped.discovery_complete());
    });
    drop(held);
}

#[test]
fn cached_local_ranges_match_adapter_masks_and_support_large_subnets() {
    let mut prober = TcpProber::new().unwrap();
    let networks = vec![network::LocalNetwork {
        address: Ipv4Addr::new(10, 1, 2, 3),
        cidr: "10.0.0.0/8".into(),
    }];
    prober.set_networks(networks.clone());
    for ip in [
        Ipv4Addr::new(10, 0, 0, 0),
        Ipv4Addr::new(10, 255, 255, 255),
        Ipv4Addr::new(11, 0, 0, 0),
        Ipv4Addr::LOCALHOST,
    ] {
        assert_eq!(!prober.routed(ip), network::is_local_target(ip, &networks));
    }
}

#[test]
fn scheduler_allows_256_host_workers() {
    let cancel = CancellationToken::new();
    let arrived = AtomicUsize::new(0);
    let started = Instant::now();
    assert!(run_host_pipeline(
        256,
        256,
        &cancel,
        |index| {
            arrived.fetch_add(1, Ordering::Relaxed);
            while arrived.load(Ordering::Relaxed) < 256 {
                assert!(
                    started.elapsed() < Duration::from_secs(5),
                    "The scheduler capped the worker pool below 256"
                );
                thread::sleep(Duration::from_millis(1));
            }
            Some(fixture(index))
        },
        |_| None,
        |host| host
    ));
    assert_eq!(arrived.load(Ordering::Relaxed), 256);
}

#[test]
fn route_only_scans_do_not_spawn_the_full_local_worker_ceiling() {
    let mut prober = TcpProber::with_options(ScanMode::Fast, 256, true).unwrap();
    prober.set_networks(vec![network::LocalNetwork {
        address: Ipv4Addr::new(192, 168, 1, 73),
        cidr: "192.168.1.0/24".into(),
    }]);
    let mut options = ScanOptions {
        mode: ScanMode::Fast,
        targets: TargetRange::parse("192.168.1.0/24").unwrap(),
        ports: Vec::new(),
        timeout_ms: 200,
        workers: 256,
        adaptive_concurrency: true,
        resolve_names: false,
        fetch_mac: false,
        fetch_vendor: false,
        discover_arp: false,
        extra: ExtraOptions::default(),
    };
    assert_eq!(prober.host_workers(&options), 256);
    options.targets = TargetRange::parse("192.168.213.0/24").unwrap();
    assert_eq!(prober.host_workers(&options), 128);
    options.targets = TargetRange::parse("192.168.0.0/16").unwrap();
    assert_eq!(prober.host_workers(&options), 256);
}

#[test]
fn rechecking_reports_initial_and_final_counts_despite_throttling() {
    let (sender, events) = mpsc::sync_channel(8);
    let cancel = CancellationToken::new();
    let mut progress = RecheckProgress::new(65_389, &sender, &cancel);
    progress.interval = Duration::from_secs(3600);
    for _ in 0..65_391 {
        progress.completed();
    }
    let messages: Vec<_> = events
        .try_iter()
        .map(|event| {
            let ScanEvent::Phase(message) = event else {
                panic!("Expected rechecking progress");
            };
            message
        })
        .collect();
    assert_eq!(
        messages,
        vec![
            "Rechecking 0 of 65389 addresses without an echo reply (paced confirmation)",
            "Rechecking 65389 of 65389 addresses without an echo reply (paced confirmation)",
        ]
    );
}

#[test]
fn parallel_rechecking_progress_never_moves_backwards() {
    let (sender, events) = mpsc::sync_channel(128);
    let cancel = CancellationToken::new();
    let mut progress = RecheckProgress::new(100, &sender, &cancel);
    progress.interval = Duration::ZERO;
    thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| {
                for _ in 0..25 {
                    progress.completed();
                }
            });
        }
    });
    let messages: Vec<_> = events.try_iter().collect();
    assert_eq!(messages.len(), 101);
    for (current, event) in messages.into_iter().enumerate() {
        let ScanEvent::Phase(message) = event else {
            panic!("Expected rechecking progress");
        };
        assert_eq!(
            message,
            format!(
                "Rechecking {current} of 100 addresses without an echo reply (paced confirmation)"
            )
        );
    }
}

#[test]
fn cancelled_rechecking_does_not_advance_its_counter() {
    let (sender, events) = mpsc::sync_channel(8);
    let cancel = CancellationToken::new();
    let progress = RecheckProgress::new(3, &sender, &cancel);
    cancel.cancel();
    progress.completed();
    assert_eq!(progress.state.lock().unwrap().0, 0);
    assert_eq!(events.try_iter().count(), 1);
}

#[test]
fn progress_cancels_when_its_consumer_disconnects() {
    let (sender, events) = mpsc::sync_channel(8);
    let cancel = CancellationToken::new();
    drop(events);
    RecheckProgress::new(3, &sender, &cancel);
    assert!(cancel.is_cancelled());
}

#[tokio::test(start_paused = true)]
async fn routed_pacer_spreads_parallel_starts_and_cancels_waiters() {
    let pacer = ProbePacer::new(Duration::from_millis(10), 1);
    let cancel = CancellationToken::new();
    let started = tokio::time::Instant::now();
    let mut starts = stream::iter(0..8)
        .map(|_| async {
            assert!(pacer.wait(&cancel).await);
            tokio::time::Instant::now() - started
        })
        .buffer_unordered(8)
        .collect::<Vec<_>>()
        .await;
    starts.sort_unstable();
    for pair in starts.windows(2) {
        assert!(pair[1] - pair[0] >= Duration::from_millis(10));
    }
    let wait = pacer.wait(&cancel);
    let stop = async {
        tokio::time::sleep(Duration::from_millis(1)).await;
        cancel.cancel();
    };
    let (allowed, ()) = join(wait, stop).await;
    assert!(!allowed);
    assert!(!pacer.wait(&cancel).await);
}

#[tokio::test(start_paused = true)]
async fn routed_pacer_does_not_accumulate_unused_burst_tokens() {
    let pacer = ProbePacer::new(Duration::from_millis(10), 1);
    let cancel = CancellationToken::new();
    assert!(pacer.wait(&cancel).await);
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(pacer.wait(&cancel).await);
    let started = tokio::time::Instant::now();
    assert!(pacer.wait(&cancel).await);
    assert!(tokio::time::Instant::now() - started >= Duration::from_millis(10));
}

#[tokio::test(start_paused = true)]
async fn routed_pacer_limits_each_windows_timer_batch() {
    let pacer = ProbePacer::new(Duration::from_millis(16), 8);
    let cancel = CancellationToken::new();
    let started = tokio::time::Instant::now();
    let mut starts = stream::iter(0..24)
        .map(|_| async {
            assert!(pacer.wait(&cancel).await);
            tokio::time::Instant::now() - started
        })
        .buffer_unordered(24)
        .collect::<Vec<_>>()
        .await;
    starts.sort_unstable();
    assert!(starts[..8].iter().all(|time| *time == Duration::ZERO));
    assert!(
        starts[8..16]
            .iter()
            .all(|time| *time == Duration::from_millis(16))
    );
    assert!(
        starts[16..]
            .iter()
            .all(|time| *time == Duration::from_millis(32))
    );
}

#[tokio::test(start_paused = true)]
async fn routed_pacer_applies_adaptive_intervals_with_a_safety_floor() {
    let pacer = ProbePacer::new(Duration::from_millis(16), 1);
    let cancel = CancellationToken::new();
    assert!(pacer.wait(&cancel).await);
    for requested_ms in [64, 32, 0] {
        let started = tokio::time::Instant::now();
        assert!(
            pacer
                .wait_with_interval(&cancel, || Duration::from_millis(requested_ms))
                .await
        );
        assert_eq!(
            tokio::time::Instant::now() - started,
            Duration::from_millis(requested_ms.max(16))
        );
    }
}

#[test]
fn cancellation_releases_routed_connection_and_icmp_waiters() {
    let mut prober = TcpProber::with_mode(ScanMode::Fast).unwrap();
    prober.set_networks(Vec::new());
    let icmp = prober.routed_icmp.try_acquire_many(32).unwrap();
    let tcp = prober.routed_connections.try_acquire_many(64).unwrap();
    let cancel = CancellationToken::new();
    thread::scope(|scope| {
        scope.spawn(|| {
            thread::sleep(Duration::from_millis(20));
            cancel.cancel();
        });
        let (ping, ports) = prober
            .probe(Ipv4Addr::new(192, 0, 2, 1), &[80, 443], 200, 1, &cancel)
            .unwrap();
        assert_eq!(ping.sent, 0);
        assert_eq!(ports.checked, 0);
    });
    drop((icmp, tcp));
    assert_eq!(prober.routed_icmp.available_permits(), 32);
    assert_eq!(prober.routed_connections.available_permits(), 64);
    assert_eq!(prober.connections.available_permits(), FAST_TCP_CONNECTIONS);
}

#[cfg(windows)]
#[test]
fn confirmation_recovers_a_lost_echo_and_then_rescans_tcp() {
    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    let options = ScanOptions {
        mode: ScanMode::Fast,
        targets: TargetRange::parse("127.0.0.1").unwrap(),
        ports: vec![port],
        timeout_ms: 200,
        workers: 1,
        adaptive_concurrency: false,
        resolve_names: false,
        fetch_mac: false,
        fetch_vendor: false,
        discover_arp: false,
        extra: ExtraOptions::default(),
    };
    let prober = TcpProber::with_mode(ScanMode::Fast).unwrap();
    let cancel = CancellationToken::new();
    let (sender, events) = mpsc::sync_channel(8);
    let publisher = ResultPublisher::new(&sender, &cancel);
    let mut host = fixture(1);
    host.ip = Ipv4Addr::LOCALHOST;
    host.extra.icmp_sent = 1;
    host.extra.discovery_complete = Some(true);
    let result = confirm_host(host, &options, &prober, &cancel, &publisher).unwrap();
    assert_eq!(result.status, HostStatus::Alive);
    assert!(result.ping_ms.is_some());
    assert_eq!(result.open_ports, vec![port]);
    assert_eq!((result.extra.icmp_sent, result.extra.icmp_received), (2, 1));
    let ScanEvent::Host(early) = events.try_recv().unwrap() else {
        panic!("Missing early recovery");
    };
    assert_eq!(early.status, HostStatus::Alive);
    assert!(early.ping_ms.is_some());
    assert!(early.open_ports.is_empty());
}

#[tokio::test]
async fn tcp_confirmation_only_retries_inconclusive_ports() {
    let ports = collect_port_probes(
        &[22, 80, 443],
        3,
        &CancellationToken::new(),
        |port| async move {
            match port {
                22 => Ok(()),
                80 => Err(std::io::ErrorKind::ConnectionRefused.into()),
                _ => Err(std::io::ErrorKind::TimedOut.into()),
            }
        },
    )
    .await
    .unwrap();
    assert_eq!(ports.open, vec![22]);
    assert_eq!(ports.refused, 1);
    assert_eq!(ports.unanswered, vec![443]);
    assert_eq!(ports.checked, 3);
}

#[test]
fn confirmation_promotes_silent_hosts_and_keeps_measurement_history() {
    let mut host = fixture(50);
    host.extra.icmp_sent = 1;
    merge_ping(
        &mut host,
        PingResult {
            ping_ms: Some(7.0),
            ttl: Some(62),
            sent: 1,
            received: 1,
            error: None,
        },
        true,
    );
    assert_eq!(host.status, HostStatus::Alive);
    assert_eq!(host.ping_ms, Some(7.0));
    assert_eq!(host.extra.ttl, Some(62));
    assert_eq!((host.extra.icmp_sent, host.extra.icmp_received), (2, 1));
    assert_eq!(host.extra.packet_loss, Some(50.0));
    merge_ping(
        &mut host,
        PingResult {
            ping_ms: Some(9.0),
            ttl: Some(63),
            sent: 1,
            received: 1,
            error: None,
        },
        true,
    );
    assert_eq!(host.ping_ms, Some(8.0));
    assert_eq!(host.extra.ttl, Some(62));
    merge_ping(
        &mut host,
        PingResult {
            sent: 1,
            ..Default::default()
        },
        true,
    );
    assert_eq!(host.status, HostStatus::Alive);
    assert_eq!(host.ping_ms, Some(8.0));
    assert_eq!(host.extra.packet_loss, Some(50.0));
}

#[test]
fn confirmation_candidates_skip_echo_replies_and_incomplete_discovery() {
    let (sender, events) = mpsc::sync_channel(8);
    let cancel = CancellationToken::new();
    let publisher = ResultPublisher::new(&sender, &cancel);
    let silent = fixture(1);
    let mut tcp_alive = fixture(2);
    tcp_alive.status = HostStatus::Alive;
    tcp_alive.open_ports = vec![443];
    let mut echo_alive = fixture(3);
    echo_alive.status = HostStatus::Alive;
    echo_alive.ping_ms = Some(7.0);
    let mut partial = fixture(4);
    partial.extra.discovery_complete = Some(false);
    for host in [silent.clone(), tcp_alive.clone(), echo_alive, partial] {
        publisher.publish(host);
    }
    assert_eq!(publisher.retry_candidates(), vec![silent.ip, tcp_alive.ip]);
    assert_eq!(publisher.host(tcp_alive.ip), Some(tcp_alive));
    assert_eq!(events.try_iter().count(), 4);
}

fn fixture(index: usize) -> HostResult {
    HostResult {
        ip: Ipv4Addr::from(0xc0000200 + index as u32),
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
    }
}

#[test]
fn slow_metadata_does_not_block_basic_results() {
    let published = Mutex::new(Vec::new());
    let basic = AtomicUsize::new(0);
    let start = Instant::now();
    assert!(run_host_pipeline(
        16,
        4,
        &CancellationToken::new(),
        |index| {
            thread::sleep(Duration::from_millis(5));
            Some(fixture(index))
        },
        |mut host| {
            while basic.load(Ordering::Acquire) < 16 {
                assert!(
                    start.elapsed() < Duration::from_secs(3),
                    "Metadata blocked the probe pool"
                );
                thread::sleep(Duration::from_millis(1));
            }
            host.hostname = "done".into();
            Some(host)
        },
        |host| {
            published.lock().unwrap().push(host.hostname.is_empty());
            if host.hostname.is_empty() {
                basic.fetch_add(1, Ordering::Release);
            }
            host
        }
    ));
    let published = published.into_inner().unwrap();
    assert_eq!(published.len(), 32);
    assert!(published[..16].iter().all(|&basic| basic));
}

#[test]
fn cancellation_releases_a_full_metadata_queue() {
    let cancel = CancellationToken::new();
    let basic = AtomicUsize::new(0);
    thread::scope(|scope| {
        scope.spawn(|| {
            let start = Instant::now();
            while basic.load(Ordering::Relaxed) < METADATA_QUEUE + 2
                && start.elapsed() < Duration::from_secs(3)
            {
                thread::sleep(Duration::from_millis(1));
            }
            cancel.cancel();
        });
        assert!(run_host_pipeline(
            10_000,
            1,
            &cancel,
            |index| Some(fixture(index)),
            |_| {
                while !cancel.is_cancelled() {
                    thread::sleep(Duration::from_millis(1));
                }
                None
            },
            |host| {
                basic.fetch_add(1, Ordering::Relaxed);
                host
            }
        ));
    });
    assert_eq!(basic.load(Ordering::Relaxed), METADATA_QUEUE + 2);
}

#[test]
fn panicking_metadata_cancels_without_a_queue_deadlock() {
    let cancel = CancellationToken::new();
    assert!(!run_host_pipeline(
        10_000,
        1,
        &cancel,
        |index| Some(fixture(index)),
        |_| panic!("test worker failure"),
        |host| host
    ));
    assert!(cancel.is_cancelled());
}

#[test]
fn fast_mode_bounds_tcp_concurrency_and_skips_silent_host_enrichment() {
    let prober = TcpProber::with_mode(ScanMode::Fast).unwrap();
    assert_eq!(prober.connections.available_permits(), FAST_TCP_CONNECTIONS);
    let options = ScanOptions {
        mode: ScanMode::Fast,
        targets: TargetRange::parse("192.0.2.1").unwrap(),
        ports: Vec::new(),
        timeout_ms: 5000,
        workers: 128,
        adaptive_concurrency: false,
        resolve_names: true,
        fetch_mac: true,
        fetch_vendor: true,
        discover_arp: true,
        extra: ExtraOptions {
            netbios: true,
            web: true,
            certificates: true,
            banners: true,
            packet_loss: true,
            llmnr: true,
            ..Default::default()
        },
    };
    let web = WebProber::new(Duration::from_secs(5), false).unwrap();
    let cancel = CancellationToken::new();
    let (sender, events) = mpsc::sync_channel(16);
    let publisher = ResultPublisher::new(&sender, &cancel);
    let started = Instant::now();
    assert!(
        enrich_host(
            fixture(1),
            &options,
            None,
            &prober,
            Some(&web),
            &cancel,
            &publisher
        )
        .is_none()
    );
    assert!(started.elapsed() < Duration::from_millis(100));
    assert!(events.try_recv().is_err());
    assert_eq!(prober.connections.available_permits(), FAST_TCP_CONNECTIONS);
    assert_eq!(
        TcpProber::new().unwrap().connections.available_permits(),
        MAX_TCP_CONNECTIONS
    );
}

#[test]
fn fast_udp_can_enrich_a_host_without_baseline_liveness() {
    let socket = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let port = socket.local_addr().unwrap().port();
    let options = ScanOptions {
        mode: ScanMode::Fast,
        targets: TargetRange::parse("127.0.0.1").unwrap(),
        ports: Vec::new(),
        timeout_ms: 500,
        workers: 1,
        adaptive_concurrency: false,
        resolve_names: false,
        fetch_mac: false,
        fetch_vendor: false,
        discover_arp: false,
        extra: ExtraOptions {
            udp: udp::Options {
                ports: vec![port],
                ..Default::default()
            },
            ..Default::default()
        },
    };
    let prober = TcpProber::with_mode(ScanMode::Fast).unwrap();
    let (sender, events) = mpsc::sync_channel(16);
    let cancel = CancellationToken::new();
    let publisher = ResultPublisher::new(&sender, &cancel);
    let mut host = fixture(1);
    host.ip = Ipv4Addr::LOCALHOST;
    let host = publisher.publish(host);
    let result = thread::scope(|scope| {
        scope.spawn(|| {
            let (size, peer) = socket.recv_from(&mut [0; 16]).unwrap();
            assert_eq!(size, 0);
            socket.send_to(b"UDP-only device", peer).unwrap();
        });
        enrich_host(host, &options, None, &prober, None, &cancel, &publisher).unwrap()
    });
    assert_eq!(result.status, HostStatus::Alive);
    assert_eq!(result.extra.udp.open_ports, vec![port]);
    assert!(result.open_ports.is_empty());
    assert!(
        events
            .try_iter()
            .any(|event| matches!(event, ScanEvent::Host(host)
            if host.status == HostStatus::Alive && host.extra.udp.open_ports == [port]))
    );
}

#[test]
fn udp_progress_survives_late_updates_and_only_positive_replies_promote_hosts() {
    let (sender, events) = mpsc::sync_channel(16);
    let cancel = CancellationToken::new();
    let publisher = ResultPublisher::new(&sender, &cancel);
    let mut stale = publisher.publish(fixture(1));
    let mut udp = UdpResult {
        requested: 3,
        completed: 1,
        closed: 1,
        ..Default::default()
    };
    publisher.udp(stale.ip, &udp);
    assert_eq!(
        publisher.state.lock().unwrap().hosts[&stale.ip].status,
        HostStatus::NoResponse
    );
    udp.completed = 2;
    udp.open_ports.push(53);
    udp.dns = "53/udp: reply".into();
    publisher.udp(stale.ip, &udp);
    publisher.udp(stale.ip, &udp);
    assert_eq!(events.try_iter().count(), 3);
    stale.hostname = "late-name".into();
    let latest = publisher.publish(stale);
    assert_eq!(latest.status, HostStatus::Alive);
    assert_eq!(latest.extra.udp, udp);
    assert_eq!(latest.hostname, "late-name");
}

#[test]
fn discovery_and_identity_survive_later_metadata_updates() {
    let (sender, events) = mpsc::sync_channel(16);
    let cancel = CancellationToken::new();
    let publisher = ResultPublisher::new(&sender, &cancel);
    let mut stale = publisher.publish(fixture(1));
    let mut local = LocalInfo::default();
    local.wsd.push(WsdDevice::default());
    let promoted = publisher.discover(HashMap::from([(stale.ip, local)]));
    assert_eq!(promoted.len(), 1);
    publisher.identity(
        stale.ip,
        Identity {
            hostname: "SDCHGS07".into(),
            ..Default::default()
        },
    );
    stale.extra.netbios = "NetBIOS reply".into();
    let latest = publisher.publish(stale);
    assert_eq!(latest.status, HostStatus::Alive);
    assert_eq!(latest.hostname, "SDCHGS07");
    assert_eq!(latest.extra.wsd.len(), 1);
    assert_eq!(latest.extra.netbios, "NetBIOS reply");
    let last = events.try_iter().last().unwrap();
    assert!(
        matches!(last, ScanEvent::Host(host) if host.hostname == "SDCHGS07" && !host.extra.netbios.is_empty())
    );
}

#[test]
fn hostname_race_keeps_success_and_respects_deadlines_and_cancel() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let cancel = CancellationToken::new();
        let slow = || async {
            tokio::time::sleep(Duration::from_secs(10)).await;
            None
        };
        let budget = Duration::from_millis(20);
        assert_eq!(
            first_name(
                slow(),
                async { Some("Windows-name".into()) },
                budget,
                &cancel
            )
            .await
            .as_deref(),
            Some("Windows-name")
        );
        assert_eq!(
            first_name(
                async { None },
                async { Some("Windows-name".into()) },
                budget,
                &cancel
            )
            .await
            .as_deref(),
            Some("Windows-name")
        );
        assert_eq!(
            first_name(async { Some("DNS-name".into()) }, slow(), budget, &cancel)
                .await
                .as_deref(),
            Some("DNS-name")
        );
        assert!(first_name(slow(), slow(), budget, &cancel).await.is_none());
        cancel.cancel();
        assert!(
            first_name(slow(), slow(), Duration::from_secs(10), &cancel)
                .await
                .is_none()
        );
    });
}

#[test]
#[ignore = "Synthetic first-result benchmark; run explicitly with --ignored --nocapture"]
fn pipeline_first_result_benchmark() {
    let start = Instant::now();
    let first = Mutex::new(None);
    let all_basic = Mutex::new(None);
    let basic_count = AtomicUsize::new(0);
    run_host_pipeline(
        16,
        4,
        &CancellationToken::new(),
        |index| {
            thread::sleep(Duration::from_millis(10));
            Some(fixture(index))
        },
        |mut host| {
            thread::sleep(Duration::from_millis(80));
            host.hostname = "ready".into();
            Some(host)
        },
        |host| {
            if host.hostname.is_empty() {
                first.lock().unwrap().get_or_insert(start.elapsed());
                if basic_count.fetch_add(1, Ordering::Relaxed) == 15 {
                    *all_basic.lock().unwrap() = Some(start.elapsed());
                }
            }
            host
        },
    );
    let pipeline_total = start.elapsed();
    let start = Instant::now();
    let previous_first = Mutex::new(None);
    let next = AtomicUsize::new(0);
    thread::scope(|scope| {
        for _ in 0..4 {
            let (previous_first, next) = (&previous_first, &next);
            scope.spawn(move || {
                while next.fetch_add(1, Ordering::Relaxed) < 16 {
                    thread::sleep(Duration::from_millis(90));
                    previous_first
                        .lock()
                        .unwrap()
                        .get_or_insert(start.elapsed());
                }
            });
        }
    });
    println!(
        "Synthetic 16 hosts / 4 workers / 10 ms probe + 80 ms metadata: previous first {:?}, pipeline first {:?}, all basic {:?}, previous total {:?}, pipeline total {:?}",
        previous_first.into_inner().unwrap().unwrap(),
        first.into_inner().unwrap().unwrap(),
        all_basic.into_inner().unwrap().unwrap(),
        start.elapsed(),
        pipeline_total
    );
}

#[test]
fn ping_samples_average_replies_and_count_missing_echoes() {
    let mut replies = [
        Ok(Some(network::EchoReply {
            round_trip_ms: 10.0,
            ttl: Some(64),
        })),
        Ok(None),
        Ok(Some(network::EchoReply {
            round_trip_ms: 30.0,
            ttl: Some(63),
        })),
    ]
    .into_iter();
    let result = collect_pings(3, &CancellationToken::new(), || replies.next().unwrap());
    assert_eq!((result.sent, result.received), (3, 2));
    assert_eq!(result.ping_ms, Some(20.0));
    assert_eq!(result.ttl, Some(64));
    assert!(result.error.is_none());
    let failed = collect_pings(3, &CancellationToken::new(), || Err("API error".into()));
    assert_eq!(failed.sent, 0);
    assert_eq!(failed.error.as_deref(), Some("API error"));
}

#[test]
fn ping_sampling_stops_between_native_calls() {
    let cancel = CancellationToken::new();
    let mut calls = 0;
    let result = collect_pings(10, &cancel, || {
        calls += 1;
        cancel.cancel();
        Ok(None)
    });
    assert_eq!(calls, 1);
    assert_eq!(result.sent, 1);
}

#[test]
fn port_probes_overlap_with_a_bounded_window_and_sorted_results() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let active = AtomicUsize::new(0);
        let peak = AtomicUsize::new(0);
        let ports: Vec<_> = (1..=40).rev().collect();
        let result =
            collect_port_probes(&ports, PORTS_PER_HOST, &CancellationToken::new(), |port| {
                let (active, peak) = (&active, &peak);
                async move {
                    let count = active.fetch_add(1, Ordering::Relaxed) + 1;
                    peak.fetch_max(count, Ordering::Relaxed);
                    tokio::time::sleep(Duration::from_millis(5)).await;
                    active.fetch_sub(1, Ordering::Relaxed);
                    if port % 2 == 0 {
                        Ok(())
                    } else {
                        Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
                    }
                }
            })
            .await
            .unwrap();
        assert_eq!(peak.load(Ordering::Relaxed), PORTS_PER_HOST);
        assert_eq!(active.load(Ordering::Relaxed), 0);
        assert_eq!(result.open, (2..=40).step_by(2).collect::<Vec<_>>());
        assert_eq!(result.refused, 20);
        assert_eq!(result.checked, 40);
    });
}

#[test]
fn cancelled_tcp_probes_drop_pending_work_and_release_slots() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let slots = tokio::sync::Semaphore::new(2);
        let cancel = CancellationToken::new();
        let started = AtomicUsize::new(0);
        let probes =
            collect_port_probes(&[80, 81, 82, 83, 84], PORTS_PER_HOST, &cancel, |_| async {
                let _permit = slots.acquire().await.unwrap();
                started.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(())
            });
        let stop = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel.cancel();
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(1), join(probes, stop))
            .await
            .unwrap();
        let result = result.unwrap();
        assert_eq!(result.checked, 0);
        assert!(result.open.is_empty());
        assert_eq!(started.load(Ordering::Relaxed), 2);
        assert_eq!(slots.available_permits(), 2);
    });
}

#[test]
fn stopping_tcp_probes_keeps_completed_open_and_refused_results() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let cancel = CancellationToken::new();
        let work = collect_port_probes(&[83, 80, 81, 82], 4, &cancel, |port| async move {
            match port {
                80 | 83 => Ok(()),
                81 => Err(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
                _ => {
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Ok(())
                }
            }
        });
        let stop = async {
            tokio::time::sleep(Duration::from_millis(30)).await;
            cancel.cancel();
        };
        let (result, ()) = tokio::time::timeout(Duration::from_secs(1), join(work, stop))
            .await
            .unwrap();
        let result = result.unwrap();
        assert_eq!(result.open, vec![80, 83]);
        assert_eq!(result.refused, 1);
        assert_eq!(result.checked, 3);
        assert!(
            collect_port_probes(&[80], 1, &cancel, |_| async {
                panic!("Cancelled probe started")
            })
            .await
            .is_none()
        );
    });
}

#[cfg(windows)]
#[test]
fn stopping_a_host_with_pending_tcp_keeps_its_successful_ping() {
    let prober = TcpProber::with_mode(ScanMode::Fast).unwrap();
    let guard = prober
        .connections
        .try_acquire_many(FAST_TCP_CONNECTIONS as u32)
        .unwrap();
    let cancel = CancellationToken::new();
    let options = ScanOptions {
        mode: ScanMode::Fast,
        targets: TargetRange::parse("127.0.0.1").unwrap(),
        ports: vec![80],
        timeout_ms: 200,
        workers: 1,
        adaptive_concurrency: false,
        resolve_names: false,
        fetch_mac: false,
        fetch_vendor: false,
        discover_arp: false,
        extra: ExtraOptions::default(),
    };
    let result = thread::scope(|scope| {
        scope.spawn(|| {
            thread::sleep(Duration::from_millis(150));
            cancel.cancel();
        });
        scan_host(Ipv4Addr::LOCALHOST, &options, &prober, &cancel).unwrap()
    });
    assert_eq!(result.status, HostStatus::Alive);
    assert!(result.ping_ms.is_some());
    assert!(!result.discovery_complete());
    assert!(result.notes.contains("stopped"));
    drop(guard);
    assert_eq!(prober.connections.available_permits(), FAST_TCP_CONNECTIONS);
}

#[test]
fn incomplete_discovery_is_not_mislabeled_no_response() {
    let mut host = fixture(1);
    finish_host_discovery(&mut host, false);
    assert_eq!(host.status, HostStatus::Incomplete);
    assert!(!host.discovery_complete());
    let mut alive = fixture(2);
    alive.status = HostStatus::Alive;
    alive.open_ports = vec![443];
    finish_host_discovery(&mut alive, false);
    assert_eq!(alive.status, HostStatus::Alive);
    assert_eq!(alive.open_ports, vec![443]);
    assert!(!alive.discovery_complete());
}

#[test]
fn full_16_pipeline_visits_every_address_including_reported_missing_subnets() {
    let range = TargetRange::parse("192.168.0.0/16").unwrap();
    let visits: Vec<_> = (0..range.len()).map(|_| AtomicUsize::new(0)).collect();
    assert!(run_host_pipeline(
        range.len(),
        8,
        &CancellationToken::new(),
        |index| {
            let mut host = fixture(0);
            host.ip = Ipv4Addr::from(range.first + index as u32);
            Some(host)
        },
        |_| None,
        |host| {
            visits[(u32::from(host.ip) - range.first) as usize].fetch_add(1, Ordering::Relaxed);
            host
        }
    ));
    assert!(
        visits
            .iter()
            .all(|count| count.load(Ordering::Relaxed) == 1)
    );
    for ip in [
        Ipv4Addr::new(192, 168, 213, 1),
        Ipv4Addr::new(192, 168, 212, 8),
    ] {
        assert_eq!(
            visits[(u32::from(ip) - range.first) as usize].load(Ordering::Relaxed),
            1
        );
    }
}

#[test]
#[ignore = "Deterministic latency benchmark; run explicitly with --ignored --nocapture"]
fn port_probe_latency_benchmark() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let ports: Vec<_> = (1..=12).collect();
    let cancel = CancellationToken::new();
    let mut elapsed = Vec::new();
    for parallelism in [1, PORTS_PER_HOST] {
        let started = Instant::now();
        let result = runtime
            .block_on(collect_port_probes(
                &ports,
                parallelism,
                &cancel,
                |_| async {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    Err(std::io::Error::from(std::io::ErrorKind::TimedOut))
                },
            ))
            .unwrap();
        assert!(result.open.is_empty());
        elapsed.push(started.elapsed());
    }
    println!(
        "12 simulated 100 ms port probes: sequential {:?}, concurrent {:?}, {:.1}x faster",
        elapsed[0],
        elapsed[1],
        elapsed[0].as_secs_f64() / elapsed[1].as_secs_f64()
    );
    assert!(elapsed[1] < elapsed[0] / 2);
}

fn test_dns_config(address: SocketAddr) -> ResolverConfig {
    use hickory_resolver::config::{NameServerConfig, Protocol};
    ResolverConfig::from_parts(
        None,
        Vec::new(),
        vec![NameServerConfig {
            socket_addr: address,
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: true,
            bind_addr: None,
        }],
    )
}

#[test]
fn reverse_dns_uses_ptr_records() {
    use hickory_resolver::proto::{
        op::{Message, MessageType},
        rr::{Name, RData, Record, rdata::PTR},
    };
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let config = test_dns_config(socket.local_addr().unwrap());
    let server = thread::spawn(move || {
        let mut bytes = [0u8; 4096];
        let (length, peer) = socket.recv_from(&mut bytes).unwrap();
        let query = Message::from_vec(&bytes[..length]).unwrap();
        let mut response = Message::new();
        response
            .set_id(query.id())
            .set_message_type(MessageType::Response)
            .set_authoritative(true)
            .set_recursion_available(true);
        response.add_queries(query.queries().iter().cloned());
        response.add_answer(Record::from_rdata(
            query.queries()[0].name().clone(),
            60,
            RData::PTR(PTR(Name::from_ascii("test.scout.local.").unwrap())),
        ));
        socket.send_to(&response.to_vec().unwrap(), peer).unwrap();
    });
    let resolver = DnsResolver::new(config, ResolverOpts::default(), 1000).unwrap();
    assert_eq!(
        resolver.reverse_name(Ipv4Addr::new(192, 0, 2, 1), &CancellationToken::new()),
        Some("test.scout.local".into())
    );
    server.join().unwrap();
}

#[test]
fn unanswered_dns_has_an_overall_deadline() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let resolver = DnsResolver::new(
        test_dns_config(socket.local_addr().unwrap()),
        ResolverOpts::default(),
        100,
    )
    .unwrap();
    let start = Instant::now();
    assert!(
        resolver
            .reverse_name(Ipv4Addr::new(192, 0, 2, 1), &CancellationToken::new())
            .is_none()
    );
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn tcp_listener_is_discovered_on_loopback() {
    let listeners: Vec<_> = (0..3)
        .map(|_| std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap())
        .collect();
    let ports: Vec<_> = listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap().port())
        .collect();
    let mut expected = ports.clone();
    expected.sort_unstable();
    let options = ScanOptions {
        mode: ScanMode::Thorough,
        targets: TargetRange::parse("127.0.0.1").unwrap(),
        ports,
        timeout_ms: 200,
        workers: 1,
        adaptive_concurrency: false,
        resolve_names: false,
        fetch_mac: false,
        fetch_vendor: false,
        discover_arp: true,
        extra: ExtraOptions::default(),
    };
    let handle = start_scan(options);
    let mut found = false;
    loop {
        match handle.events.recv_timeout(Duration::from_secs(5)).unwrap() {
            ScanEvent::Host(host) => {
                assert_eq!(host.status, HostStatus::Alive);
                if host.discovery_complete() {
                    assert_eq!(host.open_ports, expected);
                    found = true;
                }
            }
            ScanEvent::Finished { cancelled, .. } => {
                assert!(!cancelled);
                break;
            }
            ScanEvent::Phase(_) | ScanEvent::Concurrency(_) => {}
            ScanEvent::Warning(message) => panic!("{message}"),
        }
    }
    assert!(found);
}

#[test]
fn scan_collects_a_custom_web_server_and_optional_ping_statistics() {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = thread::spawn(move || {
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            match listener.accept() {
                Ok((mut socket, _)) => {
                    socket.set_nonblocking(false).unwrap();
                    socket
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    let mut bytes = [0; 2048];
                    let mut length = socket.read(&mut bytes).unwrap_or(0);
                    // A custom port may also receive a TLS probe; respond only to HTTP.
                    if bytes[..length].starts_with(b"HEAD ") || bytes[..length].starts_with(b"GET ")
                    {
                        while length < bytes.len()
                            && !bytes[..length].windows(4).any(|part| part == b"\r\n\r\n")
                        {
                            let count = socket.read(&mut bytes[length..]).unwrap_or(0);
                            if count == 0 {
                                break;
                            }
                            length += count;
                        }
                        socket.write_all(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\nConnection: close\r\nContent-Length: 0\r\n\r\n").unwrap();
                        return;
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => panic!("{error}"),
            }
        }
        panic!("No HTTP request reached the custom port");
    });
    let handle = start_scan(ScanOptions {
        mode: ScanMode::Fast,
        targets: TargetRange::parse("127.0.0.1").unwrap(),
        ports: vec![port],
        timeout_ms: 500,
        workers: 1,
        adaptive_concurrency: false,
        resolve_names: false,
        fetch_mac: false,
        fetch_vendor: false,
        discover_arp: false,
        extra: ExtraOptions {
            web: true,
            packet_loss: true,
            ..Default::default()
        },
    });
    let basic = match handle.events.recv_timeout(Duration::from_secs(5)).unwrap() {
        ScanEvent::Host(host) => host,
        ScanEvent::Phase(_) | ScanEvent::Concurrency(_) => {
            panic!("No host result before confirmation")
        }
        ScanEvent::Warning(message) => panic!("{message}"),
        ScanEvent::Finished { .. } => panic!("No host result"),
    };
    assert_eq!(basic.status, HostStatus::Alive);
    let mut latest = Some(basic);
    loop {
        match handle.events.recv_timeout(Duration::from_secs(5)).unwrap() {
            ScanEvent::Host(host) => latest = Some(host),
            ScanEvent::Phase(_) | ScanEvent::Concurrency(_) => {}
            ScanEvent::Warning(message) => panic!("{message}"),
            ScanEvent::Finished { cancelled, .. } => {
                assert!(!cancelled);
                break;
            }
        }
    }
    let host = latest.expect("No enriched host result");
    assert_eq!(host.status, HostStatus::Alive);
    assert_eq!(host.open_ports, vec![port]);
    let web = host
        .extra
        .web
        .iter()
        .find(|service| service.url == format!("http://127.0.0.1:{port}/"))
        .unwrap_or_else(|| panic!("Custom HTTP endpoint missing from {host:#?}"));
    assert_eq!(web.server, "Apache/2.4");
    assert_eq!(web.status, 200);
    #[cfg(windows)]
    {
        assert!(host.extra.ttl.is_some());
        assert_eq!(host.extra.packet_loss, Some(0.0));
        assert_eq!((host.extra.icmp_sent, host.extra.icmp_received), (3, 3));
    }
    server.join().unwrap();
}

#[test]
fn cancellation_stops_a_large_scan_promptly() {
    let handle = start_scan(ScanOptions {
        mode: ScanMode::Thorough,
        targets: TargetRange::parse("127.0.0.0/16").unwrap(),
        ports: Vec::new(),
        timeout_ms: 100,
        workers: 2,
        adaptive_concurrency: false,
        resolve_names: false,
        fetch_mac: false,
        fetch_vendor: false,
        discover_arp: true,
        extra: ExtraOptions::default(),
    });
    handle.cancel();
    loop {
        if let ScanEvent::Finished { cancelled, .. } =
            handle.events.recv_timeout(Duration::from_secs(5)).unwrap()
        {
            assert!(cancelled);
            break;
        }
    }
}

#[cfg(windows)]
#[test]
fn native_ping_reaches_loopback() {
    assert!(network::ping(Ipv4Addr::LOCALHOST, 1000).unwrap().is_some());
    assert!(
        network::ping_reply(Ipv4Addr::LOCALHOST, 1000)
            .unwrap()
            .unwrap()
            .ttl
            .is_some()
    );
}

#[test]
fn locally_administered_mac_does_not_claim_a_vendor() {
    assert!(vendor([0x02, 0, 0, 0, 0, 1]).is_none());
    assert!(vendors().len() > 1000);
}

#[test]
fn arp_response_alone_is_alive_but_no_probes_is_not() {
    assert!(is_alive(None, &[], 0, true));
    assert!(!is_alive(None, &[], 0, false));
}

#[test]
fn most_specific_mac_assignment_wins() {
    let table = HashMap::from([
        ((24, 0x001122), "Large".into()),
        ((28, 0x0011223), "Medium".into()),
        ((36, 0x001122334), "Small".into()),
    ]);
    assert_eq!(
        lookup_vendor([0, 0x11, 0x22, 0x33, 0x44, 0x55], &table),
        Some("Small")
    );
    assert_eq!(
        lookup_vendor([0, 0x11, 0x22, 0x35, 0, 0], &table),
        Some("Medium")
    );
    assert_eq!(
        lookup_vendor([0, 0x11, 0x22, 0x45, 0, 0], &table),
        Some("Large")
    );
}

#[test]
fn bundled_small_and_medium_mac_assignments_are_loaded() {
    assert_eq!(
        vendor([0xC8, 0x5C, 0xE2, 0x70, 0, 1]),
        Some("SYNERGY SYSTEMS AND SOLUTIONS")
    );
    assert_eq!(
        vendor([0x8C, 0x1F, 0x64, 0xAF, 0xA0, 1]),
        Some("DATA ELECTRONIC DEVICES, INC")
    );
    assert!(vendors().len() > 40000);
}

#[test]
fn randomized_mac_does_not_invent_a_brand() {
    let mac = [0xCA, 0xC7, 0xCC, 0x87, 0xCC, 0xE2];
    assert!(vendor(mac).is_none());
    assert_eq!(probable_brand(mac, ""), "Unknown (randomized/local MAC)");
    assert_eq!(
        probable_brand(mac, "Galaxy-S23.home"),
        "Samsung (hostname hint, unverified)"
    );
    assert_eq!(
        probable_brand(mac, "apple-pie"),
        "Unknown (randomized/local MAC)"
    );
}
