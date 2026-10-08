use super::{
    FAST_TCP_CONNECTIONS, MAX_HOST_WORKERS, MAX_TCP_CONNECTIONS, PORTS_PER_HOST, model::*,
};
use crate::{
    adaptive::{AdaptiveConcurrency, Observation},
    inventory::InventoryProber,
    network,
    udp::UdpProber,
};
use futures_util::{StreamExt, future::join, stream};
use std::thread;
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Mutex,
        mpsc::{self, SyncSender},
    },
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

pub(super) struct ProbePacer {
    pub(super) window: tokio::sync::Mutex<(tokio::time::Instant, usize)>,
    pub(super) interval: Duration,
    pub(super) batch: usize,
}

impl ProbePacer {
    pub(super) fn new(interval: Duration, batch: usize) -> Self {
        Self {
            window: tokio::sync::Mutex::new((tokio::time::Instant::now(), 0)),
            interval,
            batch: batch.max(1),
        }
    }

    #[cfg(test)]
    pub(super) async fn wait(&self, cancel: &CancellationToken) -> bool {
        self.wait_with_interval(cancel, || self.interval).await
    }

    pub(super) async fn wait_with_interval(
        &self,
        cancel: &CancellationToken,
        interval: impl Fn() -> Duration,
    ) -> bool {
        if cancel.is_cancelled() {
            return false;
        }
        let Some(mut window) = cancel.run_until_cancelled(self.window.lock()).await else {
            return false;
        };
        let interval = interval().max(self.interval);
        let now = tokio::time::Instant::now();
        if now >= window.0 + interval {
            *window = (now, 0);
        }
        if window.1 >= self.batch {
            if cancel
                .run_until_cancelled(tokio::time::sleep_until(window.0 + interval))
                .await
                .is_none()
            {
                return false;
            }
            // Windows timers can have coarse granularity; use small batches, never catch-up bursts.
            *window = (tokio::time::Instant::now(), 0);
        }
        window.1 += 1;
        true
    }
}

#[derive(Default)]
pub(super) struct PortResult {
    pub(super) open: Vec<u16>,
    pub(super) unanswered: Vec<u16>,
    pub(super) refused: usize,
    pub(super) checked: usize,
}

#[derive(Default)]
pub(super) struct PingResult {
    pub(super) ping_ms: Option<f64>,
    pub(super) ttl: Option<u8>,
    pub(super) sent: u8,
    pub(super) received: u8,
    pub(super) error: Option<String>,
}

pub(super) fn collect_pings(
    samples: u8,
    cancel: &CancellationToken,
    mut ping: impl FnMut() -> Result<Option<network::EchoReply>, String>,
) -> PingResult {
    extend_pings(PingResult::default(), samples, cancel, &mut ping)
}

pub(super) fn extend_pings(
    mut result: PingResult,
    samples: u8,
    cancel: &CancellationToken,
    mut ping: impl FnMut() -> Result<Option<network::EchoReply>, String>,
) -> PingResult {
    let mut total_ms = result.ping_ms.unwrap_or_default() * f64::from(result.received);
    if result.error.is_some() {
        return result;
    }
    for index in result.sent..samples.clamp(1, 10) {
        if cancel.is_cancelled() {
            break;
        }
        if index > 0 {
            // Space multi-sample measurements; cancellation waits at most one ICMP timeout.
            for _ in 0..10 {
                if cancel.is_cancelled() {
                    return result;
                }
                thread::sleep(Duration::from_millis(10));
            }
        }
        match ping() {
            Ok(reply) => {
                result.sent += 1;
                if let Some(reply) = reply {
                    result.received += 1;
                    total_ms += reply.round_trip_ms;
                    result.ttl = result.ttl.or(reply.ttl);
                    result.ping_ms = Some(total_ms / f64::from(result.received));
                }
            }
            Err(error) => {
                result.error = Some(error);
                break;
            }
        }
    }
    result
}

#[cfg(test)]
pub(super) async fn collect_port_probes<F, Fut>(
    ports: &[u16],
    parallelism: usize,
    cancel: &CancellationToken,
    probe: F,
) -> Option<PortResult>
where
    F: Fn(u16) -> Fut,
    Fut: Future<Output = std::io::Result<()>>,
{
    collect_port_probes_with_progress(ports, parallelism, cancel, probe, |_| {}).await
}

pub(super) async fn collect_port_probes_with_progress<F, Fut>(
    ports: &[u16],
    parallelism: usize,
    cancel: &CancellationToken,
    probe: F,
    mut progress: impl FnMut(&PortResult),
) -> Option<PortResult>
where
    F: Fn(u16) -> Fut,
    Fut: Future<Output = std::io::Result<()>>,
{
    if cancel.is_cancelled() {
        return None;
    }
    let mut result = PortResult::default();
    let mut reported = false;
    let mut last_report = Instant::now();
    let _ = cancel
        .run_until_cancelled(async {
            let mut pending = stream::iter(ports.iter().copied())
                .map(|port| {
                    let future = probe(port);
                    async move { (port, future.await) }
                })
                .buffer_unordered(parallelism.max(1));
            while let Some((port, outcome)) = pending.next().await {
                result.checked += 1;
                match outcome {
                    Ok(()) => result.open.push(port),
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                        result.refused += 1
                    }
                    Err(_) => result.unanswered.push(port),
                }
                if (!result.open.is_empty() || result.refused > 0)
                    && (!reported || last_report.elapsed() >= Duration::from_millis(250))
                {
                    progress(&result);
                    reported = true;
                    last_report = Instant::now();
                }
            }
        })
        .await;
    result.open.sort_unstable();
    result.unanswered.sort_unstable();
    Some(result)
}

pub(super) struct TcpProber {
    pub(super) runtime: tokio::runtime::Runtime,
    pub(super) connections: tokio::sync::Semaphore,
    pub(super) routed_connections: tokio::sync::Semaphore,
    pub(super) routed_icmp: tokio::sync::Semaphore,
    pub(super) routed_pacer: ProbePacer,
    pub(super) local_adaptive: AdaptiveConcurrency,
    pub(super) routed_adaptive: AdaptiveConcurrency,
    pub(super) adaptive_enabled: bool,
    pub(super) max_workers: usize,
    pub(super) routed_max: usize,
    pub(super) concurrency_report: Mutex<(Option<ConcurrencySnapshot>, Instant)>,
    pub(super) networks: Vec<network::LocalNetwork>,
    local_ranges: Vec<(u32, u32)>,
    pub(super) inventory: InventoryProber,
    pub(super) udp: UdpProber,
}

impl TcpProber {
    #[cfg(test)]
    pub(super) fn new() -> std::io::Result<Self> {
        Self::with_mode(ScanMode::Thorough)
    }

    #[cfg(test)]
    pub(super) fn with_mode(mode: ScanMode) -> std::io::Result<Self> {
        Self::with_options(mode, 128, false)
    }

    pub(super) fn with_options(
        mode: ScanMode,
        workers: usize,
        adaptive: bool,
    ) -> std::io::Result<Self> {
        let max_workers = workers.clamp(1, MAX_HOST_WORKERS);
        let fast = mode == ScanMode::Fast;
        let routed_max = if fast { 64 } else { 32 };
        let networks = network::local_networks();
        let local_ranges = local_ranges(&networks);
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(MAX_HOST_WORKERS)
            .enable_all()
            .build()?;
        Ok(Self {
            runtime,
            connections: tokio::sync::Semaphore::new(if mode == ScanMode::Fast {
                FAST_TCP_CONNECTIONS
            } else {
                MAX_TCP_CONNECTIONS
            }),
            routed_connections: tokio::sync::Semaphore::new(if mode == ScanMode::Fast {
                64
            } else {
                32
            }),
            routed_icmp: tokio::sync::Semaphore::new(32),
            routed_pacer: ProbePacer::new(
                Duration::from_millis(if mode == ScanMode::Fast { 16 } else { 32 }),
                8,
            ),
            local_adaptive: AdaptiveConcurrency::new(true, fast, max_workers, adaptive),
            routed_adaptive: AdaptiveConcurrency::new(false, fast, routed_max, adaptive),
            adaptive_enabled: adaptive,
            max_workers,
            routed_max,
            concurrency_report: Mutex::new((None, Instant::now())),
            networks,
            local_ranges,
            inventory: InventoryProber::default(),
            udp: UdpProber::default(),
        })
    }

    pub(super) fn routed(&self, ip: Ipv4Addr) -> bool {
        let ip = u32::from(ip);
        !self
            .local_ranges
            .iter()
            .any(|&(first, last)| (first..=last).contains(&ip))
    }

    #[cfg(test)]
    pub(super) fn set_networks(&mut self, networks: Vec<network::LocalNetwork>) {
        self.local_ranges = local_ranges(&networks);
        self.networks = networks;
    }

    pub(super) fn controller(&self, ip: Ipv4Addr) -> &AdaptiveConcurrency {
        if self.routed(ip) {
            &self.routed_adaptive
        } else {
            &self.local_adaptive
        }
    }

    pub(super) fn host_workers(&self, options: &ScanOptions) -> usize {
        let local = self
            .local_ranges
            .iter()
            .any(|&(first, last)| first <= options.targets.last && options.targets.first <= last);
        self.max_workers
            .min(if local { MAX_HOST_WORKERS } else { 128 })
    }

    pub(super) fn report_concurrency(
        &self,
        sender: &SyncSender<ScanEvent>,
        cancel: &CancellationToken,
        force: bool,
    ) {
        if !self.adaptive_enabled || cancel.is_cancelled() {
            return;
        }
        let (routed_tcp, interval) = self.routed_adaptive.snapshot();
        let snapshot = ConcurrencySnapshot {
            local_workers: self.local_adaptive.snapshot().0,
            max_workers: self.max_workers,
            routed_tcp,
            routed_tcp_max: self.routed_max,
            routed_interval_ms: interval.as_millis() as u64,
        };
        let mut last = self.concurrency_report.lock().unwrap();
        if force || last.0 != Some(snapshot) && last.1.elapsed() >= Duration::from_millis(250) {
            match sender.try_send(ScanEvent::Concurrency(snapshot)) {
                Ok(()) => *last = (Some(snapshot), Instant::now()),
                Err(mpsc::TrySendError::Disconnected(_)) => cancel.cancel(),
                Err(mpsc::TrySendError::Full(_)) => {}
            }
        }
    }

    pub(super) async fn echo(
        &self,
        ip: Ipv4Addr,
        timeout_ms: u32,
        samples: u8,
        cancel: &CancellationToken,
    ) -> PingResult {
        let _permit = if self.routed(ip) {
            let Some(Ok(permit)) = cancel.run_until_cancelled(self.routed_icmp.acquire()).await
            else {
                return PingResult::default();
            };
            if !self
                .routed_pacer
                .wait_with_interval(cancel, || self.routed_adaptive.snapshot().1)
                .await
            {
                return PingResult::default();
            }
            Some(permit)
        } else {
            None
        };
        let ping_cancel = cancel.clone();
        let ping = tokio::task::spawn_blocking(move || {
            collect_pings(samples, &ping_cancel, || {
                network::ping_reply(ip, timeout_ms)
            })
        })
        .await
        .unwrap_or_else(|error| PingResult {
            error: Some(format!("ICMP worker failed: {error}")),
            ..Default::default()
        });
        if self.routed(ip) && !cancel.is_cancelled() && ping.received > 0 {
            self.controller(ip).observe(Observation::Reply {
                rtt_ms: ping.ping_ms,
                timeout_ms,
            });
        }
        ping
    }

    pub(super) async fn ports(
        &self,
        ip: Ipv4Addr,
        ports: &[u16],
        timeout_ms: u32,
        cancel: &CancellationToken,
    ) -> Option<PortResult> {
        self.ports_with_progress(ip, ports, timeout_ms, cancel, |_| {})
            .await
    }

    async fn ports_with_progress(
        &self,
        ip: Ipv4Addr,
        ports: &[u16],
        timeout_ms: u32,
        cancel: &CancellationToken,
        progress: impl FnMut(&PortResult),
    ) -> Option<PortResult> {
        let timeout = Duration::from_millis(u64::from(timeout_ms.max(1)));
        let routed = self.routed(ip);
        collect_port_probes_with_progress(
            ports,
            PORTS_PER_HOST,
            cancel,
            |port| async move {
                let _adaptive = if routed {
                    let Some(permit) = self.routed_adaptive.acquire(cancel).await else {
                        return Err(std::io::ErrorKind::Interrupted.into());
                    };
                    Some(permit)
                } else {
                    None
                };
                let _routed = if routed {
                    let permit = self
                        .routed_connections
                        .acquire()
                        .await
                        .map_err(std::io::Error::other)?;
                    Some(permit)
                } else {
                    None
                };
                let _permit = self
                    .connections
                    .acquire()
                    .await
                    .map_err(std::io::Error::other)?;
                if routed
                    && !self
                        .routed_pacer
                        .wait_with_interval(cancel, || self.routed_adaptive.snapshot().1)
                        .await
                {
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                // Queueing for a rate/connection slot does not consume the network timeout.
                let started = Instant::now();
                let outcome = tokio::time::timeout(
                    timeout,
                    tokio::net::TcpStream::connect(SocketAddr::new(IpAddr::V4(ip), port)),
                )
                .await
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
                .map(|_| ());
                if routed
                    && (outcome.is_ok()
                        || outcome.as_ref().is_err_and(|error| {
                            error.kind() == std::io::ErrorKind::ConnectionRefused
                        }))
                    && !cancel.is_cancelled()
                {
                    self.routed_adaptive.observe(Observation::Reply {
                        rtt_ms: Some(started.elapsed().as_secs_f64() * 1000.0),
                        timeout_ms,
                    });
                }
                outcome
            },
            progress,
        )
        .await
    }

    pub(super) async fn sample_echo(
        &self,
        ip: Ipv4Addr,
        mut ping: PingResult,
        samples: u8,
        timeout_ms: u32,
        cancel: &CancellationToken,
    ) -> PingResult {
        while ping.sent < samples.clamp(1, 10) && ping.error.is_none() && !cancel.is_cancelled() {
            if ping.sent > 0
                && cancel
                    .run_until_cancelled(tokio::time::sleep(Duration::from_millis(100)))
                    .await
                    .is_none()
            {
                break;
            }
            let next = self.echo(ip, timeout_ms, 1, cancel).await;
            if ping.received > 0 && next.sent > next.received && !cancel.is_cancelled() {
                self.controller(ip).observe(Observation::LostReply);
            }
            let received = ping.received + next.received;
            if next.received > 0 {
                ping.ping_ms = Some(
                    (ping.ping_ms.unwrap_or_default() * f64::from(ping.received)
                        + next.ping_ms.unwrap_or_default() * f64::from(next.received))
                        / f64::from(received),
                );
            }
            ping.received = received;
            ping.sent += next.sent;
            ping.ttl = ping.ttl.or(next.ttl);
            ping.error = next.error;
            if next.sent == 0 {
                break;
            }
        }
        ping
    }

    #[cfg(test)]
    pub(super) fn probe(
        &self,
        ip: Ipv4Addr,
        ports: &[u16],
        timeout_ms: u32,
        samples: u8,
        cancel: &CancellationToken,
    ) -> Option<(PingResult, PortResult)> {
        self.probe_progress(ip, ports, timeout_ms, samples, cancel, (|_| {}, |_| {}))
    }

    pub(super) fn probe_progress(
        &self,
        ip: Ipv4Addr,
        ports: &[u16],
        timeout_ms: u32,
        samples: u8,
        cancel: &CancellationToken,
        progress: (impl Fn(&PingResult), impl FnMut(&PortResult)),
    ) -> Option<(PingResult, PortResult)> {
        if cancel.is_cancelled() {
            return None;
        }
        self.runtime.block_on(async {
            let ping = async {
                let ping = self.echo(ip, timeout_ms, samples, cancel).await;
                progress.0(&ping);
                ping
            };
            let ports = self.ports_with_progress(ip, ports, timeout_ms, cancel, progress.1);
            let (ping, ports) = join(ping, ports).await;
            Some((ping, ports.unwrap_or_default()))
        })
    }
}

fn local_ranges(networks: &[network::LocalNetwork]) -> Vec<(u32, u32)> {
    let mut ranges = vec![(0x7f000000, 0x7fffffff)];
    ranges.extend(networks.iter().filter_map(|network| {
        let prefix = network.cidr.split_once('/')?.1.parse::<u32>().ok()?;
        if prefix > 32 {
            return None;
        }
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let first = u32::from(network.address) & mask;
        Some((first, first | !mask))
    }));
    ranges
}
