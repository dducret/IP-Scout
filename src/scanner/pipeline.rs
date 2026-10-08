use super::{
    MAX_HOST_WORKERS, METADATA_QUEUE, METADATA_WORKERS, Notifier, delivery,
    identity::{Identity, apply_identity},
    model::*,
};
use crate::{discovery::LocalInfo, udp::UdpResult};
use std::sync::Arc;
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

pub(super) struct RecheckProgress<'a> {
    pub(super) total: usize,
    pub(super) state: Mutex<(usize, Instant)>,
    pub(super) interval: Duration,
    pub(super) sender: &'a SyncSender<ScanEvent>,
    pub(super) cancel: &'a CancellationToken,
}

impl<'a> RecheckProgress<'a> {
    pub(super) fn new(
        total: usize,
        sender: &'a SyncSender<ScanEvent>,
        cancel: &'a CancellationToken,
    ) -> Self {
        let progress = Self {
            total,
            state: Mutex::new((0, Instant::now())),
            interval: Duration::from_millis(250),
            sender,
            cancel,
        };
        progress.send(0);
        progress
    }

    pub(super) fn send(&self, current: usize) {
        if !self.cancel.is_cancelled()
            && self.sender.send(ScanEvent::Phase(format!(
                "Rechecking {current} of {} addresses without an echo reply (paced confirmation)", self.total
            ))).is_err()
        {
            self.cancel.cancel();
        }
    }

    pub(super) fn completed(&self) {
        let mut state = self.state.lock().unwrap();
        if self.cancel.is_cancelled() || state.0 >= self.total {
            return;
        }
        state.0 += 1;
        if state.0 == self.total || state.1.elapsed() >= self.interval {
            // Keep sends ordered across workers, while limiting GUI event traffic.
            self.send(state.0);
            state.1 = Instant::now();
        }
    }
}

#[derive(Default)]
pub(super) struct PublishedResults {
    pub(super) hosts: HashMap<Ipv4Addr, HostResult>,
    pub(super) local: HashMap<Ipv4Addr, LocalInfo>,
}

pub(super) struct ResultPublisher<'a> {
    pub(super) state: Arc<Mutex<PublishedResults>>,
    pub(super) sender: &'a SyncSender<ScanEvent>,
    pub(super) cancel: &'a CancellationToken,
    delivery: Option<delivery::Delivery>,
}

impl<'a> ResultPublisher<'a> {
    #[cfg(test)]
    pub(super) fn new(sender: &'a SyncSender<ScanEvent>, cancel: &'a CancellationToken) -> Self {
        Self {
            state: Arc::new(Mutex::new(PublishedResults::default())),
            sender,
            cancel,
            delivery: None,
        }
    }

    pub(super) fn buffered(
        sender: &'a SyncSender<ScanEvent>,
        cancel: &'a CancellationToken,
        notify: Option<Notifier>,
    ) -> Self {
        let state = Arc::new(Mutex::new(PublishedResults::default()));
        let delivery =
            delivery::Delivery::new(state.clone(), sender.clone(), cancel.clone(), notify);
        Self {
            state,
            sender,
            cancel,
            delivery: Some(delivery),
        }
    }

    pub(super) fn finish(&mut self) {
        if let Some(delivery) = &mut self.delivery {
            delivery.finish();
        }
    }

    pub(super) fn send(&self, host: &HostResult) {
        if let Some(delivery) = &self.delivery {
            delivery.enqueue(host.ip);
        } else if self
            .sender
            .send(ScanEvent::Host(Box::new(host.clone())))
            .is_err()
        {
            self.cancel.cancel();
        }
    }

    pub(super) fn retry_candidates(&self) -> Vec<Ipv4Addr> {
        let state = self.state.lock().unwrap();
        let mut candidates: Vec<_> = state
            .hosts
            .values()
            .filter(|host| {
                host.discovery_complete()
                    && host.status != HostStatus::Incomplete
                    && host.ping_ms.is_none()
            })
            .map(|host| host.ip)
            .collect();
        candidates.sort_unstable();
        candidates
    }

    pub(super) fn host(&self, ip: Ipv4Addr) -> Option<HostResult> {
        self.state.lock().unwrap().hosts.get(&ip).cloned()
    }

    pub(super) fn publish(&self, mut host: HostResult) -> HostResult {
        let mut state = self.state.lock().unwrap();
        if let Some(local) = state.local.get(&host.ip) {
            merge_local(&mut host, local);
        }
        if let Some(previous) = state.hosts.get(&host.ip) {
            if host.extra.udp.requested == 0 {
                host.extra.udp.clone_from(&previous.extra.udp);
                if !host.extra.udp.open_ports.is_empty() {
                    host.status = HostStatus::Alive;
                }
            }
            // Identity may have completed on the discovery thread while metadata was in flight.
            if host.hostname.is_empty() {
                host.hostname.clone_from(&previous.hostname);
            }
            if host.mac.is_empty() {
                host.mac.clone_from(&previous.mac);
            }
            if host.vendor.is_empty() {
                host.vendor.clone_from(&previous.vendor);
            }
            if host.probable_brand.is_empty() {
                host.probable_brand.clone_from(&previous.probable_brand);
            }
            if &host == previous {
                return host;
            }
        }
        state.hosts.insert(host.ip, host.clone());
        // Keep publication ordered with merges, so a stale snapshot cannot follow a newer one.
        self.send(&host);
        host
    }

    pub(super) fn discover(&self, local: HashMap<Ipv4Addr, LocalInfo>) -> Vec<HostResult> {
        let mut state = self.state.lock().unwrap();
        let mut promoted = Vec::new();
        for (ip, info) in &local {
            if let Some(host) = state.hosts.get_mut(ip) {
                let previous = host.clone();
                let before = host.status;
                merge_local(host, info);
                if before == HostStatus::NoResponse && host.status == HostStatus::Alive {
                    promoted.push(host.clone());
                }
                if *host != previous {
                    self.send(host);
                }
            }
        }
        state.local = local;
        promoted
    }

    pub(super) fn identity(&self, ip: Ipv4Addr, identity: Identity) {
        let mut state = self.state.lock().unwrap();
        if let Some(host) = state.hosts.get_mut(&ip) {
            let changed = !identity.hostname.is_empty() && identity.hostname != host.hostname
                || !identity.mac.is_empty() && identity.mac != host.mac
                || !identity.vendor.is_empty() && identity.vendor != host.vendor
                || !identity.probable_brand.is_empty()
                    && identity.probable_brand != host.probable_brand;
            apply_identity(host, identity);
            if changed {
                self.send(host);
            }
        }
    }

    pub(super) fn udp(&self, ip: Ipv4Addr, udp: &UdpResult) {
        let mut state = self.state.lock().unwrap();
        if let Some(host) = state.hosts.get_mut(&ip) {
            let changed = host.extra.udp != *udp
                || !udp.open_ports.is_empty() && host.status != HostStatus::Alive;
            host.extra.udp = udp.clone();
            if !udp.open_ports.is_empty() {
                host.status = HostStatus::Alive;
            }
            if changed {
                self.send(host);
            }
        }
    }
}

pub(super) fn merge_local(host: &mut HostResult, local: &LocalInfo) {
    host.extra.bonjour.clone_from(&local.bonjour);
    host.extra.wsd.clone_from(&local.wsd);
    host.extra.advertisements.clone_from(&local.advertisements);
    // Bonjour sleep proxies alone are not evidence of liveness.
    if !local.wsd.is_empty()
        || !local.advertisements.ssdp.is_empty()
        || !local.advertisements.mndp.is_empty()
        || !local.advertisements.ubiquiti.is_empty()
    {
        host.status = HostStatus::Alive;
    }
}

pub(super) fn run_host_pipeline(
    count: usize,
    workers: usize,
    cancel: &CancellationToken,
    probe: impl Fn(usize) -> Option<HostResult> + Sync,
    enrich: impl Fn(HostResult) -> Option<HostResult> + Sync,
    publish: impl Fn(HostResult) -> HostResult + Sync,
) -> bool {
    let next = AtomicUsize::new(0);
    let failed = std::sync::atomic::AtomicBool::new(false);
    let (jobs, pending) = mpsc::sync_channel(METADATA_QUEUE);
    let pending = Mutex::new(pending);
    thread::scope(|scope| {
        for _ in 0..workers.clamp(1, METADATA_WORKERS).min(count) {
            let pending = &pending;
            let enrich = &enrich;
            let publish = &publish;
            let failed = &failed;
            scope.spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    loop {
                        let Ok(host) = pending.lock().unwrap().recv() else {
                            break;
                        };
                        if !cancel.is_cancelled()
                            && let Some(host) = enrich(host)
                        {
                            publish(host);
                        }
                    }
                }));
                if outcome.is_err() {
                    failed.store(true, Ordering::Relaxed);
                    cancel.cancel();
                }
            });
        }
        for _ in 0..workers.clamp(1, MAX_HOST_WORKERS).min(count) {
            let jobs = jobs.clone();
            let (next, probe, publish) = (&next, &probe, &publish);
            let failed = &failed;
            scope.spawn(move || {
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    while !cancel.is_cancelled() {
                        let index = next.fetch_add(1, Ordering::Relaxed);
                        if index >= count {
                            break;
                        }
                        if let Some(host) = probe(index) {
                            let mut host = publish(host);
                            loop {
                                if cancel.is_cancelled() {
                                    break;
                                }
                                match jobs.try_send(host) {
                                    Ok(()) => break,
                                    Err(mpsc::TrySendError::Disconnected(_)) => {
                                        cancel.cancel();
                                        break;
                                    }
                                    Err(mpsc::TrySendError::Full(returned)) => {
                                        host = returned;
                                        thread::sleep(Duration::from_millis(2));
                                    }
                                }
                            }
                        }
                    }
                }));
                if outcome.is_err() {
                    failed.store(true, Ordering::Relaxed);
                    cancel.cancel();
                }
            });
        }
        drop(jobs);
    });
    !failed.load(Ordering::Relaxed)
}
