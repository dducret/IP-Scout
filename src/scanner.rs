use crate::{advertisements, discovery, metadata::WebProber};
use futures_util::future::join;
use std::{
    net::Ipv4Addr,
    sync::{
        atomic::{AtomicUsize, Ordering},
        mpsc::{self, Receiver},
    },
    thread,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

mod delivery;
mod host;
mod hostname;
mod identity;
mod model;
mod pipeline;
mod probes;

use host::{confirm_host, enrich_host, scan_host_with_progress};
#[cfg(test)]
use host::{finish_host_discovery, merge_ping, scan_host};
#[cfg(test)]
use hostname::first_name;
use hostname::make_resolver;
#[cfg(test)]
use identity::lookup_vendor;
use identity::{identity, vendors};
pub use model::*;
use pipeline::{RecheckProgress, ResultPublisher, run_host_pipeline};
use probes::TcpProber;
#[cfg(test)]
use probes::{ProbePacer, collect_pings, collect_port_probes};
pub const PORTS_PER_HOST: usize = 16;
pub const MAX_TCP_CONNECTIONS: usize = 256;
pub const MAX_HOST_WORKERS: usize = 256;
const FAST_TCP_CONNECTIONS: usize = 1024;
const METADATA_WORKERS: usize = 32;
const METADATA_QUEUE: usize = 256;

pub struct ScanHandle {
    pub events: Receiver<ScanEvent>,
    cancel: CancellationToken,
}

impl ScanHandle {
    pub fn cancel(&self) {
        self.cancel.cancel();
    }
}

impl Drop for ScanHandle {
    fn drop(&mut self) {
        self.cancel();
    }
}

pub fn start_scan(options: ScanOptions) -> ScanHandle {
    start_scan_inner(options, None)
}

/// Wake an event consumer from background scan/delivery threads. Host wakes are coalesced.
/// The callback must be thread-safe and nonblocking; events still arrive through ScanHandle.
pub fn start_scan_with_notifier(
    options: ScanOptions,
    notify: impl Fn() + Send + Sync + 'static,
) -> ScanHandle {
    start_scan_inner(options, Some(std::sync::Arc::new(notify)))
}

type Notifier = std::sync::Arc<dyn Fn() + Send + Sync>;

fn start_scan_inner(options: ScanOptions, notify: Option<Notifier>) -> ScanHandle {
    let (sender, events) = mpsc::sync_channel(256);
    let cancel = CancellationToken::new();
    let stopped = cancel.clone();
    thread::spawn(move || {
        let started = Instant::now();
        let prober = match TcpProber::with_options(
            options.mode,
            options.workers,
            options.adaptive_concurrency,
        ) {
            Ok(prober) => prober,
            Err(error) => {
                let _ = sender.send(ScanEvent::Warning(format!(
                    "Could not start scan runtime: {error}"
                )));
                let _ = sender.send(ScanEvent::Finished {
                    elapsed: started.elapsed(),
                    cancelled: true,
                });
                if let Some(notify) = &notify {
                    notify();
                }
                return;
            }
        };
        let resolver = if options.resolve_names {
            match make_resolver(options.timeout_ms) {
                Ok(resolver) => Some(resolver),
                Err(error) => {
                    let _ = sender.send(ScanEvent::Warning(error));
                    None
                }
            }
        } else {
            None
        };
        let web = if options.extra.web || options.extra.web_titles {
            match WebProber::new_with_titles(
                Duration::from_millis(u64::from(options.timeout_ms.max(1))),
                options.extra.allow_unverified_tls,
                options.extra.web_titles,
            ) {
                Ok(web) => Some(web),
                Err(error) => {
                    let _ = sender.send(ScanEvent::Warning(format!(
                        "Web detection unavailable: {error}"
                    )));
                    None
                }
            }
        } else {
            None
        };
        let mut publisher = ResultPublisher::buffered(&sender, &stopped, notify.clone());
        prober.report_concurrency(&sender, &stopped, true);
        thread::scope(|scope| {
            if options.fetch_vendor {
                scope.spawn(vendors);
            }
            if options.extra.bonjour || options.extra.wsd || options.extra.advertisements.enabled()
            {
                scope.spawn(|| {
                    let interfaces = discovery::interfaces_for(&prober.networks, &options.targets);
                    let window = Duration::from_secs(u64::from(
                        options.extra.discovery_seconds.clamp(1, 120),
                    ));
                    let (mut local, ads) = prober.runtime.block_on(join(
                        discovery::collect(
                            &options.targets,
                            &interfaces,
                            options.extra.bonjour,
                            options.extra.wsd,
                            window,
                            &stopped,
                        ),
                        advertisements::collect(
                            &options.targets,
                            &interfaces,
                            options.extra.advertisements,
                            window,
                            &stopped,
                        ),
                    ));
                    for (ip, info) in ads.hosts {
                        if local.hosts.len() < 2048 || local.hosts.contains_key(&ip) {
                            local.hosts.entry(ip).or_default().advertisements = info.advertisements;
                        }
                    }
                    local.warnings.extend(ads.warnings);
                    for warning in local.warnings {
                        let _ = sender.send(ScanEvent::Warning(warning));
                    }
                    let promoted = publisher.discover(local.hosts);
                    // Hosts identified only by a late advertisement still get identity fetchers.
                    let next = AtomicUsize::new(0);
                    thread::scope(|scope| {
                        for _ in 0..options
                            .workers
                            .clamp(1, METADATA_WORKERS)
                            .min(promoted.len())
                        {
                            scope.spawn(|| {
                                while !stopped.is_cancelled() {
                                    let index = next.fetch_add(1, Ordering::Relaxed);
                                    let Some(host) = promoted.get(index) else {
                                        break;
                                    };
                                    let identity = identity(
                                        host.ip,
                                        &options,
                                        resolver.as_ref(),
                                        &prober,
                                        &stopped,
                                    );
                                    publisher.identity(host.ip, identity);
                                }
                            });
                        }
                    });
                });
            }
            if !run_host_pipeline(
                options.targets.len(),
                prober.host_workers(&options),
                &stopped,
                |index| {
                    let host = scan_host_with_progress(
                        Ipv4Addr::from(options.targets.first + index as u32),
                        &options,
                        &prober,
                        &stopped,
                        Some(&publisher),
                    );
                    prober.report_concurrency(&sender, &stopped, false);
                    host
                },
                |host| {
                    enrich_host(
                        host,
                        &options,
                        resolver.as_ref(),
                        &prober,
                        web.as_ref(),
                        &stopped,
                        &publisher,
                    )
                },
                |host| publisher.publish(host),
            ) {
                let _ = sender.send(ScanEvent::Warning(
                    "A scan worker failed; the scan was stopped".into(),
                ));
            }
        });
        if !stopped.is_cancelled() {
            let candidates = publisher.retry_candidates();
            if !candidates.is_empty() {
                let progress = RecheckProgress::new(candidates.len(), &sender, &stopped);
                if !run_host_pipeline(
                    candidates.len(),
                    options.workers.min(if options.mode == ScanMode::Fast {
                        64
                    } else {
                        32
                    }),
                    &stopped,
                    |index| {
                        let host = publisher.host(candidates[index]).and_then(|host| {
                            confirm_host(host, &options, &prober, &stopped, &publisher)
                        });
                        // Count completed addresses; parallel workers finish out of order.
                        if host.is_some() {
                            progress.completed();
                        }
                        prober.report_concurrency(&sender, &stopped, false);
                        host
                    },
                    |host| {
                        if host.status != HostStatus::Alive {
                            return None;
                        }
                        enrich_host(
                            host,
                            &options,
                            resolver.as_ref(),
                            &prober,
                            web.as_ref(),
                            &stopped,
                            &publisher,
                        )
                    },
                    |host| publisher.publish(host),
                ) {
                    let _ = sender.send(ScanEvent::Warning(
                        "A confirmation worker failed; the scan was stopped".into(),
                    ));
                }
            }
        }
        publisher.finish();
        prober.report_concurrency(&sender, &stopped, true);
        let _ = sender.send(ScanEvent::Finished {
            elapsed: started.elapsed(),
            cancelled: stopped.is_cancelled(),
        });
        if let Some(notify) = notify {
            notify();
        }
    });
    ScanHandle { events, cancel }
}

#[cfg(test)]
mod tests;
