use super::{Notifier, model::ScanEvent, pipeline};
use std::{
    collections::{HashSet, VecDeque},
    sync::{Arc, Condvar},
};
use std::{
    net::Ipv4Addr,
    sync::{Mutex, mpsc::SyncSender},
    thread,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

#[derive(Default)]
struct Pending {
    order: VecDeque<Ipv4Addr>,
    queued: HashSet<Ipv4Addr>,
    closed: bool,
}

pub(super) struct Delivery {
    pending: Arc<(Mutex<Pending>, Condvar)>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Delivery {
    pub(super) fn new(
        state: Arc<Mutex<pipeline::PublishedResults>>,
        sender: SyncSender<ScanEvent>,
        cancel: CancellationToken,
        notify: Option<Notifier>,
    ) -> Self {
        let pending = Arc::new((Mutex::new(Pending::default()), Condvar::new()));
        let work = pending.clone();
        let worker = thread::spawn(move || {
            let mut last_wake = None::<Instant>;
            loop {
                let ip = {
                    let (lock, ready) = &*work;
                    let mut pending = lock.lock().unwrap();
                    while pending.order.is_empty() && !pending.closed {
                        pending = ready.wait(pending).unwrap();
                    }
                    let Some(ip) = pending.order.pop_front() else {
                        break;
                    };
                    pending.queued.remove(&ip);
                    ip
                };
                let host = state.lock().unwrap().hosts.get(&ip).cloned();
                // Only this thread delivers host snapshots, and never holds the publisher lock
                // while waiting for GUI capacity. Pending updates for an IP share one queue entry.
                if let Some(host) = host
                    && sender.send(ScanEvent::Host(Box::new(host))).is_err()
                {
                    cancel.cancel();
                    break;
                }
                if let Some(notify) = &notify
                    && last_wake.is_none_or(|last| last.elapsed() >= Duration::from_millis(16))
                {
                    notify();
                    last_wake = Some(Instant::now());
                }
            }
        });
        Self {
            pending,
            worker: Some(worker),
        }
    }

    pub(super) fn enqueue(&self, ip: Ipv4Addr) {
        let (lock, ready) = &*self.pending;
        let mut pending = lock.lock().unwrap();
        if !pending.closed && pending.queued.insert(ip) {
            pending.order.push_back(ip);
            ready.notify_one();
        }
    }

    pub(super) fn finish(&mut self) {
        let (lock, ready) = &*self.pending;
        lock.lock().unwrap().closed = true;
        ready.notify_one();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for Delivery {
    fn drop(&mut self) {
        self.finish();
    }
}
