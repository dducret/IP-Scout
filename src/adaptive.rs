use std::{
    sync::Mutex,
    time::{Duration, Instant},
};
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

#[derive(Clone, Copy)]
pub(crate) enum Observation {
    Reply {
        rtt_ms: Option<f64>,
        timeout_ms: u32,
    },
    Silent,
    LostReply,
}

struct State {
    limit: usize,
    active: usize,
    interval: Duration,
    baseline_ms: Option<f64>,
    healthy: usize,
    local_completed: usize,
    grow_after: Instant,
    backoff_after: Instant,
}

pub(crate) struct AdaptiveConcurrency {
    state: Mutex<State>,
    changed: Notify,
    enabled: bool,
    local: bool,
    min: usize,
    max: usize,
    step: usize,
    base_interval: Duration,
}

pub(crate) struct Permit<'a>(&'a AdaptiveConcurrency);

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        self.0.state.lock().unwrap().active -= 1;
        self.0.changed.notify_one();
    }
}

impl AdaptiveConcurrency {
    pub(crate) fn new(local: bool, fast: bool, maximum: usize, enabled: bool) -> Self {
        let max = maximum.max(1);
        let initial = if local {
            if fast { 128 } else { 64 }
        } else if fast {
            32
        } else {
            16
        };
        let base_interval = if local {
            Duration::ZERO
        } else {
            Duration::from_millis(if fast { 16 } else { 32 })
        };
        let now = Instant::now();
        Self {
            state: Mutex::new(State {
                limit: if enabled { initial.min(max) } else { max },
                active: 0,
                interval: if enabled {
                    base_interval * 2
                } else {
                    base_interval
                },
                baseline_ms: None,
                healthy: 0,
                local_completed: 0,
                grow_after: now,
                backoff_after: now,
            }),
            changed: Notify::new(),
            enabled,
            local,
            min: (if local || fast { 16 } else { 8 }).min(max),
            max,
            step: if local { 32 } else { 8 },
            base_interval,
        }
    }

    pub(crate) fn snapshot(&self) -> (usize, Duration) {
        let state = self.state.lock().unwrap();
        (state.limit, state.interval)
    }

    pub(crate) async fn acquire(&self, cancel: &CancellationToken) -> Option<Permit<'_>> {
        loop {
            if cancel.is_cancelled() {
                return None;
            }
            let notified = self.changed.notified();
            tokio::pin!(notified);
            // Register before checking capacity, so a concurrent release cannot be missed.
            notified.as_mut().enable();
            {
                let mut state = self.state.lock().unwrap();
                if state.active < state.limit {
                    state.active += 1;
                    return Some(Permit(self));
                }
            }
            cancel.run_until_cancelled(notified).await?;
        }
    }

    pub(crate) fn observe(&self, observation: Observation) {
        self.observe_at(observation, Instant::now());
    }

    fn observe_at(&self, observation: Observation, now: Instant) {
        if !self.enabled {
            return;
        }
        let mut state = self.state.lock().unwrap();
        let slow = match observation {
            Observation::Reply {
                rtt_ms: Some(rtt),
                timeout_ms,
            } => {
                let rtt = rtt.max(1.0);
                let baseline = state.baseline_ms.unwrap_or(rtt);
                let slow =
                    rtt >= f64::from(timeout_ms.max(1)) * 0.75 || rtt > baseline * 3.0 + 20.0;
                if !slow {
                    state.baseline_ms = Some(baseline * 0.875 + rtt * 0.125);
                }
                slow
            }
            Observation::LostReply => true,
            _ => false,
        };
        let previous = state.limit;
        if slow {
            state.healthy = 0;
            state.local_completed = 0;
            if now >= state.backoff_after {
                state.limit = (state.limit / 2).max(self.min);
                state.interval = (state.interval * 2).min(self.base_interval * 4);
                state.backoff_after = now + Duration::from_secs(1);
                state.grow_after = now + Duration::from_secs(2);
            }
        } else {
            if self.local {
                state.local_completed += 1;
            }
            if matches!(observation, Observation::Reply { .. }) {
                state.healthy += 1;
            }
            // Unused routed IPs are not loss signals, nor evidence to raise the VPN rate.
            let ready = state.healthy >= 8 || self.local && state.local_completed >= 32;
            if ready && now >= state.grow_after {
                state.limit = (state.limit + self.step).min(self.max);
                state.interval = state
                    .interval
                    .saturating_sub(self.base_interval)
                    .max(self.base_interval);
                state.healthy = 0;
                state.local_completed = 0;
                state.grow_after = now + Duration::from_millis(250);
            }
        }
        if state.limit > previous {
            self.changed.notify_waiters();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn healthy(controller: &AdaptiveConcurrency, now: Instant) {
        for _ in 0..8 {
            controller.observe_at(
                Observation::Reply {
                    rtt_ms: Some(7.0),
                    timeout_ms: 200,
                },
                now,
            );
        }
    }

    #[test]
    fn local_concurrency_grows_to_256_even_for_unused_addresses() {
        let controller = AdaptiveConcurrency::new(true, true, 256, true);
        assert_eq!(controller.snapshot().0, 128);
        let now = Instant::now();
        for round in 1..=8 {
            for _ in 0..32 {
                controller.observe_at(Observation::Silent, now + Duration::from_secs(round));
            }
        }
        assert_eq!(controller.snapshot(), (256, Duration::ZERO));
    }

    #[test]
    fn routed_rate_increases_only_after_reliable_replies() {
        let controller = AdaptiveConcurrency::new(false, true, 64, true);
        let initial = controller.snapshot();
        for _ in 0..65_534 {
            controller.observe(Observation::Silent);
        }
        assert_eq!(controller.snapshot(), initial);
        let now = Instant::now();
        for round in 1..=8 {
            healthy(&controller, now + Duration::from_secs(round));
        }
        assert_eq!(controller.snapshot(), (64, Duration::from_millis(16)));
    }

    #[test]
    fn loss_backs_off_without_cancelling_active_work_and_has_cooldown() {
        let controller = AdaptiveConcurrency::new(false, true, 64, true);
        let now = Instant::now();
        healthy(&controller, now);
        controller.observe_at(Observation::LostReply, now);
        let reduced = controller.snapshot();
        assert_eq!(reduced, (20, Duration::from_millis(32)));
        for _ in 0..100 {
            controller.observe_at(Observation::LostReply, now);
        }
        assert_eq!(controller.snapshot(), reduced);
        healthy(&controller, now + Duration::from_secs(1));
        assert_eq!(controller.snapshot(), reduced);
        healthy(&controller, now + Duration::from_secs(3));
        assert_eq!(controller.snapshot(), (28, Duration::from_millis(16)));
    }

    #[test]
    fn latency_spikes_reduce_concurrency_and_user_ceilings_are_respected() {
        let controller = AdaptiveConcurrency::new(true, true, 20, true);
        healthy(&controller, Instant::now());
        assert_eq!(controller.snapshot().0, 20);
        controller.observe(Observation::Reply {
            rtt_ms: Some(150.0),
            timeout_ms: 200,
        });
        assert_eq!(controller.snapshot().0, 16);
        let tiny = AdaptiveConcurrency::new(false, true, 1, true);
        tiny.observe(Observation::LostReply);
        assert_eq!(tiny.snapshot().0, 1);
    }

    #[test]
    fn fixed_mode_does_not_adjust_after_feedback() {
        let controller = AdaptiveConcurrency::new(false, true, 64, false);
        controller.observe(Observation::LostReply);
        healthy(&controller, Instant::now());
        assert_eq!(controller.snapshot(), (64, Duration::from_millis(16)));
    }

    #[tokio::test]
    async fn permits_enforce_current_capacity_and_cancel_waiters() {
        let controller = AdaptiveConcurrency::new(true, true, 1, true);
        let cancel = CancellationToken::new();
        let held = controller.acquire(&cancel).await.unwrap();
        let wait = controller.acquire(&cancel);
        let stop = async {
            tokio::task::yield_now().await;
            cancel.cancel();
        };
        let (permit, ()) = futures_util::future::join(wait, stop).await;
        assert!(permit.is_none());
        drop(held);
        let fresh = CancellationToken::new();
        assert!(controller.acquire(&fresh).await.is_some());
    }

    #[tokio::test]
    async fn a_reduced_budget_waits_for_active_requests_to_drain() {
        let controller = AdaptiveConcurrency::new(false, true, 64, true);
        let cancel = CancellationToken::new();
        let mut permits = Vec::new();
        for _ in 0..32 {
            permits.push(controller.acquire(&cancel).await.unwrap());
        }
        controller.observe(Observation::LostReply);
        assert_eq!(controller.snapshot().0, 16);
        let wait = controller.acquire(&cancel);
        let drain = async {
            tokio::task::yield_now().await;
            while permits.len() >= 16 {
                permits.pop();
            }
        };
        let (permit, ()) = futures_util::future::join(wait, drain).await;
        assert!(permit.is_some());
    }

    #[tokio::test]
    async fn growth_wakes_requests_waiting_for_new_capacity() {
        let controller = AdaptiveConcurrency::new(true, true, 256, true);
        let cancel = CancellationToken::new();
        let mut held = Vec::new();
        for _ in 0..128 {
            held.push(controller.acquire(&cancel).await.unwrap());
        }
        let wait = futures_util::future::join_all((0..32).map(|_| controller.acquire(&cancel)));
        let grow = async {
            tokio::task::yield_now().await;
            healthy(&controller, Instant::now());
        };
        let (permits, ()) = futures_util::future::join(wait, grow).await;
        assert!(permits.iter().all(Option::is_some));
        assert_eq!(controller.snapshot().0, 160);
        assert_eq!(controller.state.lock().unwrap().active, 160);
        drop((held, permits));
        assert_eq!(controller.state.lock().unwrap().active, 0);
    }

    #[test]
    fn growth_cooldown_prevents_a_large_instantaneous_ramp() {
        let controller = AdaptiveConcurrency::new(true, true, 256, true);
        let now = Instant::now();
        for _ in 0..100 {
            healthy(&controller, now);
        }
        assert_eq!(controller.snapshot().0, 160);
        healthy(&controller, now + Duration::from_millis(250));
        assert_eq!(controller.snapshot().0, 192);
    }
}
