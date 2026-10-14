use super::probes::ProbePacer;
use crate::{
    adaptive::AdaptiveConcurrency,
    network::{self, RoutePath},
};
use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};

pub(super) struct PathBudget {
    pub controller: Arc<AdaptiveConcurrency>,
    pub pacer: ProbePacer,
}

pub(super) struct RouteBudgets {
    paths: Mutex<HashMap<(u32, Ipv4Addr), Arc<PathBudget>>>,
    resolved: Mutex<HashMap<Ipv4Addr, Option<RoutePath>>>,
    fallback: Arc<PathBudget>,
    fast: bool,
    adaptive: bool,
    ceiling: usize,
}

impl RouteBudgets {
    pub fn new(
        fast: bool,
        adaptive: bool,
        ceiling: usize,
        fallback: Arc<AdaptiveConcurrency>,
    ) -> Self {
        Self {
            paths: Mutex::new(HashMap::new()),
            resolved: Mutex::new(HashMap::new()),
            fallback: Arc::new(Self::budget(fast, fallback)),
            fast,
            adaptive,
            ceiling,
        }
    }

    fn budget(fast: bool, controller: Arc<AdaptiveConcurrency>) -> PathBudget {
        PathBudget {
            controller,
            pacer: ProbePacer::new(Duration::from_millis(if fast { 16 } else { 32 }), 8),
        }
    }

    pub fn route(&self, ip: Ipv4Addr) -> Option<RoutePath> {
        let mut resolved = self.resolved.lock().unwrap();
        *resolved
            .entry(ip)
            .or_insert_with(|| network::route_path(ip))
    }

    pub fn for_ip(&self, ip: Ipv4Addr) -> Arc<PathBudget> {
        self.for_route(self.route(ip))
    }

    pub fn fallback(&self) -> Arc<PathBudget> {
        self.fallback.clone()
    }

    fn for_route(&self, route: Option<RoutePath>) -> Arc<PathBudget> {
        let Some(route) = route else {
            return self.fallback.clone();
        };
        let key = (route.interface_index, route.next_hop);
        let mut paths = self.paths.lock().unwrap();
        if let Some(budget) = paths.get(&key) {
            return budget.clone();
        }
        if paths.len() >= 256 {
            return self.fallback.clone();
        }
        let budget = Arc::new(Self::budget(
            self.fast,
            Arc::new(AdaptiveConcurrency::new(
                false,
                self.fast,
                self.ceiling,
                self.adaptive,
            )),
        ));
        paths.insert(key, budget.clone());
        budget
    }

    pub fn snapshot(&self) -> (usize, u64, usize) {
        let paths = self.paths.lock().unwrap();
        if paths.is_empty() {
            let (limit, interval) = self.fallback.controller.snapshot();
            return (limit, interval.as_millis() as u64, 0);
        }
        let mut limit = 0;
        let mut interval = 0;
        for budget in paths.values() {
            let (capacity, pacing) = budget.controller.snapshot();
            limit += capacity;
            interval = interval.max(pacing.as_millis() as u64);
        }
        (limit.min(self.ceiling), interval, paths.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive::Observation;
    #[test]
    fn feedback_is_isolated_by_adapter_and_next_hop() {
        let routes = RouteBudgets::new(
            true,
            true,
            64,
            Arc::new(AdaptiveConcurrency::new(false, true, 64, true)),
        );
        let route = RoutePath {
            interface_index: 7,
            source: Ipv4Addr::new(10, 0, 0, 2),
            next_hop: Ipv4Addr::new(10, 0, 0, 1),
        };
        let a = routes.for_route(Some(route));
        let same = routes.for_route(Some(RoutePath {
            source: Ipv4Addr::new(10, 0, 0, 3),
            ..route
        }));
        let b = routes.for_route(Some(RoutePath {
            interface_index: 8,
            ..route
        }));
        let c = routes.for_route(Some(RoutePath {
            next_hop: Ipv4Addr::new(10, 0, 0, 4),
            ..route
        }));
        assert!(Arc::ptr_eq(&a, &same));
        a.controller.observe(Observation::LostReply);
        assert_eq!(a.controller.snapshot().0, 16);
        assert_eq!(b.controller.snapshot().0, 32);
        assert_eq!(c.controller.snapshot().0, 32);
        assert_eq!(routes.snapshot().2, 3);
    }
}
