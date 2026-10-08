use crate::network;
use hickory_resolver::{
    TokioAsyncResolver,
    config::{ResolverConfig, ResolverOpts},
};
use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub(super) struct DnsResolver {
    pub(super) resolver: TokioAsyncResolver,
    pub(super) timeout: Duration,
}

impl DnsResolver {
    pub(super) fn new(
        config: ResolverConfig,
        mut options: ResolverOpts,
        timeout_ms: u32,
    ) -> Result<Self, String> {
        let timeout = Duration::from_millis(u64::from(timeout_ms.clamp(100, 5000)));
        options.timeout = timeout;
        options.attempts = 1;
        let resolver = TokioAsyncResolver::tokio(config, options);
        Ok(Self { resolver, timeout })
    }

    #[cfg(test)]
    pub(super) fn reverse_name(&self, ip: Ipv4Addr, cancel: &CancellationToken) -> Option<String> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(self.dns_name(ip, cancel))
    }

    pub(super) async fn dns_name(
        &self,
        ip: Ipv4Addr,
        cancel: &CancellationToken,
    ) -> Option<String> {
        let names = cancel
            .run_until_cancelled(tokio::time::timeout(
                self.timeout,
                self.resolver.reverse_lookup(IpAddr::V4(ip)),
            ))
            .await?
            .ok()?
            .ok()?;
        names
            .iter()
            .next()
            .map(|name| name.to_utf8().trim_end_matches('.').to_owned())
    }

    pub(super) async fn host_name(
        &self,
        ip: Ipv4Addr,
        cancel: &CancellationToken,
    ) -> Option<String> {
        first_name(
            self.dns_name(ip, cancel),
            network::native_hostname(ip, cancel),
            self.timeout.max(Duration::from_secs(1)),
            cancel,
        )
        .await
    }
}

pub(super) async fn first_name(
    dns: impl Future<Output = Option<String>>,
    native: impl Future<Output = Option<String>>,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Option<String> {
    cancel
        .run_until_cancelled(tokio::time::timeout(timeout, async {
            tokio::pin!(dns, native);
            match futures_util::future::select(dns, native).await {
                futures_util::future::Either::Left((name, remaining)) => match name {
                    Some(name) => Some(name),
                    None => remaining.await,
                },
                futures_util::future::Either::Right((name, remaining)) => match name {
                    Some(name) => Some(name),
                    None => remaining.await,
                },
            }
        }))
        .await?
        .ok()
        .flatten()
}

pub(super) fn make_resolver(timeout_ms: u32) -> Result<DnsResolver, String> {
    let (config, options) = hickory_resolver::system_conf::read_system_conf()
        .map_err(|error| format!("DNS configuration unavailable: {error}"))?;
    DnsResolver::new(config, options, timeout_ms)
}
