use super::*;

#[derive(Default)]
pub(super) struct ViewCache {
    search: Vec<Option<String>>,
    sort_keys: Vec<Option<String>>,
    sort_fetcher: Option<Fetcher>,
}

impl ViewCache {
    pub(super) fn clear(&mut self) {
        self.search.clear();
        self.sort_keys.clear();
        self.sort_fetcher = None;
    }

    pub(super) fn invalidate(&mut self, index: usize) {
        if let Some(text) = self.search.get_mut(index) {
            *text = None;
        }
        if let Some(key) = self.sort_keys.get_mut(index) {
            *key = None;
        }
    }

    pub(super) fn rebuild(
        &mut self,
        hosts: &[HostResult],
        visible: &mut Vec<usize>,
        filter: Filter,
        sort: Sort,
        descending: bool,
        query: &str,
    ) {
        let query = query.trim().to_lowercase();
        self.search.resize_with(hosts.len(), || None);
        visible.clear();
        visible.extend(hosts.iter().enumerate().filter_map(|(index, host)| {
            let included = match filter {
                Filter::All => true,
                Filter::Alive => host.status == HostStatus::Alive,
                Filter::OpenPorts => has_open_ports(host),
                Filter::NoResponse => host.status == HostStatus::NoResponse,
            };
            if !included {
                return None;
            }
            let matches = query.is_empty()
                || self.search[index]
                    .get_or_insert_with(|| search_text(host))
                    .contains(&query);
            (included && matches).then_some(index)
        }));
        if let Sort::Metadata(fetcher) = sort
            && !matches!(fetcher, Fetcher::WebDetect | Fetcher::HttpStatus)
        {
            if self.sort_fetcher != Some(fetcher) {
                self.sort_keys.clear();
                self.sort_fetcher = Some(fetcher);
            }
            self.sort_keys.resize_with(hosts.len(), || None);
            for &index in visible.iter() {
                self.sort_keys[index].get_or_insert_with(|| fetcher.value(&hosts[index]));
            }
            visible.sort_unstable_by(|&left, &right| {
                self.sort_keys[left]
                    .cmp(&self.sort_keys[right])
                    .then_with(|| hosts[left].ip.cmp(&hosts[right].ip))
            });
            if descending {
                visible.reverse();
            }
            return;
        }
        visible.sort_unstable_by(|&left, &right| {
            let order = compare(sort, &hosts[left], &hosts[right]);
            if descending { order.reverse() } else { order }
        });
    }
}

fn included(filter: Filter, host: &HostResult) -> bool {
    match filter {
        Filter::All => true,
        Filter::Alive => host.status == HostStatus::Alive,
        Filter::OpenPorts => has_open_ports(host),
        Filter::NoResponse => host.status == HostStatus::NoResponse,
    }
}

pub(super) fn affects_update(
    previous: Option<&HostResult>,
    host: &HostResult,
    filter: Filter,
    sort: Sort,
    query: &str,
) -> bool {
    let new_included = included(filter, host);
    let Some(previous) = previous else {
        return new_included;
    };
    if included(filter, previous) != new_included {
        return true;
    }
    new_included && (!query.trim().is_empty() || compare(sort, previous, host) != Ordering::Equal)
}

fn compare(sort: Sort, left: &HostResult, right: &HostResult) -> Ordering {
    match sort {
        Sort::Ip => left.ip.cmp(&right.ip),
        Sort::Status => {
            (left.status != HostStatus::Alive).cmp(&(right.status != HostStatus::Alive))
        }
        Sort::Ping => match (left.ping_ms, right.ping_ms) {
            (Some(left), Some(right)) => left.total_cmp(&right),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        },
        Sort::Hostname => left.hostname.cmp(&right.hostname),
        Sort::Ports => left.open_ports.cmp(&right.open_ports),
        Sort::Mac => left.mac.cmp(&right.mac),
        Sort::Vendor => left.brand_label().cmp(right.brand_label()),
        Sort::RefusedPorts => left.refused_ports.cmp(&right.refused_ports),
        Sort::ArpResponse => left.arp_response.cmp(&right.arp_response),
        Sort::ProbableBrand => left.probable_brand.cmp(&right.probable_brand),
        Sort::Notes => left.notes.cmp(&right.notes),
        Sort::Ttl => match (left.extra.ttl, right.extra.ttl) {
            (Some(left), Some(right)) => left.cmp(&right),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        },
        Sort::PacketLoss => match (left.extra.packet_loss, right.extra.packet_loss) {
            (Some(left), Some(right)) => left.total_cmp(&right),
            (Some(_), None) => Ordering::Less,
            (None, Some(_)) => Ordering::Greater,
            (None, None) => Ordering::Equal,
        },
        Sort::Metadata(Fetcher::WebDetect) => left
            .extra
            .web
            .iter()
            .map(|service| &service.server)
            .cmp(right.extra.web.iter().map(|service| &service.server)),
        Sort::Metadata(Fetcher::HttpStatus) => left
            .extra
            .web
            .iter()
            .map(|service| service.status)
            .cmp(right.extra.web.iter().map(|service| service.status)),
        Sort::Metadata(fetcher) => fetcher.value(left).cmp(&fetcher.value(right)),
    }
    .then_with(|| left.ip.cmp(&right.ip))
}

fn search_text(host: &HostResult) -> String {
    let mut text = String::new();
    for value in [
        host.ip.to_string(),
        host.hostname.clone(),
        host.mac.clone(),
        host.brand_label().to_owned(),
        host.extra.netbios.clone(),
        host.notes.clone(),
        ports_text(&host.open_ports),
    ] {
        text.push_str(&value);
        text.push('\n');
    }
    for fetcher in [
        Fetcher::Ssdp,
        Fetcher::Mndp,
        Fetcher::Ubiquiti,
        Fetcher::Llmnr,
        Fetcher::ServiceBanners,
        Fetcher::TlsCertificates,
        Fetcher::WebTitle,
        Fetcher::DeviceIdentity,
        Fetcher::UdpPorts,
        Fetcher::UdpStatus,
        Fetcher::DnsInfo,
        Fetcher::NtpInfo,
        Fetcher::SnmpInfo,
    ] {
        text.push_str(&fetcher.value(host));
        text.push('\n');
    }
    for service in &host.extra.bonjour {
        text.push_str(&service.summary());
        text.push('\n');
    }
    for device in &host.extra.wsd {
        text.push_str(&device.summary());
        text.push('\n');
    }
    for service in &host.extra.web {
        text.push_str(&format!(
            "{}\n{}\n{}\n",
            service.server, service.url, service.status
        ));
    }
    text.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrelated_updates_do_not_rebuild_the_active_view() {
        let previous = smoke_host("192.0.2.1", "");
        let mut updated = previous.clone();
        updated.ping_ms = Some(7.0);
        assert!(!affects_update(
            Some(&previous),
            &updated,
            Filter::All,
            Sort::Ip,
            ""
        ));
        assert!(!affects_update(
            Some(&previous),
            &updated,
            Filter::Alive,
            Sort::Hostname,
            ""
        ));
        assert!(affects_update(
            Some(&previous),
            &updated,
            Filter::All,
            Sort::Ping,
            ""
        ));
        updated.status = HostStatus::NoResponse;
        assert!(affects_update(
            Some(&previous),
            &updated,
            Filter::Alive,
            Sort::Ip,
            ""
        ));
        assert!(!affects_update(None, &updated, Filter::Alive, Sort::Ip, ""));
        assert!(affects_update(
            Some(&previous),
            &previous,
            Filter::All,
            Sort::Ip,
            "printer"
        ));
    }

    #[test]
    fn searches_cache_text_and_refresh_after_an_update_or_clear() {
        let mut hosts = vec![smoke_host("192.0.2.1", "")];
        hosts[0].hostname = "Samsung-S23".into();
        let mut view = ViewCache::default();
        let mut visible = Vec::new();
        view.rebuild(
            &hosts,
            &mut visible,
            Filter::All,
            Sort::Ip,
            false,
            "SAMSUNG",
        );
        assert_eq!(visible, vec![0]);
        let cached = view.search[0].as_ref().unwrap().as_ptr();
        view.rebuild(&hosts, &mut visible, Filter::All, Sort::Ip, false, "s23");
        assert_eq!(cached, view.search[0].as_ref().unwrap().as_ptr());
        hosts[0].hostname = "new-name".into();
        hosts[0].notes = "confirmation recovered".into();
        view.invalidate(0);
        view.rebuild(
            &hosts,
            &mut visible,
            Filter::All,
            Sort::Ip,
            false,
            "samsung",
        );
        assert!(visible.is_empty());
        view.rebuild(
            &hosts,
            &mut visible,
            Filter::All,
            Sort::Ip,
            false,
            "recovered",
        );
        assert_eq!(visible, vec![0]);
        view.clear();
        assert!(view.search.is_empty());
    }

    #[test]
    fn cached_metadata_keys_keep_ip_ties_and_descending_order() {
        let mut hosts = vec![
            smoke_host("192.0.2.3", ""),
            smoke_host("192.0.2.2", ""),
            smoke_host("192.0.2.1", ""),
        ];
        hosts[0].extra.netbios = "B".into();
        hosts[1].extra.netbios = "A".into();
        hosts[2].extra.netbios = "A".into();
        let mut view = ViewCache::default();
        let mut visible = Vec::new();
        view.rebuild(
            &hosts,
            &mut visible,
            Filter::All,
            Sort::Metadata(Fetcher::Netbios),
            false,
            "",
        );
        assert_eq!(visible, vec![2, 1, 0]);
        view.rebuild(
            &hosts,
            &mut visible,
            Filter::All,
            Sort::Metadata(Fetcher::Netbios),
            true,
            "",
        );
        assert_eq!(visible, vec![0, 1, 2]);
        let cached = view.sort_keys[0].as_ref().unwrap().as_ptr();
        view.rebuild(
            &hosts,
            &mut visible,
            Filter::All,
            Sort::Metadata(Fetcher::Netbios),
            true,
            "",
        );
        assert_eq!(cached, view.sort_keys[0].as_ref().unwrap().as_ptr());
        hosts[0].extra.netbios = "0".into();
        view.invalidate(0);
        view.rebuild(
            &hosts,
            &mut visible,
            Filter::All,
            Sort::Metadata(Fetcher::Netbios),
            false,
            "",
        );
        assert_eq!(visible, vec![0, 2, 1]);
    }

    #[test]
    fn filters_skip_incomplete_hosts_and_include_udp_ports() {
        let mut hosts = vec![smoke_host("192.0.2.1", ""), smoke_host("192.0.2.2", "")];
        hosts[0].status = HostStatus::Incomplete;
        hosts[1].extra.udp.open_ports = vec![53];
        let mut view = ViewCache::default();
        let mut visible = Vec::new();
        view.rebuild(
            &hosts,
            &mut visible,
            Filter::NoResponse,
            Sort::Ip,
            false,
            "",
        );
        assert!(visible.is_empty());
        view.rebuild(&hosts, &mut visible, Filter::OpenPorts, Sort::Ip, false, "");
        assert_eq!(visible, vec![1]);
    }

    #[test]
    #[ignore = "CPU timing benchmark, no network traffic"]
    fn result_view_latency_benchmark() {
        let hosts: Vec<_> = (0..65_534)
            .map(|index| {
                let mut host = smoke_host(&Ipv4Addr::from(0xc0a80001 + index).to_string(), "");
                host.hostname = format!("host-{:05}", (index * 7919) % 65_534);
                host.extra.netbios = format!("{} | WORKGROUP | File server", host.hostname);
                host
            })
            .collect();
        let mut old: Vec<_> = (0..hosts.len()).collect();
        let started = Instant::now();
        old.sort_unstable_by(|&left, &right| {
            Fetcher::DeviceIdentity
                .value(&hosts[left])
                .cmp(&Fetcher::DeviceIdentity.value(&hosts[right]))
                .then_with(|| hosts[left].ip.cmp(&hosts[right].ip))
        });
        let previous = started.elapsed();
        let mut view = ViewCache::default();
        let mut visible = Vec::new();
        let started = Instant::now();
        view.rebuild(
            &hosts,
            &mut visible,
            Filter::All,
            Sort::Metadata(Fetcher::DeviceIdentity),
            false,
            "",
        );
        let cached_sort = started.elapsed();
        assert_eq!(visible, old);
        let started = Instant::now();
        view.rebuild(
            &hosts,
            &mut visible,
            Filter::All,
            Sort::Metadata(Fetcher::DeviceIdentity),
            false,
            "",
        );
        let warm_sort = started.elapsed();
        assert_eq!(visible, old);
        let started = Instant::now();
        view.rebuild(
            &hosts,
            &mut visible,
            Filter::All,
            Sort::Ip,
            false,
            "absent-device",
        );
        let cold_search = started.elapsed();
        let started = Instant::now();
        view.rebuild(
            &hosts,
            &mut visible,
            Filter::All,
            Sort::Ip,
            false,
            "absent-device",
        );
        let warm_search = started.elapsed();
        assert!(visible.is_empty());
        println!(
            "65,534 simulated hosts: previous metadata sort {previous:?}, cached sort {cached_sort:?}, warm sort {warm_sort:?}, cold search {cold_search:?}, cached search {warm_search:?}"
        );
    }
}
