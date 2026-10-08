use ip_scout::{
    advertisements, export, fetchers,
    scanner::{ExtraOptions, HostResult, ScanEvent, ScanMode, ScanOptions, start_scan},
    targets::{TargetRange, parse_ports},
    udp,
};
use std::{collections::HashMap, net::Ipv4Addr, time::Instant};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty()
        || args.iter().skip(1).any(|arg| {
            !matches!(
                arg.as_str(),
                "--inventory"
                    | "--fast"
                    | "--deep"
                    | "--basic"
                    | "--udp"
                    | "--icmp-only"
                    | "--fixed"
            ) && !arg.starts_with("--csv=")
                && !arg.starts_with("--watch=")
                && !arg.starts_with("--workers=")
                && !arg.starts_with("--timeout=")
        })
        || args.iter().any(|arg| arg == "--fast") && args.iter().any(|arg| arg == "--deep")
    {
        return Err(
            "Usage: diagnose_scan <IPv4 range/CIDR> [--inventory] [--fast | --deep] [--basic] [--udp] [--icmp-only] [--fixed] [--workers=1..256] [--timeout=10..5000] [--csv=path] [--watch=IP,IP]".into(),
        );
    }
    let targets = TargetRange::parse(&args[0])?;
    let total = targets.len();
    let watch: Vec<Ipv4Addr> = args
        .iter()
        .filter_map(|arg| arg.strip_prefix("--watch="))
        .flat_map(|list| list.split(','))
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    let ports = if args.iter().any(|arg| arg == "--inventory") {
        fetchers::INVENTORY_PORTS
    } else {
        "22,80,443,445,3389,8080"
    };
    let fast = args.iter().any(|arg| arg == "--fast");
    let basic = args.iter().any(|arg| arg == "--basic");
    let udp_enabled = args.iter().any(|arg| arg == "--udp");
    let timeout_ms: u32 = args
        .iter()
        .find_map(|arg| arg.strip_prefix("--timeout="))
        .map(str::parse)
        .transpose()?
        .unwrap_or(if fast { 200 } else { 400 });
    let workers: usize = args
        .iter()
        .find_map(|arg| arg.strip_prefix("--workers="))
        .map(str::parse)
        .transpose()?
        .unwrap_or(if fast { 256 } else { 128 });
    if !(10..=5000).contains(&timeout_ms) || !(1..=256).contains(&workers) {
        return Err("Timeout must be 10..5000 ms and workers must be 1..256".into());
    }
    if args.iter().any(|arg| arg == "--icmp-only") {
        for index in 0..total {
            let ip = Ipv4Addr::from(targets.first + index as u32);
            println!("{ip}: {:?}", ip_scout::network::ping_reply(ip, timeout_ms));
        }
        return Ok(());
    }
    let options = ScanOptions {
        mode: if fast {
            ScanMode::Fast
        } else {
            ScanMode::Thorough
        },
        targets,
        ports: parse_ports(ports)?,
        timeout_ms,
        workers,
        adaptive_concurrency: !args.iter().any(|arg| arg == "--fixed"),
        resolve_names: !basic,
        fetch_mac: !basic,
        fetch_vendor: !basic,
        discover_arp: true,
        extra: ExtraOptions {
            discovery_seconds: if fast { 2 } else { 4 },
            udp: if udp_enabled {
                udp::Options {
                    ports: parse_ports(udp::COMMON_PORTS)?,
                    dns: true,
                    ntp: true,
                    snmp: true,
                    ..Default::default()
                }
            } else {
                udp::Options::default()
            },
            bonjour: !basic,
            wsd: !basic,
            netbios: !basic,
            web: !basic,
            packet_loss: !basic,
            banners: !basic,
            certificates: !basic,
            web_titles: !basic,
            advertisements: advertisements::Options {
                ssdp: !basic,
                mndp: !basic,
                ubiquiti: !basic,
            },
            llmnr: !basic,
            ..Default::default()
        },
    };
    println!(
        "Scanning {} addresses, {} TCP ports, {} ms, {} workers, basic={basic}, UDP={udp_enabled}",
        total,
        options.ports.len(),
        options.timeout_ms,
        options.workers
    );
    let started = Instant::now();
    let handle = start_scan(options);
    let mut hosts = HashMap::<Ipv4Addr, Box<HostResult>>::new();
    let mut checked = 0;
    let mut basic_complete = false;
    while let Ok(event) = handle.events.recv() {
        match event {
            ScanEvent::Host(host) => {
                if watch.contains(&host.ip) {
                    println!(
                        "At {:?}: {} {:?}, ping={:?}, TCP={:?}, notes={}",
                        started.elapsed(),
                        host.ip,
                        host.status,
                        host.ping_ms,
                        host.open_ports,
                        host.notes
                    );
                }
                checked += usize::from(host.discovery_complete());
                let previous = hosts.insert(host.ip, host);
                checked -= previous
                    .as_ref()
                    .map_or(0, |host| usize::from(host.discovery_complete()));
                if previous.is_none() && hosts.len() == 1 {
                    println!("First row: {:?}", started.elapsed());
                }
                if !basic_complete && checked == total {
                    println!("All basic rows: {:?}", started.elapsed());
                    basic_complete = true;
                }
            }
            ScanEvent::Phase(message) => println!("At {:?}: {message}", started.elapsed()),
            ScanEvent::Concurrency(snapshot) => {
                println!("At {:?}: adaptive {snapshot:?}", started.elapsed())
            }
            ScanEvent::Warning(warning) => eprintln!("{warning}"),
            ScanEvent::Finished { elapsed, cancelled } => {
                println!(
                    "Finished: {elapsed:?}, cancelled: {cancelled}, rows: {}",
                    hosts.len()
                );
                println!(
                    "Alive: {}, names: {}, MACs: {}, web hosts: {}, certificate hosts: {}",
                    hosts
                        .values()
                        .filter(|host| host.status == ip_scout::scanner::HostStatus::Alive)
                        .count(),
                    hosts
                        .values()
                        .filter(|host| !host.hostname.is_empty())
                        .count(),
                    hosts.values().filter(|host| !host.mac.is_empty()).count(),
                    hosts
                        .values()
                        .filter(|host| !host.extra.web.is_empty())
                        .count(),
                    hosts
                        .values()
                        .filter(|host| !host.extra.certificates.is_empty())
                        .count()
                );
                let mut hosts: Vec<_> = hosts.values().map(Box::as_ref).collect();
                hosts.sort_by_key(|host| host.ip);
                if let Some(path) = args.iter().find_map(|arg| arg.strip_prefix("--csv=")) {
                    export::save_csv_with_fetchers(
                        std::path::Path::new(path),
                        &hosts,
                        &fetchers::Fetcher::ALL,
                    )?;
                    println!("Saved {} rows to {path}", hosts.len());
                }
                break;
            }
        }
    }
    Ok(())
}
