use ip_scout::{
    scanner::{ScanEvent, ScanOptions, start_scan},
    targets::{TargetRange, parse_ports},
};

fn main() {
    let basic = std::env::args().any(|arg| arg == "--basic");
    let address = std::env::args()
        .nth(1)
        .expect("Usage: diagnose_host <single IPv4 address>");
    let ip: std::net::Ipv4Addr = address.parse().expect("Expected a single IPv4 address");
    let handle = start_scan(ScanOptions {
        mode: ip_scout::scanner::ScanMode::Thorough,
        targets: TargetRange::parse(&ip.to_string()).unwrap(),
        ports: parse_ports("22,80,443,445,3389,8080").unwrap(),
        timeout_ms: 600,
        workers: 1,
        adaptive_concurrency: true,
        resolve_names: true,
        fetch_mac: true,
        fetch_vendor: true,
        discover_arp: true,
        extra: if basic {
            Default::default()
        } else {
            ip_scout::scanner::ExtraOptions {
                bonjour: true,
                wsd: true,
                netbios: true,
                web: true,
                packet_loss: true,
                advertisements: ip_scout::advertisements::Options {
                    ssdp: true,
                    mndp: true,
                    ubiquiti: true,
                },
                llmnr: true,
                ..Default::default()
            }
        },
    });
    let started = std::time::Instant::now();
    while let Ok(event) = handle.events.recv() {
        match event {
            ScanEvent::Host(host) => println!("At {:?}: {host:#?}", started.elapsed()),
            ScanEvent::Phase(message) => println!("At {:?}: {message}", started.elapsed()),
            ScanEvent::Concurrency(snapshot) => {
                println!("At {:?}: adaptive {snapshot:?}", started.elapsed())
            }
            ScanEvent::Warning(warning) => eprintln!("{warning}"),
            ScanEvent::Finished { elapsed, cancelled } => {
                println!("Finished in {elapsed:?}, cancelled: {cancelled}");
                break;
            }
        }
    }
}
