use ip_scout::{inventory::InventoryProber, metadata::WebProber};
use std::{net::Ipv4Addr, time::Duration};
use tokio_util::sync::CancellationToken;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let usage = "Usage: diagnose_web <IPv4> <port> [--unverified-tls]";
    if !(2..=3).contains(&args.len()) || args.get(2).is_some_and(|arg| arg != "--unverified-tls") {
        return Err(usage.into());
    }
    let ip: Ipv4Addr = args[0].parse()?;
    let port: u16 = args[1].parse()?;
    if port == 0 {
        return Err("Port must be between 1 and 65535".into());
    }
    let timeout = Duration::from_secs(3);
    let allow_unverified = args.len() == 3;
    let web = WebProber::new_with_titles(timeout, allow_unverified, true)?;
    let inventory = InventoryProber::default();
    let cancel = CancellationToken::new();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    println!("Only {ip}:{port}; no redirects, credentials, or other ports.");
    println!("Allow unverified TLS: {allow_unverified}");
    runtime.block_on(async {
        let started = std::time::Instant::now();
        let web_work = async {
            let services = web.probe_endpoint(ip, port, timeout, &cancel).await;
            for scheme in ["http", "https"] {
                if let Some(service) = services
                    .iter()
                    .find(|service| service.url.starts_with(&format!("{scheme}://")))
                {
                    println!("At {:?}: {service:#?}", started.elapsed());
                } else {
                    println!("At {:?}: {scheme}: no usable response (timeout, connection, protocol, or TLS validation failure)", started.elapsed());
                }
            }
        };
        let certificate_work = async {
            let certificate = inventory
                .certificate_endpoint(ip, port, timeout, &cancel)
                .await;
            println!("At {:?}: certificate: {certificate:#?}", started.elapsed());
        };
        futures_util::future::join(web_work, certificate_work).await;
    });
    Ok(())
}
