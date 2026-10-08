use crate::fetchers::Fetcher;
use crate::scanner::HostResult;
use std::{io::Write, path::Path};

pub fn write_csv(writer: impl Write, hosts: &[&HostResult]) -> Result<(), csv::Error> {
    let mut csv = csv::Writer::from_writer(writer);
    csv.write_record([
        "IP address",
        "Status",
        "Ping (ms)",
        "Hostname",
        "MAC address",
        "Vendor",
        "Open TCP ports",
        "Refused TCP ports",
        "Notes",
        "ARP response",
        "Probable brand",
    ])?;
    for host in hosts {
        csv.write_record([
            host.ip.to_string(),
            host.status.label().to_owned(),
            host.ping_ms
                .map(|ping| format!("{ping:.1}"))
                .unwrap_or_default(),
            spreadsheet_safe(&host.hostname),
            host.mac.clone(),
            spreadsheet_safe(&host.vendor),
            host.open_ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join("; "),
            host.refused_ports.to_string(),
            spreadsheet_safe(&host.notes),
            host.arp_response.to_string(),
            spreadsheet_safe(&host.probable_brand),
        ])?;
    }
    csv.flush()?;
    Ok(())
}

pub fn save_csv(path: &Path, hosts: &[&HostResult]) -> Result<(), String> {
    let file = std::fs::File::create(path).map_err(|error| error.to_string())?;
    write_csv(file, hosts).map_err(|error| error.to_string())
}

pub fn write_csv_with_fetchers(
    writer: impl Write,
    hosts: &[&HostResult],
    fetchers: &[Fetcher],
) -> Result<(), csv::Error> {
    let mut csv = csv::Writer::from_writer(writer);
    let mut headers = vec!["IP address", "Status"];
    headers.extend(fetchers.iter().map(|fetcher| fetcher.label()));
    csv.write_record(headers)?;
    for host in hosts {
        let mut record = vec![host.ip.to_string(), host.status.label().to_owned()];
        record.extend(
            fetchers
                .iter()
                .map(|fetcher| spreadsheet_safe(&fetcher.value(host))),
        );
        csv.write_record(record)?;
    }
    csv.flush()?;
    Ok(())
}

pub fn save_csv_with_fetchers(
    path: &Path,
    hosts: &[&HostResult],
    fetchers: &[Fetcher],
) -> Result<(), String> {
    let file = std::fs::File::create(path).map_err(|error| error.to_string())?;
    write_csv_with_fetchers(file, hosts, fetchers).map_err(|error| error.to_string())
}

// Hostnames and vendor names may be opened as spreadsheet cells.
fn spreadsheet_safe(value: &str) -> String {
    if value
        .trim_start()
        .starts_with(['=', '+', '-', '@', '\t', '\r', '\n'])
        || value.starts_with(['\t', '\r', '\n'])
    {
        format!("'{value}")
    } else {
        value.to_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::HostStatus;
    use std::net::Ipv4Addr;

    #[test]
    fn csv_quotes_fields_and_neutralizes_spreadsheet_formulas() {
        let host = HostResult {
            ip: Ipv4Addr::LOCALHOST,
            status: HostStatus::Alive,
            ping_ms: Some(0.0),
            hostname: "=1+2".into(),
            mac: String::new(),
            vendor: "Example, Inc.".into(),
            open_ports: vec![80, 443],
            refused_ports: 0,
            notes: "two\nlines".into(),
            arp_response: true,
            probable_brand: "@untrusted".into(),
            extra: crate::scanner::ExtraResult {
                ttl: Some(64),
                packet_loss: Some(33.333),
                icmp_sent: 3,
                icmp_received: 2,
                netbios: "=untrusted (workstation)".into(),
                web: vec![crate::metadata::WebService {
                    url: "http://127.0.0.1:8080/".into(),
                    server: "Apache/2.4".into(),
                    status: 401,
                    tls_unverified: false,
                    title: String::new(),
                }],
                ..Default::default()
            },
        };
        let mut output = Vec::new();
        write_csv(&mut output, &[&host]).unwrap();
        let record = csv::Reader::from_reader(output.as_slice())
            .records()
            .next()
            .unwrap()
            .unwrap();
        assert_eq!(&record[3], "'=1+2");
        assert_eq!(&record[5], "Example, Inc.");
        assert_eq!(&record[6], "80; 443");
        assert_eq!(&record[8], "two\nlines");
        assert_eq!(&record[9], "true");
        assert_eq!(&record[10], "'@untrusted");
        let mut selected = Vec::new();
        write_csv_with_fetchers(
            &mut selected,
            &[&host],
            &[Fetcher::Hostname, Fetcher::MacAddress, Fetcher::Ping],
        )
        .unwrap();
        let mut reader = csv::Reader::from_reader(selected.as_slice());
        assert_eq!(
            reader.headers().unwrap().iter().collect::<Vec<_>>(),
            vec!["IP address", "Status", "Hostname", "MAC address", "Ping"]
        );
        let record = reader.records().next().unwrap().unwrap();
        assert_eq!(&record[2], "'=1+2");
        assert_eq!(&record[4], "0.0");
        let mut output = Vec::new();
        write_csv_with_fetchers(
            &mut output,
            &[&host],
            &[
                Fetcher::Ttl,
                Fetcher::Netbios,
                Fetcher::WebDetect,
                Fetcher::PacketLoss,
                Fetcher::HttpStatus,
                Fetcher::WebUrl,
            ],
        )
        .unwrap();
        let mut reader = csv::Reader::from_reader(output.as_slice());
        assert_eq!(
            reader.headers().unwrap().iter().collect::<Vec<_>>(),
            vec![
                "IP address",
                "Status",
                "TTL",
                "NetBIOS info",
                "Web detect",
                "Packet loss",
                "HTTP status",
                "Web URL"
            ]
        );
        let record = reader.records().next().unwrap().unwrap();
        assert_eq!(&record[2], "64");
        assert_eq!(&record[3], "'=untrusted (workstation)");
        assert!(record[4].contains("Apache/2.4"));
        assert_eq!(&record[5], "33.3%");
        assert!(record[6].contains("401"));
        assert_eq!(&record[7], "http://127.0.0.1:8080/");
        let mut host = host;
        host.extra.bonjour = vec![crate::discovery::BonjourService {
            instance: "=untrusted".into(),
            service_type: "_ipp._tcp.local.".into(),
            hostname: "printer.local".into(),
            port: 631,
            properties: vec!["model=Laser printer".into()],
        }];
        host.extra.wsd = vec![crate::discovery::WsdDevice {
            endpoint: "urn:uuid:printer".into(),
            types: vec!["Printer".into()],
            addresses: vec!["http://127.0.0.1:5357/printer".into()],
            ..Default::default()
        }];
        let mut output = Vec::new();
        write_csv_with_fetchers(&mut output, &[&host], &[Fetcher::Wsd, Fetcher::Bonjour]).unwrap();
        let mut reader = csv::Reader::from_reader(output.as_slice());
        assert_eq!(
            reader.headers().unwrap().iter().collect::<Vec<_>>(),
            ["IP address", "Status", "WSD info", "Bonjour / mDNS"]
        );
        let record = reader.records().next().unwrap().unwrap();
        assert!(record[2].contains("127.0.0.1:5357/printer"));
        assert!(record[3].starts_with("'=untrusted"));
        assert!(record[3].contains("model=Laser printer"));
        host.extra.llmnr = "=untrusted-host".into();
        host.extra.advertisements.ssdp = vec![crate::advertisements::UpnpDevice {
            name: "=untrusted-tv".into(),
            ..Default::default()
        }];
        host.extra.advertisements.mndp = vec![crate::advertisements::VendorDevice {
            name: "@untrusted-router".into(),
            ..Default::default()
        }];
        host.extra.advertisements.ubiquiti = vec![crate::advertisements::VendorDevice {
            name: "+untrusted-ap".into(),
            ..Default::default()
        }];
        let mut output = Vec::new();
        write_csv_with_fetchers(
            &mut output,
            &[&host],
            &[
                Fetcher::Llmnr,
                Fetcher::Ssdp,
                Fetcher::Mndp,
                Fetcher::Ubiquiti,
            ],
        )
        .unwrap();
        let mut reader = csv::Reader::from_reader(output.as_slice());
        assert_eq!(
            reader.headers().unwrap().iter().collect::<Vec<_>>(),
            [
                "IP address",
                "Status",
                "LLMNR hostname",
                "SSDP / UPnP",
                "MikroTik MNDP",
                "Ubiquiti discovery"
            ]
        );
        let record = reader.records().next().unwrap().unwrap();
        for index in 2..6 {
            assert!(record[index].starts_with('\''));
        }
        host.extra.udp = crate::udp::UdpResult {
            open_ports: vec![53, 123],
            requested: 3,
            completed: 3,
            open_or_filtered: 1,
            dns: "=untrusted-DNS".into(),
            ntp: "123/udp: stratum 2".into(),
            snmp: "Not queried".into(),
            ..Default::default()
        };
        let mut output = Vec::new();
        write_csv_with_fetchers(
            &mut output,
            &[&host],
            &[
                Fetcher::UdpPorts,
                Fetcher::UdpStatus,
                Fetcher::DnsInfo,
                Fetcher::NtpInfo,
                Fetcher::SnmpInfo,
            ],
        )
        .unwrap();
        let mut reader = csv::Reader::from_reader(output.as_slice());
        assert_eq!(
            reader.headers().unwrap().iter().collect::<Vec<_>>(),
            [
                "IP address",
                "Status",
                "Open UDP ports",
                "UDP scan status",
                "DNS service",
                "NTP service",
                "SNMP info"
            ]
        );
        let record = reader.records().next().unwrap().unwrap();
        assert_eq!(&record[2], "53, 123");
        assert!(record[3].contains("open or filtered 1"));
        assert_eq!(&record[4], "'=untrusted-DNS");
        assert_eq!(&record[5], "123/udp: stratum 2");
        assert_eq!(&record[6], "Not queried");
    }
}
