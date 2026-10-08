use super::*;
use hickory_proto::rr::{Record, rdata::PTR};
use hickory_proto::{
    op::{Message, MessageType, Query},
    rr::{Name, RData, RecordType},
};
use std::io::{Read, Write};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}
fn tlv(data: &mut Vec<u8>, kind: u16, value: &[u8], wide: bool) {
    if wide {
        data.extend_from_slice(&kind.to_be_bytes());
    } else {
        data.push(kind as u8);
    }
    data.extend_from_slice(&(value.len() as u16).to_be_bytes());
    data.extend_from_slice(value);
}
fn vendor_packet(ubiquiti: bool) -> Vec<u8> {
    let mut data = vec![0; 4];
    tlv(&mut data, 1, &[2, 3, 4, 5, 6, 7], !ubiquiti);
    tlv(
        &mut data,
        if ubiquiti { 11 } else { 5 },
        b"lab-device",
        !ubiquiti,
    );
    tlv(
        &mut data,
        if ubiquiti { 20 } else { 12 },
        b"test-model",
        !ubiquiti,
    );
    if ubiquiti {
        data[0] = 1;
        let len = data.len() - 4;
        data[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    }
    data
}
#[test]
fn vendor_tlvs_are_bounded_and_never_expose_sensitive_fields() {
    let mndp = vendor_packet(false);
    let device = parse_mndp(&mndp).unwrap();
    assert_eq!(device.name, "lab-device");
    assert_eq!(device.model, "test-model");
    for len in 0..mndp.len() {
        if let Some(partial) = parse_mndp(&mndp[..len]) {
            assert!(!partial.mac.is_empty());
        }
    }
    let mut malformed = mndp.clone();
    malformed[6..8].copy_from_slice(&[255, 255]);
    assert!(parse_mndp(&malformed).is_none());
    let mut ubnt = vendor_packet(true);
    tlv(&mut ubnt, 6, b"secret-username", false);
    tlv(&mut ubnt, 7, b"secret-salt", false);
    let len = ubnt.len() - 4;
    ubnt[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    let device = parse_ubiquiti(&ubnt).unwrap();
    assert!(!device.summary().contains("secret"));
    for len in 0..ubnt.len() {
        assert!(parse_ubiquiti(&ubnt[..len]).is_none());
    }
    for command in [6, 9, 11] {
        ubnt[0] = 2;
        ubnt[1] = command;
        assert!(parse_ubiquiti(&ubnt).is_some());
    }
    ubnt[1] = 8;
    assert!(parse_ubiquiti(&ubnt).is_none());
    assert!(parse_mndp(&vec![0; 20_000]).is_none());
    assert!(parse_ubiquiti(&vec![0; 20_000]).is_none());
}
#[test]
fn ssdp_metadata_urls_cannot_redirect_discovery_to_another_host() {
    let peer = Ipv4Addr::LOCALHOST;
    for url in [
        "http://example.com/desc.xml",
        "http://127.0.0.2/desc",
        "file:///test",
        "http://user:password@127.0.0.1/",
        "http://127.0.0.1/#fragment",
    ] {
        assert!(safe_location(url, peer).is_none(), "{url}");
    }
    let packet = b"HTTP/1.1 200 OK\r\nUSN: uuid:test\r\nST: upnp:rootdevice\r\nSERVER: test/1 UPnP/1.0\r\nLOCATION: http://127.0.0.1:8000/desc.xml\r\n\r\n";
    let device = parse_ssdp(packet, peer).unwrap();
    assert_eq!(device.server, "test/1 UPnP/1.0");
    assert!(!device.location.is_empty());
    let device = parse_ssdp(packet, Ipv4Addr::new(192, 0, 2, 1)).unwrap();
    assert!(device.location.is_empty());
    assert!(parse_ssdp(b"NOTIFY * HTTP/1.1\r\n\r\n", peer).is_none());
    assert!(
        parse_ssdp(
            b"HTTP/1.1 200 OK\r\nUSN: x\r\nusn: y\r\nST: z\r\n\r\n",
            peer
        )
        .is_none()
    );
    let xml = br#"<root xmlns="urn:schemas-upnp-org:device-1-0"><device><friendlyName>Lab &amp; Printer</friendlyName><manufacturer>Test Co</manufacturer><modelName>Laser 1</modelName></device></root>"#;
    assert_eq!(
        parse_description(xml).unwrap(),
        ("Lab & Printer".into(), "Test Co".into(), "Laser 1".into())
    );
    assert!(parse_description(b"<!DOCTYPE root><root/>").is_none());
    assert!(parse_description(b"<root xmlns='urn:schemas-upnp-org:device-1-0'><device>").is_none());
}
#[test]
fn upnp_fetches_a_size_limited_description_without_following_redirects() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    listener.set_nonblocking(true).unwrap();
    let server = std::thread::spawn(move || {
        let start = std::time::Instant::now();
        let mut requests = 0;
        while requests < 2 && start.elapsed() < Duration::from_secs(5) {
            let (mut socket, _) = match listener.accept() {
                Ok(connection) => connection,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                Err(e) => panic!("{e}"),
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut buffer = [0; 4096];
            let mut len = socket.read(&mut buffer).unwrap();
            while len < buffer.len() && !buffer[..len].windows(4).any(|bytes| bytes == b"\r\n\r\n")
            {
                let count = socket.read(&mut buffer[len..]).unwrap();
                if count == 0 {
                    break;
                }
                len += count;
            }
            let request = std::str::from_utf8(&buffer[..len]).unwrap();
            assert!(!request.contains("Authorization:"));
            if request.starts_with("GET /description ") {
                let body = "<root xmlns='urn:schemas-upnp-org:device-1-0'><device><friendlyName>Lab printer</friendlyName><manufacturer>Test Co</manufacturer><modelName>Laser</modelName></device></root>";
                write!(
                    socket,
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                )
                .unwrap();
            } else {
                assert!(request.starts_with("GET /redirect "));
                socket.write_all(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").unwrap();
            }
            requests += 1;
        }
        assert_eq!(requests, 2);
    });
    let mut snapshot = Snapshot::default();
    snapshot
        .hosts
        .entry(Ipv4Addr::LOCALHOST)
        .or_default()
        .advertisements
        .ssdp = vec![
        UpnpDevice {
            location: format!("http://127.0.0.1:{port}/redirect"),
            ..Default::default()
        },
        UpnpDevice {
            location: format!("http://127.0.0.1:{port}/description"),
            ..Default::default()
        },
        UpnpDevice {
            usn: "second-service".into(),
            location: format!("http://127.0.0.1:{port}/description"),
            ..Default::default()
        },
    ];
    runtime().block_on(enrich_upnp(&mut snapshot, &CancellationToken::new()));
    server.join().unwrap();
    let devices = &snapshot.hosts[&Ipv4Addr::LOCALHOST].advertisements.ssdp;
    assert!(devices[0].name.is_empty());
    assert_eq!(devices[1].name, "Lab printer");
    assert_eq!(devices[2].name, "Lab printer");
}
#[test]
fn llmnr_requires_matching_transaction_question_and_ptr_owner() {
    let query = Name::from_ascii("1.0.0.127.in-addr.arpa.").unwrap();
    let mut message = Message::new();
    message
        .set_id(123)
        .set_message_type(MessageType::Response)
        .add_query(Query::query(query.clone(), RecordType::PTR))
        .add_answer(Record::from_rdata(
            query.clone(),
            120,
            RData::PTR(PTR(Name::from_ascii("lab-pc.").unwrap())),
        ));
    let data = message.to_vec().unwrap();
    assert_eq!(parse_llmnr(&data, 123, &query).unwrap(), "lab-pc");
    assert!(parse_llmnr(&data, 124, &query).is_none());
    assert!(
        parse_llmnr(
            &data,
            123,
            &Name::from_ascii("2.0.0.127.in-addr.arpa.").unwrap()
        )
        .is_none()
    );
    for len in 0..data.len() {
        assert!(parse_llmnr(&data[..len], 123, &query).is_none());
    }
    message.set_truncated(true);
    assert!(parse_llmnr(&message.to_vec().unwrap(), 123, &query).is_none());
}
#[test]
fn unicast_llmnr_loopback_query_and_cancellation() {
    runtime().block_on(async {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let peer = server.local_addr().unwrap();
        let fixture = async {
            let (mut stream, _) = server.accept().await.unwrap();
            let mut buffer = [0u8; 4096];
            let len = usize::from(stream.read_u16().await.unwrap());
            stream.read_exact(&mut buffer[..len]).await.unwrap();
            let query = Message::from_vec(&buffer[..len]).unwrap();
            assert_eq!(query.queries()[0].query_type(), RecordType::PTR);
            assert!(!query.recursion_desired());
            let mut response = Message::new();
            response
                .set_id(query.id())
                .set_message_type(MessageType::Response)
                .add_query(query.queries()[0].clone())
                .add_answer(Record::from_rdata(
                    query.queries()[0].name().clone(),
                    120,
                    RData::PTR(PTR(Name::from_ascii("fixture-pc.").unwrap())),
                ));
            let data = response.to_vec().unwrap();
            stream.write_u16(data.len() as u16).await.unwrap();
            stream.write_all(&data).await.unwrap();
        };
        let cancel = CancellationToken::new();
        let (result, _) = futures_util::future::join(
            llmnr_at(peer, Ipv4Addr::LOCALHOST, Duration::from_secs(1), &cancel),
            fixture,
        )
        .await;
        assert_eq!(result.unwrap(), "fixture-pc");
        cancel.cancel();
        assert!(
            llmnr_at(peer, Ipv4Addr::LOCALHOST, Duration::from_secs(30), &cancel)
                .await
                .is_none()
        );
    });
}
#[test]
fn llmnr_pending_tcp_reads_cancel_and_oversized_frames_are_rejected() {
    runtime().block_on(async {
        for oversized in [false, true] {
            let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let peer = server.local_addr().unwrap();
            let cancel = CancellationToken::new();
            let fixture = async {
                let (mut stream, _) = server.accept().await.unwrap();
                let len = usize::from(stream.read_u16().await.unwrap());
                let mut query = vec![0; len];
                stream.read_exact(&mut query).await.unwrap();
                if oversized {
                    stream.write_u16(65535).await.unwrap();
                } else {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    cancel.cancel();
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            };
            let start = std::time::Instant::now();
            let (result, _) = futures_util::future::join(
                llmnr_at(peer, Ipv4Addr::LOCALHOST, Duration::from_secs(30), &cancel),
                fixture,
            )
            .await;
            assert!(result.is_none());
            assert!(start.elapsed() < Duration::from_secs(2));
        }
    });
}

#[test]
fn upnp_description_work_is_cancelled_and_oversized_xml_is_rejected() {
    runtime().block_on(async {
        let server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = server.local_addr().unwrap().port();
        let cancel = CancellationToken::new();
        let mut snapshot = Snapshot::default();
        snapshot
            .hosts
            .entry(Ipv4Addr::LOCALHOST)
            .or_default()
            .advertisements
            .ssdp
            .push(UpnpDevice {
                location: format!("http://127.0.0.1:{port}/description"),
                ..Default::default()
            });
        let fixture = async {
            let (mut stream, _) = server.accept().await.unwrap();
            let mut request = [0u8; 4096];
            assert!(stream.read(&mut request).await.unwrap() > 0);
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel.cancel();
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let start = std::time::Instant::now();
        futures_util::future::join(enrich_upnp(&mut snapshot, &cancel), fixture).await;
        assert!(start.elapsed() < Duration::from_secs(2));
        assert!(
            snapshot.hosts[&Ipv4Addr::LOCALHOST].advertisements.ssdp[0]
                .name
                .is_empty()
        );
        assert!(parse_description(&vec![b' '; 16385]).is_none());
    });
}

#[test]
fn udp_collection_rejects_out_of_range_hosts_and_deduplicates() {
    runtime().block_on(async {
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer = receiver.local_addr().unwrap();
        let packet = b"HTTP/1.1 200 OK\r\nUSN: uuid:test\r\nST: upnp:rootdevice\r\n\r\n";
        for _ in 0..3 {
            sender.send_to(packet, peer).await.unwrap();
        }
        let mut snapshot = Snapshot::default();
        let targets = TargetRange::parse("127.0.0.1").unwrap();
        let _ = tokio::time::timeout(
            Duration::from_millis(100),
            receive(&receiver, Kind::Ssdp, &targets, &mut snapshot),
        )
        .await;
        assert_eq!(
            snapshot.hosts[&Ipv4Addr::LOCALHOST]
                .advertisements
                .ssdp
                .len(),
            1
        );
        sender.send_to(packet, peer).await.unwrap();
        let mut snapshot = Snapshot::default();
        let targets = TargetRange::parse("192.0.2.1").unwrap();
        let _ = tokio::time::timeout(
            Duration::from_millis(100),
            receive(&receiver, Kind::Ssdp, &targets, &mut snapshot),
        )
        .await;
        assert!(snapshot.hosts.is_empty());
    });
}
#[test]
fn disabled_cancelled_and_missing_interface_discovery_are_fast() {
    runtime().block_on(async {
        let targets = TargetRange::parse("192.0.2.1").unwrap();
        let cancel = CancellationToken::new();
        assert!(
            collect(
                &targets,
                &[],
                Options::default(),
                Duration::from_secs(60),
                &cancel
            )
            .await
            .warnings
            .is_empty()
        );
        let options = Options {
            ssdp: true,
            mndp: true,
            ubiquiti: true,
        };
        assert_eq!(
            collect(&targets, &[], options, Duration::from_secs(60), &cancel)
                .await
                .warnings
                .len(),
            1
        );
        cancel.cancel();
        assert!(
            collect(
                &targets,
                &[Ipv4Addr::LOCALHOST],
                options,
                Duration::from_secs(60),
                &cancel
            )
            .await
            .warnings
            .is_empty()
        );
    });
}
#[test]
fn vendor_broadcast_is_scoped_to_the_selected_adapter_subnet() {
    let address = Ipv4Addr::new(192, 168, 1, 5);
    let networks = [crate::network::LocalNetwork {
        address,
        cidr: "192.168.1.0/24".into(),
    }];
    assert_eq!(
        broadcast_for(&networks, address),
        Ipv4Addr::new(192, 168, 1, 255)
    );
    assert_eq!(
        broadcast_for(&networks, Ipv4Addr::new(10, 0, 0, 1)),
        Ipv4Addr::BROADCAST
    );
}
