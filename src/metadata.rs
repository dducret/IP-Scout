use futures_util::{StreamExt, stream};
use netbios_parser::{NMFlags, RClass, RCode, RData, RType, parse_nbss_header, parse_nbss_packet};
use serde::{Deserialize, Serialize};
use std::{
    net::{Ipv4Addr, SocketAddr},
    sync::atomic::{AtomicU16, Ordering},
    time::Duration,
};
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WebService {
    pub url: String,
    pub server: String,
    pub status: u16,
    pub tls_unverified: bool,
    #[serde(default)]
    pub title: String,
}

impl WebService {
    pub fn endpoint(&self) -> &str {
        self.url
            .split_once("://")
            .map_or(&self.url, |(_, address)| address)
    }
}

pub struct WebProber {
    client: reqwest::Client,
    slots: tokio::sync::Semaphore,
    allow_unverified_tls: bool,
    titles: bool,
}

impl WebProber {
    pub fn new(timeout: Duration, allow_unverified_tls: bool) -> Result<Self, reqwest::Error> {
        Self::new_with_titles(timeout, allow_unverified_tls, false)
    }

    pub fn new_with_titles(
        timeout: Duration,
        allow_unverified_tls: bool,
        titles: bool,
    ) -> Result<Self, reqwest::Error> {
        Ok(Self {
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .timeout(timeout)
                .pool_max_idle_per_host(0)
                .danger_accept_invalid_certs(allow_unverified_tls)
                .user_agent(concat!("IP-Scout/", env!("CARGO_PKG_VERSION")))
                .build()?,
            slots: tokio::sync::Semaphore::new(32),
            allow_unverified_tls,
            titles,
        })
    }

    pub async fn probe(
        &self,
        ip: Ipv4Addr,
        open_ports: &[u16],
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Vec<WebService> {
        self.probe_scanned(ip, &[], open_ports, timeout, cancel)
            .await
    }

    /// Avoid repeating TCP probes for ports already scanned without an open listener.
    pub async fn probe_scanned(
        &self,
        ip: Ipv4Addr,
        scanned_ports: &[u16],
        open_ports: &[u16],
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Vec<WebService> {
        let ports = web_ports(scanned_ports, open_ports);
        let mut services = Vec::new();
        let work = async {
            let endpoints = ports
                .into_iter()
                .flat_map(|port| [(port, "http"), (port, "https")]);
            let mut pending = stream::iter(endpoints)
                .map(|(port, scheme)| self.probe_scheme(ip, port, scheme))
                .buffer_unordered(8);
            while let Some(service) = pending.next().await {
                if let Some(service) = service {
                    services.push(service);
                }
            }
        };
        let _ = cancel
            .run_until_cancelled(tokio::time::timeout(timeout.saturating_mul(4), work))
            .await;
        services.sort_by(|a, b| a.url.cmp(&b.url));
        services
    }

    #[cfg(test)]
    async fn probe_port(&self, ip: Ipv4Addr, port: u16) -> Option<WebService> {
        self.probe_schemes(ip, port).await.into_iter().next()
    }

    #[cfg(test)]
    async fn probe_schemes(&self, ip: Ipv4Addr, port: u16) -> Vec<WebService> {
        self.probe_endpoint(ip, port, Duration::from_secs(3), &CancellationToken::new())
            .await
    }

    /// Check both schemes on only this endpoint, retaining completed responses at the deadline.
    pub async fn probe_endpoint(
        &self,
        ip: Ipv4Addr,
        port: u16,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Vec<WebService> {
        let mut services = Vec::new();
        let work = async {
            let mut pending = stream::iter(["http", "https"])
                .map(|scheme| self.probe_scheme(ip, port, scheme))
                .buffer_unordered(2);
            while let Some(service) = pending.next().await {
                if let Some(service) = service {
                    services.push(service);
                }
            }
        };
        let _ = cancel
            .run_until_cancelled(tokio::time::timeout(timeout, work))
            .await;
        services.sort_by(|a, b| a.url.cmp(&b.url));
        services
    }

    async fn probe_scheme(&self, ip: Ipv4Addr, port: u16, scheme: &str) -> Option<WebService> {
        let _slot = self.slots.acquire().await.ok()?;
        let url = format!("{scheme}://{ip}:{port}/");
        let request = if self.titles {
            self.client.get(&url)
        } else {
            self.client.head(&url)
        };
        let response = match request.send().await {
            Ok(response) if matches!(response.status().as_u16(), 405 | 501) => {
                self.client.get(&url).send().await.ok()
            }
            Ok(response) => Some(response),
            Err(_) => None,
        };
        if let Some(response) = response {
            let server = response
                .headers()
                .get(reqwest::header::SERVER)
                .and_then(|header| header.to_str().ok())
                .map(clean_text)
                .unwrap_or_default();
            let status = response.status().as_u16();
            let title = if self.titles {
                read_title(response).await
            } else {
                String::new()
            };
            return Some(WebService {
                url,
                server,
                status,
                tls_unverified: scheme == "https" && self.allow_unverified_tls,
                title,
            });
        }
        None
    }
}

fn web_ports(scanned: &[u16], open: &[u16]) -> Vec<u16> {
    let mut ports = vec![80, 443, 8000, 8080, 8443, 8888];
    for &port in open {
        if ports.len() == 32 {
            break;
        }
        if !ports.contains(&port) && !non_web_port(port) {
            ports.push(port);
        }
    }
    ports.retain(|port| !scanned.contains(port) || open.contains(port));
    // Spend the bounded request budget on confirmed listeners first.
    ports.sort_by_key(|port| !open.contains(port));
    ports
}

pub(crate) fn non_web_port(port: u16) -> bool {
    [
        21, 22, 25, 53, 110, 135, 139, 143, 389, 445, 465, 515, 587, 636, 853, 993, 995, 1883,
        3389, 5900, 9100,
    ]
    .contains(&port)
}

async fn read_title(mut response: reqwest::Response) -> String {
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if !matches!(content_type.as_str(), "text/html" | "application/xhtml+xml")
        || response
            .headers()
            .contains_key(reqwest::header::CONTENT_ENCODING)
    {
        return String::new();
    }
    let mut bytes = Vec::new();
    let work = async {
        while bytes.len() < 16 * 1024 {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    let count = chunk.len().min(16 * 1024 - bytes.len());
                    bytes.extend_from_slice(&chunk[..count]);
                }
                _ => break,
            }
        }
    };
    let _ = tokio::time::timeout(Duration::from_millis(400), work).await;
    let document = scraper::Html::parse_document(&String::from_utf8_lossy(&bytes));
    let selector = scraper::Selector::parse("title").expect("Static CSS selector");
    document
        .select(&selector)
        .next()
        .map(|title| clean_text(&title.text().collect::<Vec<_>>().join(" ")))
        .unwrap_or_default()
}

fn clean_text(value: &str) -> String {
    value
        .chars()
        .filter(|ch| !ch.is_control())
        .take(256)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn netbios_request(id: u16) -> Vec<u8> {
    let mut request = Vec::with_capacity(50);
    request.extend(id.to_be_bytes());
    request.extend([0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 32]);
    // RFC 1002 first-level encoding of the wildcard node-status name.
    for byte in std::iter::once(b'*').chain(std::iter::repeat_n(0, 15)) {
        request.extend([b'A' + (byte >> 4), b'A' + (byte & 15)]);
    }
    request.extend([0, 0, 0x21, 0, 1]);
    request
}

fn parse_netbios(bytes: &[u8], id: u16) -> Option<String> {
    let (_, header) = parse_nbss_header(bytes).ok()?;
    if header.name_trn_id != id
        || !header.response()
        // netbios-parser 0.2 includes the authoritative flag in opcode().
        // RFC 1002 defines only bits 11..14 as the opcode.
        || bytes[2] & 0x78 != 0
        || header.rcode() != RCode::NoErr
        || header.nm_flags().0 & NMFlags::Truncation.0 != 0
        || header.qdcount > 1
        || u32::from(header.ancount) + u32::from(header.nscount) + u32::from(header.arcount) > 32
    {
        return None;
    }
    let (_, packet) = parse_nbss_packet(bytes).ok()?;
    let mut labels = Vec::new();
    for record in packet.rr_answer {
        if record.rr_type != RType::NBSTAT || record.rr_class != RClass::IN {
            continue;
        }
        if let RData::NBStat { names, .. } = record.rdata {
            for node in names {
                let name = clean_text(&node.name.nb_name);
                if name.is_empty() {
                    continue;
                }
                let role = if node.name_flags & 0x8000 != 0 {
                    "group"
                } else {
                    match node.name.nb_type.0 {
                        0 => "workstation",
                        0x20 => "file server",
                        0x1b => "domain master",
                        0x1d => "master browser",
                        _ => "service",
                    }
                };
                let label = format!("{name} ({role}, {:02X})", node.name.nb_type.0);
                if !labels.contains(&label) {
                    labels.push(label);
                }
            }
        }
    }
    (!labels.is_empty()).then(|| labels.join("; "))
}

pub async fn netbios(
    address: SocketAddr,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Option<String> {
    static NEXT_ID: AtomicU16 = AtomicU16::new(0x5343);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    cancel
        .run_until_cancelled(tokio::time::timeout(timeout, async {
            let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
            socket.connect(address).await.ok()?;
            socket.send(&netbios_request(id)).await.ok()?;
            let mut bytes = [0u8; 8192];
            loop {
                let length = socket.recv(&mut bytes).await.ok()?;
                if let Some(info) = parse_netbios(&bytes[..length], id) {
                    return Some(info);
                }
            }
        }))
        .await?
        .ok()?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn accept_http(listener: &std::net::TcpListener) -> (std::net::TcpStream, String) {
        loop {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut bytes = [0; 2048];
            let mut length = socket.read(&mut bytes).unwrap_or(0);
            if bytes[..length].starts_with(b"HEAD ") || bytes[..length].starts_with(b"GET ") {
                while length < bytes.len()
                    && !bytes[..length].windows(4).any(|part| part == b"\r\n\r\n")
                {
                    let count = socket.read(&mut bytes[length..]).unwrap_or(0);
                    if count == 0 {
                        break;
                    }
                    length += count;
                }
                return (
                    socket,
                    String::from_utf8_lossy(&bytes[..length]).into_owned(),
                );
            }
        }
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    fn response(id: u16) -> Vec<u8> {
        let request = netbios_request(id);
        let mut bytes = vec![0; 12];
        bytes[..2].copy_from_slice(&id.to_be_bytes());
        bytes[2] = 0x84;
        bytes[7] = 1;
        bytes.extend(&request[12..46]);
        bytes.extend([0, 0x21, 0, 1, 0, 0, 0, 0, 0, 93]);
        bytes.push(2);
        bytes.extend(b"SCOUT-PC       \x00\x04\x00");
        bytes.extend(b"WORKGROUP      \x00\x84\x00");
        bytes.extend([0; 56]);
        bytes
    }

    #[test]
    fn netbios_validates_ids_flags_and_truncated_packets() {
        let bytes = response(123);
        assert_eq!(
            parse_netbios(&bytes, 123).unwrap(),
            "SCOUT-PC (workstation, 00); WORKGROUP (group, 00)"
        );
        assert!(parse_netbios(&bytes, 124).is_none());
        for length in 0..bytes.len() {
            assert!(parse_netbios(&bytes[..length], 123).is_none());
        }
        let mut bad = bytes;
        bad[2] = 0;
        assert!(parse_netbios(&bad, 123).is_none());
    }

    #[test]
    fn netbios_queries_a_single_host_and_obeys_cancellation() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut bytes = [0; 512];
            let (length, peer) = socket.recv_from(&mut bytes).unwrap();
            assert_eq!(length, 50);
            let (_, query) = parse_nbss_packet(&bytes[..length]).unwrap();
            assert!(query.header.request());
            assert_eq!(query.questions[0].qtype, netbios_parser::QType::NBSTAT);
            let id = u16::from_be_bytes([bytes[0], bytes[1]]);
            socket.send_to(&response(id), peer).unwrap();
        });
        let rt = runtime();
        assert!(
            rt.block_on(netbios(
                address,
                Duration::from_secs(2),
                &CancellationToken::new()
            ))
            .unwrap()
            .contains("SCOUT-PC")
        );
        server.join().unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        assert!(
            rt.block_on(netbios(address, Duration::from_secs(2), &cancel))
                .is_none()
        );
    }

    #[test]
    fn web_candidates_reuse_scan_results_and_preserve_open_custom_ports() {
        assert!(web_ports(&[80, 443, 8000, 8080, 8443, 8888], &[]).is_empty());
        assert_eq!(
            web_ports(&[80, 443, 8000, 8080, 8443, 8888], &[8080, 12345, 9100]),
            vec![8080, 12345]
        );
        assert_eq!(
            web_ports(&[80, 443, 8080], &[443]),
            vec![443, 8000, 8443, 8888]
        );
        assert_eq!(
            web_ports(&[], &(10000..10100).collect::<Vec<_>>()).len(),
            32
        );
    }

    #[test]
    fn web_detection_reads_headers_without_following_redirects() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, request) = accept_http(&listener);
            assert!(request.starts_with("HEAD / HTTP/1.1"));
            socket.write_all(b"HTTP/1.1 302 Found\r\nServer: nginx/1.26\r\nLocation: http://127.0.0.1:1/private\r\nContent-Length: 99999999\r\n\r\n").unwrap();
        });
        let rt = runtime();
        let prober = WebProber::new(Duration::from_millis(300), false).unwrap();
        let result = rt
            .block_on(prober.probe_port(Ipv4Addr::LOCALHOST, port))
            .unwrap();
        assert_eq!(result.server, "nginx/1.26");
        assert_eq!(result.status, 302);
        assert!(!result.tls_unverified);
        assert_eq!(result.url, format!("http://127.0.0.1:{port}/"));
        server.join().unwrap();
    }

    #[test]
    fn web_detection_falls_back_to_get_when_head_is_unsupported() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            for (method, reply) in [
                (
                    "HEAD",
                    "HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                ),
                (
                    "GET",
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 99999999\r\n\r\n",
                ),
            ] {
                let (mut socket, request) = accept_http(&listener);
                assert!(request.starts_with(method));
                socket.write_all(reply.as_bytes()).unwrap();
            }
        });
        let prober = WebProber::new(Duration::from_millis(500), false).unwrap();
        let result = runtime()
            .block_on(prober.probe_port(Ipv4Addr::LOCALHOST, port))
            .unwrap();
        assert_eq!(result.server, "");
        assert_eq!(result.status, 200);
        server.join().unwrap();
    }

    #[test]
    fn netbios_ignores_unrelated_replies_and_has_an_overall_deadline() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let mut bytes = [0; 512];
            let (_, peer) = socket.recv_from(&mut bytes).unwrap();
            let id = u16::from_be_bytes([bytes[0], bytes[1]]);
            socket.send_to(&response(id.wrapping_add(1)), peer).unwrap();
            // Keep the socket alive so the query ends by timeout, not ICMP refusal.
            std::thread::sleep(Duration::from_millis(200));
        });
        let start = std::time::Instant::now();
        assert!(
            runtime()
                .block_on(netbios(
                    address,
                    Duration::from_millis(50),
                    &CancellationToken::new()
                ))
                .is_none()
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        server.join().unwrap();
    }

    #[test]
    fn waiting_web_requests_obey_deadlines_and_stop_promptly() {
        let prober = WebProber::new(Duration::from_secs(10), false).unwrap();
        let rt = runtime();
        rt.block_on(async {
            let all_slots = prober.slots.acquire_many(32).await.unwrap();
            let timeout = Duration::from_millis(25);
            let cancel = CancellationToken::new();
            let start = std::time::Instant::now();
            assert!(
                prober
                    .probe(Ipv4Addr::LOCALHOST, &[12345], timeout, &cancel)
                    .await
                    .is_empty()
            );
            assert!(start.elapsed() < Duration::from_secs(1));
            assert!(
                prober
                    .probe_endpoint(Ipv4Addr::LOCALHOST, 12345, timeout, &cancel)
                    .await
                    .is_empty()
            );
            let stop = async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                cancel.cancel();
            };
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                futures_util::future::join(
                    prober.probe(
                        Ipv4Addr::LOCALHOST,
                        &[12345],
                        Duration::from_secs(10),
                        &cancel,
                    ),
                    stop,
                ),
            )
            .await
            .unwrap()
            .0;
            assert!(result.is_empty());
            assert!(
                prober
                    .probe_endpoint(Ipv4Addr::LOCALHOST, 12345, Duration::from_secs(10), &cancel,)
                    .await
                    .is_empty()
            );
            drop(all_slots);
            assert_eq!(prober.slots.available_permits(), 32);
        });
    }

    #[test]
    fn focused_web_probe_retains_http_when_tls_reaches_the_deadline() {
        runtime().block_on(async {
            use tokio::io::AsyncWriteExt;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let mut tasks = Vec::new();
                for _ in 0..2 {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    tasks.push(tokio::spawn(async move {
                        let mut prefix = [0u8; 1];
                        socket.peek(&mut prefix).await.unwrap();
                        if prefix[0] == 0x16 {
                            tokio::time::sleep(Duration::from_millis(250)).await;
                        } else {
                            let mut request = Vec::new();
                            while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                                let mut bytes = [0u8; 2048];
                                let count = tokio::io::AsyncReadExt::read(&mut socket, &mut bytes).await.unwrap();
                                assert!(count > 0 && request.len() < 8192);
                                request.extend_from_slice(&bytes[..count]);
                            }
                            assert!(request.starts_with(b"HEAD / HTTP/1.1"));
                            socket.write_all(b"HTTP/1.1 200 OK\r\nServer: focused-test\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
                        }
                    }));
                }
                for task in tasks { task.await.unwrap(); }
            });
            let prober = WebProber::new(Duration::from_secs(2), false).unwrap();
            let services = prober.probe_endpoint(Ipv4Addr::LOCALHOST, port, Duration::from_millis(150), &CancellationToken::new()).await;
            assert_eq!(services.len(), 1);
            assert_eq!(services[0].server, "focused-test");
            assert!(services[0].url.starts_with("http://"));
            server.await.unwrap();
        });
    }

    #[test]
    fn same_port_is_checked_for_both_http_and_https_and_titles_are_parsed() {
        runtime().block_on(async {
            use std::sync::Arc;
            use tokio_rustls::{rustls, TlsAcceptor};
            use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
            async fn respond(mut socket: impl AsyncRead + AsyncWrite + Unpin, title: &str) {
                let mut request = Vec::new();
                while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                    let mut bytes = [0u8; 2048];
                    let count = socket.read(&mut bytes).await.unwrap();
                    assert!(count > 0 && request.len() < 8192);
                    request.extend_from_slice(&bytes[..count]);
                }
                assert!(request.starts_with(b"GET / HTTP/1.1"));
                let body = format!("<html><head><title>{title} &amp; console</title></head><body><script>ignored()</script></body></html>");
                let response = format!("HTTP/1.1 200 OK\r\nServer: inventory-test\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
                socket.write_all(response.as_bytes()).await.unwrap();
                socket.shutdown().await.unwrap();
            }
            let generated = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider())).with_safe_default_protocol_versions().unwrap().with_no_client_auth()
                .with_single_cert(vec![generated.cert.der().clone()], rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der()).into()).unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let mut tasks = Vec::new();
                for _ in 0..2 {
                    let (socket, _) = listener.accept().await.unwrap();
                    let config = config.clone();
                    tasks.push(tokio::spawn(async move {
                        let mut prefix = [0u8; 1];
                        socket.peek(&mut prefix).await.unwrap();
                        if prefix[0] == 0x16 {
                            respond(TlsAcceptor::from(Arc::new(config)).accept(socket).await.unwrap(), "Secure NAS").await;
                        } else { respond(socket, "NAS").await; }
                    }));
                }
                for task in tasks { task.await.unwrap(); }
            });
            let prober = WebProber::new_with_titles(Duration::from_secs(2), true, true).unwrap();
            let services = tokio::time::timeout(Duration::from_secs(3), prober.probe_schemes(Ipv4Addr::LOCALHOST, port)).await.unwrap();
            assert_eq!(services.len(), 2);
            assert!(services.iter().any(|service| service.url.starts_with("http://") && service.title == "NAS & console" && !service.tls_unverified));
            assert!(services.iter().any(|service| service.url.starts_with("https://") && service.title == "Secure NAS & console" && service.tls_unverified));
            server.await.unwrap();
        });
    }

    #[test]
    fn html_title_download_is_bounded_and_does_not_follow_links() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, request) = accept_http(&listener);
            assert!(request.starts_with("GET / HTTP/1.1"));
            let body = format!(
                "<title>Printer &amp; scanner</title><a href='/admin'>admin</a>{}",
                "x".repeat(32 * 1024)
            );
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = socket.write_all(headers.as_bytes());
            let _ = socket.write_all(body.as_bytes());
        });
        let prober = WebProber::new_with_titles(Duration::from_secs(1), false, true).unwrap();
        let service = runtime()
            .block_on(prober.probe_scheme(Ipv4Addr::LOCALHOST, port, "http"))
            .unwrap();
        assert_eq!(service.title, "Printer & scanner");
        server.join().unwrap();
    }
}
