//! Bounded identification using greetings and conventional, read-only probes.
//! Protocol recognition is separate from the server's unverified product claims.
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    time::{Instant, timeout_at},
};
use tokio_util::sync::CancellationToken;

const MAX_ENDPOINTS: usize = 16;
const MAX_RESPONSE: usize = 4096;
const MAX_SMB_RESPONSE: usize = 16384;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceIdentification {
    pub port: u16,
    pub protocol: String,
    /// Server supplied text, never a verified vendor, version, or operating system.
    pub product: String,
    pub evidence: String,
}

impl ServiceIdentification {
    pub fn summary(&self) -> String {
        let identity = if self.product.is_empty() {
            format!("{}: {}", self.port, self.protocol)
        } else {
            format!(
                "{}: {} ({}, unverified claim)",
                self.port, self.protocol, self.product
            )
        };
        if self.evidence.is_empty() {
            identity
        } else {
            format!("{identity} — {}", self.evidence)
        }
    }
}

pub struct ServiceProber {
    slots: Semaphore,
}

impl Default for ServiceProber {
    fn default() -> Self {
        Self {
            slots: Semaphore::new(32),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeKind {
    Greeting,
    Rtsp,
    Redis,
    Smb,
}

fn probe_kind(port: u16) -> Option<ProbeKind> {
    match port {
        21 | 22 | 25 | 110 | 143 | 587 | 5900..=5905 => Some(ProbeKind::Greeting),
        445 => Some(ProbeKind::Smb),
        554 => Some(ProbeKind::Rtsp),
        6379 => Some(ProbeKind::Redis),
        // In particular: no commands or generic payloads to printer port 9100.
        _ => None,
    }
}

impl ServiceProber {
    pub async fn probe(
        &self,
        ip: Ipv4Addr,
        open: &[u16],
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Vec<ServiceIdentification> {
        let mut ports = Vec::new();
        for &port in open {
            if probe_kind(port).is_some() && !ports.contains(&port) {
                ports.push(port);
                if ports.len() == MAX_ENDPOINTS {
                    break;
                }
            }
        }
        self.probe_endpoints(
            ports
                .into_iter()
                .map(|port| (SocketAddr::from((ip, port)), port)),
            timeout,
            cancel,
        )
        .await
    }

    async fn probe_endpoints(
        &self,
        endpoints: impl IntoIterator<Item = (SocketAddr, u16)>,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Vec<ServiceIdentification> {
        if cancel.is_cancelled() || timeout.is_zero() {
            return Vec::new();
        }
        let deadline = Instant::now() + timeout.saturating_mul(4);
        let work = stream::iter(endpoints)
            .map(|(address, port)| async move {
                let end = (Instant::now() + timeout).min(deadline);
                timeout_at(end, async {
                    let _permit = self.slots.acquire().await.ok()?;
                    let kind = probe_kind(port)?;
                    probe_endpoint(address, port, kind).await
                })
                .await
                .ok()
                .flatten()
            })
            .buffer_unordered(4);
        tokio::pin!(work);
        let mut records = Vec::new();
        loop {
            tokio::select! {
                // Consume records already ready when cancellation arrives.
                biased;
                record = work.next() => match record {
                    Some(Some(record)) => records.push(record),
                    Some(None) => {},
                    None => break,
                },
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep_until(deadline) => break,
            }
        }
        records.sort_by_key(|record| record.port);
        records
    }
}

async fn probe_endpoint(
    address: SocketAddr,
    port: u16,
    kind: ProbeKind,
) -> Option<ServiceIdentification> {
    let mut socket = TcpStream::connect(address).await.ok()?;
    match kind {
        ProbeKind::Greeting => {
            let bytes = read_text(&mut socket, false).await?;
            identify_greeting(port, &bytes)
        }
        ProbeKind::Rtsp => {
            // RFC 2326 sections 9.1 and 10.1; OPTIONS does not establish a session.
            socket
                .write_all(b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: IP-Scout\r\n\r\n")
                .await
                .ok()?;
            identify_rtsp(port, &read_text(&mut socket, true).await?)
        }
        ProbeKind::Redis => {
            // Redis RESP array containing only PING; no INFO or authentication.
            socket.write_all(b"*1\r\n$4\r\nPING\r\n").await.ok()?;
            identify_redis(port, &read_text(&mut socket, false).await?)
        }
        ProbeKind::Smb => {
            socket.write_all(&smb_negotiate_request()).await.ok()?;
            let mut prefix = [0; 4];
            socket.read_exact(&mut prefix).await.ok()?;
            if prefix[0] != 0 {
                return None;
            }
            let size =
                usize::from(prefix[1]) << 16 | usize::from(prefix[2]) << 8 | usize::from(prefix[3]);
            if !(128..=MAX_SMB_RESPONSE).contains(&size) {
                return None;
            }
            let mut response = vec![0; size];
            socket.read_exact(&mut response).await.ok()?;
            identify_smb(port, &response)
        }
    }
}

async fn read_text(socket: &mut TcpStream, headers: bool) -> Option<Vec<u8>> {
    let mut bytes = Vec::new();
    let mut chunk = [0; 512];
    while bytes.len() < MAX_RESPONSE {
        let limit = chunk.len().min(MAX_RESPONSE - bytes.len());
        let read = socket.read(&mut chunk[..limit]).await.ok()?;
        if read == 0 {
            return None;
        } // An unterminated response is not a greeting.
        bytes.extend_from_slice(&chunk[..read]);
        let complete = if headers {
            bytes.windows(4).any(|part| part == b"\r\n\r\n")
        } else {
            bytes.contains(&b'\n')
        };
        if complete {
            return Some(bytes);
        }
    }
    None
}

fn clean(text: &str) -> String {
    text.chars()
        .filter(|ch| !ch.is_control())
        .take(240)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn record(port: u16, protocol: &str, product: &str, evidence: &str) -> ServiceIdentification {
    ServiceIdentification {
        port,
        protocol: protocol.to_owned(),
        product: clean(product),
        evidence: clean(evidence),
    }
}

/// Recognize a complete protocol greeting, including on a nonstandard port when
/// the caller already collected a banner. This function never opens a socket.
pub fn identify_greeting(port: u16, bytes: &[u8]) -> Option<ServiceIdentification> {
    if bytes.len() > MAX_RESPONSE {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let line = text.split('\n').next()?;
    let line = line.strip_suffix('\r').unwrap_or(line);
    if !text.contains('\n') || line.chars().any(|ch| ch.is_control()) {
        return None;
    }
    if let Some(rest) = line.strip_prefix("SSH-") {
        let (version, software) = rest.split_once('-')?;
        if !matches!(version, "2.0" | "1.99" | "1.5") || software.is_empty() {
            return None;
        }
        return Some(record(
            port,
            "SSH",
            software,
            &format!("SSH {version} identification line; software is an unverified banner claim"),
        ));
    }
    if line.len() == 11
        && line.starts_with("RFB ")
        && line.as_bytes()[7] == b'.'
        && line.as_bytes()[4..7].iter().all(u8::is_ascii_digit)
        && line.as_bytes()[8..11].iter().all(u8::is_ascii_digit)
    {
        return Some(record(
            port,
            "RFB / VNC",
            "",
            &format!("RFB protocol greeting {}", &line[4..]),
        ));
    }
    let lower = line.to_ascii_lowercase();
    if (line.starts_with("220 ") || line.starts_with("220-"))
        && (lower.contains("smtp") || lower.contains("ftp"))
    {
        let protocol = if lower.contains("smtp") {
            "SMTP"
        } else {
            "FTP"
        };
        return Some(record(
            port,
            protocol,
            &line[4..],
            "220 greeting with protocol marker; server identity is an unverified banner claim",
        ));
    }
    if port == 110 && (line == "+OK" || line.starts_with("+OK ")) {
        return Some(record(
            port,
            "POP3",
            line.trim_start_matches("+OK").trim(),
            "POP3 +OK greeting on port 110; server identity is an unverified banner claim",
        ));
    }
    if port == 143
        && (line.starts_with("* OK ") || line.starts_with("* PREAUTH ") || line == "* OK")
    {
        return Some(record(
            port,
            "IMAP",
            line,
            "IMAP untagged greeting on port 143; server identity is an unverified banner claim",
        ));
    }
    None
}

fn identify_rtsp(port: u16, bytes: &[u8]) -> Option<ServiceIdentification> {
    let text = std::str::from_utf8(bytes).ok()?;
    let (headers, _) = text.split_once("\r\n\r\n")?;
    let mut lines = headers.split("\r\n");
    let status = lines.next()?;
    let mut parts = status.splitn(3, ' ');
    if !matches!(parts.next()?, "RTSP/1.0" | "RTSP/2.0") {
        return None;
    }
    let code = parts.next()?;
    if code.len() != 3
        || !code.bytes().all(|b| b.is_ascii_digit())
        || !(100..=599).contains(&code.parse::<u16>().ok()?)
    {
        return None;
    }
    let mut sequence = false;
    let mut server = "";
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case("CSeq") {
            sequence = value.trim() == "1";
        }
        if name.eq_ignore_ascii_case("Server") {
            server = value.trim();
        }
    }
    if !sequence {
        return None;
    }
    Some(record(
        port,
        "RTSP",
        server,
        &format!(
            "OPTIONS response {status}, matching CSeq 1; Server header is an unverified claim"
        ),
    ))
}

fn identify_redis(port: u16, bytes: &[u8]) -> Option<ServiceIdentification> {
    let line = bytes.split_inclusive(|byte| *byte == b'\n').next()?;
    let evidence = if line == b"+PONG\r\n" {
        "RESP +PONG response to PING (Redis-compatible protocol)"
    } else if line.starts_with(b"-NOAUTH ")
        && line.ends_with(b"\r\n")
        && line[8..line.len() - 2]
            .iter()
            .all(|byte| (32..127).contains(byte))
    {
        "RESP NOAUTH response to PING (Redis-compatible protocol; authentication required)"
    } else {
        return None;
    };
    Some(record(port, "Redis / RESP", "", evidence))
}

fn smb_negotiate_request() -> Vec<u8> {
    // MS-SMB2 2.2.1.2 and 2.2.3: SYNC header + NEGOTIATE, then dialects.
    // 3.1.1 is deliberately omitted because it requires negotiate contexts.
    let mut packet = vec![0; 4 + 64 + 36 + 8];
    packet[3] = (packet.len() - 4) as u8;
    let body = &mut packet[4..];
    body[..4].copy_from_slice(b"\xfeSMB");
    body[4..6].copy_from_slice(&64u16.to_le_bytes());
    body[14..16].copy_from_slice(&1u16.to_le_bytes());
    body[64..66].copy_from_slice(&36u16.to_le_bytes());
    body[66..68].copy_from_slice(&4u16.to_le_bytes());
    body[68..70].copy_from_slice(&1u16.to_le_bytes());
    body[76..92].copy_from_slice(uuid::Uuid::new_v4().as_bytes());
    for (index, dialect) in [0x0202u16, 0x0210, 0x0300, 0x0302].into_iter().enumerate() {
        body[100 + index * 2..102 + index * 2].copy_from_slice(&dialect.to_le_bytes());
    }
    packet
}

fn identify_smb(port: u16, bytes: &[u8]) -> Option<ServiceIdentification> {
    // MS-SMB2 2.2.4. Validate the response command, success, correlation and
    // dialect before presenting it. Never parse NTLM tokens or attempt login.
    if bytes.len() < 128 || bytes.len() > MAX_SMB_RESPONSE || &bytes[..4] != b"\xfeSMB" {
        return None;
    }
    let word = |offset| u16::from_le_bytes([bytes[offset], bytes[offset + 1]]);
    if word(4) != 64
        || bytes[8..14] != [0; 6]
        || bytes[24..32] != [0; 8]
        || bytes[16] & 3 != 1
        || bytes[20..24] != [0; 4]
        || word(64) != 65
    {
        return None;
    }
    let dialect = match word(68) {
        0x0202 => "2.0.2",
        0x0210 => "2.1",
        0x0300 => "3.0",
        0x0302 => "3.0.2",
        _ => return None,
    };
    let security_offset = usize::from(word(120));
    let security_length = usize::from(word(122));
    if security_length > 0
        && (security_offset < 128 || security_offset.checked_add(security_length)? > bytes.len())
    {
        return None;
    }
    let signing = if word(66) & 2 != 0 {
        "required"
    } else {
        "not required"
    };
    Some(record(
        port,
        "SMB",
        "",
        &format!("SMB {dialect} negotiated; signing {signing}; no authentication attempted"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn greetings_require_protocol_evidence() {
        assert_eq!(
            identify_greeting(22, b"SSH-2.0-OpenSSH_9.9\r\n")
                .unwrap()
                .product,
            "OpenSSH_9.9"
        );
        assert_eq!(
            identify_greeting(21, b"220 FileZilla FTP server\r\n")
                .unwrap()
                .protocol,
            "FTP"
        );
        assert_eq!(
            identify_greeting(25, b"220 mail.example ESMTP\r\n")
                .unwrap()
                .protocol,
            "SMTP"
        );
        assert!(identify_greeting(21, b"220 Welcome\r\n").is_none());
        assert!(identify_greeting(22, b"OpenSSH on Linux\r\n").is_none());
        assert!(identify_greeting(22, b"SSH-2.0-OpenSSH").is_none());
        assert!(identify_greeting(22, b"SSH-potato-OpenSSH\r\n").is_none());
        assert_eq!(
            identify_greeting(5900, b"RFB 003.008\n").unwrap().protocol,
            "RFB / VNC"
        );
        assert!(identify_greeting(5900, b"RFB bad.bad\n").is_none());
        assert!(identify_greeting(110, b"+OK ready\r\n").is_some());
        assert!(identify_greeting(143, b"* OK [CAPABILITY IMAP4rev1] ready\r\n").is_some());
    }

    #[test]
    fn active_responses_validate_correlation_and_protocol() {
        assert!(
            identify_rtsp(
                554,
                b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nServer: Example\r\n\r\n"
            )
            .is_some()
        );
        assert!(identify_rtsp(554, b"HTTP/1.1 200 OK\r\nCSeq: 1\r\n\r\n").is_none());
        assert!(identify_rtsp(554, b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n").is_none());
        assert!(identify_redis(6379, b"+PONG\r\n").is_some());
        assert!(identify_redis(6379, b"-NOAUTH Authentication required.\r\n").is_some());
        assert!(identify_redis(6379, b"+OK\r\n").is_none());
        assert!(identify_redis(6379, b"-ERR unknown command\r\n").is_none());
        assert!(probe_kind(9100).is_none());
        assert!(probe_kind(12345).is_none());
    }

    fn smb_response() -> Vec<u8> {
        let mut response = vec![0; 128];
        response[..4].copy_from_slice(b"\xfeSMB");
        response[4..6].copy_from_slice(&64u16.to_le_bytes());
        response[16] = 1;
        response[64..66].copy_from_slice(&65u16.to_le_bytes());
        response[66..68].copy_from_slice(&3u16.to_le_bytes());
        response[68..70].copy_from_slice(&0x0302u16.to_le_bytes());
        response
    }

    #[test]
    fn smb_negotiation_checks_bounds_command_and_dialect() {
        let request = smb_negotiate_request();
        assert_eq!(request.len(), 112);
        assert_eq!(&request[104..], &[2, 2, 16, 2, 0, 3, 2, 3]);
        let mut response = smb_response();
        assert!(
            identify_smb(445, &response)
                .unwrap()
                .evidence
                .contains("3.0.2")
        );
        response[12] = 1;
        assert!(identify_smb(445, &response).is_none());
        response[12] = 0;
        response[68] = 0x11;
        assert!(identify_smb(445, &response).is_none());
        response[68] = 2;
        response[122] = 1;
        assert!(identify_smb(445, &response).is_none());
    }

    #[tokio::test]
    async fn fragmented_greeting_is_read_without_sending_data() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"SSH-2.0-").await.unwrap();
            tokio::task::yield_now().await;
            socket.write_all(b"Synthetic_1\r\n").await.unwrap();
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
        });
        let found = ServiceProber::default()
            .probe_endpoints(
                [(address, 22)],
                Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].product, "Synthetic_1");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn redis_sends_only_ping_and_validates_reply() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 14];
            socket.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"*1\r\n$4\r\nPING\r\n");
            socket.write_all(b"+PONG\r\n").await.unwrap();
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
        });
        let found = ServiceProber::default()
            .probe_endpoints(
                [(address, 6379)],
                Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await;
        assert_eq!(found.len(), 1);
        assert!(found[0].product.is_empty());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn rtsp_only_requests_options_and_accepts_authentication_required() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let request = read_text(&mut socket, true).await.unwrap();
            assert_eq!(
                &request,
                b"OPTIONS * RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: IP-Scout\r\n\r\n"
            );
            socket
                .write_all(
                    b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nServer: SyntheticCamera\r\n\r\n",
                )
                .await
                .unwrap();
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
        });
        let found = ServiceProber::default()
            .probe_endpoints(
                [(address, 554)],
                Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await;
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].product, "SyntheticCamera");
        assert!(found[0].summary().contains("unverified claim"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn smb_negotiates_without_session_setup_or_authentication() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 112];
            socket.read_exact(&mut request).await.unwrap();
            assert_eq!(
                &request[..12],
                &[0, 0, 0, 108, 0xfe, b'S', b'M', b'B', 64, 0, 0, 0]
            );
            assert_eq!(&request[16..18], &[0, 0]); // NEGOTIATE command only.
            assert_eq!(&request[44..68], &[0; 24]); // No tree, session, or signature.
            assert_eq!(&request[68..76], &[36, 0, 4, 0, 1, 0, 0, 0]);
            assert_eq!(&request[104..], &[2, 2, 16, 2, 0, 3, 2, 3]);
            let response = smb_response();
            socket.write_all(&[0, 0, 0, 128]).await.unwrap();
            socket.write_all(&response[..64]).await.unwrap();
            tokio::task::yield_now().await;
            socket.write_all(&response[64..]).await.unwrap();
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
        });
        let found = ServiceProber::default()
            .probe_endpoints(
                [(address, 445)],
                Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await;
        assert_eq!(found.len(), 1);
        assert!(found[0].evidence.contains("signing required"));
        assert!(found[0].product.is_empty());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn oversized_smb_frame_is_rejected_without_allocation_or_more_commands() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 112];
            socket.read_exact(&mut request).await.unwrap();
            socket.write_all(&[0, 255, 255, 255]).await.unwrap();
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
        });
        let found = ServiceProber::default()
            .probe_endpoints(
                [(address, 445)],
                Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await;
        assert!(found.is_empty());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn precancelled_probe_does_not_connect() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let found = ServiceProber::default()
            .probe_endpoints(
                [(listener.local_addr().unwrap(), 22)],
                Duration::from_secs(1),
                &cancel,
            )
            .await;
        assert!(found.is_empty());
        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn cancellation_keeps_completed_records() {
        let fast = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let slow = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addresses = [
            (fast.local_addr().unwrap(), 22),
            (slow.local_addr().unwrap(), 21),
        ];
        let cancel = CancellationToken::new();
        let trigger = cancel.clone();
        let server = tokio::spawn(async move {
            let (mut socket, _) = fast.accept().await.unwrap();
            socket.write_all(b"SSH-2.0-Synthetic\r\n").await.unwrap();
            let mut byte = [0];
            assert_eq!(socket.read(&mut byte).await.unwrap(), 0);
            // Closed greeting connection proves its record was completed.
            trigger.cancel();
        });
        let found = ServiceProber::default()
            .probe_endpoints(addresses, Duration::from_secs(1), &cancel)
            .await;
        assert_eq!(found.len(), 1);
        server.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn semaphore_wait_is_included_in_endpoint_timeout() {
        let prober = ServiceProber {
            slots: Semaphore::new(0),
        };
        let start = Instant::now();
        let found = prober
            .probe_endpoints(
                [(SocketAddr::from((Ipv4Addr::LOCALHOST, 1)), 22)],
                Duration::from_secs(1),
                &CancellationToken::new(),
            )
            .await;
        assert!(found.is_empty());
        assert_eq!(start.elapsed(), Duration::from_secs(1));
    }
}
