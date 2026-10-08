use futures_util::{StreamExt, stream};
use hickory_proto::{
    op::{Message, MessageType, OpCode, Query},
    rr::{Name, RData, RecordType},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    net::{Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

pub const COMMON_PORTS: &str = "53,123,161";
pub const MAX_UDP_CONNECTIONS: usize = 128;
const PORTS_PER_HOST: usize = 8;
const MAX_DATAGRAM: usize = 16_384;

#[derive(Clone, Default)]
pub struct Options {
    pub ports: Vec<u16>,
    pub dns: bool,
    pub ntp: bool,
    pub snmp: bool,
    pub community: String,
}

impl fmt::Debug for Options {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UdpOptions")
            .field("ports", &self.ports)
            .field("dns", &self.dns)
            .field("ntp", &self.ntp)
            .field("snmp", &self.snmp)
            .field("community", &"[redacted]")
            .finish()
    }
}

impl Options {
    pub fn enabled(&self) -> bool {
        !self.ports.is_empty() || self.dns || self.ntp || self.snmp
    }
    fn candidates(&self) -> Vec<u16> {
        let mut ports = self.ports.clone();
        if self.dns {
            ports.push(53);
        }
        if self.ntp {
            ports.push(123);
        }
        if self.snmp && !self.community.is_empty() {
            ports.push(161);
        }
        ports.retain(|port| *port != 0);
        ports.sort_unstable();
        ports.dedup();
        ports
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UdpResult {
    pub open_ports: Vec<u16>,
    pub requested: usize,
    pub completed: usize,
    pub closed: usize,
    pub open_or_filtered: usize,
    pub errors: usize,
    pub dns: String,
    pub ntp: String,
    pub snmp: String,
}

impl UdpResult {
    pub fn summary(&self) -> String {
        if self.requested == 0 {
            return String::new();
        }
        format!(
            "{}/{} checked | open {} | closed {} | open or filtered {} | errors {}{}",
            self.completed,
            self.requested,
            self.open_ports.len(),
            self.closed,
            self.open_or_filtered,
            self.errors,
            if self.completed < self.requested {
                " [incomplete]"
            } else {
                ""
            }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum State {
    Open,
    Closed,
    OpenOrFiltered,
    Error,
}

struct Outcome {
    state: State,
    info: String,
}
impl Outcome {
    fn new(state: State) -> Self {
        Self {
            state,
            info: String::new(),
        }
    }
    fn open(info: String) -> Self {
        Self {
            state: State::Open,
            info,
        }
    }
}

pub struct UdpProber {
    slots: tokio::sync::Semaphore,
}
impl Default for UdpProber {
    fn default() -> Self {
        Self {
            slots: tokio::sync::Semaphore::new(MAX_UDP_CONNECTIONS),
        }
    }
}

impl UdpProber {
    pub async fn scan(
        &self,
        ip: Ipv4Addr,
        options: &Options,
        timeout: Duration,
        retry: bool,
        cancel: &CancellationToken,
        progress: impl Fn(&UdpResult),
    ) -> UdpResult {
        let ports = options.candidates();
        let mut result = UdpResult {
            requested: ports.len(),
            ..Default::default()
        };
        if options.snmp && options.community.is_empty() {
            result.snmp = "Not queried (SNMPv2c community not set)".into();
        }
        let mut last_update = Instant::now();
        let work = async {
            let mut pending = stream::iter(ports)
                .map(|port| async move {
                    let _slot = self.slots.acquire().await.ok()?;
                    let address = SocketAddr::from((ip, port));
                    let kind = match port {
                        53 => Kind::Dns,
                        123 => Kind::Ntp,
                        161 if !options.community.is_empty() => Kind::Snmp,
                        _ => Kind::Generic,
                    };
                    let mut outcome = self.attempt(address, kind, options, timeout).await;
                    if retry && outcome.state == State::OpenOrFiltered && !cancel.is_cancelled() {
                        outcome = self.attempt(address, kind, options, timeout).await;
                    }
                    Some((port, outcome))
                })
                .buffer_unordered(PORTS_PER_HOST);
            while let Some(completed) = pending.next().await {
                let Some((port, outcome)) = completed else {
                    continue;
                };
                let first_response = result.open_ports.is_empty() && outcome.state == State::Open;
                result.completed += 1;
                match outcome.state {
                    State::Open => result.open_ports.push(port),
                    State::Closed => result.closed += 1,
                    State::OpenOrFiltered => result.open_or_filtered += 1,
                    State::Error => result.errors += 1,
                }
                if !outcome.info.is_empty() {
                    match port {
                        53 => result.dns = outcome.info,
                        123 => result.ntp = outcome.info,
                        161 => result.snmp = outcome.info,
                        _ => {}
                    }
                }
                if first_response || last_update.elapsed() >= Duration::from_millis(250) {
                    result.open_ports.sort_unstable();
                    progress(&result);
                    last_update = Instant::now();
                }
            }
        };
        let _ = cancel.run_until_cancelled(work).await;
        result.open_ports.sort_unstable();
        progress(&result);
        result
    }

    async fn attempt(
        &self,
        address: SocketAddr,
        kind: Kind,
        options: &Options,
        timeout: Duration,
    ) -> Outcome {
        tokio::time::timeout(timeout, async {
            match kind {
                Kind::Dns => dns(address).await,
                Kind::Ntp => ntp(address).await,
                Kind::Snmp => snmp(address, &options.community).await,
                Kind::Generic => datagram(address, &[]).await.map_or_else(
                    |error| Outcome::new(io_state(&error)),
                    |_| Outcome::new(State::Open),
                ),
            }
        })
        .await
        .unwrap_or_else(|_| Outcome::new(State::OpenOrFiltered))
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Generic,
    Dns,
    Ntp,
    Snmp,
}

fn io_state(error: &std::io::Error) -> State {
    if error.kind() == std::io::ErrorKind::ConnectionRefused
        || cfg!(windows) && error.raw_os_error() == Some(10054)
    {
        State::Closed
    } else if matches!(
        error.kind(),
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
    ) {
        State::OpenOrFiltered
    } else {
        State::Error
    }
}

async fn connected(address: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    socket.connect(address).await?;
    Ok(socket)
}

async fn datagram(address: SocketAddr, request: &[u8]) -> std::io::Result<Vec<u8>> {
    let socket = connected(address).await?;
    socket.send(request).await?;
    let mut bytes = vec![0; MAX_DATAGRAM + 1];
    let count = socket.recv(&mut bytes).await?;
    bytes.truncate(count);
    Ok(bytes)
}

async fn dns(address: SocketAddr) -> Outcome {
    let id = u16::from_be_bytes(uuid::Uuid::new_v4().as_bytes()[..2].try_into().unwrap());
    let query = Query::query(Name::root(), RecordType::SOA);
    let mut request = Message::new();
    request
        .set_id(id)
        .set_recursion_desired(false)
        .add_query(query.clone());
    let Ok(packet) = request.to_vec() else {
        return Outcome::new(State::Error);
    };
    match datagram(address, &packet).await {
        Ok(bytes) => Outcome::open(dns_info(&bytes, id, &query).unwrap_or_default()),
        Err(error) => Outcome::new(io_state(&error)),
    }
}

fn dns_info(bytes: &[u8], id: u16, query: &Query) -> Option<String> {
    if bytes.len() > MAX_DATAGRAM {
        return None;
    }
    let response = Message::from_vec(bytes).ok()?;
    if response.id() != id
        || response.message_type() != MessageType::Response
        || response.op_code() != OpCode::Query
        || response.queries() != [query.clone()]
    {
        return None;
    }
    let mut info = format!(
        "53/udp: {} | recursion advertised: {} | authoritative: {}{}",
        response.response_code(),
        response.recursion_available(),
        response.authoritative(),
        if response.truncated() {
            " | truncated response"
        } else {
            ""
        }
    );
    if let Some(soa) = response
        .answers()
        .iter()
        .chain(response.name_servers())
        .find_map(|record| match record.data() {
            Some(RData::SOA(soa)) => Some(soa),
            _ => None,
        })
    {
        info.push_str(&format!(" | SOA: {}", clean(&soa.mname().to_utf8(), 256)));
    }
    Some(info)
}

async fn ntp(address: SocketAddr) -> Outcome {
    let socket = match connected(address).await {
        Ok(socket) => sntpc_net_tokio::UdpSocketWrapper::from(socket),
        Err(error) => return Outcome::new(io_state(&error)),
    };
    match sntpc::get_time(
        address,
        &socket,
        sntpc::NtpContext::new(sntpc::StdTimestampGen::default()),
    )
    .await
    {
        Ok(time) => Outcome::open(format!(
            "123/udp: stratum {} | Unix time {} | offset {:.3} ms | RTT {:.3} ms | reference {}",
            time.stratum,
            time.seconds,
            time.offset as f64 / 1000.0,
            time.roundtrip as f64 / 1000.0,
            clean(&format!("{:?}", time.reference_id), 64)
        )),
        Err(sntpc::Error::KissOfDeath(code)) => Outcome::open(format!(
            "123/udp: server declined request ({code:?}); no retry"
        )),
        // The adapter intentionally hides OS error details. Do not infer a closed port.
        Err(_) => Outcome::new(State::OpenOrFiltered),
    }
}

const SYSTEM_OIDS: [&[u64]; 4] = [
    &[1, 3, 6, 1, 2, 1, 1, 1, 0],
    &[1, 3, 6, 1, 2, 1, 1, 2, 0],
    &[1, 3, 6, 1, 2, 1, 1, 3, 0],
    &[1, 3, 6, 1, 2, 1, 1, 5, 0],
];

async fn snmp(address: SocketAddr, community: &str) -> Outcome {
    if community.is_empty() || community.len() > 255 {
        return Outcome::new(State::Error);
    }
    let id =
        i32::from_be_bytes(*uuid::Uuid::new_v4().as_bytes().first_chunk::<4>().unwrap()) & i32::MAX;
    let mut session = match snmp2::AsyncSession::new_v2c(address, community.as_bytes(), id).await {
        Ok(session) => session,
        Err(error) => return Outcome::new(io_state(&error)),
    };
    let oids: Vec<_> = SYSTEM_OIDS
        .iter()
        .map(|oid| snmp2::Oid::from(oid).unwrap())
        .collect();
    match session.get_many(&oids.iter().collect::<Vec<_>>()).await {
        Ok(response) => {
            if response.version() != Ok(snmp2::Version::V2C) {
                return Outcome::new(State::OpenOrFiltered);
            }
            if response.error_status != 0 {
                return Outcome::open(format!("161/udp: SNMPv2c error {}", response.error_status));
            }
            let mut parts = Vec::new();
            for (oid, value) in response.varbinds.take(16) {
                if let Some(index) = oids.iter().position(|expected| *expected == oid) {
                    let text = match (index, value) {
                        (0 | 3, snmp2::Value::OctetString(bytes)) => {
                            clean(&String::from_utf8_lossy(bytes), 256)
                        }
                        (1, snmp2::Value::ObjectIdentifier(oid)) => oid.to_string(),
                        (2, snmp2::Value::Timeticks(ticks)) => {
                            format!("{}.{:02} s", ticks / 100, ticks % 100)
                        }
                        _ => continue,
                    };
                    parts.push(format!(
                        "{}: {text}",
                        ["description", "object ID", "uptime", "name"][index]
                    ));
                }
            }
            Outcome::open(format!("161/udp: SNMPv2c | {}", parts.join(" | ")))
        }
        Err(_) => Outcome::new(State::OpenOrFiltered),
    }
}

fn clean(text: &str, limit: usize) -> String {
    text.chars()
        .filter(|character| !character.is_control())
        .take(limit)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tokio::net::UdpSocket;

    async fn listener() -> UdpSocket {
        UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap()
    }

    #[test]
    fn selections_are_optional_unique_and_not_limited_to_1024() {
        assert!(!Options::default().enabled());
        let mut options = Options {
            ports: (0..=u16::MAX).collect(),
            dns: true,
            ntp: true,
            snmp: true,
            community: "private-test-community".into(),
        };
        assert_eq!(options.candidates(), (1..=u16::MAX).collect::<Vec<_>>());
        assert!(!format!("{options:?}").contains("private-test-community"));
        options.ports.clear();
        options.community.clear();
        assert_eq!(options.candidates(), vec![53, 123]);
        assert_eq!(clean("a\nb\0c", 2), "ab");
    }

    #[test]
    fn socket_errors_do_not_turn_silence_into_closed() {
        use std::io::{Error, ErrorKind};
        assert_eq!(
            io_state(&Error::from(ErrorKind::ConnectionRefused)),
            State::Closed
        );
        assert_eq!(
            io_state(&Error::from(ErrorKind::TimedOut)),
            State::OpenOrFiltered
        );
        assert_eq!(
            io_state(&Error::from(ErrorKind::PermissionDenied)),
            State::Error
        );
        #[cfg(windows)]
        assert_eq!(io_state(&Error::from_raw_os_error(10054)), State::Closed);
    }

    #[tokio::test]
    async fn generic_response_is_published_immediately_and_silence_is_inconclusive() {
        let echo = listener().await;
        let silent = listener().await;
        let port = echo.local_addr().unwrap().port();
        let server = async {
            let mut request = [0; 100];
            let (size, peer) = echo.recv_from(&mut request).await.unwrap();
            assert_eq!(size, 0);
            echo.send_to(&[], peer).await.unwrap();
        };
        let prober = UdpProber::default();
        let cancel = CancellationToken::new();
        let options = Options {
            ports: vec![port, silent.local_addr().unwrap().port()],
            ..Default::default()
        };
        let updates = Mutex::new(Vec::new());
        let (result, ()) = tokio::join!(
            prober.scan(
                Ipv4Addr::LOCALHOST,
                &options,
                Duration::from_millis(100),
                false,
                &cancel,
                |result| updates.lock().unwrap().push(result.clone())
            ),
            server
        );
        assert_eq!(result.open_ports, vec![port]);
        assert_eq!(
            (result.completed, result.open_or_filtered, result.closed),
            (2, 1, 0)
        );
        assert_eq!(updates.lock().unwrap()[0].completed, 1);
        assert!(!result.summary().contains("incomplete"));
        assert_eq!(prober.slots.available_permits(), MAX_UDP_CONNECTIONS);
    }

    #[tokio::test]
    async fn unrelated_sender_cannot_confirm_a_port() {
        let silent = listener().await;
        let forger = listener().await;
        let prober = UdpProber::default();
        let server = async {
            let mut packet = [0; 1];
            let (_, peer) = silent.recv_from(&mut packet).await.unwrap();
            forger.send_to(b"wrong source", peer).await.unwrap();
        };
        let options = Options::default();
        let (outcome, ()) = tokio::join!(
            prober.attempt(
                silent.local_addr().unwrap(),
                Kind::Generic,
                &options,
                Duration::from_millis(60)
            ),
            server
        );
        assert_eq!(outcome.state, State::OpenOrFiltered);
    }

    #[tokio::test]
    async fn deep_retries_silence_once_and_fast_does_not() {
        for (retry, expected) in [(false, 1), (true, 2)] {
            let socket = listener().await;
            let options = Options {
                ports: vec![socket.local_addr().unwrap().port()],
                ..Default::default()
            };
            let result = UdpProber::default()
                .scan(
                    Ipv4Addr::LOCALHOST,
                    &options,
                    Duration::from_millis(30),
                    retry,
                    &CancellationToken::new(),
                    |_| {},
                )
                .await;
            assert_eq!(result.open_or_filtered, 1);
            let mut count = 0;
            while socket.try_recv(&mut [0; 1]).is_ok() {
                count += 1;
            }
            assert_eq!(count, expected);
        }
    }

    #[tokio::test]
    async fn cancellation_retains_results_and_releases_queued_permits() {
        let echo = listener().await;
        let silent = listener().await;
        let port = echo.local_addr().unwrap().port();
        let cancel = CancellationToken::new();
        let options = Options {
            ports: vec![port, silent.local_addr().unwrap().port()],
            ..Default::default()
        };
        let prober = UdpProber::default();
        let server = async {
            let (_, peer) = echo.recv_from(&mut [0; 1]).await.unwrap();
            echo.send_to(b"alive", peer).await.unwrap();
        };
        let (result, ()) = tokio::join!(
            prober.scan(
                Ipv4Addr::LOCALHOST,
                &options,
                Duration::from_secs(30),
                true,
                &cancel,
                |result| {
                    if !result.open_ports.is_empty() {
                        cancel.cancel();
                    }
                }
            ),
            server
        );
        assert_eq!(result.open_ports, vec![port]);
        assert_eq!(result.completed, 1);
        assert!(result.summary().contains("incomplete"));
        assert_eq!(prober.slots.available_permits(), MAX_UDP_CONNECTIONS);
        let guard = prober
            .slots
            .acquire_many(MAX_UDP_CONNECTIONS as u32)
            .await
            .unwrap();
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let result = prober
            .scan(
                Ipv4Addr::LOCALHOST,
                &options,
                Duration::from_secs(30),
                true,
                &cancelled,
                |_| {},
            )
            .await;
        assert_eq!(result.completed, 0);
        drop(guard);
        assert_eq!(prober.slots.available_permits(), MAX_UDP_CONNECTIONS);
    }

    #[tokio::test]
    async fn dns_uses_read_only_nonrecursive_query_and_validates_identity() {
        let socket = listener().await;
        let server = async {
            let mut bytes = [0; 512];
            let (size, peer) = socket.recv_from(&mut bytes).await.unwrap();
            let mut message = Message::from_vec(&bytes[..size]).unwrap();
            assert!(!message.recursion_desired());
            assert_eq!(
                message.queries(),
                &[Query::query(Name::root(), RecordType::SOA)]
            );
            message
                .set_message_type(MessageType::Response)
                .set_response_code(hickory_proto::op::ResponseCode::Refused)
                .set_recursion_available(true);
            socket
                .send_to(&message.to_vec().unwrap(), peer)
                .await
                .unwrap();
        };
        let prober = UdpProber::default();
        let options = Options::default();
        let (outcome, ()) = tokio::join!(
            prober.attempt(
                socket.local_addr().unwrap(),
                Kind::Dns,
                &options,
                Duration::from_secs(1)
            ),
            server
        );
        assert_eq!(outcome.state, State::Open);
        assert!(outcome.info.contains("recursion advertised: true"));
        let query = Query::query(Name::root(), RecordType::SOA);
        let mut response = Message::new();
        response
            .set_id(7)
            .set_message_type(MessageType::Response)
            .add_query(query.clone());
        assert!(dns_info(&response.to_vec().unwrap(), 7, &query).is_some());
        assert!(dns_info(&response.to_vec().unwrap(), 8, &query).is_none());
        assert!(
            dns_info(
                &response.to_vec().unwrap(),
                7,
                &Query::query(Name::root(), RecordType::A)
            )
            .is_none()
        );
        assert!(dns_info(&vec![0; MAX_DATAGRAM + 1], 7, &query).is_none());
        assert!(dns_info(&[0; 4], 7, &query).is_none());
    }

    #[tokio::test]
    async fn ntp_validates_origin_and_handles_rate_limit_without_retry() {
        for variant in 0..3 {
            let socket = listener().await;
            let server = async {
                let mut request = [0; 100];
                let (size, peer) = socket.recv_from(&mut request).await.unwrap();
                assert_eq!(size, 48);
                assert_eq!(request[0] & 7, 3);
                let mut response = [0; 48];
                response[0] = 0x24;
                response[1] = 2;
                response[3] = (-20i8) as u8;
                response[24..32].copy_from_slice(&request[40..48]);
                response[32..40].copy_from_slice(&request[40..48]);
                response[40..48].copy_from_slice(&request[40..48]);
                if variant == 1 {
                    response[1] = 0;
                    response[12..16].copy_from_slice(b"RATE");
                }
                if variant == 2 {
                    response[24] ^= 1;
                }
                socket.send_to(&response, peer).await.unwrap();
            };
            let prober = UdpProber::default();
            let options = Options::default();
            let (outcome, ()) = tokio::join!(
                prober.attempt(
                    socket.local_addr().unwrap(),
                    Kind::Ntp,
                    &options,
                    Duration::from_secs(1)
                ),
                server
            );
            match variant {
                0 => {
                    assert_eq!(outcome.state, State::Open);
                    assert!(outcome.info.contains("stratum 2"));
                }
                1 => {
                    assert_eq!(outcome.state, State::Open);
                    assert!(outcome.info.contains("no retry"));
                }
                _ => {
                    assert_eq!(outcome.state, State::OpenOrFiltered);
                    assert!(outcome.info.is_empty());
                }
            }
        }
    }

    // BER fixtures only: production requests and responses use snmp2.
    fn tlv(tag: u8, bytes: &[u8]) -> Vec<u8> {
        let mut value = vec![tag];
        if bytes.len() < 128 {
            value.push(bytes.len() as u8);
        } else {
            value.extend([0x82, (bytes.len() >> 8) as u8, bytes.len() as u8]);
        }
        value.extend_from_slice(bytes);
        value
    }

    #[tokio::test]
    async fn snmp_only_gets_system_oids_and_rejects_unrelated_responses() {
        for variant in 0..3 {
            let socket = listener().await;
            let options = Options {
                community: "explicit-test-community".into(),
                ..Default::default()
            };
            let server = async {
                let mut bytes = [0; 2048];
                let (size, peer) = socket.recv_from(&mut bytes).await.unwrap();
                let mut pdu = snmp2::Pdu::from_bytes(&bytes[..size]).unwrap();
                assert_eq!(pdu.message_type, snmp2::MessageType::GetRequest);
                assert_eq!(pdu.version().unwrap(), snmp2::Version::V2C);
                assert_eq!(pdu.community, options.community.as_bytes());
                assert_eq!(
                    pdu.varbinds
                        .clone()
                        .map(|(oid, _)| oid.to_string())
                        .collect::<Vec<_>>(),
                    vec![
                        "1.3.6.1.2.1.1.1.0",
                        "1.3.6.1.2.1.1.2.0",
                        "1.3.6.1.2.1.1.3.0",
                        "1.3.6.1.2.1.1.5.0"
                    ]
                );
                let mut varbinds = Vec::new();
                for (id, tag, value) in [
                    (1, 4, b"Test\nrouter".as_slice()),
                    (2, 6, &[0x2b, 6, 1, 4, 1, 0x30]),
                    (3, 0x43, &[0x30, 0x39]),
                    (5, 4, b"Router-A"),
                ] {
                    let mut pair = tlv(6, &[0x2b, 6, 1, 2, 1, 1, id, 0]);
                    pair.extend(tlv(tag, value));
                    varbinds.extend(tlv(0x30, &pair));
                }
                pdu.message_type = snmp2::MessageType::Response;
                pdu.varbinds = snmp2::Varbinds::from_bytes(&varbinds);
                if variant == 1 {
                    pdu.req_id ^= 1;
                }
                if variant == 2 {
                    pdu.community = b"wrong-community";
                }
                socket
                    .send_to(&pdu.to_bytes().unwrap(), peer)
                    .await
                    .unwrap();
            };
            let prober = UdpProber::default();
            let (outcome, ()) = tokio::join!(
                prober.attempt(
                    socket.local_addr().unwrap(),
                    Kind::Snmp,
                    &options,
                    Duration::from_secs(1)
                ),
                server
            );
            if variant == 0 {
                assert_eq!(outcome.state, State::Open);
                for field in ["Testrouter", "1.3.6.1.4.1.48", "123.45 s", "Router-A"] {
                    assert!(outcome.info.contains(field), "{}", outcome.info);
                }
                assert!(!outcome.info.contains(&options.community));
            } else {
                assert_eq!(outcome.state, State::OpenOrFiltered);
                assert!(outcome.info.is_empty());
            }
        }
    }

    #[tokio::test]
    async fn snmp_without_community_does_not_guess_or_send() {
        let socket = listener().await;
        let prober = UdpProber::default();
        let outcome = prober
            .attempt(
                socket.local_addr().unwrap(),
                Kind::Snmp,
                &Options::default(),
                Duration::from_secs(1),
            )
            .await;
        assert_eq!(outcome.state, State::Error);
        assert!(socket.try_recv(&mut [0; 512]).is_err());
        let result = prober
            .scan(
                Ipv4Addr::LOCALHOST,
                &Options {
                    snmp: true,
                    ..Default::default()
                },
                Duration::from_secs(1),
                true,
                &CancellationToken::new(),
                |_| {},
            )
            .await;
        assert_eq!(result.requested, 0);
        assert!(result.snmp.contains("Not queried"));
        assert!(result.open_ports.is_empty());
    }
}
