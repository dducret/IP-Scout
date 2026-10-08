use super::clean;
use hickory_proto::{
    op::{Message, MessageType, Query, ResponseCode},
    rr::{DNSClass, Name, RData, RecordType},
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

pub async fn llmnr(
    ip: Ipv4Addr,
    local_ip: Ipv4Addr,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Option<String> {
    llmnr_at(SocketAddr::from((ip, 5355)), local_ip, timeout, cancel).await
}

pub(super) async fn llmnr_at(
    peer: SocketAddr,
    local_ip: Ipv4Addr,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Option<String> {
    let id = u16::from_be_bytes(uuid::Uuid::new_v4().as_bytes()[..2].try_into().ok()?);
    let IpAddr::V4(ip) = peer.ip() else {
        return None;
    };
    let [a, b, c, d] = ip.octets();
    let name = Name::from_ascii(format!("{d}.{c}.{b}.{a}.in-addr.arpa.")).ok()?;
    let mut query = Message::new();
    query
        .set_id(id)
        .add_query(Query::query(name.clone(), RecordType::PTR));
    let work = async {
        // RFC 4795 requires unicast PTR queries over TCP, with a TTL of one
        // during connection setup to prevent reaching an off-link responder.
        let sock = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::STREAM,
            Some(socket2::Protocol::TCP),
        )
        .ok()?;
        sock.set_ttl_v4(1).ok()?;
        sock.bind(&SocketAddr::from((local_ip, 0)).into()).ok()?;
        sock.set_nonblocking(true).ok()?;
        let stream: std::net::TcpStream = sock.into();
        let sock = tokio::net::TcpSocket::from_std_stream(stream);
        let mut stream = sock.connect(peer).await.ok()?;
        let data = query.to_vec().ok()?;
        stream.write_u16(data.len().try_into().ok()?).await.ok()?;
        stream.write_all(&data).await.ok()?;
        let mut buffer = [0u8; 4096];
        for _ in 0..8 {
            let len = usize::from(stream.read_u16().await.ok()?);
            if len > buffer.len() {
                return None;
            }
            stream.read_exact(&mut buffer[..len]).await.ok()?;
            if let Some(name) = parse_llmnr(&buffer[..len], id, &name) {
                return Some(name);
            }
        }
        None
    };
    cancel
        .run_until_cancelled(tokio::time::timeout(timeout, work))
        .await?
        .ok()?
}

pub(super) fn parse_llmnr(data: &[u8], id: u16, name: &Name) -> Option<String> {
    let response = Message::from_vec(data).ok()?;
    if response.id() != id
        || response.message_type() != MessageType::Response
        || response.truncated()
        || response.response_code() != ResponseCode::NoError
        || data.get(2)? & 0x7f != 0
        || data.get(3)? & 0xf0 != 0
        || response.queries().len() != 1
        || response.queries()[0].name() != name
        || response.queries()[0].query_type() != RecordType::PTR
        || response.queries()[0].query_class() != DNSClass::IN
    {
        return None;
    }
    response.answers().iter().find_map(|answer| {
        if answer.name() != name || answer.dns_class() != DNSClass::IN {
            return None;
        }
        match answer.data()? {
            RData::PTR(ptr) => {
                Some(clean(ptr.to_utf8().trim_end_matches('.'))).filter(|s| !s.is_empty())
            }
            _ => None,
        }
    })
}
