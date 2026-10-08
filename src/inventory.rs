use crate::{metadata::WebService, scanner::HostResult};
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    net::Ipv4Addr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::AsyncReadExt;
use tokio_rustls::{
    TlsConnector,
    rustls::{
        self,
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        pki_types::{CertificateDer, ServerName, UnixTime},
    },
};
use tokio_util::sync::CancellationToken;
use x509_parser::{extensions::GeneralName, prelude::parse_x509_certificate};

const TLS_PORTS: [u16; 11] = [443, 8443, 465, 636, 853, 993, 995, 5986, 8000, 8080, 8888];
const GREETING_PORTS: [u16; 7] = [21, 22, 25, 110, 143, 587, 5900];

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ServiceBanner {
    pub port: u16,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TlsCertificate {
    pub port: u16,
    pub common_name: String,
    pub subject: String,
    pub issuer: String,
    pub names: Vec<String>,
    pub valid_from: String,
    pub valid_until: String,
    pub serial: String,
}

impl TlsCertificate {
    pub fn summary(&self) -> String {
        format!(
            "{}: {} | SAN: {} | issuer: {} | valid: {} to {} | serial: {} [identity unverified]",
            self.port,
            self.subject,
            self.names.join(", "),
            self.issuer,
            self.valid_from,
            self.valid_until,
            self.serial
        )
    }
}

pub struct InventoryProber {
    slots: tokio::sync::Semaphore,
    provider: Arc<rustls::crypto::CryptoProvider>,
}

impl Default for InventoryProber {
    fn default() -> Self {
        Self {
            slots: tokio::sync::Semaphore::new(32),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl InventoryProber {
    pub async fn banners(
        &self,
        ip: Ipv4Addr,
        open: &[u16],
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Vec<ServiceBanner> {
        let ports: Vec<_> = open
            .iter()
            .copied()
            .filter(|port| {
                GREETING_PORTS.contains(port)
                    || (!TLS_PORTS.contains(port)
                        && ![
                            80, 135, 139, 389, 445, 515, 631, 1883, 3389, 5357, 5985, 8000, 8080,
                            8888, 9100,
                        ]
                        .contains(port))
            })
            .take(16)
            .collect();
        let mut results = Vec::new();
        let work = async {
            let mut pending = stream::iter(ports)
                .map(|port| async move {
                    let _slot = self.slots.acquire().await.ok()?;
                    read_banner(ip, port, timeout)
                        .await
                        .map(|text| ServiceBanner { port, text })
                })
                .buffer_unordered(4);
            while let Some(result) = pending.next().await {
                if let Some(result) = result {
                    results.push(result);
                }
            }
        };
        let _ = cancel
            .run_until_cancelled(tokio::time::timeout(timeout.saturating_mul(3), work))
            .await;
        results.sort_by_key(|banner| banner.port);
        results
    }

    pub async fn certificates(
        &self,
        ip: Ipv4Addr,
        scanned: &[u16],
        open: &[u16],
        web: &[WebService],
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Vec<TlsCertificate> {
        let scanned: HashSet<_> = scanned.iter().copied().collect();
        let open_set: HashSet<_> = open.iter().copied().collect();
        let mut chosen = HashSet::new();
        let mut ports: Vec<_> = TLS_PORTS
            .into_iter()
            .filter(|port| !scanned.contains(port) || open_set.contains(port))
            .inspect(|port| {
                chosen.insert(*port);
            })
            .collect();
        for &port in open {
            if !crate::metadata::non_web_port(port) && chosen.insert(port) {
                ports.push(port);
            }
        }
        for service in web {
            if let Ok(url) = reqwest::Url::parse(&service.url)
                && matches!(url.scheme(), "http" | "https")
                && url
                    .host_str()
                    .and_then(|host| host.parse::<Ipv4Addr>().ok())
                    == Some(ip)
                && let Some(port) = url.port_or_known_default()
                && !crate::metadata::non_web_port(port)
                && chosen.insert(port)
            {
                ports.push(port);
            }
        }
        ports.sort_by_key(|port| !open_set.contains(port));
        ports.truncate(16);
        let mut results = Vec::new();
        let work = async {
            let mut pending = stream::iter(ports)
                .map(|port| async move {
                    let _slot = self.slots.acquire().await.ok()?;
                    tokio::time::timeout(timeout, self.certificate(ip, port))
                        .await
                        .ok()
                        .flatten()
                })
                .buffer_unordered(4);
            while let Some(result) = pending.next().await {
                if let Some(result) = result {
                    results.push(result);
                }
            }
        };
        let _ = cancel
            .run_until_cancelled(tokio::time::timeout(timeout.saturating_mul(4), work))
            .await;
        results.sort_by_key(|certificate| certificate.port);
        results
    }

    /// Collect the public certificate on only this endpoint, without accepting or authenticating it.
    pub async fn certificate_endpoint(
        &self,
        ip: Ipv4Addr,
        port: u16,
        timeout: Duration,
        cancel: &CancellationToken,
    ) -> Option<TlsCertificate> {
        cancel
            .run_until_cancelled(tokio::time::timeout(timeout, async {
                let _slot = self.slots.acquire().await.ok()?;
                self.certificate(ip, port).await
            }))
            .await?
            .ok()?
    }

    async fn certificate(&self, ip: Ipv4Addr, port: u16) -> Option<TlsCertificate> {
        let captured = Arc::new(Mutex::new(None));
        let provider = self.provider.clone();
        let verifier = CaptureCertificate {
            port,
            captured: captured.clone(),
            schemes: provider
                .signature_verification_algorithms
                .supported_schemes(),
        };
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .ok()?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(verifier))
            .with_no_client_auth();
        let socket = tokio::net::TcpStream::connect((ip, port)).await.ok()?;
        // Capture the public certificate and deliberately abort. Never accept an untrusted peer,
        // present a client certificate, or send application/authentication data.
        let _ = TlsConnector::from(Arc::new(config))
            .connect(ServerName::IpAddress(ip.into()), socket)
            .await;
        captured.lock().ok()?.take()
    }
}

#[derive(Debug)]
struct CaptureCertificate {
    port: u16,
    captured: Arc<Mutex<Option<TlsCertificate>>>,
    schemes: Vec<rustls::SignatureScheme>,
}

impl ServerCertVerifier for CaptureCertificate {
    fn verify_server_cert(
        &self,
        leaf: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        if let Ok(mut captured) = self.captured.lock() {
            *captured = parse_certificate(leaf.as_ref(), self.port);
        }
        Err(rustls::Error::General(
            "Inventory certificate captured; handshake intentionally aborted".into(),
        ))
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "Inventory does not authenticate TLS peers".into(),
        ))
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General(
            "Inventory does not authenticate TLS peers".into(),
        ))
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.schemes.clone()
    }
}

fn parse_certificate(bytes: &[u8], port: u16) -> Option<TlsCertificate> {
    if bytes.len() > 32 * 1024 {
        return None;
    }
    let (remaining, certificate) = parse_x509_certificate(bytes).ok()?;
    if !remaining.is_empty() {
        return None;
    }
    let mut names = Vec::new();
    if let Ok(Some(san)) = certificate.subject_alternative_name() {
        for name in &san.value.general_names {
            let name = match name {
                GeneralName::DNSName(name) => clean(name, 256),
                GeneralName::IPAddress(bytes) if bytes.len() == 4 => {
                    Ipv4Addr::from(<[u8; 4]>::try_from(*bytes).ok()?).to_string()
                }
                GeneralName::IPAddress(bytes) if bytes.len() == 16 => {
                    std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*bytes).ok()?).to_string()
                }
                _ => continue,
            };
            if !name.is_empty() && !names.contains(&name) {
                names.push(name);
            }
            if names.len() == 16 {
                break;
            }
        }
    }
    Some(TlsCertificate {
        port,
        common_name: certificate
            .subject()
            .iter_common_name()
            .find_map(|name| name.as_str().ok())
            .map(|name| clean(name, 256))
            .unwrap_or_default(),
        subject: clean(&certificate.subject().to_string(), 512),
        issuer: clean(&certificate.issuer().to_string(), 512),
        names,
        valid_from: certificate.validity().not_before.to_string(),
        valid_until: certificate.validity().not_after.to_string(),
        serial: clean(&certificate.raw_serial_as_string(), 256),
    })
}

async fn read_banner(ip: Ipv4Addr, port: u16, timeout: Duration) -> Option<String> {
    let mut bytes = Vec::new();
    let work = async {
        let mut socket = tokio::net::TcpStream::connect((ip, port)).await.ok()?;
        let mut buffer = [0u8; 1024];
        while bytes.len() < buffer.len() {
            let count = socket.read(&mut buffer[..1024 - bytes.len()]).await.ok()?;
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&buffer[..count]);
            if bytes.contains(&b'\n') {
                break;
            }
        }
        Some(())
    };
    let _ = tokio::time::timeout(timeout, work).await;
    let text = clean(&String::from_utf8_lossy(&bytes), 512);
    (!text.is_empty()).then_some(text)
}

fn clean(text: &str, limit: usize) -> String {
    text.chars()
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .filter(|c| !c.is_control())
        .take(limit)
        .collect::<String>()
        .trim()
        .to_owned()
}

pub fn device_identity(host: &HostResult) -> String {
    let mut parts = Vec::new();
    let mut add = |source: &str, value: &str| {
        if parts.len() < 24 && !value.is_empty() {
            let value = format!("{source}: {}", clean(value, 256));
            if !parts.contains(&value) {
                parts.push(value);
            }
        }
    };
    add("Resolved name", &host.hostname);
    add("NetBIOS", &host.extra.netbios);
    add("LLMNR", &host.extra.llmnr);
    if host.extra.udp.snmp.starts_with("161/udp: SNMPv2c |") {
        add("SNMP (reported)", &host.extra.udp.snmp);
    }
    for service in &host.extra.bonjour {
        add("mDNS host", &service.hostname);
        add("mDNS service", &service.instance);
        for property in &service.properties {
            add("mDNS property", property);
        }
    }
    for device in &host.extra.advertisements.ssdp {
        add("UPnP name", &device.name);
        add("UPnP model", &device.model);
        add("UPnP manufacturer", &device.manufacturer);
    }
    for device in &host.extra.advertisements.mndp {
        add("MNDP name", &device.name);
        add("MNDP model", &device.model);
        add("MNDP firmware", &device.firmware);
    }
    for device in &host.extra.advertisements.ubiquiti {
        add("Ubiquiti name", &device.name);
        add("Ubiquiti model", &device.model);
        add("Ubiquiti firmware", &device.firmware);
    }
    for service in &host.extra.web {
        add(
            if service.tls_unverified {
                "Web title (TLS unverified)"
            } else {
                "Web title"
            },
            &service.title,
        );
    }
    for certificate in &host.extra.certificates {
        add("TLS common name (unverified)", &certificate.common_name);
        for name in &certificate.names {
            add("TLS SAN (unverified)", name);
        }
    }
    parts.join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn certificate_parser_extracts_names_and_rejects_invalid_or_excessive_der() {
        let certificate =
            rcgen::generate_simple_self_signed(vec!["printer.local".into(), "192.0.2.7".into()])
                .unwrap()
                .cert;
        let parsed = parse_certificate(certificate.der(), 443).unwrap();
        assert_eq!(parsed.names, ["printer.local", "192.0.2.7"]);
        assert!(!parsed.subject.is_empty());
        assert!(!parsed.valid_until.is_empty());
        assert!(parsed.summary().contains("unverified"));
        for length in 0..certificate.der().len() {
            assert!(parse_certificate(&certificate.der()[..length], 443).is_none());
        }
        assert!(parse_certificate(&vec![0; 32769], 443).is_none());
        let mut extra = certificate.der().to_vec();
        extra.push(0);
        assert!(parse_certificate(&extra, 443).is_none());
    }

    #[test]
    fn tls_probe_captures_self_signed_certificate_without_completing_authentication() {
        runtime().block_on(async {
            let generated = rcgen::generate_simple_self_signed(vec!["nas.local".into()]).unwrap();
            let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![generated.cert.der().clone()],
                rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der())
                    .into(),
            )
            .unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                assert!(
                    tokio_rustls::TlsAcceptor::from(Arc::new(config))
                        .accept(socket)
                        .await
                        .is_err()
                );
            });
            let certificate = tokio::time::timeout(
                Duration::from_secs(2),
                InventoryProber::default().certificate_endpoint(
                    Ipv4Addr::LOCALHOST,
                    port,
                    Duration::from_secs(1),
                    &CancellationToken::new(),
                ),
            )
            .await
            .unwrap()
            .unwrap();
            assert!(certificate.names.contains(&"nas.local".into()));
            server.await.unwrap();
        });
    }

    #[test]
    fn focused_certificate_probe_bounds_queue_wait_and_cancellation() {
        runtime().block_on(async {
            let prober = InventoryProber::default();
            let all_slots = prober.slots.acquire_many(32).await.unwrap();
            let cancel = CancellationToken::new();
            let started = std::time::Instant::now();
            assert!(
                prober
                    .certificate_endpoint(
                        Ipv4Addr::LOCALHOST,
                        12345,
                        Duration::from_millis(20),
                        &cancel
                    )
                    .await
                    .is_none()
            );
            assert!(started.elapsed() < Duration::from_secs(1));
            let stop = async {
                tokio::time::sleep(Duration::from_millis(20)).await;
                cancel.cancel();
            };
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                futures_util::future::join(
                    prober.certificate_endpoint(
                        Ipv4Addr::LOCALHOST,
                        12345,
                        Duration::from_secs(10),
                        &cancel,
                    ),
                    stop,
                ),
            )
            .await
            .unwrap()
            .0;
            assert!(result.is_none());
            drop(all_slots);
            assert_eq!(prober.slots.available_permits(), 32);
        });
    }

    #[test]
    fn banner_probe_reads_greeting_without_sending_commands_and_obeys_deadlines() {
        runtime().block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let server = tokio::spawn(async move {
                use tokio::io::AsyncWriteExt;
                let (mut socket, _) = listener.accept().await.unwrap();
                socket.write_all(b"SSH-2.0-OpenSSH_9.6\r\n").await.unwrap();
                let mut bytes = [0; 32];
                assert_eq!(socket.read(&mut bytes).await.unwrap(), 0);
            });
            assert_eq!(
                read_banner(Ipv4Addr::LOCALHOST, port, Duration::from_secs(1))
                    .await
                    .as_deref(),
                Some("SSH-2.0-OpenSSH_9.6")
            );
            server.await.unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            assert!(
                read_banner(
                    Ipv4Addr::LOCALHOST,
                    listener.local_addr().unwrap().port(),
                    Duration::from_millis(20)
                )
                .await
                .is_none()
            );
            let cancel = CancellationToken::new();
            cancel.cancel();
            assert!(
                InventoryProber::default()
                    .certificates(
                        Ipv4Addr::LOCALHOST,
                        &[],
                        &[],
                        &[],
                        Duration::from_secs(2),
                        &cancel
                    )
                    .await
                    .is_empty()
            );
        });
    }
}
