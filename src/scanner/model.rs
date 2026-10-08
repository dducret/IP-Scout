use crate::{
    advertisements::{self, Advertisements},
    discovery::{BonjourService, WsdDevice},
    inventory::{ServiceBanner, TlsCertificate},
    metadata::WebService,
    targets::TargetRange,
    udp::{self, UdpResult},
};
use serde::{Deserialize, Serialize};
use std::{net::Ipv4Addr, time::Duration};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HostStatus {
    Alive,
    NoResponse,
    Incomplete,
}

impl HostStatus {
    pub fn label(self) -> &'static str {
        match self {
            Self::Alive => "Alive",
            Self::NoResponse => "No response",
            Self::Incomplete => "Incomplete",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HostResult {
    pub ip: Ipv4Addr,
    pub status: HostStatus,
    pub ping_ms: Option<f64>,
    pub hostname: String,
    pub mac: String,
    pub vendor: String,
    pub open_ports: Vec<u16>,
    pub refused_ports: usize,
    pub notes: String,
    #[serde(default)]
    pub arp_response: bool,
    #[serde(default)]
    pub probable_brand: String,
    #[serde(default)]
    pub extra: ExtraResult,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ExtraResult {
    #[serde(skip)]
    pub retry_tcp: Vec<u16>,
    // Missing in legacy snapshots, which already represented finished host discovery.
    pub discovery_complete: Option<bool>,
    pub udp: UdpResult,
    pub ttl: Option<u8>,
    pub packet_loss: Option<f64>,
    pub icmp_sent: u8,
    pub icmp_received: u8,
    pub netbios: String,
    pub web: Vec<WebService>,
    pub bonjour: Vec<BonjourService>,
    pub wsd: Vec<WsdDevice>,
    pub advertisements: Advertisements,
    pub llmnr: String,
    pub banners: Vec<ServiceBanner>,
    pub certificates: Vec<TlsCertificate>,
}

#[derive(Debug, Clone)]
pub struct ExtraOptions {
    pub udp: udp::Options,
    pub netbios: bool,
    pub web: bool,
    pub packet_loss: bool,
    pub icmp_samples: u8,
    pub allow_unverified_tls: bool,
    pub bonjour: bool,
    pub wsd: bool,
    pub discovery_seconds: u8,
    pub advertisements: advertisements::Options,
    pub llmnr: bool,
    pub banners: bool,
    pub certificates: bool,
    pub web_titles: bool,
}

impl Default for ExtraOptions {
    fn default() -> Self {
        Self {
            udp: udp::Options::default(),
            netbios: false,
            web: false,
            packet_loss: false,
            icmp_samples: 3,
            allow_unverified_tls: false,
            bonjour: false,
            wsd: false,
            discovery_seconds: 4,
            advertisements: advertisements::Options::default(),
            llmnr: false,
            banners: false,
            certificates: false,
            web_titles: false,
        }
    }
}

impl HostResult {
    pub fn discovery_complete(&self) -> bool {
        self.extra.discovery_complete != Some(false)
    }

    pub fn brand_label(&self) -> &str {
        if self.vendor.is_empty() {
            &self.probable_brand
        } else {
            &self.vendor
        }
    }
}

#[derive(Clone)]
pub struct ScanOptions {
    pub mode: ScanMode,
    pub targets: TargetRange,
    pub ports: Vec<u16>,
    pub timeout_ms: u32,
    pub workers: usize,
    pub adaptive_concurrency: bool,
    pub resolve_names: bool,
    pub fetch_mac: bool,
    pub fetch_vendor: bool,
    pub discover_arp: bool,
    pub extra: ExtraOptions,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScanMode {
    #[default]
    Fast,
    Thorough,
}

pub enum ScanEvent {
    /// A host's latest snapshot. Later events for the same IP replace its row.
    /// Positive replies can be published before discovery_complete() becomes true.
    Host(Box<HostResult>),
    Phase(String),
    Concurrency(ConcurrencySnapshot),
    Warning(String),
    Finished {
        elapsed: Duration,
        cancelled: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConcurrencySnapshot {
    pub local_workers: usize,
    pub max_workers: usize,
    pub routed_tcp: usize,
    pub routed_tcp_max: usize,
    pub routed_interval_ms: u64,
}
