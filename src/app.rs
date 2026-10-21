use eframe::egui::{self, Color32, RichText};
use egui_extras::{Column, TableBuilder};
use egui_phosphor::regular as icons;
use ip_scout::{
    export,
    fetchers::{self, Fetcher, FetcherDraft},
    network::{self, LocalNetwork},
    scanner::{
        self, ConcurrencySnapshot, ExtraOptions, HostResult, HostStatus, ScanEvent, ScanHandle,
        ScanMode, ScanOptions,
    },
    targets::{TargetRange, TargetSet, format_ports, parse_ports},
    udp,
};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::HashMap,
    net::Ipv4Addr,
    sync::mpsc::{self, Receiver, TryRecvError},
    time::{Duration, Instant},
};

#[path = "app/i18n.rs"]
mod i18n;
use i18n::{Language, Locale, Message};

const GREEN: Color32 = Color32::from_rgb(20, 133, 96);
#[path = "app/view.rs"]
mod view;
#[path = "app/workflows.rs"]
mod workflows;
const BLUE: Color32 = Color32::from_rgb(35, 111, 192);
const MUTED: Color32 = Color32::from_rgb(116, 125, 133);
const RED: Color32 = Color32::from_rgb(192, 61, 63);
const COPY_CONFIRMATION_TIME: Duration = Duration::from_secs(2);
const PORT_PRESETS: [(&str, &str); 6] = [
    ("Common", "22,80,443,445,3389,8080"),
    ("Web", "80,443,8000,8080,8443"),
    ("Windows", "135,139,445,3389"),
    ("No TCP", ""),
    ("Inventory", fetchers::INVENTORY_PORTS),
    ("All TCP", "1-65535"),
];

#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    #[serde(default = "legacy_scan_mode")]
    mode: ScanMode,
    target: String,
    ports: String,
    timeout_ms: u32,
    workers: usize,
    adaptive_concurrency: bool,
    resolve_names: bool,
    fetch_mac: bool,
    discover_arp: bool,
    dark: bool,
    fetchers: Option<Vec<Fetcher>>,
    icmp_samples: u8,
    allow_unverified_tls: bool,
    discovery_seconds: u8,
    udp_ports: String,
    #[serde(skip)]
    snmp_community: String,
}

fn legacy_scan_mode() -> ScanMode {
    ScanMode::Thorough
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            mode: ScanMode::Fast,
            target: String::new(),
            ports: "22,80,443,445,3389,8080".into(),
            timeout_ms: 200,
            workers: 256,
            adaptive_concurrency: true,
            resolve_names: true,
            fetch_mac: network::ARP_SUPPORTED,
            discover_arp: network::ARP_SUPPORTED,
            dark: false,
            fetchers: None,
            icmp_samples: 3,
            allow_unverified_tls: false,
            discovery_seconds: 2,
            udp_ports: udp::COMMON_PORTS.into(),
            snmp_community: String::new(),
        }
    }
}

impl Settings {
    fn apply_mode_profile(&mut self) {
        let fast = self.mode == ScanMode::Fast;
        self.timeout_ms = if fast { 200 } else { 400 };
        self.workers = if fast { 256 } else { 128 };
        self.discovery_seconds = if fast { 2 } else { 4 };
    }

    fn normalize_fetchers(&mut self) {
        let mut selected = self.fetchers.take().unwrap_or_else(|| {
            fetchers::defaults()
                .into_iter()
                .filter(|fetcher| match fetcher {
                    Fetcher::Hostname => self.resolve_names,
                    Fetcher::MacAddress | Fetcher::Manufacturer => self.fetch_mac,
                    _ => true,
                })
                .collect()
        });
        fetchers::normalize(&mut selected);
        self.fetchers = Some(selected);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Filter {
    All,
    Alive,
    OpenPorts,
    NoResponse,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sort {
    Ip,
    Status,
    Ping,
    Hostname,
    Ports,
    Mac,
    Vendor,
    RefusedPorts,
    ArpResponse,
    ProbableBrand,
    Notes,
    Ttl,
    PacketLoss,
    Metadata(Fetcher),
}

#[derive(Clone, Copy, Hash)]
enum AddressColumn {
    Ip,
    Mac,
}

#[derive(Clone)]
struct CopyFeedback {
    button: egui::Id,
    expires_at: Instant,
}

impl CopyFeedback {
    fn active_for(&self, button: egui::Id, now: Instant) -> bool {
        self.button == button && now < self.expires_at
    }
}

pub struct ScoutApp {
    language: Language,
    workflow: workflows::WorkflowState,
    logo: egui::TextureHandle,
    settings: Settings,
    networks: Vec<LocalNetwork>,
    hosts: Vec<HostResult>,
    host_positions: HashMap<Ipv4Addr, usize>,
    visible: Vec<usize>,
    view: view::ViewCache,
    dirty: bool,
    filter: Filter,
    query: String,
    sort: Sort,
    descending: bool,
    selected: Option<Ipv4Addr>,
    scan: Option<ScanHandle>,
    concurrency: Option<ConcurrencySnapshot>,
    stopping: bool,
    total: usize,
    checked: usize,
    scan_complete: bool,
    alive: usize,
    with_ports: usize,
    started: Option<Instant>,
    elapsed: Duration,
    message: Message,
    error: Option<String>,
    warnings: Vec<String>,
    show_settings: bool,
    show_about: bool,
    show_ports_editor: bool,
    ports_draft: String,
    ports_error: Option<String>,
    ports_focus: bool,
    ports_are_udp: bool,
    export_result: Option<Receiver<Result<Message, String>>>,
    show_fetchers: bool,
    fetchers_draft: FetcherDraft,
    fetcher_scroll_selected: bool,
    #[cfg(feature = "gui-smoke")]
    smoke_offset: f32,
    #[cfg(feature = "gui-smoke")]
    smoke_details_offset: f32,
    #[cfg(feature = "gui-smoke")]
    smoke_port_buttons: [Option<egui::Pos2>; 3],
    #[cfg(feature = "gui-smoke")]
    smoke_copy_buttons: [Option<egui::Pos2>; 4],
    #[cfg(feature = "gui-smoke")]
    smoke_fetcher_buttons: [Option<egui::Pos2>; 9],
    #[cfg(feature = "gui-smoke")]
    smoke_mode_buttons: [Option<egui::Pos2>; 2],
    #[cfg(feature = "gui-smoke")]
    smoke_udp_button: Option<egui::Pos2>,
    #[cfg(feature = "gui-smoke")]
    smoke_language_buttons: [Option<egui::Pos2>; 4],
}

fn upsert_host(
    hosts: &mut Vec<HostResult>,
    positions: &mut HashMap<Ipv4Addr, usize>,
    alive: &mut usize,
    with_ports: &mut usize,
    checked: &mut usize,
    host: HostResult,
) {
    if let Some(&index) = positions.get(&host.ip) {
        let previous = &hosts[index];
        *alive -= usize::from(previous.status == HostStatus::Alive);
        *checked -= usize::from(previous.discovery_complete());
        *with_ports -= usize::from(has_open_ports(previous));
        *alive += usize::from(host.status == HostStatus::Alive);
        *checked += usize::from(host.discovery_complete());
        *with_ports += usize::from(has_open_ports(&host));
        hosts[index] = host;
    } else {
        positions.insert(host.ip, hosts.len());
        *alive += usize::from(host.status == HostStatus::Alive);
        *checked += usize::from(host.discovery_complete());
        *with_ports += usize::from(has_open_ports(&host));
        hosts.push(host);
    }
}

fn has_open_ports(host: &HostResult) -> bool {
    !host.open_ports.is_empty() || !host.extra.udp.open_ports.is_empty()
}

fn scan_finished_message(cancelled: bool, checked: usize, total: usize) -> Message {
    if cancelled {
        Message::new(
            "Scan stopped: {0}/{1} checked, {2} unchecked; fetchers may be incomplete",
            vec![
                checked.to_string(),
                total.to_string(),
                total.saturating_sub(checked).to_string(),
            ],
        )
    } else {
        "Scan complete".into()
    }
}

impl ScoutApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut fonts = egui::FontDefinitions::default();
        egui_phosphor::add_to_fonts(&mut fonts, egui_phosphor::Variant::Regular);
        cc.egui_ctx.set_fonts(fonts);
        let networks = network::local_networks();
        let mut settings: Settings = cc
            .storage
            .and_then(|s| eframe::get_value(s, "settings"))
            .unwrap_or_default();
        settings.timeout_ms = settings.timeout_ms.clamp(100, 5000);
        settings.workers = settings.workers.clamp(1, scanner::MAX_HOST_WORKERS);
        settings.icmp_samples = settings.icmp_samples.clamp(1, 10);
        settings.discovery_seconds = settings.discovery_seconds.clamp(1, 120);
        settings.normalize_fetchers();
        if settings.target.is_empty() {
            settings.target = networks
                .first()
                .map(|n| n.cidr.clone())
                .unwrap_or_else(|| "127.0.0.1".into());
        }
        apply_theme(&cc.egui_ctx, settings.dark);
        cc.egui_ctx.all_styles_mut(|style| {
            style.spacing.item_spacing = egui::vec2(10.0, 10.0);
            style.spacing.button_padding = egui::vec2(10.0, 7.0);
            style.spacing.interact_size.y = 30.0;
            style.spacing.scroll = egui::style::ScrollStyle::solid();
            style
                .text_styles
                .insert(egui::TextStyle::Body, egui::FontId::proportional(14.0));
            style
                .text_styles
                .insert(egui::TextStyle::Button, egui::FontId::proportional(14.0));
        });
        Self {
            language: cc
                .storage
                .and_then(|storage| eframe::get_value(storage, "language"))
                .unwrap_or_default(),
            workflow: workflows::WorkflowState::new(cc),
            logo: {
                let icon = eframe::icon_data::from_png_bytes(include_bytes!(concat!(
                    env!("OUT_DIR"),
                    "/runtime-logo.png"
                )))
                .expect("bundled IP Scout logo must be a valid PNG");
                cc.egui_ctx.load_texture(
                    "ip-scout-logo",
                    egui::ColorImage::from_rgba_unmultiplied(
                        [icon.width as usize, icon.height as usize],
                        &icon.rgba,
                    ),
                    egui::TextureOptions::LINEAR,
                )
            },
            settings,
            networks,
            hosts: Vec::new(),
            host_positions: HashMap::new(),
            visible: Vec::new(),
            view: view::ViewCache::default(),
            dirty: true,
            filter: Filter::All,
            query: String::new(),
            sort: Sort::Ip,
            descending: false,
            selected: None,
            scan: None,
            concurrency: None,
            stopping: false,
            total: 0,
            checked: 0,
            scan_complete: true,
            alive: 0,
            with_ports: 0,
            started: None,
            elapsed: Duration::ZERO,
            message: "Ready".into(),
            error: None,
            warnings: Vec::new(),
            show_settings: false,
            show_about: false,
            show_ports_editor: false,
            ports_draft: String::new(),
            ports_error: None,
            ports_focus: false,
            ports_are_udp: false,
            export_result: None,
            show_fetchers: false,
            fetchers_draft: FetcherDraft::new(fetchers::defaults()),
            fetcher_scroll_selected: false,
            #[cfg(feature = "gui-smoke")]
            smoke_offset: 0.0,
            #[cfg(feature = "gui-smoke")]
            smoke_details_offset: 0.0,
            #[cfg(feature = "gui-smoke")]
            smoke_port_buttons: [None; 3],
            #[cfg(feature = "gui-smoke")]
            smoke_copy_buttons: [None; 4],
            #[cfg(feature = "gui-smoke")]
            smoke_fetcher_buttons: [None; 9],
            #[cfg(feature = "gui-smoke")]
            smoke_mode_buttons: [None; 2],
            #[cfg(feature = "gui-smoke")]
            smoke_udp_button: None,
            #[cfg(feature = "gui-smoke")]
            smoke_language_buttons: [None; 4],
        }
    }

    fn begin_scan(&mut self, ctx: &egui::Context) {
        self.workflow.scan_targets = None;
        self.begin_scan_impl(ctx);
    }

    fn begin_scan_impl(&mut self, ctx: &egui::Context) {
        if self.workflow.busy() {
            return;
        }
        let targets = match self
            .workflow
            .scan_targets
            .take()
            .map(Ok)
            .unwrap_or_else(|| TargetSet::parse(&self.settings.target))
        {
            Ok(targets) => targets,
            Err(error) => {
                self.error = Some(error);
                return;
            }
        };
        let required = fetchers::requirements(self.selected_fetchers());
        let options = (|| {
            if self.udp_enabled() && self.settings.snmp_community.len() > 255 {
                return Err("SNMPv2c community must be at most 255 UTF-8 bytes".into());
            }
            Ok::<_, String>(ScanOptions {
                mode: self.settings.mode,
                targets: targets.bounds(),
                ports: if required.tcp || required.web {
                    parse_ports(&self.settings.ports)?
                } else {
                    Vec::new()
                },
                timeout_ms: self.settings.timeout_ms,
                workers: self.settings.workers,
                adaptive_concurrency: self.settings.adaptive_concurrency,
                resolve_names: required.dns,
                fetch_mac: required.mac && network::ARP_SUPPORTED,
                fetch_vendor: required.vendor && network::ARP_SUPPORTED,
                discover_arp: self.settings.discover_arp && network::ARP_SUPPORTED,
                extra: ExtraOptions {
                    udp: udp::Options {
                        ports: if required.udp {
                            parse_ports(&self.settings.udp_ports)?
                        } else {
                            Vec::new()
                        },
                        dns: required.dns_info,
                        ntp: required.ntp_info,
                        snmp: required.snmp_info,
                        community: self.settings.snmp_community.clone(),
                    },
                    netbios: required.netbios,
                    web: required.web,
                    packet_loss: required.packet_loss,
                    icmp_samples: self.settings.icmp_samples,
                    allow_unverified_tls: self.settings.allow_unverified_tls,
                    bonjour: required.bonjour,
                    wsd: required.wsd,
                    discovery_seconds: self.settings.discovery_seconds,
                    advertisements: required.advertisements,
                    llmnr: required.llmnr,
                    banners: required.banners,
                    certificates: required.certificates,
                    web_titles: required.web_titles,
                    services: required.services,
                },
            })
        })();
        match options {
            Err(error) => self.error = Some(error),
            Ok(options) => {
                self.workflow
                    .record_scan(&options, &targets, self.selected_fetchers().to_vec());
                self.total = targets.len();
                self.checked = 0;
                self.concurrency = None;
                self.scan_complete = false;
                self.hosts.clear();
                self.host_positions.clear();
                self.visible.clear();
                self.view.clear();
                self.alive = 0;
                self.with_ports = 0;
                self.selected = None;
                self.elapsed = Duration::ZERO;
                self.started = Some(Instant::now());
                self.error = None;
                self.warnings.clear();
                if self
                    .selected_fetchers()
                    .iter()
                    .any(|&fetcher| !fetcher_supported(fetcher))
                {
                    self.warnings.push("Some selected fetchers are unavailable on this platform; existing historical values remain readable.".into());
                }
                self.stopping = false;
                self.dirty = true;
                self.message = Message::new("Scanning {0}", vec![self.settings.target.clone()]);
                let ctx = ctx.clone();
                self.scan = Some(scanner::start_scan_targets_with_notifier(
                    options,
                    targets,
                    move || ctx.request_repaint(),
                ));
            }
        }
    }

    fn selected_fetchers(&self) -> &[Fetcher] {
        self.settings.fetchers.as_deref().unwrap_or_default()
    }

    fn edit_fetchers(&mut self) {
        self.fetchers_draft = FetcherDraft::new(self.selected_fetchers().to_vec());
        self.fetcher_scroll_selected = true;
        self.show_fetchers = true;
    }

    fn apply_fetchers(&mut self) {
        let required = fetchers::requirements(&self.fetchers_draft.selected);
        self.settings.resolve_names = required.dns;
        self.settings.fetch_mac = required.mac;
        self.settings.fetchers = Some(self.fetchers_draft.selected.clone());
        self.sort = Sort::Ip;
        self.descending = false;
        self.dirty = true;
        self.show_fetchers = false;
    }

    fn edit_ports(&mut self) {
        self.ports_are_udp = false;
        self.ports_draft = self.settings.ports.clone();
        self.ports_error = None;
        self.show_ports_editor = true;
        self.ports_focus = true;
    }

    fn apply_ports(&mut self) {
        match parse_ports(&self.ports_draft) {
            Ok(ports) => {
                if self.ports_are_udp {
                    self.settings.udp_ports = format_ports(&ports);
                } else {
                    self.settings.ports = format_ports(&ports);
                }
                self.show_ports_editor = false;
                self.ports_error = None;
            }
            Err(error) => self.ports_error = Some(error),
        }
    }

    fn edit_udp_ports(&mut self) {
        self.edit_ports();
        self.ports_are_udp = true;
        self.ports_draft = self.settings.udp_ports.clone();
    }

    fn udp_enabled(&self) -> bool {
        self.selected_fetchers().iter().any(|fetcher| {
            matches!(
                fetcher,
                Fetcher::UdpPorts
                    | Fetcher::UdpStatus
                    | Fetcher::DnsInfo
                    | Fetcher::NtpInfo
                    | Fetcher::SnmpInfo
            )
        })
    }

    fn set_udp_enabled(&mut self, enabled: bool) {
        let mut selected = self.selected_fetchers().to_vec();
        let udp_fetchers = [
            Fetcher::UdpPorts,
            Fetcher::UdpStatus,
            Fetcher::DnsInfo,
            Fetcher::NtpInfo,
            Fetcher::SnmpInfo,
        ];
        if enabled {
            for fetcher in udp_fetchers {
                if !selected.contains(&fetcher) {
                    selected.push(fetcher);
                }
            }
        } else {
            selected.retain(|fetcher| !udp_fetchers.contains(fetcher));
        }
        self.fetchers_draft = FetcherDraft::new(selected);
        self.apply_fetchers();
    }

    fn receive(&mut self, ctx: &egui::Context) {
        let mut finished = false;
        if let Some(scan) = &self.scan {
            let started = Instant::now();
            // Drain bursts promptly, with a wall-clock budget for input and painting.
            for event in 0..4096 {
                if event > 0 && started.elapsed() >= Duration::from_millis(4) {
                    ctx.request_repaint();
                    break;
                }
                if event == 4095 {
                    ctx.request_repaint();
                }
                match scan.events.try_recv() {
                    Ok(ScanEvent::Host(host)) => {
                        if self.hosts.is_empty() && !self.stopping {
                            self.message =
                                Message::new("Scanning {0}", vec![self.settings.target.clone()]);
                        }
                        let previous = self.host_positions.get(&host.ip).copied();
                        self.view.invalidate(previous.unwrap_or(self.hosts.len()));
                        self.dirty |= view::affects_update(
                            previous.map(|index| &self.hosts[index]),
                            &host,
                            self.filter,
                            self.sort,
                            &self.query,
                        );
                        upsert_host(
                            &mut self.hosts,
                            &mut self.host_positions,
                            &mut self.alive,
                            &mut self.with_ports,
                            &mut self.checked,
                            *host,
                        );
                    }
                    Ok(ScanEvent::Phase(message)) => {
                        if !self.stopping {
                            self.message = Message::phase(message);
                        }
                    }
                    Ok(ScanEvent::Concurrency(snapshot)) => self.concurrency = Some(snapshot),
                    Ok(ScanEvent::Warning(warning)) => self.warnings.push(warning),
                    Ok(ScanEvent::Finished { elapsed, cancelled }) => {
                        self.elapsed = elapsed;
                        self.scan_complete = !cancelled;
                        self.message = scan_finished_message(cancelled, self.checked, self.total);
                        finished = true;
                        break;
                    }
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.error = Some("The scan ended unexpectedly".into());
                        self.message = "Scan interrupted".into();
                        self.elapsed = self.started.map(|s| s.elapsed()).unwrap_or_default();
                        finished = true;
                        break;
                    }
                }
            }
        }
        if finished {
            self.scan = None;
            self.stopping = false;
        }
        if let Some(receiver) = &self.export_result {
            match receiver.try_recv() {
                Ok(result) => {
                    match result {
                        Ok(message) if !message.is_empty() => self.message = message,
                        Ok(_) => {}
                        Err(error) => self.error = Some(error),
                    }
                    self.export_result = None;
                }
                Err(TryRecvError::Disconnected) => {
                    self.error = Some("Export did not finish".into());
                    self.export_result = None;
                }
                Err(TryRecvError::Empty) => {}
            }
        }
    }

    fn rebuild_visible(&mut self) {
        if self.dirty {
            self.view.rebuild(
                &self.hosts,
                &mut self.visible,
                self.filter,
                self.sort,
                self.descending,
                &self.query,
            );
            self.dirty = false;
        }
    }

    fn begin_export(&mut self, ctx: &egui::Context) {
        let tr = self.language.resolve();
        let fetchers = self.selected_fetchers().to_vec();
        let snapshot: Vec<_> = self
            .visible
            .iter()
            .map(|&i| self.hosts[i].clone())
            .collect();
        let (sender, receiver) = mpsc::channel();
        self.export_result = Some(receiver);
        let ctx = ctx.clone();
        let partial = !self.scan_complete && self.total > 0;
        std::thread::spawn(move || {
            let result = if let Some(path) = rfd::FileDialog::new()
                .set_title(if partial {
                    tr.text("Export partial scan results")
                } else {
                    tr.text("Export visible scan results")
                })
                .add_filter("CSV", &["csv"])
                .set_file_name(if partial {
                    "ip-scout-partial-scan.csv"
                } else {
                    "ip-scout-scan.csv"
                })
                .save_file()
            {
                let hosts: Vec<_> = snapshot.iter().collect();
                export::save_csv_with_fetchers(&path, &hosts, &fetchers)
                    .map(|()| {
                        Message::new(
                            "Exported {0} hosts to {1}",
                            vec![hosts.len().to_string(), path.display().to_string()],
                        )
                    })
                    .map_err(|error| format!("Could not export: {error}"))
            } else {
                Ok("".into())
            };
            let _ = sender.send(result);
            ctx.request_repaint();
        });
    }

    fn controls(&mut self, ctx: &egui::Context) {
        let tr = self.language.resolve();
        egui::TopBottomPanel::top("controls")
            .frame(
                egui::Frame::new()
                    .fill(ctx.style().visuals.panel_fill)
                    .inner_margin(egui::Margin::same(18)),
            )
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add(egui::Image::new(&self.logo).fit_to_exact_size(egui::vec2(34.0, 34.0)));
                    ui.label(RichText::new("IP Scout").size(23.0).strong());
                    ui.label(RichText::new(tr.text("NETWORK SCANNER")).size(11.0).color(MUTED));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if icon_button(ui, icons::INFO, tr.text("About IP Scout")).clicked() {
                            self.show_about = true;
                        }
                        if icon_button(
                            ui,
                            if self.settings.dark {
                                icons::SUN
                            } else {
                                icons::MOON
                            },
                            tr.text("Switch theme"),
                        )
                        .clicked()
                        {
                            self.settings.dark = !self.settings.dark;
                            apply_theme(ctx, self.settings.dark);
                        }
                        if icon_button(ui, icons::GEAR, tr.text("Scan settings")).clicked() {
                            self.show_settings = true;
                        }
                        if ui.button(tr.text("Tools")).on_hover_text(tr.text("Targets, profiles and scan history")).clicked() {
                            self.workflow.open = true;
                            self.workflow.target_draft = self.settings.target.clone();
                        }
                        let fetchers = ui.button(tr.format("{0} Fetchers", &[icons::LIST_CHECKS.to_string()]));
                        #[cfg(feature = "gui-smoke")]
                        {
                            self.smoke_fetcher_buttons[0] = Some(fetchers.rect.center());
                        }
                        if fetchers
                            .on_hover_text(tr.text("Select and arrange fetchers"))
                            .clicked()
                        {
                            self.edit_fetchers();
                        }
                    });
                });
                ui.add_space(10.0);
                ui.horizontal(|ui| {
                    ui.label(tr.text("Targets"));
                    let available = (ui.available_width() - 255.0).max(180.0);
                    ui.add_enabled(
                        self.scan.is_none(),
                        egui::TextEdit::singleline(&mut self.settings.target)
                            .desired_width(available)
                            .font(egui::TextStyle::Monospace)
                            .hint_text("192.168.1.0/24, 10.0.0.5, !192.168.1.10"),
                    );
                    ui.add_enabled_ui(self.scan.is_none(), |ui| {
                        egui::ComboBox::from_id_salt("local_network")
                            .selected_text(tr.format("{0} Local", &[icons::NETWORK.to_string()]))
                            .width(92.0)
                            .show_ui(ui, |ui| {
                                if self.networks.is_empty() {
                                    ui.label(tr.text("No local networks found"));
                                }
                                for network in &self.networks {
                                    if ui
                                        .selectable_label(
                                            self.settings.target == network.cidr,
                                            format!("{}  ({})", network.cidr, network.address),
                                        )
                                        .clicked()
                                    {
                                        self.settings.target = network.cidr.clone();
                                    }
                                }
                                ui.separator();
                                if ui
                                    .button(tr.format("{0} Refresh", &[icons::ARROWS_CLOCKWISE.to_string()]))
                                    .clicked()
                                {
                                    self.networks = network::local_networks();
                                }
                            });
                    });
                    if let Some(scan) = &self.scan {
                        if ui
                            .add_enabled(
                                !self.stopping,
                                egui::Button::new(tr.format("{0} Stop", &[icons::STOP.to_string()]))
                                    .min_size(egui::vec2(115.0, 32.0)),
                            )
                            .clicked()
                        {
                            scan.cancel();
                            self.stopping = true;
                            self.message = "Stopping scan...".into();
                        }
                    } else if ui
                        .add_enabled(!self.workflow.busy(),
                            egui::Button::new(
                                RichText::new(tr.format("{0} Start scan", &[icons::PLAY.to_string()]))
                                    .color(Color32::WHITE),
                            )
                            .fill(GREEN)
                            .min_size(egui::vec2(115.0, 32.0)),
                        )
                        .clicked()
                    {
                        self.begin_scan(ctx);
                    }
                });
                ui.horizontal(|ui| {
                    ui.label(tr.text("TCP ports"));
                    ui.add(
                        egui::TextEdit::singleline(&mut self.settings.ports)
                            .id(egui::Id::new("tcp_ports"))
                            .desired_width((ui.available_width() - 550.0).clamp(100.0, 280.0))
                            .font(egui::TextStyle::Monospace)
                            .hint_text("80,443,8000-8010"),
                    );
                    ui.scope(|ui| {
                        egui::ComboBox::from_id_salt("port_presets")
                            .selected_text(
                                PORT_PRESETS
                                    .iter()
                                    .find(|(_, ports)| *ports == self.settings.ports.trim())
                                    .map(|(name, _)| tr.text(name))
                                    .unwrap_or(tr.text("Custom")),
                            )
                            .width(100.0)
                            .show_ui(ui, |ui| {
                                for (name, ports) in PORT_PRESETS {
                                    let preset = ui.button(tr.text(name));
                                    let preset = if name == "All TCP" {
                                        preset.on_hover_text(tr.text("All 65,535 TCP ports per address. Large ranges can take minutes or longer; concurrent connections remain bounded."))
                                    } else { preset };
                                    if preset.clicked() {
                                        self.settings.ports = ports.into();
                                        if name == "Inventory" {
                                            self.fetchers_draft =
                                                FetcherDraft::new(fetchers::inventory().into_iter().filter(|&fetcher| fetcher_supported(fetcher)).collect());
                                            self.apply_fetchers();
                                        }
                                    }
                                }
                                ui.separator();
                                if ui
                                    .button(tr.format("{0} Custom...", &[icons::PENCIL_SIMPLE.to_string()]))
                                    .clicked()
                                {
                                    self.edit_ports();
                                }
                            });
                        let edit = icon_button(ui, icons::PENCIL_SIMPLE, tr.text("Edit TCP ports"));
                        #[cfg(feature = "gui-smoke")]
                        {
                            self.smoke_port_buttons[0] = Some(edit.rect.center());
                        }
                        if edit.clicked() {
                            self.edit_ports();
                        }
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.label(
                            RichText::new(format!(
                                "{} {}  /  {} ms",
                                if self.settings.adaptive_concurrency { tr.text("Auto max") } else { tr.text("Workers") },
                                self.settings.workers, self.settings.timeout_ms
                            ))
                            .size(12.0)
                            .color(MUTED),
                        ).on_hover_text(if let Some(snapshot) = self.concurrency.filter(|_| self.scan.is_some()) {
                            tr.format("Local host budget: {0} / {1} | Routed TCP budget: {2} / {3} | {4} independent interface/next-hop paths | Slowest path pacing: up to 8 starts every {5} ms", &[format!("{}", snapshot.local_workers), format!("{}", snapshot.max_workers), format!("{}", snapshot.routed_tcp), format!("{}", snapshot.routed_tcp_max), format!("{}", snapshot.active_paths), format!("{}", snapshot.routed_interval_ms)])
                        } else { "Worker ceiling; routed traffic has separate connection and pacing limits.".into() });
                        let previous = self.settings.mode;
                        ui.add_enabled_ui(self.scan.is_none(), |ui| {
                            let deep = ui.selectable_value(&mut self.settings.mode, ScanMode::Thorough, tr.text("Deep"))
                                .on_hover_text(tr.text("Probe silent addresses for extra services; longer timeouts and discovery window."));
                            let fast = ui.selectable_value(&mut self.settings.mode, ScanMode::Fast, tr.text("Fast"))
                                .on_hover_text(tr.text("Enrich responding devices; bounded ARP waits and higher TCP concurrency. Slower devices may need Deep."));
                            #[cfg(feature = "gui-smoke")]
                            { self.smoke_mode_buttons = [Some(fast.rect.center()), Some(deep.rect.center())]; }
                            let _ = (deep, fast);
                        });
                        if previous != self.settings.mode {
                            self.settings.apply_mode_profile();
                        }
                    });
                });
                ui.horizontal(|ui| {
                    let mut enabled = self.udp_enabled();
                    let toggle = ui.add_enabled(self.scan.is_none(), egui::Checkbox::new(&mut enabled, "UDP"))
                        .on_hover_text(tr.text("Optional UDP ports and DNS/NTP/SNMP fetchers. Timeouts mean open or filtered, not closed."));
                    #[cfg(feature = "gui-smoke")]
                    { self.smoke_udp_button = Some(toggle.rect.center()); }
                    if toggle.changed() {
                        self.set_udp_enabled(enabled);
                    }
                    ui.label(tr.text("Ports"));
                    ui.add(egui::TextEdit::singleline(&mut self.settings.udp_ports)
                        .id(egui::Id::new("udp_ports")).desired_width(280.0)
                        .font(egui::TextStyle::Monospace).hint_text("53,123,161"));
                    egui::ComboBox::from_id_salt("udp_presets").width(100.0)
                        .selected_text(match self.settings.udp_ports.trim() {
                            udp::COMMON_PORTS => tr.text("Common"), "1-65535" => tr.text("All UDP"), "" => tr.text("Services"), _ => tr.text("Custom")
                        }).show_ui(ui, |ui| {
                            for (label, ports) in [(tr.text("Common"), udp::COMMON_PORTS), (tr.text("All UDP"), "1-65535"), (tr.text("Services"), "")] {
                                if ui.button(label).on_hover_text(if label == tr.text("All UDP") {
                                    tr.text("All UDP ports; usually much slower and less conclusive. Deep mode allows one retry.")
                                } else if label == tr.text("Services") {
                                    tr.text("Only selected DNS/NTP/SNMP service fetchers; no additional port list.")
                                } else { label }).clicked() { self.settings.udp_ports = ports.into(); }
                            }
                            if ui.button(tr.format("{0} Custom...", &[icons::PENCIL_SIMPLE.to_string()])).clicked() { self.edit_udp_ports(); }
                        });
                    if icon_button(ui, icons::PENCIL_SIMPLE, tr.text("Edit UDP ports")).clicked() { self.edit_udp_ports(); }
                });
            });
    }

    fn summary(&self, ctx: &egui::Context) {
        let tr = self.language.resolve();
        let vertical_margin = if ctx.content_rect().height() < 600.0 {
            8
        } else {
            14
        };
        egui::TopBottomPanel::top("summary")
            .frame(
                egui::Frame::new()
                    .fill(if self.settings.dark {
                        Color32::from_rgb(32, 36, 39)
                    } else {
                        Color32::from_rgb(244, 246, 248)
                    })
                    .inner_margin(egui::Margin::symmetric(22, vertical_margin)),
            )
            .show(ctx, |ui| {
                ui.columns(4, |columns| {
                    metric(
                        &mut columns[0],
                        tr.text("SCANNED"),
                        &format!("{} / {}", self.checked, self.total),
                        None,
                    );
                    metric(
                        &mut columns[1],
                        tr.text("ALIVE"),
                        &self.alive.to_string(),
                        Some(GREEN),
                    );
                    metric(
                        &mut columns[2],
                        tr.text("WITH OPEN PORTS"),
                        &self.with_ports.to_string(),
                        Some(BLUE),
                    );
                    metric(
                        &mut columns[3],
                        tr.text("ELAPSED"),
                        &format_duration(self.current_elapsed()),
                        None,
                    );
                });
                if self.scan.is_some() {
                    ui.add_space(8.0);
                    ui.add(
                        egui::ProgressBar::new(self.checked as f32 / self.total.max(1) as f32)
                            .desired_height(4.0)
                            .fill(GREEN),
                    );
                }
            });
    }

    fn current_elapsed(&self) -> Duration {
        if self.scan.is_some() {
            self.started.map(|s| s.elapsed()).unwrap_or_default()
        } else {
            self.elapsed
        }
    }

    fn status_bar(&self, ctx: &egui::Context) {
        let tr = self.language.resolve();
        let message = self.message.render(tr);
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if self.scan.is_some() {
                    ui.spinner();
                }
                let width = (ui.available_width() - 210.0).max(80.0);
                ui.add_sized(
                    [width, 20.0],
                    egui::Label::new(RichText::new(&message).size(12.0))
                        .truncate()
                        .sense(egui::Sense::hover()),
                )
                .on_hover_text(&message);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(tr.format(
                            "{0} shown  /  {1} results",
                            &[
                                format!("{}", self.visible.len()),
                                format!("{}", self.hosts.len()),
                            ],
                        ))
                        .size(12.0)
                        .color(MUTED),
                    );
                });
            });
        });
    }

    fn details(&mut self, ctx: &egui::Context) {
        let tr = self.language.resolve();
        let host = self
            .selected
            .and_then(|ip| self.hosts.iter().find(|host| host.ip == ip));
        if let Some(host) = host {
            egui::SidePanel::right("details")
                .resizable(true)
                .default_width(270.0)
                .min_width(220.0)
                .max_width(360.0)
                .show(ctx, |ui| {
                    ui.add_space(10.0);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(tr.text("Host details")).strong());
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if icon_button(ui, icons::X, tr.text("Close details")).clicked() {
                                self.selected = None;
                            }
                        });
                    });
                    ui.separator();
                    let scroll = egui::ScrollArea::vertical().auto_shrink([false, false]);
                    #[cfg(feature = "gui-smoke")]
                    let scroll = scroll.vertical_scroll_offset(self.smoke_details_offset);
                    scroll.show(ui, |ui| {
                        ui.label(
                            RichText::new(host.ip.to_string())
                                .size(22.0)
                                .monospace()
                                .strong(),
                        );
                        ui.label(
                            RichText::new(tr.text(host.status.label()))
                                .color(status_color(host.status)),
                        );
                        ui.add_space(8.0);
                        detail(
                            ui,
                            tr.text("Host discovery"),
                            if host.discovery_complete() {
                                tr.text("Complete")
                            } else {
                                tr.text("Incomplete")
                            },
                        );
                        detail(ui, tr.text("Hostname"), &host.hostname);
                        detail(ui, tr.text("Ping"), &ping_text(host.ping_ms));
                        detail(ui, tr.text("MAC address"), &host.mac);
                        detail(ui, tr.text("Manufacturer"), &host.vendor);
                        if host.vendor.is_empty() {
                            detail(ui, tr.text("Probable brand"), &host.probable_brand);
                        }
                        detail(
                            ui,
                            tr.text("ARP response"),
                            if host.arp_response {
                                tr.text("Yes")
                            } else {
                                tr.text("Not tested / no response")
                            },
                        );
                        detail(ui, tr.text("Open TCP ports"), &ports_text(&host.open_ports));
                        detail(
                            ui,
                            tr.text("Refused TCP ports"),
                            &host.refused_ports.to_string(),
                        );
                        for fetcher in [
                            Fetcher::Ttl,
                            Fetcher::PacketLoss,
                            Fetcher::Netbios,
                            Fetcher::WebDetect,
                            Fetcher::HttpStatus,
                            Fetcher::WebUrl,
                            Fetcher::Bonjour,
                            Fetcher::Wsd,
                            Fetcher::Ssdp,
                            Fetcher::Mndp,
                            Fetcher::Ubiquiti,
                            Fetcher::Llmnr,
                            Fetcher::ServiceBanners,
                            Fetcher::ServiceDetails,
                            Fetcher::NetworkPath,
                            Fetcher::TlsCertificates,
                            Fetcher::WebTitle,
                            Fetcher::DeviceIdentity,
                            Fetcher::UdpPorts,
                            Fetcher::UdpStatus,
                            Fetcher::DnsInfo,
                            Fetcher::NtpInfo,
                            Fetcher::SnmpInfo,
                        ] {
                            let value = fetcher_display_value(tr, fetcher, host);
                            if !value.is_empty() {
                                detail(ui, tr.text(fetcher.label()), &value);
                            }
                        }
                        if host.extra.packet_loss.is_some() {
                            detail(
                                ui,
                                tr.text("ICMP replies / samples"),
                                &format!("{} / {}", host.extra.icmp_received, host.extra.icmp_sent),
                            );
                        }
                        if !host.notes.is_empty() {
                            detail(ui, tr.text("Notes"), &host.notes);
                        }
                        ui.add_space(10.0);
                        ui.horizontal(|ui| {
                            if icon_button(ui, icons::COPY, tr.text("Copy host details")).clicked()
                            {
                                ctx.copy_text(host_text(host));
                            }
                            if (!host.extra.web.is_empty()
                                || host.open_ports.contains(&443)
                                || host.open_ports.contains(&80))
                                && icon_button(ui, icons::GLOBE, tr.text("Open host web page"))
                                    .clicked()
                            {
                                let scheme = if host.open_ports.contains(&443) {
                                    "https"
                                } else {
                                    "http"
                                };
                                let url = host
                                    .extra
                                    .web
                                    .first()
                                    .map(|service| service.url.clone())
                                    .unwrap_or_else(|| format!("{scheme}://{}", host.ip));
                                ctx.open_url(egui::OpenUrl::new_tab(url));
                            }
                        });
                    });
                });
        }
    }

    fn results(&mut self, ctx: &egui::Context) {
        let tr = self.language.resolve();
        egui::CentralPanel::default()
            .frame(egui::Frame::central_panel(&ctx.style()).inner_margin(egui::Margin::same(18)))
            .show(ctx, |ui| {
                ui.horizontal_wrapped(|ui| {
                    for (filter, label) in [
                        (Filter::All, tr.text("All hosts")),
                        (Filter::Alive, tr.text("Alive")),
                        (Filter::OpenPorts, tr.text("Open ports")),
                        (Filter::NoResponse, tr.text("No response")),
                    ] {
                        if ui
                            .selectable_value(&mut self.filter, filter, label)
                            .changed()
                        {
                            self.dirty = true;
                        }
                    }
                });
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(icons::MAGNIFYING_GLASS)
                            .size(18.0)
                            .color(MUTED),
                    );
                    if ui
                        .add(
                            egui::TextEdit::singleline(&mut self.query)
                                .desired_width((ui.available_width() - 255.0).max(100.0))
                                .hint_text(tr.text("Filter hosts")),
                        )
                        .changed()
                    {
                        self.dirty = true;
                    }
                    self.rebuild_visible();
                    for (column, label, tooltip) in [
                        (
                            AddressColumn::Ip,
                            "IP",
                            tr.text("Copy visible IP addresses"),
                        ),
                        (
                            AddressColumn::Mac,
                            "MAC",
                            tr.text("Copy visible MAC addresses (skip missing values)"),
                        ),
                    ] {
                        let feedback_id = egui::Id::new(("copy_visible", column));
                        let confirmed = copy_confirmed(ctx, feedback_id);
                        let available = match column {
                            AddressColumn::Ip => !self.visible.is_empty(),
                            AddressColumn::Mac => {
                                self.visible.iter().any(|&i| !self.hosts[i].mac.is_empty())
                            }
                        };
                        let icon = if confirmed { icons::CHECK } else { icons::COPY };
                        let mut text = RichText::new(format!("{icon} {label}"));
                        if confirmed {
                            text = text.color(GREEN);
                        }
                        let copy = ui.add_enabled(
                            available,
                            egui::Button::new(text).min_size(egui::vec2(56.0, 32.0)),
                        );
                        if !confirmed {
                            copy.clone().on_hover_text(tooltip);
                        }
                        #[cfg(feature = "gui-smoke")]
                        {
                            self.smoke_copy_buttons[match column {
                                AddressColumn::Ip => 0,
                                AddressColumn::Mac => 1,
                            }] = Some(copy.rect.center());
                        }
                        if copy.clicked() {
                            let text =
                                address_list(self.visible.iter().map(|&i| &self.hosts[i]), column);
                            self.message = Message::new(
                                "Copied {0} {1} addresses",
                                vec![text.lines().count().to_string(), label.to_owned()],
                            );
                            copy_with_feedback(ctx, feedback_id, text);
                        }
                        show_copy_confirmation(&copy, feedback_id, tr);
                    }
                    ui.add_enabled_ui(
                        !self.hosts.is_empty() && self.export_result.is_none(),
                        |ui| {
                            if icon_button(
                                ui,
                                icons::DOWNLOAD_SIMPLE,
                                tr.text("Export visible results to CSV"),
                            )
                            .clicked()
                            {
                                self.rebuild_visible();
                                self.begin_export(ctx);
                            }
                        },
                    );
                    ui.add_enabled_ui(
                        self.scan.is_none() && !self.workflow.busy() && !self.hosts.is_empty(),
                        |ui| {
                            if icon_button(ui, icons::TRASH, tr.text("Clear scan results"))
                                .clicked()
                            {
                                self.workflow.clear_current();
                                self.hosts.clear();
                                self.host_positions.clear();
                                self.view.clear();
                                self.visible.clear();
                                self.selected = None;
                                self.alive = 0;
                                self.with_ports = 0;
                                self.total = 0;
                                self.checked = 0;
                                self.scan_complete = true;
                                self.elapsed = Duration::ZERO;
                                self.message = "Ready".into();
                                self.warnings.clear();
                                self.error = None;
                                self.dirty = true;
                            }
                        },
                    );
                });
                if let Some(error) = self.error.clone() {
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(RED, tr.error(&error));
                        if icon_button(ui, icons::X, tr.text("Dismiss error")).clicked() {
                            self.error = None;
                        }
                    });
                }
                for warning in &self.warnings {
                    ui.colored_label(Color32::from_rgb(170, 119, 17), tr.text(warning));
                }
                ui.add_space(4.0);
                ui.separator();
                self.rebuild_visible();
                if self.hosts.is_empty() && self.scan.is_none() {
                    ui.add_space((ui.available_height() * 0.30).max(12.0));
                    ui.vertical_centered(|ui| {
                        ui.label(RichText::new(icons::NETWORK).size(44.0).color(MUTED));
                        ui.add_space(8.0);
                        ui.label(
                            RichText::new(tr.text("No scan results"))
                                .size(18.0)
                                .strong(),
                        );
                    });
                } else if self.visible.is_empty() {
                    ui.add_space(25.0);
                    ui.label(if self.scan.is_some() && self.hosts.is_empty() {
                        tr.text("Scanning...")
                    } else {
                        tr.text("No matching hosts")
                    });
                } else {
                    self.table(ui, ctx);
                }
            });
    }

    fn table(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let tr = self.language.resolve();
        let fetchers = self.selected_fetchers().to_vec();
        let mut headers = vec![
            (Sort::Ip, tr.text("IP address")),
            (Sort::Status, tr.text("Status")),
        ];
        headers.extend(
            fetchers
                .iter()
                .map(|fetcher| (fetcher_sort(*fetcher), tr.text(fetcher.label()))),
        );
        let content_width = 310.0
            + fetchers
                .iter()
                .map(|fetcher| fetcher.width() + 10.0)
                .sum::<f32>();
        let mut new_sort = None;
        let mut rescan = None;
        let table_height = (ui.available_height()
            - ui.spacing().scroll.bar_width
            - ui.spacing().scroll.bar_outer_margin)
            .max(0.0);
        let body_height = (table_height - 34.0 - ui.spacing().item_spacing.y).max(0.0);
        let viewport_width = ui.available_width();
        let scroll = egui::ScrollArea::horizontal().auto_shrink([false, false]);
        #[cfg(feature = "gui-smoke")]
        let scroll = scroll.horizontal_scroll_offset(self.smoke_offset);
        let table_scroll = scroll.show(ui, |ui| {
            ui.set_width(ui.available_width().max(content_width));
            let mut table = TableBuilder::new(ui)
                .id_salt(("results_fetchers", &fetchers))
                .min_scrolled_height(0.0)
                .max_scroll_height(body_height)
                .striped(true)
                .resizable(true)
                .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
                .sense(egui::Sense::click())
                .column(Column::initial(170.0).at_least(145.0).clip(true));
            table = table.column(if fetchers.is_empty() {
                Column::remainder().at_least(115.0).clip(true)
            } else {
                Column::initial(115.0).at_least(105.0).clip(true)
            });
            for (index, fetcher) in fetchers.iter().enumerate() {
                table = table.column(if index == fetchers.len() - 1 {
                    Column::remainder().at_least(fetcher.width()).clip(true)
                } else {
                    Column::initial(fetcher.width())
                        .at_least((fetcher.width() - 25.0).max(75.0))
                        .clip(true)
                });
            }
            table
                .header(34.0, |mut header| {
                    for (sort, label) in headers {
                        header.col(|ui| {
                            let arrow = if self.sort == sort {
                                if self.descending {
                                    icons::CARET_DOWN
                                } else {
                                    icons::CARET_UP
                                }
                            } else {
                                ""
                            };
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new(format!("{label} {arrow}")).strong(),
                                    )
                                    .frame(false),
                                )
                                .clicked()
                            {
                                new_sort = Some(sort);
                            }
                        });
                    }
                })
                .body(|body| {
                    body.rows(34.0, self.visible.len(), |mut row| {
                        let index = row.index();
                        let host = &self.hosts[self.visible[index]];
                        row.set_selected(self.workflow.selected.contains(&host.ip));
                        row.col(|ui| {
                            let copy = address_cell(
                                ui,
                                ctx,
                                &host.ip.to_string(),
                                tr.text("Copy IP address"),
                                egui::Id::new(("copy_address", host.ip, AddressColumn::Ip)),
                                tr,
                            );
                            #[cfg(feature = "gui-smoke")]
                            if index == 0 {
                                self.smoke_copy_buttons[2] = Some(copy.rect.center());
                            }
                            #[cfg(not(feature = "gui-smoke"))]
                            let _ = copy;
                        });
                        row.col(|ui| {
                            let (rect, _) =
                                ui.allocate_exact_size(egui::vec2(8.0, 8.0), egui::Sense::hover());
                            ui.painter().circle_filled(
                                rect.center(),
                                3.5,
                                status_color(host.status),
                            );
                            ui.colored_label(
                                status_color(host.status),
                                tr.text(host.status.label()),
                            );
                        });
                        for fetcher in &fetchers {
                            row.col(|ui| match fetcher {
                                Fetcher::Ping => {
                                    ui.label(ping_text(host.ping_ms));
                                }
                                Fetcher::Ports => {
                                    ui.colored_label(
                                        BLUE,
                                        display_value(&ports_text(&host.open_ports)),
                                    );
                                }
                                Fetcher::MacAddress => {
                                    let copy = address_cell(
                                        ui,
                                        ctx,
                                        &host.mac,
                                        tr.text("Copy MAC address"),
                                        egui::Id::new((
                                            "copy_address",
                                            host.ip,
                                            AddressColumn::Mac,
                                        )),
                                        tr,
                                    );
                                    #[cfg(feature = "gui-smoke")]
                                    if index == 0 {
                                        self.smoke_copy_buttons[3] = Some(copy.rect.center());
                                    }
                                    #[cfg(not(feature = "gui-smoke"))]
                                    let _ = copy;
                                }
                                fetcher => cell(ui, &fetcher_display_value(tr, *fetcher, host)),
                            });
                        }
                        let response = row.response();
                        if response.clicked() {
                            self.selected = Some(host.ip);
                            if ctx.input(|input| input.modifiers.ctrl || input.modifiers.command) {
                                if !self.workflow.selected.insert(host.ip) {
                                    self.workflow.selected.remove(&host.ip);
                                }
                            } else {
                                self.workflow.selected.clear();
                                self.workflow.selected.insert(host.ip);
                            }
                        }
                        response.context_menu(|ui| {
                            if ui
                                .add_enabled(
                                    self.scan.is_none(),
                                    egui::Button::new(tr.text("Rescan selected devices")),
                                )
                                .clicked()
                            {
                                rescan = Some(if self.workflow.selected.contains(&host.ip) {
                                    self.workflow.selected.iter().copied().collect()
                                } else {
                                    vec![host.ip]
                                });
                                ui.close();
                            }
                            if ui
                                .button(
                                    tr.format("{0} Copy IP address", &[icons::COPY.to_string()]),
                                )
                                .clicked()
                            {
                                ctx.copy_text(host.ip.to_string());
                                ui.close();
                            }
                            if ui
                                .add_enabled(
                                    !host.mac.is_empty(),
                                    egui::Button::new(tr.format(
                                        "{0} Copy MAC address",
                                        &[icons::COPY.to_string()],
                                    )),
                                )
                                .clicked()
                            {
                                ctx.copy_text(host.mac.clone());
                                ui.close();
                            }
                            if ui
                                .button(
                                    tr.format("{0} Copy host details", &[icons::COPY.to_string()]),
                                )
                                .clicked()
                            {
                                ctx.copy_text(host_text(host));
                                ui.close();
                            }
                        });
                    });
                });
        });
        #[cfg(feature = "gui-smoke")]
        if self.selected.is_some() {
            assert!(table_scroll.inner_rect.width() <= viewport_width + 1.0);
            assert!(table_scroll.content_size.x >= content_width - 1.0);
            if self.smoke_offset > 0.0 {
                assert!(table_scroll.state.offset.x > 500.0);
            }
        }
        #[cfg(not(feature = "gui-smoke"))]
        let _ = (table_scroll, viewport_width);
        if let Some(sort) = new_sort {
            if self.sort == sort {
                self.descending = !self.descending;
            } else {
                self.sort = sort;
                self.descending = false;
            }
            self.dirty = true;
        }
        if let Some(ips) = rescan {
            self.begin_selected_scan(ctx, ips);
        }
    }

    fn fetchers_window(&mut self, ctx: &egui::Context) {
        let tr = self.language.resolve();
        let mut open = self.show_fetchers;
        let mut apply = false;
        let mut cancel = false;
        egui::Window::new(tr.text("Fetchers"))
            .id(egui::Id::new("fetchers_window"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.vertical(|ui| {
                        ui.set_width(216.0);
                        ui.label(RichText::new(tr.text("Selected fetchers")).strong());
                        egui::Frame::group(ui.style())
                            .corner_radius(4)
                            .show(ui, |ui| {
                                ui.set_min_width(200.0);
                                egui::ScrollArea::vertical()
                                    .id_salt("selected_fetchers")
                                    .min_scrolled_height(230.0)
                                    .max_height(230.0)
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        for fetcher in self.fetchers_draft.selected.clone() {
                                            let row = ui
                                                .selectable_value(
                                                    &mut self.fetchers_draft.selected_row,
                                                    Some(fetcher),
                                                    tr.text(fetcher.label()),
                                                )
                                                .on_hover_text(tr.text(fetcher.help()));
                                            if self.fetcher_scroll_selected
                                                && self.fetchers_draft.selected_row == Some(fetcher)
                                            {
                                                row.scroll_to_me(Some(egui::Align::Center));
                                                self.fetcher_scroll_selected = false;
                                            }
                                        }
                                    });
                            });
                    });
                    ui.vertical(|ui| {
                        ui.add_space(50.0);
                        let index = self.fetchers_draft.selected_index();
                        let up = ui
                            .add_enabled(
                                index.is_some_and(|i| i > 0),
                                egui::Button::new(icons::ARROW_UP).min_size(egui::vec2(32.0, 32.0)),
                            )
                            .on_hover_text(tr.text("Move selected fetcher up"));
                        #[cfg(feature = "gui-smoke")]
                        {
                            self.smoke_fetcher_buttons[3] = Some(up.rect.center());
                        }
                        if up.clicked() {
                            self.fetchers_draft.move_selected(-1);
                            self.fetcher_scroll_selected = true;
                        }
                        if ui
                            .add_enabled(
                                index.is_some_and(|i| i + 1 < self.fetchers_draft.selected.len()),
                                egui::Button::new(icons::ARROW_DOWN)
                                    .min_size(egui::vec2(32.0, 32.0)),
                            )
                            .on_hover_text(tr.text("Move selected fetcher down"))
                            .clicked()
                        {
                            self.fetchers_draft.move_selected(1);
                            self.fetcher_scroll_selected = true;
                        }
                        ui.add_space(8.0);
                        let add = ui
                            .add_enabled(
                                self.fetchers_draft.available_row.is_some(),
                                egui::Button::new(icons::ARROW_LEFT)
                                    .min_size(egui::vec2(32.0, 32.0)),
                            )
                            .on_hover_text(tr.text("Add available fetcher"));
                        #[cfg(feature = "gui-smoke")]
                        {
                            self.smoke_fetcher_buttons[2] = Some(add.rect.center());
                        }
                        if add.clicked() {
                            self.fetchers_draft.add();
                            self.fetcher_scroll_selected = true;
                        }
                        let remove = ui
                            .add_enabled(
                                self.fetchers_draft.selected_row.is_some(),
                                egui::Button::new(icons::ARROW_RIGHT)
                                    .min_size(egui::vec2(32.0, 32.0)),
                            )
                            .on_hover_text(tr.text("Remove selected fetcher"));
                        #[cfg(feature = "gui-smoke")]
                        {
                            self.smoke_fetcher_buttons[4] = Some(remove.rect.center());
                        }
                        if remove.clicked() {
                            self.fetchers_draft.remove();
                            self.fetcher_scroll_selected = true;
                        }
                    });
                    ui.vertical(|ui| {
                        ui.set_width(216.0);
                        ui.label(RichText::new(tr.text("Available fetchers")).strong());
                        egui::Frame::group(ui.style())
                            .corner_radius(4)
                            .show(ui, |ui| {
                                ui.set_min_width(200.0);
                                egui::ScrollArea::vertical()
                                    .id_salt("available_fetchers")
                                    .min_scrolled_height(230.0)
                                    .max_height(230.0)
                                    .auto_shrink([false, false])
                                    .show(ui, |ui| {
                                        for fetcher in self.fetchers_draft.available() {
                                            let row = ui.add_enabled_ui(fetcher_supported(fetcher), |ui| ui
                                                .selectable_value(
                                                    &mut self.fetchers_draft.available_row,
                                                    Some(fetcher),
                                                    tr.text(fetcher.label()),
                                                )
                                                .on_hover_text(tr.text(fetcher.help()))).inner;
                                            #[cfg(feature = "gui-smoke")]
                                            if fetcher == Fetcher::ArpResponse {
                                                self.smoke_fetcher_buttons[1] =
                                                    Some(row.rect.center());
                                            }
                                            #[cfg(not(feature = "gui-smoke"))]
                                            let _ = row;
                                        }
                                    });
                            });
                    });
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    let defaults =
                        ui.button(tr.format("{0} Defaults", &[icons::ARROW_COUNTER_CLOCKWISE.to_string()]));
                    #[cfg(feature = "gui-smoke")]
                    {
                        self.smoke_fetcher_buttons[7] = Some(defaults.rect.center());
                    }
                    if defaults.clicked() {
                        self.fetchers_draft = FetcherDraft::new(fetchers::defaults().into_iter().filter(|&fetcher| fetcher_supported(fetcher)).collect());
                    }
                    let inventory = ui.button(tr.format("{0} Inventory", &[icons::LIST_CHECKS.to_string()])).on_hover_text(tr.text("Select inventory fetchers; keeps the current TCP port list. The Inventory TCP preset includes common device services."));
                    #[cfg(feature = "gui-smoke")]
                    { self.smoke_fetcher_buttons[8] = Some(inventory.rect.center()); }
                    if inventory.clicked() {
                        self.fetchers_draft = FetcherDraft::new(fetchers::inventory().into_iter().filter(|&fetcher| fetcher_supported(fetcher)).collect());
                    }
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let cancel_button = ui.button(tr.text("Cancel"));
                        #[cfg(feature = "gui-smoke")]
                        {
                            self.smoke_fetcher_buttons[6] = Some(cancel_button.rect.center());
                        }
                        cancel = cancel_button.clicked();
                        let apply_button = ui.button(tr.format("{0} Apply", &[icons::CHECK.to_string()]));
                        #[cfg(feature = "gui-smoke")]
                        {
                            self.smoke_fetcher_buttons[5] = Some(apply_button.rect.center());
                        }
                        apply = apply_button.clicked();
                    });
                });
                cancel |= ui.input(|input| input.key_pressed(egui::Key::Escape));
            });
        self.show_fetchers = open && !cancel;
        if apply {
            self.apply_fetchers();
        }
    }

    fn windows(&mut self, ctx: &egui::Context) {
        let tr = self.language.resolve();
        self.fetchers_window(ctx);
        let mut ports_open = self.show_ports_editor;
        let mut apply_ports = false;
        let mut cancel_ports = false;
        let protocol = if self.ports_are_udp { "UDP" } else { "TCP" };
        egui::Window::new(tr.format("Custom {0} ports", &[protocol.to_owned()]))
            .id(egui::Id::new("custom_ports_window"))
            .open(&mut ports_open)
            .collapsible(false)
            .resizable(false)
            .default_pos(ctx.content_rect().center() - egui::vec2(210.0, 100.0))
            .default_width(400.0)
            .show(ctx, |ui| {
                ui.scope(|ui| {
                    ui.label(if self.ports_are_udp {
                        tr.text("UDP ports")
                    } else {
                        tr.text("TCP ports")
                    });
                    let editor = ui.add(
                        egui::TextEdit::singleline(&mut self.ports_draft)
                            .id(egui::Id::new("custom_ports_draft"))
                            .font(egui::TextStyle::Monospace)
                            .desired_width(390.0)
                            .hint_text("22,80,443,8000-8010"),
                    );
                    #[cfg(feature = "gui-smoke")]
                    {
                        self.smoke_port_buttons[1] = Some(editor.rect.center());
                    }
                    if self.ports_focus {
                        editor.request_focus();
                        self.ports_focus = false;
                    }
                    if editor.changed() {
                        self.ports_error = None;
                    }
                    if let Some(error) = &self.ports_error {
                        ui.colored_label(RED, tr.error(error));
                    }
                    if let Ok(ports) = parse_ports(&self.ports_draft) {
                        ui.label(if ports.is_empty() {
                            tr.format("No {0} ports", &[protocol.to_string()])
                        } else {
                            tr.format(
                                "{0} {1} ports",
                                &[format!("{}", ports.len()), protocol.to_string()],
                            )
                        });
                    }
                    ui.horizontal(|ui| {
                        let apply = ui.button(tr.format("{0} Apply", &[icons::CHECK.to_string()]));
                        #[cfg(feature = "gui-smoke")]
                        {
                            self.smoke_port_buttons[2] = Some(apply.rect.center());
                        }
                        apply_ports = apply.clicked();
                        cancel_ports = ui.button(tr.text("Cancel")).clicked();
                    });
                    apply_ports |= editor.lost_focus()
                        && ui.input(|input| input.key_pressed(egui::Key::Enter));
                    cancel_ports |= ui.input(|input| input.key_pressed(egui::Key::Escape));
                });
            });
        self.show_ports_editor = ports_open && !cancel_ports;
        if apply_ports {
            self.apply_ports();
        }
        let mut edit_fetchers = false;
        egui::Window::new(tr.text("Scan settings"))
            .id(egui::Id::new("scan_settings"))
            .open(&mut self.show_settings)
            .collapsible(false)
            .resizable(false)
            .vscroll(true)
            .max_height((ctx.content_rect().height() - 60.0).max(240.0))
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.label(tr.text("Interface language"));
                    let previous = self.language;
                    let picker = egui::ComboBox::from_id_salt("interface_language")
                        .width(205.0)
                        .selected_text(match self.language {
                            Language::Auto => tr.text("Automatic (system)"),
                            Language::English => "English",
                            Language::French => "Français",
                        })
                        .show_ui(ui, |ui| {
                            let automatic = ui.selectable_value(&mut self.language, Language::Auto, tr.text("Automatic (system)"))
                                .on_hover_text(tr.text("Follows the system display language. Unsupported languages use English."));
                            let english = ui.selectable_value(&mut self.language, Language::English, "English");
                            let french = ui.selectable_value(&mut self.language, Language::French, "Français");
                            #[cfg(feature = "gui-smoke")]
                            {
                                self.smoke_language_buttons[1] = Some(automatic.rect.center());
                                self.smoke_language_buttons[2] = Some(english.rect.center());
                                self.smoke_language_buttons[3] = Some(french.rect.center());
                            }
                            #[cfg(not(feature = "gui-smoke"))]
                            let _ = (automatic, english, french);
                        });
                    #[cfg(feature = "gui-smoke")]
                    { self.smoke_language_buttons[0] = Some(picker.response.rect.center()); }
                    #[cfg(not(feature = "gui-smoke"))]
                    let _ = picker;
                    if self.language != previous {
                        ctx.request_repaint();
                    }
                });
                ui.separator();
                ui.add_enabled_ui(self.scan.is_none(), |ui| {
                    egui::Grid::new("settings_grid")
                        .spacing([24.0, 16.0])
                        .show(ui, |ui| {
                            ui.label(tr.text("Probe timeout"));
                            ui.add(
                                egui::DragValue::new(&mut self.settings.timeout_ms)
                                    .range(100..=5000)
                                    .speed(50)
                                    .suffix(" ms"),
                            );
                            ui.end_row();
                            ui.label(tr.text("Max workers"));
                            ui.add(egui::DragValue::new(&mut self.settings.workers).range(1..=scanner::MAX_HOST_WORKERS));
                            ui.end_row();
                            ui.label(tr.text("Scan adaptation"));
                            ui.checkbox(&mut self.settings.adaptive_concurrency, tr.text("Adaptive"))
                                .on_hover_text(tr.text("Adjusts workers and routed TCP/ICMP pacing independently for each interface/next hop. Learns per-host deadlines from latency and jitter: 50 ms minimum on LAN, 100 ms routed, up to 4× the initial timeout (maximum 5 seconds). Unmeasured hosts keep the initial timeout."));
                            ui.end_row();
                            ui.label(tr.text("ICMP samples"));
                            ui.add(egui::DragValue::new(&mut self.settings.icmp_samples).range(1..=10))
                                .on_hover_text(tr.text("Used only with Packet loss selected. Other scans send one ping per host."));
                            ui.end_row();
                            ui.label(tr.text("Fetchers"));
                            edit_fetchers = ui
                                .button(tr.format("{0} Configure", &[icons::LIST_CHECKS.to_string()]))
                                .clicked();
                            ui.end_row();
                            ui.label(tr.text("Discovery window"));
                            ui.add(egui::DragValue::new(&mut self.settings.discovery_seconds).range(1..=120).suffix(" s"))
                                .on_hover_text(tr.text("Shared local discovery time per scan, only when selected. MNDP advertisements are periodic; allow 30-120 seconds when needed. UPnP descriptions add at most two seconds."));
                            ui.end_row();
                            ui.label(tr.text("HTTPS web probes"));
                            ui.checkbox(&mut self.settings.allow_unverified_tls, tr.text("Allow unverified TLS"))
                                .on_hover_text(tr.text("Off by default. Enables detection on self-signed HTTPS services; these results are labeled TLS unverified."));
                            ui.end_row();
                            ui.label(tr.text("Local discovery"));
                            ui.add_enabled(network::ARP_SUPPORTED, egui::Checkbox::new(
                                &mut self.settings.discover_arp, tr.text("Confirm ARP-only devices")));
                            ui.end_row();
                            ui.label(tr.text("SNMPv2c community"));
                            ui.add(egui::TextEdit::singleline(&mut self.settings.snmp_community)
                                .password(true).char_limit(255).desired_width(230.0))
                                .on_hover_text(tr.text("Optional and not saved. Sent unencrypted for read-only SNMPv2c GET when SNMP info or UDP 161 is selected. No default guessing or writes."));
                            ui.end_row();
                        });
                });
                if !network::ARP_SUPPORTED || !network::ROUTE_SUPPORTED {
                    ui.small(tr.text("Initial Linux support: ARP/MAC discovery and per-interface route inspection are not yet available."));
                }
            });
        if edit_fetchers {
            self.show_settings = false;
            self.edit_fetchers();
        }
        egui::Window::new(tr.text("About IP Scout"))
            .id(egui::Id::new("about_window"))
            .open(&mut self.show_about)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.heading("IP Scout");
                ui.label(tr.format("Version {0}", &[env!("CARGO_PKG_VERSION").to_string()]));
                ui.label(tr.format("License: {0}", &[env!("CARGO_PKG_LICENSE").to_string()]));
                ui.label(tr.text("An independent scanner inspired by Angry IP Scanner."));
                ui.label(if cfg!(target_os = "linux") {
                    "Rust / egui / Linux ICMP"
                } else {
                    "Rust / egui / Windows ICMP"
                });
                ui.separator();
                ui.hyperlink_to(
                    tr.text("Manufacturer data: IEEE Registration Authority"),
                    "https://standards-oui.ieee.org/oui/oui.csv",
                );
            });
    }
}

#[cfg(feature = "gui-smoke")]
#[allow(
    dead_code,
    reason = "These helpers are consumed by the GUI smoke example"
)]
impl ScoutApp {
    pub fn smoke_language_setup(&mut self, ctx: &egui::Context) {
        self.language = Language::English;
        self.settings = Settings::default();
        self.settings.normalize_fetchers();
        self.settings.target = "192.0.2.0/24".into();
        let mut host = smoke_host("192.0.2.1", "02:11:22:33:44:55");
        host.hostname = "café-router-{0}".into();
        host.vendor = "Example Networks".into();
        host.open_ports = vec![80, 443];
        self.hosts = vec![host];
        self.host_positions = HashMap::from([(self.hosts[0].ip, 0)]);
        self.total = 254;
        self.checked = 254;
        self.alive = 1;
        self.with_ports = 1;
        self.scan_complete = true;
        self.message = "Scan complete".into();
        self.show_settings = true;
        self.show_about = false;
        self.show_fetchers = false;
        self.view.clear();
        self.dirty = true;
        apply_theme(ctx, false);
    }

    pub fn smoke_language_layout(&mut self, stage: usize, ctx: &egui::Context) {
        let small = stage >= 2;
        ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(if small {
            egui::vec2(820.0, 540.0)
        } else {
            egui::vec2(1180.0, 760.0)
        }));
        self.settings.dark = small;
        apply_theme(ctx, small);
        self.show_settings = stage != 3;
        self.show_fetchers = stage == 3;
        if stage == 3 {
            self.edit_fetchers();
        }
        self.smoke_language_buttons = [None; 4];
    }

    pub fn smoke_language_click(&self, slot: usize) -> Option<Vec<egui::Event>> {
        let pos = self.smoke_language_buttons[slot]?;
        Some(vec![
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: Default::default(),
            },
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: Default::default(),
            },
        ])
    }

    pub fn smoke_language_verify(&self, stage: usize) {
        let expected = match stage {
            0 | 4 => Language::English,
            5 => Language::Auto,
            _ => Language::French,
        };
        assert_eq!(
            self.language, expected,
            "the language picker did not select its option"
        );
        assert_eq!(self.hosts[0].hostname, "café-router-{0}");
        assert_eq!(
            self.message.render(self.language.resolve()),
            self.language.resolve().text("Scan complete")
        );
    }

    pub fn smoke_stage(&mut self, stage: usize, port: u16, ctx: &egui::Context) {
        self.view.clear();
        match stage {
            0 => {
                self.settings.fetchers = Some(fetchers::defaults());
                self.settings.target = "127.0.0.1-3".into();
                self.settings.ports = port.to_string();
                self.settings.dark = false;
                apply_theme(ctx, false);
            }
            1 => {
                self.settings.timeout_ms = 200;
                self.settings.workers = 2;
                self.settings.resolve_names = false;
                self.settings.fetch_mac = false;
                self.settings.discover_arp = true;
                self.begin_scan(ctx);
            }
            2 => {
                assert_eq!(self.hosts.len(), 3);
                assert_eq!(self.with_ports, 1);
                self.selected = Some(Ipv4Addr::LOCALHOST);
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(820.0, 540.0)));
            }
            3 => {
                self.settings.dark = true;
                apply_theme(ctx, true);
                self.show_settings = true;
            }
            4 => {
                self.show_settings = false;
                self.smoke_offset = 600.0;
            }
            5 => {
                self.smoke_offset = 0.0;
                self.show_settings = false;
                self.selected = None;
                self.settings.dark = false;
                apply_theme(ctx, false);
                self.filter = Filter::OpenPorts;
                self.query = "127.0.0.1".into();
                self.sort = Sort::Ping;
                self.descending = true;
                self.dirty = true;
                self.rebuild_visible();
                assert_eq!(self.visible.len(), 1);
                let path = std::path::Path::new("artifacts/gui-scan.csv");
                export::save_csv(path, &[&self.hosts[self.visible[0]]]).unwrap();
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1180.0, 760.0)));
            }
            6 => {
                self.settings.target = "127.0.0.0/16".into();
                self.settings.workers = 1;
                self.begin_scan(ctx);
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(820.0, 540.0)));
            }
            7 => {}
            8 => {
                let previous = self.settings.ports.clone();
                self.edit_ports();
                self.ports_draft = "0,70000".into();
                self.apply_ports();
                assert!(self.ports_error.is_some());
                assert!(self.show_ports_editor);
                assert_eq!(self.settings.ports, previous);
            }
            9 => {
                self.show_ports_editor = false;
                self.hosts = vec![
                    smoke_host("192.0.2.1", "02:11:22:33:44:01"),
                    smoke_host("192.0.2.2", ""),
                    smoke_host("192.0.2.3", "02:11:22:33:44:03"),
                ];
                self.filter = Filter::All;
                self.query.clear();
                self.sort = Sort::Ip;
                self.descending = false;
                self.selected = None;
                self.total = 3;
                self.checked = 3;
                self.alive = 3;
                self.with_ports = 0;
                self.dirty = true;
            }
            10 => {
                self.query = "192.0.2.1".into();
                self.dirty = true;
            }
            12 => {
                self.selected = None;
                self.smoke_offset = 600.0;
            }
            14 => {
                self.smoke_offset = 0.0;
                self.selected = None;
                self.query.clear();
                self.dirty = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1180.0, 760.0)));
            }
            16 => {
                self.settings.dark = true;
                apply_theme(ctx, true);
                self.edit_fetchers();
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(820.0, 540.0)));
            }
            18 => {
                self.settings.dark = false;
                apply_theme(ctx, false);
                self.fetchers_draft = FetcherDraft::new(Vec::new());
                self.apply_fetchers();
                assert!(self.selected_fetchers().is_empty());
                self.selected = None;
            }
            19 => {
                self.fetchers_draft = FetcherDraft::new(Fetcher::ALL.to_vec());
                self.apply_fetchers();
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1180.0, 760.0)));
            }
            20 => {
                self.smoke_offset = 0.0;
                self.fetchers_draft = FetcherDraft::new(vec![
                    Fetcher::Ttl,
                    Fetcher::Netbios,
                    Fetcher::WebDetect,
                    Fetcher::PacketLoss,
                ]);
                self.apply_fetchers();
                for host in &mut self.hosts {
                    host.extra.ttl = Some(64);
                    host.extra.packet_loss = Some(0.0);
                    host.extra.icmp_sent = 3;
                    host.extra.icmp_received = 3;
                    host.extra.netbios = "SCOUT-PC (workstation, 00); WORKGROUP (group, 00)".into();
                    host.extra.web = vec![ip_scout::metadata::WebService {
                        url: format!("http://{}:8080/", host.ip),
                        server: "nginx/1.26".into(),
                        status: 200,
                        tls_unverified: false,
                        title: String::new(),
                    }];
                }
                self.dirty = true;
                let hosts: Vec<_> = self.hosts.iter().collect();
                export::save_csv_with_fetchers(
                    std::path::Path::new("artifacts/gui-new-fetchers.csv"),
                    &hosts,
                    &Fetcher::ALL,
                )
                .unwrap();
            }
            21 => {
                self.fetchers_draft = FetcherDraft::new(vec![Fetcher::HttpStatus, Fetcher::WebUrl]);
                self.apply_fetchers();
                self.settings.dark = true;
                apply_theme(ctx, true);
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(820.0, 540.0)));
            }
            22 => {
                self.smoke_details_offset = 500.0;
                self.selected = self.hosts.first().map(|host| host.ip);
            }
            23 => {
                self.selected = None;
                self.smoke_offset = 0.0;
                self.smoke_details_offset = 0.0;
                self.settings.dark = false;
                apply_theme(ctx, false);
                self.fetchers_draft = FetcherDraft::new(vec![Fetcher::Bonjour, Fetcher::Wsd]);
                self.apply_fetchers();
                for host in &mut self.hosts {
                    host.extra.bonjour = vec![ip_scout::discovery::BonjourService {
                        instance: "Lab Printer".into(),
                        service_type: "_ipp._tcp.local.".into(),
                        hostname: "printer.local".into(),
                        port: 631,
                        properties: vec!["ty=Laser printer".into()],
                    }];
                    host.extra.wsd = vec![ip_scout::discovery::WsdDevice {
                        endpoint: "urn:uuid:printer-1".into(),
                        types: vec!["wsdp:Device".into()],
                        scopes: vec!["urn:location:Lab".into()],
                        addresses: vec![format!("http://{}:5357/printer-1", host.ip)],
                    }];
                }
                self.dirty = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1180.0, 760.0)));
                let hosts: Vec<_> = self.hosts.iter().collect();
                export::save_csv_with_fetchers(
                    std::path::Path::new("artifacts/gui-discovery-fetchers.csv"),
                    &hosts,
                    self.selected_fetchers(),
                )
                .unwrap();
                assert!(host_text(&self.hosts[0]).contains("Bonjour / mDNS: Lab Printer"));
                assert!(host_text(&self.hosts[0]).contains("WSD info: wsdp:Device"));
            }
            24 => {
                self.query = "laser printer".into();
                self.dirty = true;
                self.settings.dark = true;
                apply_theme(ctx, true);
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(820.0, 540.0)));
            }
            25 => {
                self.edit_fetchers();
                self.fetchers_draft.selected_row = Some(Fetcher::Wsd);
                self.fetcher_scroll_selected = true;
            }
            26 => {
                self.show_fetchers = false;
                self.query.clear();
                self.smoke_offset = 0.0;
                self.settings.dark = false;
                apply_theme(ctx, false);
                self.fetchers_draft = FetcherDraft::new(vec![
                    Fetcher::Ssdp,
                    Fetcher::Mndp,
                    Fetcher::Ubiquiti,
                    Fetcher::Llmnr,
                ]);
                self.apply_fetchers();
                for host in &mut self.hosts {
                    host.extra.advertisements.ssdp = vec![ip_scout::advertisements::UpnpDevice {
                        usn: "uuid:lab-tv".into(),
                        device_type: "urn:schemas-upnp-org:device:MediaRenderer:1".into(),
                        server: "Linux/6.0 UPnP/1.0".into(),
                        location: format!("http://{}:8000/device.xml", host.ip),
                        name: "Lab TV".into(),
                        manufacturer: "Example manufacturer".into(),
                        model: "TV-1".into(),
                    }];
                    host.extra.advertisements.mndp = vec![ip_scout::advertisements::VendorDevice {
                        name: "lab-router".into(),
                        model: "hAP ax3".into(),
                        firmware: "RouterOS".into(),
                        platform: "MikroTik".into(),
                        interface: "ether1".into(),
                        mac: host.mac.clone(),
                    }];
                    host.extra.advertisements.ubiquiti =
                        vec![ip_scout::advertisements::VendorDevice {
                            name: "lab-ap".into(),
                            model: "U6-Lite".into(),
                            firmware: "test firmware".into(),
                            mac: host.mac.clone(),
                            ..Default::default()
                        }];
                    host.extra.llmnr = "LAB-PC".into();
                }
                self.dirty = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1180.0, 760.0)));
                export::save_csv_with_fetchers(
                    std::path::Path::new("artifacts/gui-advertisements.csv"),
                    &self.hosts.iter().collect::<Vec<_>>(),
                    self.selected_fetchers(),
                )
                .unwrap();
                let details = host_text(&self.hosts[0]);
                for phrase in [
                    "SSDP / UPnP: Lab TV",
                    "MikroTik MNDP: lab-router",
                    "Ubiquiti discovery: lab-ap",
                    "LLMNR hostname: LAB-PC",
                ] {
                    assert!(details.contains(phrase));
                }
                for fetcher in self.selected_fetchers() {
                    assert!(matches!(fetcher_sort(*fetcher), Sort::Metadata(_)));
                }
            }
            27 => {
                self.settings.dark = true;
                apply_theme(ctx, true);
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(820.0, 540.0)));
                self.fetchers_draft = FetcherDraft::new(vec![Fetcher::Llmnr]);
                self.apply_fetchers();
                self.query = "lab-pc".into();
                self.rebuild_visible();
                assert_eq!(self.visible.len(), self.hosts.len());
                self.query = "no-match-at-all".into();
                self.dirty = true;
                self.rebuild_visible();
                assert!(self.visible.is_empty());
                self.query = "lab-pc".into();
                self.dirty = true;
            }
            28 => {
                self.edit_fetchers();
                self.fetchers_draft = FetcherDraft::new(vec![
                    Fetcher::Ssdp,
                    Fetcher::Mndp,
                    Fetcher::Ubiquiti,
                    Fetcher::Llmnr,
                ]);
                self.fetchers_draft.selected_row = Some(Fetcher::Llmnr);
                self.fetcher_scroll_selected = true;
            }
            29 => {
                self.show_fetchers = false;
                self.query.clear();
                self.settings.dark = false;
                apply_theme(ctx, false);
                self.smoke_offset = 0.0;
                self.fetchers_draft = FetcherDraft::new(vec![
                    Fetcher::ServiceBanners,
                    Fetcher::TlsCertificates,
                    Fetcher::WebTitle,
                    Fetcher::DeviceIdentity,
                ]);
                self.apply_fetchers();
                for host in &mut self.hosts {
                    host.extra.banners = vec![ip_scout::inventory::ServiceBanner {
                        port: 22,
                        text: "SSH-2.0-OpenSSH_9.6".into(),
                    }];
                    host.extra.certificates = vec![ip_scout::inventory::TlsCertificate {
                        server_name: String::new(),
                        port: 8080,
                        common_name: "lab-nas.local".into(),
                        subject: "CN=lab-nas.local".into(),
                        issuer: "CN=Lab CA".into(),
                        names: vec!["lab-nas.local".into()],
                        valid_from: "2026-01-01".into(),
                        valid_until: "2027-01-01".into(),
                        serial: "01:02".into(),
                    }];
                    host.extra.web = vec![ip_scout::metadata::WebService {
                        url: format!("https://{}:8080/", host.ip),
                        server: "nginx".into(),
                        status: 200,
                        tls_unverified: true,
                        title: "Secure NAS console".into(),
                    }];
                }
                self.dirty = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1180.0, 760.0)));
                export::save_csv_with_fetchers(
                    std::path::Path::new("artifacts/gui-inventory.csv"),
                    &self.hosts.iter().collect::<Vec<_>>(),
                    self.selected_fetchers(),
                )
                .unwrap();
                let details = host_text(&self.hosts[0]);
                for phrase in [
                    "Service banners: 22: SSH",
                    "TLS certificates: 8080:",
                    "Web page title: https://",
                    "Device identity:",
                ] {
                    assert!(details.contains(phrase));
                }
            }
            30 => {
                self.settings.dark = true;
                apply_theme(ctx, true);
                self.fetchers_draft = FetcherDraft::new(vec![Fetcher::WebTitle]);
                self.apply_fetchers();
                self.query = "secure nas".into();
                self.rebuild_visible();
                assert_eq!(self.visible.len(), self.hosts.len());
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(820.0, 540.0)));
            }
            31 => {
                self.selected = Some(self.hosts[0].ip);
                self.smoke_details_offset = 1300.0;
            }
            32 => {
                self.selected = None;
                self.edit_fetchers();
            }
            33 => {
                self.show_fetchers = false;
                self.settings.mode = ScanMode::Thorough;
                self.settings.apply_mode_profile();
                self.settings.ports = "80,443,8080,8443".into();
                self.smoke_mode_buttons = [None; 2];
            }
            34 => {
                self.smoke_mode_buttons = [None; 2];
            }
            35 => {
                self.edit_ports();
                self.ports_draft = "1-65535".into();
            }
            37 => {
                self.query.clear();
                self.settings.dark = false;
                apply_theme(ctx, false);
                self.settings.ports = "80,443".into();
                self.settings.udp_ports = udp::COMMON_PORTS.into();
                self.set_udp_enabled(false);
                self.smoke_udp_button = None;
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1180.0, 760.0)));
            }
            38 => {
                self.edit_udp_ports();
                self.ports_draft = "53,123,161,9999-10000".into();
            }
            40 => {
                self.selected = None;
                self.smoke_details_offset = 0.0;
                self.hosts = vec![smoke_host("192.0.2.1", "02:11:22:33:44:01")];
                self.host_positions = HashMap::from([(self.hosts[0].ip, 0)]);
                self.hosts[0].open_ports.clear();
                self.hosts[0].extra.udp = udp::UdpResult {
                    open_ports: vec![53, 123, 161],
                    requested: 5,
                    completed: 5,
                    open_or_filtered: 1,
                    closed: 1,
                    dns: "53/udp: NOERROR | recursion advertised: true".into(),
                    ntp: "123/udp: stratum 2 | offset 0.120 ms".into(),
                    snmp: "161/udp: SNMPv2c | description: Test router | name: Router-A".into(),
                    ..Default::default()
                };
                self.fetchers_draft = FetcherDraft::new(vec![
                    Fetcher::UdpPorts,
                    Fetcher::UdpStatus,
                    Fetcher::DnsInfo,
                    Fetcher::NtpInfo,
                    Fetcher::SnmpInfo,
                ]);
                self.apply_fetchers();
                self.alive = 1;
                self.checked = 1;
                self.total = 1;
                self.with_ports = 1;
                self.filter = Filter::OpenPorts;
                self.dirty = true;
                self.rebuild_visible();
                assert_eq!(self.visible.len(), 1);
                let details = host_text(&self.hosts[0]);
                assert!(details.contains("Router-A") && details.contains("53, 123, 161"));
                export::save_csv_with_fetchers(
                    std::path::Path::new("artifacts/gui-udp.csv"),
                    &[&self.hosts[0]],
                    self.selected_fetchers(),
                )
                .unwrap();
            }
            41 => {
                self.settings.dark = true;
                apply_theme(ctx, true);
                self.selected = Some(self.hosts[0].ip);
                self.smoke_details_offset = 560.0;
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(820.0, 540.0)));
            }
            42 => {
                self.selected = None;
                self.show_settings = true;
                self.settings.snmp_community = "test-only-community".into();
            }
            43 => {
                self.show_settings = false;
                self.edit_udp_ports();
                self.ports_draft = "1-65535".into();
            }
            45 => {
                self.settings.dark = false;
                apply_theme(ctx, false);
                self.settings.target = "192.168.0.0/16".into();
                self.settings.udp_ports = udp::COMMON_PORTS.into();
                self.selected = None;
                self.query.clear();
                self.filter = Filter::All;
                self.hosts = vec![
                    smoke_host("192.168.1.1", ""),
                    smoke_host("192.168.212.8", ""),
                    smoke_host("192.168.213.1", ""),
                ];
                self.hosts[1].status = HostStatus::Incomplete;
                self.hosts[1].ping_ms = None;
                self.hosts[1].extra.discovery_complete = Some(false);
                self.hosts[1].notes = "Scan stopped before host discovery finished".into();
                self.hosts[2].extra.discovery_complete = Some(false);
                self.hosts[2].ping_ms = Some(7.0);
                self.hosts[2].open_ports = vec![443];
                self.hosts[2].notes = "Scan stopped before host discovery finished".into();
                self.host_positions = self
                    .hosts
                    .iter()
                    .enumerate()
                    .map(|(index, host)| (host.ip, index))
                    .collect();
                self.total = 65534;
                self.checked = 1;
                self.scan_complete = false;
                self.alive = 2;
                self.with_ports = 1;
                self.message = scan_finished_message(true, self.checked, self.total);
                self.fetchers_draft =
                    FetcherDraft::new(vec![Fetcher::Ping, Fetcher::Ports, Fetcher::Notes]);
                self.apply_fetchers();
                self.dirty = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1180.0, 760.0)));
                export::save_csv_with_fetchers(
                    std::path::Path::new("artifacts/gui-stopped-scan.csv"),
                    &self.hosts.iter().collect::<Vec<_>>(),
                    self.selected_fetchers(),
                )
                .unwrap();
                assert!(self.message.contains("65533 unchecked"));
            }
            46 => {
                self.settings.dark = true;
                apply_theme(ctx, true);
                self.selected = Some(self.hosts[2].ip);
                self.smoke_details_offset = 0.0;
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(820.0, 540.0)));
            }
            47 => {
                self.selected = None;
                self.message = "Rechecking 12345 of 65389 addresses without an echo reply (paced confirmation)".into();
                assert!(self.message.starts_with("Rechecking 12345 of 65389"));
            }
            48 => {
                self.settings.dark = false;
                apply_theme(ctx, false);
                self.message = "Rechecking 65389 of 65389 addresses without an echo reply (paced confirmation)".into();
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1180.0, 760.0)));
            }
            49 => {
                self.settings.mode = ScanMode::Fast;
                self.settings.apply_mode_profile();
                self.settings.adaptive_concurrency = true;
                self.show_settings = true;
                self.message = "Ready".into();
                assert_eq!(self.settings.workers, 256);
            }
            50 => {
                self.settings.dark = true;
                apply_theme(ctx, true);
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(820.0, 540.0)));
            }
            51 => {
                self.show_settings = false;
                self.settings.adaptive_concurrency = false;
                assert_eq!(self.settings.workers, 256);
            }
            52 => {
                self.settings.dark = false;
                apply_theme(ctx, false);
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(1180.0, 760.0)));
                self.settings.fetchers = Some(vec![
                    Fetcher::Ping,
                    Fetcher::Hostname,
                    Fetcher::Ports,
                    Fetcher::Notes,
                ]);
                self.hosts = (0..65_534)
                    .map(|index| {
                        let mut host =
                            smoke_host(&Ipv4Addr::from(0xc0a80001 + index).to_string(), "");
                        host.hostname = format!("host-{index:05}");
                        host
                    })
                    .collect();
                self.host_positions = self
                    .hosts
                    .iter()
                    .enumerate()
                    .map(|(index, host)| (host.ip, index))
                    .collect();
                self.query.clear();
                self.filter = Filter::All;
                self.sort = Sort::Ip;
                self.descending = false;
                self.selected = None;
                self.total = self.hosts.len();
                self.checked = self.total;
                self.alive = self.total;
                self.with_ports = 0;
                self.scan_complete = true;
                self.dirty = true;
                self.rebuild_visible();
                assert_eq!(self.visible.len(), 65_534);
                self.message = "Scan complete".into();
            }
            53 => {
                self.query = "host-00042".into();
                self.dirty = true;
                self.rebuild_visible();
                assert_eq!(self.visible, vec![42]);
            }
            54 => {
                self.query.clear();
                self.settings.fetchers = Some(vec![Fetcher::DeviceIdentity, Fetcher::Notes]);
                self.sort = Sort::Metadata(Fetcher::DeviceIdentity);
                self.descending = true;
                self.dirty = true;
                self.rebuild_visible();
                assert_eq!(self.visible.len(), 65_534);
                self.settings.dark = true;
                apply_theme(ctx, true);
                ctx.send_viewport_cmd(egui::ViewportCommand::InnerSize(egui::vec2(820.0, 540.0)));
            }
            _ => {}
        }
    }

    pub fn smoke_verify_inventory(&self) {
        assert_eq!(self.fetchers_draft.selected, fetchers::inventory());
    }

    pub fn smoke_verify_full_ports(&self) {
        assert!(!self.show_ports_editor);
        assert!(self.ports_error.is_none());
        assert_eq!(self.settings.ports, "1-65535");
        assert_eq!(parse_ports(&self.settings.ports).unwrap().len(), 65535);
        assert_eq!(self.selected_fetchers(), &[Fetcher::WebTitle]);
        assert_eq!(self.settings.mode, ScanMode::Thorough);
    }

    pub fn smoke_udp_click(&self) -> Option<Vec<egui::Event>> {
        let pos = self.smoke_udp_button?;
        Some(vec![
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::default(),
            },
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::default(),
            },
        ])
    }

    pub fn smoke_verify_udp(&self, stage: usize) {
        assert!(self.udp_enabled());
        assert_eq!(self.settings.ports, "80,443");
        if stage == 39 || stage == 44 {
            assert!(!self.show_ports_editor);
            assert!(self.ports_error.is_none());
            assert_eq!(
                self.settings.udp_ports,
                if stage == 39 {
                    "53,123,161,9999-10000"
                } else {
                    "1-65535"
                }
            );
        }
    }

    pub fn smoke_mode_click(&self, button: usize) -> Option<Vec<egui::Event>> {
        let pos = self.smoke_mode_buttons[button]?;
        Some(vec![
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::default(),
            },
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::default(),
            },
        ])
    }

    pub fn smoke_verify_mode(&self, fast: bool) {
        assert_eq!(
            self.settings.mode,
            if fast {
                ScanMode::Fast
            } else {
                ScanMode::Thorough
            }
        );
        assert_eq!(self.settings.timeout_ms, if fast { 200 } else { 400 });
        assert_eq!(self.settings.workers, if fast { 256 } else { 128 });
        assert_eq!(self.settings.discovery_seconds, if fast { 2 } else { 4 });
        assert_eq!(self.settings.ports, "80,443,8080,8443");
        assert_eq!(self.selected_fetchers(), &[Fetcher::WebTitle]);
    }

    pub fn smoke_ready(&self) -> bool {
        self.scan.is_none()
    }

    pub fn smoke_fetcher_click(&self, button: usize) -> Vec<egui::Event> {
        let pos = self.smoke_fetcher_buttons[button].expect("Fetcher control not rendered");
        vec![
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::default(),
            },
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::default(),
            },
        ]
    }

    pub fn smoke_fetcher_ready(&self, button: usize) -> bool {
        self.smoke_fetcher_buttons[button].is_some()
    }

    pub fn smoke_verify_fetchers_applied(&self) {
        assert!(!self.show_fetchers);
        assert_eq!(
            self.selected_fetchers(),
            &[
                Fetcher::Ping,
                Fetcher::Hostname,
                Fetcher::Ports,
                Fetcher::MacAddress,
                Fetcher::ArpResponse,
                Fetcher::Manufacturer
            ]
        );
        let path = std::path::Path::new("artifacts/gui-fetchers.csv");
        let hosts = self
            .visible
            .iter()
            .map(|&index| &self.hosts[index])
            .collect::<Vec<_>>();
        export::save_csv_with_fetchers(path, &hosts, self.selected_fetchers()).unwrap();
        let mut reader = csv::Reader::from_path(path).unwrap();
        assert_eq!(
            reader.headers().unwrap().iter().collect::<Vec<_>>(),
            vec![
                "IP address",
                "Status",
                "Ping",
                "Hostname",
                "Open TCP ports",
                "MAC address",
                "ARP response",
                "Manufacturer"
            ]
        );
    }

    pub fn smoke_verify_ports_during_scan(&self) {
        assert!(!self.show_ports_editor);
        assert_eq!(
            parse_ports(&self.settings.ports).unwrap(),
            vec![80, 443, 8000, 8001, 8002]
        );
        self.scan
            .as_ref()
            .expect("The ports were edited during an active scan")
            .cancel();
    }

    pub fn smoke_port_click(&self, button: usize) -> Vec<egui::Event> {
        let pos = self.smoke_port_buttons[button].expect("Port control not rendered");
        vec![
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::default(),
            },
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::default(),
            },
        ]
    }

    pub fn smoke_copy_click(&self, button: usize) -> Vec<egui::Event> {
        let pos = self.smoke_copy_buttons[button].expect("Copy control not rendered");
        vec![
            egui::Event::PointerMoved(pos),
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: true,
                modifiers: egui::Modifiers::default(),
            },
            egui::Event::PointerButton {
                pos,
                button: egui::PointerButton::Primary,
                pressed: false,
                modifiers: egui::Modifiers::default(),
            },
        ]
    }

    pub fn smoke_verify_copy_feedback(&self, ctx: &egui::Context, button: usize, active: bool) {
        let column = if button.is_multiple_of(2) {
            AddressColumn::Ip
        } else {
            AddressColumn::Mac
        };
        let id = if button < 2 {
            egui::Id::new(("copy_visible", column))
        } else {
            egui::Id::new((
                "copy_address",
                "192.0.2.1".parse::<Ipv4Addr>().unwrap(),
                column,
            ))
        };
        assert_eq!(
            copy_confirmed(ctx, id),
            active,
            "Copy confirmation state did not match"
        );
    }

    pub fn smoke_type_ports(&self) -> Vec<egui::Event> {
        let modifiers = egui::Modifiers {
            ctrl: true,
            command: true,
            ..Default::default()
        };
        vec![
            egui::Event::Key {
                key: egui::Key::A,
                physical_key: None,
                pressed: true,
                repeat: false,
                modifiers,
            },
            egui::Event::Text("80,443,8000-8002".into()),
        ]
    }
}

impl eframe::App for ScoutApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.receive(ctx);
        self.receive_workflow(ctx);
        self.controls(ctx);
        self.summary(ctx);
        self.rebuild_visible();
        self.status_bar(ctx);
        self.details(ctx);
        self.results(ctx);
        self.windows(ctx);
        self.workflow_window(ctx);
        if self.scan.is_some() || self.export_result.is_some() || self.workflow.busy() {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        eframe::set_value(storage, "language", &self.language);
        eframe::set_value(storage, "settings", &self.settings);
        eframe::set_value(storage, "profiles", &self.workflow.profiles);
    }
}

fn apply_theme(ctx: &egui::Context, dark: bool) {
    ctx.set_theme(if dark {
        egui::Theme::Dark
    } else {
        egui::Theme::Light
    });
    let mut visuals = if dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    visuals.selection.bg_fill = if dark {
        Color32::from_rgb(28, 78, 99)
    } else {
        Color32::from_rgb(213, 232, 248)
    };
    visuals.selection.stroke.color = if dark {
        Color32::WHITE
    } else {
        Color32::from_rgb(20, 50, 70)
    };
    if !dark {
        visuals.panel_fill = Color32::WHITE;
        visuals.extreme_bg_color = Color32::from_rgb(248, 250, 251);
        visuals.override_text_color = Some(Color32::from_rgb(37, 46, 52));
    }
    ctx.set_visuals(visuals);
}

fn icon_button(ui: &mut egui::Ui, icon: &str, tooltip: &str) -> egui::Response {
    ui.add(egui::Button::new(RichText::new(icon).size(19.0)).min_size(egui::vec2(32.0, 32.0)))
        .on_hover_text(tooltip)
}

fn fetcher_supported(fetcher: Fetcher) -> bool {
    match fetcher {
        Fetcher::MacAddress
        | Fetcher::Manufacturer
        | Fetcher::ProbableBrand
        | Fetcher::ArpResponse => network::ARP_SUPPORTED,
        Fetcher::NetworkPath => network::ROUTE_SUPPORTED,
        _ => true,
    }
}

fn fetcher_sort(fetcher: Fetcher) -> Sort {
    match fetcher {
        Fetcher::Ping => Sort::Ping,
        Fetcher::Hostname => Sort::Hostname,
        Fetcher::Ports => Sort::Ports,
        Fetcher::MacAddress => Sort::Mac,
        Fetcher::Manufacturer => Sort::Vendor,
        Fetcher::RefusedPorts => Sort::RefusedPorts,
        Fetcher::ArpResponse => Sort::ArpResponse,
        Fetcher::ProbableBrand => Sort::ProbableBrand,
        Fetcher::Notes => Sort::Notes,
        Fetcher::Ttl => Sort::Ttl,
        Fetcher::PacketLoss => Sort::PacketLoss,
        Fetcher::Netbios
        | Fetcher::WebDetect
        | Fetcher::HttpStatus
        | Fetcher::WebUrl
        | Fetcher::Bonjour
        | Fetcher::Wsd
        | Fetcher::Ssdp
        | Fetcher::Mndp
        | Fetcher::Ubiquiti
        | Fetcher::Llmnr => Sort::Metadata(fetcher),
        Fetcher::ServiceDetails
        | Fetcher::NetworkPath
        | Fetcher::ServiceBanners
        | Fetcher::TlsCertificates
        | Fetcher::WebTitle
        | Fetcher::DeviceIdentity => Sort::Metadata(fetcher),
        Fetcher::UdpPorts
        | Fetcher::UdpStatus
        | Fetcher::DnsInfo
        | Fetcher::NtpInfo
        | Fetcher::SnmpInfo => Sort::Metadata(fetcher),
        Fetcher::RetiredLinkNeighbors => Sort::Ip,
    }
}

fn address_list<'a>(hosts: impl Iterator<Item = &'a HostResult>, column: AddressColumn) -> String {
    hosts
        .filter_map(|host| match column {
            AddressColumn::Ip => Some(host.ip.to_string()),
            AddressColumn::Mac if !host.mac.is_empty() => Some(host.mac.clone()),
            AddressColumn::Mac => None,
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn address_cell(
    ui: &mut egui::Ui,
    ctx: &egui::Context,
    value: &str,
    tooltip: &str,
    feedback_id: egui::Id,
    tr: Locale,
) -> egui::Response {
    ui.spacing_mut().item_spacing.x = 2.0;
    let width = (ui.available_width() - 26.0).max(0.0);
    ui.add_sized(
        [width, 24.0],
        egui::Label::new(RichText::new(display_value(value)).monospace()).truncate(),
    )
    .on_hover_text(value);
    let confirmed = copy_confirmed(ctx, feedback_id);
    let mut icon = RichText::new(if confirmed { icons::CHECK } else { icons::COPY }).size(15.0);
    if confirmed {
        icon = icon.color(GREEN);
    }
    let copy = ui.add_enabled(
        !value.is_empty(),
        egui::Button::new(icon)
            .small()
            .frame(false)
            .min_size(egui::vec2(24.0, 24.0)),
    );
    if !confirmed {
        copy.clone().on_hover_text(tooltip);
    }
    if copy.clicked() {
        copy_with_feedback(ctx, feedback_id, value.to_owned());
    }
    show_copy_confirmation(&copy, feedback_id, tr);
    copy
}

fn copy_with_feedback(ctx: &egui::Context, button: egui::Id, text: String) {
    ctx.copy_text(text);
    ctx.data_mut(|data| {
        data.insert_temp(
            egui::Id::new("clipboard_feedback"),
            CopyFeedback {
                button,
                expires_at: Instant::now() + COPY_CONFIRMATION_TIME,
            },
        )
    });
    ctx.request_repaint();
}

fn copy_confirmed(ctx: &egui::Context, button: egui::Id) -> bool {
    ctx.data(|data| data.get_temp::<CopyFeedback>(egui::Id::new("clipboard_feedback")))
        .is_some_and(|feedback| feedback.active_for(button, Instant::now()))
}

fn show_copy_confirmation(response: &egui::Response, button: egui::Id, tr: Locale) {
    let ctx = &response.ctx;
    if let Some(feedback) =
        ctx.data(|data| data.get_temp::<CopyFeedback>(egui::Id::new("clipboard_feedback")))
    {
        let now = Instant::now();
        if feedback.active_for(button, now) && response.enabled() {
            ctx.request_repaint_after(feedback.expires_at.saturating_duration_since(now));
            egui::Tooltip::for_widget(response).width(90.0).show(|ui| {
                ui.label(
                    RichText::new(format!("{} {}", icons::CHECK, tr.text("Copied"))).color(GREEN),
                );
            });
        }
    }
}

#[cfg(any(test, feature = "gui-smoke"))]
fn smoke_host(ip: &str, mac: &str) -> HostResult {
    HostResult {
        ip: ip.parse().unwrap(),
        status: HostStatus::Alive,
        ping_ms: None,
        hostname: String::new(),
        mac: mac.into(),
        vendor: String::new(),
        open_ports: Vec::new(),
        refused_ports: 0,
        notes: String::new(),
        arp_response: true,
        probable_brand: String::new(),
        extra: Default::default(),
    }
}

fn fetcher_display_value(tr: Locale, fetcher: Fetcher, host: &HostResult) -> String {
    let value = fetcher.value(host);
    if fetcher == Fetcher::ArpResponse {
        tr.text(&value).to_owned()
    } else {
        value
    }
}

fn metric(ui: &mut egui::Ui, label: &str, value: &str, color: Option<Color32>) {
    ui.label(RichText::new(label).size(11.0).color(MUTED));
    let mut text = RichText::new(value).size(23.0).strong();
    if let Some(color) = color {
        text = text.color(color);
    }
    ui.label(text);
}

fn status_color(status: HostStatus) -> Color32 {
    match status {
        HostStatus::Alive => GREEN,
        HostStatus::NoResponse => MUTED,
        HostStatus::Incomplete => Color32::from_rgb(170, 119, 17),
    }
}

fn ports_text(ports: &[u16]) -> String {
    ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

fn ping_text(ping: Option<f64>) -> String {
    match ping {
        Some(value) if value < 1.0 => "<1 ms".into(),
        Some(value) => format!("{value:.0} ms"),
        None => "-".into(),
    }
}

fn display_value(value: &str) -> &str {
    if value.is_empty() { "-" } else { value }
}

fn format_duration(duration: Duration) -> String {
    let seconds = duration.as_secs();
    format!("{:02}:{:02}", seconds / 60, seconds % 60)
}

fn cell(ui: &mut egui::Ui, value: &str) {
    ui.add(egui::Label::new(display_value(value)).truncate())
        .on_hover_text(value);
}

fn detail(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.label(RichText::new(label).size(12.0).color(MUTED));
    ui.add(egui::Label::new(display_value(value)).wrap());
    ui.add_space(4.0);
}

fn host_text(host: &HostResult) -> String {
    let mut text = format!(
        "IP: {}\nStatus: {}\nPing: {}\nHostname: {}\nMAC: {}\nManufacturer: {}\nProbable brand: {}\nARP response: {}\nOpen TCP ports: {}\nRefused TCP ports: {}\nNotes: {}",
        host.ip,
        host.status.label(),
        ping_text(host.ping_ms),
        host.hostname,
        host.mac,
        host.vendor,
        host.probable_brand,
        host.arp_response,
        ports_text(&host.open_ports),
        host.refused_ports,
        host.notes
    );
    text.push_str(if host.discovery_complete() {
        "\nHost discovery: Complete"
    } else {
        "\nHost discovery: Incomplete"
    });
    for fetcher in [
        Fetcher::Ttl,
        Fetcher::PacketLoss,
        Fetcher::Netbios,
        Fetcher::WebDetect,
        Fetcher::HttpStatus,
        Fetcher::WebUrl,
        Fetcher::Bonjour,
        Fetcher::Wsd,
        Fetcher::Ssdp,
        Fetcher::Mndp,
        Fetcher::Ubiquiti,
        Fetcher::Llmnr,
        Fetcher::ServiceBanners,
        Fetcher::ServiceDetails,
        Fetcher::NetworkPath,
        Fetcher::TlsCertificates,
        Fetcher::WebTitle,
        Fetcher::DeviceIdentity,
        Fetcher::UdpPorts,
        Fetcher::UdpStatus,
        Fetcher::DnsInfo,
        Fetcher::NtpInfo,
        Fetcher::SnmpInfo,
    ] {
        let value = fetcher.value(host);
        if !value.is_empty() {
            text.push_str(&format!("\n{}: {value}", fetcher.label()));
        }
    }
    if host.extra.packet_loss.is_some() {
        text.push_str(&format!(
            "\nICMP replies / samples: {} / {}",
            host.extra.icmp_received, host.extra.icmp_sent
        ));
    }
    text
}

#[cfg(test)]
mod clipboard_tests {
    use super::*;

    #[test]
    fn runtime_logo_preserves_the_existing_256px_icon_pixels_and_alpha() {
        let png = include_bytes!(concat!(env!("OUT_DIR"), "/runtime-logo.png"));
        let icon = include_bytes!("../assets/ip-scout.ico");
        let frames = u16::from_le_bytes(icon[4..6].try_into().unwrap()) as usize;
        let frame = (0..frames)
            .map(|index| &icon[6 + index * 16..22 + index * 16])
            .find(|entry| entry[0] == 0 && entry[1] == 0)
            .expect("256px ICO frame");
        let size = u32::from_le_bytes(frame[8..12].try_into().unwrap()) as usize;
        let offset = u32::from_le_bytes(frame[12..16].try_into().unwrap()) as usize;
        assert_eq!(
            png.as_slice(),
            &icon[offset..offset + size],
            "reuse the icon without re-encoding or quantizing it"
        );
        let image = image::load_from_memory(png).unwrap().to_rgba8();
        assert_eq!(image.dimensions(), (256, 256));
        assert!(image.pixels().any(|pixel| pixel[3] == 0));
        assert!(image.pixels().any(|pixel| pixel[3] == 255));
        assert!(image.pixels().any(|pixel| pixel[3] > 0 && pixel[3] < 255));
        assert!(png.len() < include_bytes!("../assets/ip-scout-logo.png").len() / 10);
    }

    #[test]
    fn progressive_updates_replace_rows_and_keep_counters_correct() {
        let mut hosts = Vec::new();
        let mut positions = HashMap::new();
        let (mut alive, mut ports) = (0, 0);
        let mut checked = 0;
        let mut host = smoke_host("192.0.2.1", "");
        host.status = HostStatus::NoResponse;
        host.open_ports.clear();
        upsert_host(
            &mut hosts,
            &mut positions,
            &mut alive,
            &mut ports,
            &mut checked,
            host.clone(),
        );
        assert_eq!((hosts.len(), alive, ports), (1, 0, 0));
        host.status = HostStatus::Alive;
        host.open_ports = vec![80];
        host.hostname = "SDCHGS07".into();
        for _ in 0..3 {
            upsert_host(
                &mut hosts,
                &mut positions,
                &mut alive,
                &mut ports,
                &mut checked,
                host.clone(),
            );
        }
        assert_eq!((hosts.len(), alive, ports), (1, 1, 1));
        assert_eq!(hosts[0].hostname, "SDCHGS07");
        host.open_ports.clear();
        host.extra.udp.open_ports.push(53);
        upsert_host(
            &mut hosts,
            &mut positions,
            &mut alive,
            &mut ports,
            &mut checked,
            host.clone(),
        );
        assert_eq!((hosts.len(), alive, ports), (1, 1, 1));
        host.extra.udp.open_ports.clear();
        upsert_host(
            &mut hosts,
            &mut positions,
            &mut alive,
            &mut ports,
            &mut checked,
            host,
        );
        assert_eq!((hosts.len(), alive, ports), (1, 1, 0));
        assert_eq!(checked, 1);
        let mut partial = hosts[0].clone();
        partial.status = HostStatus::Incomplete;
        partial.extra.discovery_complete = Some(false);
        upsert_host(
            &mut hosts,
            &mut positions,
            &mut alive,
            &mut ports,
            &mut checked,
            partial,
        );
        assert_eq!((hosts.len(), checked, alive, ports), (1, 0, 0, 0));
    }

    #[test]
    fn stopped_scan_reports_coverage_not_just_alive_rows() {
        let message = scan_finished_message(true, 54200, 65534);
        assert!(message.contains("54200/65534 checked"));
        assert!(message.contains("11334 unchecked"));
        assert!(message.contains("incomplete"));
        assert_eq!(
            scan_finished_message(false, 65534, 65534).render(Locale::English),
            "Scan complete"
        );
    }

    #[test]
    fn fetcher_preferences_migrate_legacy_flags_and_preserve_empty_selection() {
        let mut settings = Settings {
            resolve_names: false,
            fetch_mac: false,
            ..Default::default()
        };
        settings.normalize_fetchers();
        assert_eq!(settings.fetchers, Some(vec![Fetcher::Ping, Fetcher::Ports]));
        settings.fetchers = Some(Vec::new());
        settings.normalize_fetchers();
        assert_eq!(settings.fetchers, Some(Vec::new()));
    }

    #[test]
    fn fetcher_preferences_round_trip_in_saved_order() {
        #[derive(Default)]
        struct Storage(std::collections::HashMap<String, String>);
        impl eframe::Storage for Storage {
            fn get_string(&self, key: &str) -> Option<String> {
                self.0.get(key).cloned()
            }
            fn set_string(&mut self, key: &str, value: String) {
                self.0.insert(key.to_owned(), value);
            }
            fn flush(&mut self) {}
        }
        let settings = Settings {
            fetchers: Some(vec![
                Fetcher::Bonjour,
                Fetcher::Wsd,
                Fetcher::Ssdp,
                Fetcher::Mndp,
                Fetcher::Ubiquiti,
                Fetcher::Llmnr,
                Fetcher::Notes,
                Fetcher::MacAddress,
                Fetcher::Ping,
                Fetcher::UdpPorts,
                Fetcher::UdpStatus,
                Fetcher::DnsInfo,
                Fetcher::NtpInfo,
                Fetcher::SnmpInfo,
            ]),
            discovery_seconds: 90,
            adaptive_concurrency: false,
            udp_ports: "53,123,9999-10000".into(),
            snmp_community: "must-not-be-saved".into(),
            ..Default::default()
        };
        let mut storage = Storage::default();
        eframe::set_value(&mut storage, "settings", &settings);
        assert!(!storage.0["settings"].contains("must-not-be-saved"));
        assert!(!storage.0["settings"].contains("snmp_community"));
        let mut restored: Settings = eframe::get_value(&storage, "settings").unwrap();
        restored.normalize_fetchers();
        assert_eq!(restored.fetchers, settings.fetchers);
        assert_eq!(restored.discovery_seconds, 90);
        assert!(!restored.adaptive_concurrency);
        assert_eq!(restored.mode, ScanMode::Fast);
        assert_eq!(restored.udp_ports, settings.udp_ports);
        assert!(restored.snmp_community.is_empty());
        eframe::Storage::set_string(&mut storage, "legacy", "(target: \"192.168.1.0/24\", ports: \"8080,12345\", timeout_ms: 750, workers: 16, discovery_seconds: 90)".into());
        let legacy: Settings = eframe::get_value(&storage, "legacy").unwrap();
        assert_eq!(legacy.mode, ScanMode::Thorough);
        assert!(legacy.adaptive_concurrency);
        assert_eq!(
            (legacy.timeout_ms, legacy.workers, legacy.discovery_seconds),
            (750, 16, 90)
        );
        assert_eq!(legacy.ports, "8080,12345");
        assert_eq!(legacy.udp_ports, udp::COMMON_PORTS);
        assert!(legacy.snmp_community.is_empty());
        let previous = Settings {
            target: "192.168.1.0/24".into(),
            ports: "1234,4321".into(),
            fetchers: Some(vec![
                Fetcher::Ssdp,
                Fetcher::RetiredLinkNeighbors,
                Fetcher::Llmnr,
            ]),
            discovery_seconds: 60,
            ..Default::default()
        };
        eframe::set_value(&mut storage, "settings", &previous);
        assert!(
            eframe::Storage::get_string(&storage, "settings")
                .unwrap()
                .contains("LinkNeighbors")
        );
        let mut migrated: Settings = eframe::get_value(&storage, "settings").unwrap();
        migrated.normalize_fetchers();
        assert_eq!(migrated.fetchers, Some(vec![Fetcher::Ssdp, Fetcher::Llmnr]));
        assert_eq!(migrated.target, previous.target);
        assert_eq!(migrated.ports, previous.ports);
        assert_eq!(migrated.discovery_seconds, 60);
    }

    #[test]
    fn scan_modes_change_timing_without_changing_custom_ports_or_fetchers() {
        let mut settings = Settings {
            ports: "8080,12345".into(),
            fetchers: Some(vec![Fetcher::WebDetect, Fetcher::TlsCertificates]),
            ..Default::default()
        };
        settings.mode = ScanMode::Thorough;
        settings.apply_mode_profile();
        assert_eq!(
            (
                settings.timeout_ms,
                settings.workers,
                settings.discovery_seconds
            ),
            (400, 128, 4)
        );
        settings.mode = ScanMode::Fast;
        settings.apply_mode_profile();
        assert_eq!(
            (
                settings.timeout_ms,
                settings.workers,
                settings.discovery_seconds
            ),
            (200, 256, 2)
        );
        assert_eq!(settings.ports, "8080,12345");
        assert_eq!(
            settings.fetchers,
            Some(vec![Fetcher::WebDetect, Fetcher::TlsCertificates])
        );
    }

    #[test]
    fn confirmation_targets_one_button_and_expires() {
        let now = Instant::now();
        let first = egui::Id::new("first");
        let second = egui::Id::new("second");
        let feedback = CopyFeedback {
            button: first,
            expires_at: now + COPY_CONFIRMATION_TIME,
        };
        assert!(feedback.active_for(first, now));
        assert!(!feedback.active_for(second, now));
        assert!(!feedback.active_for(first, now + COPY_CONFIRMATION_TIME));
        let refreshed = CopyFeedback {
            button: second,
            expires_at: now + COPY_CONFIRMATION_TIME + Duration::from_millis(100),
        };
        assert!(!refreshed.active_for(first, now));
        assert!(refreshed.active_for(second, now + COPY_CONFIRMATION_TIME));
    }

    #[test]
    fn lists_preserve_visible_order_and_skip_missing_macs() {
        let hosts = [
            smoke_host("192.0.2.3", "02:11:22:33:44:03"),
            smoke_host("192.0.2.2", ""),
            smoke_host("192.0.2.1", "02:11:22:33:44:01"),
        ];
        assert_eq!(
            address_list(hosts.iter(), AddressColumn::Ip),
            "192.0.2.3\n192.0.2.2\n192.0.2.1"
        );
        assert_eq!(
            address_list(hosts.iter(), AddressColumn::Mac),
            "02:11:22:33:44:03\n02:11:22:33:44:01"
        );
        assert_eq!(
            address_list(hosts.iter().skip(2), AddressColumn::Ip),
            "192.0.2.1"
        );
        assert_eq!(address_list(hosts.iter().take(0), AddressColumn::Mac), "");
        assert_eq!(address_list(hosts[1..2].iter(), AddressColumn::Mac), "");
    }
}
