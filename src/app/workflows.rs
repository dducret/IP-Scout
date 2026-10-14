use super::*;
use ip_scout::history::{self, HostChange, ScanSnapshot};
use std::{
    collections::BTreeSet,
    io::Read,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct ScanProfile {
    name: String,
    settings: Settings,
}

enum WorkflowOutcome {
    Targets(String),
    Loaded(Box<ScanSnapshot>),
    Baseline(Box<ScanSnapshot>),
    Saved(String),
    Compared(Vec<HostChange>),
    Cancelled,
}

pub(super) struct WorkflowState {
    pub open: bool,
    tab: usize,
    pub target_draft: String,
    pub profiles: Vec<ScanProfile>,
    profile_name: String,
    pub scan_targets: Option<TargetSet>,
    scan_meta: Option<ScanSnapshot>,
    baseline: Option<ScanSnapshot>,
    changes: Vec<HostChange>,
    compared: bool,
    change_page: usize,
    pub selected: BTreeSet<Ipv4Addr>,
    job: Option<Receiver<Result<WorkflowOutcome, String>>>,
}

impl WorkflowState {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        let mut profiles: Vec<ScanProfile> = cc
            .storage
            .and_then(|storage| eframe::get_value(storage, "profiles"))
            .unwrap_or_default();
        profiles.truncate(32);
        for profile in &mut profiles {
            profile.settings.snmp_community.clear();
            profile.settings.normalize_fetchers();
        }
        Self {
            open: false,
            tab: 0,
            target_draft: String::new(),
            profiles,
            profile_name: String::new(),
            scan_targets: None,
            scan_meta: None,
            baseline: None,
            changes: Vec::new(),
            compared: false,
            change_page: 0,
            selected: BTreeSet::new(),
            job: None,
        }
    }

    pub fn busy(&self) -> bool {
        self.job.is_some()
    }

    pub fn clear_current(&mut self) {
        self.scan_meta = None;
        self.selected.clear();
        self.changes.clear();
        self.compared = false;
        self.change_page = 0;
    }

    pub fn record_scan(
        &mut self,
        options: &ScanOptions,
        targets: &TargetSet,
        fetchers: Vec<Fetcher>,
    ) {
        let mut udp_ports = options.extra.udp.ports.clone();
        if options.extra.udp.dns {
            udp_ports.push(53);
        }
        if options.extra.udp.ntp {
            udp_ports.push(123);
        }
        if options.extra.udp.snmp && !options.extra.udp.community.is_empty() {
            udp_ports.push(161);
        }
        udp_ports.sort_unstable();
        udp_ports.dedup();
        let mut text = targets.canonical_text();
        if text.len() > 16000 {
            text.truncate(16000);
            text.push_str(" …");
        }
        self.scan_meta = Some(ScanSnapshot {
            schema_version: history::SCHEMA_VERSION,
            recorded_unix_secs: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            app_version: env!("CARGO_PKG_VERSION").into(),
            label: format!("{} addresses", targets.len()),
            target_text: text,
            targets: targets.ranges().to_vec(),
            tcp_ports: options.ports.clone(),
            udp_ports,
            fetchers,
            probe_policy: format!(
                "mode={:?};arp={};timeout={};adaptive={};workers={};dns={};mac={};netbios={};web={};tls_unverified={};bonjour={};wsd={};ssdp={};mndp={};ubiquiti={};llmnr={};banners={};certificates={};services={};titles={};udp_dns={};udp_ntp={};udp_snmp={};community_present={}",
                options.mode,
                options.discover_arp,
                options.timeout_ms,
                options.adaptive_concurrency,
                options.workers,
                options.resolve_names,
                options.fetch_mac,
                options.extra.netbios,
                options.extra.web,
                options.extra.allow_unverified_tls,
                options.extra.bonjour,
                options.extra.wsd,
                options.extra.advertisements.ssdp,
                options.extra.advertisements.mndp,
                options.extra.advertisements.ubiquiti,
                options.extra.llmnr,
                options.extra.banners,
                options.extra.certificates,
                options.extra.services,
                options.extra.web_titles,
                options.extra.udp.dns,
                options.extra.udp.ntp,
                options.extra.udp.snmp,
                !options.extra.udp.community.is_empty()
            ),
            complete: false,
            cancelled: false,
            hosts: Vec::new(),
            elapsed_ms: 0,
        });
        self.changes.clear();
        self.compared = false;
        self.selected.clear();
    }
}

impl ScoutApp {
    fn current_snapshot(&self) -> Option<ScanSnapshot> {
        let mut snapshot = self.workflow.scan_meta.clone()?;
        snapshot.hosts = self.hosts.clone();
        snapshot.complete = self.scan.is_none() && self.scan_complete;
        snapshot.cancelled = self.scan.is_none() && !self.scan_complete;
        snapshot.elapsed_ms = self
            .started
            .filter(|_| self.scan.is_some())
            .map(|start| start.elapsed())
            .unwrap_or(self.elapsed)
            .as_millis()
            .min(u128::from(u64::MAX)) as u64;
        Some(snapshot)
    }

    pub(super) fn begin_selected_scan(&mut self, ctx: &egui::Context, ips: Vec<Ipv4Addr>) {
        if self.scan.is_some() || self.workflow.busy() {
            return;
        }
        match TargetSet::from_ips(ips) {
            Ok(targets) => {
                self.settings.target = targets.canonical_text();
                self.workflow.scan_targets = Some(targets);
                self.begin_scan_impl(ctx);
            }
            Err(error) => self.error = Some(error),
        }
    }

    fn start_workflow_job(
        &mut self,
        ctx: &egui::Context,
        job: impl FnOnce() -> Result<WorkflowOutcome, String> + Send + 'static,
    ) {
        if self.workflow.busy() {
            return;
        }
        let (sender, receiver) = mpsc::channel();
        self.workflow.job = Some(receiver);
        let ctx = ctx.clone();
        std::thread::spawn(move || {
            let _ = sender.send(job());
            ctx.request_repaint();
        });
    }

    fn history_job(&mut self, ctx: &egui::Context, action: usize) {
        if action == 0 {
            let Some(snapshot) = self.current_snapshot() else {
                self.error = Some("Run or load a scan before saving it".into());
                return;
            };
            self.start_workflow_job(ctx, move || {
                let Some(path) = rfd::FileDialog::new()
                    .set_title("Save scan snapshot")
                    .add_filter("Scan snapshot", &["json"])
                    .set_file_name("ip-scout-scan.json")
                    .save_file()
                else {
                    return Ok(WorkflowOutcome::Cancelled);
                };
                snapshot.save(&path)?;
                Ok(WorkflowOutcome::Saved(format!(
                    "Saved scan to {}",
                    path.display()
                )))
            });
        } else {
            self.start_workflow_job(ctx, move || {
                let Some(path) = rfd::FileDialog::new()
                    .set_title(if action == 1 {
                        "Load scan snapshot"
                    } else {
                        "Choose comparison baseline"
                    })
                    .add_filter("Scan snapshot", &["json"])
                    .pick_file()
                else {
                    return Ok(WorkflowOutcome::Cancelled);
                };
                let snapshot = Box::new(ScanSnapshot::load(&path)?);
                Ok(if action == 1 {
                    WorkflowOutcome::Loaded(snapshot)
                } else {
                    WorkflowOutcome::Baseline(snapshot)
                })
            });
        }
    }

    pub(super) fn receive_workflow(&mut self, _ctx: &egui::Context) {
        let outcome = match self.workflow.job.as_ref().map(|job| job.try_recv()) {
            Some(Ok(outcome)) => outcome,
            Some(Err(TryRecvError::Disconnected)) => {
                Err("The file operation ended unexpectedly".into())
            }
            _ => return,
        };
        self.workflow.job = None;
        match outcome {
            Err(error) => self.error = Some(error),
            Ok(WorkflowOutcome::Cancelled) => {}
            Ok(WorkflowOutcome::Saved(message)) => self.message = message,
            Ok(WorkflowOutcome::Compared(changes)) => {
                self.workflow.changes = changes;
                self.workflow.compared = true;
                self.workflow.change_page = 0;
            }
            Ok(WorkflowOutcome::Targets(text)) => {
                self.workflow.target_draft = text;
                self.workflow.open = true;
                self.workflow.tab = 0;
            }
            Ok(WorkflowOutcome::Baseline(snapshot)) => {
                self.workflow.baseline = Some(*snapshot);
                self.workflow.changes.clear();
                self.workflow.compared = false;
            }
            Ok(WorkflowOutcome::Loaded(snapshot)) => {
                if self.scan.is_some() {
                    self.error = Some("Stop the active scan before loading another scan".into());
                    return;
                }
                self.load_snapshot(*snapshot);
            }
        }
    }

    fn load_snapshot(&mut self, mut snapshot: ScanSnapshot) {
        self.total = snapshot.targets.iter().map(TargetRange::len).sum();
        self.hosts = std::mem::take(&mut snapshot.hosts);
        self.host_positions.clear();
        for (index, host) in self.hosts.iter().enumerate() {
            self.host_positions.insert(host.ip, index);
        }
        self.checked = self
            .hosts
            .iter()
            .filter(|host| host.discovery_complete())
            .count();
        self.alive = self
            .hosts
            .iter()
            .filter(|host| host.status == HostStatus::Alive)
            .count();
        self.with_ports = self
            .hosts
            .iter()
            .filter(|host| has_open_ports(host))
            .count();
        self.scan_complete = snapshot.complete && !snapshot.cancelled;
        self.elapsed = Duration::from_millis(snapshot.elapsed_ms);
        self.started = None;
        self.stopping = false;
        self.concurrency = None;
        self.settings.target = snapshot
            .targets
            .iter()
            .map(|range| {
                if range.first == range.last {
                    Ipv4Addr::from(range.first).to_string()
                } else {
                    format!(
                        "{}-{}",
                        Ipv4Addr::from(range.first),
                        Ipv4Addr::from(range.last)
                    )
                }
            })
            .collect::<Vec<_>>()
            .join(", ");
        self.settings.ports = format_ports(&snapshot.tcp_ports);
        self.settings.udp_ports = format_ports(&snapshot.udp_ports);
        self.settings.fetchers = Some(snapshot.fetchers.clone());
        self.settings.normalize_fetchers();
        self.fetchers_draft = FetcherDraft::new(self.selected_fetchers().to_vec());
        self.view.clear();
        self.visible.clear();
        self.dirty = true;
        self.selected = None;
        self.workflow.selected.clear();
        self.message = format!(
            "Loaded {} ({} rows{})",
            snapshot.label,
            self.hosts.len(),
            if self.scan_complete { "" } else { ", partial" }
        );
        self.workflow.scan_meta = Some(snapshot);
        self.workflow.changes.clear();
        self.workflow.compared = false;
        self.warnings.clear();
        self.error = None;
    }

    pub(super) fn workflow_window(&mut self, ctx: &egui::Context) {
        if !self.workflow.open {
            return;
        }
        let mut open = true;
        egui::Window::new("Scan tools")
            .open(&mut open)
            .default_width(610.0)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    for (tab, label) in ["Targets", "Profiles", "History"].iter().enumerate() {
                        ui.selectable_value(&mut self.workflow.tab, tab, *label);
                    }
                });
                ui.separator();
                egui::ScrollArea::vertical()
                    .max_height((ctx.content_rect().height() - 160.0).max(180.0))
                    .show(ui, |ui| match self.workflow.tab {
                        0 => self.targets_tools(ui, ctx),
                        1 => self.profile_tools(ui, ctx),
                        _ => self.history_tools(ui, ctx),
                    });
                if self.workflow.busy() {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Working with file…");
                    });
                }
            });
        self.workflow.open &= open;
    }

    fn targets_tools(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.label("Paste addresses, ranges or subnets. Use commas, spaces or one target per line. Prefix exclusions with !.");
        ui.add_enabled(
            self.scan.is_none(),
            egui::TextEdit::multiline(&mut self.workflow.target_draft)
                .desired_rows(7)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace)
                .hint_text("192.168.1.0/24\n10.0.0.5\n!192.168.1.20-30"),
        );
        let targets = TargetSet::parse(&self.workflow.target_draft);
        match &targets {
            Ok(targets) => {
                ui.label(format!(
                    "{} unique addresses in {} ranges",
                    targets.len(),
                    targets.ranges().len()
                ));
            }
            Err(error) => {
                ui.colored_label(RED, error);
            }
        }
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    self.scan.is_none() && !self.workflow.busy(),
                    egui::Button::new("Import target file…"),
                )
                .clicked()
            {
                self.start_workflow_job(ctx, || {
                    let Some(path) = rfd::FileDialog::new()
                        .set_title("Import target list")
                        .add_filter("Text targets", &["txt", "csv", "list"])
                        .pick_file()
                    else {
                        return Ok(WorkflowOutcome::Cancelled);
                    };
                    Ok(WorkflowOutcome::Targets(read_target_file(path)?))
                });
            }
            if ui
                .add_enabled(
                    self.scan.is_none() && targets.is_ok(),
                    egui::Button::new("Apply targets"),
                )
                .clicked()
            {
                self.settings.target = targets.as_ref().unwrap().canonical_text();
                self.workflow.open = false;
            }
            if ui
                .add_enabled(
                    self.scan.is_none() && targets.is_ok(),
                    egui::Button::new("Start scan"),
                )
                .clicked()
            {
                self.settings.target = targets.as_ref().unwrap().canonical_text();
                self.begin_scan(ctx);
                self.workflow.open = false;
            }
        });
        ui.separator();
        ui.label(format!(
            "{} selected devices. Ctrl-click rows to select several.",
            self.workflow.selected.len()
        ));
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    self.scan.is_none() && !self.workflow.selected.is_empty(),
                    egui::Button::new("Scan selected"),
                )
                .clicked()
            {
                self.begin_selected_scan(ctx, self.workflow.selected.iter().copied().collect());
            }
            if ui
                .add_enabled(
                    self.scan.is_none() && !self.visible.is_empty(),
                    egui::Button::new("Scan visible results"),
                )
                .clicked()
            {
                self.begin_selected_scan(
                    ctx,
                    self.visible
                        .iter()
                        .map(|&index| self.hosts[index].ip)
                        .collect(),
                );
            }
            if ui
                .add_enabled(
                    self.scan.is_none()
                        && self.hosts.iter().any(|host| {
                            host.status != HostStatus::Alive || !host.discovery_complete()
                        }),
                    egui::Button::new("Retry inconclusive"),
                )
                .clicked()
            {
                self.begin_selected_scan(
                    ctx,
                    self.hosts
                        .iter()
                        .filter(|host| {
                            host.status != HostStatus::Alive || !host.discovery_complete()
                        })
                        .map(|host| host.ip)
                        .collect(),
                );
            }
        });
    }

    fn profile_tools(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.label("Profiles save targets, ports, fetchers and scan settings. SNMP communities are excluded.");
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.workflow.profile_name)
                    .char_limit(64)
                    .hint_text("Profile name"),
            );
            if ui
                .add_enabled(
                    !self.workflow.profile_name.trim().is_empty()
                        && (self.workflow.profiles.len() < 32
                            || self
                                .workflow
                                .profiles
                                .iter()
                                .any(|profile| profile.name == self.workflow.profile_name.trim())),
                    egui::Button::new("Save current"),
                )
                .clicked()
            {
                let name = self.workflow.profile_name.trim().to_owned();
                let mut settings = self.settings.clone();
                settings.snmp_community.clear();
                if let Some(profile) = self
                    .workflow
                    .profiles
                    .iter_mut()
                    .find(|profile| profile.name == name)
                {
                    profile.settings = settings;
                } else {
                    self.workflow.profiles.push(ScanProfile { name, settings });
                }
                self.workflow.profile_name.clear();
            }
        });
        let mut load = None;
        let mut remove = None;
        for (index, profile) in self.workflow.profiles.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(&profile.name);
                if ui
                    .add_enabled(self.scan.is_none(), egui::Button::new("Load"))
                    .clicked()
                {
                    load = Some(index);
                }
                if ui.button("Delete").clicked() {
                    remove = Some(index);
                }
            });
        }
        if let Some(index) = load {
            self.settings = self.workflow.profiles[index].settings.clone();
            self.settings.timeout_ms = self.settings.timeout_ms.clamp(100, 5000);
            self.settings.workers = self.settings.workers.clamp(1, scanner::MAX_HOST_WORKERS);
            self.settings.icmp_samples = self.settings.icmp_samples.clamp(1, 10);
            self.settings.discovery_seconds = self.settings.discovery_seconds.clamp(1, 120);
            self.settings.normalize_fetchers();
            self.fetchers_draft = FetcherDraft::new(self.selected_fetchers().to_vec());
            apply_theme(ctx, self.settings.dark);
            self.dirty = true;
            self.message = "Profile loaded; ready to scan".into();
        }
        if let Some(index) = remove {
            self.workflow.profiles.remove(index);
        }
    }

    fn history_tools(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.label("Save full scan records, including coverage. Reload them or compare against a previous scan.");
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    !self.workflow.busy() && self.workflow.scan_meta.is_some(),
                    egui::Button::new("Save scan…"),
                )
                .clicked()
            {
                self.history_job(ctx, 0);
            }
            if ui
                .add_enabled(
                    !self.workflow.busy() && self.scan.is_none(),
                    egui::Button::new("Load scan…"),
                )
                .clicked()
            {
                self.history_job(ctx, 1);
            }
            if ui
                .add_enabled(!self.workflow.busy(), egui::Button::new("Load baseline…"))
                .clicked()
            {
                self.history_job(ctx, 2);
            }
            if ui
                .add_enabled(
                    !self.workflow.busy()
                        && self.scan.is_none()
                        && self.workflow.scan_meta.is_some(),
                    egui::Button::new("Current as baseline"),
                )
                .clicked()
            {
                self.workflow.baseline = self.current_snapshot();
                self.workflow.changes.clear();
                self.workflow.compared = false;
            }
        });
        if let Some(baseline) = &self.workflow.baseline {
            ui.label(format!(
                "Baseline: {} · {} rows · {}",
                baseline.label,
                baseline.hosts.len(),
                if baseline.complete && !baseline.cancelled {
                    "complete"
                } else {
                    "partial"
                }
            ));
        }
        if ui
            .add_enabled(
                !self.workflow.busy()
                    && self.scan.is_none()
                    && self.workflow.baseline.is_some()
                    && self.workflow.scan_meta.is_some(),
                egui::Button::new("Compare current scan"),
            )
            .clicked()
            && let (Some(baseline), Some(current)) =
                (&self.workflow.baseline, self.current_snapshot())
        {
            let baseline = baseline.clone();
            self.start_workflow_job(ctx, move || {
                Ok(WorkflowOutcome::Compared(history::compare(
                    &baseline, &current,
                )))
            });
        }
        if self.workflow.compared {
            ui.label(format!(
                "{} changed or uncertain devices",
                self.workflow.changes.len()
            ));
            let page_count = self.workflow.changes.len().div_ceil(200);
            self.workflow.change_page = self.workflow.change_page.min(page_count.saturating_sub(1));
            if page_count > 1 {
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(self.workflow.change_page > 0, egui::Button::new("Previous"))
                        .clicked()
                    {
                        self.workflow.change_page -= 1;
                    }
                    ui.label(format!(
                        "Page {} of {}",
                        self.workflow.change_page + 1,
                        page_count
                    ));
                    if ui
                        .add_enabled(
                            self.workflow.change_page + 1 < page_count,
                            egui::Button::new("Next"),
                        )
                        .clicked()
                    {
                        self.workflow.change_page += 1;
                    }
                });
            }
            for change in self
                .workflow
                .changes
                .iter()
                .skip(self.workflow.change_page * 200)
                .take(200)
            {
                ui.collapsing(format!("{} · {}", change.ip, change.kind.label()), |ui| {
                    for detail in &change.details {
                        ui.label(detail);
                    }
                });
            }
        }
        ui.small("No response is inconclusive. Changed target scopes, probe selections and unfinished work can limit comparisons.");
    }
}

fn read_target_file(path: PathBuf) -> Result<String, String> {
    let file = std::fs::File::open(&path).map_err(|error| error.to_string())?;
    if file.metadata().map_err(|error| error.to_string())?.len() > 1024 * 1024 {
        return Err("Target files must be at most 1 MiB".into());
    }
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > 1024 * 1024 {
        return Err("Target file is too large".into());
    }
    let text = String::from_utf8(bytes).map_err(|_| "Target list must be UTF-8 text".to_owned())?;
    let text = text.trim_start_matches('\u{feff}').to_owned();
    if TargetSet::parse(&text).is_ok() {
        return Ok(text);
    }
    // CSV exports can be reused by selecting only their explicit address column.
    let delimiter = if text
        .lines()
        .next()
        .is_some_and(|line| line.contains(';') && !line.contains(','))
    {
        b';'
    } else {
        b','
    };
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delimiter)
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers = reader
        .headers()
        .map_err(|error| format!("Invalid target CSV: {error}"))?;
    let column = headers.iter().position(|name| {
        matches!(
            name.trim().to_ascii_lowercase().as_str(),
            "ip" | "ip address" | "ipv4" | "ipv4 address" | "address" | "target" | "targets"
        )
    });
    let Some(column) = column else {
        return TargetSet::parse(&text).map(|_| text);
    };
    let mut targets = String::new();
    for row in reader.records() {
        let row = row.map_err(|error| format!("Invalid target CSV row: {error}"))?;
        if let Some(value) = row
            .get(column)
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            targets.push_str(value);
            targets.push('\n');
        }
    }
    TargetSet::parse(&targets)?;
    Ok(targets)
}

#[cfg(feature = "gui-smoke")]
#[allow(dead_code)]
impl ScoutApp {
    pub fn smoke_workflows(&mut self, stage: usize, ctx: &egui::Context) {
        let mut current=ScanSnapshot {
            schema_version:history::SCHEMA_VERSION,recorded_unix_secs:1_800_000_000,
            app_version:env!("CARGO_PKG_VERSION").into(),label:"Current lab scan".into(),target_text:"127.0.0.1-3 !127.0.0.2".into(),
            targets:TargetSet::parse("127.0.0.1-3 !127.0.0.2").unwrap().ranges().to_vec(),
            tcp_ports:vec![8080],udp_ports:vec![],fetchers:vec![Fetcher::Hostname,Fetcher::Ports,Fetcher::ServiceDetails,Fetcher::NetworkPath],probe_policy:"smoke-demo".into(),
            complete:true,cancelled:false,elapsed_ms:230,
            hosts:vec![HostResult {
                ip:Ipv4Addr::LOCALHOST,status:HostStatus::Alive,ping_ms:Some(2.0),hostname:"lab-nas".into(),mac:String::new(),vendor:String::new(),open_ports:vec![8080],refused_ports:0,
                notes:String::new(),arp_response:false,probable_brand:String::new(),extra:scanner::ExtraResult {
                    discovery_complete:Some(true),services:vec![ip_scout::services::ServiceIdentification {
                        port:8080,protocol:"HTTP".into(),product:"NAS/2.0".into(),evidence:"http://127.0.0.1:8080/: HTTP response 200; Server header is an unverified claim".into(),
                    }],route:Some(ip_scout::network::RoutePath {interface_index:7,source:Ipv4Addr::LOCALHOST,next_hop:Ipv4Addr::UNSPECIFIED}),..Default::default()
                }
            }],
        };
        let mut previous = current.clone();
        previous.label = "Previous lab scan".into();
        previous.hosts[0].hostname = "lab-storage".into();
        previous.hosts[0].extra.services[0].product = "NAS/1.0".into();
        current.validate().unwrap();
        if stage == 57 {
            current.save("artifacts/workflow-scan.json").unwrap();
            current = ScanSnapshot::load("artifacts/workflow-scan.json").unwrap();
            assert_eq!(current.hosts[0].hostname, "lab-nas");
        }
        self.load_snapshot(current);
        self.workflow.baseline = Some(previous);
        self.workflow.changes = history::compare(
            self.workflow.baseline.as_ref().unwrap(),
            &self.current_snapshot().unwrap(),
        );
        assert_eq!(self.workflow.changes.len(), 1);
        self.workflow.compared = true;
        self.workflow.open = stage != 58;
        self.workflow.tab = match stage {
            55 => 0,
            56 => 1,
            _ => 2,
        };
        self.workflow.target_draft = "127.0.0.1-3\n!127.0.0.2".into();
        assert_eq!(
            TargetSet::parse(&self.workflow.target_draft).unwrap().len(),
            2
        );
        self.workflow.profiles = vec![ScanProfile {
            name: "Lab inventory".into(),
            settings: self.settings.clone(),
        }];
        self.workflow.profiles[0].settings.snmp_community = "should-not-be-saved".into();
        assert!(
            !serde_json::to_string(&self.workflow.profiles)
                .unwrap()
                .contains("should-not-be-saved")
        );
        self.workflow.profiles[0].settings.snmp_community.clear();
        self.settings.dark = stage == 59;
        apply_theme(ctx, self.settings.dark);
        self.show_settings = false;
        self.show_fetchers = false;
        self.show_ports_editor = false;
        self.smoke_offset = 0.0;
        self.smoke_details_offset = 0.0;
        if stage == 58 {
            self.selected = Some(Ipv4Addr::LOCALHOST);
            self.workflow.selected.insert(Ipv4Addr::LOCALHOST);
        }
        ctx.request_repaint();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn saved_profiles_omit_credentials_and_keep_target_configuration() {
        let settings = Settings {
            target: "10.0.0.1, 10.0.2.0/24 !10.0.2.10".into(),
            snmp_community: "private-community-secret".into(),
            ..Default::default()
        };
        let profile = ScanProfile {
            name: "Lab".into(),
            settings,
        };
        let json = serde_json::to_string(&profile).unwrap();
        assert!(!json.contains("private-community-secret"));
        let restored: ScanProfile = serde_json::from_str(&json).unwrap();
        assert_eq!(
            TargetSet::parse(&restored.settings.target).unwrap().len(),
            254
        );
        assert!(restored.settings.snmp_community.is_empty());
    }
    #[test]
    fn csv_target_import_uses_only_address_column() {
        let path = std::env::temp_dir().join(format!("ip-scout-targets-{}.csv", uuid_for_test()));
        std::fs::write(&path,"IP,Hostname,Open TCP ports\n127.0.0.1,nas,8080\n127.0.0.3,printer,9100\n127.0.0.1,nas,8080\n").unwrap();
        let targets = TargetSet::parse(&read_target_file(path.clone()).unwrap()).unwrap();
        assert_eq!(targets.len(), 2);
        assert!(!targets.contains(Ipv4Addr::new(127, 0, 0, 2)));
        std::fs::remove_file(path).unwrap();
    }
    fn uuid_for_test() -> String {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_string()
    }
}
