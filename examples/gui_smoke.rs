#[path = "../src/app.rs"]
mod app;

use eframe::{App, egui};
use std::{
    collections::HashSet,
    net::TcpListener,
    time::{Duration, Instant},
};

struct SmokeApp {
    scout: app::ScoutApp,
    listener: TcpListener,
    stage: usize,
    waiting: bool,
    settled: Instant,
    started: Instant,
    ports_phase: usize,
    pending_events: Vec<egui::Event>,
    copy_clicked: bool,
    copy_verified: bool,
    fetcher_phase: usize,
}

impl App for SmokeApp {
    fn raw_input_hook(&mut self, _ctx: &egui::Context, input: &mut egui::RawInput) {
        input.events.append(&mut self.pending_events);
    }

    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        assert!(
            self.started.elapsed() < Duration::from_secs(120),
            "GUI smoke test timed out"
        );
        let captures = ctx.input(|input| {
            input
                .events
                .iter()
                .filter_map(|event| {
                    if let egui::Event::Screenshot { image, .. } = event {
                        Some(image.clone())
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>()
        });
        for image in captures {
            let colors: HashSet<_> = image.pixels.iter().map(|p| p.to_array()).collect();
            assert!(colors.len() > 100, "The GUI screenshot is blank");
            let bytes: Vec<_> = image.pixels.iter().flat_map(|p| p.to_array()).collect();
            let path = format!(
                "artifacts/gui-{}.png",
                [
                    "desktop-empty",
                    "desktop-results",
                    "small-details",
                    "small-dark-settings",
                    "small-scrolled-right",
                    "filtered-export",
                    "custom-port-editor",
                    "custom-ports-saved",
                    "invalid-port-error",
                    "copy-ip-list",
                    "copy-filtered-mac-list",
                    "copy-row-ip",
                    "copy-row-mac",
                    "copy-feedback-expired",
                    "fetcher-selection",
                    "fetcher-columns-applied",
                    "fetcher-small-dark",
                    "fetcher-cancelled",
                    "fetcher-empty-selection",
                    "fetcher-all-columns",
                    "new-fetchers",
                    "http-small-dark",
                    "new-fetcher-details",
                    "discovery-fetchers",
                    "discovery-small-dark",
                    "discovery-selection",
                    "advertisements",
                    "advertisements-small-dark",
                    "advertisements-selection",
                    "inventory-results",
                    "inventory-small-dark",
                    "inventory-details",
                    "inventory-selection",
                    "fast-mode-small",
                    "deep-mode-small",
                    "full-port-editor",
                    "full-ports-saved",
                    "udp-enabled",
                    "udp-port-editor",
                    "udp-ports-saved",
                    "udp-results",
                    "udp-small-dark-details",
                    "udp-snmp-settings",
                    "udp-full-port-editor",
                    "udp-full-ports-saved",
                    "stopped-wide-scan",
                    "stopped-small-details",
                    "rechecking-small-progress",
                    "rechecking-complete-progress",
                    "adaptive-desktop-settings",
                    "adaptive-small-settings",
                    "adaptive-disabled",
                    "large-range-results",
                    "large-range-search",
                    "large-range-metadata-sort"
                ][self.stage]
            );
            image::save_buffer(
                &path,
                &bytes,
                image.size[0] as u32,
                image.size[1] as u32,
                image::ColorType::Rgba8,
            )
            .unwrap();
            println!(
                "Verified {path}: {} x {}, {} colors",
                image.size[0],
                image.size[1],
                colors.len()
            );
            self.stage += 1;
            if self.stage == 55 {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                return;
            }
            self.scout
                .smoke_stage(self.stage, self.listener.local_addr().unwrap().port(), ctx);
            if self.stage == 7 {
                self.pending_events.extend(self.scout.smoke_port_click(2));
                self.ports_phase = 4;
            }
            if self.stage == 15 {
                self.pending_events
                    .extend(self.scout.smoke_fetcher_click(5));
                self.fetcher_phase = 5;
            }
            if self.stage == 17 {
                self.pending_events
                    .extend(self.scout.smoke_fetcher_click(6));
                self.fetcher_phase = 8;
            }
            if matches!(self.stage, 36 | 39 | 44) {
                self.pending_events.extend(self.scout.smoke_port_click(2));
            }
            self.waiting = false;
            self.copy_clicked = false;
            self.copy_verified = false;
            self.settled = Instant::now();
        }
        if self.stage == 14
            && self.fetcher_phase < 4
            && self.settled.elapsed() > Duration::from_millis((self.fetcher_phase as u64 + 1) * 100)
        {
            let button = [0, 1, 2, 3][self.fetcher_phase];
            if self.pending_events.is_empty() && self.scout.smoke_fetcher_ready(button) {
                self.pending_events
                    .extend(self.scout.smoke_fetcher_click(button));
                self.fetcher_phase += 1;
            }
        }
        if self.stage == 16
            && self.fetcher_phase == 6
            && self.settled.elapsed() > Duration::from_millis(150)
        {
            self.pending_events
                .extend(self.scout.smoke_fetcher_click(4));
            self.fetcher_phase = 7;
        }
        if self.stage == 6 {
            match self.ports_phase {
                0 if self.settled.elapsed() > Duration::from_millis(100) => {
                    self.pending_events.extend(self.scout.smoke_port_click(0));
                    self.ports_phase = 1;
                }
                1 if self.settled.elapsed() > Duration::from_millis(200) => {
                    self.pending_events.extend(self.scout.smoke_port_click(1));
                    self.ports_phase = 2;
                }
                2 if self.settled.elapsed() > Duration::from_millis(300) => {
                    self.pending_events.extend(self.scout.smoke_type_ports());
                    self.ports_phase = 3;
                }
                _ => {}
            }
        }
        if (9..=12).contains(&self.stage)
            && !self.copy_clicked
            && self.settled.elapsed() > Duration::from_millis(150)
        {
            self.pending_events
                .extend(self.scout.smoke_copy_click(self.stage - 9));
            self.copy_clicked = true;
        }
        if self.stage == 32
            && !self.copy_clicked
            && self.scout.smoke_fetcher_ready(8)
            && self.pending_events.is_empty()
        {
            self.pending_events
                .extend(self.scout.smoke_fetcher_click(8));
            self.copy_clicked = true;
        }
        self.scout.update(ctx, frame);
        if self.stage == 32 && self.copy_clicked && self.pending_events.is_empty() {
            self.scout.smoke_verify_inventory();
        }
        if (self.stage == 15 && self.fetcher_phase == 5
            || self.stage == 17 && self.fetcher_phase == 8)
            && self.pending_events.is_empty()
        {
            self.scout.smoke_verify_fetchers_applied();
            self.fetcher_phase += 1;
        }
        if (9..=12).contains(&self.stage)
            && self.copy_clicked
            && !self.copy_verified
            && self.pending_events.is_empty()
        {
            let expected = match self.stage {
                9 => "192.0.2.1\n192.0.2.2\n192.0.2.3",
                10 | 12 => "02:11:22:33:44:01",
                11 => "192.0.2.1",
                _ => unreachable!(),
            };
            assert!(ctx.output(|output| output.commands.iter().any(|command| matches!(command, egui::OutputCommand::CopyText(text) if text == expected))), "The copy button did not send the expected addresses to the clipboard");
            self.copy_verified = true;
            self.scout
                .smoke_verify_copy_feedback(ctx, self.stage - 9, true);
            // Check clipboard dispatch without replacing the user's clipboard.
            ctx.output_mut(|output| {
                output
                    .commands
                    .retain(|command| !matches!(command, egui::OutputCommand::CopyText(_)))
            });
        }
        if self.stage == 13 && self.settled.elapsed() > Duration::from_millis(2200) {
            self.scout.smoke_verify_copy_feedback(ctx, 3, false);
        }
        if self.stage == 7 && self.ports_phase == 4 && self.pending_events.is_empty() {
            self.scout.smoke_verify_ports_during_scan();
            self.ports_phase = 5;
        }
        if matches!(self.stage, 33 | 34)
            && !self.copy_clicked
            && self.settled.elapsed() > Duration::from_millis(150)
            && let Some(events) = self.scout.smoke_mode_click(self.stage - 33)
        {
            self.pending_events.extend(events);
            self.copy_clicked = true;
        }
        if matches!(self.stage, 33 | 34) && self.copy_clicked && self.pending_events.is_empty() {
            self.scout.smoke_verify_mode(self.stage == 33);
            self.copy_verified = true;
        }
        if self.stage == 36 && self.pending_events.is_empty() {
            self.scout.smoke_verify_full_ports();
        }
        if self.stage == 37
            && !self.copy_clicked
            && self.settled.elapsed() > Duration::from_millis(150)
            && let Some(events) = self.scout.smoke_udp_click()
        {
            self.pending_events.extend(events);
            self.copy_clicked = true;
        }
        if self.stage == 37 && self.copy_clicked && self.pending_events.is_empty() {
            self.scout.smoke_verify_udp(37);
            self.copy_verified = true;
        }
        if matches!(self.stage, 39 | 44) && self.pending_events.is_empty() {
            self.scout.smoke_verify_udp(self.stage);
        }
        if !self.waiting
            && (self.scout.smoke_ready() || (self.stage == 6 && self.ports_phase == 3))
            && self.settled.elapsed() > Duration::from_millis(500)
            && (self.stage != 13 || self.settled.elapsed() > Duration::from_millis(2200))
            && (!matches!(self.stage, 33 | 34 | 37) || self.copy_verified)
        {
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
            self.waiting = true;
        }
        ctx.request_repaint_after(Duration::from_millis(30));
    }

    fn persist_egui_memory(&self) -> bool {
        false
    }
}

fn main() -> eframe::Result {
    std::fs::create_dir_all("artifacts").unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    eframe::run_native(
        "IP Scout GUI verification",
        eframe::NativeOptions {
            persist_window: false,
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1180.0, 760.0])
                .with_min_inner_size([820.0, 540.0])
                .with_visible(false),
            ..Default::default()
        },
        Box::new(move |cc| {
            let mut scout = app::ScoutApp::new(cc);
            scout.smoke_stage(0, listener.local_addr().unwrap().port(), &cc.egui_ctx);
            Ok(Box::new(SmokeApp {
                scout,
                listener,
                stage: 0,
                waiting: false,
                settled: Instant::now(),
                started: Instant::now(),
                ports_phase: 0,
                pending_events: Vec::new(),
                copy_clicked: false,
                copy_verified: false,
                fetcher_phase: 0,
            }))
        }),
    )
}
