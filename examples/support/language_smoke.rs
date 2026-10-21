//! Native visual and pointer-input verification of the language picker. No network probes.
use super::app;
use eframe::{App, egui};
use std::time::{Duration, Instant};

struct LanguageSmoke {
    scout: app::ScoutApp,
    stage: usize,
    phase: usize,
    pending: Vec<egui::Event>,
    settled: Instant,
    started: Instant,
    waiting: bool,
}

impl App for LanguageSmoke {
    fn raw_input_hook(&mut self, _ctx: &egui::Context, input: &mut egui::RawInput) {
        input.events.append(&mut self.pending);
    }

    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        assert!(
            self.started.elapsed() < Duration::from_secs(40),
            "language smoke test timed out"
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
            let name = [
                "english-settings",
                "french-settings",
                "french-small-settings",
                "french-fetchers",
                "english-small-settings",
                "automatic-settings",
            ][self.stage];
            let path = format!("artifacts/i18n-{name}.png");
            let bytes: Vec<_> = image
                .pixels
                .iter()
                .flat_map(|pixel| pixel.to_array())
                .collect();
            image::save_buffer(
                &path,
                &bytes,
                image.size[0] as u32,
                image.size[1] as u32,
                image::ColorType::Rgba8,
            )
            .unwrap();
            println!("Verified {path}: {} x {}", image.size[0], image.size[1]);
            self.stage += 1;
            if self.stage == 6 {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                return;
            }
            self.scout.smoke_language_layout(self.stage, ctx);
            self.phase = 0;
            self.waiting = false;
            self.settled = Instant::now();
        }
        self.scout.update(ctx, frame);
        let choice = match self.stage {
            1 => Some(3),
            4 => Some(2),
            5 => Some(1),
            _ => None,
        };
        if let Some(choice) = choice
            && self.phase < 2
            && self.pending.is_empty()
            && self.settled.elapsed() > Duration::from_millis(250)
            && let Some(events) =
                self.scout
                    .smoke_language_click(if self.phase == 0 { 0 } else { choice })
        {
            self.pending.extend(events);
            self.phase += 1;
            self.settled = Instant::now();
        }
        if !self.waiting
            && (choice.is_none() || self.phase == 2)
            && self.pending.is_empty()
            && self.settled.elapsed() > Duration::from_millis(500)
        {
            self.scout.smoke_language_verify(self.stage);
            ctx.send_viewport_cmd(egui::ViewportCommand::Screenshot(egui::UserData::default()));
            self.waiting = true;
        }
        ctx.request_repaint_after(Duration::from_millis(30));
    }

    fn persist_egui_memory(&self) -> bool {
        false
    }
}

pub fn run() -> eframe::Result {
    std::fs::create_dir_all("artifacts").unwrap();
    eframe::run_native(
        "IP Scout language verification",
        eframe::NativeOptions {
            persist_window: false,
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1180.0, 760.0])
                .with_min_inner_size([820.0, 540.0])
                .with_visible(false),
            ..Default::default()
        },
        Box::new(|cc| {
            let mut scout = app::ScoutApp::new(cc);
            scout.smoke_language_setup(&cc.egui_ctx);
            scout.smoke_language_layout(0, &cc.egui_ctx);
            Ok(Box::new(LanguageSmoke {
                scout,
                stage: 0,
                phase: 0,
                pending: Vec::new(),
                settled: Instant::now(),
                started: Instant::now(),
                waiting: false,
            }))
        }),
    )
}
