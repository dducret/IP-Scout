#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;

fn main() -> eframe::Result {
    eframe::run_native(
        "IP Scout",
        eframe::NativeOptions {
            viewport: eframe::egui::ViewportBuilder::default()
                .with_inner_size([1180.0, 760.0])
                .with_min_inner_size([820.0, 540.0]),
            centered: true,
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(app::ScoutApp::new(cc)))),
    )
}
