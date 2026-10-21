#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod app;

fn main() -> eframe::Result {
    eframe::run_native(
        "IP Scout",
        eframe::NativeOptions {
            viewport: eframe::egui::ViewportBuilder::default()
                .with_inner_size([1180.0, 760.0])
                .with_min_inner_size([820.0, 540.0])
                .with_icon(
                    eframe::icon_data::from_png_bytes(include_bytes!(concat!(
                        env!("OUT_DIR"),
                        "/runtime-logo.png"
                    )))
                    .expect("bundled IP Scout logo must be a valid PNG"),
                ),
            centered: true,
            ..Default::default()
        },
        Box::new(|cc| Ok(Box::new(app::ScoutApp::new(cc)))),
    )
}
