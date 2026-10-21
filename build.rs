#[path = "build_support/assets.rs"]
mod assets;

fn main() {
    println!("cargo:rerun-if-changed=build_support/assets.rs");
    println!("cargo:rerun-if-changed=assets/ip-scout.ico");
    println!("cargo:rerun-if-changed=assets/ip-scout-logo.png");
    println!("cargo:rerun-if-changed=Cargo.toml");
    let out =
        std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo must set OUT_DIR"));
    assets::generate(&out).expect("failed to prepare embedded IEEE data and runtime logo");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/ip-scout.ico")
            .set("ProductName", "IP Scout")
            .set("OriginalFilename", "ip-scout.exe")
            .compile_for("ip-scout")
            .expect("failed to embed the IP Scout executable icon with the Windows SDK");
    }
}
