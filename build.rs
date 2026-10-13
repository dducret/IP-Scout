fn main() {
    println!("cargo:rerun-if-changed=assets/ip-scout.ico");
    println!("cargo:rerun-if-changed=Cargo.toml");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        winresource::WindowsResource::new()
            .set_icon("assets/ip-scout.ico")
            .set("ProductName", "IP Scout")
            .set("OriginalFilename", "ip-scout.exe")
            .compile_for("ip-scout")
            .expect("failed to embed the IP Scout executable icon with the Windows SDK");
    }
}
