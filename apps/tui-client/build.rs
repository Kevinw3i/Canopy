fn main() {
    println!("cargo:rerun-if-env-changed=CANOPY_BUILD_VERSION");

    if let Ok(version) = std::env::var("CANOPY_BUILD_VERSION") {
        let version = version.trim();
        if !version.is_empty() {
            println!("cargo:rustc-env=CANOPY_TUI_VERSION={version}");
        }
    }
}
