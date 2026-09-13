fn main() {
    println!("cargo:rerun-if-env-changed=WGD_GIT_TAG");

    let build_version = std::env::var("WGD_GIT_TAG")
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    println!("cargo:rustc-env=WGD_BUILD_VERSION={build_version}");
}
