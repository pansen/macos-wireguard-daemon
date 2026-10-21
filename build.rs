fn main() {
    println!("cargo:rerun-if-env-changed=WGD_GIT_TAG");
    println!("cargo:rerun-if-env-changed=WGD_GIT_COMMIT");

    let build_version =
        env_nonempty("WGD_GIT_TAG").unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string());

    // The release workflow sets WGD_GIT_COMMIT; local builds leave it unset
    // and show the version alone.
    let build_label = match env_nonempty("WGD_GIT_COMMIT") {
        Some(commit) => format!("{build_version} {commit}"),
        None => build_version,
    };

    println!("cargo:rustc-env=WGD_BUILD_LABEL={build_label}");
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}
