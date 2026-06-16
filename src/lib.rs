// tunmux library crate
//
// Exports the modules shared between the `tunmux` binary and any library
// consumers. This build targets desktop (Linux/macOS) only and serves the
// WireGuard config-file (`wgconf`) path.

// Provider-agnostic infrastructure
pub mod cli;
pub mod config;
pub mod error;
pub mod logging;
pub mod shared;

// WireGuard config-file provider (the sole provider in this build)
pub mod wgconf;

// WireGuard config and connection state (portable);
// backend implementations (kernel, wg_quick, userspace) are cfg-gated inside wireguard/mod.rs
pub mod wireguard;

// Privileged API types (portable serde types only, no unix deps)
pub mod privileged_api;

// Network namespaces: real implementation on Linux, stub on other platforms (macOS)
#[cfg(target_os = "linux")]
pub mod netns;
#[cfg(not(target_os = "linux"))]
#[path = "netns_stub.rs"]
pub mod netns;

pub mod privileged;
pub mod privileged_client;

// Proxy daemon: real implementation on Linux with the proxy feature, stub otherwise
#[cfg(all(feature = "proxy", target_os = "linux"))]
#[path = "proxy/mod.rs"]
pub mod proxy;
#[cfg(not(all(feature = "proxy", target_os = "linux")))]
#[path = "proxy_stub.rs"]
pub mod proxy;
