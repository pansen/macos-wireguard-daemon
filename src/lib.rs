// tunmux library crate
//
// Exports the modules shared between the `tunmux` binary and any library
// consumers. This build targets macOS only and serves the WireGuard
// config-file (`wgconf`) path.

// Provider-agnostic infrastructure
pub mod autoconnect;
pub mod cli;
pub mod config;
pub mod error;
pub mod launchctl;
pub mod launchd;
pub mod logging;
pub mod shared;

// WireGuard config-file provider (the sole provider in this build)
pub mod wgconf;

// WireGuard config and connection state, plus the userspace/wg-quick backends.
pub mod wireguard;

// Privileged API types (portable serde types only, no unix deps)
pub mod privileged_api;

pub mod privileged;
pub mod privileged_client;
