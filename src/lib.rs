// tunmux library crate
//
// Exports the modules shared between the `tunmux` binary and any library
// consumers. This build targets macOS only.

// Provider-agnostic infrastructure
pub mod cli;
pub mod color;
pub mod config;
pub mod error;
pub mod launchctl;
pub mod launchd;
pub mod logging;
pub mod reload;
pub mod session_agent;
pub mod state_file;
pub mod trusted_exec;

// WireGuard config parsing shared by the CLI and the privileged daemon.
pub mod wireguard;

// Privileged API types (portable serde types only, no unix deps)
pub mod privileged_api;

pub mod privileged;
pub mod privileged_client;
