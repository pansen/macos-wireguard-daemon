// wgd library crate
//
// Exports the modules shared between the `wgd` binary and any library
// consumers. This build targets macOS only.

/// `v0.1.5 bd3e6659` in release builds, the crate version otherwise (see
/// `build.rs`). The menu bar app shows it through `wgd-bar-ffi`.
pub const BUILD_LABEL: &str = env!("WGD_BUILD_LABEL");

// Provider-agnostic infrastructure
pub mod cli;
pub mod completion;
pub mod config;
pub mod dns_custody;
pub mod dns_dynamic_store;
pub mod doctor;
// Also home to the `<ID>` completer `cli` attaches to its connection
// positionals, so `cli` cannot compile without it.
pub mod connection_cli;
pub mod error;
pub mod launchctl;
pub mod launchd;
pub mod logging;
pub mod logs;
pub mod macos_dns;
// State for the menu bar app, exported to Swift by `crates/wgd-bar-ffi`.
pub mod menu_bar;
pub mod reload;
pub mod session_agent;
pub mod state_file;
pub mod status;
pub mod status_model;
pub mod status_notify;
pub mod status_render;
pub mod trusted_exec;
pub mod ui;

// WireGuard config parsing shared by the CLI and the privileged daemon.
pub mod wireguard;

// Privileged API types (portable serde types only, no unix deps)
pub mod privileged_api;

pub mod privileged;
pub mod privileged_client;
