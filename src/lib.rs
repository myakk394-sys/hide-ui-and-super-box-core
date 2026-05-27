//! # super_box
//!
//! Ultra-lightweight Hidekey proxy core written in pure async Rust.
//!
//! ## Architecture (sing-box inspired)
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                         super_box                                │
//! │                                                                  │
//! │  ┌─────────────┐    ┌─────────────┐    ┌──────────────────────┐ │
//! │  │  inbound.rs  │───▶│  router.rs  │───▶│    outbound.rs       │ │
//! │  │  (SOCKS5 /  │    │  (planned)  │    │ (Hidekey connector / │ │
//! │  │  HTTP proxy)│    └─────────────┘    │   server simulation) │ │
//! │  └─────────────┘                       └──────────────────────┘ │
//! │         ▲                                         │              │
//! │         │         config.rs (Arc<Config>)         │              │
//! │         └─────────────────────────────────────────┘              │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Modules
//!
//! - [`config`]   — Hidekey URI parser and [`Config`] structure.
//! - [`inbound`]  — Local TCP listener (client-facing SOCKS5/HTTP side).
//! - [`outbound`] — Remote TCP listener (server-facing Hidekey side /
//!                  test-mode server simulation).
//!
//! [`Config`]: config::Config

pub mod config;
pub mod inbound;
pub mod outbound;
pub mod stats;
pub mod tls13;
pub mod tun_device;
pub mod hidekey;
pub mod hideui;
