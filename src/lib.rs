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
pub mod outbound_udp;
pub mod stats;
pub mod tls13;
pub mod tun_device;
pub mod hidekey;
pub mod hideui;

/// Android JNI entry points — compiled only when targeting Android.
/// The source lives in `android/jni_wrapper.rs` and is included here
/// so it can access all private crate internals (config, inbound, etc.).
#[cfg(target_os = "android")]
#[path = "../android/jni_wrapper.rs"]
pub mod android;

/// C-compatible API bindings — compiled on non-Android UNIX targets (such as iOS or Linux) for C integration.
#[cfg(all(target_family = "unix", not(target_os = "android")))]
pub mod c_api;
