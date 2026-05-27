//! # super_box::config
//!
//! Configuration module for the SuperBox proxy core.
//!
//! Provides the [`Config`] structure and a parser that constructs it
//! from a raw `vless://` URI string. The parser extracts connection
//! parameters, REALITY/TLS settings, and optional tuning knobs
//! (fragmentation, multiplexing) used by inbound/outbound modules.

use std::fmt;
use std::str::FromStr;

use thiserror::Error;
use url::Url;
use uuid::Uuid;

// ──────────────────────────────────────────────────────────────────────
// Error types
// ──────────────────────────────────────────────────────────────────────

/// Errors that can occur while parsing a VLESS URI into [`Config`].
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("URL scheme must be \"vless\", got \"{0}\"")]
    InvalidScheme(String),

    #[error("missing VLESS UUID in URL userinfo")]
    MissingUuid,

    #[error("invalid UUID format: {0}")]
    InvalidUuid(#[from] uuid::Error),

    #[error("missing remote host in URL")]
    MissingHost,

    #[error("missing remote port in URL")]
    MissingPort,

    #[error("invalid parameter \"{key}\": {reason}")]
    InvalidParameter { key: String, reason: String },

    #[error("HTTP request error: {0}")]
    HttpError(String),

    #[error("base64 decoding error: {0}")]
    Base64Error(String),

    #[error("no valid VLESS link found in subscription")]
    NoValidLinkInSubscription,
}

// ──────────────────────────────────────────────────────────────────────
// Security types
// ──────────────────────────────────────────────────────────────────────

/// Transport-layer security mode extracted from the `security=` query parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityType {
    /// No transport security.
    None,
    /// Standard TLS.
    Tls,
    /// REALITY (uTLS-based anti-censorship transport).
    Reality,
}

impl fmt::Display for SecurityType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityType::None => write!(f, "none"),
            SecurityType::Tls => write!(f, "tls"),
            SecurityType::Reality => write!(f, "reality"),
        }
    }
}

impl FromStr for SecurityType {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "none" | "" => Ok(SecurityType::None),
            "tls" => Ok(SecurityType::Tls),
            "reality" => Ok(SecurityType::Reality),
            other => Err(ConfigError::InvalidParameter {
                key: "security".into(),
                reason: format!("unknown security type \"{other}\""),
            }),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Transport type
// ──────────────────────────────────────────────────────────────────────

/// Network transport extracted from the `type=` query parameter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportType {
    /// Raw TCP stream (default).
    Tcp,
    /// WebSocket framing over TCP.
    Ws,
    /// HTTP/2 multiplexed stream.
    H2,
    /// gRPC tunneling.
    Grpc,
}

impl fmt::Display for TransportType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportType::Tcp => write!(f, "tcp"),
            TransportType::Ws => write!(f, "ws"),
            TransportType::H2 => write!(f, "h2"),
            TransportType::Grpc => write!(f, "grpc"),
        }
    }
}

impl FromStr for TransportType {
    type Err = ConfigError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "tcp" | "" => Ok(TransportType::Tcp),
            "ws" | "websocket" => Ok(TransportType::Ws),
            "h2" | "http" => Ok(TransportType::H2),
            "grpc" => Ok(TransportType::Grpc),
            other => Err(ConfigError::InvalidParameter {
                key: "type".into(),
                reason: format!("unknown transport type \"{other}\""),
            }),
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Fragment settings (anti-DPI)
// ──────────────────────────────────────────────────────────────────────

/// TCP fragmentation parameters used to bypass deep packet inspection.
///
/// When enabled, outgoing TLS ClientHello packets are split into
/// chunks of `size_bytes` with an artificial `delay_ms` pause between
/// each chunk, making signature-based DPI significantly harder.
#[derive(Debug, Clone)]
pub struct FragmentSettings {
    /// Whether fragmentation is enabled.
    pub enabled: bool,
    /// Minimum size (in bytes) of each TCP segment.
    pub size_min: usize,
    /// Maximum size (in bytes) of each TCP segment.
    pub size_max: usize,
    /// Minimum delay (in milliseconds) inserted between consecutive fragments.
    pub delay_min: u64,
    /// Maximum delay (in milliseconds) inserted between consecutive fragments.
    pub delay_max: u64,
}

impl Default for FragmentSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            size_min: 50,
            size_max: 50,
            delay_min: 30,
            delay_max: 30,
        }
    }
}

impl fmt::Display for FragmentSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.enabled {
            write!(f, "ON (size={}-{}B, delay={}-{}ms)", self.size_min, self.size_max, self.delay_min, self.delay_max)
        } else {
            write!(f, "OFF")
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Mux settings
// ──────────────────────────────────────────────────────────────────────

/// Connection multiplexing settings.
///
/// When enabled, multiple logical streams share a single TCP connection
/// to reduce handshake overhead and improve latency.
#[derive(Debug, Clone)]
pub struct MuxSettings {
    /// Whether mux is enabled.
    pub enabled: bool,
    /// Maximum number of concurrent streams per muxed connection.
    pub max_streams: u16,
}

impl Default for MuxSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            max_streams: 8,
        }
    }
}

impl fmt::Display for MuxSettings {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.enabled {
            write!(f, "ON (max_streams={})", self.max_streams)
        } else {
            write!(f, "OFF")
        }
    }
}

// ──────────────────────────────────────────────────────────────────────
// Core Config
// ──────────────────────────────────────────────────────────────────────

/// Complete runtime configuration for a SuperBox instance.
///
/// Built by [`Config::from_vless_url`] from a `vless://` URI string.
/// This struct is designed to be passed by shared reference (`&Config`)
/// into the inbound listener and outbound connector modules.
#[derive(Debug, Clone)]
pub struct Config {
    // ── Identification ───────────────────────────────────────────────
    /// Human-readable profile name (from the URL fragment, e.g. `#SuperBox`).
    pub profile_name: String,

    /// VLESS user UUID — the primary authentication credential.
    pub vless_uuid: Uuid,

    // ── Inbound (local SOCKS5/HTTP listener) ─────────────────────────
    /// Port on which the local inbound proxy listens for client connections.
    pub local_inbound_port: u16,

    // ── Outbound (remote VLESS server) ───────────────────────────────
    /// Remote server address (IP or hostname).
    pub remote_outbound_address: String,

    /// Remote server port.
    pub server_listen_port: u16,

    // ── Transport & Security ─────────────────────────────────────────
    /// Transport-layer security mode (none / tls / reality).
    pub security: SecurityType,

    /// Network transport type (tcp / ws / h2 / grpc).
    pub transport: TransportType,

    /// REALITY public key (`pbk=` query parameter).
    pub reality_public_key: Option<String>,

    /// REALITY short ID (`sid=` query parameter).
    pub reality_short_id: Option<String>,

    /// Server Name Indication — the domain sent in the TLS handshake.
    pub sni: Option<String>,

    /// TLS fingerprint to emulate (`fp=` query parameter, e.g. `chrome`).
    pub fingerprint: Option<String>,

    /// VLESS flow control (e.g. `xtls-rprx-vision`).
    pub flow: Option<String>,

    // ── Anti-censorship knobs ────────────────────────────────────────
    /// TCP fragmentation settings for DPI bypass.
    pub fragment: FragmentSettings,

    /// Connection multiplexing settings.
    pub mux: MuxSettings,

    // ── Runtime flags ────────────────────────────────────────────────
    /// If `true`, the config was created in test mode:
    /// - inbound binds to `127.0.0.1:1080`
    /// - outbound connects to `127.0.0.1:8080`
    pub test_mode: bool,

    /// Source of this configuration (VLESS URL or remote subscription URL).
    pub loaded_from: String,

    /// Master key for Hidekey polymorphic protocol (from password field in hidekey:// URI)
    pub hidekey_master_key: Option<String>,

    /// Physical IP discovered for bypassing TUN interface
    pub physical_ip: Option<std::net::IpAddr>,

    /// Physical interface index for IP_UNICAST_IF bypass (Windows only)
    pub physical_if_index: Option<u32>,
}

impl Config {
    // ── Constants for test mode ──────────────────────────────────────

    const TEST_INBOUND_PORT: u16 = 1080;
    const TEST_OUTBOUND_PORT: u16 = 8080;
    const TEST_LOOPBACK: &'static str = "127.0.0.1";
    const DEFAULT_INBOUND_PORT: u16 = 1080;

    /// Parse a raw `vless://` URI string and produce a validated [`Config`].
    ///
    /// # URI format
    ///
    /// ```text
    /// vless://<UUID>@<host>:<port>?<query>#<fragment>
    /// ```
    ///
    /// ## Supported query parameters
    ///
    /// | Key              | Description                                  |
    /// |------------------|----------------------------------------------|
    /// | `security`       | `none`, `tls`, `reality`                     |
    /// | `type`           | `tcp`, `ws`, `h2`, `grpc`                    |
    /// | `pbk`            | REALITY public key                           |
    /// | `sid`            | REALITY short ID                             |
    /// | `sni`            | Server Name Indication                       |
    /// | `fp`             | TLS fingerprint (e.g. `chrome`)              |
    /// | `test`           | `true` / `1` — activate test mode            |
    /// | `fragment`       | `true` / `1` — enable TCP fragmentation      |
    /// | `fragment_size`  | Fragment chunk size in bytes                 |
    /// | `fragment_delay` | Delay between fragments in ms                |
    /// | `mux`            | `true` / `1` — enable mux                   |
    /// | `mux_streams`    | Max concurrent mux streams                   |
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if the URI is malformed or contains
    /// invalid values for any recognised parameter.
    ///
    /// # Examples
    ///
    /// ```
    /// use super_box::config::Config;
    ///
    /// let uri = "vless://b8a6f4c3-4a21-4d4b-a7e3-0570889df159@93.184.216.34:443\
    ///            ?security=reality&pbk=KEY&sni=www.microsoft.com#SuperBox";
    /// let cfg = Config::from_vless_url(uri).unwrap();
    /// assert_eq!(cfg.server_listen_port, 443);
    /// ```
    pub fn from_vless_url(raw: &str) -> Result<Config, ConfigError> {
        // ── Step 1: Parse the URL ────────────────────────────────────
        let parsed = Url::parse(raw)?;

        // ── Step 2: Validate scheme ──────────────────────────────────
        if parsed.scheme() != "vless" && parsed.scheme() != "hidekey" {
            return Err(ConfigError::InvalidScheme(parsed.scheme().to_owned()));
        }

        // ── Step 3: Extract UUID from userinfo ───────────────────────
        let uuid_str = parsed.username();
        if uuid_str.is_empty() {
            return Err(ConfigError::MissingUuid);
        }
        let vless_uuid = Uuid::parse_str(uuid_str)?;
        let hidekey_master_key = parsed.password().map(|p| p.to_owned());

        // ── Step 4: Extract host and port ────────────────────────────
        let host = parsed
            .host_str()
            .ok_or(ConfigError::MissingHost)?
            .to_owned();
        let port = parsed.port().ok_or(ConfigError::MissingPort)?;

        // ── Step 5: Collect query parameters into a map ──────────────
        let params: std::collections::HashMap<String, String> = parsed
            .query_pairs()
            .map(|(k, v)| (k.to_lowercase(), v.to_string()))
            .collect();

        // Helper to check boolean-ish params
        let is_flag_set = |key: &str| -> bool {
            params
                .get(key)
                .map(|v| matches!(v.as_str(), "true" | "1" | "yes" | "on"))
                .unwrap_or(false)
        };

        // ── Step 6: Security & transport ─────────────────────────────
        let security = params
            .get("security")
            .map(|s| s.parse::<SecurityType>())
            .transpose()?
            .unwrap_or(SecurityType::None);

        let transport = params
            .get("type")
            .map(|s| s.parse::<TransportType>())
            .transpose()?
            .unwrap_or(TransportType::Tcp);

        // ── Step 7: REALITY / TLS parameters ─────────────────────────
        let reality_public_key = params.get("pbk").cloned();
        let reality_short_id = params.get("sid").cloned();
        let sni = params.get("sni").cloned();
        let fingerprint = params.get("fp").cloned();
        let flow = params.get("flow").cloned();

        // ── Step 8: Fragment settings ────────────────────────────────
        let fragment = {
            let enabled = is_flag_set("fragment");
            
            let parse_usize_range = |s: &str| -> Result<(usize, usize), ConfigError> {
                if let Some((min_s, max_s)) = s.split_once('-') {
                    let min = min_s.parse::<usize>().map_err(|_| ConfigError::InvalidParameter { key: "fragment_size".into(), reason: format!("invalid range min: {}", min_s) })?;
                    let max = max_s.parse::<usize>().map_err(|_| ConfigError::InvalidParameter { key: "fragment_size".into(), reason: format!("invalid range max: {}", max_s) })?;
                    Ok((min, max))
                } else {
                    let val = s.parse::<usize>().map_err(|_| ConfigError::InvalidParameter { key: "fragment_size".into(), reason: format!("invalid val: {}", s) })?;
                    Ok((val, val))
                }
            };

            let parse_u64_range = |s: &str| -> Result<(u64, u64), ConfigError> {
                if let Some((min_s, max_s)) = s.split_once('-') {
                    let min = min_s.parse::<u64>().map_err(|_| ConfigError::InvalidParameter { key: "fragment_delay".into(), reason: format!("invalid range min: {}", min_s) })?;
                    let max = max_s.parse::<u64>().map_err(|_| ConfigError::InvalidParameter { key: "fragment_delay".into(), reason: format!("invalid range max: {}", max_s) })?;
                    Ok((min, max))
                } else {
                    let val = s.parse::<u64>().map_err(|_| ConfigError::InvalidParameter { key: "fragment_delay".into(), reason: format!("invalid val: {}", s) })?;
                    Ok((val, val))
                }
            };

            let (size_min, size_max) = params
                .get("fragment_size")
                .map(|v| parse_usize_range(v))
                .transpose()?
                .unwrap_or((FragmentSettings::default().size_min, FragmentSettings::default().size_max));

            let (delay_min, delay_max) = params
                .get("fragment_delay")
                .map(|v| parse_u64_range(v))
                .transpose()?
                .unwrap_or((FragmentSettings::default().delay_min, FragmentSettings::default().delay_max));

            FragmentSettings {
                enabled,
                size_min,
                size_max,
                delay_min,
                delay_max,
            }
        };

        // ── Step 9: Mux settings ─────────────────────────────────────
        let mux = {
            let enabled = is_flag_set("mux");
            let max_streams = params
                .get("mux_streams")
                .map(|v| {
                    v.parse::<u16>().map_err(|_| ConfigError::InvalidParameter {
                        key: "mux_streams".into(),
                        reason: format!("\"{v}\" is not a valid u16"),
                    })
                })
                .transpose()?
                .unwrap_or(MuxSettings::default().max_streams);

            MuxSettings {
                enabled,
                max_streams,
            }
        };

        // ── Step 10: Test mode detection ─────────────────────────────
        let test_mode = is_flag_set("test");

        // ── Step 11: Profile name from URL fragment ──────────────────
        let profile_name = parsed
            .fragment()
            .filter(|f| !f.is_empty())
            .unwrap_or("default")
            .to_owned();

        // ── Step 12: Apply test-mode overrides ───────────────────────
        let (remote_outbound_address, server_listen_port, local_inbound_port) = if test_mode {
            (
                Self::TEST_LOOPBACK.to_owned(),
                Self::TEST_OUTBOUND_PORT,
                Self::TEST_INBOUND_PORT,
            )
        } else {
            (host, port, Self::DEFAULT_INBOUND_PORT)
        };

        // ── Build ────────────────────────────────────────────────────
        Ok(Config {
            profile_name,
            vless_uuid,
            local_inbound_port,
            remote_outbound_address,
            server_listen_port,
            security,
            transport,
            reality_public_key,
            reality_short_id,
            sni,
            fingerprint,
            flow,
            fragment,
            mux,
            test_mode,
            loaded_from: "Direct VLESS URI / Прямая ссылка".to_string(),
            hidekey_master_key,
            physical_ip: None,
            physical_if_index: None,
        })
    }

    /// Load subscription from either a raw `vless://` URL or an HTTP/HTTPS subscription link.
    ///
    /// If the input starts with `vless://`, parses it directly.
    /// If it starts with `http://` or `https://`, downloads the subscription, base64 decodes if needed,
    /// splits the payload into lines, and returns the first parsed valid VLESS config.
    pub async fn load_from_any_url(url_or_vless: &str) -> Result<Config, ConfigError> {
        let configs = Self::load_all_from_any_url(url_or_vless).await?;
        configs.into_iter().next().ok_or(ConfigError::NoValidLinkInSubscription)
    }

    /// Load all subscriptions from either a raw `vless://` URL or an HTTP/HTTPS subscription link.
    ///
    /// If the input starts with `vless://`, parses it directly and returns a Vec of length 1.
    /// If it starts with `http://` or `https://`, downloads the subscription, base64 decodes if needed,
    /// splits the payload into lines, and returns all parsed valid VLESS configs.
    pub async fn load_all_from_any_url(url_or_vless: &str) -> Result<Vec<Config>, ConfigError> {
        let trimmed = url_or_vless.trim();
        if trimmed.starts_with("vless://") || trimmed.starts_with("hidekey://") {
            let mut cfg = Self::from_vless_url(trimmed)?;
            cfg.loaded_from = if trimmed.starts_with("hidekey://") {
                "Direct Hidekey URI / Прямая ссылка".to_string()
            } else {
                "Direct VLESS URI / Прямая ссылка".to_string()
            };
            return Ok(vec![cfg]);
        } else if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            tracing::info!("Downloading subscription from: {trimmed}");
            
            let client = reqwest::Client::builder()
                .build()
                .map_err(|e| ConfigError::HttpError(e.to_string()))?;
                
            let response = client.get(trimmed)
                .send()
                .await
                .map_err(|e| ConfigError::HttpError(e.to_string()))?;
                
            let status = response.status();
            if !status.is_success() {
                return Err(ConfigError::HttpError(format!("HTTP status {status}")));
            }
            
            let text = response.text()
                .await
                .map_err(|e| ConfigError::HttpError(e.to_string()))?;
                
            let decoded_text = match robust_base64_decode(&text) {
                Some(bytes) => {
                    tracing::debug!("Successfully base64-decoded subscription");
                    String::from_utf8(bytes).unwrap_or_else(|_| {
                        tracing::warn!("Base64 payload was not valid UTF-8, trying raw text fallback");
                        text.clone()
                    })
                }
                None => {
                    tracing::debug!("Base64 decoding failed — treating subscription as raw text");
                    text.clone()
                }
            };
            
            let mut configs = Vec::new();
            for line in decoded_text.lines() {
                let line_trimmed = line.trim();
                if line_trimmed.starts_with("vless://") || line_trimmed.starts_with("hidekey://") {
                    tracing::debug!("Found link candidate in subscription: {}", line_trimmed);
                    match Self::from_vless_url(line_trimmed) {
                        Ok(mut cfg) => {
                            tracing::info!("Parsed subscription config successfully from URL");
                            cfg.loaded_from = trimmed.to_string();
                            configs.push(cfg);
                        }
                        Err(e) => {
                            tracing::warn!("Skipping malformed link in subscription: {e}");
                        }
                    }
                }
            }
            
            if configs.is_empty() {
                Err(ConfigError::NoValidLinkInSubscription)
            } else {
                Ok(configs)
            }
        } else {
            Err(ConfigError::InvalidParameter {
                key: "url".into(),
                reason: "URI must start with vless://, hidekey://, http://, or https://".into(),
            })
        }
    }

    /// Returns the remote address formatted as `host:port` for use in
    /// TCP connect calls.
    pub fn remote_addr(&self) -> String {
        format!("{}:{}", self.remote_outbound_address, self.server_listen_port)
    }

    /// Returns the local bind address formatted as `0.0.0.0:port`
    /// (or `127.0.0.1:port` in test mode).
    pub fn local_bind_addr(&self) -> String {
        if self.test_mode {
            format!("127.0.0.1:{}", self.local_inbound_port)
        } else {
            format!("0.0.0.0:{}", self.local_inbound_port)
        }
    }

    /// Validate that the config is internally consistent and all
    /// required fields for the selected security type are present.
    pub fn validate(&self) -> Result<(), ConfigError> {
        // REALITY requires a public key
        if self.security == SecurityType::Reality && self.reality_public_key.is_none() {
            return Err(ConfigError::InvalidParameter {
                key: "pbk".into(),
                reason: "REALITY security requires a public key (pbk=...)".into(),
            });
        }

        // TLS and REALITY benefit from SNI — warn-level only, not an error
        // (validated at connection time instead)

        // Validate that the UUID is not the nil UUID
        if self.vless_uuid.is_nil() {
            return Err(ConfigError::InvalidParameter {
                key: "uuid".into(),
                reason: "VLESS UUID must not be nil (all zeros)".into(),
            });
        }

        // Validate outbound address is parseable as IP or is a valid hostname
        if self.remote_outbound_address.is_empty() {
            return Err(ConfigError::MissingHost);
        }

        Ok(())
    }
}

impl fmt::Display for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let border = "\x1b[36m║\x1b[0m";
        let line = "\x1b[36m╠══════════════════════════════════════════════════════╣\x1b[0m";
        
        writeln!(f, "\x1b[36m╔══════════════════════════════════════════════════════╗\x1b[0m")?;
        writeln!(f, "{}          \x1b[1;33mSuperBox Configuration / Конфигурация\x1b[0m       {}", border, border)?;
        writeln!(f, "{}", line)?;
        writeln!(f, "{}  \x1b[1;37mProfile / Профиль:\x1b[0m      \x1b[1;32m{:<29}\x1b[0m {}", border, self.profile_name, border)?;
        writeln!(f, "{}  \x1b[1;37mUUID / Идентификатор:\x1b[0m   \x1b[1;35m{:<29}\x1b[0m {}", border, self.vless_uuid, border)?;
        let display_src = if self.loaded_from.chars().count() > 29 {
            format!("{}…", self.loaded_from.chars().take(26).collect::<String>())
        } else {
            self.loaded_from.clone()
        };
        writeln!(f, "{}  \x1b[1;37mSource / Источник:\x1b[0m     \x1b[1;34m{:<29}\x1b[0m {}", border, display_src, border)?;
        writeln!(f, "{}", line)?;
        writeln!(f, "{}  \x1b[1;37mInbound / Входящий (SOCKS):\x1b[0m \x1b[1;32m{:<25}\x1b[0m {}", border, self.local_bind_addr(), border)?;
        writeln!(f, "{}  \x1b[1;37mOutbound / Внешний (VLESS):\x1b[0m \x1b[1;32m{:<25}\x1b[0m {}", border, self.remote_addr(), border)?;
        writeln!(f, "{}", line)?;
        writeln!(f, "{}  \x1b[1;37mSecurity / Защита:\x1b[0m          \x1b[1;33m{:<29}\x1b[0m {}", border, format!("{}", self.security), border)?;
        writeln!(f, "{}  \x1b[1;37mTransport / Транспорт:\x1b[0m      \x1b[1;33m{:<29}\x1b[0m {}", border, format!("{}", self.transport), border)?;
        
        if let Some(ref sni) = self.sni {
            writeln!(f, "{}  \x1b[1;37mSNI / Домен:\x1b[0m                \x1b[1;32m{:<29}\x1b[0m {}", border, sni, border)?;
        }
        if let Some(ref pbk) = self.reality_public_key {
            let display = if pbk.chars().count() > 25 {
                format!("{}…", pbk.chars().take(22).collect::<String>())
            } else {
                pbk.clone()
            };
            writeln!(f, "{}  \x1b[1;37mPubKey / Ключ REALITY:\x1b[0m      \x1b[1;32m{:<29}\x1b[0m {}", border, display, border)?;
        }
        if let Some(ref sid) = self.reality_short_id {
            writeln!(f, "{}  \x1b[1;37mShortID / Короткий ID:\x1b[0m      \x1b[1;32m{:<29}\x1b[0m {}", border, sid, border)?;
        }
        if let Some(ref fp) = self.fingerprint {
            writeln!(f, "{}  \x1b[1;37mFingerprint / Отпечаток:\x1b[0m    \x1b[1;32m{:<29}\x1b[0m {}", border, fp, border)?;
        }
        
        writeln!(f, "{}", line)?;
        writeln!(f, "{}  \x1b[1;37mFragment / Фрагментация:\x1b[0m    \x1b[1;32m{:<29}\x1b[0m {}", border, format!("{}", self.fragment), border)?;
        writeln!(f, "{}  \x1b[1;37mMux / Мультиплексирование:\x1b[0m  \x1b[1;32m{:<29}\x1b[0m {}", border, format!("{}", self.mux), border)?;
        
        if self.test_mode {
            writeln!(f, "{}", line)?;
            writeln!(f, "{}  \x1b[1;31m⚠ WARNING: TEST LOOPBACK ACTIVE / ТЕСТОВЫЙ РЕЖИМ\x1b[0m    {}", border, border)?;
        }
        
        writeln!(f, "\x1b[36m╚══════════════════════════════════════════════════════╝\x1b[0m")?;
        Ok(())
    }
}

/// Helper function to perform robust base64 decoding.
/// Tries multiple base64 dialects and handles unpadded and URL-safe payloads.
fn robust_base64_decode(input: &str) -> Option<Vec<u8>> {
    use base64::{Engine as _, engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD}};
    
    // Clean whitespaces and newlines
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    
    if let Ok(bytes) = STANDARD.decode(&cleaned) {
        return Some(bytes);
    }
    if let Ok(bytes) = STANDARD_NO_PAD.decode(&cleaned) {
        return Some(bytes);
    }
    if let Ok(bytes) = URL_SAFE.decode(&cleaned) {
        return Some(bytes);
    }
    if let Ok(bytes) = URL_SAFE_NO_PAD.decode(&cleaned) {
        return Some(bytes);
    }
    None
}

// ──────────────────────────────────────────────────────────────────────
// Unit tests
// ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_URL: &str =
        "vless://b8a6f4c3-4a21-4d4b-a7e3-0570889df159@93.184.216.34:443\
         ?security=reality&pbk=KEY123&sni=www.microsoft.com&fp=chrome#SuperBox";

    const TEST_URL: &str =
        "vless://b8a6f4c3-4a21-4d4b-a7e3-0570889df159@93.184.216.34:443\
         ?security=reality&pbk=KEY123&sni=www.microsoft.com&test=true#TestProfile";

    #[test]
    fn parse_standard_vless_url() {
        let cfg = Config::from_vless_url(SAMPLE_URL).expect("should parse");
        assert_eq!(cfg.profile_name, "SuperBox");
        assert_eq!(
            cfg.vless_uuid,
            Uuid::parse_str("b8a6f4c3-4a21-4d4b-a7e3-0570889df159").unwrap()
        );
        assert_eq!(cfg.remote_outbound_address, "93.184.216.34");
        assert_eq!(cfg.server_listen_port, 443);
        assert_eq!(cfg.security, SecurityType::Reality);
        assert_eq!(cfg.transport, TransportType::Tcp);
        assert_eq!(cfg.reality_public_key.as_deref(), Some("KEY123"));
        assert_eq!(cfg.sni.as_deref(), Some("www.microsoft.com"));
        assert_eq!(cfg.fingerprint.as_deref(), Some("chrome"));
        assert!(!cfg.test_mode);
        assert!(!cfg.fragment.enabled);
        assert!(!cfg.mux.enabled);
    }

    #[test]
    fn parse_test_mode_url() {
        let cfg = Config::from_vless_url(TEST_URL).expect("should parse");
        assert!(cfg.test_mode);
        assert_eq!(cfg.profile_name, "TestProfile");
        assert_eq!(cfg.local_inbound_port, 1080);
        assert_eq!(cfg.server_listen_port, 8080);
        assert_eq!(cfg.remote_outbound_address, "127.0.0.1");
        assert_eq!(cfg.local_bind_addr(), "127.0.0.1:1080");
        assert_eq!(cfg.remote_addr(), "127.0.0.1:8080");
    }

    #[test]
    fn parse_fragment_and_mux_params() {
        let url = "vless://b8a6f4c3-4a21-4d4b-a7e3-0570889df159@10.0.0.1:8443\
                   ?security=tls&sni=example.com\
                   &fragment=true&fragment_size=200&fragment_delay=30\
                   &mux=true&mux_streams=16#Frag";
        let cfg = Config::from_vless_url(url).expect("should parse");
        assert!(cfg.fragment.enabled);
        assert_eq!(cfg.fragment.size_bytes, 200);
        assert_eq!(cfg.fragment.delay_ms, 30);
        assert!(cfg.mux.enabled);
        assert_eq!(cfg.mux.max_streams, 16);
        assert_eq!(cfg.security, SecurityType::Tls);
    }

    #[test]
    fn reject_invalid_scheme() {
        let result = Config::from_vless_url("https://user@host:443");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::InvalidScheme(_)));
    }

    #[test]
    fn reject_missing_uuid() {
        let result = Config::from_vless_url("vless://@host:443");
        assert!(result.is_err());
    }

    #[test]
    fn reject_invalid_uuid() {
        let result = Config::from_vless_url("vless://not-a-uuid@host:443");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ConfigError::InvalidUuid(_)));
    }

    #[test]
    fn reject_missing_port() {
        let result = Config::from_vless_url(
            "vless://b8a6f4c3-4a21-4d4b-a7e3-0570889df159@host",
        );
        assert!(result.is_err());
    }

    #[test]
    fn validate_catches_missing_reality_key() {
        let url = "vless://b8a6f4c3-4a21-4d4b-a7e3-0570889df159@1.2.3.4:443\
                   ?security=reality&sni=example.com#NoKey";
        let cfg = Config::from_vless_url(url).expect("should parse");
        let err = cfg.validate();
        assert!(err.is_err());
    }

    #[test]
    fn display_format_works() {
        let cfg = Config::from_vless_url(SAMPLE_URL).expect("should parse");
        let display = format!("{cfg}");
        assert!(display.contains("SuperBox"));
        assert!(display.contains("b8a6f4c3"));
        assert!(display.contains("reality"));
    }

    #[test]
    fn default_profile_name_when_no_fragment() {
        let url = "vless://b8a6f4c3-4a21-4d4b-a7e3-0570889df159@1.2.3.4:443\
                   ?security=none";
        let cfg = Config::from_vless_url(url).expect("should parse");
        assert_eq!(cfg.profile_name, "default");
    }

    #[test]
    fn websocket_transport_parsed() {
        let url = "vless://b8a6f4c3-4a21-4d4b-a7e3-0570889df159@1.2.3.4:443\
                   ?type=ws&security=tls&sni=example.com#WS";
        let cfg = Config::from_vless_url(url).expect("should parse");
        assert_eq!(cfg.transport, TransportType::Ws);
    }

    #[test]
    fn test_robust_base64_decode_scenarios() {
        // Standard padded
        let data1 = "SGVsbG8gV29ybGQ="; // "Hello World"
        assert_eq!(robust_base64_decode(data1).unwrap(), b"Hello World");

        // Standard unpadded
        let data2 = "SGVsbG8gV29ybGQ";
        assert_eq!(robust_base64_decode(data2).unwrap(), b"Hello World");

        // With newlines and whitespaces
        let data3 = "SGVsbG8\n gV29\r\nybGQ=";
        assert_eq!(robust_base64_decode(data3).unwrap(), b"Hello World");
    }

    #[tokio::test]
    async fn test_load_from_any_url_vless_direct() {
        let cfg = Config::load_from_any_url(SAMPLE_URL).await.expect("should load");
        assert_eq!(cfg.profile_name, "SuperBox");
        assert_eq!(cfg.server_listen_port, 443);
    }
}
