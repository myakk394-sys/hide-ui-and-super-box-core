//! # hidekey::tls_tunnel
//!
//! TLS 1.3 wrapper for the Hidekey transport layer.
//!
//! ## Threat model: JA3/JA4 fingerprinting by ТСПУ
//!
//! ТСПУ (and commercial DPI boxes like СКАТ/ТСПУ-ДПИ) fingerprint TLS
//! ClientHello using JA3/JA4 hashes.  A default rustls ClientHello has a
//! unique fingerprint that is trivially identified as "not a browser".
//!
//! This module patches the TLS configuration so the ClientHello matches
//! Chrome 120 as closely as possible within rustls constraints:
//!
//!   - Cipher suite order: TLS_AES_128_GCM_SHA256 first (Chrome default)
//!   - ALPN: ["h2", "http/1.1"]  (required for HTTP/2 obfuscation layer)
//!   - SNI: configurable (should be a real CDN hostname)
//!   - Certificate verification: disabled on client (self-signed server cert)
//!
//! ## Server side
//!
//! The server loads its TLS certificate from the sled DB (same cert used by
//! Hide-UI panel) and creates a TlsAcceptor with ALPN = ["h2", "http/1.1"].

use std::sync::Arc;

use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer},
    },
};

// ── Server side ───────────────────────────────────────────────────────────────

/// Creates a `TlsAcceptor` for the Hidekey server.
///
/// Uses the PEM-encoded certificate and private key stored in the sled DB.
/// ALPN is set to `["h2", "http/1.1"]` so the negotiated protocol matches
/// what the HTTP/2 obfuscation layer expects.
pub fn make_server_tls_acceptor(
    cert_pem: &[u8],
    key_pem:  &[u8],
) -> Result<TlsAcceptor, Box<dyn std::error::Error + Send + Sync>> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut std::io::BufReader::new(cert_pem))
            .collect::<Result<_, _>>()?;

    let key_raw = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_pem))?
        .ok_or("No private key in PEM")?;
    let key = PrivateKeyDer::try_from(key_raw)?;

    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    // Advertise h2 so the client's ALPN negotiation succeeds
    cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

// ── Client side ───────────────────────────────────────────────────────────────

/// Creates a `tokio_native_tls::TlsConnector` for the Hidekey client.
///
/// Uses Windows Schannel (on Windows) or OpenSSL (on Linux/OpenWRT/Android)
/// to perfectly emulate standard OS web requests.
///
/// - Certificate verification is disabled (to support self-signed server certs).
/// - Hostname verification is disabled (to allow SNI masking).
/// - ALPN negotiates "h2" and "http/1.1".
pub fn make_client_tls_connector() -> tokio_native_tls::TlsConnector {
    let native_connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .request_alpns(&["h2", "http/1.1"])
        .build()
        .expect("Failed to build native-tls connector");

    tokio_native_tls::TlsConnector::from(native_connector)
}

fn get_random_domain() -> &'static str {
    let domains = [
        "cdn.random-site.com",
        "static.cloudflare-ok.net",
        "assets.github-cdn.org",
        "img.pinterest-cdn.com",
        "media.tumblr-srv.net",
        "cdn.shopify-cms.com",
        "api.squarespace-sys.net",
        "static.wix-cdn.com",
    ];
    let mut idx = 0;
    if let Ok(duration) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        idx = (duration.as_millis() % domains.len() as u128) as usize;
    }
    domains[idx]
}

/// Parses a hostname string into a standard String.
///
/// To bypass DPI/firewalls that block TLS ClientHellos without an SNI extension,
/// this function forcefully masks IP addresses, empty SNIs, and Google-related domains
/// with a high-reputation, random non-Google CDN domain.
pub fn parse_server_name(sni: &str) -> String {
    let mut sni_str = sni.to_string();
    let is_ip = sni_str.parse::<std::net::IpAddr>().is_ok();
    let is_google = sni_str.contains("google") || sni_str.contains("googleapis");

    if sni_str.is_empty() || is_google || is_ip {
        let masked = get_random_domain();
        tracing::info!("⚠️ Anti-DPI: Masking SNI '{}' with random secure domain: '{}'", sni_str, masked);
        sni_str = masked.to_string();
    }

    sni_str
}
