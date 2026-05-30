pub mod db;
pub mod handlers;

use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use axum::{
    routing::{get, post, delete},
    Router,
    response::IntoResponse,
    http::{header, StatusCode},
};
use rust_embed::RustEmbed;
use tracing::{info, warn, error};

use crate::hideui::db::HideDb;
use crate::hideui::handlers::{
    AppState, TspuMetrics, login, list_peers, create_peer, delete_peer, get_metrics,
    update_security_mode, upload_morphing_plugin, get_settings, save_settings, toggle_peer,
};

// ── Embedded static files ─────────────────────────────────────────────────────

#[derive(RustEmbed)]
#[folder = "frontend/"]
struct Assets;

async fn index_handler() -> impl IntoResponse {
    match Assets::get("index.html") {
        Some(c) => (
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            c.data.into_owned(),
        ).into_response(),
        None => (StatusCode::NOT_FOUND, "Not Found").into_response(),
    }
}

async fn decoy_handler(
    original_uri: axum::extract::OriginalUri,
    axum::extract::State(state): axum::extract::State<Arc<AppState>>,
) -> impl IntoResponse {
    let path = original_uri.path();
    let secret_path = state.db.get_setting("panel_secret_path").unwrap_or(None).unwrap_or_default();
    
    if !secret_path.is_empty() && path == format!("/{}", secret_path) {
        let redirect_path = format!("{}/", path);
        return axum::response::Redirect::permanent(&redirect_path).into_response();
    }

    (
        StatusCode::NOT_FOUND,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        "<html><head><title>404 Not Found</title></head>\
         <body><center><h1>404 Not Found</h1></center><hr>\
         <center>nginx/1.24.0</center></body></html>",
    ).into_response()
}

// ── TLS certificate generation ────────────────────────────────────────────────

fn generate_self_signed_cert(server_ip: &str)
    -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error + Send + Sync>>
{
    use rcgen::{CertificateParams, DistinguishedName, DnType, SanType, KeyPair};

    let mut params = CertificateParams::default();
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName,       "Super Box Hide-UI");
    params.distinguished_name.push(DnType::OrganizationName, "Hidekey");
    params.distinguished_name.push(DnType::CountryName,      "CH");
    params.subject_alt_names = vec![SanType::DnsName("localhost".try_into()?)];
    if let Ok(ip) = server_ip.parse::<std::net::IpAddr>() {
        params.subject_alt_names.push(SanType::IpAddress(ip));
    }
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after  = now + time::Duration::days(3650);

    let key_pair = KeyPair::generate()?;
    let cert     = params.self_signed(&key_pair)?;
    Ok((cert.pem().into_bytes(), key_pair.serialize_pem().into_bytes()))
}

fn make_tls_acceptor(cert_pem: &[u8], key_pem: &[u8])
    -> Result<tokio_rustls::TlsAcceptor, Box<dyn std::error::Error + Send + Sync>>
{
    use tokio_rustls::rustls::{ServerConfig, pki_types::{CertificateDer, PrivateKeyDer}};

    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(
        &mut std::io::BufReader::new(cert_pem),
    ).collect::<Result<_, _>>()?;

    let key_raw = rustls_pemfile::private_key(
        &mut std::io::BufReader::new(key_pem),
    )?.ok_or("No private key in PEM")?;

    let key = PrivateKeyDer::try_from(key_raw)?;

    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(cfg)))
}

// ── Build router ──────────────────────────────────────────────────────────────

fn build_router(state: Arc<AppState>, secret_path: &str) -> Router {
    let mut r = Router::new();

    if !secret_path.is_empty() {
        let prefix = format!("/{}", secret_path);
        r = r
            .route(&prefix,                                 get(index_handler))
            .route(&format!("{}/", prefix),                 get(index_handler))
            .route(&format!("{}/index.html", prefix),       get(index_handler))
            .route(&format!("{}/api/auth", prefix),         post(login))
            .route(&format!("{}/api/peers", prefix),        get(list_peers).post(create_peer))
            .route(&format!("{}/api/peers/:id", prefix),    delete(delete_peer))
            .route(&format!("{}/api/peers/:id/toggle", prefix), post(toggle_peer))
            .route(&format!("{}/api/metrics", prefix),      get(get_metrics))
            .route(&format!("{}/api/metrics/mode", prefix), post(update_security_mode))
            .route(&format!("{}/api/plugins", prefix),      post(upload_morphing_plugin))
            .route(&format!("{}/api/settings", prefix),     get(get_settings).post(save_settings))
            .fallback(decoy_handler);
    } else {
        r = r
            .route("/",                         get(index_handler))
            .route("/index.html",               get(index_handler))
            .route("/api/auth",                 post(login))
            .route("/api/peers",                get(list_peers).post(create_peer))
            .route("/api/peers/:id",            delete(delete_peer))
            .route("/api/peers/:id/toggle",     post(toggle_peer))
            .route("/api/metrics",              get(get_metrics))
            .route("/api/metrics/mode",         post(update_security_mode))
            .route("/api/plugins",              post(upload_morphing_plugin))
            .route("/api/settings",             get(get_settings).post(save_settings))
            .fallback(decoy_handler);
    }

    r.with_state(state)
}

// ── HideUiServer ──────────────────────────────────────────────────────────────

pub struct HideUiServer {
    state:          Arc<AppState>,
    listen_address: String,
    listen_port:    u16,
    secret_path:    String,
    tls_cert_pem:   Vec<u8>,
    tls_key_pem:    Vec<u8>,
}

impl HideUiServer {
    pub fn new(
        db_path:        &str,
        server_address: String,
        _server_port:   u16,
        listen_address: String,
        listen_port:    u16,
        stats:          Arc<crate::stats::ProxyStats>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        info!("Opening embedded database at: {}", db_path);
        let db = Arc::new(HideDb::open(db_path)?);

        if db.get_setting("admin_user")?.is_none() {
            db.save_setting("admin_user", "admin")?;
            db.save_setting("admin_pass", "hidekey2026")?;
        }

        let secret_path = db.get_setting("panel_secret_path")?.unwrap_or_default();
        if !secret_path.is_empty() {
            info!("Secret panel path (лапша) active: /{}/", secret_path);
        }

        let (tls_cert_pem, tls_key_pem) = {
            let c = db.get_setting("tls_cert_pem")?.unwrap_or_default();
            let k = db.get_setting("tls_key_pem")?.unwrap_or_default();
            if !c.is_empty() && !k.is_empty() {
                info!("Loaded existing TLS certificate from DB");
                (c.into_bytes(), k.into_bytes())
            } else {
                info!("Generating new self-signed TLS certificate...");
                match generate_self_signed_cert(&server_address) {
                    Ok((cert, key)) => {
                        db.save_setting("tls_cert_pem", &String::from_utf8_lossy(&cert))?;
                        db.save_setting("tls_key_pem",  &String::from_utf8_lossy(&key))?;
                        info!("TLS certificate generated (valid 10 years)");
                        (cert, key)
                    }
                    Err(e) => {
                        warn!("Could not generate TLS cert: {}. HTTP fallback.", e);
                        (vec![], vec![])
                    }
                }
            }
        };

        let saved_peers = db.list_peers()?;
        let mut peer_map = HashMap::new();
        for p in saved_peers { peer_map.insert(p.id.clone(), p); }
        info!("Loaded {} peers from DB", peer_map.len());

        let peers   = Arc::new(RwLock::new(peer_map));
        let _ = db.sync_panel_conf();
        let metrics = Arc::new(RwLock::new(TspuMetrics {
            rtt_ms: 12, jitter_ms: 2, packet_loss_percent: 0,
            mode: "Normal".to_string(),
        }));

        let resolved_port = match db.get_setting("panel_port")? {
            Some(p) => p.parse::<u16>().unwrap_or(listen_port),
            None    => { db.save_setting("panel_port", &listen_port.to_string())?; listen_port },
        };

        let resolved_server_port = match db.get_setting("server_listen_port")? {
            Some(p) => p.parse::<u16>().unwrap_or(51443),
            None    => { db.save_setting("server_listen_port", "51443")?; 51443 },
        };

        let state = Arc::new(AppState {
            db, peers, metrics, server_address, server_port: resolved_server_port, stats,
            last_cpu_time:      std::sync::Mutex::new(None),
            last_traffic_speed: std::sync::Mutex::new((0, 0, std::time::Instant::now())),
        });

        Ok(Self {
            state, listen_address, listen_port: resolved_port,
            secret_path, tls_cert_pem, tls_key_pem,
        })
    }

    pub fn get_state(&self) -> Arc<AppState> { Arc::clone(&self.state) }

    /// Returns the VPN server listen port stored in DB (falls back to 51443).
    pub fn get_server_listen_port(&self) -> u16 {
        self.state.db
            .get_setting("server_listen_port")
            .unwrap_or(None)
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(51443)
    }

    /// Returns the TLS certificate PEM bytes (for sharing with Hidekey server).
    pub fn get_cert_pem(&self) -> Vec<u8> { self.tls_cert_pem.clone() }

    /// Returns the TLS private key PEM bytes (for sharing with Hidekey server).
    pub fn get_key_pem(&self) -> Vec<u8> { self.tls_key_pem.clone() }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr        = format!("{}:{}", self.listen_address, self.listen_port);
        let secret_path = self.secret_path.clone();
        let use_tls     = !self.tls_cert_pem.is_empty() && !self.tls_key_pem.is_empty();

        // Try HTTPS first, fall back to HTTP on any error
        if use_tls {
            match make_tls_acceptor(&self.tls_cert_pem, &self.tls_key_pem) {
                Ok(acceptor) => {
                    let panel_url = if secret_path.is_empty() {
                        format!("https://{}", addr)
                    } else {
                        format!("https://{}/{}/", addr, secret_path)
                    };
                    info!("Hide-UI Panel (HTTPS): {}", panel_url);
                    info!("TLS: self-signed cert — accept browser security warning once");

                    let listener = tokio::net::TcpListener::bind(&addr).await?;
                    let sp    = secret_path.clone();
                    let state = Arc::clone(&self.state);

                    tokio::spawn(async move {
                        loop {
                            let (tcp_stream, peer_addr) = match listener.accept().await {
                                Ok(v)  => v,
                                Err(e) => { error!("TCP accept error: {}", e); continue; }
                            };
                            let acceptor = acceptor.clone();
                            let svc = build_router(Arc::clone(&state), &sp).into_make_service();

                            tokio::spawn(async move {
                                let tls_stream = match acceptor.accept(tcp_stream).await {
                                    Ok(s)  => s,
                                    Err(e) => {
                                        warn!("TLS handshake failed from {:?}: {}", peer_addr, e);
                                        return;
                                    }
                                };

                                let io = hyper_util::rt::TokioIo::new(tls_stream);
                                let mut conn_builder = hyper_util::server::conn::auto::Builder::new(
                                    hyper_util::rt::TokioExecutor::new()
                                );

                                // We use hyper-util to serve an axum make_service
                                use tower::Service as _;
                                let mut svc = svc;
                                let handler = match svc.call(()).await {
                                    Ok(h)  => h,
                                    Err(e) => { error!("Service init error: {}", e); return; }
                                };
                                let hyper_service = hyper_util::service::TowerToHyperService::new(handler);
                                let _ = conn_builder.serve_connection_with_upgrades(io, hyper_service).await;
                            });
                        }
                    });

                    return Ok(());
                }
                Err(e) => {
                    warn!("TLS acceptor build failed ({}). Serving on plain HTTP.", e);
                }
            }
        }

        // Plain HTTP
        let app = build_router(Arc::clone(&self.state), &secret_path);
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        let panel_url = if secret_path.is_empty() {
            format!("http://{}", addr)
        } else {
            format!("http://{}/{}/", addr, secret_path)
        };
        info!("Hide-UI Panel (HTTP): {}", panel_url);
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, app).await {
                error!("HTTP server crashed: {}", e);
            }
        });

        Ok(())
    }
}
