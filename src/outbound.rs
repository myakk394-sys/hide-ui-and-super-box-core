//! # super_box::outbound
//!
//! Hidekey server listener and relay handler.
//!
//! For every incoming connection:
//!   1. Reads the 76-byte ClientChallenge.
//!   2. Tries all active peers' master_keys to verify the BLAKE3 MAC.
//!      Invalid/unknown clients are silently dropped.
//!   3. Sends the 76-byte ServerResponse.
//!   4. Reads the first encrypted frame: proxy destination (CMD+PORT+ATYP+ADDR).
//!   5. Connects to the target (port-53 TCP → 127.0.0.53:53 redirect).
//!   6. Relays traffic bidirectionally:
//!      - Client→Target: decrypt with rx_key, forward plaintext
//!      - Target→Client: encrypt with tx_key, send framed

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{warn, error, debug, info};


use crate::config::Config;
use crate::stats::ProxyStats;
use rand::{rngs::OsRng, RngCore};
use crate::hidekey::handshake::{ClientChallenge, ServerHandshake, CHALLENGE_SIZE};
use crate::hidekey::framing::length_prefix;

use crate::hidekey::crypto::{encrypt_chacha20poly1305, decrypt_chacha20poly1305};
use crate::hidekey::stego::{RtpSessionState, unpack_rtp};
use crate::hidekey::tls_tunnel::make_server_tls_acceptor;
use crate::hidekey::h2_obfs;
use crate::hidekey::mux;


// ── Public entry point ────────────────────────────────────────────────────────

/// Start the Hidekey server listener.
pub async fn start_outbound_server(
    config: Arc<std::sync::RwLock<Config>>,
    peers: Arc<tokio::sync::RwLock<std::collections::HashMap<String, crate::hideui::db::Peer>>>,
    stats: Arc<ProxyStats>,
    tls_cert_pem: Vec<u8>,
    tls_key_pem:  Vec<u8>,
) -> tokio::io::Result<()> {
    let bind_addr = {
        let cfg = config.read().unwrap();
        format!("0.0.0.0:{}", cfg.server_listen_port)
    };

    // Build TLS acceptor — if cert/key are empty, fall back to raw TCP (dev mode)
    let tls_acceptor: Option<tokio_rustls::TlsAcceptor> = if !tls_cert_pem.is_empty() && !tls_key_pem.is_empty() {
        match make_server_tls_acceptor(&tls_cert_pem, &tls_key_pem) {
            Ok(a) => {
                info!("🔒 Hidekey server: TLS+HTTP/2 stealth mode active on {}", bind_addr);
                Some(a)
            }
            Err(e) => {
                error!("❌ Hidekey server: TLS acceptor build failed: {} — falling back to raw TCP", e);
                None
            }
        }
    } else {
        warn!("⚠️ Hidekey server: no TLS cert/key — running in raw TCP mode (not stealthy)");
        None
    };

    let tls_acceptor = Arc::new(tls_acceptor);

    let listener = TcpListener::bind(&bind_addr).await.map_err(|e| {
        stats.log_event(
            &format!("Сервер: Ошибка привязки к {}", bind_addr),
            &format!("Server: Failed to bind Hidekey listener to {}", bind_addr),
        );
        e
    })?;

    // Secondary listener on port 2053 — fallback for clients whose ISP blocks
    // outbound TCP 443. Port 2053 (DNS-over-HTTPS alt) is rarely filtered.
    let alt_port = 2053u16;
    let alt_bind = format!("0.0.0.0:{}", alt_port);
    let alt_listener = match TcpListener::bind(&alt_bind).await {
        Ok(l) => {
            info!("🔒 Hidekey server: secondary listener on {} (ISP-443-block fallback)", alt_bind);
            Some(l)
        }
        Err(e) => {
            warn!("⚠️ Hidekey server: could not bind secondary port {}: {}", alt_port, e);
            None
        }
    };

    stats.log_event(
        &format!("Сервер Hidekey запущен на {}", bind_addr),
        &format!("Hidekey Server active on {}", bind_addr),
    );

    // Spawn secondary listener as a background task
    if let Some(alt) = alt_listener {
        let peers2   = Arc::clone(&peers);
        let stats2   = Arc::clone(&stats);
        let acceptor2 = Arc::clone(&tls_acceptor);
        tokio::spawn(async move {
            loop {
                match alt.accept().await {
                    Ok((stream, peer_addr)) => {
                        let p = Arc::clone(&peers2);
                        let s = Arc::clone(&stats2);
                        let a = Arc::clone(&acceptor2);
                        tokio::spawn(async move {
                            dispatch_connection(stream, peer_addr, p, s, a).await;
                        });
                    }
                    Err(e) => { error!("Alt listener accept error: {}", e); break; }
                }
            }
        });
    }

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let peers_cloned  = Arc::clone(&peers);
                let st            = Arc::clone(&stats);
                let acceptor      = Arc::clone(&tls_acceptor);
                tokio::spawn(async move {
                    dispatch_connection(stream, peer_addr, peers_cloned, st, acceptor).await;
                });
            }
            Err(e) => {
                stats.log_event(
                    &format!("Сервер: Ошибка приёма: {}", e),
                    &format!("Server: Accept connection error: {}", e),
                );
            }
        }
    }
}

// ── TLS dispatch + HTTP/2 handshake ──────────────────────────────────────────

/// Accepts a raw TCP connection, optionally upgrades to TLS + HTTP/2,
/// then hands off to the Hidekey protocol handler.
async fn dispatch_connection(
    tcp_stream: TcpStream,
    peer_addr:  SocketAddr,
    peers:      Arc<tokio::sync::RwLock<std::collections::HashMap<String, crate::hideui::db::Peer>>>,
    stats:      Arc<ProxyStats>,
    tls_acceptor: Arc<Option<tokio_rustls::TlsAcceptor>>,
) {
    let _ = tcp_stream.set_nodelay(true);
    if let Some(acceptor) = tls_acceptor.as_ref() {
        // ── TLS + HTTP/2 stealth path ─────────────────────────────────────────
        let tls_stream = match acceptor.accept(tcp_stream).await {
            Ok(s)  => s,
            Err(e) => {
                debug!("Server: TLS handshake failed from {}: {}", peer_addr.ip(), e);
                return;
            }
        };

        // Wrap in a Box<dyn AsyncRead+AsyncWrite> so we can pass it generically
        let mut boxed: Box<dyn crate::hidekey::h2_obfs::AsyncStream> =
            Box::new(tls_stream);

        if let Err(e) = h2_obfs::server_handshake(&mut boxed).await {
            debug!("Server: HTTP/2 handshake failed from {}: {}", peer_addr.ip(), e);
            return;
        }

        debug!("✅ Server: TLS+HTTP/2 handshake OK from {}", peer_addr.ip());
        handle_hidekey_h2_or_mux(boxed, peer_addr, peers, stats).await;
    } else {
        // ── Raw TCP fallback (dev/test mode) ──────────────────────────────────
        handle_hidekey_connection(tcp_stream, peer_addr, peers, stats).await;
    }
}

// ── Single-direction cipher state ─────────────────────────────────────────────
//
// To allow independent ownership in two async tasks, we split send/recv into
// separate structs rather than a single HideSession.

struct HideCipher {
    key: [u8; 32],
    direction: u8,
    counter: u32,
    rtp_state: RtpSessionState,
}

impl HideCipher {
    fn new(key: [u8; 32], direction: u8) -> Self {
        Self { key, direction, counter: 0, rtp_state: RtpSessionState::new() }
    }

    fn make_nonce(&self, seq: u16) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[0] = self.direction;
        nonce[1..5].copy_from_slice(&self.counter.to_be_bytes());
        nonce[5..7].copy_from_slice(&seq.to_be_bytes());
        nonce[7..12].copy_from_slice(&self.key[0..5]);
        nonce
    }

    /// Encrypt plaintext, wrap in RTP, prefix with 2-byte length. Returns wire bytes.
    fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
        let seq = self.rtp_state.seq_number;
        let nonce = self.make_nonce(seq);
        let ciphertext = encrypt_chacha20poly1305(&self.key, &nonce, plaintext, b"")
            .map_err(|e| format!("{:?}", e))?;
        let packet = self.rtp_state.pack(&ciphertext);
        self.counter = self.counter.wrapping_add(1);
        Ok(length_prefix(&packet))
    }

    /// Decrypt one RTP packet (already length-stripped). Returns plaintext.
    fn open(&mut self, packet: &[u8]) -> Option<Vec<u8>> {
        let ciphertext = unpack_rtp(packet)?;
        let seq = u16::from_be_bytes([packet[2], packet[3]]);
        let nonce = self.make_nonce(seq);
        let pt = decrypt_chacha20poly1305(&self.key, &nonce, &ciphertext, b"").ok()?;
        self.counter = self.counter.wrapping_add(1);
        Some(pt)
    }
}

// ── Connection handler ────────────────────────────────────────────────────────

async fn handle_hidekey_connection(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    peers: Arc<tokio::sync::RwLock<std::collections::HashMap<String, crate::hideui::db::Peer>>>,
    stats: Arc<ProxyStats>,
) {
    stats.inc_active_connections();

    // ── 1. Read Client's random junk and ClientChallenge ──────────────────────
    let mut junk_len_buf = [0u8; 2];
    if let Err(e) = stream.read_exact(&mut junk_len_buf).await {
        debug!("Server: Failed to read junk length from {}: {}", peer_addr.ip(), e);
        stats.dec_active_connections();
        return;
    }
    let junk_len = u16::from_be_bytes(junk_len_buf) as usize;
    if junk_len < 16 || junk_len > 128 {
        debug!("Server: Invalid junk length from {} ({} bytes) — silent drop", peer_addr.ip(), junk_len);
        stats.dec_active_connections();
        return;
    }

    let mut junk_buf = vec![0u8; junk_len];
    if let Err(e) = stream.read_exact(&mut junk_buf).await {
        debug!("Server: Failed to read junk data from {}: {}", peer_addr.ip(), e);
        stats.dec_active_connections();
        return;
    }

    let mut challenge_len_buf = [0u8; 2];
    if let Err(e) = stream.read_exact(&mut challenge_len_buf).await {
        debug!("Server: Failed to read challenge length from {}: {}", peer_addr.ip(), e);
        stats.dec_active_connections();
        return;
    }
    let challenge_len = u16::from_be_bytes(challenge_len_buf) as usize;
    if challenge_len != 88 {
        debug!("Server: Invalid challenge length from {} ({} bytes)", peer_addr.ip(), challenge_len);
        stats.dec_active_connections();
        return;
    }

    let mut challenge_rtp_buf = vec![0u8; challenge_len];
    if let Err(e) = stream.read_exact(&mut challenge_rtp_buf).await {
        debug!("Server: Failed to read challenge RTP packet from {}: {}", peer_addr.ip(), e);
        stats.dec_active_connections();
        return;
    }

    let challenge_payload = match crate::hidekey::stego::unpack_rtp(&challenge_rtp_buf) {
        Some(p) => p,
        None => {
            debug!("Server: Invalid RTP challenge packet from {}", peer_addr.ip());
            stats.dec_active_connections();
            return;
        }
    };

    if challenge_payload.len() != CHALLENGE_SIZE {
        debug!("Server: Invalid unpacked challenge size from {} ({} bytes)", peer_addr.ip(), challenge_payload.len());
        stats.dec_active_connections();
        return;
    }

    let mut challenge_buf = [0u8; CHALLENGE_SIZE];
    challenge_buf.copy_from_slice(&challenge_payload);
    let challenge = ClientChallenge::from_bytes(&challenge_buf);

    // ── 2. Find matching peer ─────────────────────────────────────────────────
    let handshake_result = {
        let peers_guard = peers.read().await;
        let mut result = None;
        for (_id, peer) in peers_guard.iter() {
            if !peer.active || peer.master_key.len() != 64 { continue; }
            let key_bytes: Option<Vec<u8>> = (0..32)
                .map(|i| u8::from_str_radix(&peer.master_key[i * 2..i * 2 + 2], 16).ok())
                .collect();
            let key_bytes = match key_bytes {
                Some(b) => b,
                None => continue,
            };
            let mut master_key = [0u8; 32];
            master_key.copy_from_slice(&key_bytes);

            let hs = ServerHandshake::new(master_key);
            if let Some((response, session_keys)) = hs.process_challenge(&challenge) {
                result = Some((response.to_bytes(), session_keys.rx_key, session_keys.tx_key));
                break;
            }
        }
        result
    };

    let (response_bytes, rx_key, tx_key) = match handshake_result {
        Some(r) => r,
        None => {
            debug!("Server: No peer matched ClientChallenge from {} — silent drop", peer_addr.ip());
            stats.dec_active_connections();
            return;
        }
    };

    // ── 3. Send ServerResponse with random junk ───────────────────────────────
    let mut len_byte = [0u8; 1];
    OsRng.fill_bytes(&mut len_byte);
    let srv_junk_len = 16 + (len_byte[0] % 113) as usize; // 16 to 128
    let mut srv_junk_bytes = vec![0u8; srv_junk_len];
    OsRng.fill_bytes(&mut srv_junk_bytes);

    // Steganography: insert a valid RTP v2 header at the start of srv_junk_bytes
    // so the server response is disguised as WebRTC/Opus audio over TCP
    let mut rtp_header = [0u8; 12];
    let mut rtp_state = crate::hidekey::stego::RtpSessionState::new();
    let header = crate::hidekey::stego::RtpHeader::new(rtp_state.seq_number, rtp_state.timestamp, rtp_state.ssrc);
    header.serialize(&mut rtp_header);
    srv_junk_bytes[0..12].copy_from_slice(&rtp_header);

    // Packet 1: Server Junk (RTP framed)
    let mut packet1 = Vec::with_capacity(2 + srv_junk_len);
    packet1.extend_from_slice(&(srv_junk_len as u16).to_be_bytes());
    packet1.extend_from_slice(&srv_junk_bytes);

    // Packet 2: Server Response (RTP framed)
    let mut response_rtp_state = crate::hidekey::stego::RtpSessionState::new();
    let response_rtp_packet = response_rtp_state.pack(&response_bytes);
    let mut packet2 = Vec::with_capacity(2 + response_rtp_packet.len());
    packet2.extend_from_slice(&(response_rtp_packet.len() as u16).to_be_bytes());
    packet2.extend_from_slice(&response_rtp_packet);

    if let Err(e) = stream.write_all(&packet1).await {
        error!("Server: Failed to send ServerJunk to {}: {}", peer_addr.ip(), e);
        stats.dec_active_connections();
        return;
    }
    if let Err(e) = stream.write_all(&packet2).await {
        error!("Server: Failed to send ServerResponse to {}: {}", peer_addr.ip(), e);
        stats.dec_active_connections();
        return;
    }

    // ── 4. Read proxy target (first encrypted frame) ──────────────────────────
    // Server decrypts using rx_key (what client encrypted with its tx_key).
    // Direction for server rx = 0x00 (client→server direction marker)
    let mut rx_cipher = HideCipher::new(rx_key, 0x00);
    let mut tx_cipher = HideCipher::new(tx_key, 0x01);

    let target_payload = {
        // Read one length-prefixed frame inline (avoids Rust 1.87 Linux type inference issue)
        let frame: Vec<u8> = {
            use tokio::io::AsyncReadExt;
            let mut len_buf = [0u8; 2];
            match stream.read_exact(&mut len_buf).await {
                Ok(_) => {},
                Err(e) => {
                    error!("Server: Failed to read proxy target frame from {}: {}", peer_addr.ip(), e);
                    stats.dec_active_connections();
                    return;
                }
            }
            let flen = u16::from_be_bytes(len_buf) as usize;
            let mut fbuf = vec![0u8; flen];
            match stream.read_exact(&mut fbuf).await {
                Ok(_) => fbuf,
                Err(e) => {
                    error!("Server: Failed to read proxy target body from {}: {}", peer_addr.ip(), e);
                    stats.dec_active_connections();
                    return;
                }
            }
        };
        match rx_cipher.open(&frame) {
            Some(p) => p,
            None => {
                error!("Server: Decryption failed for proxy target from {}: MAC mismatch", peer_addr.ip());
                stats.dec_active_connections();
                return;
            }
        }
    };

    // Parse: CMD(1) + PORT(2) + ATYP(1) + ADDR(N)
    if target_payload.len() < 4 {
        error!("Server: Proxy target frame too short from {}", peer_addr.ip());
        stats.dec_active_connections();
        return;
    }

    let cmd = target_payload[0];
    let port = u16::from_be_bytes([target_payload[1], target_payload[2]]);
    let atyp = target_payload[3];

    if cmd != 0x01 {
        error!("Server: Unsupported CMD 0x{:02x} from {}", cmd, peer_addr.ip());
        stats.dec_active_connections();
        return;
    }

    let target_host = match atyp {
        0x01 => {
            if target_payload.len() < 8 {
                stats.dec_active_connections(); return;
            }
            format!("{}.{}.{}.{}", target_payload[4], target_payload[5], target_payload[6], target_payload[7])
        }
        0x03 => {
            if target_payload.len() < 5 {
                stats.dec_active_connections(); return;
            }
            let domain_len = target_payload[4] as usize;
            if target_payload.len() < 5 + domain_len {
                stats.dec_active_connections(); return;
            }
            match String::from_utf8(target_payload[5..5 + domain_len].to_vec()) {
                Ok(d) => d,
                Err(_) => { stats.dec_active_connections(); return; }
            }
        }
        0x04 => {
            if target_payload.len() < 20 {
                stats.dec_active_connections(); return;
            }
            let ip = std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&target_payload[4..20]).unwrap()
            );
            ip.to_string()
        }
        _ => {
            error!("Server: Unknown ATYP 0x{:02x} from {}", atyp, peer_addr.ip());
            stats.dec_active_connections();
            return;
        }
    };

    // ── 5. Connect to target ──────────────────────────────────────────────────
    // Connect directly to the requested target (even for DNS on port 53)
    let connect_addr = format!("{}:{}", target_host, port);


    let target_stream = match TcpStream::connect(&connect_addr).await {
        Ok(s) => {
            let _ = s.set_nodelay(true);
            s
        }
        Err(e) => {
            stats.log_event(
                &format!("Сервер: Ошибка подключения к {}: {}", connect_addr, e),
                &format!("Server: Failed to connect to target {}: {}", connect_addr, e),
            );
            stats.dec_active_connections();
            return;
        }
    };

    stats.log_event(
        &format!("Сервер: Клиент {} → {}:{}", peer_addr.ip(), target_host, port),
        &format!("Server: Client {} → {}:{}", peer_addr.ip(), target_host, port),
    );

    // ── 6. Bidirectional relay with Hidekey framing ───────────────────────────
    let (mut client_reader, mut client_writer) = stream.into_split();
    let (mut target_reader, mut target_writer) = target_stream.into_split();

    let stats_up = Arc::clone(&stats);
    let stats_down = Arc::clone(&stats);

    // Client → Target: read encrypted frames from client, decrypt, forward plaintext
    let upload = tokio::spawn(async move {
        let mut total = 0usize;
        loop {
            // Inline length-prefixed frame read with explicit Vec<u8>
            let frame: Vec<u8> = {
                use tokio::io::AsyncReadExt;
                let mut len_buf = [0u8; 2];
                if client_reader.read_exact(&mut len_buf).await.is_err() { break; }
                let flen = u16::from_be_bytes(len_buf) as usize;
                if flen == 0 { break; }
                let mut fbuf = vec![0u8; flen];
                if client_reader.read_exact(&mut fbuf).await.is_err() { break; }
                fbuf
            };
            let plaintext = match rx_cipher.open(&frame) {
                Some(p) => p,
                None => {
                    warn!("Server: Decryption failed in upload relay — closing");
                    break;
                }
            };
            if target_writer.write_all(&plaintext).await.is_err() { break; }
            stats_up.add_uploaded(plaintext.len() as u64);
            total += plaintext.len();
        }
        total
    });

    // Target → Client: read plaintext from target, encrypt, send framed to client
    let download = tokio::spawn(async move {
        let mut total = 0usize;
        let mut buf = vec![0u8; 16384];
        loop {
            let n = match target_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let wire = match tx_cipher.seal(&buf[..n]) {
                Ok(w) => w,
                Err(e) => {
                    warn!("Server: Encryption failed in download relay: {}", e);
                    break;
                }
            };
            if client_writer.write_all(&wire).await.is_err() { break; }
            stats_down.add_downloaded(n as u64);
            total += n;
        }
        total
    });

    let (up_res, down_res) = tokio::join!(upload, download);
    let up_bytes = up_res.unwrap_or(0);
    let down_bytes = down_res.unwrap_or(0);

    stats.dec_active_connections();
    stats.log_event(
        &format!("Сервер: Туннель {}:{} закрыт (↑{:.1} КБ / ↓{:.1} КБ)", target_host, port, up_bytes as f64 / 1024.0, down_bytes as f64 / 1024.0),
        &format!("Server: Tunnel {}:{} closed (↑{:.1} KB / ↓{:.1} KB)", target_host, port, up_bytes as f64 / 1024.0, down_bytes as f64 / 1024.0),
    );
}

// ── TLS+HTTP/2 MUX-обработчик ─────────────────────────────────────────────────
//
// После Hidekey handshake переходит в MUX-режим: одно соединение
// обслуживает множество параллельных TCP-сессий.

/// Обработчик TLS+H2 соединения с MUX-мультиплексированием.
///
/// После Hidekey handshake переходит в MUX-режим: одно соединение
/// обслуживает множество параллельных TCP-сессий.
async fn handle_hidekey_h2_or_mux(
    stream: Box<dyn crate::hidekey::h2_obfs::AsyncStream>,
    peer_addr: SocketAddr,
    peers:     Arc<tokio::sync::RwLock<std::collections::HashMap<String, crate::hideui::db::Peer>>>,
    stats:     Arc<ProxyStats>,
) {
    // After h2_obfs handshake, immediately enter H2 MUX mode.
    // Authentication is now handled inside run_mux_server via /api/v1/auth H2 stream.
    // The client sends auth as the very first H2 request before any proxy streams.
    info!("✅ Server MUX: h2_obfs OK from {} → entering H2 MUX mode", peer_addr.ip());
    mux::run_mux_server(stream, peers, stats).await;
}

// ── TLS+HTTP/2 Hidekey handler ────────────────────────────────────────────────
//
// Same logic as handle_hidekey_connection but reads/writes through HTTP/2 DATA
// frames instead of raw length-prefixed frames.

async fn handle_hidekey_h2(
    mut stream: Box<dyn crate::hidekey::h2_obfs::AsyncStream>,
    peer_addr:  SocketAddr,
    peers:      Arc<tokio::sync::RwLock<std::collections::HashMap<String, crate::hideui::db::Peer>>>,
    stats:      Arc<ProxyStats>,
) {
    stats.inc_active_connections();

    // ── Helper: read one Hidekey frame from HTTP/2 DATA ───────────────────────
    // The Hidekey framing (2-byte length prefix + RTP packet) is preserved
    // inside the HTTP/2 DATA payload.  We read DATA frames until we have
    // accumulated enough bytes for one complete Hidekey frame.

    macro_rules! read_h2_frame {
        ($stream:expr, $peer:expr, $stats:expr) => {{
            match h2_obfs::recv_data($stream).await {
                Ok(Some(data)) => data,
                Ok(None) => {
                    debug!("Server H2: clean EOF from {}", $peer.ip());
                    $stats.dec_active_connections();
                    return;
                }
                Err(e) => {
                    debug!("Server H2: read error from {}: {}", $peer.ip(), e);
                    $stats.dec_active_connections();
                    return;
                }
            }
        }};
    }

    // ── 1. Read junk frame ────────────────────────────────────────────────────
    let junk_data = read_h2_frame!(&mut stream, peer_addr, stats);
    let junk_len = if junk_data.len() >= 2 {
        u16::from_be_bytes([junk_data[0], junk_data[1]]) as usize
    } else { 0 };
    if junk_len < 16 || junk_len > 256 {
        debug!("Server H2: invalid junk length {} from {}", junk_len, peer_addr.ip());
        stats.dec_active_connections();
        return;
    }

    // ── 2. Read challenge frame ───────────────────────────────────────────────
    let challenge_data = read_h2_frame!(&mut stream, peer_addr, stats);
    if challenge_data.len() < 2 {
        stats.dec_active_connections(); return;
    }
    let challenge_len = u16::from_be_bytes([challenge_data[0], challenge_data[1]]) as usize;
    if challenge_len != 88 || challenge_data.len() < 2 + challenge_len {
        debug!("Server H2: invalid challenge length {} from {}", challenge_len, peer_addr.ip());
        stats.dec_active_connections();
        return;
    }
    let challenge_rtp = &challenge_data[2..2 + challenge_len];

    let challenge_payload = match crate::hidekey::stego::unpack_rtp(challenge_rtp) {
        Some(p) => p,
        None => {
            debug!("Server H2: invalid RTP challenge from {}", peer_addr.ip());
            stats.dec_active_connections();
            return;
        }
    };
    if challenge_payload.len() != CHALLENGE_SIZE {
        stats.dec_active_connections(); return;
    }
    let mut challenge_buf = [0u8; CHALLENGE_SIZE];
    challenge_buf.copy_from_slice(&challenge_payload);
    let challenge = ClientChallenge::from_bytes(&challenge_buf);

    // ── 3. Find matching peer ─────────────────────────────────────────────────
    let handshake_result = {
        let peers_guard = peers.read().await;
        let mut result = None;
        for (_id, peer) in peers_guard.iter() {
            if !peer.active || peer.master_key.len() != 64 { continue; }
            let key_bytes: Option<Vec<u8>> = (0..32)
                .map(|i| u8::from_str_radix(&peer.master_key[i * 2..i * 2 + 2], 16).ok())
                .collect();
            let key_bytes = match key_bytes { Some(b) => b, None => continue };
            let mut master_key = [0u8; 32];
            master_key.copy_from_slice(&key_bytes);
            let hs = ServerHandshake::new(master_key);
            if let Some((response, session_keys)) = hs.process_challenge(&challenge) {
                result = Some((response.to_bytes(), session_keys.rx_key, session_keys.tx_key));
                break;
            }
        }
        result
    };

    let (response_bytes, rx_key, tx_key) = match handshake_result {
        Some(r) => r,
        None => {
            debug!("Server H2: no peer matched from {} — silent drop", peer_addr.ip());
            stats.dec_active_connections();
            return;
        }
    };

    // ── 4. Send ServerResponse via HTTP/2 DATA ────────────────────────────────
    let mut len_byte = [0u8; 1];
    OsRng.fill_bytes(&mut len_byte);
    let srv_junk_len = 16 + (len_byte[0] % 113) as usize;
    let mut srv_junk_bytes = vec![0u8; srv_junk_len];
    OsRng.fill_bytes(&mut srv_junk_bytes);
    let mut rtp_state = crate::hidekey::stego::RtpSessionState::new();
    let rtp_hdr = crate::hidekey::stego::RtpHeader::new(rtp_state.seq_number, rtp_state.timestamp, rtp_state.ssrc);
    let mut rtp_hdr_buf = [0u8; 12];
    rtp_hdr.serialize(&mut rtp_hdr_buf);
    srv_junk_bytes[0..12].copy_from_slice(&rtp_hdr_buf);

    let mut junk_frame = Vec::with_capacity(2 + srv_junk_len);
    junk_frame.extend_from_slice(&(srv_junk_len as u16).to_be_bytes());
    junk_frame.extend_from_slice(&srv_junk_bytes);

    let mut response_rtp_state = crate::hidekey::stego::RtpSessionState::new();
    let response_rtp_packet = response_rtp_state.pack(&response_bytes);
    let mut resp_frame = Vec::with_capacity(2 + response_rtp_packet.len());
    resp_frame.extend_from_slice(&(response_rtp_packet.len() as u16).to_be_bytes());
    resp_frame.extend_from_slice(&response_rtp_packet);

    // Apply AmneziaWG padding before sending
    let junk_padded = crate::hidekey::stego::amnezia_pad(&junk_frame);
    let resp_padded = crate::hidekey::stego::amnezia_pad(&resp_frame);

    if h2_obfs::send_data(&mut stream, &junk_padded).await.is_err() {
        stats.dec_active_connections(); return;
    }
    if stream.flush().await.is_err() { stats.dec_active_connections(); return; }
    tokio::time::sleep(crate::hidekey::stego::amnezia_jitter_delay()).await;
    if h2_obfs::send_data(&mut stream, &resp_padded).await.is_err() {
        stats.dec_active_connections(); return;
    }
    if stream.flush().await.is_err() { stats.dec_active_connections(); return; }

    // ── 5. Read proxy target (first encrypted frame via HTTP/2) ──────────────
    let mut rx_cipher = HideCipher::new(rx_key, 0x00);
    let mut tx_cipher = HideCipher::new(tx_key, 0x01);

    let target_frame_data = read_h2_frame!(&mut stream, peer_addr, stats);
    if target_frame_data.len() < 2 {
        stats.dec_active_connections(); return;
    }
    let target_flen = u16::from_be_bytes([target_frame_data[0], target_frame_data[1]]) as usize;
    if target_frame_data.len() < 2 + target_flen {
        stats.dec_active_connections(); return;
    }
    let target_rtp = &target_frame_data[2..2 + target_flen];
    let target_payload = match rx_cipher.open(target_rtp) {
        Some(p) => p,
        None => {
            error!("Server H2: decryption failed for proxy target from {}", peer_addr.ip());
            stats.dec_active_connections();
            return;
        }
    };

    if target_payload.len() < 4 { stats.dec_active_connections(); return; }
    let cmd  = target_payload[0];
    let port = u16::from_be_bytes([target_payload[1], target_payload[2]]);
    let atyp = target_payload[3];
    if cmd != 0x01 { stats.dec_active_connections(); return; }

    let target_host = match atyp {
        0x01 => {
            if target_payload.len() < 8 { stats.dec_active_connections(); return; }
            format!("{}.{}.{}.{}", target_payload[4], target_payload[5], target_payload[6], target_payload[7])
        }
        0x03 => {
            if target_payload.len() < 5 { stats.dec_active_connections(); return; }
            let dlen = target_payload[4] as usize;
            if target_payload.len() < 5 + dlen { stats.dec_active_connections(); return; }
            match String::from_utf8(target_payload[5..5 + dlen].to_vec()) {
                Ok(d) => d,
                Err(_) => { stats.dec_active_connections(); return; }
            }
        }
        0x04 => {
            if target_payload.len() < 20 { stats.dec_active_connections(); return; }
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&target_payload[4..20]).unwrap()).to_string()
        }
        _ => { stats.dec_active_connections(); return; }
    };

    // ── 6. Connect to target ──────────────────────────────────────────────────
    let connect_addr = format!("{}:{}", target_host, port);
    let target_stream = match TcpStream::connect(&connect_addr).await {
        Ok(s) => {
            let _ = s.set_nodelay(true);
            s
        }
        Err(e) => {
            stats.log_event(
                &format!("Сервер H2: Ошибка подключения к {}: {}", connect_addr, e),
                &format!("Server H2: Failed to connect to target {}: {}", connect_addr, e),
            );
            stats.dec_active_connections();
            return;
        }
    };

    stats.log_event(
        &format!("Сервер H2: Клиент {} → {}:{}", peer_addr.ip(), target_host, port),
        &format!("Server H2: Client {} → {}:{}", peer_addr.ip(), target_host, port),
    );

    // ── 7. Bidirectional relay: HTTP/2 DATA ↔ raw TCP ────────────────────────
    // We can't split the boxed stream, so we use a channel-based approach.
    let (target_reader, mut target_writer) = target_stream.into_split();

    // Spawn upload: read H2 DATA from client, decrypt, forward to target
    let stats_up   = Arc::clone(&stats);
    let (tx_up, mut rx_up) = tokio::sync::mpsc::channel::<Vec<u8>>(32);

    // We need to drive both directions from a single task since we can't split
    // the boxed TLS stream.  Use a select! loop.
    let mut target_reader = target_reader;
    // 16KB read buffer — safe atomic chunk size
    let mut buf = vec![0u8; 16384];

    loop {
        tokio::select! {
            // Client → Target
            h2_result = h2_obfs::recv_data(&mut stream) => {
                match h2_result {
                    Ok(Some(data)) => {
                        if data.len() < 2 { break; }
                        let flen = u16::from_be_bytes([data[0], data[1]]) as usize;
                        if data.len() < 2 + flen { break; }
                        let rtp = &data[2..2 + flen];
                        if let Some(pt) = rx_cipher.open(rtp) {
                            if target_writer.write_all(&pt).await.is_err() { break; }
                            stats_up.add_uploaded(pt.len() as u64);
                        } else { break; }
                    }
                    _ => break,
                }
            }
            // Target → Client
            read_result = target_reader.read(&mut buf) => {
                match read_result {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        match tx_cipher.seal(&buf[..n]) {
                            Ok(wire) => {
                                if h2_obfs::send_data(&mut stream, &wire).await.is_err() { break; }
                                if stream.flush().await.is_err() { break; }
                                stats.add_downloaded(n as u64);
                            }
                            Err(e) => { error!("Server H2 seal failed: {}", e); break; }
                        }
                    }
                }
            }
        }
    }

    drop(tx_up);
    let _ = rx_up.recv().await;

    stats.dec_active_connections();
    stats.log_event(
        &format!("Сервер H2: Туннель {}:{} закрыт", target_host, port),
        &format!("Server H2: Tunnel {}:{} closed", target_host, port),
    );
}
