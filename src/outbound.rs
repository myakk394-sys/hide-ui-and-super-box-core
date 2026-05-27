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
use tracing::{warn, error, debug};


use crate::config::Config;
use crate::stats::ProxyStats;
use rand::{rngs::OsRng, RngCore};
use crate::hidekey::handshake::{ClientChallenge, ServerHandshake, CHALLENGE_SIZE};
use crate::hidekey::framing::length_prefix;

use crate::hidekey::crypto::{encrypt_chacha20poly1305, decrypt_chacha20poly1305};
use crate::hidekey::stego::{RtpSessionState, unpack_rtp};


// ── Public entry point ────────────────────────────────────────────────────────

/// Start the Hidekey server listener.
pub async fn start_outbound_server(
    config: Arc<std::sync::RwLock<Config>>,
    peers: Arc<tokio::sync::RwLock<std::collections::HashMap<String, crate::hideui::db::Peer>>>,
    stats: Arc<ProxyStats>,
) -> tokio::io::Result<()> {
    let bind_addr = {
        let cfg = config.read().unwrap();
        format!("{}:{}", cfg.remote_outbound_address, cfg.server_listen_port)
    };

    let listener = TcpListener::bind(&bind_addr).await.map_err(|e| {
        stats.log_event(
            &format!("Сервер: Ошибка привязки к {}", bind_addr),
            &format!("Server: Failed to bind Hidekey listener to {}", bind_addr),
        );
        e
    })?;

    stats.log_event(
        &format!("Сервер Hidekey запущен на {}", bind_addr),
        &format!("Hidekey Server active on {}", bind_addr),
    );

    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let peers_cloned = Arc::clone(&peers);
                let st = Arc::clone(&stats);
                tokio::spawn(async move {
                    handle_hidekey_connection(stream, peer_addr, peers_cloned, st).await;
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

    let mut challenge_buf = [0u8; CHALLENGE_SIZE];
    if let Err(e) = stream.read_exact(&mut challenge_buf).await {
        debug!("Server: Failed to read ClientChallenge from {}: {}", peer_addr.ip(), e);
        stats.dec_active_connections();
        return;
    }
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

    let mut response_packet = Vec::with_capacity(2 + srv_junk_len + response_bytes.len());
    response_packet.extend_from_slice(&(srv_junk_len as u16).to_be_bytes());
    response_packet.extend_from_slice(&srv_junk_bytes);
    response_packet.extend_from_slice(&response_bytes);

    if let Err(e) = stream.write_all(&response_packet).await {
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
    // Redirect port 53 TCP to local systemd-resolved (avoids ISP blocking of foreign DNS)
    let connect_addr = if port == 53 {
        "127.0.0.53:53".to_string()
    } else {
        format!("{}:{}", target_host, port)
    };

    let target_stream = match TcpStream::connect(&connect_addr).await {
        Ok(s) => s,
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
