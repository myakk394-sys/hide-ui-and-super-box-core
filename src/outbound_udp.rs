//! # super_box::outbound_udp
//!
//! Server-side UDP listener for the Hidekey obfuscated transport.
//!
//! ## State machine
//!
//! Each client `SocketAddr` maps to a `SessionState`:
//!
//! ```text
//!  (unknown addr)
//!       │  recv datagram, decode with pre-session key
//!       │  verify ClientChallenge BLAKE3 MAC
//!       ▼
//!   Pending { rx_key, tx_key, rx_counter }
//!       │  recv next datagram, decode with session rx_key
//!       │  parse target addr from payload (CMD + PORT + ATYP + ADDR)
//!       │  TcpStream::connect(target)
//!       │  spawn tcp_to_udp_relay task
//!       ▼
//!   Established { rx_key, tcp_tx (mpsc sender) }
//!       │  recv datagram → decode → send to tcp_tx channel
//!       │  tcp_to_udp_relay reads TCP → encodes → send_to(client_addr)
//!       ▼
//!   (TCP closed → remove from table)
//! ```
//!
//! ## Concurrency model
//!
//! - One receive loop owns the `recv_from` call (single consumer).
//! - Session table is `Arc<DashMap<SocketAddr, SessionState>>`:
//!   - DashMap uses internal sharding (default 16 shards) — no global lock.
//!   - Hot path (established sessions) takes a per-shard read lock only.
//!   - Insert/remove take a per-shard write lock — other shards unaffected.
//! - Each established session has an `mpsc::Sender<Bytes>` for the TCP write
//!   direction. The relay task owns the `Receiver` end.
//! - TCP→UDP relay tasks are fully independent `tokio::spawn` tasks.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use crate::hidekey::handshake::{
    ClientChallenge, ServerHandshake, CHALLENGE_SIZE,
};
use crate::hidekey::udp_obfs::{
    self, UdpSessionCounter,
    DIR_CLIENT_TO_SERVER, DIR_SERVER_TO_CLIENT, MAX_UDP_PAYLOAD,
};
use crate::hidekey::crypto::derive_blake3_key;

// ── Session state machine ─────────────────────────────────────────────────────

/// Per-client session state.
enum SessionState {
    /// Handshake verified. Waiting for the first data packet that carries
    /// the proxy target address (CMD + PORT + ATYP + ADDR).
    Pending {
        rx_key: [u8; 32],
        tx_key: [u8; 32],
        rx_counter: UdpSessionCounter,
    },

    /// TCP connection to the target is open. Data flows bidirectionally.
    Established {
        rx_key: [u8; 32],
        /// Channel to the TCP writer task (client→target direction).
        tcp_tx: mpsc::Sender<Bytes>,
    },
}

// ── Session table type alias ──────────────────────────────────────────────────

/// Sharded concurrent hash map — no global lock, O(1) per-shard contention.
/// DashMap uses 16 shards by default; each shard has its own RwLock.
type SessionTable = Arc<DashMap<SocketAddr, SessionState>>;

// ── Public entry point ────────────────────────────────────────────────────────

/// Starts the Hidekey UDP server on `bind_addr`.
///
/// # Arguments
/// * `bind_addr`  — local UDP address (e.g. `"0.0.0.0:4430"`)
/// * `master_key` — 32-byte shared secret
pub async fn start_udp_server(
    bind_addr: &str,
    master_key: [u8; 32],
) -> tokio::io::Result<()> {
    let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
    info!("Hidekey UDP server listening on {}", bind_addr);

    let xor_key = udp_obfs::derive_header_xor_key(&master_key);
    let pre_rx_key = derive_blake3_key("hidekey-udp-pre-session-rx", &master_key);
    let pre_tx_key = derive_blake3_key("hidekey-udp-pre-session-tx", &master_key);

    // DashMap: sharded, no global lock — each shard is an independent RwLock.
    let sessions: SessionTable = Arc::new(DashMap::new());

    let mut recv_buf = [0u8; MAX_UDP_PAYLOAD];

    loop {
        let (n, client_addr) = match socket.recv_from(&mut recv_buf).await {
            Ok(v) => v,
            Err(e) => { error!("UDP recv_from: {}", e); continue; }
        };

        let datagram = Bytes::copy_from_slice(&recv_buf[..n]);

        // ── Fast path: established session ────────────────────────────────────
        // DashMap::get() takes a per-shard read lock — no global contention.
        if let Some(state) = sessions.get(&client_addr) {
            if let SessionState::Established { rx_key, tcp_tx } = state.value() {
                match udp_obfs::decode_packet(&datagram, DIR_CLIENT_TO_SERVER, rx_key, &xor_key) {
                    Ok(decoded) => { let _ = tcp_tx.try_send(decoded.payload); }
                    Err(e) => { debug!("UDP data decode failed from {}: {}", client_addr, e); }
                }
                continue; // shard read lock released here (state guard dropped)
            }
        }

        // ── Slow path: Pending session or new client ──────────────────────────
        // DashMap::get_mut() takes a per-shard write lock — other shards free.
        if let Some(mut entry) = sessions.get_mut(&client_addr) {
            // ── State: Pending — first data packet carries target address ─────
            if let SessionState::Pending { rx_key, tx_key, rx_counter } = entry.value_mut() {
                let rx_key = *rx_key;
                let tx_key = *tx_key;

                let decoded = match udp_obfs::decode_packet(
                    &datagram, DIR_CLIENT_TO_SERVER, &rx_key, &xor_key,
                ) {
                    Ok(d) => d,
                    Err(e) => { debug!("UDP pending decode failed from {}: {}", client_addr, e); continue; }
                };

                if !rx_counter.accept_rx(decoded.packet_id) {
                    debug!("UDP pending replay from {} — dropped", client_addr);
                    continue;
                }

                let target_addr = match parse_target_addr(&decoded.payload) {
                    Some(a) => a,
                    None => {
                        warn!("UDP: invalid target addr from {} — removing session", client_addr);
                        drop(entry); // release shard lock before remove
                        sessions.remove(&client_addr);
                        continue;
                    }
                };

                drop(entry); // release shard lock before async TCP connect

                debug!("UDP: {} → connecting to target {}", client_addr, target_addr);

                let tcp_stream = match tokio::time::timeout(
                    tokio::time::Duration::from_secs(15),
                    tokio::net::TcpStream::connect(&target_addr),
                ).await {
                    Ok(Ok(s)) => {
                        let _ = s.set_nodelay(true);
                        s
                    }
                    Ok(Err(e)) => {
                        warn!("UDP: TCP connect to {} failed: {}", target_addr, e);
                        sessions.remove(&client_addr);
                        continue;
                    }
                    Err(_) => {
                        warn!("UDP: TCP connect to {} timed out", target_addr);
                        sessions.remove(&client_addr);
                        continue;
                    }
                };

                info!("UDP: session established {} → {}", client_addr, target_addr);

                let (tcp_read_half, tcp_write_half) = tcp_stream.into_split();
                let (tcp_tx, tcp_rx) = mpsc::channel::<Bytes>(256);

                tokio::spawn(udp_to_tcp_writer(tcp_rx, tcp_write_half));
                tokio::spawn(tcp_to_udp_relay(
                    tcp_read_half,
                    Arc::clone(&socket),
                    client_addr,
                    tx_key,
                    xor_key,
                    Arc::clone(&sessions),
                ));

                sessions.insert(client_addr, SessionState::Established { rx_key, tcp_tx });
            }
            continue;
        }

        // ── No session: new client, expect ClientChallenge ────────────────────
        let decoded = match udp_obfs::decode_packet(
            &datagram, DIR_CLIENT_TO_SERVER, &pre_rx_key, &xor_key,
        ) {
            Ok(d) => d,
            Err(e) => { debug!("UDP: decode failed from new client {} ({})", client_addr, e); continue; }
        };

        if decoded.payload.len() != CHALLENGE_SIZE {
            warn!(
                "UDP: unexpected payload {} bytes from new client {} (expected {})",
                decoded.payload.len(), client_addr, CHALLENGE_SIZE
            );
            continue;
        }

        let mut challenge_buf = [0u8; CHALLENGE_SIZE];
        challenge_buf.copy_from_slice(&decoded.payload);
        let challenge = ClientChallenge::from_bytes(&challenge_buf);

        let hs = ServerHandshake::new(master_key);
        let (response, session_keys) = match hs.process_challenge(&challenge) {
            Some(v) => v,
            None => {
                warn!("UDP: handshake MAC failed from {} — silent drop", client_addr);
                continue;
            }
        };

        // Send ServerResponse
        let response_bytes = response.to_bytes();
        let mut out_buf = [0u8; MAX_UDP_PAYLOAD];
        match udp_obfs::encode_packet(
            &response_bytes, 0, DIR_SERVER_TO_CLIENT,
            &pre_tx_key, &xor_key, &mut out_buf,
        ) {
            Ok(pkt_len) => {
                let sock = Arc::clone(&socket);
                let buf_copy = out_buf;
                let addr = client_addr;
                tokio::spawn(async move {
                    if let Err(e) = sock.send_to(&buf_copy[..pkt_len], addr).await {
                        error!("UDP: send handshake response to {}: {}", addr, e);
                    }
                });
            }
            Err(e) => { error!("UDP: encode handshake response failed: {}", e); continue; }
        }

        sessions.insert(client_addr, SessionState::Pending {
            rx_key: session_keys.rx_key,
            tx_key: session_keys.tx_key,
            rx_counter: UdpSessionCounter::new(),
        });

        debug!("UDP: handshake OK from {} → Pending", client_addr);
    }
}

// ── Target address parser ─────────────────────────────────────────────────────

/// Parses the proxy target from the first post-handshake payload.
///
/// Wire format (same as used by the client in `handle_hidekey_udp`):
///   [0]    = CMD  (0x01 = TCP CONNECT)
///   [1..3] = PORT (big-endian u16)
///   [3]    = ATYP (0x01 = IPv4, 0x04 = IPv6)
///   [4..]  = address bytes (4 for IPv4, 16 for IPv6)
fn parse_target_addr(payload: &[u8]) -> Option<String> {
    if payload.len() < 4 { return None; }
    if payload[0] != 0x01 { return None; }
    let port = u16::from_be_bytes([payload[1], payload[2]]);
    match payload[3] {
        0x01 => {
            if payload.len() < 8 { return None; }
            let ip = std::net::Ipv4Addr::new(payload[4], payload[5], payload[6], payload[7]);
            Some(format!("{}:{}", ip, port))
        }
        0x04 => {
            if payload.len() < 20 { return None; }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&payload[4..20]);
            let ip = std::net::Ipv6Addr::from(octets);
            Some(format!("[{}]:{}", ip, port))
        }
        _ => None,
    }
}

// ── TCP writer task (client → target) ────────────────────────────────────────

/// Receives decoded payloads from the receive loop via `mpsc` channel
/// and writes them to the outbound TCP stream.
async fn udp_to_tcp_writer(
    mut rx: mpsc::Receiver<Bytes>,
    mut tcp_write: tokio::net::tcp::OwnedWriteHalf,
) {
    use tokio::io::AsyncWriteExt;
    while let Some(payload) = rx.recv().await {
        if let Err(e) = tcp_write.write_all(&payload).await {
            debug!("udp_to_tcp_writer: TCP write error: {}", e);
            break;
        }
    }
    debug!("udp_to_tcp_writer: channel closed");
}

// ── TCP reader task (target → client) ────────────────────────────────────────

/// Reads from the outbound TCP stream and sends obfuscated UDP datagrams
/// back to the client. Removes the session when TCP closes.
async fn tcp_to_udp_relay(
    mut tcp_read: tokio::net::tcp::OwnedReadHalf,
    socket: Arc<UdpSocket>,
    client_addr: SocketAddr,
    tx_key: [u8; 32],
    xor_key: [u8; 4],
    sessions: SessionTable,
) {
    use tokio::io::AsyncReadExt;

    let mut read_buf = [0u8; 8192];
    let mut out_buf = [0u8; MAX_UDP_PAYLOAD];
    let mut tx_counter: u32 = 0;

    // Max payload per UDP chunk: leave room for header + AEAD overhead + min padding
    const CHUNK: usize = MAX_UDP_PAYLOAD
        - udp_obfs::HEADER_SIZE
        - udp_obfs::ENCRYPT_OVERHEAD
        - 16;

    loop {
        let n = match tcp_read.read(&mut read_buf).await {
            Ok(0) => { debug!("tcp_to_udp_relay: TCP EOF for {}", client_addr); break; }
            Ok(n) => n,
            Err(e) => { debug!("tcp_to_udp_relay: TCP read error for {}: {}", client_addr, e); break; }
        };

        let mut offset = 0;
        while offset < n {
            let end = (offset + CHUNK).min(n);
            match udp_obfs::encode_packet(
                &read_buf[offset..end],
                tx_counter,
                DIR_SERVER_TO_CLIENT,
                &tx_key, &xor_key,
                &mut out_buf,
            ) {
                Ok(pkt_len) => {
                    if let Err(e) = socket.send_to(&out_buf[..pkt_len], client_addr).await {
                        debug!("tcp_to_udp_relay: UDP send error to {}: {}", client_addr, e);
                    }
                    tx_counter = tx_counter.wrapping_add(1);
                }
                Err(e) => { error!("tcp_to_udp_relay: encode error: {}", e); }
            }
            offset = end;
        }
    }

    // TCP closed — remove session so the client can reconnect cleanly.
    // DashMap::remove() takes only the affected shard's write lock.
    if sessions.remove(&client_addr).is_some() {
        debug!("UDP: session {} removed (TCP closed)", client_addr);
    }
}
