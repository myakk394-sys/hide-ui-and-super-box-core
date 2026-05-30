//! # hidekey::mux
//!
//! HTTP/2 Stream-per-Session Multiplexer using the official robust `h2` crate.
//!
//! Eliminates custom binary framing and window management by using standard
//! HTTP/2 Streams and flow control.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{debug, warn, info, error};
use futures::future::poll_fn;
use bytes::{Bytes, BytesMut};
use tokio::io::AsyncWriteExt;

use super::h2_obfs::AsyncStream;

// ── Flow Control Helper ──────────────────────────────────────────────────────

/// Robustly writes data chunk by chunk to H2 SendStream, respecting flow control capacity.
/// Loops on poll_capacity until we get actual capacity (non-zero) or an error.
pub async fn send_chunk(
    send_stream: &mut h2::SendStream<Bytes>,
    chunk: &[u8],
) -> Result<(), h2::Error> {
    let mut offset = 0;
    while offset < chunk.len() {
        let remaining = chunk.len() - offset;
        let reserve_sz = remaining.min(65536);
        send_stream.reserve_capacity(reserve_sz);
        
        // Loop until we get non-zero capacity; n==0 means window not yet available.
        let n = loop {
            let granted = poll_fn(|cx| send_stream.poll_capacity(cx)).await;
            match granted {
                Some(Ok(0)) => {
                    // Flow control window temporarily at zero — yield to let H2 connection driver run.
                    tokio::task::yield_now().await;
                    send_stream.reserve_capacity(reserve_sz);
                    continue;
                }
                Some(Ok(n)) => break n,
                Some(Err(e)) => return Err(e),
                // None means the stream was closed/reset by the peer.
                None => return Err(h2::Reason::CANCEL.into()),
            }
        };
        
        let write_sz = n.min(remaining);
        let bytes = Bytes::copy_from_slice(&chunk[offset..offset + write_sz]);
        send_stream.send_data(bytes, false)?;
        offset += write_sz;
    }
    Ok(())
}

/// Robustly writes Bytes chunk by chunk to H2 SendStream using zero-copy slicing, respecting flow control.
/// Loops on poll_capacity until we get actual capacity (non-zero) or an error.
pub async fn send_bytes(
    send_stream: &mut h2::SendStream<Bytes>,
    mut chunk: Bytes,
) -> Result<(), h2::Error> {
    while !chunk.is_empty() {
        let remaining = chunk.len();
        let reserve_sz = remaining.min(65536);
        send_stream.reserve_capacity(reserve_sz);
        
        // Loop until we get non-zero capacity; n==0 means window not yet available.
        let n = loop {
            let granted = poll_fn(|cx| send_stream.poll_capacity(cx)).await;
            match granted {
                Some(Ok(0)) => {
                    // Flow control window temporarily at zero — yield to let H2 connection driver run.
                    tokio::task::yield_now().await;
                    send_stream.reserve_capacity(reserve_sz);
                    continue;
                }
                Some(Ok(n)) => break n,
                Some(Err(e)) => return Err(e),
                // None means the stream was closed/reset by the peer.
                None => return Err(h2::Reason::CANCEL.into()),
            }
        };
        
        let write_sz = n.min(remaining);
        let bytes = chunk.split_to(write_sz);
        send_stream.send_data(bytes, false)?;
    }
    Ok(())
}

// ── MUX Client ───────────────────────────────────────────────────────────────

pub struct MuxClient {
    send_request: h2::client::SendRequest<Bytes>,
    is_closed: Arc<AtomicBool>,
    pub sni: String,
}

impl MuxClient {
    /// Create a new MuxClient wrapping H2 send request.
    pub fn new(
        send_request: h2::client::SendRequest<Bytes>,
        is_closed: Arc<AtomicBool>,
        sni: String,
    ) -> Self {
        Self {
            send_request,
            is_closed,
            sni,
        }
    }

    /// Check if the H2 connection is still alive.
    pub fn is_alive(&self) -> bool {
        !self.is_closed.load(Ordering::SeqCst)
    }

    /// Perform Hidekey authentication challenge/response handshake over an H2 stream.
    pub async fn authenticate(&self, master_key: [u8; 32]) -> Result<(), String> {
        let sni = &self.sni;
        let mut send_request = self.send_request.clone();
        
        let ready_res = tokio::time::timeout(
            tokio::time::Duration::from_secs(15),
            poll_fn(|cx| send_request.poll_ready(cx))
        ).await;

        let ready_res = match ready_res {
            Ok(res) => res,
            Err(_) => return Err("H2 client ready timeout".to_string()),
        };

        if let Err(e) = ready_res {
            return Err(format!("H2 client not ready: {}", e));
        }
        
        // Build challenge
        use crate::hidekey::handshake::{ClientHandshake, RESPONSE_SIZE};
        let hs = ClientHandshake::new(master_key);
        let challenge = hs.build_challenge();
        
        let mut len_byte = [0u8; 1];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut len_byte);
        let junk_len = 16 + (len_byte[0] % 113) as usize; // 16 to 128
        let mut junk_bytes = vec![0u8; junk_len];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut junk_bytes);
        
        let mut rtp_header = [0u8; 12];
        let mut rtp_state = crate::hidekey::stego::RtpSessionState::new();
        let header = crate::hidekey::stego::RtpHeader::new(rtp_state.seq_number, rtp_state.timestamp, rtp_state.ssrc);
        header.serialize(&mut rtp_header);
        junk_bytes[0..12].copy_from_slice(&rtp_header);
        
        let mut packet1 = Vec::with_capacity(2 + junk_len);
        packet1.extend_from_slice(&(junk_len as u16).to_be_bytes());
        packet1.extend_from_slice(&junk_bytes);
        
        let mut challenge_rtp_state = crate::hidekey::stego::RtpSessionState::new();
        let challenge_rtp_packet = challenge_rtp_state.pack(&challenge.to_bytes());
        let mut packet2 = Vec::with_capacity(2 + challenge_rtp_packet.len());
        packet2.extend_from_slice(&(challenge_rtp_packet.len() as u16).to_be_bytes());
        packet2.extend_from_slice(&challenge_rtp_packet);
        
        let p1_padded = crate::hidekey::stego::amnezia_pad(&packet1);
        let p2_padded = crate::hidekey::stego::amnezia_pad(&packet2);
        
        // Build standard HTTP/2 auth request carrying challenge in headers
        let mut request = http::Request::new(());
        *request.method_mut() = http::Method::POST;
        *request.uri_mut() = http::Uri::try_from(format!("https://{}/api/v1/auth", sni)).unwrap();
        
        request.headers_mut().insert("x-challenge", http::HeaderValue::from_str(&hex::encode(p2_padded)).unwrap());
        request.headers_mut().insert("x-junk", http::HeaderValue::from_str(&hex::encode(p1_padded)).unwrap());
        
        // Send request (end_of_stream = false)
        let address = request.uri().clone();
        debug!("Sending request to: {:?}, SNI: {:?}", address, sni);
        let (response_future, mut send_stream) = match send_request.send_request(request, false) {
            Ok(res) => res,
            Err(e) => return Err(format!("H2 send auth request failed: {}", e)),
        };
        
        let response = match response_future.await {
            Ok(res) => res,
            Err(e) => return Err(format!("H2 auth response error: {}", e)),
        };
        
        // Cleanly close client's send stream side as headers are sent
        let _ = send_stream.send_data(Bytes::new(), true);
        
        if response.status() != http::StatusCode::OK {
            return Err(format!("Server rejected authentication: {}", response.status()));
        }
        
        // Read ServerResponse and ServerJunk from headers
        let srv_resp_hex = match response.headers().get("x-response").and_then(|v| v.to_str().ok()) {
            Some(v) => v,
            None => {
                error!("Auth failed, received headers: {:?}", response.headers());
                return Err("Auth failed".to_string());
            }
        };
        let srv_junk_hex = match response.headers().get("x-junk").and_then(|v| v.to_str().ok()) {
            Some(v) => v,
            None => {
                error!("Auth failed, received headers: {:?}", response.headers());
                return Err("Auth failed".to_string());
            }
        };
            
        let srv_resp_data = hex::decode(srv_resp_hex).map_err(|e| format!("Invalid x-response hex: {}", e))?;
        let srv_junk_data = hex::decode(srv_junk_hex).map_err(|e| format!("Invalid x-junk hex: {}", e))?;
        
        let srv_junk_len = if srv_junk_data.len() >= 2 {
            u16::from_be_bytes([srv_junk_data[0], srv_junk_data[1]]) as usize
        } else { 0 };
        if srv_junk_len < 16 || srv_junk_len > 256 {
            return Err("Invalid ServerJunkLen".to_string());
        }
        
        if srv_resp_data.len() < 2 {
            return Err("ServerResponse too short".to_string());
        }
        let resp_len = u16::from_be_bytes([srv_resp_data[0], srv_resp_data[1]]) as usize;
        if resp_len != 88 || srv_resp_data.len() < 2 + resp_len {
            return Err("Invalid ServerResponseLen".to_string());
        }
        let resp_rtp = &srv_resp_data[2..2 + resp_len];
        let resp_payload = crate::hidekey::stego::unpack_rtp(resp_rtp)
            .ok_or_else(|| "Invalid RTP response".to_string())?;
        if resp_payload.len() != RESPONSE_SIZE {
            return Err("Invalid unpacked response size".to_string());
        }
        
        let mut resp_buf = [0u8; RESPONSE_SIZE];
        resp_buf.copy_from_slice(&resp_payload);
        
        let server_response = crate::hidekey::handshake::ServerResponse::from_bytes(&resp_buf);
        let _session = match hs.process_response(&server_response) {
            Some(s) => s,
            None => return Err("ServerResponse MAC verification FAILED".to_string()),
        };
        
        Ok(())
    }

    /// Open a new dedicated H2 stream for proxying.
    pub async fn open_stream(
        &self,
        target_info: &[u8],
    ) -> Result<(h2::client::ResponseFuture, h2::SendStream<Bytes>), String> {
        let sni = &self.sni;
        let mut send_request = self.send_request.clone();
        
        let ready_res = tokio::time::timeout(
            tokio::time::Duration::from_secs(15),
            poll_fn(|cx| send_request.poll_ready(cx))
        ).await;

        let ready_res = match ready_res {
            Ok(res) => res,
            Err(_) => return Err("H2 client ready timeout (connection overloaded)".to_string()),
        };

        if let Err(e) = ready_res {
            return Err(format!("H2 client not ready: {}", e));
        }
        
        let mut request = http::Request::new(());
        *request.method_mut() = http::Method::POST;
        *request.uri_mut() = http::Uri::try_from(format!("https://{}/api/v1/stream", sni)).unwrap();
        
        request.headers_mut().insert("x-target", http::HeaderValue::from_str(&hex::encode(target_info)).unwrap());
        
        let address = request.uri().clone();
        debug!("Sending request to: {:?}, SNI: {:?}", address, sni);
        match send_request.send_request(request, false) {
            Ok(res) => Ok(res),
            Err(e) => Err(format!("H2 send request failed: {}", e)),
        }
    }
}

// ── MUX Server ───────────────────────────────────────────────────────────────

/// Run standard H2 server multiplexing over a secure TLS connection.
pub async fn run_mux_server(
    stream: Box<dyn AsyncStream>,
    peers: Arc<tokio::sync::RwLock<std::collections::HashMap<String, crate::hideui::db::Peer>>>,
    stats: Arc<crate::stats::ProxyStats>,
) {
    let mut builder = h2::server::Builder::new();
    builder.max_header_list_size(65536);
    // Window sizes tuned for 1-core VPS: 1MB per stream, 8MB total connection.
    // Large windows increase memory pressure when many streams are active.
    builder.initial_window_size(8_388_608);         // 8 MB per-stream window (match client)
    builder.initial_connection_window_size(16_777_216); // 16 MB connection window (match client)
    builder.max_frame_size(65536);                  // 64 KB frames for good stream fairness
    builder.max_concurrent_streams(4000); // Allow up to 4000 concurrent streams
    let mut h2_conn = match builder.handshake(stream).await {
        Ok(h) => h,
        Err(e) => {
            warn!("MuxServer: H2 handshake failed: {}", e);
            return;
        }
    };
    
    debug!("MuxServer: H2 engine active, accepting streams...");
    
    while let Some(result) = h2_conn.accept().await {
        let (request, mut respond) = match result {
            Ok(r) => r,
            Err(e) => {
                warn!("MuxServer: H2 accept stream error: {}", e);
                break;
            }
        };
        
        let path = request.uri().path();
        
        if path == "/api/v1/auth" {
            // --- Hidekey Handshake Challenge Verification ---
            let headers = request.headers();
            info!("Получены заголовки: {:?}", headers);
            
            let challenge_header = headers.get("x-challenge");
            if challenge_header.is_none() {
                error!("Auth headers missing in request!");
                let response = http::Response::builder()
                    .status(http::StatusCode::UNAUTHORIZED)
                    .header("x-error", "Auth headers missing in request!")
                    .body(())
                    .unwrap();
                let _ = respond.send_response(response, true);
                continue;
            } else {
                info!("Processing challenge: {:?}", challenge_header);
            }
            
            let challenge_hex = challenge_header.unwrap().to_str().ok();
            let junk_hex = headers.get("x-junk").and_then(|v| v.to_str().ok());
            
            if challenge_hex.is_none() {
                let response = http::Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .header("x-error", "challenge header decode failed")
                    .body(())
                    .unwrap();
                let _ = respond.send_response(response, true);
                continue;
            }
            
            if junk_hex.is_none() {
                error!("Junk header missing in request!");
                let response = http::Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .header("x-error", "Junk header missing in request!")
                    .body(())
                    .unwrap();
                let _ = respond.send_response(response, true);
                continue;
            }
            
            let p2_padded = match hex::decode(challenge_hex.unwrap()) {
                Ok(b) => b,
                Err(_) => {
                    let response = http::Response::builder()
                        .status(http::StatusCode::BAD_REQUEST)
                        .header("x-error", "challenge hex decode failed")
                        .body(())
                        .unwrap();
                    let _ = respond.send_response(response, true);
                    continue;
                }
            };

            // The first 2 bytes are the length of the RTP packet (amnezia_pad may add extra bytes after).
            // Slice exactly frame_len bytes before passing to unpack_rtp.
            if p2_padded.len() < 2 {
                let response = http::Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .header("x-error", "challenge too short")
                    .body(()).unwrap();
                let _ = respond.send_response(response, true);
                continue;
            }
            let rtp_len = u16::from_be_bytes([p2_padded[0], p2_padded[1]]) as usize;
            if p2_padded.len() < 2 + rtp_len {
                let response = http::Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .header("x-error", "challenge rtp slice out of bounds")
                    .body(()).unwrap();
                let _ = respond.send_response(response, true);
                continue;
            }

            let challenge_payload = match crate::hidekey::stego::unpack_rtp(&p2_padded[2..2 + rtp_len]) {
                Some(p) => p,
                None => {
                    let response = http::Response::builder()
                        .status(http::StatusCode::BAD_REQUEST)
                        .header("x-error", "challenge rtp unpack failed")
                        .body(())
                        .unwrap();
                    let _ = respond.send_response(response, true);
                    continue;
                }
            };

            use crate::hidekey::handshake::{ClientChallenge, ServerHandshake, CHALLENGE_SIZE};
            if challenge_payload.len() != CHALLENGE_SIZE {
                let response = http::Response::builder()
                    .status(http::StatusCode::BAD_REQUEST)
                    .header("x-error", "invalid challenge payload size")
                    .body(())
                    .unwrap();
                let _ = respond.send_response(response, true);
                continue;
            }
            
            let mut challenge_buf = [0u8; CHALLENGE_SIZE];
            challenge_buf.copy_from_slice(&challenge_payload);
            let challenge = ClientChallenge::from_bytes(&challenge_buf);
            
            // Loop through active peers to verify challenge Blake3 MAC
            let peers_guard = peers.read().await;
            let mut verified = None;
            for peer in peers_guard.values() {
                if !peer.active || peer.master_key.len() != 64 { continue; }
                let key_bytes = (0..32)
                    .map(|i| u8::from_str_radix(&peer.master_key[i * 2..i * 2 + 2], 16).ok())
                    .collect::<Option<Vec<u8>>>();
                let key_bytes = match key_bytes {
                    Some(b) => b,
                    None => continue,
                };
                let mut mk = [0u8; 32];
                mk.copy_from_slice(&key_bytes);
                
                let hs = ServerHandshake::new(mk);
                if let Some((resp, _)) = hs.process_challenge(&challenge) {
                    verified = Some((resp, mk));
                    break;
                }
            }
            drop(peers_guard);
            
            let (response_handshake, _mk) = match verified {
                Some(v) => v,
                None => {
                    warn!("MuxServer: peer handshake MAC verification FAILED");
                    let response = http::Response::builder()
                        .status(http::StatusCode::UNAUTHORIZED)
                        .header("x-error", "handshake MAC verification failed")
                        .body(())
                        .unwrap();
                    let _ = respond.send_response(response, true);
                    continue;
                }
            };
            
            // Build Server response junk
            let mut len_byte = [0u8; 1];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut len_byte);
            let srv_junk_len = 16 + (len_byte[0] % 113) as usize;
            let mut srv_junk_bytes = vec![0u8; srv_junk_len];
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut srv_junk_bytes);
            
            let mut rtp_header = [0u8; 12];
            let mut rtp_state = crate::hidekey::stego::RtpSessionState::new();
            let header = crate::hidekey::stego::RtpHeader::new(rtp_state.seq_number, rtp_state.timestamp, rtp_state.ssrc);
            header.serialize(&mut rtp_header);
            srv_junk_bytes[0..12].copy_from_slice(&rtp_header);
            
            let mut junk_frame = Vec::with_capacity(2 + srv_junk_len);
            junk_frame.extend_from_slice(&(srv_junk_len as u16).to_be_bytes());
            junk_frame.extend_from_slice(&srv_junk_bytes);
            let srv_junk_padded = crate::hidekey::stego::amnezia_pad(&junk_frame);
            
            let resp_bytes = response_handshake.to_bytes();
            let mut rtp_state2 = crate::hidekey::stego::RtpSessionState::new();
            let resp_rtp = rtp_state2.pack(&resp_bytes);
            let resp_framed = crate::hidekey::framing::length_prefix(&resp_rtp);
            let resp_padded = crate::hidekey::stego::amnezia_pad(&resp_framed);
            
            let encoded_response = hex::encode(&resp_padded);
            let encoded_junk = hex::encode(&srv_junk_padded);
            
            let mut response = match http::Response::builder()
                .status(http::StatusCode::OK)
                .header("x-response", encoded_response)
                .header("x-junk", encoded_junk)
                .body(())
            {
                Ok(resp) => resp,
                Err(e) => {
                    error!("MuxServer: failed to build auth response: {:?}", e);
                    continue;
                }
            };
            
            let mut send_stream = match respond.send_response(response, false) {
                Ok(s) => s,
                Err(e) => {
                    warn!("MuxServer: auth send response failed: {}", e);
                    continue;
                }
            };
            let _ = send_stream.send_data(Bytes::new(), true);
            debug!("MuxServer: H2 auth successful, client authenticated");
            continue;
        }
        
        if path == "/api/v1/stream" {
            // --- Proxy Stream request ---
            let headers = request.headers();
            let target_hex = match headers.get("x-target").and_then(|v| v.to_str().ok()) {
                Some(t) => t,
                None => {
                    let mut response = http::Response::new(());
                    *response.status_mut() = http::StatusCode::BAD_REQUEST;
                    let _ = respond.send_response(response, true);
                    continue;
                }
            };
            
            let target_info = match hex::decode(target_hex) {
                Ok(b) => b,
                Err(_) => {
                    let mut response = http::Response::new(());
                    *response.status_mut() = http::StatusCode::BAD_REQUEST;
                    let _ = respond.send_response(response, true);
                    continue;
                }
            };
            
            if target_info.len() < 4 {
                let mut response = http::Response::new(());
                *response.status_mut() = http::StatusCode::BAD_REQUEST;
                let _ = respond.send_response(response, true);
                continue;
            }
            
            let network_type = target_info[0];
            let port = u16::from_be_bytes([target_info[1], target_info[2]]);
            let atyp = target_info[3];
            let target_host = match atyp {
                0x01 if target_info.len() >= 8 => {
                    let ip = std::net::Ipv4Addr::new(target_info[4], target_info[5], target_info[6], target_info[7]);
                    ip.to_string()
                }
                0x04 if target_info.len() >= 20 => {
                    let ip = std::net::Ipv6Addr::from(
                        <[u8; 16]>::try_from(&target_info[4..20]).unwrap()
                    );
                    ip.to_string()
                }
                _ => {
                    let mut response = http::Response::new(());
                    *response.status_mut() = http::StatusCode::BAD_REQUEST;
                    let _ = respond.send_response(response, true);
                    continue;
                }
            };
            
            let connect_addr = format!("{}:{}", target_host, port);
            
            let mut recv_stream = request.into_body();
            
            let mut response = http::Response::new(());
            *response.status_mut() = http::StatusCode::OK;
            
            let mut send_stream = match respond.send_response(response, false) {
                Ok(s) => s,
                Err(e) => {
                    warn!("MuxServer: send stream response failed: {}", e);
                    continue;
                }
            };
            
            let stats_up = Arc::clone(&stats);
            let stats_down = Arc::clone(&stats);
            
            if network_type == 0x11 {
                // --- UDP Proxy (DNS over standard UDP) ---
                tokio::spawn(async move {
                    let udp_socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
                        Ok(s) => s,
                        Err(e) => { warn!("MuxServer: UDP bind failed: {}", e); return; }
                    };

                    if let Err(e) = udp_socket.connect(&connect_addr).await {
                        warn!("MuxServer: UDP connect to {} failed: {}", connect_addr, e);
                        return;
                    }

                    debug!("MuxServer: UDP session H2-stream relay active: {}", connect_addr);
                    stats_up.inc_active_connections();
                    
                    let last_activity = Arc::new(std::sync::Mutex::new(tokio::time::Instant::now()));
                    let last_activity_up = Arc::clone(&last_activity);
                    let last_activity_down = Arc::clone(&last_activity);
                    
                    let udp_sock_send = Arc::new(udp_socket);
                    let udp_sock_recv = Arc::clone(&udp_sock_send);
                    
                    let mut send_stream_cloned = send_stream;
                    let mut recv_stream_cloned = recv_stream;
                    
                    let stats_up_inner = Arc::clone(&stats_up);
                    let stats_down_inner = Arc::clone(&stats_down);

                    let upload = tokio::spawn(async move {
                        loop {
                            match recv_stream_cloned.data().await {
                                Some(Ok(chunk)) => {
                                    let len = chunk.len();
                                    if let Err(e) = udp_sock_send.send(&chunk).await {
                                        if e.raw_os_error() == Some(10054) {
                                            debug!("MuxServer: UDP session ConnectionReset (OS 10054)");
                                        } else {
                                            debug!("MuxServer: UDP session target send error: {}", e);
                                        }
                                        break;
                                    }
                                    stats_up_inner.add_uploaded(len as u64);
                                    if let Ok(mut time) = last_activity_up.lock() {
                                        *time = tokio::time::Instant::now();
                                    }
                                    let _ = recv_stream_cloned.flow_control().release_capacity(len);
                                }
                                Some(Err(e)) => {
                                    debug!("MuxServer: UDP session H2 recv error: {}", e);
                                    break;
                                }
                                None => break,
                            }
                        }
                    });
                    
                    let download = tokio::spawn(async move {
                        let mut buf = vec![0u8; 2048];
                        loop {
                            match udp_sock_recv.recv(&mut buf).await {
                                Ok(n) => {
                                    if let Err(e) = send_chunk(&mut send_stream_cloned, &buf[..n]).await {
                                        debug!("MuxServer: UDP session H2 send error: {}", e);
                                        break;
                                    }
                                    stats_down_inner.add_downloaded(n as u64);
                                    if let Ok(mut time) = last_activity_down.lock() {
                                        *time = tokio::time::Instant::now();
                                    }
                                }
                                Err(ref e) if e.raw_os_error() == Some(10054) => {
                                    debug!("MuxServer: UDP session ConnectionReset (OS 10054)");
                                    break;
                                }
                                Err(e) => {
                                    debug!("MuxServer: UDP session target recv error: {}", e);
                                    break;
                                }
                            }
                        }
                    });
                    
                    tokio::select! {
                        _ = upload => {}
                        _ = download => {}
                    }
                    stats_down.dec_active_connections();
                });
                
                continue;
            }
            
            // --- TCP Proxy ---
            tokio::spawn(async move {
                let target_stream = match tokio::net::TcpStream::connect(&connect_addr).await {
                    Ok(s) => {
                        let _ = s.set_nodelay(true);
                        s
                    }
                    Err(e) => {
                        warn!("MuxServer: TCP connect to {} failed: {}", connect_addr, e);
                        return;
                    }
                };
                
                debug!("MuxServer: TCP session H2-stream relay active: {}", connect_addr);
                stats_up.inc_active_connections();
                
                let (mut target_reader, mut target_writer) = target_stream.into_split();
                
                let mut send_stream_cloned = send_stream;
                let mut recv_stream_cloned = recv_stream;
                
                let stats_up_inner = Arc::clone(&stats_up);
                let stats_down_inner = Arc::clone(&stats_down);

                let upload = tokio::spawn(async move {
                    loop {
                        match recv_stream_cloned.data().await {
                            Some(Ok(chunk)) => {
                                let len = chunk.len();
                                if let Err(e) = target_writer.write_all(&chunk).await {
                                    if e.raw_os_error() == Some(10054) {
                                        debug!("MuxServer: TCP session ConnectionReset (OS 10054)");
                                    } else {
                                        debug!("MuxServer: TCP session target write error: {}", e);
                                    }
                                    break;
                                }
                                stats_up_inner.add_uploaded(len as u64);
                                let _ = recv_stream_cloned.flow_control().release_capacity(len);
                            }
                            Some(Err(e)) => {
                                debug!("MuxServer: TCP session H2 recv error: {}", e);
                                break;
                            }
                            None => break,
                        }
                    }
                });
                
                let download = tokio::spawn(async move {
                    use tokio::io::AsyncReadExt;
                    let mut buf = BytesMut::with_capacity(65536);
                    loop {
                        buf.reserve(65536);
                        match target_reader.read_buf(&mut buf).await {
                            Ok(0) => break,
                            Err(ref e) if e.raw_os_error() == Some(10054) => {
                                debug!("MuxServer: TCP session ConnectionReset (OS 10054)");
                                break;
                            }
                            Err(e) => {
                                debug!("MuxServer: TCP session target read error: {}", e);
                                break;
                            }
                            Ok(n) => {
                                let chunk = buf.split_to(n).freeze();
                                if let Err(e) = send_bytes(&mut send_stream_cloned, chunk).await {
                                    debug!("MuxServer: TCP session H2 send error: {}", e);
                                    break;
                                }
                                stats_down_inner.add_downloaded(n as u64);
                            }
                        }
                    }
                });
                
                tokio::select! {
                    _ = upload => {}
                    _ = download => {}
                }
                stats_down.dec_active_connections();
            });
        }
    }
}
