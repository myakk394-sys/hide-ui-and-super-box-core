use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::{Aes256Gcm, KeyInit, aead::Aead};
use hmac::Mac;
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use tracing::{info, error, debug, warn};
use x25519_dalek::PublicKey;

use crate::config::{Config, SecurityType};
use crate::hidekey::handshake::{ClientHandshake, RESPONSE_SIZE};
use crate::hidekey::framing::length_prefix;

use crate::hidekey::crypto::{encrypt_chacha20poly1305, decrypt_chacha20poly1305};
use crate::hidekey::stego::{RtpSessionState, unpack_rtp};

// ── TLS constants ────────────────────────────────────────────────────────────
const TLS_RECORD_HANDSHAKE: u8 = 0x16;
const TLS_LEGACY_VERSION: [u8; 2] = [0x03, 0x01]; // TLS 1.0 record layer (for compat)
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_VERSION_12: [u8; 2] = [0x03, 0x03]; // ClientHello version (TLS 1.2 compat)

// Chrome-like TLS 1.3 cipher suites (matches JA3 fingerprint)
const CIPHER_SUITES: &[u8] = &[
    0x13, 0x01, // TLS_AES_128_GCM_SHA256
    0x13, 0x02, // TLS_AES_256_GCM_SHA384
    0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
    0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    0xcc, 0xa9, // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
    0xcc, 0xa8, // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
    0x00, 0x9c, // TLS_RSA_WITH_AES_128_GCM_SHA256
    0x00, 0x9d, // TLS_RSA_WITH_AES_256_GCM_SHA384
];

// ── Public entry point ────────────────────────────────────────────────────────

/// Starts processing TCP connections from the TUN interface.
pub async fn start_inbound(config: Arc<Config>, mut listener: netstack_smoltcp::TcpListener) -> tokio::io::Result<()> {
    use futures::StreamExt;
    info!("🚀 TUN TCP listener active");

    while let Some((stream, peer_addr, dest_addr)) = listener.next().await {
        let cfg = Arc::clone(&config);
        tokio::spawn(async move {
            handle_connection(stream, peer_addr, dest_addr, cfg).await;
        });
    }
    
    error!("❌ TUN TCP listener closed");
    Ok(())
}

// ── TLS ClientHello builder ───────────────────────────────────────────────────
//
// Produces a byte-perfect TLS 1.3 ClientHello with an embedded REALITY session-id.
//
// Structure (RFC 8446 §4.1.2):
//   TLS Record Layer  : type(1) + legacy_version(2) + length(2)
//   Handshake Header  : msg_type(1) + length(3)
//   ClientHello body  : legacy_version(2) + random(32) + sid_len(1) + sid(32)
//                     + cipher_suites_len(2) + cipher_suites(N*2) + 0x01 0x00
//                     + extensions_len(2) + extensions(...)
//
// The REALITY session-id is an AES-256-GCM ciphertext of 16-byte plaintext
// (protocol flags + timestamp + short_id), encrypted with a key derived from
// the X25519 shared secret via HMAC-SHA256 (HKDF-Extract + HKDF-Expand).
// The ciphertext is 16+16=32 bytes and lives where the session-id normally would.
//
fn build_tls_client_hello(
    shared_secret: &[u8; 32],
    short_id: &[u8],
    ephemeral_pub: &[u8; 32],
    sni: &str,
) -> Vec<u8> {

    // ── Step 1: Generate the 32-byte TLS Random field ────────────────────────
    let mut tls_random = [0u8; 32];
    OsRng.fill_bytes(&mut tls_random);

    // ── Step 2: Derive the REALITY session-id ────────────────────────────────
    //
    // Plaintext layout (16 bytes):
    //   [0]    = 0x01  (auth marker)
    //   [1]    = 0x08  (flow marker)
    //   [2]    = 0x01
    //   [3]    = 0x00
    //   [4..8] = Unix timestamp (big-endian u32)
    //   [8..8+sid_len] = short_id bytes (up to 8 bytes)
    let mut plaintext = [0u8; 16];
    plaintext[0] = 0x01;
    plaintext[1] = 0x08;
    plaintext[2] = 0x01;
    plaintext[3] = 0x00;
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32;
    plaintext[4..8].copy_from_slice(&ts.to_be_bytes());
    let sid_len = short_id.len().min(8);
    plaintext[8..8 + sid_len].copy_from_slice(&short_id[..sid_len]);

    // HKDF-Extract: PRK = HMAC-SHA256(salt=random[0..20], IKM=shared_secret)
    let mut mac_extract = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(&tls_random[0..20])
        .expect("HMAC");
    mac_extract.update(shared_secret);
    let prk = mac_extract.finalize().into_bytes();

    // HKDF-Expand: auth_key = HMAC-SHA256(PRK, "REALITY" || 0x01)
    let mut mac_expand = <hmac::Hmac<Sha256> as KeyInit>::new_from_slice(&prk)
        .expect("HMAC");
    mac_expand.update(b"REALITY");
    mac_expand.update(&[0x01]);
    let auth_key = mac_expand.finalize().into_bytes();


    let aes = <Aes256Gcm as KeyInit>::new_from_slice(&auth_key).expect("AES-256-GCM key");

    // ── Step 3: Build Extensions ─────────────────────────────────────────────
    // Each extension: type(2) + length(2) + data(length)
    // All lengths are computed dynamically — no magic constants.
    let mut exts = Vec::<u8>::new();

    // 0x0000  server_name (SNI)
    // server_name_list_len(2) + name_type(1) + name_len(2) + name(N)
    {
        let name = sni.as_bytes();
        let name_len = name.len() as u16;
        let list_len = 1u16 + 2 + name_len;   // name_type(1) + name_len(2) + name(N)
        let ext_len  = 2u16 + list_len;        // list_len_field(2) + list body
        exts.extend_from_slice(&0x0000u16.to_be_bytes()); // ext type
        exts.extend_from_slice(&ext_len.to_be_bytes());
        exts.extend_from_slice(&list_len.to_be_bytes());
        exts.push(0x00);                                    // name_type = host_name
        exts.extend_from_slice(&name_len.to_be_bytes());
        exts.extend_from_slice(name);
    }

    // 0x000a  supported_groups: X25519(0x001d) + P-256(0x0017) + P-384(0x0018)
    {
        let groups: &[u16] = &[0x001d, 0x0017, 0x0018];
        let list_body_len = (groups.len() * 2) as u16;  // 6
        let ext_len       = 2u16 + list_body_len;        // 8
        exts.extend_from_slice(&0x000au16.to_be_bytes());
        exts.extend_from_slice(&ext_len.to_be_bytes());
        exts.extend_from_slice(&list_body_len.to_be_bytes());
        for &g in groups { exts.extend_from_slice(&g.to_be_bytes()); }
    }

    // 0x000d  signature_algorithms
    {
        let schemes: &[u16] = &[
            0x0403, // ecdsa_secp256r1_sha256
            0x0804, // rsa_pss_rsae_sha256
            0x0401, // rsa_pkcs1_sha256
            0x0503, // ecdsa_secp384r1_sha384
            0x0805, // rsa_pss_rsae_sha384
            0x0501, // rsa_pkcs1_sha384
            0x0806, // rsa_pss_rsae_sha512
            0x0601, // rsa_pkcs1_sha512
        ];
        let list_body_len = (schemes.len() * 2) as u16;
        let ext_len       = 2u16 + list_body_len;
        exts.extend_from_slice(&0x000du16.to_be_bytes());
        exts.extend_from_slice(&ext_len.to_be_bytes());
        exts.extend_from_slice(&list_body_len.to_be_bytes());
        for &s in schemes { exts.extend_from_slice(&s.to_be_bytes()); }
    }

    // 0x002b  supported_versions
    // FIX: "versions" in ClientHello is a length-prefixed vector with a 1-byte count.
    // Old code set ext_len=5 but forgot that the 1-byte count itself is part of ext data,
    // so Xray's parser read garbage and reported "unsupported versions: [302 301]".
    // Correct layout: ext_len(2) | list_byte_count(1) | version(2) | version(2)
    //                      5            4               0x0304        0x0303
    {
        let versions: &[u16] = &[0x0304, 0x0303]; // TLS 1.3 first, then TLS 1.2
        let list_byte_count  = (versions.len() * 2) as u8; // 4
        let ext_len          = 1u16 + list_byte_count as u16; // 5
        exts.extend_from_slice(&0x002bu16.to_be_bytes());
        exts.extend_from_slice(&ext_len.to_be_bytes());
        exts.push(list_byte_count); // 1-byte length prefix for the versions vector
        for &v in versions { exts.extend_from_slice(&v.to_be_bytes()); }
    }

    // 0x0010  ALPN: h2, http/1.1
    {
        let protos: &[&[u8]] = &[b"h2", b"http/1.1"];
        let mut proto_list = Vec::<u8>::new();
        for p in protos {
            proto_list.push(p.len() as u8);
            proto_list.extend_from_slice(p);
        }
        let proto_list_len = proto_list.len() as u16;
        let ext_len        = 2u16 + proto_list_len;
        exts.extend_from_slice(&0x0010u16.to_be_bytes());
        exts.extend_from_slice(&ext_len.to_be_bytes());
        exts.extend_from_slice(&proto_list_len.to_be_bytes());
        exts.extend_from_slice(&proto_list);
    }

    // 0x0033  key_share: one X25519 entry
    {
        let key_entry_len     = 2u16 + 2u16 + 32u16; // group(2)+key_len(2)+key(32) = 36
        let client_shares_len = key_entry_len;
        let ext_len           = 2u16 + client_shares_len; // shares_len_field(2) + entry = 38
        exts.extend_from_slice(&0x0033u16.to_be_bytes());
        exts.extend_from_slice(&ext_len.to_be_bytes());
        exts.extend_from_slice(&client_shares_len.to_be_bytes());
        exts.extend_from_slice(&0x001du16.to_be_bytes()); // X25519
        exts.extend_from_slice(&0x0020u16.to_be_bytes()); // key_len = 32
        exts.extend_from_slice(ephemeral_pub);
    }

    // ── Step 4: Assemble ClientHello body ────────────────────────────────────
    // Layout (RFC 8446 §4.1.2):
    //   legacy_version(2) = 0x0303
    //   random(32)
    //   sid_len(1)        = 0x20 (32)
    //   sid(32)           ← REALITY fills with AES-GCM ciphertext
    //   cipher_suites_len(2)
    //   cipher_suites(N)
    //   compression_methods_len(1) = 0x01
    //   compression_methods(1)     = 0x00
    //   extensions_len(2)
    //   extensions(...)
    let mut ch_body = Vec::<u8>::new();
    ch_body.extend_from_slice(&[0x03, 0x03]);   // legacy_version = TLS 1.2
    ch_body.extend_from_slice(&tls_random);      // random
    ch_body.push(0x20);                          // session_id_len = 32
    let session_id_offset = ch_body.len();
    ch_body.extend_from_slice(&[0u8; 32]);       // placeholder SID for AAD

    // Chrome cipher suite order, same 22 bytes as the constant at top of file
    let cs_list: &[u8] = &[
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,
        0xcc, 0xa9, 0xcc, 0xa8,
        0x00, 0x9c, 0x00, 0x9d,
    ];
    ch_body.extend_from_slice(&(cs_list.len() as u16).to_be_bytes());
    ch_body.extend_from_slice(cs_list);
    ch_body.push(0x01); // compression_methods_len
    ch_body.push(0x00); // null compression
    ch_body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    ch_body.extend_from_slice(&exts);

    // ── Step 5: Handshake header: msg_type(1) + 24-bit length ────────────────
    let ch_body_len = ch_body.len() as u32;
    let hs_header = [
        0x01,
        ((ch_body_len >> 16) & 0xff) as u8,
        ((ch_body_len >>  8) & 0xff) as u8,
        ( ch_body_len        & 0xff) as u8,
    ];

    // ── Step 6: Encrypt REALITY session-id ───────────────────────────────────
    // AAD = hs_header(4) + ch_body (with zero SID placeholder)
    // Nonce = tls_random[20..32] (12 bytes)
    // Result = ciphertext(16) + tag(16) = 32 bytes → replaces the SID field
    let mut aad = Vec::<u8>::with_capacity(4 + ch_body.len());
    aad.extend_from_slice(&hs_header);
    aad.extend_from_slice(&ch_body);

    let nonce = aes_gcm::Nonce::from_slice(&tls_random[20..32]);
    let sid_ciphertext = aes.encrypt(nonce, aes_gcm::aead::Payload {
        msg: &plaintext,
        aad: &aad,
    }).expect("REALITY: AES-256-GCM encryption failed");
    debug_assert_eq!(sid_ciphertext.len(), 32);

    // Splice encrypted SID into the body
    ch_body[session_id_offset..session_id_offset + 32].copy_from_slice(&sid_ciphertext);

    // ── Step 7: TLS record wrapper ────────────────────────────────────────────
    // content_type(1) = 0x16 + legacy_record_version(2) = 0x0301 + length(2)
    let record_body_len = (hs_header.len() + ch_body.len()) as u16;
    let mut record = Vec::<u8>::with_capacity(5 + record_body_len as usize);
    record.push(0x16);
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record layer per RFC 8446
    record.extend_from_slice(&record_body_len.to_be_bytes());
    record.extend_from_slice(&hs_header);
    record.extend_from_slice(&ch_body);

    record
}


// ── VLESS header builder ──────────────────────────────────────────────────────

fn build_vless_header(
    vless_uuid: &uuid::Uuid,
    vless_addr_type: u8,
    addr_bytes: &[u8],
    port: u16,
    flow: Option<&str>,
) -> Vec<u8> {
    let mut header = Vec::new();
    header.push(0x00); // VLESS version 0
    header.extend_from_slice(vless_uuid.as_bytes()); // 16-byte UUID
    
    if let Some(f) = flow {
        if f == "xtls-rprx-vision" {
            // Protobuf message: Addons { Flow: "xtls-rprx-vision", Seed: empty }
            // Field 1 (String): tag = (1 << 3) | 2 = 10 (0x0A)
            let flow_bytes = f.as_bytes();
            let mut addons = Vec::new();
            addons.push(0x0A);
            addons.push(flow_bytes.len() as u8);
            addons.extend_from_slice(flow_bytes);
            
            header.push(addons.len() as u8);
            header.extend_from_slice(&addons);
        } else {
            header.push(0x00);
        }
    } else {
        header.push(0x00); // addons length = 0
    }
    
    header.push(0x01); // cmd = CONNECT (TCP)
    header.extend_from_slice(&port.to_be_bytes()); // destination port (2 bytes)
    header.push(vless_addr_type); // address type
    header.extend_from_slice(addr_bytes); // address bytes
    header
}

// ── Main connection handler ───────────────────────────────────────────────────

async fn handle_connection(mut stream: netstack_smoltcp::TcpStream, peer_addr: SocketAddr, dest_addr: SocketAddr, config: Arc<Config>) {
    // In TUN mode, dest_addr is directly passed from the listener
    let dest_ip = dest_addr.ip();
    let port = dest_addr.port();
    let addr_str = dest_ip.to_string();

    debug!("🔗 TUN TCP connection intercepted: {} -> {}:{}", peer_addr, dest_ip, port);

    // ── Dispatch to Hidekey protocol if master key is present ────────────────
    if let Some(master_key_hex) = config.hidekey_master_key.as_deref() {
        if master_key_hex.len() == 64 {
            let key_bytes: Option<Vec<u8>> = (0..32)
                .map(|i| u8::from_str_radix(&master_key_hex[i * 2..i * 2 + 2], 16).ok())
                .collect();
            if let Some(kb) = key_bytes {
                let mut master_key = [0u8; 32];
                master_key.copy_from_slice(&kb);
                handle_hidekey_connection(stream, master_key, dest_ip, port, config).await;
                return;
            }
        }
        error!("❌ Hidekey master key invalid hex (need 64 hex chars): '{}'", master_key_hex);
        return;
    }

    let (vless_addr_type, addr_bytes) = match dest_ip {
        std::net::IpAddr::V4(ipv4) => (1, ipv4.octets().to_vec()),
        std::net::IpAddr::V6(ipv6) => (3, ipv6.octets().to_vec()),
    };

    // ── 2. Open raw TCP to the VLESS server ─────────────────────────
    let server_addr = format!(
        "{}:{}",
        config.remote_outbound_address, config.server_listen_port
    );

    // Log fragment settings so we can confirm they're read from the URL.
    debug!(
        "🔍 Попытка установить базовое TCP соединение с Аезой: {} | фрагментация: {} (размер={}-{}B, задержка={}-{}ms)",
        server_addr,
        if config.fragment.enabled { "ВКЛ" } else { "ВЫКЛ" },
        config.fragment.size_min,
        config.fragment.size_max,
        config.fragment.delay_min,
        config.fragment.delay_max,
    );

    // Resolve server_addr to SocketAddr
    let resolved_server_addr = match tokio::net::lookup_host(&server_addr).await {
        Ok(mut addrs) => match addrs.next() {
            Some(addr) => addr,
            None => {
                error!("❌ DNS resolved successfully but returned no addresses for {}", server_addr);
                let _ = stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                return;
            }
        },
        Err(e) => {
            error!("❌ DNS resolution failed for {}: {}", server_addr, e);
            let _ = stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            return;
        }
    };

    let socket = if resolved_server_addr.is_ipv4() {
        tokio::net::TcpSocket::new_v4().unwrap()
    } else {
        tokio::net::TcpSocket::new_v6().unwrap()
    };

    // Force-bind this socket to the physical interface (not TUN) using IP_UNICAST_IF.
    // This is the ONLY reliable way to bypass TUN on Windows — route table tricks don't work
    // because Wintun intercepts at driver level before routing decisions are made.
    #[cfg(target_os = "windows")]
    if let Some(if_index) = config.physical_if_index {
        use std::os::windows::io::AsRawSocket;
        let raw = socket.as_raw_socket();
        // IP_UNICAST_IF = 31 (IPv4), IPV6_UNICAST_IF = 31 (IPv6)
        // Forces this socket's outbound packets through the specified interface index.
        let if_index_be = (if_index as u32).to_be(); // network byte order
        let ret = unsafe {
            windows_sys::Win32::Networking::WinSock::setsockopt(
                raw as usize,
                windows_sys::Win32::Networking::WinSock::IPPROTO_IP as i32,
                31, // IP_UNICAST_IF
                &if_index_be as *const u32 as *const u8,
                std::mem::size_of::<u32>() as i32,
            )
        };
        if ret != 0 {
            error!("⚠️ IP_UNICAST_IF setsockopt failed with error: {}", unsafe { windows_sys::Win32::Networking::WinSock::WSAGetLastError() });
        } else {
            debug!("✅ Socket bound to physical interface index {} via IP_UNICAST_IF", if_index);
        }
    }

    // Wrap the connect in a 15-second timeout.
    let connect_result = tokio::time::timeout(
        tokio::time::Duration::from_secs(15),
        socket.connect(resolved_server_addr),
    )
    .await;


    let mut server_stream = match connect_result {
        // tokio::time::timeout fired — no TCP SYN/ACK within 15 s
        Err(_elapsed) => {
            error!(
                "🔴 Сервер Аезы не отвечает на TCP-запрос (возможно, IP/порт {} забанен ТСПУ — таймаут 15 сек)",
                server_addr
            );
            return;
        }
        // Got an OS error (e.g. 10060 WSAETIMEDOUT, 10061 WSAECONNREFUSED, etc.)
        Ok(Err(e)) => {
            error!(
                "🔴 TCP connect к {} провалился: {} \
                 | Если это os error 10060 — порт {} скорее всего заблокирован ТСПУ на уровне IP",
                server_addr, e, config.server_listen_port
            );
            return;
        }
        // TCP three-way handshake succeeded — TSPU did not block this IP:port
        Ok(Ok(s)) => {
            debug!(
                "🟢 Базовый TCP-туннель открыт с {}. Переходим к отправке {}REALITY ClientHello...",
                server_addr,
                if config.fragment.enabled { "фрагментированного " } else { "" },
            );
            s
        }
    };

    // ── 3. REALITY handshake (only when security = reality) ──────────
    let mut app_encrypter: Option<crate::tls13::ZeroCopyTlsEncrypter> = None;
    let mut app_decrypter: Option<crate::tls13::ZeroCopyTlsDecrypter> = None;
    let mut tls_cipher_suite: Option<u16> = None;

    if config.security == SecurityType::Reality {
        // 3a. Parse server public key (base64 → 32 bytes)
        let pbk_str = match &config.reality_public_key {
            Some(k) => k.clone(),
            None => {
                error!("❌ REALITY requires pbk (public key) in config");
                let _ = stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                return;
            }
        };

        let pbk_bytes = match base64_decode_x25519(&pbk_str) {
            Some(b) => b,
            None => {
                error!("❌ REALITY: Failed to decode server public key: {}", pbk_str);
                let _ = stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                return;
            }
        };

        // 3b. Parse short_id (hex → bytes)
        let sid_str = config.reality_short_id.as_deref().unwrap_or("");
        let sid_bytes = hex_decode(sid_str);

        let client_secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);
        let server_pubkey = x25519_dalek::PublicKey::from(pbk_bytes);
        let shared_secret = client_secret.diffie_hellman(&server_pubkey);
        let shared_secret_bytes: [u8; 32] = *shared_secret.as_bytes();
        let client_pub_bytes = *client_public.as_bytes();

        // 3e. Get SNI from config
        let sni = match config.sni.as_deref() {
            Some(s) if !s.is_empty() && s.parse::<std::net::IpAddr>().is_err() => s,
            _ => {
                error!("❌ REALITY: config.sni MUST be provided and cannot be an IP address! Your server will drop the connection.");
                return;
            }
        };

        // 3f. Build raw TLS ClientHello with integrated REALITY Session ID
        let client_hello = build_tls_client_hello(
            &shared_secret_bytes,
            &sid_bytes,
            &client_pub_bytes,
            sni,
        );

        // 3g. Hash the ClientHello into the TLS 1.3 Transcript
        let mut transcript = crate::tls13::TranscriptHash::new();
        transcript.update(&client_hello[5..]); // skip 5-byte TLS record header

        // ── 3h. Fragmented ClientHello send ──────────────────────────
        //
        // Enable TCP_NODELAY so each write() call results in an independent
        // TCP segment. Without this, Nagle's algorithm would coalesce fragments
        // back into one packet, defeating the entire DPI bypass.
        if let Err(e) = server_stream.set_nodelay(true) {
            error!("❌ REALITY: Failed to set TCP_NODELAY: {}", e);
            let _ = stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            return;
        }

        if config.fragment.enabled {
            // ── Fragmented path ──────────────────────────────────────
            //
            // Strategy: split the raw ClientHello byte array into chunks of
            // randomized sizes between `fragment.size_min` and `fragment.size_max`.
            // Send each chunk with an explicit flush + randomized sleep between
            // `fragment.delay_min` and `fragment.delay_max`.
            use rand::Rng;
            let mut offset = 0;
            let total = client_hello.len();
            let mut chunk_idx = 0;

            debug!(
                "✂️ REALITY fragment: {} bytes total, size={}-{}B, delay={}-{}ms",
                total, config.fragment.size_min, config.fragment.size_max, config.fragment.delay_min, config.fragment.delay_max
            );

            while offset < total {
                let size = {
                    let mut rng = rand::thread_rng();
                    rng.gen_range(config.fragment.size_min..=config.fragment.size_max).max(1)
                };
                let end = std::cmp::min(offset + size, total);
                let chunk = &client_hello[offset..end];
                chunk_idx += 1;

                if let Err(e) = server_stream.write_all(chunk).await {
                    error!("❌ REALITY fragment {}: write failed: {}", chunk_idx, e);
                    let _ = stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    return;
                }
                // flush() forces an immediate syscall; combined with TCP_NODELAY this
                // guarantees the bytes leave the socket buffer right now.
                if let Err(e) = server_stream.flush().await {
                    error!("❌ REALITY fragment {}: flush failed: {}", chunk_idx, e);
                    let _ = stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    return;
                }
                
                // After every fragment except the last, insert the randomized delay.
                if end < total {
                    let delay = {
                        let mut rng = rand::thread_rng();
                        rng.gen_range(config.fragment.delay_min..=config.fragment.delay_max)
                    };
                    tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                }
                debug!("  ↑ fragment {}: {} bytes sent", chunk_idx, chunk.len());
                offset = end;
            }

            debug!("✅ REALITY fragment: all {} chunks sent", chunk_idx);
        } else {
            // ── Non-fragmented path ──────────────────────────────────
            //
            // Fragmentation is disabled — send the ClientHello as one write.
            // This is fine for servers reachable without censorship.
            debug!(
                "🔒 REALITY: Sending ClientHello in one shot ({} bytes) to {}",
                client_hello.len(), server_addr
            );
            if let Err(e) = server_stream.write_all(&client_hello).await {
                error!("❌ REALITY: Failed to send ClientHello: {}", e);
                let _ = stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                return;
            }
            if let Err(e) = server_stream.flush().await {
                error!("❌ REALITY: Failed to flush ClientHello: {}", e);
                let _ = stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                return;
            }
        }

        // ── 3i. Drain all inbound TLS records until server is done ───
        //
        // After a valid REALITY ClientHello the server sends back one or more
        // TLS records (ServerHello, optional ChangeCipherSpec, EncryptedExtensions).
        // We must consume ALL of them — not just the first — before sending VLESS
        // data, otherwise the server will see our VLESS header as unexpected data
        // mid-handshake and reset the connection.
        //
        // We read records greedily: read 5-byte header, read body, repeat until
        // we receive an alert (0x15) or the socket returns 0 bytes (half-close),
        // or the record type transitions to application_data (0x17) which means
        // the handshake is complete and the server is ready for VLESS.
        let mut records_drained: usize = 0;
        let mut server_hello_parsed = false;
        let mut decrypter: Option<crate::tls13::ZeroCopyTlsDecrypter> = None;
        let mut encrypter: Option<crate::tls13::ZeroCopyTlsEncrypter> = None;
        let mut tls_state: Option<crate::tls13::Tls13State> = None;

        loop {
            // Read the 5-byte TLS record header: type(1) + version(2) + length(2)
            let mut rec_header = [0u8; 5];
            match server_stream.read_exact(&mut rec_header).await {
                Ok(_) => {}
                Err(e) => {
                    error!("❌ REALITY: Failed to read TLS record header (record {}): {}", records_drained + 1, e);
                    let _ = stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    return;
                }
            }

            let rec_type = rec_header[0];
            let rec_body_len = u16::from_be_bytes([rec_header[3], rec_header[4]]) as usize;

            if rec_body_len > 18_000 {
                error!("❌ REALITY: Implausible TLS record body length {}", rec_body_len);
                let _ = stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                return;
            }

            let mut rec_body = vec![0u8; rec_body_len];
            if let Err(e) = server_stream.read_exact(&mut rec_body).await {
                error!("❌ REALITY: Failed to read TLS record body: {}", e);
                let _ = stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                return;
            }

            records_drained += 1;
            debug!("  ← TLS record {}: type=0x{:02x} len={} bytes", records_drained, rec_type, rec_body_len);

            match rec_type {
                0x15 => {
                    let alert_level = rec_body.first().copied().unwrap_or(0);
                    let alert_code  = rec_body.get(1).copied().unwrap_or(0);
                    error!("❌ REALITY: Server sent TLS Alert level={} code={} — handshake rejected.", alert_level, alert_code);
                    let _ = stream.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
                    return;
                }
                0x14 => {
                    debug!("  ← ChangeCipherSpec received");
                }
                0x16 => {
                    if !server_hello_parsed {
                        if rec_body.len() < 4 || rec_body[0] != 0x02 {
                            error!("❌ Expected ServerHello, got type 0x{:02x}", rec_body.first().unwrap_or(&0));
                            return;
                        }
                        
                        let hs_len = u32::from_be_bytes([0, rec_body[1], rec_body[2], rec_body[3]]) as usize;
                        if hs_len + 4 > rec_body.len() {
                            error!("❌ ServerHello handshake message length exceeds record body");
                            return;
                        }
                        
                        // Extract ServerKeyShare from ServerHello body
                        match crate::tls13::extract_server_key_share(&rec_body[4..4+hs_len]) {
                            Ok((server_ephemeral_pub, cipher_suite)) => {
                                let server_ephemeral_key = x25519_dalek::PublicKey::from(server_ephemeral_pub);
                                let tls_shared_secret = client_secret.diffie_hellman(&server_ephemeral_key);
                                
                                transcript.update(&rec_body[..4+hs_len]); // Hash EXACTLY ServerHello
                                
                                let state = crate::tls13::Tls13State::new(
                                    tls_shared_secret.as_bytes(),
                                    &transcript.finalize(cipher_suite),
                                    cipher_suite,
                                );
                                
                                decrypter = Some(crate::tls13::ZeroCopyTlsDecrypter::new(&state.server_handshake_secret, cipher_suite).unwrap());
                                encrypter = Some(crate::tls13::ZeroCopyTlsEncrypter::new(&state.client_handshake_secret, cipher_suite).unwrap());
                                tls_state = Some(state);
                                tls_cipher_suite = Some(cipher_suite);
                                server_hello_parsed = true;
                                debug!("✅ ServerHello parsed, CipherSuite: 0x{:04x}, Handshake secrets derived", cipher_suite);
                            }
                            Err(e) => {
                                error!("❌ Failed to parse ServerHello KeyShare: {:?}", e);
                                return;
                            }
                        }
                    } else {
                        // Unencrypted handshake message after ServerHello? Not expected in TLS 1.3
                        transcript.update(&rec_body);
                    }
                }
                0x17 => {
                    // ApplicationData: this is an encrypted record.
                    if let Some(dec) = &mut decrypter {
                        let mut full_record = Vec::with_capacity(5 + rec_body.len());
                        full_record.extend_from_slice(&rec_header);
                        full_record.extend_from_slice(&rec_body);
                        
                        match dec.decrypt_in_place(&mut full_record) {
                            Ok(pt_len) => {
                                // The plaintext is at full_record[5..5+pt_len]
                                // In TLS 1.3, the last non-zero byte of the plaintext is the true content type.
                                let mut true_type = 0;
                                let mut actual_len = pt_len;
                                while actual_len > 0 {
                                    actual_len -= 1;
                                    let b = full_record[5 + actual_len];
                                    if b != 0 {
                                        true_type = b;
                                        break;
                                    }
                                }
                                
                                debug!("  🔓 Decrypted record (true_type=0x{:02x}, len={})", true_type, actual_len);
                                
                                if true_type == 0x16 {
                                    let mut hs_pos = 5;
                                    let hs_end = 5 + actual_len;
                                    let mut finished_found = false;
                                    
                                    while hs_pos < hs_end {
                                        let msg_type = full_record[hs_pos];
                                        let msg_len = u32::from_be_bytes([0, full_record[hs_pos+1], full_record[hs_pos+2], full_record[hs_pos+3]]) as usize;
                                        let msg_end = hs_pos + 4 + msg_len;
                                        
                                        if msg_end > hs_end {
                                            error!("❌ Handshake message bounds exceeded");
                                            return;
                                        }
                                        
                                        if msg_type == 0x14 { // Finished
                                            debug!("  ✅ Received Server Finished message!");
                                            // The Server Finished message is NOT hashed before computing verify data.
                                            // It is hashed AFTER.
                                            transcript.update(&full_record[hs_pos..msg_end]);
                                            finished_found = true;
                                        } else {
                                            transcript.update(&full_record[hs_pos..msg_end]);
                                        }
                                        
                                        hs_pos = msg_end;
                                    }
                                    
                                    if finished_found {
                                        break; // Handshake complete from server side
                                    }
                                } else {
                                    debug!("  ⚠️ Unexpected encrypted record type 0x{:02x}", true_type);
                                }
                            }
                            Err(e) => {
                                error!("❌ Decryption of TLS record failed: {:?}", e);
                                return;
                            }
                        }
                    } else {
                        error!("❌ Received encrypted record before ServerHello");
                        return;
                    }
                }
                other => {
                    debug!("  ← Unknown TLS record type 0x{:02x}", other);
                }
            }
        }

        debug!("✅ REALITY: Server handshake done, sending Client Finished");
        
        let mut tls_state = tls_state.unwrap();
        
        // 1. Send ChangeCipherSpec
        let ccs = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        if let Err(e) = server_stream.write_all(&ccs).await {
            error!("❌ REALITY: Failed to write CCS: {}", e);
            return;
        }
        
        // 2. Compute Client Finished
        let client_verify_data = tls_state.compute_finished_verify_data(
            &tls_state.client_handshake_secret,
            &transcript.finalize(tls_state.cipher_suite)
        );
        
        let mut client_finished = Vec::with_capacity(64);
        client_finished.extend_from_slice(&[0, 0, 0, 0, 0]); // 5 byte header placeholder
        client_finished.extend_from_slice(&[0x14, 0x00, 0x00, 0x20]); // Handshake Type 0x14, Length 32
        client_finished.extend_from_slice(&client_verify_data);
        client_finished.push(0x16); // True content type = Handshake (0x16)
        
        client_finished.resize(5 + 37 + 16, 0); // Header (5) + Content (37) + Tag (16)
        
        let mut enc = encrypter.unwrap();
        let record_len = enc.encrypt_in_place(&mut client_finished, 37).unwrap();
        
        if let Err(e) = server_stream.write_all(&client_finished[..record_len]).await {
            error!("❌ REALITY: Failed to write Client Finished: {}", e);
            return;
        }
        
        // Hash the Client Finished message
        transcript.update(&[0x14, 0x00, 0x00, 0x20]);
        transcript.update(&client_verify_data);
        
        // 3. Derive Application Secrets
        tls_state.derive_app_secrets(&transcript.finalize(tls_state.cipher_suite));
        
        // 4. Update encrypter and decrypter for Application Data
        app_encrypter = Some(crate::tls13::ZeroCopyTlsEncrypter::new(&tls_state.client_app_secret, tls_cipher_suite.unwrap()).unwrap());
        app_decrypter = Some(crate::tls13::ZeroCopyTlsDecrypter::new(&tls_state.server_app_secret, tls_cipher_suite.unwrap()).unwrap());
        
        debug!("✅ REALITY: TLS 1.3 Handshake completely successful! Upgrading to VLESS stream.");

    } else if config.security == SecurityType::Tls {
        // Plain TLS mode: not supported in the raw relay path.
        // Use standard VLESS + none for testing; set security=reality for production.
        error!("❌ Plain TLS mode not supported in raw relay; use security=none or security=reality");
        let _ = stream.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
        return;
    }
    // security=none: skip all TLS and connect raw VLESS directly

    // ── 4. Send VLESS header ─────────────────────────────────────────
    let vless_header = build_vless_header(&config.vless_uuid, vless_addr_type, &addr_bytes, port, config.flow.as_deref());
    
    if config.security == SecurityType::Reality {
        let mut app_enc = app_encrypter.unwrap();
        let mut app_dec = app_decrypter.unwrap();
        
        // Encrypt VLESS header
        let mut encrypted_vless = Vec::with_capacity(vless_header.len() + 21 + 64);
        encrypted_vless.extend_from_slice(&[0, 0, 0, 0, 0]);
        encrypted_vless.extend_from_slice(&vless_header);
        encrypted_vless.push(0x17); // True type = Application Data
        
        encrypted_vless.resize(5 + vless_header.len() + 1 + 16, 0);
        
        let enc_len = app_enc.encrypt_in_place(&mut encrypted_vless, vless_header.len() + 1).unwrap();
        if let Err(e) = server_stream.write_all(&encrypted_vless[..enc_len]).await {
            error!("❌ VLESS: Failed to send encrypted header: {}", e);
            return;
        }
        let _ = server_stream.flush().await;

        // ── 6. TLS Bidirectional relay ───────────────────────────────────
        debug!("⚡ TLS Relay active: {}:{} via {}", addr_str, port, server_addr);
        
        let (mut client_read, mut client_write) = tokio::io::split(stream);
        let (mut server_read, mut server_write) = tokio::io::split(server_stream);
        
        let client_to_server = async move {
            let mut buf = vec![0u8; 16384 + 5 + 16 + 1]; // +1 for content type
            loop {
                use tokio::io::AsyncReadExt;
                use tokio::io::AsyncWriteExt;
                match client_read.read(&mut buf[5..5+16384]).await {
                    Ok(0) => break,
                    Ok(n) => {
                        buf[5+n] = 0x17; // Content type = Application Data
                        if let Ok(enc_len) = app_enc.encrypt_in_place(&mut buf, n + 1) {
                            if server_write.write_all(&buf[..enc_len]).await.is_err() { break; }
                        } else {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        };

        let server_to_client = async move {
            let mut vless_response_skipped = false;
            loop {
                use tokio::io::AsyncReadExt;
                use tokio::io::AsyncWriteExt;
                let mut header = [0u8; 5];
                if server_read.read_exact(&mut header).await.is_err() { break; }
                let len = u16::from_be_bytes([header[3], header[4]]) as usize;
                
                if len > 18000 { break; }
                let mut body = vec![0u8; len];
                if server_read.read_exact(&mut body).await.is_err() { break; }
                
                let mut full_record = Vec::with_capacity(5 + len);
                full_record.extend_from_slice(&header);
                full_record.extend_from_slice(&body);
                
                if let Ok(pt_len) = app_dec.decrypt_in_place(&mut full_record) {
                    let mut actual_len = pt_len;
                    let mut true_type = 0;
                    while actual_len > 0 {
                        actual_len -= 1;
                        let b = full_record[5 + actual_len];
                        if b != 0 {
                            true_type = b;
                            break;
                        }
                    }
                    if true_type == 0x17 {
                        let mut payload = &full_record[5..5+actual_len];
                        if !vless_response_skipped {
                            if payload.len() >= 2 {
                                let addon_len = payload[1] as usize;
                                if payload.len() >= 2 + addon_len {
                                    payload = &payload[2 + addon_len..];
                                    vless_response_skipped = true;
                                }
                            }
                        }
                        if !payload.is_empty() {
                            if client_write.write_all(payload).await.is_err() { break; }
                        }
                    } else if true_type == 0x15 {
                        break; // Alert
                    }
                } else {
                    break;
                }
            }
        };

        tokio::join!(client_to_server, server_to_client);
        debug!("✅ TLS Relay closed: {}:{}", addr_str, port);

    } else {
        // security=none: skip all TLS and connect raw VLESS directly
        if let Err(e) = server_stream.write_all(&vless_header).await {
            error!("❌ VLESS: Failed to send header: {}", e);
            return;
        }
        let _ = server_stream.flush().await;

        use tokio::io::AsyncReadExt;
        let mut resp_hdr = [0u8; 2];
        if server_stream.read_exact(&mut resp_hdr).await.is_ok() {
            let addon_len = resp_hdr[1] as usize;
            if addon_len > 0 {
                let mut addons = vec![0u8; addon_len];
                let _ = server_stream.read_exact(&mut addons).await;
            }
        }

        debug!("⚡ Relay active: {}:{} via {}", addr_str, port, server_addr);
        match tokio::io::copy_bidirectional(&mut stream, &mut server_stream).await {
            Ok((up, down)) => {
                debug!("✅ Relay closed: {}:{} (↑{} ↓{})", addr_str, port, up, down);
            }
            Err(e) => {
                debug!("⚠️ Relay error for {}:{}: {}", addr_str, port, e);
            }
        }
    }
}

// ── Hidekey protocol: per-direction cipher state ──────────────────────────────

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

    /// Encrypt plaintext → RTP packet → 2-byte length prefix. Returns wire bytes.
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

// ── Hidekey protocol client connection handler ────────────────────────────────
//
// Called when a hidekey:// config is used.
// Performs the Hidekey handshake with the server, then relays traffic
// bidirectionally with ChaCha20-Poly1305 + RTP steganographic framing.

async fn handle_hidekey_connection(
    tun_stream: netstack_smoltcp::TcpStream,
    master_key: [u8; 32],
    dest_ip: std::net::IpAddr,
    port: u16,
    config: Arc<Config>,
) {
    let server_addr = format!("{}:{}", config.remote_outbound_address, config.server_listen_port);

    // ── 1. Resolve server address ─────────────────────────────────────────────
    let resolved = match tokio::net::lookup_host(&server_addr).await {
        Ok(mut a) => match a.next() {
            Some(addr) => addr,
            None => {
                error!("❌ Hidekey: DNS resolved no addresses for {}", server_addr);
                return;
            }
        },
        Err(e) => {
            error!("❌ Hidekey: DNS resolution failed for {}: {}", server_addr, e);
            return;
        }
    };

    // ── 2. Open TCP socket bound to physical interface (bypass TUN) ───────────
    let socket = if resolved.is_ipv4() {
        tokio::net::TcpSocket::new_v4().unwrap()
    } else {
        tokio::net::TcpSocket::new_v6().unwrap()
    };

    #[cfg(target_os = "windows")]
    if let Some(if_index) = config.physical_if_index {
        use std::os::windows::io::AsRawSocket;
        let raw = socket.as_raw_socket();
        let if_index_be = (if_index as u32).to_be();
        let ret = unsafe {
            windows_sys::Win32::Networking::WinSock::setsockopt(
                raw as usize,
                windows_sys::Win32::Networking::WinSock::IPPROTO_IP as i32,
                31, // IP_UNICAST_IF
                &if_index_be as *const u32 as *const u8,
                std::mem::size_of::<u32>() as i32,
            )
        };
        if ret != 0 {
            error!("⚠️ Hidekey: IP_UNICAST_IF setsockopt failed: {}",
                unsafe { windows_sys::Win32::Networking::WinSock::WSAGetLastError() });
        }
    }

    let mut server_stream = match tokio::time::timeout(
        tokio::time::Duration::from_secs(15),
        socket.connect(resolved),
    ).await {
        Err(_) => {
            error!("🔴 Hidekey: TCP connect to {} timed out (15s)", server_addr);
            return;
        }
        Ok(Err(e)) => {
            error!("🔴 Hidekey: TCP connect to {} failed: {}", server_addr, e);
            return;
        }
        Ok(Ok(s)) => s,
    };

    // ── 3. Hidekey handshake with random junk ────────────────────────────────
    let hs = ClientHandshake::new(master_key);
    let challenge = hs.build_challenge();

    // Generate random junk length between 16 and 128
    let mut len_byte = [0u8; 1];
    OsRng.fill_bytes(&mut len_byte);
    let junk_len = 16 + (len_byte[0] % 113) as usize; // 16 to 128
    let mut junk_bytes = vec![0u8; junk_len];
    OsRng.fill_bytes(&mut junk_bytes);

    let mut handshake_packet = Vec::with_capacity(2 + junk_len + challenge.to_bytes().len());
    handshake_packet.extend_from_slice(&(junk_len as u16).to_be_bytes());
    handshake_packet.extend_from_slice(&junk_bytes);
    handshake_packet.extend_from_slice(&challenge.to_bytes());

    if let Err(e) = server_stream.write_all(&handshake_packet).await {
        error!("❌ Hidekey: Failed to send ClientChallenge to {}: {}", server_addr, e);
        return;
    }

    // Read server's random junk
    let mut srv_junk_len_buf = [0u8; 2];
    if let Err(e) = server_stream.read_exact(&mut srv_junk_len_buf).await {
        error!("❌ Hidekey: Failed to read ServerJunkLen from {}: {}", server_addr, e);
        return;
    }
    let srv_junk_len = u16::from_be_bytes(srv_junk_len_buf) as usize;
    if srv_junk_len < 16 || srv_junk_len > 128 {
        error!("❌ Hidekey: Invalid ServerJunkLen received: {}", srv_junk_len);
        return;
    }
    let mut srv_junk_bytes = vec![0u8; srv_junk_len];
    if let Err(e) = server_stream.read_exact(&mut srv_junk_bytes).await {
        error!("❌ Hidekey: Failed to read ServerJunk from {}: {}", server_addr, e);
        return;
    }

    let mut resp_buf = [0u8; RESPONSE_SIZE];
    if let Err(e) = server_stream.read_exact(&mut resp_buf).await {
        error!("❌ Hidekey: Failed to read ServerResponse from {}: {}", server_addr, e);
        return;
    }

    let server_response = crate::hidekey::handshake::ServerResponse::from_bytes(&resp_buf);
    let session = match hs.process_response(&server_response) {
        Some(s) => s,
        None => {
            error!("❌ Hidekey: ServerResponse MAC verification FAILED — wrong key or MITM!");
            return;
        }
    };

    debug!("✅ Hidekey: Handshake OK with {} → {}:{}", server_addr, dest_ip, port);

    // ── 4. Send encrypted proxy target ────────────────────────────────────────
    // Format: CMD(0x01=TCP) + PORT(2 BE) + ATYP(1) + ADDR(N)
    let mut target_frame = Vec::new();
    target_frame.push(0x01); // CMD = TCP CONNECT
    target_frame.extend_from_slice(&port.to_be_bytes());
    match dest_ip {
        std::net::IpAddr::V4(ipv4) => {
            target_frame.push(0x01); // ATYP = IPv4
            target_frame.extend_from_slice(&ipv4.octets());
        }
        std::net::IpAddr::V6(ipv6) => {
            target_frame.push(0x04); // ATYP = IPv6
            target_frame.extend_from_slice(&ipv6.octets());
        }
    }

    // Client tx_direction = 0x00 (Client→Server), rx_direction = 0x01 (Server→Client)
    let mut tx_cipher = HideCipher::new(session.tx_key, 0x00);
    let mut rx_cipher = HideCipher::new(session.rx_key, 0x01);

    let target_wire = match tx_cipher.seal(&target_frame) {
        Ok(w) => w,
        Err(e) => {
            error!("❌ Hidekey: Failed to encrypt proxy target frame: {}", e);
            return;
        }
    };

    if let Err(e) = server_stream.write_all(&target_wire).await {
        error!("❌ Hidekey: Failed to send proxy target frame: {}", e);
        return;
    }

    debug!("⚡ Hidekey relay started: {}:{} via {}", dest_ip, port, server_addr);

    // ── 5. Bidirectional relay with Hidekey framing ───────────────────────────
    let (mut tun_reader, mut tun_writer) = tokio::io::split(tun_stream);
    let (mut server_reader, mut server_writer) = server_stream.into_split();

    // TUN → Server: read raw bytes from TUN, encrypt with tx_cipher, send framed
    let upload = tokio::spawn(async move {
        let mut buf = vec![0u8; 16384];
        loop {
            let n = match tun_reader.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let wire = match tx_cipher.seal(&buf[..n]) {
                Ok(w) => w,
                Err(e) => { warn!("Hidekey upload seal failed: {}", e); break; }
            };
            if server_writer.write_all(&wire).await.is_err() { break; }
        }
    });

    // Server → TUN: read framed packets from server, decrypt with rx_cipher, forward to TUN
    let download = tokio::spawn(async move {
        loop {
            // Inline length-prefixed frame read (explicit Vec<u8> fixes Rust 1.87 Linux type inference)
            let frame: Vec<u8> = {
                let mut len_buf = [0u8; 2];
                if server_reader.read_exact(&mut len_buf).await.is_err() { break; }
                let flen = u16::from_be_bytes(len_buf) as usize;
                if flen == 0 { break; }
                let mut fbuf = vec![0u8; flen];
                if server_reader.read_exact(&mut fbuf).await.is_err() { break; }
                fbuf
            };
            let plaintext = match rx_cipher.open(&frame) {
                Some(p) => p,
                None => { warn!("Hidekey download decrypt failed — closing"); break; }
            };
            if tun_writer.write_all(&plaintext).await.is_err() { break; }
        }
    });


    tokio::join!(upload, download);
    debug!("✅ Hidekey relay closed: {}:{}", dest_ip, port);
}

// ── Helper: base64-decode a standard or URL-safe base64 string into 32 bytes ─


fn base64_decode_x25519(s: &str) -> Option<[u8; 32]> {
    use base64::{Engine as _, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD, URL_SAFE, STANDARD_NO_PAD}};
    let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = URL_SAFE_NO_PAD.decode(&cleaned)
        .or_else(|_| URL_SAFE.decode(&cleaned))
        .or_else(|_| STANDARD_NO_PAD.decode(&cleaned))
        .or_else(|_| STANDARD.decode(&cleaned))
        .ok()?;
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    }
}

// ── Helper: hex-decode a string like "a8" or "aabbccdd" into bytes ───────────

fn hex_decode(s: &str) -> Vec<u8> {
    let s = s.trim();
    if s.is_empty() {
        return Vec::new();
    }
    (0..s.len())
        .step_by(2)
        .filter_map(|i| {
            if i + 2 <= s.len() {
                u8::from_str_radix(&s[i..i + 2], 16).ok()
            } else {
                None
            }
        })
        .collect()
}
