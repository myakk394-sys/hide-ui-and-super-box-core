//! # hidekey::udp_obfs
//!
//! UDP obfuscation transport layer for the Hidekey protocol.
//!
//! ## Wire format (on the wire, seen by DPI / ТСПУ)
//!
//! ```text
//! +------------------+----------------------------------------------+-------------------+
//! | XOR header       | ChaCha20-Poly1305 ciphertext                 | Random padding    |
//! | 4 bytes          | 4 (packet_id) + 2 (payload_len) + N + 16tag  | 16..=512 bytes    |
//! +------------------+----------------------------------------------+-------------------+
//! ```
//!
//! ### XOR header (4 bytes, obfuscated)
//!
//! Plaintext layout before XOR:
//!   [0]    = MAGIC (0xHK = 0x48 ^ xor_key[0])  — protocol marker, hidden by XOR
//!   [1]    = version byte (0x01)
//!   [2..4] = ciphertext_len as u16 big-endian   — total encrypted body length
//!
//! The 4-byte XOR key is derived per-session from the master key:
//!   xor_key = BLAKE3_KDF("hidekey-udp-header-xor-v1", master_key)[0..4]
//!
//! ### Encrypted body (ChaCha20-Poly1305)
//!
//! Plaintext inside the cipher:
//!   [0..4]  = packet_id: u32 big-endian  — replay protection + ordering
//!   [4..6]  = payload_len: u16 big-endian — actual data length (hidden from DPI)
//!   [6..]   = payload bytes
//!
//! AAD = XOR-masked header (4 bytes) — binds ciphertext to its header,
//!       prevents header substitution attacks.
//!
//! Nonce (12 bytes):
//!   [0..4]  = packet_id (same as in plaintext, for nonce uniqueness)
//!   [4..8]  = direction_tag: 0x00000001 (client→server) or 0x00000002 (server→client)
//!   [8..12] = first 4 bytes of session tx_key (session-unique material)
//!
//! ### Random padding
//!
//! 16..=512 random bytes appended after the ciphertext.
//! The receiver strips padding using ciphertext_len from the (decrypted) header.
//! Padding size is NOT encoded anywhere in plaintext — it is implicit from
//! UDP datagram length minus (4 + ciphertext_len).

use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, aead::{Aead, KeyInit, Payload}};
use rand::{Rng, RngCore, rngs::OsRng};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Protocol magic byte (plaintext, before XOR masking).
const MAGIC: u8 = 0x48; // 'H' for Hidekey

/// Protocol version.
const VERSION: u8 = 0x01;

/// ChaCha20-Poly1305 authentication tag size.
const TAG_SIZE: usize = 16;

/// Overhead added by encryption: packet_id(4) + payload_len(2) + tag(16).
pub const ENCRYPT_OVERHEAD: usize = 4 + 2 + TAG_SIZE;

/// XOR header size (always 4 bytes).
pub const HEADER_SIZE: usize = 4;

/// Maximum UDP payload we will ever produce (stays under typical MTU 1400).
pub const MAX_UDP_PAYLOAD: usize = 1400;

/// Padding range.
const PAD_MIN: usize = 16;
const PAD_MAX: usize = 512;

/// Direction tags for nonce construction.
pub const DIR_CLIENT_TO_SERVER: u32 = 0x0000_0001;
pub const DIR_SERVER_TO_CLIENT: u32 = 0x0000_0002;

// ── XOR key derivation ────────────────────────────────────────────────────────

/// Derives the 4-byte XOR mask for header obfuscation from the master key.
///
/// Uses BLAKE3 KDF so each server/user gets a unique mask.
/// An attacker who captures one config cannot deobfuscate traffic from
/// a different server that uses a different master key.
pub fn derive_header_xor_key(master_key: &[u8]) -> [u8; 4] {
    let full = blake3::derive_key("hidekey-udp-header-xor-v1", master_key);
    [full[0], full[1], full[2], full[3]]
}

// ── Nonce construction ────────────────────────────────────────────────────────

/// Builds a 12-byte ChaCha20-Poly1305 nonce.
///
/// Layout:
///   [0..4]  = packet_id (big-endian u32)
///   [4..8]  = direction_tag (big-endian u32)
///   [8..12] = first 4 bytes of tx_key (session-unique material)
fn make_nonce(packet_id: u32, direction: u32, tx_key: &[u8; 32]) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[0..4].copy_from_slice(&packet_id.to_be_bytes());
    n[4..8].copy_from_slice(&direction.to_be_bytes());
    n[8..12].copy_from_slice(&tx_key[0..4]);
    n
}

// ── Packet encoder ────────────────────────────────────────────────────────────

/// Encodes a plaintext payload into a wire-ready UDP datagram.
///
/// Uses a stack-allocated buffer to avoid heap allocation on the hot path.
/// Returns the number of bytes written into `out_buf`.
///
/// # Arguments
/// * `payload`    — application data to send (max ~1350 bytes)
/// * `packet_id`  — monotonically increasing counter (replay protection)
/// * `direction`  — `DIR_CLIENT_TO_SERVER` or `DIR_SERVER_TO_CLIENT`
/// * `tx_key`     — 32-byte session encryption key
/// * `xor_key`    — 4-byte header XOR mask (from `derive_header_xor_key`)
/// * `out_buf`    — caller-provided output buffer (must be >= MAX_UDP_PAYLOAD)
///
/// # Returns
/// `Ok(n)` — bytes written into `out_buf[..n]`
/// `Err`   — payload too large or encryption failure
pub fn encode_packet(
    payload: &[u8],
    packet_id: u32,
    direction: u32,
    tx_key: &[u8; 32],
    xor_key: &[u8; 4],
    out_buf: &mut [u8; MAX_UDP_PAYLOAD],
) -> Result<usize, &'static str> {
    // ── 1. Build plaintext for the cipher ────────────────────────────────────
    // Layout: packet_id(4) + payload_len(2) + payload(N)
    let payload_len = payload.len();
    if payload_len > 0xFFFF {
        return Err("payload exceeds u16 max");
    }

    // plaintext lives on the stack
    const PT_HEADER: usize = 6; // packet_id(4) + payload_len(2)
    let pt_len = PT_HEADER + payload_len;
    if pt_len + TAG_SIZE + HEADER_SIZE + PAD_MAX > MAX_UDP_PAYLOAD {
        return Err("payload too large for MTU");
    }

    let mut plaintext = [0u8; MAX_UDP_PAYLOAD];
    plaintext[0..4].copy_from_slice(&packet_id.to_be_bytes());
    plaintext[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
    plaintext[6..6 + payload_len].copy_from_slice(payload);

    // ── 2. Build the XOR-masked header (needed as AAD before encryption) ─────
    let ct_len = pt_len + TAG_SIZE; // ciphertext = plaintext + 16-byte tag
    if ct_len > 0xFFFF {
        return Err("ciphertext length overflows u16");
    }

    let mut header_plain = [0u8; HEADER_SIZE];
    header_plain[0] = MAGIC;
    header_plain[1] = VERSION;
    header_plain[2] = ((ct_len >> 8) & 0xFF) as u8;
    header_plain[3] = (ct_len & 0xFF) as u8;

    let mut header_masked = [0u8; HEADER_SIZE];
    for i in 0..HEADER_SIZE {
        header_masked[i] = header_plain[i] ^ xor_key[i];
    }

    // ── 3. Encrypt plaintext with ChaCha20-Poly1305 ──────────────────────────
    // AAD = masked header — binds ciphertext to its header
    let cipher = ChaCha20Poly1305::new(Key::from_slice(tx_key));
    let nonce_bytes = make_nonce(packet_id, direction, tx_key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload {
            msg: &plaintext[..pt_len],
            aad: &header_masked,
        })
        .map_err(|_| "ChaCha20-Poly1305 encryption failed")?;

    debug_assert_eq!(ciphertext.len(), ct_len);

    // ── 4. Assemble output: header || ciphertext || padding ──────────────────
    let pad_size: usize = OsRng.gen_range(PAD_MIN..=PAD_MAX);
    let total = HEADER_SIZE + ct_len + pad_size;
    if total > MAX_UDP_PAYLOAD {
        // Reduce padding to fit MTU rather than failing
        let pad_size = MAX_UDP_PAYLOAD.saturating_sub(HEADER_SIZE + ct_len);
        let total = HEADER_SIZE + ct_len + pad_size;
        out_buf[0..HEADER_SIZE].copy_from_slice(&header_masked);
        out_buf[HEADER_SIZE..HEADER_SIZE + ct_len].copy_from_slice(&ciphertext);
        OsRng.fill_bytes(&mut out_buf[HEADER_SIZE + ct_len..total]);
        return Ok(total);
    }

    out_buf[0..HEADER_SIZE].copy_from_slice(&header_masked);
    out_buf[HEADER_SIZE..HEADER_SIZE + ct_len].copy_from_slice(&ciphertext);
    OsRng.fill_bytes(&mut out_buf[HEADER_SIZE + ct_len..total]);

    Ok(total)
}

// ── Packet decoder ────────────────────────────────────────────────────────────

/// Result of a successful `decode_packet` call.
pub struct DecodedPacket {
    /// Monotonically increasing counter from the sender (replay / ordering).
    pub packet_id: u32,
    /// Actual application payload bytes.
    pub payload: bytes::Bytes,
}

/// Decodes and authenticates a received UDP datagram.
///
/// Strips XOR masking, verifies the ChaCha20-Poly1305 tag, and returns
/// the inner payload. Padding is discarded automatically — the receiver
/// reads `ciphertext_len` from the header and ignores everything after.
///
/// # Arguments
/// * `datagram`   — raw bytes received from the UDP socket
/// * `direction`  — expected direction tag (use the *sender's* direction)
/// * `rx_key`     — 32-byte session decryption key
/// * `xor_key`    — 4-byte header XOR mask (same as encoder)
///
/// # Returns
/// `Ok(DecodedPacket)` on success, `Err(&str)` on any validation failure.
/// All errors are intentionally opaque — the caller should silently drop
/// the datagram (no error response to sender).
pub fn decode_packet(
    datagram: &[u8],
    direction: u32,
    rx_key: &[u8; 32],
    xor_key: &[u8; 4],
) -> Result<DecodedPacket, &'static str> {
    if datagram.len() < HEADER_SIZE + ENCRYPT_OVERHEAD {
        return Err("datagram too short");
    }

    // ── 1. Deobfuscate header ─────────────────────────────────────────────────
    let mut header_plain = [0u8; HEADER_SIZE];
    for i in 0..HEADER_SIZE {
        header_plain[i] = datagram[i] ^ xor_key[i];
    }

    if header_plain[0] != MAGIC {
        return Err("bad magic");
    }
    if header_plain[1] != VERSION {
        return Err("unsupported version");
    }

    let ct_len = ((header_plain[2] as usize) << 8) | (header_plain[3] as usize);
    if ct_len < ENCRYPT_OVERHEAD {
        return Err("ciphertext_len too small");
    }
    if HEADER_SIZE + ct_len > datagram.len() {
        return Err("datagram shorter than declared ciphertext_len");
    }

    // ── 2. Decrypt ────────────────────────────────────────────────────────────
    // We need the packet_id from the ciphertext to build the nonce, but it's
    // encrypted. Solution: try decryption with packet_id=0 first? No —
    // instead we embed packet_id in the nonce using the *ciphertext* first 4
    // bytes XOR'd with a known constant, then verify via AEAD tag.
    //
    // Better approach: packet_id is also the first 4 bytes of the *plaintext*,
    // so we derive the nonce from the ciphertext prefix (first 4 bytes of ct
    // before the tag). This is safe because the tag covers the entire plaintext.
    //
    // We use the first 4 bytes of the ciphertext as a "nonce hint" — they are
    // the encrypted packet_id and are unique per packet.
    let ct_slice = &datagram[HEADER_SIZE..HEADER_SIZE + ct_len];
    let header_masked = &datagram[0..HEADER_SIZE];

    // Extract nonce hint: first 4 bytes of ciphertext (encrypted packet_id).
    // XOR with rx_key[0..4] to get a stable nonce prefix without decrypting.
    let mut nonce_hint = [0u8; 4];
    nonce_hint.copy_from_slice(&ct_slice[0..4]);
    for i in 0..4 {
        nonce_hint[i] ^= rx_key[i];
    }
    let hint_id = u32::from_be_bytes(nonce_hint);

    let nonce_bytes = make_nonce(hint_id, direction, rx_key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(rx_key));
    let plaintext = cipher
        .decrypt(nonce, Payload { msg: ct_slice, aad: header_masked })
        .map_err(|_| "AEAD authentication failed")?;

    if plaintext.len() < 6 {
        return Err("plaintext too short");
    }

    // ── 3. Parse inner plaintext ──────────────────────────────────────────────
    let packet_id = u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
    let payload_len = u16::from_be_bytes([plaintext[4], plaintext[5]]) as usize;

    if 6 + payload_len > plaintext.len() {
        return Err("payload_len exceeds plaintext bounds");
    }

    let payload = bytes::Bytes::copy_from_slice(&plaintext[6..6 + payload_len]);

    Ok(DecodedPacket { packet_id, payload })
}

// ── Session state ─────────────────────────────────────────────────────────────

/// Per-direction packet counter for a UDP session.
///
/// Tracks the outgoing `packet_id` counter and detects replayed/reordered
/// incoming packets using a 64-bit sliding window bitmask.
pub struct UdpSessionCounter {
    /// Next packet_id to use for outgoing packets.
    pub tx_counter: u32,
    /// Highest packet_id seen from the remote peer.
    rx_highest: u32,
    /// 64-bit sliding window: bit N set = packet (rx_highest - N) was received.
    rx_window: u64,
}

impl UdpSessionCounter {
    pub fn new() -> Self {
        Self { tx_counter: 0, rx_highest: 0, rx_window: 0 }
    }

    /// Returns the next outgoing packet_id and increments the counter.
    pub fn next_tx_id(&mut self) -> u32 {
        let id = self.tx_counter;
        self.tx_counter = self.tx_counter.wrapping_add(1);
        id
    }

    /// Checks whether an incoming `packet_id` is fresh (not a replay).
    /// Updates the sliding window if accepted.
    ///
    /// Returns `true` if the packet should be processed, `false` if it
    /// should be silently dropped (replay or too old).
    pub fn accept_rx(&mut self, packet_id: u32) -> bool {
        const WINDOW: u32 = 64;

        if packet_id > self.rx_highest {
            // New highest — shift window
            let shift = packet_id.wrapping_sub(self.rx_highest);
            if shift >= WINDOW {
                self.rx_window = 1; // all old entries expire
            } else {
                self.rx_window = (self.rx_window << shift) | 1;
            }
            self.rx_highest = packet_id;
            return true;
        }

        let diff = self.rx_highest.wrapping_sub(packet_id);
        if diff >= WINDOW {
            return false; // too old
        }

        let bit = 1u64 << diff;
        if self.rx_window & bit != 0 {
            return false; // replay
        }
        self.rx_window |= bit;
        true
    }
}
