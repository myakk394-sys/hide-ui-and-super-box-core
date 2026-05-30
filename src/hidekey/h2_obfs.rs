//! # hidekey::h2_obfs
//!
//! HTTP/2 obfuscation layer for Hidekey protocol.
//!
//! Wraps a TLS stream in a minimal HTTP/2 framing layer so that L7 DPI sees
//! a legitimate HTTP/2 session (RFC 7540).  All Hidekey payload bytes are
//! transported inside HTTP/2 DATA frames on stream-id 1.
//!
//! ## Wire layout seen by DPI
//!
//! Client → Server:
//!   1. HTTP/2 Connection Preface (24 bytes)
//!   2. SETTINGS frame  (client settings)
//!   3. HEADERS frame   (fake POST /api/v1/stream)
//!   4. DATA frames     (Hidekey payload, arbitrary length)
//!
//! Server → Client:
//!   1. SETTINGS frame  (server settings)
//!   2. SETTINGS ACK    (acknowledges client SETTINGS)
//!   3. HEADERS frame   (fake 200 OK)
//!   4. DATA frames     (Hidekey payload, arbitrary length)
//!
//! ## HTTP/2 frame format (RFC 7540 §4.1)
//!
//!   +-----------------------------------------------+
//!   |                 Length (24)                   |
//!   +---------------+---------------+---------------+
//!   |   Type (8)    |   Flags (8)   |
//!   +-+-------------+---------------+-------------------------------+
//!   |R|                 Stream Identifier (31)                      |
//!   +=+=============================================================+
//!   |                   Frame Payload (0...)                      ...
//!   +---------------------------------------------------------------+
//!
//! Frame types used:
//!   0x00  DATA     — carries Hidekey payload
//!   0x01  HEADERS  — fake request/response headers (HPACK-encoded)
//!   0x04  SETTINGS — connection parameters
//!
//! Flags:
//!   0x01  END_STREAM  (DATA / HEADERS)
//!   0x04  END_HEADERS (HEADERS)
//!   0x01  ACK         (SETTINGS)

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

// ── Combined AsyncRead+AsyncWrite supertrait ──────────────────────────────────
//
// Rust does not allow `Box<dyn AsyncRead + AsyncWrite>` directly (E0225).
// We define a combined supertrait so callers can use `Box<dyn AsyncStream>`.

pub trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncStream for T {}

// ── Constants ─────────────────────────────────────────────────────────────────

/// HTTP/2 Connection Preface sent by the client (RFC 7540 §3.5)
pub const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_HEADER_SIZE: usize = 9;

// Frame types
const FRAME_DATA:     u8 = 0x00;
const FRAME_HEADERS:  u8 = 0x01;
const FRAME_SETTINGS: u8 = 0x04;

// Flags
const FLAG_END_HEADERS: u8 = 0x04;
const FLAG_ACK:         u8 = 0x01;

// ── Frame builder helpers ─────────────────────────────────────────────────────

/// Builds a raw HTTP/2 frame.
fn build_frame(frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) -> Vec<u8> {
    let len = payload.len();
    let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + len);
    // 3-byte length
    frame.push(((len >> 16) & 0xff) as u8);
    frame.push(((len >>  8) & 0xff) as u8);
    frame.push(( len        & 0xff) as u8);
    frame.push(frame_type);
    frame.push(flags);
    // 4-byte stream id (R bit always 0)
    frame.push(((stream_id >> 24) & 0x7f) as u8);
    frame.push(((stream_id >> 16) & 0xff) as u8);
    frame.push(((stream_id >>  8) & 0xff) as u8);
    frame.push(( stream_id        & 0xff) as u8);
    frame.extend_from_slice(payload);
    frame
}

/// Builds a SETTINGS frame.  `settings` is a list of (id, value) pairs.
fn build_settings_frame(settings: &[(u16, u32)], ack: bool) -> Vec<u8> {
    if ack {
        return build_frame(FRAME_SETTINGS, FLAG_ACK, 0, &[]);
    }
    let mut payload = Vec::with_capacity(settings.len() * 6);
    for &(id, val) in settings {
        payload.push(((id >> 8) & 0xff) as u8);
        payload.push(( id       & 0xff) as u8);
        payload.push(((val >> 24) & 0xff) as u8);
        payload.push(((val >> 16) & 0xff) as u8);
        payload.push(((val >>  8) & 0xff) as u8);
        payload.push(( val        & 0xff) as u8);
    }
    build_frame(FRAME_SETTINGS, 0, 0, &payload)
}

/// Builds a minimal HPACK-encoded HEADERS frame that looks like a Chrome POST.
///
/// We use literal header field without indexing (HPACK §6.2.2) for all fields
/// so the header block is self-contained and requires no dynamic table state.
fn build_client_headers_frame(stream_id: u32) -> Vec<u8> {
    // HPACK literal without indexing: 0x00 | name_len | name | value_len | value
    let headers: &[(&[u8], &[u8])] = &[
        (b":method",    b"POST"),
        (b":path",      b"/api/v1/stream"),
        (b":scheme",    b"https"),
        (b":authority", b"update.googleapis.com"),
        (b"content-type",    b"application/grpc"),
        (b"user-agent",      b"grpc-go/1.59.0"),
        (b"te",              b"trailers"),
    ];
    let mut block = Vec::new();
    for &(name, value) in headers {
        block.push(0x00); // literal, no indexing, new name
        block.push(name.len() as u8);
        block.extend_from_slice(name);
        block.push(value.len() as u8);
        block.extend_from_slice(value);
    }
    build_frame(FRAME_HEADERS, FLAG_END_HEADERS, stream_id, &block)
}

/// Builds a minimal HPACK-encoded HEADERS frame that looks like a 200 OK response.
fn build_server_headers_frame(stream_id: u32) -> Vec<u8> {
    let headers: &[(&[u8], &[u8])] = &[
        (b":status",      b"200"),
        (b"content-type", b"application/grpc"),
        (b"server",       b"Google Frontend"),
    ];
    let mut block = Vec::new();
    for &(name, value) in headers {
        block.push(0x00);
        block.push(name.len() as u8);
        block.extend_from_slice(name);
        block.push(value.len() as u8);
        block.extend_from_slice(value);
    }
    build_frame(FRAME_HEADERS, FLAG_END_HEADERS, stream_id, &block)
}

/// Wraps `payload` in an HTTP/2 DATA frame on `stream_id`.
pub fn build_data_frame(stream_id: u32, payload: &[u8]) -> Vec<u8> {
    build_frame(FRAME_DATA, 0, stream_id, payload)
}

// ── Chrome-like client SETTINGS ───────────────────────────────────────────────
//
// Matches Chrome 120 SETTINGS frame captured in the wild:
//   HEADER_TABLE_SIZE      = 65536
//   ENABLE_PUSH            = 0
//   INITIAL_WINDOW_SIZE    = 6291456
//   MAX_HEADER_LIST_SIZE   = 262144

fn chrome_client_settings() -> Vec<u8> {
    build_settings_frame(&[
        (0x0001, 65536),    // HEADER_TABLE_SIZE
        (0x0002, 0),        // ENABLE_PUSH = 0
        (0x0004, 6291456),  // INITIAL_WINDOW_SIZE
        (0x0006, 262144),   // MAX_HEADER_LIST_SIZE
    ], false)
}

/// Server SETTINGS — raised MAX_FRAME_SIZE to 1MB for high-throughput relay.
/// Default 16384 means one syscall per 16KB; 1MB means one syscall per 1MB.
fn server_settings() -> Vec<u8> {
    build_settings_frame(&[
        (0x0003, 100),        // MAX_CONCURRENT_STREAMS
        (0x0004, 16_777_215), // INITIAL_WINDOW_SIZE = max (prevents flow-control stalls)
        (0x0005, 1_048_576),  // MAX_FRAME_SIZE = 1MB
    ], false)
}

// ── Handshake ─────────────────────────────────────────────────────────────────

/// Performs the client-side HTTP/2 handshake over an already-established TLS stream.
///
/// After this returns the stream is ready for `send_data` / `recv_data`.
pub async fn client_handshake<S>(stream: &mut S) -> tokio::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Send HTTP/2 Connection Preface
    stream.write_all(H2_PREFACE).await?;

    // 2. Send client SETTINGS
    stream.write_all(&chrome_client_settings()).await?;

    // 3. Send fake HEADERS (POST /api/v1/stream)
    stream.write_all(&build_client_headers_frame(1)).await?;
    stream.flush().await?;

    // 4. Read server SETTINGS
    read_frame_type(stream, FRAME_SETTINGS).await?;

    // 5. Read server SETTINGS ACK (or HEADERS — server may reorder)
    read_any_frame_until_headers(stream).await?;

    Ok(())
}

/// Performs the server-side HTTP/2 handshake over an already-established TLS stream.
pub async fn server_handshake<S>(stream: &mut S) -> tokio::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // 1. Read and verify HTTP/2 Connection Preface
    let mut preface = [0u8; 24];
    stream.read_exact(&mut preface).await?;
    if &preface != H2_PREFACE {
        return Err(tokio::io::Error::new(
            tokio::io::ErrorKind::InvalidData,
            "H2: invalid connection preface",
        ));
    }

    // 2. Read client SETTINGS
    read_frame_type(stream, FRAME_SETTINGS).await?;

    // 3. Read client HEADERS
    read_frame_type(stream, FRAME_HEADERS).await?;

    // 4. Send server SETTINGS
    stream.write_all(&server_settings()).await?;

    // 5. Send SETTINGS ACK
    stream.write_all(&build_settings_frame(&[], true)).await?;

    // 6. Send fake 200 OK HEADERS
    stream.write_all(&build_server_headers_frame(1)).await?;
    stream.flush().await?;

    Ok(())
}

// ── Data I/O ──────────────────────────────────────────────────────────────────

/// Sends `data` as one or more HTTP/2 DATA frames on stream-id 1.
///
/// ## Performance notes
///
/// - Frames are batched into a single `write_all` call to avoid per-frame
///   syscall overhead. `flush()` is called only once at the end.
/// - MAX_FRAME_PAYLOAD is raised to 1MB to match the server SETTINGS above.
///   This means large payloads (video, bulk transfer) go out in one frame
///   instead of being split into 64 × 16KB frames.
pub async fn send_data<S>(stream: &mut S, data: &[u8]) -> tokio::io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    const MAX_FRAME_PAYLOAD: usize = 1_048_576; // 1MB — matches server SETTINGS

    if data.len() <= MAX_FRAME_PAYLOAD {
        // Fast path: single frame, single write_all, single flush
        let mut frame = Vec::with_capacity(FRAME_HEADER_SIZE + data.len());
        let len = data.len();
        frame.push(((len >> 16) & 0xff) as u8);
        frame.push(((len >>  8) & 0xff) as u8);
        frame.push(( len        & 0xff) as u8);
        frame.push(FRAME_DATA);
        frame.push(0); // flags
        frame.push(0); frame.push(0); frame.push(0); frame.push(1); // stream_id = 1
        frame.extend_from_slice(data);
        stream.write_all(&frame).await?;
    } else {
        // Slow path: chunk into multiple frames, batch into one allocation
        let num_frames = (data.len() + MAX_FRAME_PAYLOAD - 1) / MAX_FRAME_PAYLOAD;
        let total_size = data.len() + num_frames * FRAME_HEADER_SIZE;
        let mut batch = Vec::with_capacity(total_size);
        let mut offset = 0;
        while offset < data.len() {
            let end = (offset + MAX_FRAME_PAYLOAD).min(data.len());
            let chunk = &data[offset..end];
            let len = chunk.len();
            batch.push(((len >> 16) & 0xff) as u8);
            batch.push(((len >>  8) & 0xff) as u8);
            batch.push(( len        & 0xff) as u8);
            batch.push(FRAME_DATA);
            batch.push(0);
            batch.push(0); batch.push(0); batch.push(0); batch.push(1);
            batch.extend_from_slice(chunk);
            offset = end;
        }
        stream.write_all(&batch).await?;
    }

    // Без implicit flush — вызывающий код решает когда делать flush.
    // Это позволяет батчить несколько send_data в один TLS-рекорд,
    // что критически важно для пропускной способности.
    Ok(())
}

/// Reads exactly one HTTP/2 DATA frame from stream-id 1 and returns its payload.
///
/// Non-DATA frames (SETTINGS, PING, WINDOW_UPDATE) are silently consumed.
/// Returns `Ok(None)` on clean EOF.
///
/// ## Performance notes
///
/// Uses a stack-allocated 9-byte header buffer. The payload Vec is allocated
/// once per DATA frame — unavoidable since the caller owns the data. For the
/// common case (one DATA frame per Hidekey packet) this is one allocation per
/// network round-trip, which is acceptable.
pub async fn recv_data<S>(stream: &mut S) -> tokio::io::Result<Option<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    loop {
        // Stack-allocated header — no heap allocation for non-DATA frames
        let mut header = [0u8; FRAME_HEADER_SIZE];
        match stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(e) if e.kind() == tokio::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(e) => return Err(e),
        }

        let length = ((header[0] as usize) << 16)
            | ((header[1] as usize) << 8)
            |  (header[2] as usize);
        let frame_type = header[3];

        if length > 16_777_215 {
            return Err(tokio::io::Error::new(
                tokio::io::ErrorKind::InvalidData,
                "H2: frame length exceeds maximum",
            ));
        }

        if frame_type == FRAME_DATA {
            // Only allocate for DATA frames — the common case
            let mut payload = vec![0u8; length];
            if length > 0 {
                stream.read_exact(&mut payload).await?;
            }
            return Ok(Some(payload));
        }

        // Non-DATA frame: drain without allocating when possible
        if length > 0 {
            // For small control frames use stack buffer; for large ones allocate
            if length <= 256 {
                let mut discard = [0u8; 256];
                stream.read_exact(&mut discard[..length]).await?;
            } else {
                let mut discard = vec![0u8; length];
                stream.read_exact(&mut discard).await?;
            }
        }
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Reads frames until one with the expected type is found.  Others are discarded.
async fn read_frame_type<S>(stream: &mut S, expected: u8) -> tokio::io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    loop {
        let mut header = [0u8; FRAME_HEADER_SIZE];
        stream.read_exact(&mut header).await?;
        let length = ((header[0] as usize) << 16)
            | ((header[1] as usize) << 8)
            |  (header[2] as usize);
        let frame_type = header[3];
        let mut payload = vec![0u8; length];
        if length > 0 { stream.read_exact(&mut payload).await?; }
        if frame_type == expected { return Ok(payload); }
    }
}

/// Reads frames until the server's fake HEADERS frame is found and consumed.
/// The server sends: SETTINGS, SETTINGS_ACK, then HEADERS(stream_id=1).
/// All frames must be consumed before starting the real H2 session, otherwise
/// the leftover HEADERS(stream_id=1) confuses the real H2 client library
/// (which throws PROTOCOL_ERROR: "cannot open stream — not server initiated").
async fn read_any_frame_until_headers<S>(stream: &mut S) -> tokio::io::Result<()>
where
    S: AsyncRead + Unpin,
{
    loop {
        let mut header = [0u8; FRAME_HEADER_SIZE];
        stream.read_exact(&mut header).await?;
        let length = ((header[0] as usize) << 16)
            | ((header[1] as usize) << 8)
            |  (header[2] as usize);
        let frame_type = header[3];
        let mut payload = vec![0u8; length];
        if length > 0 { stream.read_exact(&mut payload).await?; }
        // Stop ONLY when we see HEADERS — consume everything else (SETTINGS, SETTINGS_ACK, etc.)
        // The server sends SETTINGS → SETTINGS_ACK → HEADERS in that order.
        // We MUST read and discard all frames until HEADERS to leave the stream clean.
        if frame_type == FRAME_HEADERS { return Ok(()); }
    }
}
