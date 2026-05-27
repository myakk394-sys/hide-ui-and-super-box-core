//! # hidekey::framing
//!
//! Length-prefixed TCP frame helpers for the Hidekey encrypted protocol.
//!
//! ## Wire format per packet
//!
//! ```text
//! [2-byte big-endian length] [RTP header: 12 bytes] [ChaCha20-Poly1305 ciphertext + 16-byte Poly1305 tag]
//! ```

use tokio::io::AsyncReadExt;

/// Wraps a Hidekey RTP packet with a 2-byte length prefix for TCP framing.
pub fn length_prefix(packet: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + packet.len());
    let len = packet.len() as u16;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(packet);
    out
}

/// Reads exactly one length-prefixed frame from a TCP stream asynchronously.
/// Returns the raw RTP packet bytes (without the 2-byte prefix) as `Vec<u8>`.
pub async fn read_frame<R>(reader: &mut R) -> tokio::io::Result<Vec<u8>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 {
        return Err(tokio::io::Error::new(
            tokio::io::ErrorKind::InvalidData,
            "Hidekey frame length is zero",
        ));
    }
    let mut buf: Vec<u8> = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}
