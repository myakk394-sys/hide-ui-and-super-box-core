use rand::Rng;

pub const RTP_HEADER_SIZE: usize = 12;

/// Structure representing a standard RTP v2 Header (RFC 3550)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtpHeader {
    pub version: u8,         // 2 bits, always 2
    pub padding: bool,       // 1 bit
    pub extension: bool,     // 1 bit
    pub csrc_count: u8,      // 4 bits
    pub marker: bool,        // 1 bit
    pub payload_type: u8,    // 7 bits (e.g., 111 for Opus/WebRTC)
    pub seq_number: u16,     // 16 bits
    pub timestamp: u32,      // 32 bits
    pub ssrc: u32,           // 32 bits
}

impl RtpHeader {
    /// Creates a new RTP header with sensible defaults (Opus-like stream)
    pub fn new(seq_number: u16, timestamp: u32, ssrc: u32) -> Self {
        Self {
            version: 2,
            padding: false,
            extension: false,
            csrc_count: 0,
            marker: false,
            payload_type: 111, // Typical dynamic payload type for Opus/WebRTC audio
            seq_number,
            timestamp,
            ssrc,
        }
    }

    /// Serializes the RTP header into a 12-byte buffer.
    pub fn serialize(&self, buf: &mut [u8; RTP_HEADER_SIZE]) {
        // Byte 0: V=2 (2 bits) | P (1 bit) | X (1 bit) | CC (4 bits)
        let mut b0 = (self.version & 0x03) << 6;
        if self.padding { b0 |= 0x20; }
        if self.extension { b0 |= 0x10; }
        b0 |= self.csrc_count & 0x0F;
        buf[0] = b0;

        // Byte 1: M (1 bit) | PT (7 bits)
        let mut b1 = (self.payload_type & 0x7F) as u8;
        if self.marker { b1 |= 0x80; }
        buf[1] = b1;

        // Bytes 2-3: Sequence Number
        buf[2..4].copy_from_slice(&self.seq_number.to_be_bytes());

        // Bytes 4-7: Timestamp
        buf[4..8].copy_from_slice(&self.timestamp.to_be_bytes());

        // Bytes 8-11: SSRC
        buf[8..12].copy_from_slice(&self.ssrc.to_be_bytes());
    }

    /// Deserializes the RTP header from a 12-byte buffer.
    pub fn deserialize(buf: &[u8; RTP_HEADER_SIZE]) -> Self {
        let b0 = buf[0];
        let version = (b0 >> 6) & 0x03;
        let padding = (b0 & 0x20) != 0;
        let extension = (b0 & 0x10) != 0;
        let csrc_count = b0 & 0x0F;

        let b1 = buf[1];
        let marker = (b1 & 0x80) != 0;
        let payload_type = b1 & 0x7F;

        let mut seq_bytes = [0u8; 2];
        seq_bytes.copy_from_slice(&buf[2..4]);
        let seq_number = u16::from_be_bytes(seq_bytes);

        let mut ts_bytes = [0u8; 4];
        ts_bytes.copy_from_slice(&buf[4..8]);
        let timestamp = u32::from_be_bytes(ts_bytes);

        let mut ssrc_bytes = [0u8; 4];
        ssrc_bytes.copy_from_slice(&buf[8..12]);
        let ssrc = u32::from_be_bytes(ssrc_bytes);

        Self {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            seq_number,
            timestamp,
            ssrc,
        }
    }
}

/// Tracks the active RTP state for an outgoing media stream session
pub struct RtpSessionState {
    pub seq_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    timestamp_increment: u32,
}

impl RtpSessionState {
    /// Creates a new RTP state with randomized SSRC, sequence number, and timestamp.
    pub fn new() -> Self {
        let mut rng = rand::thread_rng();
        Self {
            seq_number: rng.gen(),
            timestamp: rng.gen(),
            ssrc: rng.gen(),
            timestamp_increment: 960, // 20ms of audio at 48kHz (standard Opus)
        }
    }

    /// Packs a Hidekey payload into an RTP packet.
    /// Returns the RTP header bytes prepended to the payload.
    pub fn pack(&mut self, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; RTP_HEADER_SIZE + payload.len()];
        
        let header = RtpHeader::new(self.seq_number, self.timestamp, self.ssrc);
        let mut header_buf = [0u8; RTP_HEADER_SIZE];
        header.serialize(&mut header_buf);
        
        packet[0..RTP_HEADER_SIZE].copy_from_slice(&header_buf);
        packet[RTP_HEADER_SIZE..].copy_from_slice(payload);

        // Increment sequence and timestamp for the next packet
        self.seq_number = self.seq_number.wrapping_add(1);
        self.timestamp = self.timestamp.wrapping_add(self.timestamp_increment);

        packet
    }
}

/// Unpacks a received RTP packet.
/// Verifies the RTP header format and returns the underlying Hidekey payload.
/// If the packet is not valid RTP (e.g. incorrect version), returns None.
pub fn unpack_rtp(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() < RTP_HEADER_SIZE {
        return None;
    }

    let mut header_buf = [0u8; RTP_HEADER_SIZE];
    header_buf.copy_from_slice(&packet[0..RTP_HEADER_SIZE]);
    let header = RtpHeader::deserialize(&header_buf);

    // Validate that this is indeed an RTP v2 packet
    if header.version != 2 {
        return None;
    }

    // Return the payload (everything after the 12-byte header)
    Some(packet[RTP_HEADER_SIZE..].to_vec())
}
