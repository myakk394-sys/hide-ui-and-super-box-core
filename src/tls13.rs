use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha384};
use thiserror::Error;
use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305, Nonce, Aad};

#[derive(Error, Debug)]
pub enum TlsError {
    #[error("Invalid TLS record")]
    InvalidRecord,
    #[error("Invalid Handshake")]
    InvalidHandshake,
    #[error("Missing KeyShare")]
    MissingKeyShare,
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8], is_384: bool) -> Vec<u8> {
    if is_384 {
        let mut mac = <Hmac<Sha384> as hmac::digest::KeyInit>::new_from_slice(salt).unwrap();
        mac.update(ikm);
        mac.finalize().into_bytes().to_vec()
    } else {
        let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(salt).unwrap();
        mac.update(ikm);
        mac.finalize().into_bytes().to_vec()
    }
}

pub fn hkdf_expand_label(secret: &[u8], label: &str, context: &[u8], length: u16, is_384: bool) -> Vec<u8> {
    let mut hkdf_label = Vec::new();
    hkdf_label.extend_from_slice(&length.to_be_bytes());
    let full_label = format!("tls13 {}", label);
    hkdf_label.push(full_label.len() as u8);
    hkdf_label.extend_from_slice(full_label.as_bytes());
    hkdf_label.push(context.len() as u8);
    hkdf_label.extend_from_slice(context);

    if is_384 {
        let mut mac = <Hmac<Sha384> as hmac::digest::KeyInit>::new_from_slice(secret).unwrap();
        mac.update(&hkdf_label);
        mac.update(&[0x01]);
        let mut out = mac.finalize().into_bytes().to_vec();
        out.truncate(length as usize);
        out
    } else {
        let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(secret).unwrap();
        mac.update(&hkdf_label);
        mac.update(&[0x01]);
        let mut out = mac.finalize().into_bytes().to_vec();
        out.truncate(length as usize);
        out
    }
}

pub fn derive_key(secret: &[u8], is_384: bool, key_len: u16) -> Vec<u8> {
    hkdf_expand_label(secret, "key", &[], key_len, is_384)
}

pub fn derive_iv(secret: &[u8], is_384: bool) -> [u8; 12] {
    let iv = hkdf_expand_label(secret, "iv", &[], 12, is_384);
    let mut out = [0u8; 12];
    out.copy_from_slice(&iv);
    out
}

pub struct Tls13State {
    pub handshake_secret: Vec<u8>,
    pub client_handshake_secret: Vec<u8>,
    pub server_handshake_secret: Vec<u8>,
    pub client_app_secret: Vec<u8>,
    pub server_app_secret: Vec<u8>,
    pub cipher_suite: u16,
}

impl Tls13State {
    pub fn new(shared_secret: &[u8; 32], hello_hash: &[u8], cipher_suite: u16) -> Self {
        let is_384 = cipher_suite == 0x1302;
        let empty_hash = if is_384 { Sha384::digest(b"").to_vec() } else { Sha256::digest(b"").to_vec() };
        let zero_salt = vec![0u8; if is_384 { 48 } else { 32 }];
        
        let early_secret = hkdf_extract(&zero_salt, &zero_salt, is_384);
        let derived_early = hkdf_expand_label(&early_secret, "derived", &empty_hash, if is_384 { 48 } else { 32 }, is_384);
        let handshake_secret = hkdf_extract(&derived_early, shared_secret, is_384);
        
        let client_hs = hkdf_expand_label(&handshake_secret, "c hs traffic", hello_hash, if is_384 { 48 } else { 32 }, is_384);
        let server_hs = hkdf_expand_label(&handshake_secret, "s hs traffic", hello_hash, if is_384 { 48 } else { 32 }, is_384);
        
        Self {
            handshake_secret,
            client_handshake_secret: client_hs,
            server_handshake_secret: server_hs,
            client_app_secret: Vec::new(),
            server_app_secret: Vec::new(),
            cipher_suite,
        }
    }

    pub fn compute_finished_verify_data(&self, secret: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
        let is_384 = self.cipher_suite == 0x1302;
        let finished_key = hkdf_expand_label(secret, "finished", &[], if is_384 { 48 } else { 32 }, is_384);
        if is_384 {
            let mut mac = <Hmac<Sha384> as hmac::digest::KeyInit>::new_from_slice(&finished_key).unwrap();
            mac.update(transcript_hash);
            mac.finalize().into_bytes().to_vec()
        } else {
            let mut mac = <Hmac<Sha256> as hmac::digest::KeyInit>::new_from_slice(&finished_key).unwrap();
            mac.update(transcript_hash);
            mac.finalize().into_bytes().to_vec()
        }
    }

    pub fn derive_app_secrets(&mut self, transcript_hash: &[u8]) {
        let is_384 = self.cipher_suite == 0x1302;
        let empty_hash = if is_384 { Sha384::digest(b"").to_vec() } else { Sha256::digest(b"").to_vec() };
        let derived_hs = hkdf_expand_label(&self.handshake_secret, "derived", &empty_hash, if is_384 { 48 } else { 32 }, is_384);
        let zero_salt = vec![0u8; if is_384 { 48 } else { 32 }];
        let master_secret = hkdf_extract(&derived_hs, &zero_salt, is_384);
        
        let client_app = hkdf_expand_label(&master_secret, "c ap traffic", transcript_hash, if is_384 { 48 } else { 32 }, is_384);
        let server_app = hkdf_expand_label(&master_secret, "s ap traffic", transcript_hash, if is_384 { 48 } else { 32 }, is_384);
        self.client_app_secret = client_app;
        self.server_app_secret = server_app;
    }
}

pub enum TlsCipher {
    Aes128Gcm(LessSafeKey),
    Aes256Gcm(LessSafeKey),
    ChaCha20(LessSafeKey),
}

impl TlsCipher {
    pub fn new(cipher_suite: u16, secret: &[u8]) -> Result<(Self, [u8; 12]), TlsError> {
        let is_384 = cipher_suite == 0x1302;
        let iv = derive_iv(secret, is_384);
        match cipher_suite {
            0x1301 => {
                let key = derive_key(secret, is_384, 16);
                let unbound = UnboundKey::new(&AES_128_GCM, &key)
                    .map_err(|_| TlsError::CryptoError("Failed to create AES-128 key".into()))?;
                Ok((TlsCipher::Aes128Gcm(LessSafeKey::new(unbound)), iv))
            }
            0x1302 => {
                let key = derive_key(secret, is_384, 32);
                let unbound = UnboundKey::new(&AES_256_GCM, &key)
                    .map_err(|_| TlsError::CryptoError("Failed to create AES-256 key".into()))?;
                Ok((TlsCipher::Aes256Gcm(LessSafeKey::new(unbound)), iv))
            }
            0x1303 => {
                let key = derive_key(secret, is_384, 32);
                let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key)
                    .map_err(|_| TlsError::CryptoError("Failed to create ChaCha20 key".into()))?;
                Ok((TlsCipher::ChaCha20(LessSafeKey::new(unbound)), iv))
            }
            _ => Err(TlsError::CryptoError(format!("Unsupported cipher suite: 0x{:04x}", cipher_suite))),
        }
    }
}

pub struct ZeroCopyTlsEncrypter {
    cipher: TlsCipher,
    iv: [u8; 12],
    pub seq: u64,
}

impl ZeroCopyTlsEncrypter {
    pub fn new(secret: &[u8], cipher_suite: u16) -> Result<Self, TlsError> {
        let (cipher, iv) = TlsCipher::new(cipher_suite, secret)?;
        Ok(Self { cipher, iv, seq: 0 })
    }
    
    pub fn encrypt_in_place(&mut self, payload: &mut [u8], content_len: usize) -> Result<usize, TlsError> {
        let tag_len = 16;
        let header_len = 5;
        let record_payload_len = content_len + tag_len;
        
        if payload.len() < header_len + record_payload_len {
            return Err(TlsError::CryptoError("Buffer too small".into()));
        }

        payload[0] = 0x17; // type
        payload[1] = 0x03; // version
        payload[2] = 0x03; // version
        payload[3] = (record_payload_len >> 8) as u8;
        payload[4] = (record_payload_len & 0xff) as u8;

        let (header, rest) = payload.split_at_mut(5);
        let aad = Aad::from(&*header);

        let mut nonce_bytes = self.iv;
        let seq_bytes = self.seq.to_be_bytes();
        for i in 0..8 {
            nonce_bytes[4 + i] ^= seq_bytes[i];
        }
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let plaintext_slice = &mut rest[0..content_len];
        
        let tag = match &self.cipher {
            TlsCipher::Aes128Gcm(c) => {
                c.seal_in_place_separate_tag(nonce, aad, plaintext_slice)
                    .map_err(|e| TlsError::CryptoError(format!("Encryption failed: {:?}", e)))?
            }
            TlsCipher::Aes256Gcm(c) => {
                c.seal_in_place_separate_tag(nonce, aad, plaintext_slice)
                    .map_err(|e| TlsError::CryptoError(format!("Encryption failed: {:?}", e)))?
            }
            TlsCipher::ChaCha20(c) => {
                c.seal_in_place_separate_tag(nonce, aad, plaintext_slice)
                    .map_err(|e| TlsError::CryptoError(format!("Encryption failed: {:?}", e)))?
            }
        };
        rest[content_len..content_len + 16].copy_from_slice(tag.as_ref());

        self.seq += 1;
        Ok(header_len + record_payload_len)
    }
}

pub struct ZeroCopyTlsDecrypter {
    cipher: TlsCipher,
    iv: [u8; 12],
    pub seq: u64,
}

impl ZeroCopyTlsDecrypter {
    pub fn new(secret: &[u8], cipher_suite: u16) -> Result<Self, TlsError> {
        let (cipher, iv) = TlsCipher::new(cipher_suite, secret)?;
        Ok(Self { cipher, iv, seq: 0 })
    }

    pub fn decrypt_in_place<'a>(&mut self, record: &'a mut [u8]) -> Result<usize, TlsError> {
        if record.len() < 5 + 16 {
            return Err(TlsError::InvalidRecord);
        }
        let (header, rest) = record.split_at_mut(5);
        let aad = Aad::from(&*header);

        let mut nonce_bytes = self.iv;
        let seq_bytes = self.seq.to_be_bytes();
        for i in 0..8 {
            nonce_bytes[4 + i] ^= seq_bytes[i];
        }
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);
        
        let plaintext_slice = match &self.cipher {
            TlsCipher::Aes128Gcm(c) => {
                c.open_in_place(nonce, aad, rest)
                    .map_err(|e| TlsError::CryptoError(format!("Decryption failed: {:?}", e)))?
            }
            TlsCipher::Aes256Gcm(c) => {
                c.open_in_place(nonce, aad, rest)
                    .map_err(|e| TlsError::CryptoError(format!("Decryption failed: {:?}", e)))?
            }
            TlsCipher::ChaCha20(c) => {
                c.open_in_place(nonce, aad, rest)
                    .map_err(|e| TlsError::CryptoError(format!("Decryption failed: {:?}", e)))?
            }
        };

        self.seq += 1;
        Ok(plaintext_slice.len())
    }
}

pub fn extract_server_key_share(handshake_body: &[u8]) -> Result<([u8; 32], u16), TlsError> {
    if handshake_body.len() < 34 {
        return Err(TlsError::InvalidHandshake);
    }
    
    let mut pos = 34;
    let sid_len = handshake_body[pos] as usize;
    pos += 1 + sid_len;
    
    if pos + 3 > handshake_body.len() {
        return Err(TlsError::InvalidHandshake);
    }
    
    let cipher_suite = u16::from_be_bytes([handshake_body[pos], handshake_body[pos+1]]);
    pos += 3;
    
    if pos + 2 > handshake_body.len() {
        return Err(TlsError::InvalidHandshake);
    }
    
    let extensions_len = u16::from_be_bytes([handshake_body[pos], handshake_body[pos+1]]) as usize;
    pos += 2;
    
    if pos + extensions_len > handshake_body.len() {
        return Err(TlsError::InvalidHandshake);
    }
    
    let ext_end = pos + extensions_len;
    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([handshake_body[pos], handshake_body[pos+1]]);
        let ext_len = u16::from_be_bytes([handshake_body[pos+2], handshake_body[pos+3]]) as usize;
        pos += 4;
        
        if ext_type == 0x0033 {
            if ext_len >= 4 {
                let group = u16::from_be_bytes([handshake_body[pos], handshake_body[pos+1]]);
                let key_len = u16::from_be_bytes([handshake_body[pos+2], handshake_body[pos+3]]) as usize;
                if group == 0x001d && key_len == 32 && pos + 4 + key_len <= ext_end {
                    let mut pub_key = [0u8; 32];
                    pub_key.copy_from_slice(&handshake_body[pos+4..pos+4+32]);
                    return Ok((pub_key, cipher_suite));
                }
            }
        }
        pos += ext_len;
    }
    
    Err(TlsError::MissingKeyShare)
}

pub struct TranscriptHash {
    hasher256: Sha256,
    hasher384: Sha384,
}

impl TranscriptHash {
    pub fn new() -> Self {
        Self {
            hasher256: Sha256::new(),
            hasher384: Sha384::new(),
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.hasher256.update(data);
        self.hasher384.update(data);
    }

    pub fn finalize(&self, cipher_suite: u16) -> Vec<u8> {
        if cipher_suite == 0x1302 {
            self.hasher384.clone().finalize().to_vec()
        } else {
            self.hasher256.clone().finalize().to_vec()
        }
    }
}
