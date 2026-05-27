use rand::rngs::OsRng;
use x25519_dalek::{StaticSecret, PublicKey};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, KeyInit};

/// Derives a 32-byte key from key material using BLAKE3 in KDF mode.
pub fn derive_blake3_key(context: &str, key_material: &[u8]) -> [u8; 32] {
    blake3::derive_key(context, key_material)
}

/// Computes a 32-byte MAC for data using a keyed BLAKE3 hash.
pub fn compute_blake3_mac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let hash = blake3::keyed_hash(key, data);
    *hash.as_bytes()
}

/// Verifies a BLAKE3 MAC for data in constant time.
pub fn verify_blake3_mac(key: &[u8; 32], data: &[u8], expected_mac: &[u8; 32]) -> bool {
    let actual_mac = compute_blake3_mac(key, data);
    let mut accum = 0u8;
    for (a, b) in actual_mac.iter().zip(expected_mac.iter()) {
        accum |= a ^ b;
    }
    accum == 0
}

/// Generates an ephemeral X25519 keypair.
/// Returns the private secret and the serialized 32-byte public key.
pub fn generate_x25519_keypair() -> (StaticSecret, [u8; 32]) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, *public.as_bytes())
}

/// Computes the shared secret from a private X25519 secret and opponent's public key bytes.
pub fn compute_x25519_shared_secret(secret: &StaticSecret, public_bytes: &[u8; 32]) -> [u8; 32] {
    let opponent_public = PublicKey::from(*public_bytes);
    let shared = secret.diffie_hellman(&opponent_public);
    *shared.as_bytes()
}

/// Encrypts plaintext using ChaCha20Poly1305.
pub fn encrypt_chacha20poly1305(
    key: &[u8; 32],
    nonce: &[u8; 12],
    plaintext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_val = Nonce::from_slice(nonce);
    
    cipher.encrypt(
        nonce_val,
        chacha20poly1305::aead::Payload {
            msg: plaintext,
            aad: associated_data,
        },
    )
}

/// Decrypts ciphertext using ChaCha20Poly1305.
pub fn decrypt_chacha20poly1305(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
    associated_data: &[u8],
) -> Result<Vec<u8>, chacha20poly1305::Error> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_val = Nonce::from_slice(nonce);
    
    cipher.decrypt(
        nonce_val,
        chacha20poly1305::aead::Payload {
            msg: ciphertext,
            aad: associated_data,
        },
    )
}
