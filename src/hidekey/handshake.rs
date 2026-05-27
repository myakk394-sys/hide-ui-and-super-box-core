

use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::StaticSecret;

use crate::hidekey::crypto::{
    derive_blake3_key, compute_blake3_mac, verify_blake3_mac,
    generate_x25519_keypair, compute_x25519_shared_secret,
};

pub const CHALLENGE_SIZE: usize = 76;
pub const RESPONSE_SIZE: usize = 76;

/// Wire layout of the client-to-server challenge (76 bytes of pure high entropy)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientChallenge {
    pub nonce: [u8; 12],
    pub client_pub: [u8; 32],
    pub auth_mac: [u8; 32],
}

impl ClientChallenge {
    /// Serializes the challenge to a 76-byte buffer.
    pub fn to_bytes(&self) -> [u8; CHALLENGE_SIZE] {
        let mut buf = [0u8; CHALLENGE_SIZE];
        buf[0..12].copy_from_slice(&self.nonce);
        buf[12..44].copy_from_slice(&self.client_pub);
        buf[44..76].copy_from_slice(&self.auth_mac);
        buf
    }

    /// Deserializes the challenge from a 76-byte buffer.
    pub fn from_bytes(buf: &[u8; CHALLENGE_SIZE]) -> Self {
        let mut nonce = [0u8; 12];
        let mut client_pub = [0u8; 32];
        let mut auth_mac = [0u8; 32];
        nonce.copy_from_slice(&buf[0..12]);
        client_pub.copy_from_slice(&buf[12..44]);
        auth_mac.copy_from_slice(&buf[44..76]);
        Self { nonce, client_pub, auth_mac }
    }
}

/// Wire layout of the server-to-client response (76 bytes of pure high entropy)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerResponse {
    pub nonce: [u8; 12],
    pub server_pub: [u8; 32],
    pub auth_mac: [u8; 32],
}

impl ServerResponse {
    /// Serializes the response to a 76-byte buffer.
    pub fn to_bytes(&self) -> [u8; RESPONSE_SIZE] {
        let mut buf = [0u8; RESPONSE_SIZE];
        buf[0..12].copy_from_slice(&self.nonce);
        buf[12..44].copy_from_slice(&self.server_pub);
        buf[44..76].copy_from_slice(&self.auth_mac);
        buf
    }

    /// Deserializes the response from a 76-byte buffer.
    pub fn from_bytes(buf: &[u8; RESPONSE_SIZE]) -> Self {
        let mut nonce = [0u8; 12];
        let mut server_pub = [0u8; 32];
        let mut auth_mac = [0u8; 32];
        nonce.copy_from_slice(&buf[0..12]);
        server_pub.copy_from_slice(&buf[12..44]);
        auth_mac.copy_from_slice(&buf[44..76]);
        Self { nonce, server_pub, auth_mac }
    }
}

/// Holds session keys derived from a successful handshake.
#[derive(Debug, Clone)]
pub struct DerivedSession {
    pub rx_key: [u8; 32],
    pub tx_key: [u8; 32],
}

/// Handshake state manager for the client.
pub struct ClientHandshake {
    master_key: [u8; 32],
    client_secret: StaticSecret,
    client_pub: [u8; 32],
    client_nonce: [u8; 12],
}

impl ClientHandshake {
    /// Creates a new client handshake instance.
    pub fn new(master_key: [u8; 32]) -> Self {
        let (client_secret, client_pub) = generate_x25519_keypair();
        let mut client_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut client_nonce);
        
        Self {
            master_key,
            client_secret,
            client_pub,
            client_nonce,
        }
    }

    /// Generates the challenge payload to send to the server.
    pub fn build_challenge(&self) -> ClientChallenge {
        // Data to authenticate: client_nonce (12) + client_pub (32) = 44 bytes
        let mut auth_data = [0u8; 44];
        auth_data[0..12].copy_from_slice(&self.client_nonce);
        auth_data[12..44].copy_from_slice(&self.client_pub);

        let auth_mac = compute_blake3_mac(&self.master_key, &auth_data);

        ClientChallenge {
            nonce: self.client_nonce,
            client_pub: self.client_pub,
            auth_mac,
        }
    }

    /// Verifies the server's response and derives the session keys.
    /// If verification fails, returns None (silent drop / invalid session).
    pub fn process_response(&self, resp: &ServerResponse) -> Option<DerivedSession> {
        // 1. Verify server's MAC to ensure authentic server
        let mut auth_data = [0u8; 44];
        auth_data[0..12].copy_from_slice(&resp.nonce);
        auth_data[12..44].copy_from_slice(&resp.server_pub);

        if !verify_blake3_mac(&self.master_key, &auth_data, &resp.auth_mac) {
            return None;
        }

        // 2. Perform Diffie-Hellman to get Shared Secret
        let shared_secret = compute_x25519_shared_secret(&self.client_secret, &resp.server_pub);

        // 3. Derive Tx and Rx keys using KDF
        // Client Tx = Key used by client to encrypt, server to decrypt (Client -> Server)
        // Client Rx = Key used by client to decrypt, server to encrypt (Server -> Client)
        let tx_key = derive_blake3_key("Hidekey-Client-to-Server-Cipher", &shared_secret);
        let rx_key = derive_blake3_key("Hidekey-Server-to-Client-Cipher", &shared_secret);

        Some(DerivedSession { rx_key, tx_key })
    }
}

/// Handshake state manager for the server.
pub struct ServerHandshake {
    master_key: [u8; 32],
}

impl ServerHandshake {
    /// Creates a new server handshake instance.
    pub fn new(master_key: [u8; 32]) -> Self {
        Self { master_key }
    }

    /// Verifies client's challenge and returns the server's response + derived session keys.
    /// If verification fails, returns None (triggering Silent Drop).
    pub fn process_challenge(
        &self,
        challenge: &ClientChallenge,
    ) -> Option<(ServerResponse, DerivedSession)> {
        // 1. Verify client's MAC to ensure authentic client
        let mut auth_data = [0u8; 44];
        auth_data[0..12].copy_from_slice(&challenge.nonce);
        auth_data[12..44].copy_from_slice(&challenge.client_pub);

        if !verify_blake3_mac(&self.master_key, &auth_data, &challenge.auth_mac) {
            // Verification failed: Trigger Silent Drop (return None)
            return None;
        }

        // 2. Generate server's ephemeral X25519 keypair
        let (server_secret, server_pub) = generate_x25519_keypair();
        let mut server_nonce = [0u8; 12];
        OsRng.fill_bytes(&mut server_nonce);

        // 3. Perform Diffie-Hellman to get Shared Secret
        let shared_secret = compute_x25519_shared_secret(&server_secret, &challenge.client_pub);

        // 4. Derive Tx and Rx keys using KDF (mirroring client)
        // Server Rx = Client Tx
        // Server Tx = Client Rx
        let rx_key = derive_blake3_key("Hidekey-Client-to-Server-Cipher", &shared_secret);
        let tx_key = derive_blake3_key("Hidekey-Server-to-Client-Cipher", &shared_secret);

        // 5. Build Server's Response
        let mut response_auth_data = [0u8; 44];
        response_auth_data[0..12].copy_from_slice(&server_nonce);
        response_auth_data[12..44].copy_from_slice(&server_pub);

        let response_mac = compute_blake3_mac(&self.master_key, &response_auth_data);

        let response = ServerResponse {
            nonce: server_nonce,
            server_pub,
            auth_mac: response_mac,
        };

        Some((response, DerivedSession { rx_key, tx_key }))
    }
}
