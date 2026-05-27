"""
Hidekey protocol full handshake test (Python simulation).
Simulates exactly what the Rust client does:
1. Send ClientChallenge (76 bytes)
2. Receive ServerResponse (76 bytes)
3. Derive session keys (X25519 DH + BLAKE3 KDF)
4. Send encrypted proxy target frame (ChaCha20-Poly1305 + RTP)
5. Verify DNS response decryption

Requires:
    pip install pyca cryptography blake3 paramiko
"""

import socket
import struct
import os
import sys
import hashlib

try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    import blake3
except ImportError:
    print("Installing dependencies...")
    import subprocess
    subprocess.run([sys.executable, "-m", "pip", "install", "cryptography", "blake3", "paramiko"], check=True)
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    import blake3

# ── Config ────────────────────────────────────────────────────────────────────
SERVER_IP   = os.environ.get("SERVER_IP", "YOUR_SERVER_IP")
SERVER_PORT = int(os.environ.get("SERVER_PORT", "8443"))

MASTER_KEY_HEX = os.environ.get("MASTER_KEY", "0000000000000000000000000000000000000000000000000000000000000000")
# To run local tests: $env:MASTER_KEY="aeb064..." ; python test_hidekey.py
MASTER_KEY = bytes.fromhex(MASTER_KEY_HEX)

# ── Hidekey Crypto ────────────────────────────────────────────────────────────

def blake3_mac(key: bytes, data: bytes) -> bytes:
    """BLAKE3 keyed hash = 32-byte MAC."""
    h = blake3.blake3(data, key=key)
    return h.digest()

def blake3_kdf(context: str, key_material: bytes) -> bytes:
    """BLAKE3 derive_key KDF."""
    h = blake3.blake3(key_material, derive_key_context=context)
    return h.digest()

def make_nonce(direction: int, counter: int, seq: int, key: bytes) -> bytes:
    """Build 12-byte ChaCha20 nonce."""
    nonce = bytearray(12)
    nonce[0] = direction
    nonce[1:5] = struct.pack(">I", counter)
    nonce[5:7] = struct.pack(">H", seq)
    nonce[7:12] = key[0:5]
    return bytes(nonce)

# ── RTP Framing ───────────────────────────────────────────────────────────────

class RtpState:
    def __init__(self):
        import random
        self.seq = random.randint(0, 65535)
        self.timestamp = random.randint(0, 0xFFFFFFFF)
        self.ssrc = random.randint(0, 0xFFFFFFFF)
        self.ts_inc = 960  # 20ms Opus at 48kHz

    def pack(self, payload: bytes) -> bytes:
        """Wrap payload in RTP v2 header (12 bytes) + payload."""
        hdr = bytearray(12)
        hdr[0] = 0x80  # V=2, P=0, X=0, CC=0
        hdr[1] = 111   # M=0, PT=111 (Opus)
        hdr[2:4] = struct.pack(">H", self.seq)
        hdr[4:8] = struct.pack(">I", self.timestamp)
        hdr[8:12] = struct.pack(">I", self.ssrc)
        self.seq = (self.seq + 1) & 0xFFFF
        self.timestamp = (self.timestamp + self.ts_inc) & 0xFFFFFFFF
        return bytes(hdr) + payload

def unpack_rtp(packet: bytes) -> bytes | None:
    """Extract payload from RTP packet (skip 12-byte header)."""
    if len(packet) < 12:
        return None
    version = (packet[0] >> 6) & 0x03
    if version != 2:
        return None
    return packet[12:]

def length_prefix(data: bytes) -> bytes:
    return struct.pack(">H", len(data)) + data

def read_length_prefixed(sock: socket.socket) -> bytes:
    len_bytes = recvall(sock, 2)
    n = struct.unpack(">H", len_bytes)[0]
    return recvall(sock, n)

def recvall(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"Connection closed after {len(buf)}/{n} bytes")
        buf += chunk
    return buf

# ── Main test ─────────────────────────────────────────────────────────────────

def main():
    print(f"[*] Hidekey protocol test against {SERVER_IP}:{SERVER_PORT}")
    print(f"[*] Master key: {MASTER_KEY_HEX[:16]}...")

    # 1. Generate client X25519 keypair
    client_private = X25519PrivateKey.generate()
    client_pub = client_private.public_key().public_bytes_raw()
    client_nonce = os.urandom(12)

    # 2. Build ClientChallenge (76 bytes)
    auth_data = client_nonce + client_pub  # 12 + 32 = 44 bytes
    auth_mac = blake3_mac(MASTER_KEY, auth_data)  # 32 bytes
    challenge = client_nonce + client_pub + auth_mac  # 76 bytes total
    assert len(challenge) == 76

    print(f"[*] ClientChallenge ({len(challenge)} bytes): nonce={client_nonce.hex()[:16]}... pub={client_pub.hex()[:16]}...")

    # 3. Connect and send challenge with random junk
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((SERVER_IP, SERVER_PORT))
    print(f"[OK] TCP connected")

    import random
    junk_len = random.randint(16, 128)
    junk_bytes = os.urandom(junk_len)
    packet = struct.pack(">H", junk_len) + junk_bytes + challenge

    sock.sendall(packet)
    print(f"[OK] ClientChallenge sent (junk={junk_len} bytes)")

    # 4. Read Server's random junk and ServerResponse
    srv_junk_len_bytes = recvall(sock, 2)
    srv_junk_len = struct.unpack(">H", srv_junk_len_bytes)[0]
    print(f"[*] Server junk length: {srv_junk_len} bytes")
    
    # Discard server junk
    _ = recvall(sock, srv_junk_len)

    resp = recvall(sock, 76)
    server_nonce = resp[0:12]
    server_pub   = resp[12:44]
    server_mac   = resp[44:76]

    print(f"[*] ServerResponse received: nonce={server_nonce.hex()[:16]}... pub={server_pub.hex()[:16]}...")

    # 5. Verify server MAC
    resp_auth_data = server_nonce + server_pub
    expected_mac = blake3_mac(MASTER_KEY, resp_auth_data)
    if expected_mac != server_mac:
        print(f"[FAIL] Server MAC verification FAILED!")
        print(f"       Expected: {expected_mac.hex()}")
        print(f"       Got:      {server_mac.hex()}")
        sock.close()
        return

    print(f"[OK] ServerResponse MAC verified ✓")

    # 6. Derive session keys via X25519 DH + BLAKE3 KDF
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    server_pub_key = X25519PublicKey.from_public_bytes(server_pub)
    shared_secret = client_private.exchange(server_pub_key)

    tx_key = blake3_kdf("Hidekey-Client-to-Server-Cipher", shared_secret)
    rx_key = blake3_kdf("Hidekey-Server-to-Client-Cipher", shared_secret)

    print(f"[OK] Session keys derived: tx={tx_key.hex()[:16]}... rx={rx_key.hex()[:16]}...")

    # 7. Encrypt and send proxy target: DNS to 8.8.8.8:53
    # Format: CMD(1) + PORT(2) + ATYP(1) + ADDR(N)
    target_frame = bytes([0x01]) + struct.pack(">H", 53) + bytes([0x01]) + bytes([8, 8, 8, 8])
    print(f"[*] Proxy target: {target_frame.hex()} → 8.8.8.8:53 (server will redirect to 127.0.0.53:53)")

    # Encrypt with tx_key, direction=0x00 (client→server), counter=0
    rtp = RtpState()
    seq = rtp.seq
    nonce = make_nonce(0x00, 0, seq, tx_key)
    cipher = ChaCha20Poly1305(tx_key)
    ciphertext = cipher.encrypt(nonce, target_frame, b"")
    rtp_packet = rtp.pack(ciphertext)
    wire = length_prefix(rtp_packet)
    sock.sendall(wire)
    print(f"[OK] Encrypted proxy target sent ({len(wire)} bytes)")
    tx_counter = 1

    # 8. Send DNS query over TCP (2-byte length prefix + DNS wire format)
    dns_query = bytes([
        0x00, 0x01,  # Transaction ID
        0x01, 0x00,  # Flags: standard query
        0x00, 0x01,  # Questions: 1
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # RRs: all 0
        # Question: google.com A
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,  # \x06google
        0x03, 0x63, 0x6f, 0x6d, 0x00,               # \x03com\x00
        0x00, 0x01, 0x00, 0x01,                      # QTYPE=A, QCLASS=IN
    ])
    # TCP DNS: 2-byte length prefix
    dns_tcp = struct.pack(">H", len(dns_query)) + dns_query

    # Encrypt dns payload
    seq2 = rtp.seq
    nonce2 = make_nonce(0x00, tx_counter, seq2, tx_key)
    ciphertext2 = cipher.encrypt(nonce2, dns_tcp, b"")
    rtp_packet2 = rtp.pack(ciphertext2)
    wire2 = length_prefix(rtp_packet2)
    sock.sendall(wire2)
    print(f"[OK] Encrypted DNS query sent ({len(wire2)} bytes)")
    tx_counter += 1

    # 9. Read encrypted DNS response
    rx_packet = read_length_prefixed(sock)
    print(f"[*] Received encrypted response: {len(rx_packet)} bytes")

    # Decrypt with rx_key, direction=0x01 (server→client), counter=0
    rx_payload = unpack_rtp(rx_packet)
    if not rx_payload:
        print(f"[FAIL] Invalid RTP packet in response")
        sock.close()
        return

    rx_seq = struct.unpack(">H", rx_packet[2:4])[0]
    rx_nonce = make_nonce(0x01, 0, rx_seq, rx_key)
    rx_cipher = ChaCha20Poly1305(rx_key)
    try:
        plaintext = rx_cipher.decrypt(rx_nonce, rx_payload, b"")
        print(f"[OK] Response decrypted: {len(plaintext)} bytes")
    except Exception as e:
        print(f"[FAIL] Decryption failed: {e}")
        sock.close()
        return

    # Decode DNS-over-TCP response (first 2 bytes = length, rest = DNS)
    if len(plaintext) >= 2:
        dns_resp_len = struct.unpack(">H", plaintext[:2])[0]
        dns_resp = plaintext[2:2 + dns_resp_len]
        if len(dns_resp) >= 8:
            tx_id = struct.unpack(">H", dns_resp[:2])[0]
            flags = struct.unpack(">H", dns_resp[2:4])[0]
            answers = struct.unpack(">H", dns_resp[6:8])[0]
            print(f"[OK] DNS response: TX-ID={tx_id}, Flags=0x{flags:04x}, Answers={answers}")
            if answers > 0:
                print(f"✅ SUCCESS! Hidekey tunnel + DNS resolution working perfectly!")
            else:
                print(f"⚠️  DNS answered with 0 records (may be NXDOMAIN)")
        else:
            print(f"[OK] Got {len(plaintext)} bytes of decrypted data (non-DNS?)")
    else:
        print(f"[FAIL] Response too short: {plaintext.hex()}")

    sock.close()
    print(f"\n✅ Hidekey handshake and encrypted relay test COMPLETE")

if __name__ == "__main__":
    main()
