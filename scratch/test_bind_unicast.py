import socket
import ssl
import struct
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def test_sni(ip, port, sni, bind_interface=None):
    print(f"\n[*] Testing TLS to {ip}:{port} with SNI='{sni}' (bind_interface={bind_interface})...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    
    if bind_interface is not None:
        try:
            # IP_UNICAST_IF = 31 in Windows WinSock
            # struct.pack("@I", index) in network byte order or native?
            # Rust code does: (if_index as u32).to_be()
            if_index_be = struct.pack(">I", bind_interface)
            sock.setsockopt(0, 31, if_index_be)
            print(f"[+] Bound socket to interface {bind_interface} via IP_UNICAST_IF")
        except Exception as e:
            print(f"[-] Failed to bind socket to interface {bind_interface}: {e}")

    try:
        sock.connect((ip, port))
    except Exception as e:
        print(f"[-] TCP Connection failed: {e}")
        return

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.set_alpn_protocols(["h2", "http/1.1"])

    try:
        tls_sock = context.wrap_socket(sock, server_hostname=sni)
        cert_der = tls_sock.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        
        subject = cert.subject.rfc4514_string()
        issuer = cert.issuer.rfc4514_string()
        
        print(f"[+] TLS OK! ALPN={tls_sock.selected_alpn_protocol()}")
        print(f"    Subject: {subject}")
        print(f"    Issuer:  {issuer}")
    except Exception as e:
        print(f"[-] TLS Handshake failed: {e}")
    finally:
        sock.close()

def main():
    ip = "YOUR_VPS_IP"
    port = 51443
    sni = "static.cloudflare-ok.net"
    
    # Test without binding
    test_sni(ip, port, sni, bind_interface=None)
    
    # Test with binding to interface 8 (physical interface index from client logs)
    test_sni(ip, port, sni, bind_interface=8)

if __name__ == "__main__":
    main()
