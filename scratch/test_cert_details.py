import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def test_sni(ip, port, sni):
    print(f"\n[*] Testing TLS to {ip}:{port} with SNI='{sni}'...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
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
    snis = [
        "static.cloudflare-ok.net",
        "assets.github-cdn.org",
        "YOUR_VPS_IP"
    ]
    for sni in snis:
        test_sni(ip, port, sni)

if __name__ == "__main__":
    main()
