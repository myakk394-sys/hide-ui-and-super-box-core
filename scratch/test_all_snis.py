import socket
import ssl
from cryptography import x509
from cryptography.hazmat.backends import default_backend

def test_sni(ip, port, sni):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5)
    try:
        sock.connect((ip, port))
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.set_alpn_protocols(["h2", "http/1.1"])
        tls_sock = context.wrap_socket(sock, server_hostname=sni)
        cert_der = tls_sock.getpeercert(binary_form=True)
        cert = x509.load_der_x509_certificate(cert_der, default_backend())
        subject = cert.subject.rfc4514_string()
        print(f"[+] SNI='{sni:28}': Subject='{subject}'")
    except Exception as e:
        print(f"[-] SNI='{sni:28}': Error: {e}")
    finally:
        sock.close()

def main():
    ip = "YOUR_VPS_IP"
    port = 51443
    snis = [
        "media.tumblr-srv.net",
        "img.pinterest-cdn.com",
        "assets.github-cdn.org",
        "cdn.shopify-cms.com",
        "cdn.random-site.com",
        "static.cloudflare-ok.net",
        "YOUR_VPS_IP"
    ]
    for sni in snis:
        test_sni(ip, port, sni)

if __name__ == "__main__":
    main()
