import socket
import ssl

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
        cert = tls_sock.getpeercert(binary_form=True)
        alpn = tls_sock.selected_alpn_protocol()
        
        # Minimally parse cert to get CN
        # Easiest way is to decode to PEM and look for common patterns
        pem_cert = ssl.DER_cert_to_PEM_cert(cert)
        subject_line = ""
        for line in pem_cert.split("\n"):
            if "CN=" in line or "CN =" in line:
                subject_line = line
        
        # Let's check if the cert is self-signed (our Hide-UI) or Google
        is_our = "Super Box" in pem_cert or "Hide-UI" in pem_cert
        cert_name = "Super Box (OUR)" if is_our else "EXTERNAL (Possibly Google/Interception)"
        
        print(f"[+] TLS OK! ALPN={alpn}, Cert={cert_name}")
        if not is_our:
            # Let's print some hints about the cert issuer/subject
            # To do this, we can load it with cryptography or just check contents
            print(f"    First line: {pem_cert.splitlines()[1][:30]}...")
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
        "img.pinterest-cdn.com",
        "cdn.shopify-cms.com",
        "cdn.random-site.com",
        "YOUR_VPS_IP" # raw IP
    ]
    
    for sni in snis:
        test_sni(ip, port, sni)

if __name__ == "__main__":
    main()
