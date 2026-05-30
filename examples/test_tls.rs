use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ip = "YOUR_VPS_IP";
    let port = 51443;
    let sni = "static.cloudflare-ok.net";

    println!("[*] Connecting to {}:{}...", ip, port);
    
    // Create socket and bind to IP_UNICAST_IF to emulate inbound.rs
    let socket = if ip.parse::<std::net::IpAddr>()?.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };

    #[cfg(target_os = "windows")]
    {
        use std::os::windows::io::AsRawSocket;
        let raw = socket.as_raw_socket() as usize;
        let if_index_be = (8u32).to_be();
        unsafe {
            windows_sys::Win32::Networking::WinSock::setsockopt(
                raw,
                0, // IPPROTO_IP
                31, // IP_UNICAST_IF
                &if_index_be as *const u32 as *const u8,
                std::mem::size_of::<u32>() as i32,
            );
        }
        println!("[+] Bound socket to interface index 8");
    }

    let socket = socket.connect(format!("{}:{}", ip, port).parse()?).await?;
    println!("[+] TCP Connected!");

    let native_connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .danger_accept_invalid_hostnames(true)
        .request_alpns(&["h2", "http/1.1"])
        .build()?;
    
    let connector = tokio_native_tls::TlsConnector::from(native_connector);

    println!("[*] Performing TLS handshake with SNI='{}'...", sni);
    let tls_stream = connector.connect(sni, socket).await?;
    println!("[+] TLS Handshake Successful!");

    // Get peer certificate details
    let native_stream = tls_stream.get_ref();
    if let Ok(Some(cert)) = native_stream.peer_certificate() {
        println!("[+] Certificate found!");
        if let Ok(der) = cert.to_der() {
            println!("[+] DER length: {}", der.len());
            println!("[+] First 20 bytes: {:02x?}", &der[..20]);
        }
    } else {
        println!("[-] No peer certificate found.");
    }

    Ok(())
}
