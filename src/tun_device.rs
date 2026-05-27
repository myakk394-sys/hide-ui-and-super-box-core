use std::sync::Arc;
use std::net::SocketAddr;
use tun::Configuration;
use netstack_smoltcp::{StackBuilder, TcpListener};
use tracing::{info, error, trace};
use futures::{StreamExt, SinkExt};
use crate::config::Config;

pub async fn start_tun(config: Arc<Config>) -> Result<TcpListener, Box<dyn std::error::Error>> {
    let mut config_tun = Configuration::default();
    config_tun
        .address((10, 0, 0, 2))
        .netmask((255, 255, 255, 0))
        .destination((10, 0, 0, 1))
        .up();

    #[cfg(target_os = "windows")]
    config_tun.tun_name("hidekey_tun");

    info!("Creating TUN interface...");
    let dev = tun::create_as_async(&config_tun)?;
    info!("TUN interface created!");

    // Give Windows some time to fully register the adapter in the network stack
    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

    // ── Windows routing & DNS setup ──────────────────────────────────────────
    //
    // Strategy:
    //   1. Find the physical (non-TUN) default gateway and its interface index.
    //   2. Set the DNS server of the v2raytun adapter itself to the target DNS server
    //      (e.g., 8.8.8.8). This forces Windows to send all DNS queries through our TUN.
    //   3. In our netstack, we intercept all UDP packets on port 53 (DNS) and forward
    //      them:
    //        - Primary: DNS-over-TCP which goes through the TUN and is proxied securely via Hidekey.
    //        - Fallback: DNS-over-UDP which goes over the physical interface directly (bypassing TUN).
    //   4. Add split-default routes (0.0.0.0/1 and 128.0.0.0/1) via the TUN adapter's
    //      interface index with next-hop 0.0.0.0 (on-link) to capture all TCP traffic.
    //
    #[cfg(target_os = "windows")]
    {
        let dns_server_ip = std::env::var("DNS_SERVER").unwrap_or_else(|_| "8.8.8.8".to_string()).trim().to_string();
        info!("Configuring Windows routing and TUN DNS server ({})", dns_server_ip);
        
        let script = format!(r#"
$tun = Get-NetAdapter -InterfaceAlias 'hidekey_tun' -ErrorAction Stop

# Set DNS on the TUN interface itself so Windows sends all DNS queries there
Set-DnsClientServerAddress -InterfaceAlias 'hidekey_tun' -ServerAddresses '{}' -ErrorAction SilentlyContinue

# Find the real (non-TUN) default gateway
$phys = Get-NetRoute -DestinationPrefix '0.0.0.0/0' |
        Where-Object {{ $_.InterfaceAlias -ne 'hidekey_tun' }} |
        Sort-Object RouteMetric |
        Select-Object -First 1
$gw      = $phys.NextHop
$physIdx = $phys.InterfaceIndex

# Bypass the gateway itself (needed for ARP / DHCP renewal)
New-NetRoute -DestinationPrefix "$gw/32" `
             -InterfaceIndex $physIdx `
             -NextHop '0.0.0.0' `
             -RouteMetric 0 `
             -PolicyStore ActiveStore `
             -ErrorAction SilentlyContinue | Out-Null

# TUN split-default routes: capture all internet traffic via proxy
New-NetRoute -DestinationPrefix '0.0.0.0/1' `
             -InterfaceIndex $tun.ifIndex `
             -NextHop '0.0.0.0' `
             -RouteMetric 0 `
             -PolicyStore ActiveStore `
             -ErrorAction SilentlyContinue | Out-Null
New-NetRoute -DestinationPrefix '128.0.0.0/1' `
             -InterfaceIndex $tun.ifIndex `
             -NextHop '0.0.0.0' `
             -RouteMetric 0 `
             -PolicyStore ActiveStore `
             -ErrorAction SilentlyContinue | Out-Null

Write-Output "OK gw=$gw physIdx=$physIdx tunIdx=$($tun.ifIndex)"
"#, dns_server_ip);

        match std::process::Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .output()
        {
            Ok(out) => {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let stderr = String::from_utf8_lossy(&out.stderr);
                if !stdout.trim().is_empty() {
                    info!("Routing OK: {}", stdout.trim());
                }
                if !stderr.trim().is_empty() {
                    error!("Routing stderr: {}", stderr.trim());
                }
            }
            Err(e) => error!("Failed to run routing script: {}", e),
        }
    }

    // Build the stack with both TCP and UDP enabled
    let (mut stack, tcp_runner, udp, tcp_listener) = StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .build()?;

    let tcp_runner = tcp_runner.unwrap();
    let tcp_listener = tcp_listener.unwrap();

    tokio::spawn(async move {
        let _ = tcp_runner.await;
    });

    // Handle UDP DNS queries (Interception)
    if let Some(udp_socket) = udp {
        let (mut udp_read, mut udp_write) = udp_socket.split();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<netstack_smoltcp::udp::UdpMsg>(1024);

        // Task to write UDP packets back to the netstack
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Err(e) = udp_write.send(msg).await {
                    error!("Failed to write UDP packet to netstack: {}", e);
                }
            }
        });

        let physical_if_index = config.physical_if_index;
        let dns_server_ip = std::env::var("DNS_SERVER").unwrap_or_else(|_| "8.8.8.8".to_string()).trim().to_string();

        // Task to read UDP packets from netstack and intercept DNS queries
        tokio::spawn(async move {
            info!("🎯 UDP DNS Interceptor active. Primary: TCP (Hidekey), Fallback: UDP (Physical). Target DNS: {}", dns_server_ip);

            while let Some(msg) = udp_read.next().await {
                let (payload, src_addr, dst_addr) = msg;

                if dst_addr.port() == 53 {
                    let tx = tx.clone();
                    let dns_server_ip = dns_server_ip.clone();
                    let orig_dst_addr = dst_addr;
                    tokio::spawn(async move {
                        match forward_dns_query(payload, dns_server_ip, orig_dst_addr, physical_if_index).await {
                            Ok(resp) => {
                                // Send response back to the TUN
                                // Source must be the original destination (dst_addr)
                                // Destination must be the original source (src_addr)
                                if let Err(e) = tx.send((resp, dst_addr, src_addr)).await {
                                    error!("Failed to queue DNS response: {}", e);
                                }
                            }
                            Err(e) => {
                                error!("DNS forwarding failed for {}: {}", dst_addr, e);
                            }
                        }
                    });
                } else {
                    trace!("Dropped non-DNS UDP packet: {} -> {}", src_addr, dst_addr);
                }
            }
        });
    }

    let framed = dev.into_framed();
    let (mut tun_sink, mut tun_stream) = framed.split();
    let (mut stack_sink, mut stack_stream) = stack.split();

    // tun -> stack
    tokio::spawn(async move {
        while let Some(pkt) = tun_stream.next().await {
            match pkt {
                Ok(bytes) => {
                    if let Err(e) = stack_sink.send(bytes.into()).await {
                        error!("Failed to send to netstack: {}", e);
                    }
                }
                Err(e) => error!("Failed to read from TUN: {}", e),
            }
        }
    });

    // stack -> tun
    tokio::spawn(async move {
        while let Some(pkt) = stack_stream.next().await {
            match pkt {
                Ok(bytes) => {
                    if let Err(e) = tun_sink.send(bytes.as_slice().to_vec().into()).await {
                        error!("Failed to send to TUN: {}", e);
                    }
                }
                Err(e) => error!("Failed to read from netstack: {}", e),
            }
        }
    });

    Ok(tcp_listener)
}

/// Forwards a DNS query payload with a dual-protocol approach:
/// 1. Tries DNS-over-TCP first (which goes through the TUN and gets proxied securely via Hidekey).
/// 2. Falls back to DNS-over-UDP directly via physical interface (bypassing the TUN).
async fn forward_dns_query(
    payload: Vec<u8>,
    dns_server_ip: String,
    orig_dst_addr: SocketAddr,
    physical_if_index: Option<u32>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // Try TCP DNS first (goes through the TUN and is proxied securely via Hidekey)
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        forward_dns_query_tcp(&payload, &dns_server_ip),
    )
    .await
    {
        Ok(Ok(resp)) => {
            trace!("DNS query resolved securely via TCP (Hidekey proxy)");
            return Ok(resp);
        }
        Ok(Err(e)) => {
            trace!("TCP DNS failed: {}. Falling back to UDP...", e);
        }
        Err(_) => {
            trace!("TCP DNS timeout. Falling back to UDP...");
        }
    }

    // Fallback: UDP DNS over physical adapter (bypassing TUN) to the original gateway/DNS server
    forward_dns_query_udp(payload, orig_dst_addr, physical_if_index).await
}

/// Helper to query DNS over TCP (RFC 7766).
async fn forward_dns_query_tcp(
    payload: &[u8],
    dns_server_ip: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let dns_addr = format!("{}:53", dns_server_ip);
    let mut stream = tokio::net::TcpStream::connect(&dns_addr).await?;

    let len = payload.len() as u16;
    let mut req = Vec::with_capacity(2 + payload.len());
    req.extend_from_slice(&len.to_be_bytes());
    req.extend_from_slice(payload);

    stream.write_all(&req).await?;

    let mut len_bytes = [0u8; 2];
    stream.read_exact(&mut len_bytes).await?;
    let resp_len = u16::from_be_bytes(len_bytes) as usize;

    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;

    Ok(resp)
}

/// Helper to query DNS over UDP (bypassing TUN).
async fn forward_dns_query_udp(
    payload: Vec<u8>,
    dns_server: SocketAddr,
    physical_if_index: Option<u32>,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let socket = if dns_server.is_ipv4() {
        tokio::net::UdpSocket::bind("0.0.0.0:0").await?
    } else {
        tokio::net::UdpSocket::bind("[::]:0").await?
    };

    if let Some(if_index) = physical_if_index {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::io::AsRawSocket;
            let raw = socket.as_raw_socket();
            let if_index_be = (if_index as u32).to_be();
            let ret = unsafe {
                windows_sys::Win32::Networking::WinSock::setsockopt(
                    raw as usize,
                    windows_sys::Win32::Networking::WinSock::IPPROTO_IP as i32,
                    31, // IP_UNICAST_IF
                    &if_index_be as *const u32 as *const u8,
                    std::mem::size_of::<u32>() as i32,
                )
            };
            if ret != 0 {
                trace!("⚠️ DNS socket IP_UNICAST_IF setsockopt failed: {}", unsafe { windows_sys::Win32::Networking::WinSock::WSAGetLastError() });
            }
        }
    }

    socket.send_to(&payload, dns_server).await?;

    let mut buf = vec![0u8; 2048];
    let (len, _) = tokio::time::timeout(
        tokio::time::Duration::from_secs(2),
        socket.recv_from(&mut buf),
    )
    .await??;

    buf.truncate(len);
    Ok(buf)
}
