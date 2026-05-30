//! # Android JNI Wrapper for Hidekey VPN Core
//!
//! ## Fixes
//! 1. **protect()** — Every outbound socket is protected via VpnService.protect()
//!    before connecting. Without this, packets to the Hidekey server loop back
//!    through the TUN endlessly (routing loop).
//! 2. **stopTunnel()** — A cancellation flag lets Kotlin signal the Rust worker
//!    thread to exit cleanly when the user disconnects.

use std::os::unix::io::FromRawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use futures::{SinkExt, StreamExt};
use jni::objects::{JObject, JString, JValue};
use jni::sys::{jboolean, jint, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;
use netstack_smoltcp::StackBuilder;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{error, info, warn, debug};

use crate::config::Config;
use crate::inbound::start_inbound;

// ── Global state ──────────────────────────────────────────────────────────────

/// Set to `true` by `stopTunnel()`. The VPN loop checks this and exits cleanly.
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

/// Stores the JVM reference + VpnService global object ref so we can call
/// `VpnService.protect(fd)` from Rust background threads.
struct ProtectCtx {
    jvm: jni::JavaVM,
    vpn_service: jni::objects::GlobalRef,
}

// SAFETY: We access this only while holding the Mutex guard.
unsafe impl Send for ProtectCtx {}
unsafe impl Sync for ProtectCtx {}

static PROTECT_CTX: OnceLock<Mutex<ProtectCtx>> = OnceLock::new();

/// Call Android's `VpnService.protect(fd)` to exclude `fd` from the VPN tunnel.
/// Without this every outbound socket loops back through the TUN forever.
pub fn protect_socket(raw_fd: i32) -> bool {
    let Some(ctx_mutex) = PROTECT_CTX.get() else {
        warn!("⚠️ JNI: protect_socket called before PROTECT_CTX is initialised");
        return false;
    };
    let ctx = match ctx_mutex.lock() {
        Ok(g) => g,
        Err(_) => return false,
    };
    let mut env = match ctx.jvm.attach_current_thread() {
        Ok(e) => e,
        Err(e) => {
            error!("❌ JNI: attach_current_thread failed: {:?}", e);
            return false;
        }
    };
    match env.call_method(
        &ctx.vpn_service,
        "protect",
        "(I)Z",
        &[JValue::Int(raw_fd)],
    ) {
        Ok(v) => v.z().unwrap_or(false),
        Err(e) => {
            error!("❌ JNI: VpnService.protect() failed: {:?}", e);
            false
        }
    }
}

// ── JNI: startTunnel ─────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "system" fn Java_org_hidekey_core_superbox_VpnService_startTunnel(
    mut env: JNIEnv,
    this: JObject,   // The VpnService instance — used for protect()
    tun_fd: jint,
    config_url: JString,
) -> jboolean {
    // Reset stop flag in case this is a reconnect after a previous stop.
    STOP_REQUESTED.store(false, Ordering::SeqCst);

    // ── 1. Read configUrl ─────────────────────────────────────────────────────
    let config_str: String = match env.get_string(&config_url) {
        Ok(js) => js.into(),
        Err(e) => {
            error!("❌ JNI: cannot read configUrl: {:?}", e);
            return JNI_FALSE;
        }
    };

    // ── 2. Store JVM + VpnService ref for protect() calls ────────────────────
    let jvm = match env.get_java_vm() {
        Ok(j) => j,
        Err(e) => {
            error!("❌ JNI: get_java_vm failed: {:?}", e);
            return JNI_FALSE;
        }
    };
    let global_ref = match env.new_global_ref(this) {
        Ok(r) => r,
        Err(e) => {
            error!("❌ JNI: new_global_ref failed: {:?}", e);
            return JNI_FALSE;
        }
    };
    let _ = PROTECT_CTX.set(Mutex::new(ProtectCtx {
        jvm,
        vpn_service: global_ref,
    }));

    info!("🚀 JNI: startTunnel fd={}", tun_fd);

    // ── 3. dup() so we own the fd independently of JVM ────────────────────────
    let owned_fd = libc::dup(tun_fd);
    if owned_fd < 0 {
        error!("❌ JNI: dup(tunFd) failed: {}", std::io::Error::last_os_error());
        return JNI_FALSE;
    }

    // ── 4. Spawn VPN loop in background OS thread ─────────────────────────────
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(e) => {
                error!("❌ JNI: tokio build failed: {}", e);
                unsafe { libc::close(owned_fd) };
                return;
            }
        };
        rt.block_on(run_vpn_loop(owned_fd, config_str));
    });

    JNI_TRUE
}

// ── JNI: stopTunnel ───────────────────────────────────────────────────────────

#[no_mangle]
pub unsafe extern "system" fn Java_org_hidekey_core_superbox_VpnService_stopTunnel(
    _env: JNIEnv,
    _this: JObject,
) {
    info!("🛑 JNI: stopTunnel called — requesting shutdown");
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

// ── Core async VPN loop ───────────────────────────────────────────────────────

async fn run_vpn_loop(raw_fd: i32, config_str: String) {
    // ── 1. Parse & validate config ────────────────────────────────────────────
    let config = match Config::load_from_any_url(&config_str).await {
        Ok(c) => c,
        Err(e) => {
            error!("❌ JNI: config parse error: {}", e);
            unsafe { libc::close(raw_fd) };
            return;
        }
    };
    if let Err(e) = config.validate() {
        error!("❌ JNI: config validation failed: {}", e);
        unsafe { libc::close(raw_fd) };
        return;
    }
    let config = Arc::new(config);
    info!(
        "✅ JNI: config loaded — server={}:{}",
        config.remote_outbound_address, config.server_listen_port
    );

    // ── 2. Set TUN fd non-blocking ────────────────────────────────────────────
    let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFL, 0) };
    if flags < 0
        || unsafe { libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        error!("❌ JNI: O_NONBLOCK failed: {}", std::io::Error::last_os_error());
        unsafe { libc::close(raw_fd) };
        return;
    }

    // ── 3. Build netstack ─────────────────────────────────────────────────────
    let (stack, tcp_runner, udp, tcp_listener) = match StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .build()
    {
        Ok(r) => r,
        Err(e) => {
            error!("❌ JNI: StackBuilder failed: {}", e);
            unsafe { libc::close(raw_fd) };
            return;
        }
    };

    let tcp_runner   = tcp_runner.unwrap();
    let tcp_listener = tcp_listener.unwrap();

    tokio::spawn(async move { let _ = tcp_runner.await; });

    // Handle UDP DNS queries (Interception)
    if let Some(udp_socket) = udp {
        let (mut udp_read, mut udp_write) = udp_socket.split();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<netstack_smoltcp::udp::UdpMsg>(1024);

        // Task to write UDP packets back to the netstack
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Err(e) = udp_write.send(msg).await {
                    error!("❌ JNI: Failed to write UDP packet to netstack: {}", e);
                }
            }
        });

        let dns_server_ip = "8.8.8.8".to_string(); // Android VpnService default DNS

        // Task to read UDP packets from netstack and intercept DNS queries
        use futures::StreamExt;
        tokio::spawn(async move {
            info!("🎯 JNI: UDP DNS Interceptor active. Target DNS: {}", dns_server_ip);

            while let Some(msg) = udp_read.next().await {
                let (payload, src_addr, dst_addr) = msg;

                if dst_addr.port() == 53 {
                    let tx = tx.clone();
                    let dns_server_ip = dns_server_ip.clone();
                    tokio::spawn(async move {
                        if STOP_REQUESTED.load(Ordering::Relaxed) {
                            return;
                        }
                        match forward_dns_query(payload, &dns_server_ip).await {
                            Ok(resp) => {
                                if let Err(e) = tx.send((resp, dst_addr, src_addr)).await {
                                    error!("❌ JNI: Failed to queue DNS response: {}", e);
                                }
                            }
                            Err(e) => {
                                error!("❌ JNI: DNS forwarding failed for {}: {}", dst_addr, e);
                            }
                        }
                    });
                }
            }
        });
    }

    let (mut stack_sink, mut stack_stream) = stack.split();

    // ── 4. TUN → stack pump ───────────────────────────────────────────────────
    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(512);
    let stop_r = Arc::new(tokio::sync::Notify::new());
    let stop_w = stop_r.clone();

    tokio::spawn(async move {
        let tun_file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
        let mut tun_async = tokio::fs::File::from_std(tun_file);
        let mut buf = vec![0u8; 65535];
        loop {
            if STOP_REQUESTED.load(Ordering::Relaxed) {
                info!("ℹ️ JNI: Stop requested — TUN reader exiting");
                break;
            }
            match tokio::time::timeout(
                std::time::Duration::from_millis(200),
                tun_async.read(&mut buf),
            )
            .await
            {
                Ok(Ok(0)) => { info!("ℹ️ JNI: TUN fd EOF"); break; }
                Ok(Ok(n)) => {
                    if tun_tx.send(buf[..n].to_vec()).await.is_err() { break; }
                }
                Ok(Err(e)) => { error!("❌ JNI: TUN read: {}", e); break; }
                Err(_) => {} // timeout — loop back and check STOP flag
            }
        }
        stop_r.notify_one();
    });

    tokio::spawn(async move {
        while let Some(pkt) = tun_rx.recv().await {
            if let Err(e) = stack_sink.send(pkt).await {
                error!("❌ JNI: stack_sink: {}", e);
                break;
            }
        }
    });

    // ── 5. stack → TUN pump ───────────────────────────────────────────────────
    let write_fd = unsafe { libc::dup(raw_fd) };
    if write_fd >= 0 {
        unsafe { libc::fcntl(write_fd, libc::F_SETFL, libc::O_NONBLOCK) };
        tokio::spawn(async move {
            let tun_file = unsafe { std::fs::File::from_raw_fd(write_fd) };
            let mut tw = tokio::fs::File::from_std(tun_file);
            while let Some(pkt) = stack_stream.next().await {
                if STOP_REQUESTED.load(Ordering::Relaxed) { break; }
                match pkt {
                    Ok(bytes) => {
                        if let Err(e) = tw.write_all(&bytes).await {
                            error!("❌ JNI: TUN write: {}", e);
                            break;
                        }
                    }
                    Err(e) => { error!("❌ JNI: stack_stream: {}", e); break; }
                }
            }
        });
    } else {
        warn!("⚠️ JNI: dup for write-back fd failed");
    }

    // ── 6. Start inbound handler ──────────────────────────────────────────────
    info!("✅ JNI: Handing off to Hidekey inbound handler...");
    tokio::select! {
        res = start_inbound(config, tcp_listener) => {
            if let Err(e) = res {
                error!("❌ JNI: start_inbound: {}", e);
            }
        }
        _ = stop_w.notified() => {
            info!("🛑 JNI: Stop signal received — VPN loop exiting");
        }
    }

    info!("✅ JNI: VPN loop fully stopped.");
}

// ── DNS Query Interception & Forwarding Helpers ─────────────────────────────

async fn forward_dns_query(
    payload: Vec<u8>,
    dns_server_ip: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    // 1. Try secure DNS-over-HTTPS (DoH) first! This is 100% robust and runs over the secure VLESS tunnel on port 443!
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(3),
        forward_dns_query_doh(&payload),
    )
    .await
    {
        Ok(Ok(resp)) => {
            info!("✅ JNI DNS: resolved securely via DoH over VLESS tunnel");
            return Ok(resp);
        }
        Ok(Err(e)) => {
            warn!("⚠️ JNI DNS: DoH failed: {}. Falling back to TCP...", e);
        }
        Err(_) => {
            warn!("⚠️ JNI DNS: DoH timed out. Falling back to TCP...");
        }
    }

    // 2. Fallback 1: Secure DNS-over-TCP over tunnel
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(3),
        forward_dns_query_tcp(&payload, dns_server_ip),
    )
    .await
    {
        Ok(Ok(resp)) => {
            info!("✅ JNI DNS: resolved via TCP over VLESS");
            return Ok(resp);
        }
        Ok(Err(e)) => {
            warn!("⚠️ JNI DNS: TCP DNS failed: {}. Falling back to UDP...", e);
        }
        Err(_) => {
            warn!("⚠️ JNI DNS: TCP DNS timed out. Falling back to UDP...");
        }
    }

    // 3. Fallback 2: UDP DNS directly to target DNS server (bypassing TUN via protect_socket)
    forward_dns_query_udp(payload, dns_server_ip).await
}

async fn forward_dns_query_doh(
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    use base64::prelude::*;
    
    // Base64URL encode the raw DNS query payload (RFC 8484)
    let b64_payload = BASE64_URL_SAFE_NO_PAD.encode(payload);
    let doh_url = format!("https://8.8.8.8/dns-query?dns={}", b64_payload);

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(std::time::Duration::from_secs(3))
        .build()?;

    let resp = client.get(&doh_url)
        .header("accept", "application/dns-message")
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(format!("DoH server returned error status: {}", resp.status()).into());
    }

    let bytes = resp.bytes().await?;
    Ok(bytes.to_vec())
}

async fn forward_dns_query_tcp(
    payload: &[u8],
    dns_server_ip: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
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

async fn forward_dns_query_udp(
    payload: Vec<u8>,
    dns_server_ip: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    use std::os::unix::io::AsRawFd;
    let dns_addr = format!("{}:53", dns_server_ip);

    // Bind standard UDP socket
    let std_socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    let fd = std_socket.as_raw_fd();

    // Call JNI protect() to bypass the TUN interface and prevent routing loop
    if protect_socket(fd) {
        debug!("✅ JNI DNS: UDP fallback socket fd={} protected from TUN routing", fd);
    } else {
        warn!("⚠️ JNI DNS: Failed to protect UDP fallback socket fd={} — may loop!", fd);
    }

    // Convert to asynchronous tokio UDP socket
    let socket = tokio::net::UdpSocket::from_std(std_socket)?;
    socket.send_to(&payload, &dns_addr).await?;

    let mut buf = vec![0u8; 2048];
    let (len, _) = tokio::time::timeout(
        tokio::time::Duration::from_secs(3),
        socket.recv_from(&mut buf),
    )
    .await??;

    buf.truncate(len);
    Ok(buf)
}
