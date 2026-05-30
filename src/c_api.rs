#![cfg(target_family = "unix")]

//! # C-compatible API Bindings for iOS / Multi-Platform Integration
//!
//! Provides clean `extern "C"` functions for controlling the SuperBox VPN core.
//! This allows seamless integration into Swift/Objective-C (iOS/macOS), C/C++, and other languages.

use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::Config;
use crate::inbound::start_inbound;

// ── Global state ──────────────────────────────────────────────────────────────

/// Set to `true` by `super_box_stop_tunnel()`. The VPN loop checks this and exits cleanly.
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

// ── Exported C API ───────────────────────────────────────────────────────────

/// Starts the VPN tunnel asynchronously in a background OS thread.
///
/// # Arguments
/// * `tun_fd` - Raw file descriptor of the TUN interface created by iOS NetworkExtension.
/// * `config_url` - Null-terminated UTF-8 string containing the VLESS/Hidekey config URI.
///
/// # Returns
/// * `1` on successful launch.
/// * `0` on parsing or system initialization error.
#[no_mangle]
pub unsafe extern "C" fn super_box_start_tunnel(
    tun_fd: libc::c_int,
    config_url: *const c_char,
) -> libc::c_int {
    // Reset stop request flag
    STOP_REQUESTED.store(false, Ordering::SeqCst);

    if config_url.is_null() {
        return 0;
    }

    // Convert C string to Rust String
    let c_str = CStr::from_ptr(config_url);
    let config_str = match c_str.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return 0,
    };

    // Duplicate fd so we own it independently of the caller
    let owned_fd = unsafe { libc::dup(tun_fd) };
    if owned_fd < 0 {
        return 0;
    }

    // Spawn the core VPN event loop in a native OS background thread
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
        {
            Ok(r) => r,
            Err(_) => {
                unsafe { libc::close(owned_fd); }
                return;
            }
        };

        rt.block_on(run_c_vpn_loop(owned_fd, config_str));
    });

    1
}

/// Request a clean shutdown and stop of the active VPN tunnel.
#[no_mangle]
pub extern "C" fn super_box_stop_tunnel() {
    STOP_REQUESTED.store(true, Ordering::SeqCst);
}

// ── Core Event Loop (Adapted from JNI loop) ──────────────────────────────────

async fn run_c_vpn_loop(raw_fd: i32, config_str: String) {
    // 1. Parse & validate config
    let config = match Config::load_from_any_url(&config_str).await {
        Ok(c) => c,
        Err(_) => {
            unsafe { libc::close(raw_fd); }
            return;
        }
    };
    if config.validate().is_err() {
        unsafe { libc::close(raw_fd); }
        return;
    }
    let config = Arc::new(config);

    // 2. Set TUN non-blocking (UNIX only)
    #[cfg(unix)]
    {
        let flags = unsafe { libc::fcntl(raw_fd, libc::F_GETFL, 0) };
        if flags >= 0 {
            unsafe { libc::fcntl(raw_fd, libc::F_SETFL, flags | libc::O_NONBLOCK); }
        }
    }

    // 3. Build netstack-smoltcp
    use netstack_smoltcp::StackBuilder;
    let (stack, tcp_runner, udp, tcp_listener) = match StackBuilder::default()
        .enable_tcp(true)
        .enable_udp(true)
        .build()
    {
        Ok(r) => r,
        Err(_) => {
            unsafe { libc::close(raw_fd); }
            return;
        }
    };

    let tcp_runner = tcp_runner.unwrap();
    let tcp_listener = tcp_listener.unwrap();

    tokio::spawn(async move { let _ = tcp_runner.await; });

    // Handle UDP DNS Interceptor
    if let Some(udp_socket) = udp {
        let (mut udp_read, mut udp_write) = udp_socket.split();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<netstack_smoltcp::udp::UdpMsg>(1024);

        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                let _ = udp_write.send(msg).await;
            }
        });

        // Intercept DNS UDP packets
        use futures::StreamExt;
        tokio::spawn(async move {
            while let Some(msg) = udp_read.next().await {
                let (payload, src_addr, dst_addr) = msg;

                if dst_addr.port() == 53 {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        if STOP_REQUESTED.load(Ordering::Relaxed) {
                            return;
                        }
                        // Default iOS/WAN DNS server
                        if let Ok(resp) = forward_dns_query_doh(&payload).await {
                            let _ = tx.send((resp, dst_addr, src_addr)).await;
                        }
                    });
                }
            }
        });
    }

    // Direct piping: TUN <-> netstack
    use futures::sink::SinkExt;
    use futures::stream::StreamExt;
    use std::os::unix::io::FromRawFd;

    let (mut stack_sink, mut stack_stream) = stack.split();
    let (tun_tx, mut tun_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(512);
    let stop_r = Arc::new(tokio::sync::Notify::new());
    let stop_w = stop_r.clone();

    // Spawn TUN read thread
    tokio::spawn(async move {
        let tun_file = unsafe { std::fs::File::from_raw_fd(raw_fd) };
        let mut tun_async = tokio::fs::File::from_std(tun_file);
        let mut buf = vec![0u8; 65535];
        loop {
            if STOP_REQUESTED.load(Ordering::Relaxed) {
                break;
            }
            match tokio::time::timeout(
                std::time::Duration::from_millis(200),
                tun_async.read(&mut buf),
            )
            .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(n)) => {
                    if tun_tx.send(buf[..n].to_vec()).await.is_err() {
                        break;
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => {} // timeout check
            }
        }
        stop_r.notify_one();
    });

    // Pipe TUN packets to stack
    tokio::spawn(async move {
        while let Some(pkt) = tun_rx.recv().await {
            let _ = stack_sink.send(pkt).await;
        }
    });

    // Spawn TUN write thread
    let write_fd = unsafe { libc::dup(raw_fd) };
    if write_fd >= 0 {
        #[cfg(unix)]
        unsafe { libc::fcntl(write_fd, libc::F_SETFL, libc::O_NONBLOCK); }

        tokio::spawn(async move {
            let tun_file = unsafe { std::fs::File::from_raw_fd(write_fd) };
            let mut tw = tokio::fs::File::from_std(tun_file);
            while let Some(pkt) = stack_stream.next().await {
                if STOP_REQUESTED.load(Ordering::Relaxed) {
                    break;
                }
                match pkt {
                    Ok(bytes) => {
                        if tw.write_all(&bytes).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // Start secure tunnel routing
    tokio::select! {
        _ = start_inbound(config, tcp_listener) => {}
        _ = stop_w.notified() => {}
    }
}

// ── Secure DNS-over-HTTPS (DoH) Helper ───────────────────────────────────────

async fn forward_dns_query_doh(
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    use base64::prelude::*;
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
        return Err("DoH failed".into());
    }

    let bytes = resp.bytes().await?;
    Ok(bytes.to_vec())
}
