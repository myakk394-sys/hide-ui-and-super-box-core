use std::env;
use std::process;
use std::sync::Arc;
use tracing::{info, error, warn};
use tracing_subscriber::{fmt, EnvFilter};

use super_box::config::Config;
use super_box::inbound::start_inbound;

#[derive(Clone)]
struct DualWriter {
    file: std::sync::Arc<std::sync::Mutex<std::fs::File>>,
}

impl std::io::Write for DualWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Ok(mut f) = self.file.lock() {
            let _ = f.write_all(buf);
        }
        std::io::stdout().write_all(buf)?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if let Ok(mut f) = self.file.lock() {
            let _ = f.flush();
        }
        std::io::stdout().flush()?;
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::writer::MakeWriter<'a> for DualWriter {
    type Writer = Self;

    fn make_writer(&self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::main]
async fn main() {
    let log_file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open("super_box.log")
        .expect("Failed to create log file");

    let writer = DualWriter {
        file: std::sync::Arc::new(std::sync::Mutex::new(log_file)),
    };

    let filter_str = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

    // Initialize standard clean log output via tracing-subscriber
    fmt()
        .with_env_filter(EnvFilter::new(filter_str))
        .with_writer(writer)
        .init();

    // CPU Affinity: pin the main Tokio runtime thread to a specific CPU core (core 0)
    if let Some(core_ids) = core_affinity::get_core_ids() {
        if !core_ids.is_empty() {
            let core_id = core_ids[0];
            if core_affinity::set_for_current(core_id) {
                info!("📌 CPU Affinity: Main Tokio thread successfully pinned to Core {}", core_id.id);
            } else {
                warn!("⚠️ CPU Affinity: Failed to pin main thread to Core {}", core_id.id);
            }
        }
    }



    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        error!("❌ Missing subscription URL or command!");
        eprintln!("\nUsage:\n  Client: cargo run -- <SUBSCRIBE_URL_OR_HIDEKEY_LINK>\n  Server: cargo run -- server\n");
        process::exit(1);
    }
    let mode_arg = &args[1];

    if mode_arg == "set-admin" {
        if args.len() < 4 {
            eprintln!("❌ Usage: super_box set-admin <username> <password>");
            process::exit(1);
        }
        let db = super_box::hideui::db::HideDb::open("super_box.db").expect("Failed to open DB");
        db.save_setting("admin_user", &args[2]).expect("Failed to save admin user");
        db.save_setting("admin_pass", &args[3]).expect("Failed to save admin pass");
        let _ = db.sync_panel_conf();
        println!("✅ Admin credentials updated successfully: user='{}', pass='{}'", args[2], args[3]);
        return;
    }

    if mode_arg == "set-port" {
        if args.len() < 3 {
            eprintln!("❌ Usage: super_box set-port <port>");
            process::exit(1);
        }
        let port_str = &args[2];
        if port_str.parse::<u16>().is_err() {
            eprintln!("❌ Invalid port number");
            process::exit(1);
        }
        let db = super_box::hideui::db::HideDb::open("super_box.db").expect("Failed to open DB");
        db.save_setting("panel_port", port_str).expect("Failed to save panel port");
        let _ = db.sync_panel_conf();
        println!("✅ Web panel port updated successfully to {}", port_str);
        return;
    }

    if mode_arg == "set-server-port" {
        if args.len() < 3 {
            eprintln!("❌ Usage: super_box set-server-port <port>");
            process::exit(1);
        }
        let port_str = &args[2];
        if port_str.parse::<u16>().is_err() {
            eprintln!("❌ Invalid port number");
            process::exit(1);
        }
        let db = super_box::hideui::db::HideDb::open("super_box.db").expect("Failed to open DB");
        db.save_setting("server_listen_port", port_str).expect("Failed to save server port");
        let _ = db.sync_panel_conf();
        println!("✅ VPN server listen port updated successfully to {}", port_str);
        return;
    }

    // ── set-secret-path <path> ── sets the panel "лапша" (secret path prefix)
    if mode_arg == "set-secret-path" {
        let new_path = args.get(2).map(|s| s.trim_matches('/')).unwrap_or("").to_string();
        let db = super_box::hideui::db::HideDb::open("super_box.db").expect("Failed to open DB");
        db.save_setting("panel_secret_path", &new_path).expect("Failed to save secret path");
        let _ = db.sync_panel_conf();
        if new_path.is_empty() {
            println!("✅ Secret panel path cleared — panel accessible at root");
        } else {
            println!("✅ Secret panel path set to: /{}/", new_path);
        }
        return;
    }

    // ── get-secret-path ── prints the current secret path (used by menu.sh)
    if mode_arg == "get-secret-path" {
        let db = super_box::hideui::db::HideDb::open("super_box.db").expect("Failed to open DB");
        let path = db.get_setting("panel_secret_path").unwrap_or(None).unwrap_or_default();
        println!("{}", path);
        return;
    }

    // ── reset-tls ── deletes the saved TLS cert so it will be regenerated on next start
    if mode_arg == "reset-tls" {
        let db = super_box::hideui::db::HideDb::open("super_box.db").expect("Failed to open DB");
        db.save_setting("tls_cert_pem", "").expect("Failed to reset cert");
        db.save_setting("tls_key_pem", "").expect("Failed to reset key");
        println!("✅ TLS certificate cleared — a new one will be generated on next startup");
        return;
    }

    // ── get-admin ── prints the current admin username and password
    if mode_arg == "get-admin" {
        let db = super_box::hideui::db::HideDb::open("super_box.db").expect("Failed to open DB");
        let username = db.get_setting("admin_user").unwrap_or(None).unwrap_or_default();
        let username = if username.is_empty() { "admin".to_string() } else { username };
        let password = db.get_setting("admin_pass").unwrap_or(None).unwrap_or_default();
        let password = if password.is_empty() { "hidekey2026".to_string() } else { password };
        println!("{} {}", username, password);
        return;
    }

    // ── list-peers ── prints all registered peers in the database
    if mode_arg == "list-peers" {
        let db = super_box::hideui::db::HideDb::open("super_box.db").expect("Failed to open DB");
        let peers = db.list_peers().expect("Failed to list peers");
        for peer in peers {
            println!("ID: {}, Name: {}, Active: {}, MasterKey: {}", peer.id, peer.name, peer.active, peer.master_key);
        }
        return;
    }


    if mode_arg == "server" {
        info!("🖥️ Starting SuperBox in Server Mode...");
        
        let public_ip = if let Ok(resp) = reqwest::get("https://api.ipify.org").await {
            resp.text().await.unwrap_or_else(|_| "127.0.0.1".to_string())
        } else {
            "127.0.0.1".to_string()
        };
        
        info!("🌍 Resolved Public IP for client connections: {}", public_ip);

        let stats = Arc::new(super_box::stats::ProxyStats::new());

        // 1. Initialize Hide-UI Panel — opens DB once, reads all settings from it.
        info!("🔧 Initializing Hide-UI Panel on port 8082...");
        let ui_server = match super_box::hideui::HideUiServer::new(
            "super_box.db",
            public_ip.clone(),
            8443, // placeholder — real port read below from DB
            "0.0.0.0".to_string(),
            8082,
            Arc::clone(&stats),
        ) {
            Ok(srv) => srv,
            Err(e) => {
                error!("❌ Failed to initialize Hide-UI Panel database: {}", e);
                process::exit(1);
            }
        };

        // Read VPN listen port from the already-open DB inside HideUiServer.
        // This avoids opening sled a second time (which causes lock contention
        // on fast systemd restarts — os error 11 / EWOULDBLOCK).
        let server_port = ui_server.get_server_listen_port();
        info!("📡 VPN Server will listen on port: {}", server_port);

        let server_config = Config {
            profile_name: "HidekeyServer".to_string(),
            vless_uuid: uuid::Uuid::new_v4(),
            local_inbound_port: 1080,
            remote_outbound_address: public_ip,
            server_listen_port: server_port,
            security: super_box::config::SecurityType::None,
            transport: super_box::config::TransportType::Tcp,
            reality_public_key: None,
            reality_short_id: None,
            sni: None,
            fingerprint: None,
            flow: None,
            fragment: Default::default(),
            mux: Default::default(),
            test_mode: false,
            loaded_from: "Server Mode CLI".to_string(),
            hidekey_master_key: None,
            physical_ip: None,
            physical_if_index: None,
        };

        let config_arc = Arc::new(server_config);

        let peers_arc = ui_server.get_state().peers.clone();
        let cert_pem  = ui_server.get_cert_pem();
        let key_pem   = ui_server.get_key_pem();

        if let Err(e) = ui_server.run().await {
            error!("❌ Failed to run Hide-UI Panel: {}", e);
        } else {
            info!("✅ Hide-UI Panel successfully launched on http://0.0.0.0:8082");
        }

        // 2. Start remote tunnel outbound listener (which acts as proxy server)
        info!("📡 Starting remote tunnel listener on port {}...", config_arc.server_listen_port);
        let config_rwlock = Arc::new(std::sync::RwLock::new((*config_arc).clone()));
        
        if let Err(e) = super_box::outbound::start_outbound_server(config_rwlock, peers_arc, stats, cert_pem, key_pem).await {
            error!("❌ Remote tunnel listener crashed: {}", e);
            process::exit(1);
        }
        
        return;
    }

    info!("🚀 SuperBox Hidekey Client starting up...");
    let subscribe_url = mode_arg;

    info!("🔄 Loading configuration...");
    let mut config = match Config::load_from_any_url(subscribe_url).await {
        Ok(cfg) => cfg,
        Err(e) => {
            error!("❌ Failed to load Hidekey configuration: {e}");
            process::exit(1);
        }
    };

    // Validate the configuration
    if let Err(e) = config.validate() {
        error!("❌ Configuration validation failed: {e}");
        process::exit(1);
    }


    #[cfg(target_os = "windows")]
    {
        info!("🔧 Discovering true physical network interface (bypassing TUN via IP_UNICAST_IF)...");
        let script = r#"$gw = Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Where-Object { $_.InterfaceAlias -ne 'hidekey_tun' } | Sort-Object RouteMetric | Select-Object -First 1; $ip = Get-NetIPAddress -InterfaceIndex $gw.InterfaceIndex -AddressFamily IPv4 | Select-Object -First 1 -ExpandProperty IPAddress; Write-Output "$($gw.NextHop),$ip,$($gw.InterfaceIndex)""#;
        if let Ok(output) = std::process::Command::new("powershell")
            .arg("-NoProfile")
            .arg("-NonInteractive")
            .arg("-Command")
            .arg(script)
            .output()
        {
            let result = String::from_utf8_lossy(&output.stdout).trim().to_string();
            let parts: Vec<&str> = result.split(',').collect();
            if parts.len() == 3 {
                let gateway = parts[0].trim();
                let phys_ip = parts[1].trim();
                let if_index_str = parts[2].trim();

                info!("🔗 True Gateway: {}, Physical IP: {}, Interface Index: {}", gateway, phys_ip, if_index_str);

                if let Ok(ip_addr) = phys_ip.parse::<std::net::IpAddr>() {
                    config.physical_ip = Some(ip_addr);
                }
                if let Ok(idx) = if_index_str.parse::<u32>() {
                    config.physical_if_index = Some(idx);
                    info!("✅ Will use IP_UNICAST_IF={} to bypass TUN for all outbound connections", idx);
                }
            } else {
                error!("❌ Could not parse physical interface info! Output: '{}'", result);
                if !output.stderr.is_empty() {
                    error!("   Stderr: {}", String::from_utf8_lossy(&output.stderr).trim());
                }
            }
        }
    }


    let config_arc = Arc::new(config);
    let stats = Arc::new(super_box::stats::ProxyStats::new());

    // Initialize and run Hide-UI Panel on port 8082
    info!("🔧 Initializing Hide-UI Panel on port 8082...");
    match super_box::hideui::HideUiServer::new(
        "super_box.db",
        config_arc.remote_outbound_address.clone(),
        config_arc.server_listen_port,
        "0.0.0.0".to_string(),
        8082,
        stats,
    ) {
        Ok(ui_server) => {
            if let Err(e) = ui_server.run().await {
                error!("❌ Failed to run Hide-UI Panel: {}", e);
            } else {
                info!("✅ Hide-UI Panel successfully launched on http://0.0.0.0:8082");
            }
        }
        Err(e) => {
            error!("❌ Failed to initialize Hide-UI Panel database: {}", e);
        }
    }

    // Initialize TUN device
    info!("🔧 Starting TUN interface...");
    let tcp_listener = match super_box::tun_device::start_tun(Arc::clone(&config_arc)).await {
        Ok(l) => l,
        Err(e) => {
            error!("❌ Failed to start TUN interface: {}", e);
            process::exit(1);
        }
    };

    // Pass the config and listener directly to start_inbound
    if let Err(e) = start_inbound(config_arc, tcp_listener).await {
        error!("❌ TUN listener crashed: {}", e);
        process::exit(1);
    }
}
