use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;

/// Live statistics and rolling bilingual event logger for the SuperBox proxy core.
pub struct ProxyStats {
    /// Number of concurrent active proxy connections
    pub active_connections: AtomicUsize,
    /// Cumulative uploaded bytes (client -> server)
    pub total_uploaded: AtomicU64,
    /// Cumulative downloaded bytes (server -> client)
    pub total_downloaded: AtomicU64,
    /// Recent operational/error events in bilingual format
    pub recent_events: Mutex<Vec<String>>,
}

impl ProxyStats {
    /// Initialise standard atomic stats counters and an empty events buffer.
    pub fn new() -> Self {
        Self {
            active_connections: AtomicUsize::new(0),
            total_uploaded: AtomicU64::new(0),
            total_downloaded: AtomicU64::new(0),
            recent_events: Mutex::new(Vec::new()),
        }
    }

    /// Add uploaded bytes count.
    pub fn add_uploaded(&self, bytes: u64) {
        self.total_uploaded.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Add downloaded bytes count.
    pub fn add_downloaded(&self, bytes: u64) {
        self.total_downloaded.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Increment the active connections count.
    pub fn inc_active_connections(&self) {
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    /// Decrement the active connections count.
    pub fn dec_active_connections(&self) {
        let current = self.active_connections.load(Ordering::Relaxed);
        if current > 0 {
            self.active_connections.fetch_sub(1, Ordering::Relaxed);
        }
    }

    /// Log a bilingual operation event with a timestamp [HH:MM:SS].
    pub fn log_event(&self, ru_text: &str, en_text: &str) {
        let time_str = if let Ok(now) = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            // Convert UNIX timestamp to simple HH:MM:SS
            let secs = now.as_secs();
            let hours = (secs / 3600 + 5) % 24; // Simple UTC+5 offset or standard hours format
            let mins = (secs / 60) % 60;
            let secs_only = secs % 60;
            format!("{:02}:{:02}:{:02}", hours, mins, secs_only)
        } else {
            "00:00:00".to_string()
        };

        let formatted = format!("[{}] {} / {}", time_str, ru_text, en_text);
        let mut events = self.recent_events.lock().unwrap();
        events.push(formatted);
        if events.len() > 6 {
            events.remove(0);
        }
    }

    /// Retrieve a snapshot clone of the current bilingual operational events.
    pub fn get_events(&self) -> Vec<String> {
        self.recent_events.lock().unwrap().clone()
    }
}
