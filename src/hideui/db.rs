use std::path::Path;
use serde::{Serialize, Deserialize};
use sled::Db;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub id: String,
    pub name: String,
    pub active: bool,
    pub last_handshake: Option<u64>,
    pub master_key: String, // Hex encoded master key for Hidekey
}

pub struct HideDb {
    db: Db,
}

impl HideDb {
    /// Opens or creates a new sled database at the specified path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    /// Saves or updates a peer in the sled KV store.
    pub fn save_peer(&self, peer: &Peer) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let serialized = serde_json::to_vec(peer)?;
        self.db.insert(format!("peer:{}", peer.id).as_bytes(), serialized)?;
        self.db.flush()?;
        Ok(())
    }

    /// Retrieves a specific peer by ID.
    pub fn get_peer(&self, id: &str) -> Result<Option<Peer>, Box<dyn std::error::Error + Send + Sync>> {
        if let Some(ivec) = self.db.get(format!("peer:{}", id).as_bytes())? {
            let peer = serde_json::from_slice(&ivec)?;
            Ok(Some(peer))
        } else {
            Ok(None)
        }
    }

    /// Retrieves a list of all saved peers in the system.
    pub fn list_peers(&self) -> Result<Vec<Peer>, Box<dyn std::error::Error + Send + Sync>> {
        let mut peers = Vec::new();
        // Sled iterator yields Result<(IVec, IVec)>
        for item in self.db.scan_prefix("peer:") {
            let (_, ivec) = item?;
            if let Ok(peer) = serde_json::from_slice::<Peer>(&ivec) {
                peers.push(peer);
            }
        }
        Ok(peers)
    }

    /// Deletes a peer from the store by ID.
    pub fn delete_peer(&self, id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.db.remove(format!("peer:{}", id).as_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    /// Saves a key-value configuration setting.
    pub fn save_setting(&self, key: &str, value: &str) -> Result<(), sled::Error> {
        self.db.insert(format!("setting:{}", key).as_bytes(), value.as_bytes())?;
        self.db.flush()?;
        Ok(())
    }

    /// Retrieves a key-value configuration setting.
    pub fn get_setting(&self, key: &str) -> Result<Option<String>, sled::Error> {
        if let Some(ivec) = self.db.get(format!("setting:{}", key).as_bytes())? {
            Ok(Some(String::from_utf8_lossy(&ivec).into_owned()))
        } else {
            Ok(None)
        }
    }

    /// Syncs panel settings to a flat panel.conf file for lock-free reading.
    pub fn sync_panel_conf(&self) -> Result<(), std::io::Error> {
        let port = self.get_setting("panel_port").unwrap_or(None);
        let port = if port.is_none() || port.as_ref().unwrap().is_empty() { "8082".to_string() } else { port.unwrap() };
        
        let path = self.get_setting("panel_secret_path").unwrap_or(None).unwrap_or_default();
        
        let user = self.get_setting("admin_user").unwrap_or(None);
        let user = if user.is_none() || user.as_ref().unwrap().is_empty() { "admin".to_string() } else { user.unwrap() };
        
        let pass = self.get_setting("admin_pass").unwrap_or(None);
        let pass = if pass.is_none() || pass.as_ref().unwrap().is_empty() { "hidekey2026".to_string() } else { pass.unwrap() };

        let content = format!(
            "panel_port=\"{}\"\npanel_secret_path=\"{}\"\nadmin_user=\"{}\"\nadmin_pass=\"{}\"\n",
            port, path, user, pass
        );
        std::fs::write("panel.conf", content)
    }
}
