// Persistent client config. Stored as JSON in the Tauri app config directory so
// the operator does not have to redo the onboarding wizard on every launch.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;
use tauri::{AppHandle, Manager};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ClientConfig {
    #[serde(rename = "fortressEndpoint")]
    pub fortress_endpoint: String,
    #[serde(rename = "authToken", skip_serializing_if = "Option::is_none")]
    pub auth_token: Option<String>,
}

fn config_path(app: &AppHandle) -> Result<PathBuf, io::Error> {
    let dir = app
        .path()
        .app_config_dir()
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
    fs::create_dir_all(&dir)?;
    Ok(dir.join("menubar-config.json"))
}

pub fn load_config(app: &AppHandle) -> Result<Option<ClientConfig>, io::Error> {
    let path = config_path(app)?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)?;
    let cfg: ClientConfig =
        serde_json::from_str(&raw).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(Some(cfg))
}

pub fn save_config(app: &AppHandle, cfg: &ClientConfig) -> Result<(), io::Error> {
    let path = config_path(app)?;
    // We deliberately do NOT persist the auth token to the JSON file; it lives
    // in the platform keychain. Strip it before serializing.
    let serializable = ClientConfig {
        fortress_endpoint: cfg.fortress_endpoint.clone(),
        auth_token: None,
    };
    let raw = serde_json::to_string_pretty(&serializable)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    fs::write(&path, raw)
}
