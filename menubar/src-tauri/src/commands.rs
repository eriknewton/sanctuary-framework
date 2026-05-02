// Tauri command surface invoked by the frontend.

use serde::{Deserialize, Serialize};
use tauri::{AppHandle, State};

use crate::config::{self, ClientConfig};
use crate::keychain;
use crate::{set_tray_badge, swap_tray_icon, AppState, TrayIconVariant};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IconVariantArg {
    Clear,
    Alert,
}

impl From<IconVariantArg> for TrayIconVariant {
    fn from(v: IconVariantArg) -> Self {
        match v {
            IconVariantArg::Clear => TrayIconVariant::Clear,
            IconVariantArg::Alert => TrayIconVariant::Alert,
        }
    }
}

#[tauri::command]
pub fn config_load(app: AppHandle, state: State<'_, AppState>) -> Result<Option<ClientConfig>, String> {
    if let Ok(guard) = state.config.lock() {
        if let Some(cfg) = guard.clone() {
            return Ok(Some(cfg));
        }
    }
    config::load_config(&app).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn config_save(
    app: AppHandle,
    state: State<'_, AppState>,
    config: ClientConfig,
) -> Result<(), String> {
    config::save_config(&app, &config).map_err(|e| e.to_string())?;
    if let Ok(mut guard) = state.config.lock() {
        *guard = Some(config);
    }
    Ok(())
}

#[tauri::command]
pub fn keychain_set_token(token: String) -> Result<(), String> {
    keychain::set_auth_token(&token).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn keychain_get_token() -> Result<Option<String>, String> {
    keychain::get_auth_token().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn open_external(url: String) -> Result<(), String> {
    // Use the OS default handler. We do NOT launch a browser ourselves to keep
    // the menubar process small and avoid platform-specific browser logic.
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open")
            .arg(&url)
            .spawn()
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open")
            .arg(&url)
            .spawn()
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(&["/C", "start", "", &url])
            .spawn()
            .map_err(|e| e.to_string())?;
        return Ok(());
    }
    #[allow(unreachable_code)]
    Err("Unsupported platform".to_string())
}

#[tauri::command]
pub fn tray_set_icon(app: AppHandle, variant: IconVariantArg) -> Result<(), String> {
    swap_tray_icon(&app, variant.into()).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn tray_set_badge(app: AppHandle, count: u32) -> Result<(), String> {
    set_tray_badge(&app, count).map_err(|e| e.to_string())
}

#[tauri::command]
pub fn popover_show(app: AppHandle) -> Result<(), String> {
    crate::show_popover_at(&app, None);
    Ok(())
}

#[tauri::command]
pub fn popover_hide(app: AppHandle) -> Result<(), String> {
    crate::hide_popover(&app);
    Ok(())
}
