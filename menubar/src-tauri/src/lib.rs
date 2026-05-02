// Sanctuary Menubar Rust backend.
//
// Responsibilities:
// 1. Tray icon creation and click event routing.
// 2. Popover window lifecycle (show, hide, position near tray).
// 3. Tauri command handlers the frontend invokes (config load/save, keychain,
//    open external URL, tray icon swap, badge text).
// 4. Application activation policy on macOS so Sanctuary lives in the menubar
//    rather than the Dock.
//
// Castle Layer note: this process surfaces audit-log state. It does not enforce.
// The Castle Wall (WP-V1.x-CASTLE-WALL) is a separate process that ships in v1.x.

use serde::{Deserialize, Serialize};
use std::sync::Mutex;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, PhysicalPosition, Runtime};

mod commands;
mod config;
mod keychain;

#[derive(Debug, Default)]
struct AppState {
    config: Mutex<Option<config::ClientConfig>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "lowercase")]
enum TrayIconVariant {
    Clear,
    Alert,
}

const TRAY_ID: &str = "main-tray";

pub fn run() {
    env_logger::init();

    tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_http::init())
        .manage(AppState::default())
        .invoke_handler(tauri::generate_handler![
            commands::config_load,
            commands::config_save,
            commands::keychain_set_token,
            commands::keychain_get_token,
            commands::open_external,
            commands::tray_set_icon,
            commands::tray_set_badge,
            commands::popover_show,
            commands::popover_hide,
        ])
        .setup(|app| {
            // macOS: hide from Dock so Sanctuary lives only in the menubar.
            #[cfg(target_os = "macos")]
            {
                app.set_activation_policy(tauri::ActivationPolicy::Accessory);
            }

            let handle: AppHandle = app.handle().clone();

            // Build a small right-click menu so operators can quit without resorting
            // to Activity Monitor. Left-click toggles the popover.
            let quit = MenuItem::with_id(&handle, "quit", "Quit Sanctuary Menubar", true, None::<&str>)?;
            let menu = Menu::with_items(&handle, &[&quit])?;

            // Build the tray icon. Image bytes are loaded at runtime so we can swap
            // between clear and alert variants without rebuilding the binary.
            let _tray = TrayIconBuilder::with_id(TRAY_ID)
                .icon(load_tray_icon_image(&handle, TrayIconVariant::Clear)?)
                .icon_as_template(true)
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| {
                    if event.id().as_ref() == "quit" {
                        app.exit(0);
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        position,
                        ..
                    } = event
                    {
                        let app_handle = tray.app_handle();
                        toggle_popover(app_handle, position);
                        let _ = app_handle.emit("tray-click", ());
                    }
                })
                .build(&handle)?;

            // Frontend hydrates via the config_load command on bootstrap; we do
            // not eagerly read config here because the setup-callback borrow
            // checker treatment of State<AppState> + MutexGuard is awkward and
            // there is no functional benefit to eager loading.
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn load_tray_icon_image<R: Runtime>(
    app: &AppHandle<R>,
    variant: TrayIconVariant,
) -> Result<tauri::image::Image<'static>, tauri::Error> {
    let filename = match variant {
        TrayIconVariant::Clear => "icons/tray-clear.png",
        TrayIconVariant::Alert => "icons/tray-alert.png",
    };
    // Try the bundled-resource path first; fall back to a current_exe-relative
    // path in dev mode where the resource directory layout differs.
    if let Ok(p) = app.path().resolve(filename, tauri::path::BaseDirectory::Resource) {
        if let Ok(img) = tauri::image::Image::from_path(&p) {
            return Ok(img);
        }
    }
    // current_exe failure is catastrophic and effectively never happens on a
    // running process; fall back to the current directory and let the subsequent
    // from_path() surface a meaningful error if the icon truly is missing.
    let mut p = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("."));
    p.pop();
    p.push("icons");
    p.push(match variant {
        TrayIconVariant::Clear => "tray-clear.png",
        TrayIconVariant::Alert => "tray-alert.png",
    });
    tauri::image::Image::from_path(p)
}

pub(crate) fn swap_tray_icon(app: &AppHandle, variant: TrayIconVariant) -> Result<(), tauri::Error> {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let img = load_tray_icon_image(app, variant)?;
        tray.set_icon(Some(img))?;
    }
    Ok(())
}

pub(crate) fn set_tray_badge(app: &AppHandle, count: u32) -> Result<(), tauri::Error> {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let title = if count == 0 {
            None
        } else {
            Some(format!("{}", count))
        };
        tray.set_title(title.as_deref())?;
    }
    Ok(())
}

pub(crate) fn show_popover_at(app: &AppHandle, anchor: Option<PhysicalPosition<f64>>) {
    if let Some(window) = app.get_webview_window("popover") {
        if let Some(pos) = anchor {
            // Position the popover roughly under the tray icon. The popover is
            // 400px wide; we shift left by half to center it under the click.
            let x = (pos.x as i32) - 200;
            let y = (pos.y as i32) + 4;
            let _ = window.set_position(tauri::PhysicalPosition::new(x, y));
        }
        let _ = window.show();
        let _ = window.set_focus();
    }
}

pub(crate) fn hide_popover(app: &AppHandle) {
    if let Some(window) = app.get_webview_window("popover") {
        let _ = window.hide();
    }
}

fn toggle_popover(app: &AppHandle, position: PhysicalPosition<f64>) {
    if let Some(window) = app.get_webview_window("popover") {
        let visible = window.is_visible().unwrap_or(false);
        if visible {
            let _ = window.hide();
        } else {
            show_popover_at(app, Some(position));
        }
    }
}
