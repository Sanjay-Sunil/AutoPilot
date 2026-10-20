//! AutoPilot tray app. Tray-only (no window at start): Status, Pair phone (QR), Devices,
//! KILL SWITCH, Open logs, Quit. Global kill shortcut Ctrl+Alt+Shift+K (X11/Windows; on Hyprland
//! bind `autopilotd kill` in hyprland.conf, see docs/runbook.md).

mod daemon;

use serde_json::{Value, json};
use tauri::{
    AppHandle, Manager, RunEvent, WebviewUrl, WebviewWindowBuilder,
    menu::{Menu, MenuItem, PredefinedMenuItem},
    tray::TrayIconBuilder,
};
use tauri_plugin_global_shortcut::{Code, GlobalShortcutExt, Modifiers, Shortcut, ShortcutState};

const TRAY_ID: &str = "autopilot";

async fn blocking(cmd: Value) -> Result<Value, String> {
    tauri::async_runtime::spawn_blocking(move || daemon::request(cmd))
        .await
        .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn status() -> Result<Value, String> {
    blocking(json!({"cmd": "status"})).await
}

/// Ask the daemon for a fresh one-time pairing URI and render it as an SVG QR.
#[tauri::command]
async fn pair() -> Result<Value, String> {
    let mut v = blocking(json!({"cmd": "pair"})).await?;
    let uri = v
        .get("uri")
        .and_then(Value::as_str)
        .ok_or("daemon reply has no uri")?
        .to_owned();
    v["svg"] = Value::String(daemon::qr_svg(&uri)?);
    Ok(v)
}

#[tauri::command]
async fn devices() -> Result<Value, String> {
    blocking(json!({"cmd": "devices"})).await
}

#[tauri::command]
async fn revoke(pk: String) -> Result<Value, String> {
    blocking(json!({"cmd": "revoke", "pk": pk})).await
}

#[tauri::command]
async fn kill() -> Result<Value, String> {
    blocking(json!({"cmd": "kill", "reason": "tray"})).await
}

fn set_tooltip(app: &AppHandle, text: &str) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_tooltip(Some(text));
    }
}

/// Fire the kill switch off the UI thread and reflect the result in the tray tooltip.
fn trigger_kill(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        let msg = match daemon::request(json!({"cmd": "kill", "reason": "tray"})) {
            Ok(_) => "AutoPilot: KILLED — all actions stopped".to_owned(),
            Err(e) => format!("AutoPilot: kill FAILED: {e}"),
        };
        eprintln!("{msg}");
        set_tooltip(&app, &msg);
    });
}

fn open_view(app: &AppHandle, view: &str) {
    let label = if view == "pair" { "pair" } else { "main" };
    if let Some(w) = app.get_webview_window(label) {
        let _ = w.eval(format!("window.location.hash = '#{view}'"));
        let _ = w.show();
        let _ = w.set_focus();
        return;
    }
    let (title, w, h) = match view {
        "pair" => ("AutoPilot — Pair phone", 380.0, 520.0),
        _ => ("AutoPilot", 480.0, 560.0),
    };
    let url = WebviewUrl::App(format!("index.html#{view}").into());
    if let Err(e) = WebviewWindowBuilder::new(app, label, url)
        .title(title)
        .inner_size(w, h)
        .resizable(true)
        .build()
    {
        eprintln!("failed to open window: {e}");
    }
}

fn open_logs() {
    let dir = daemon::data_dir();
    let target = if dir.join("logs").is_dir() {
        dir.join("logs")
    } else {
        dir
    };
    let opener = if cfg!(windows) {
        "explorer"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    if let Err(e) = std::process::Command::new(opener).arg(&target).spawn() {
        eprintln!("cannot open {}: {e}", target.display());
    }
}

fn kill_shortcut() -> Shortcut {
    Shortcut::new(
        Some(Modifiers::CONTROL | Modifiers::ALT | Modifiers::SHIFT),
        Code::KeyK,
    )
}

pub fn run() {
    let app = tauri::Builder::default()
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, sc, ev| {
                    if sc == &kill_shortcut() && ev.state() == ShortcutState::Pressed {
                        trigger_kill(app);
                    }
                })
                .build(),
        )
        .invoke_handler(tauri::generate_handler![status, pair, devices, revoke, kill])
        .setup(|app| {
            let h = app.handle();
            let menu = Menu::with_items(
                h,
                &[
                    &MenuItem::with_id(h, "status", "Status", true, None::<&str>)?,
                    &MenuItem::with_id(h, "pair", "Pair phone…", true, None::<&str>)?,
                    &MenuItem::with_id(h, "devices", "Devices", true, None::<&str>)?,
                    &PredefinedMenuItem::separator(h)?,
                    &MenuItem::with_id(
                        h,
                        "kill",
                        "KILL SWITCH (Ctrl+Alt+Shift+K)",
                        true,
                        None::<&str>,
                    )?,
                    &PredefinedMenuItem::separator(h)?,
                    &MenuItem::with_id(h, "logs", "Open logs", true, None::<&str>)?,
                    &MenuItem::with_id(h, "quit", "Quit tray", true, None::<&str>)?,
                ],
            )?;
            let mut tray = TrayIconBuilder::with_id(TRAY_ID)
                .tooltip("AutoPilot")
                .menu(&menu)
                .show_menu_on_left_click(true)
                .on_menu_event(|app, ev| match ev.id().as_ref() {
                    "status" => open_view(app, "status"),
                    "pair" => open_view(app, "pair"),
                    "devices" => open_view(app, "devices"),
                    "kill" => trigger_kill(app),
                    "logs" => open_logs(),
                    "quit" => app.exit(0),
                    _ => {}
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(h)?;

            // Global shortcuts are unavailable on Wayland (Hyprland): keep running without it.
            if let Err(e) = h.global_shortcut().register(kill_shortcut()) {
                eprintln!(
                    "global kill shortcut unavailable ({e}); bind `autopilotd kill` in your compositor"
                );
            }
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("failed to build tauri app");

    app.run(|_app, ev| {
        // Tray app: closing the last window must not quit.
        if let RunEvent::ExitRequested {
            code: None, api, ..
        } = ev
        {
            api.prevent_exit();
        }
    });
}
