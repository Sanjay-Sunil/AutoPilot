//! Keyboard/mouse injection and window/app management.
//! Backends: Hyprland (hyprctl, wtype/ydotool), X11 + Windows (enigo).
//! CONTRACT: keep these public signatures; implement bodies.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton { Left, Right, Middle }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WindowInfo {
    pub id: String,
    pub app: String,
    pub title: String,
    pub workspace: String,
    pub focused: bool,
}

pub trait InputController: Send + Sync {
    fn name(&self) -> &'static str;
    fn type_text(&self, text: &str) -> anyhow::Result<()>;
    /// Combos like "ctrl+l", "super+1", "enter", "alt+tab".
    fn key_combo(&self, combo: &str) -> anyhow::Result<()>;
    fn click(&self, x: i32, y: i32, button: MouseButton) -> anyhow::Result<()>;
    fn scroll(&self, dy: i32) -> anyhow::Result<()>;
}

pub trait WindowManager: Send + Sync {
    fn name(&self) -> &'static str;
    fn list_windows(&self) -> anyhow::Result<Vec<WindowInfo>>;
    /// Focus the first window whose app/title matches (case-insensitive). Ok(false) if none.
    fn focus(&self, query: &str) -> anyhow::Result<bool>;
    /// Launch an app by name/desktop id/command (detached, no shell interpolation).
    fn launch(&self, app: &str) -> anyhow::Result<()>;
    fn close_focused(&self) -> anyhow::Result<()>;
    fn switch_workspace(&self, ws: &str) -> anyhow::Result<()>;
}

pub fn detect_input() -> Box<dyn InputController> { todo!() }
pub fn detect_wm() -> Box<dyn WindowManager> { todo!() }

/// System controls: volume (0-100), mute, brightness, media keys, lock, suspend, notifications, battery.
pub mod system {
    pub fn set_volume(_pct: u8) -> anyhow::Result<()> { todo!() }
    pub fn change_volume(_delta: i8) -> anyhow::Result<()> { todo!() }
    pub fn toggle_mute() -> anyhow::Result<()> { todo!() }
    pub fn set_brightness(_pct: u8) -> anyhow::Result<()> { todo!() }
    /// "play_pause" | "next" | "previous" (playerctl / media keys)
    pub fn media(_action: &str) -> anyhow::Result<()> { todo!() }
    pub fn lock_screen() -> anyhow::Result<()> { todo!() }
    pub fn suspend() -> anyhow::Result<()> { todo!() }
    pub fn battery() -> anyhow::Result<Option<(u8, bool)>> { todo!() }
    pub fn clipboard_get() -> anyhow::Result<String> { todo!() }
    pub fn clipboard_set(_s: &str) -> anyhow::Result<()> { todo!() }
    pub fn notify_local(_title: &str, _body: &str) -> anyhow::Result<()> { todo!() }
}
