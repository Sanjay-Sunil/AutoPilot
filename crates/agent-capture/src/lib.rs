//! Screen capture to JPEG. Backends: Hyprland/wlroots (grim), X11 (xcap), Windows (xcap).
//! CONTRACT: keep these public signatures; implement bodies.

#[derive(Debug, Clone)]
pub struct Frame {
    pub jpeg: Vec<u8>,
    pub width: u32,
    pub height: u32,
}

pub trait ScreenCapturer: Send + Sync {
    fn name(&self) -> &'static str;
    /// Capture the focused output, downscale to `max_width` (keep aspect), encode JPEG at `quality`.
    fn capture_jpeg(&self, max_width: u32, quality: u8) -> anyhow::Result<Frame>;
}

/// Pick the best backend for this session (WAYLAND_DISPLAY+grim, DISPLAY, Windows).
pub fn detect() -> Box<dyn ScreenCapturer> { todo!() }
