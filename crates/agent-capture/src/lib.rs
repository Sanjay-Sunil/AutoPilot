//! Screen capture to JPEG. Backends: Hyprland/wlroots (grim), X11 (xcap), Windows (xcap).
//! CONTRACT: keep these public signatures; implement bodies.
//!
//! Backend notes:
//! - Hyprland: `grim -o <focused output> -t jpeg -q Q -s S -` — grim scales and encodes in one
//!   step and we only parse the JPEG header for dimensions, so Rust never decodes pixels.
//! - Other wlroots compositors: same, without `-o` (whole layout).
//! - X11 (Linux, cargo feature `x11`) and Windows: `xcap` primary monitor, `image` Triangle
//!   resize and JPEG encode.
//!
//! Measured on the dev laptop (Hyprland 0.56.2, 1920x1080 eDP-1, grim, debug build, q=70,
//! while the machine was under heavy parallel-build load, loadavg ~14): avg ~211 ms for
//! 1280x720 (~86 KiB) and ~199 ms for 640x360 (~26 KiB). Nearly all of it is grim itself
//! (full-res screencopy + pixman scale + libjpeg); our Rust side does no pixel work. While the
//! output was DPMS-off, screencopy stalled for minutes, hence the hard [`GRIM_TIMEOUT`].

use std::io::Read;
use std::process::{Command, Stdio};

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
pub fn detect() -> Box<dyn ScreenCapturer> {
    let has = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    #[cfg(unix)]
    {
        if has("HYPRLAND_INSTANCE_SIGNATURE") && which("grim") {
            return Box::new(GrimCapturer { hyprland: true });
        }
        if has("WAYLAND_DISPLAY") {
            if which("grim") {
                return Box::new(GrimCapturer { hyprland: false });
            }
            if !has("DISPLAY") {
                return Box::new(Unsupported(
                    "Wayland session without grim: install grim (wlroots compositors); \
                     xdg-desktop-portal screencast support is planned for a later release",
                ));
            }
        }
    }
    #[cfg(any(windows, all(target_os = "linux", feature = "x11")))]
    {
        Box::new(xcap_backend::XcapCapturer)
    }
    #[cfg(not(any(windows, all(target_os = "linux", feature = "x11"))))]
    {
        let _ = has;
        Box::new(Unsupported(
            "no screen capture backend: on Wayland install grim; for X11 rebuild agent-capture \
             with the `x11` feature",
        ))
    }
}

/// Backend that always fails with an explanatory message.
pub struct Unsupported(pub &'static str);

impl ScreenCapturer for Unsupported {
    fn name(&self) -> &'static str {
        "unsupported"
    }
    fn capture_jpeg(&self, _max_width: u32, _quality: u8) -> anyhow::Result<Frame> {
        anyhow::bail!("{}", self.0)
    }
}

#[cfg(unix)]
fn which(bin: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|d| {
            std::fs::metadata(d.join(bin))
                .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        })
    })
}

// ---------------------------------------------------------------- grim (wlroots / Hyprland)

/// grim-based capturer. With `hyprland`, captures only the focused monitor.
pub struct GrimCapturer {
    pub hyprland: bool,
}

/// Focused-monitor geometry from `hyprctl -j monitors`.
#[derive(Debug, Clone, PartialEq)]
pub struct MonitorInfo {
    pub name: String,
    /// Logical width (pixels / scale, rotated if needed). This is what grim `-s 1` produces.
    pub logical_width: f64,
    /// Native output scale; capturing above this would upscale.
    pub scale: f64,
    /// False while the output is in DPMS-off (display asleep); screencopy would stall.
    pub dpms_on: bool,
}

#[derive(serde::Deserialize)]
struct HyprMonitor {
    name: String,
    width: f64,
    height: f64,
    #[serde(default = "one")]
    scale: f64,
    #[serde(default)]
    transform: u32,
    #[serde(default)]
    focused: bool,
    #[serde(default)]
    disabled: bool,
    #[serde(default = "yes", rename = "dpmsStatus")]
    dpms_status: bool,
}

fn yes() -> bool {
    true
}

fn one() -> f64 {
    1.0
}

/// Parse `hyprctl -j monitors` output and return the focused (or first enabled) monitor.
pub fn parse_focused_monitor(json: &[u8]) -> Option<MonitorInfo> {
    let mons: Vec<HyprMonitor> = serde_json::from_slice(json).ok()?;
    let m = mons
        .iter()
        .find(|m| m.focused && !m.disabled)
        .or_else(|| mons.iter().find(|m| !m.disabled))?;
    let scale = if m.scale > 0.0 { m.scale } else { 1.0 };
    let px_w = if m.transform % 2 == 1 {
        m.height
    } else {
        m.width
    };
    Some(MonitorInfo {
        name: m.name.clone(),
        logical_width: px_w / scale,
        scale,
        dpms_on: m.dpms_status,
    })
}

/// grim `-s` factor so the output is at most `max_width` wide (never upscales past native).
pub fn grim_scale(logical_width: f64, native_scale: f64, max_width: u32) -> f64 {
    if logical_width <= 0.0 || max_width == 0 {
        return 1.0;
    }
    // +0.25 px so grim's float->int conversion lands exactly on max_width (not max_width-1).
    let s = ((max_width as f64 + 0.25) / logical_width).min(native_scale);
    ((s * 1e6).floor() / 1e6).max(0.01)
}

/// Build grim argv (without the program name).
pub fn grim_args(output: Option<&str>, quality: u8, scale: Option<f64>) -> Vec<String> {
    let mut a = Vec::with_capacity(9);
    if let Some(o) = output {
        a.push("-o".into());
        a.push(o.into());
    }
    a.push("-t".into());
    a.push("jpeg".into());
    a.push("-q".into());
    a.push(quality.min(100).to_string());
    if let Some(s) = scale {
        a.push("-s".into());
        a.push(format!("{s:.6}"));
    }
    a.push("-".into());
    a
}

fn focused_hypr_monitor() -> Option<MonitorInfo> {
    let out = Command::new("hyprctl")
        .args(["-j", "monitors"])
        .stderr(Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_focused_monitor(&out.stdout)
}

/// Hard cap on one grim run. Screencopy can stall (e.g. output in DPMS-off), and a stuck
/// capture must not wedge the agent.
pub const GRIM_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

fn run_grim(args: &[String]) -> anyhow::Result<Vec<u8>> {
    let mut child = Command::new("grim")
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to run grim: {e}"))?;
    let mut stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut buf = Vec::with_capacity(256 * 1024);
        let r = stdout.read_to_end(&mut buf).map(|_| buf);
        let _ = tx.send(r);
    });
    let buf = match rx.recv_timeout(GRIM_TIMEOUT) {
        Ok(r) => r?,
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!(
                "grim timed out after {GRIM_TIMEOUT:?} (is the display off / DPMS disabled?)"
            );
        }
    };
    let mut err = String::new();
    if let Some(mut e) = child.stderr.take() {
        let _ = e.read_to_string(&mut err);
    }
    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("grim failed ({status}): {}", err.trim());
    }
    Ok(buf)
}

impl ScreenCapturer for GrimCapturer {
    fn name(&self) -> &'static str {
        if self.hyprland {
            "hyprland-grim"
        } else {
            "wlroots-grim"
        }
    }

    fn capture_jpeg(&self, max_width: u32, quality: u8) -> anyhow::Result<Frame> {
        let mon = if self.hyprland {
            focused_hypr_monitor()
        } else {
            None
        };
        let jpeg = match &mon {
            Some(m) => {
                if !m.dpms_on {
                    anyhow::bail!(
                        "display {} is asleep (DPMS off); wake it before capturing",
                        m.name
                    );
                }
                let s = grim_scale(m.logical_width, m.scale, max_width);
                run_grim(&grim_args(Some(&m.name), quality, Some(s)))?
            }
            None => {
                // Unknown geometry: capture at 1x, downscale only if too wide (rare path).
                let first = run_grim(&grim_args(None, quality, Some(1.0)))?;
                let (w, _) = jpeg_dimensions(&first)?;
                if max_width > 0 && w > max_width {
                    let s = grim_scale(w as f64, 1.0, max_width);
                    run_grim(&grim_args(None, quality, Some(s)))?
                } else {
                    first
                }
            }
        };
        let (width, height) = jpeg_dimensions(&jpeg)?;
        Ok(Frame {
            jpeg,
            width,
            height,
        })
    }
}

/// Read width/height from a JPEG's SOF marker without decoding.
pub fn jpeg_dimensions(data: &[u8]) -> anyhow::Result<(u32, u32)> {
    if data.len() < 4 || data[0] != 0xFF || data[1] != 0xD8 {
        anyhow::bail!("not a JPEG (missing SOI)");
    }
    let mut i = 2;
    while i + 4 <= data.len() {
        if data[i] != 0xFF {
            anyhow::bail!("corrupt JPEG marker stream at {i}");
        }
        let marker = data[i + 1];
        // Fill bytes / standalone markers.
        if marker == 0xFF {
            i += 1;
            continue;
        }
        if marker == 0xD8 || marker == 0x01 || (0xD0..=0xD7).contains(&marker) {
            i += 2;
            continue;
        }
        let len = u16::from_be_bytes([data[i + 2], data[i + 3]]) as usize;
        let is_sof = matches!(marker, 0xC0..=0xCF) && !matches!(marker, 0xC4 | 0xC8 | 0xCC);
        if is_sof {
            if i + 9 > data.len() {
                break;
            }
            let h = u16::from_be_bytes([data[i + 5], data[i + 6]]) as u32;
            let w = u16::from_be_bytes([data[i + 7], data[i + 8]]) as u32;
            return Ok((w, h));
        }
        if marker == 0xDA || marker == 0xD9 {
            break;
        }
        i += 2 + len;
    }
    anyhow::bail!("JPEG has no SOF marker")
}

// ---------------------------------------------------------------- xcap (X11 / Windows)

#[cfg(any(windows, all(target_os = "linux", feature = "x11")))]
mod xcap_backend {
    use super::{Frame, ScreenCapturer};
    use image::{DynamicImage, codecs::jpeg::JpegEncoder, imageops::FilterType};

    pub struct XcapCapturer;

    impl ScreenCapturer for XcapCapturer {
        fn name(&self) -> &'static str {
            if cfg!(windows) {
                "windows-xcap"
            } else {
                "x11-xcap"
            }
        }

        fn capture_jpeg(&self, max_width: u32, quality: u8) -> anyhow::Result<Frame> {
            let monitors = xcap::Monitor::all()?;
            let mon = monitors
                .iter()
                .find(|m| m.is_primary().unwrap_or(false))
                .or_else(|| monitors.first())
                .ok_or_else(|| anyhow::anyhow!("no monitors found"))?;
            let rgba = mon.capture_image()?;
            let mut img = DynamicImage::ImageRgba8(rgba);
            if max_width > 0 && img.width() > max_width {
                let h = ((img.height() as u64 * max_width as u64) / img.width() as u64).max(1);
                img = img.resize_exact(max_width, h as u32, FilterType::Triangle);
            }
            let rgb = img.into_rgb8();
            let (width, height) = rgb.dimensions();
            let mut jpeg = Vec::with_capacity((width * height / 4) as usize);
            JpegEncoder::new_with_quality(&mut jpeg, quality.clamp(1, 100)).encode_image(&rgb)?;
            Ok(Frame {
                jpeg,
                width,
                height,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MONITORS: &str = r#"[
      {"id":0,"name":"eDP-1","width":1920,"height":1080,"scale":1,"transform":0,"focused":false,"disabled":false},
      {"id":1,"name":"DP-2","width":3840,"height":2160,"scale":2,"transform":1,"focused":true,"disabled":false}
    ]"#;

    #[test]
    fn reads_dpms_status() {
        let asleep =
            br#"[{"name":"eDP-1","width":1920,"height":1080,"focused":true,"dpmsStatus":false}]"#;
        assert!(!parse_focused_monitor(asleep).unwrap().dpms_on);
        assert!(parse_focused_monitor(MONITORS.as_bytes()).unwrap().dpms_on);
    }

    #[test]
    fn parses_focused_monitor() {
        let m = parse_focused_monitor(MONITORS.as_bytes()).unwrap();
        assert_eq!(m.name, "DP-2");
        // rotated: height/scale
        assert_eq!(m.logical_width, 1080.0);
        assert_eq!(m.scale, 2.0);
        assert!(parse_focused_monitor(b"not json").is_none());
        assert!(parse_focused_monitor(b"[]").is_none());
    }

    #[test]
    fn scale_math() {
        assert!((grim_scale(1920.0, 1.0, 1280) - 0.666797).abs() < 1e-5);
        assert_eq!(grim_scale(1920.0, 1.0, 4000), 1.0);
        assert_eq!(grim_scale(1280.0, 2.0, 2560), 2.0);
        assert_eq!((1920.0 * grim_scale(1920.0, 1.0, 640)) as u32, 640);
    }

    #[test]
    fn builds_grim_argv() {
        assert_eq!(
            grim_args(Some("eDP-1"), 70, Some(0.5)),
            [
                "-o", "eDP-1", "-t", "jpeg", "-q", "70", "-s", "0.500000", "-"
            ]
        );
        assert_eq!(grim_args(None, 200, None), ["-t", "jpeg", "-q", "100", "-"]);
    }

    #[test]
    fn jpeg_header_parse() {
        // SOI, APP0(len 4: 2 payload bytes), SOF0 (h=480, w=640), EOI
        let data = [
            0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x04, 0x00, 0x00, 0xFF, 0xC0, 0x00, 0x11, 0x08, 0x01,
            0xE0, 0x02, 0x80, 0x03, 0xFF, 0xD9,
        ];
        assert_eq!(jpeg_dimensions(&data).unwrap(), (640, 480));
        assert!(jpeg_dimensions(b"\x89PNG....").is_err());
        assert!(jpeg_dimensions(&[0xFF, 0xD8, 0xFF, 0xD9]).is_err());
    }

    /// Live: only runs inside a Hyprland session with grim. Read-only (screenshot).
    #[test]
    fn live_capture_hyprland() {
        if std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_none() || !which("grim") {
            eprintln!("skipping: not in Hyprland");
            return;
        }
        if focused_hypr_monitor().is_some_and(|m| !m.dpms_on) {
            eprintln!("skipping: display asleep (DPMS off)");
            return;
        }
        let cap = detect();
        assert_eq!(cap.name(), "hyprland-grim");
        for w in [1280u32, 640] {
            let _ = cap.capture_jpeg(w, 70).unwrap(); // warm-up
            let n = 3;
            let t = std::time::Instant::now();
            let mut f = None;
            for _ in 0..n {
                f = Some(cap.capture_jpeg(w, 70).unwrap());
            }
            let ms = t.elapsed().as_secs_f64() * 1000.0 / n as f64;
            let f = f.unwrap();
            assert_eq!(&f.jpeg[..3], &[0xFF, 0xD8, 0xFF]);
            assert!(
                f.width <= w && f.width + 2 >= w.min(1920),
                "width {} for {w}",
                f.width
            );
            assert!(f.height > 0);
            eprintln!(
                "capture max_width={w}: {}x{} {} KiB avg {ms:.1} ms",
                f.width,
                f.height,
                f.jpeg.len() / 1024
            );
        }
    }
}
