//! Keyboard/mouse injection and window/app management.
//! Backends: Hyprland (hyprctl, wtype/ydotool), X11 + Windows (enigo).
//! CONTRACT: keep these public signatures; implement bodies.
//!
//! Backend selection (runtime):
//! - `HYPRLAND_INSTANCE_SIGNATURE` set: [`hypr::HyprWm`] + [`hypr::WtypeInput`].
//! - other Wayland: spawn-only WM + wtype input.
//! - X11: wmctrl/xdotool WM + enigo input (enigo needs the `x11` cargo feature on Linux).
//! - Windows: PowerShell/cmd WM + enigo input.
//!
//! Nothing here goes through a shell with user text except Hyprland `exec`, whose command
//! string is built from an argv with every word POSIX-quoted ([`util::shell_join`]).
use serde::{Deserialize, Serialize};

pub mod combo;
pub mod desktop;
pub mod hypr;
pub mod other;
pub mod util;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

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

fn env_set(k: &str) -> bool {
    std::env::var_os(k).is_some_and(|v| !v.is_empty())
}

fn is_hyprland() -> bool {
    env_set("HYPRLAND_INSTANCE_SIGNATURE")
}

fn is_wayland() -> bool {
    env_set("WAYLAND_DISPLAY")
}

/// Input backend that always errors with a hint.
pub struct UnsupportedInput(pub &'static str);

impl InputController for UnsupportedInput {
    fn name(&self) -> &'static str {
        "unsupported"
    }
    fn type_text(&self, _: &str) -> anyhow::Result<()> {
        anyhow::bail!("{}", self.0)
    }
    fn key_combo(&self, _: &str) -> anyhow::Result<()> {
        anyhow::bail!("{}", self.0)
    }
    fn click(&self, _: i32, _: i32, _: MouseButton) -> anyhow::Result<()> {
        anyhow::bail!("{}", self.0)
    }
    fn scroll(&self, _: i32) -> anyhow::Result<()> {
        anyhow::bail!("{}", self.0)
    }
}

pub fn detect_input() -> Box<dyn InputController> {
    #[cfg(windows)]
    {
        Box::new(other::enigo_input::EnigoInput)
    }
    #[cfg(not(windows))]
    {
        if is_wayland() {
            if util::which("wtype") {
                return Box::new(hypr::WtypeInput {
                    hyprland: is_hyprland(),
                });
            }
            return Box::new(UnsupportedInput(
                "keyboard input on Wayland needs wtype (and ydotool for the mouse)",
            ));
        }
        #[cfg(all(target_os = "linux", feature = "x11"))]
        {
            Box::new(other::enigo_input::EnigoInput)
        }
        #[cfg(not(all(target_os = "linux", feature = "x11")))]
        {
            Box::new(UnsupportedInput(
                "X11 input requires building agent-input with the `x11` feature",
            ))
        }
    }
}

pub fn detect_wm() -> Box<dyn WindowManager> {
    #[cfg(windows)]
    {
        Box::new(other::WindowsWm)
    }
    #[cfg(not(windows))]
    {
        if is_hyprland() && util::which("hyprctl") {
            Box::new(hypr::HyprWm)
        } else if !is_wayland() && env_set("DISPLAY") {
            Box::new(other::X11Wm)
        } else {
            Box::new(other::SpawnOnlyWm)
        }
    }
}

const TERMINAL_WORDS: &[&str] = &["terminal", "term", "console", "shell", "terminal emulator"];

fn safe_token(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && s.len() <= 128
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "._+-/".contains(c))
}

/// Resolve a user app request to an argv (unix). Order: terminal keywords, desktop entries
/// (fuzzy by Name/id/Exec), then a bare executable on PATH.
pub fn resolve_launch(app: &str) -> anyhow::Result<Vec<String>> {
    resolve_launch_in(app, &desktop::xdg_application_dirs())
}

pub fn resolve_launch_in(app: &str, dirs: &[std::path::PathBuf]) -> anyhow::Result<Vec<String>> {
    let app = app.trim();
    if app.is_empty() || app.len() > 200 || app.chars().any(char::is_control) {
        anyhow::bail!("invalid app name {app:?}");
    }
    let lower = app.to_lowercase();
    if TERMINAL_WORDS.contains(&lower.as_str()) {
        if util::which("omarchy-launch-terminal") {
            return Ok(vec!["omarchy-launch-terminal".into()]);
        }
        if let Ok(t) = std::env::var("TERMINAL")
            && safe_token(&t)
            && util::which(&t)
        {
            return Ok(vec![t]);
        }
        if util::which("xdg-terminal-exec") {
            return Ok(vec!["xdg-terminal-exec".into()]);
        }
    }
    let entries = desktop::load_entries(dirs);
    if let Some(e) = desktop::resolve(app, &entries) {
        let mut argv = e.argv()?;
        if e.terminal && util::which("xdg-terminal-exec") {
            argv.insert(0, "xdg-terminal-exec".into());
        }
        return Ok(argv);
    }
    if safe_token(app) && util::which(app) {
        return Ok(vec![app.to_string()]);
    }
    anyhow::bail!("no application found matching {app:?}")
}

/// Prefix `uwsm-app --` when the session uses uwsm (Omarchy does) so apps get proper
/// systemd scopes; skipped for launchers that already do it.
pub fn wrap_uwsm(argv: Vec<String>) -> Vec<String> {
    wrap_uwsm_if(argv, util::which("uwsm-app"))
}

pub fn wrap_uwsm_if(argv: Vec<String>, has_uwsm: bool) -> Vec<String> {
    let already = argv
        .first()
        .is_some_and(|a| a.starts_with("omarchy-launch") || a.starts_with("uwsm"));
    if !has_uwsm || already {
        return argv;
    }
    let mut v = Vec::with_capacity(argv.len() + 2);
    v.push("uwsm-app".into());
    v.push("--".into());
    v.extend(argv);
    v
}

/// System controls: volume (0-100), mute, brightness, media keys, lock, suspend, notifications, battery.
pub mod system {
    #[cfg(not(windows))]
    use crate::util::spawn_detached;
    use crate::util::{run, run_stdin, which};

    /// argv for an absolute volume (PipeWire first, PulseAudio fallback).
    pub fn volume_set_argv(pct: u8, wpctl: bool) -> (&'static str, Vec<String>) {
        let p = pct.min(100);
        if wpctl {
            (
                "wpctl",
                vec![
                    "set-volume".into(),
                    "@DEFAULT_AUDIO_SINK@".into(),
                    format!("{p}%"),
                ],
            )
        } else {
            (
                "pactl",
                vec![
                    "set-sink-volume".into(),
                    "@DEFAULT_SINK@".into(),
                    format!("{p}%"),
                ],
            )
        }
    }

    pub fn volume_change_argv(delta: i8, wpctl: bool) -> (&'static str, Vec<String>) {
        let mag = delta.unsigned_abs().min(100);
        let up = delta >= 0;
        if wpctl {
            (
                "wpctl",
                vec![
                    "set-volume".into(),
                    "-l".into(),
                    "1.0".into(),
                    "@DEFAULT_AUDIO_SINK@".into(),
                    format!("{mag}%{}", if up { '+' } else { '-' }),
                ],
            )
        } else {
            (
                "pactl",
                vec![
                    "set-sink-volume".into(),
                    "@DEFAULT_SINK@".into(),
                    format!("{}{mag}%", if up { '+' } else { '-' }),
                ],
            )
        }
    }

    pub fn media_playerctl_arg(action: &str) -> anyhow::Result<&'static str> {
        Ok(match action {
            "play_pause" | "play-pause" | "toggle" => "play-pause",
            "next" => "next",
            "previous" | "prev" => "previous",
            other => anyhow::bail!("unknown media action {other:?}"),
        })
    }

    /// (percent, on external power) from sysfs strings.
    pub fn parse_battery(capacity: &str, status: &str, ac_online: bool) -> Option<(u8, bool)> {
        let pct: u16 = capacity.trim().parse().ok()?;
        let st = status.trim();
        let charging = ac_online || st == "Charging" || st == "Full";
        Some((pct.min(100) as u8, charging))
    }

    #[cfg(not(windows))]
    fn audio_cmd(f: impl Fn(bool) -> (&'static str, Vec<String>)) -> anyhow::Result<()> {
        let wp = which("wpctl");
        if !wp && !which("pactl") {
            anyhow::bail!("no audio control tool found (install wireplumber or pulseaudio-utils)");
        }
        let (prog, args) = f(wp);
        run(prog, &args).map(|_| ())
    }

    #[cfg(windows)]
    fn tap(key: &str) -> anyhow::Result<()> {
        crate::detect_input().key_combo(key)
    }

    #[cfg(windows)]
    fn powershell(script: &str) -> anyhow::Result<String> {
        run(
            "powershell",
            &["-NoProfile", "-NonInteractive", "-Command", script],
        )
    }

    pub fn set_volume(pct: u8) -> anyhow::Result<()> {
        #[cfg(not(windows))]
        {
            audio_cmd(|wp| volume_set_argv(pct, wp))
        }
        #[cfg(windows)]
        {
            // No absolute API without COM; go to 0 then step up (each key = 2%).
            for _ in 0..50 {
                tap("volumedown")?;
            }
            for _ in 0..(pct.min(100) / 2) {
                tap("volumeup")?;
            }
            Ok(())
        }
    }

    pub fn change_volume(delta: i8) -> anyhow::Result<()> {
        #[cfg(not(windows))]
        {
            audio_cmd(|wp| volume_change_argv(delta, wp))
        }
        #[cfg(windows)]
        {
            let key = if delta >= 0 { "volumeup" } else { "volumedown" };
            for _ in 0..(delta.unsigned_abs() / 2).max(1) {
                tap(key)?;
            }
            Ok(())
        }
    }

    pub fn toggle_mute() -> anyhow::Result<()> {
        #[cfg(not(windows))]
        {
            audio_cmd(|wp| {
                if wp {
                    (
                        "wpctl",
                        vec![
                            "set-mute".into(),
                            "@DEFAULT_AUDIO_SINK@".into(),
                            "toggle".into(),
                        ],
                    )
                } else {
                    (
                        "pactl",
                        vec![
                            "set-sink-mute".into(),
                            "@DEFAULT_SINK@".into(),
                            "toggle".into(),
                        ],
                    )
                }
            })
        }
        #[cfg(windows)]
        {
            tap("mute")
        }
    }

    pub fn set_brightness(pct: u8) -> anyhow::Result<()> {
        let p = pct.clamp(1, 100);
        #[cfg(not(windows))]
        {
            if !which("brightnessctl") {
                anyhow::bail!("install brightnessctl to control brightness");
            }
            run("brightnessctl", &["-q", "set", &format!("{p}%")]).map(|_| ())
        }
        #[cfg(windows)]
        {
            // p is a validated integer; safe to interpolate.
            powershell(&format!(
                "(Get-WmiObject -Namespace root/WMI -Class WmiMonitorBrightnessMethods)\
                 .WmiSetBrightness(1,{p})"
            ))
            .map(|_| ())
        }
    }

    /// "play_pause" | "next" | "previous" (playerctl / media keys)
    pub fn media(action: &str) -> anyhow::Result<()> {
        let arg = media_playerctl_arg(action)?;
        #[cfg(not(windows))]
        {
            if which("playerctl") {
                return run("playerctl", &[arg]).map(|_| ());
            }
            mpris_dbus(arg)
        }
        #[cfg(windows)]
        {
            tap(match arg {
                "play-pause" => "playpause",
                "next" => "next",
                _ => "prev",
            })
        }
    }

    /// playerctl-less fallback: call the first MPRIS player over the session bus.
    #[cfg(not(windows))]
    fn mpris_dbus(arg: &str) -> anyhow::Result<()> {
        let method = match arg {
            "play-pause" => "PlayPause",
            "next" => "Next",
            _ => "Previous",
        };
        let names = run(
            "dbus-send",
            &[
                "--session",
                "--print-reply",
                "--dest=org.freedesktop.DBus",
                "/org/freedesktop/DBus",
                "org.freedesktop.DBus.ListNames",
            ],
        )?;
        let player = names
            .lines()
            .filter_map(|l| l.trim().strip_prefix("string \""))
            .filter_map(|l| l.strip_suffix('"'))
            .find(|n| {
                n.starts_with("org.mpris.MediaPlayer2.")
                    && n.chars()
                        .all(|c| c.is_ascii_alphanumeric() || "._-".contains(c))
            })
            .ok_or_else(|| anyhow::anyhow!("no media player running (MPRIS)"))?;
        run(
            "dbus-send",
            &[
                "--session",
                "--type=method_call",
                &format!("--dest={player}"),
                "/org/mpris/MediaPlayer2",
                &format!("org.mpris.MediaPlayer2.Player.{method}"),
            ],
        )
        .map(|_| ())
    }

    pub fn lock_screen() -> anyhow::Result<()> {
        #[cfg(not(windows))]
        {
            if which("omarchy-system-lock") {
                return spawn_detached(&["omarchy-system-lock".into()]);
            }
            if crate::is_hyprland() && which("hyprlock") {
                return spawn_detached(&["hyprlock".into()]);
            }
            run("loginctl", &["lock-session"]).map(|_| ())
        }
        #[cfg(windows)]
        {
            run("rundll32.exe", &["user32.dll,LockWorkStation"]).map(|_| ())
        }
    }

    pub fn suspend() -> anyhow::Result<()> {
        #[cfg(not(windows))]
        {
            run("systemctl", &["suspend"]).map(|_| ())
        }
        #[cfg(windows)]
        {
            run("rundll32.exe", &["powrprof.dll,SetSuspendState", "0,1,0"]).map(|_| ())
        }
    }

    pub fn battery() -> anyhow::Result<Option<(u8, bool)>> {
        #[cfg(not(windows))]
        {
            battery_sysfs(std::path::Path::new("/sys/class/power_supply"))
        }
        #[cfg(windows)]
        {
            let out = powershell(
                "$b = Get-CimInstance Win32_Battery | Select-Object -First 1; \
                 if ($b) { \"$($b.EstimatedChargeRemaining) $($b.BatteryStatus)\" }",
            )?;
            let mut it = out.split_whitespace();
            match (it.next(), it.next()) {
                (Some(p), Some(s)) => {
                    let pct: u8 = p.parse::<u16>()?.min(100) as u8;
                    // BatteryStatus 2 = on AC; 6-9 = charging variants.
                    let st: u16 = s.parse().unwrap_or(1);
                    Ok(Some((pct, st == 2 || (6..=9).contains(&st))))
                }
                _ => Ok(None),
            }
        }
    }

    /// Reads BAT*/capacity + status and any Mains `online` under `root`.
    pub fn battery_sysfs(root: &std::path::Path) -> anyhow::Result<Option<(u8, bool)>> {
        let Ok(rd) = std::fs::read_dir(root) else {
            return Ok(None);
        };
        let mut bat = None;
        let mut ac = false;
        for e in rd.flatten() {
            let p = e.path();
            let name = e.file_name().to_string_lossy().to_string();
            let ty = std::fs::read_to_string(p.join("type")).unwrap_or_default();
            if ty.trim() == "Mains" {
                ac |= std::fs::read_to_string(p.join("online")).is_ok_and(|s| s.trim() == "1");
            } else if bat.is_none() && (name.starts_with("BAT") || ty.trim() == "Battery") {
                if let Ok(cap) = std::fs::read_to_string(p.join("capacity")) {
                    let st = std::fs::read_to_string(p.join("status")).unwrap_or_default();
                    bat = Some((cap, st));
                }
            }
        }
        Ok(bat.and_then(|(c, s)| parse_battery(&c, &s, ac)))
    }

    pub fn clipboard_get() -> anyhow::Result<String> {
        #[cfg(not(windows))]
        {
            if crate::is_wayland() && which("wl-paste") {
                let out = std::process::Command::new("wl-paste")
                    .args(["--no-newline", "--type", "text"])
                    .stdin(std::process::Stdio::null())
                    .output()?;
                // Exit 1 with "Nothing is copied" = empty clipboard.
                return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
            }
            if which("xclip") {
                return run("xclip", &["-selection", "clipboard", "-o"]);
            }
            anyhow::bail!("install wl-clipboard (Wayland) or xclip (X11) for clipboard access")
        }
        #[cfg(windows)]
        {
            powershell("Get-Clipboard -Raw")
        }
    }

    pub fn clipboard_set(s: &str) -> anyhow::Result<()> {
        #[cfg(not(windows))]
        {
            if crate::is_wayland() && which("wl-copy") {
                return run_stdin("wl-copy", &["--type", "text/plain"], s.as_bytes());
            }
            if which("xclip") {
                return run_stdin("xclip", &["-selection", "clipboard", "-i"], s.as_bytes());
            }
            anyhow::bail!("install wl-clipboard (Wayland) or xclip (X11) for clipboard access")
        }
        #[cfg(windows)]
        {
            run_stdin(
                "powershell",
                &[
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Set-Clipboard -Value ([Console]::In.ReadToEnd())",
                ],
                s.as_bytes(),
            )
        }
    }

    pub fn notify_argv(title: &str, body: &str) -> Vec<String> {
        vec![
            "-a".into(),
            "AutoPilot".into(),
            "--".into(),
            title.into(),
            body.into(),
        ]
    }

    pub fn notify_local(title: &str, body: &str) -> anyhow::Result<()> {
        #[cfg(not(windows))]
        {
            if !which("notify-send") {
                anyhow::bail!("install libnotify (notify-send) for local notifications");
            }
            run("notify-send", &notify_argv(title, body)).map(|_| ())
        }
        #[cfg(windows)]
        {
            let _ = (title, body);
            anyhow::bail!("local notifications are not supported on Windows yet")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::system::*;
    use super::*;

    #[test]
    fn audio_argv() {
        assert_eq!(
            volume_set_argv(150, true),
            (
                "wpctl",
                vec![
                    "set-volume".into(),
                    "@DEFAULT_AUDIO_SINK@".into(),
                    "100%".into()
                ]
            )
        );
        assert_eq!(volume_change_argv(-5, true).1.last().unwrap(), "5%-");
        assert_eq!(
            volume_change_argv(10, false).1,
            ["set-sink-volume", "@DEFAULT_SINK@", "+10%"]
        );
        assert_eq!(volume_change_argv(i8::MIN, false).1[2], "-100%");
        assert_eq!(media_playerctl_arg("play_pause").unwrap(), "play-pause");
        assert!(media_playerctl_arg("rm -rf").is_err());
        assert_eq!(notify_argv("-t", "b"), ["-a", "AutoPilot", "--", "-t", "b"]);
    }

    #[test]
    fn battery_parsing() {
        assert_eq!(
            parse_battery("87\n", "Discharging\n", false),
            Some((87, false))
        );
        assert_eq!(parse_battery("100", "Full", false), Some((100, true)));
        assert_eq!(parse_battery("40", "Not charging", true), Some((40, true)));
        assert_eq!(parse_battery("x", "Full", false), None);

        let tmp = tempfile::tempdir().unwrap();
        let b = tmp.path().join("BAT1");
        let ac = tmp.path().join("ACAD");
        std::fs::create_dir_all(&b).unwrap();
        std::fs::create_dir_all(&ac).unwrap();
        std::fs::write(b.join("type"), "Battery\n").unwrap();
        std::fs::write(b.join("capacity"), "55\n").unwrap();
        std::fs::write(b.join("status"), "Discharging\n").unwrap();
        std::fs::write(ac.join("type"), "Mains\n").unwrap();
        std::fs::write(ac.join("online"), "0\n").unwrap();
        assert_eq!(battery_sysfs(tmp.path()).unwrap(), Some((55, false)));
        assert_eq!(battery_sysfs(&tmp.path().join("nope")).unwrap(), None);
    }

    #[test]
    fn uwsm_wrapping() {
        let v = |s: &[&str]| s.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            wrap_uwsm_if(v(&["firefox"]), true),
            ["uwsm-app", "--", "firefox"]
        );
        assert_eq!(wrap_uwsm_if(v(&["firefox"]), false), ["firefox"]);
        assert_eq!(
            wrap_uwsm_if(v(&["omarchy-launch-terminal"]), true),
            ["omarchy-launch-terminal"]
        );
    }

    #[test]
    fn launch_resolution_rejects_junk() {
        let none: Vec<std::path::PathBuf> = vec![];
        assert!(resolve_launch_in("", &none).is_err());
        assert!(resolve_launch_in("a\nb", &none).is_err());
        assert!(resolve_launch_in("firefox; rm -rf ~", &none).is_err());
        assert!(resolve_launch_in("--help", &none).is_err());
        // bare executable on PATH
        assert_eq!(resolve_launch_in("sh", &none).unwrap(), ["sh"]);
    }

    /// Live, read-only.
    #[test]
    fn live_battery_and_windows() {
        let b = system::battery().unwrap();
        eprintln!("battery: {b:?}");
        if std::path::Path::new("/sys/class/power_supply/BAT1/capacity").exists() {
            assert!(b.is_some());
        }
        if is_hyprland() {
            let wm = detect_wm();
            assert_eq!(wm.name(), "hyprland");
            let wins = wm.list_windows().unwrap();
            eprintln!(
                "{} windows; focused: {:?}",
                wins.len(),
                wins.iter().find(|w| w.focused)
            );
            assert!(wins.iter().filter(|w| w.focused).count() <= 1);
            assert_eq!(detect_input().name(), "wtype");
            // Resolution only (nothing is launched).
            eprintln!("terminal -> {:?}", resolve_launch("terminal"));
            eprintln!("chrome -> {:?}", resolve_launch("chrome"));
        }
    }
}
