//! Non-Hyprland backends: X11 window management (wmctrl/xdotool), generic spawn-only WM,
//! Windows WM (PowerShell / cmd), and enigo input for X11 + Windows.
use crate::util::{run, spawn_detached, which};
use crate::{WindowInfo, WindowManager};

fn unsupported<T>(what: &str, backend: &str) -> anyhow::Result<T> {
    anyhow::bail!("{what} is not supported by the {backend} backend")
}

/// Launch-only window manager (other Wayland compositors, or no tools available).
pub struct SpawnOnlyWm;

impl WindowManager for SpawnOnlyWm {
    fn name(&self) -> &'static str {
        "spawn-only"
    }
    fn list_windows(&self) -> anyhow::Result<Vec<WindowInfo>> {
        unsupported("listing windows", "spawn-only")
    }
    fn focus(&self, _query: &str) -> anyhow::Result<bool> {
        unsupported("focusing windows", "spawn-only")
    }
    fn launch(&self, app: &str) -> anyhow::Result<()> {
        spawn_detached(&crate::wrap_uwsm(crate::resolve_launch(app)?))
    }
    fn close_focused(&self) -> anyhow::Result<()> {
        unsupported("closing windows", "spawn-only")
    }
    fn switch_workspace(&self, _ws: &str) -> anyhow::Result<()> {
        unsupported("switching workspaces", "spawn-only")
    }
}

/// Parse `wmctrl -lx`: `0x0400000a  0 firefox.Firefox  host  Title words`.
pub fn parse_wmctrl(out: &str, active: Option<u64>) -> Vec<WindowInfo> {
    out.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let id = it.next()?;
            let desk = it.next()?;
            let class = it.next()?;
            let _host = it.next()?;
            let title = it.collect::<Vec<_>>().join(" ");
            if desk == "-1" {
                return None; // sticky panels/desktop
            }
            let num = u64::from_str_radix(id.trim_start_matches("0x"), 16).ok();
            Some(WindowInfo {
                id: id.to_string(),
                app: class.rsplit('.').next().unwrap_or(class).to_string(),
                title,
                workspace: desk
                    .parse::<i64>()
                    .map(|d| (d + 1).to_string())
                    .unwrap_or_default(),
                focused: num.is_some() && num == active,
            })
        })
        .collect()
}

/// X11 window manager via wmctrl (+ xdotool for the active window when present).
pub struct X11Wm;

fn x11_active() -> Option<u64> {
    if which("xdotool") {
        run("xdotool", &["getactivewindow"])
            .ok()?
            .trim()
            .parse()
            .ok()
    } else {
        None
    }
}

impl WindowManager for X11Wm {
    fn name(&self) -> &'static str {
        "x11-wmctrl"
    }
    fn list_windows(&self) -> anyhow::Result<Vec<WindowInfo>> {
        if !which("wmctrl") {
            anyhow::bail!("install wmctrl for window listing on X11");
        }
        Ok(parse_wmctrl(&run("wmctrl", &["-lx"])?, x11_active()))
    }
    fn focus(&self, query: &str) -> anyhow::Result<bool> {
        let wins = self.list_windows()?;
        match crate::hypr::find_window(&wins, query) {
            Some(w) => run("wmctrl", &["-i", "-a", &w.id]).map(|_| true),
            None => Ok(false),
        }
    }
    fn launch(&self, app: &str) -> anyhow::Result<()> {
        spawn_detached(&crate::resolve_launch(app)?)
    }
    fn close_focused(&self) -> anyhow::Result<()> {
        if which("wmctrl") {
            run("wmctrl", &["-c", ":ACTIVE:"]).map(|_| ())
        } else if which("xdotool") {
            run("xdotool", &["getactivewindow", "windowclose"]).map(|_| ())
        } else {
            anyhow::bail!("install wmctrl or xdotool to close windows on X11")
        }
    }
    fn switch_workspace(&self, ws: &str) -> anyhow::Result<()> {
        let n: u32 = ws
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("X11 workspaces are numbers (1-based), got {ws:?}"))?;
        if n == 0 {
            anyhow::bail!("workspaces are 1-based");
        }
        run("wmctrl", &["-s", &(n - 1).to_string()]).map(|_| ())
    }
}

/// argv for launching on Windows via `cmd /c start "" <app> [args]` (no shell string joining
/// by us; `start` gets each piece as a separate argument).
pub fn windows_start_argv(argv: &[String]) -> Vec<String> {
    // Empty title arg: std's Windows arg quoting renders "" for an empty string.
    let mut v = vec!["cmd".into(), "/c".into(), "start".into(), String::new()];
    v.extend(argv.iter().cloned());
    v
}

/// Windows window manager via PowerShell (no extra crates).
#[cfg(windows)]
pub struct WindowsWm;

#[cfg(windows)]
impl WindowManager for WindowsWm {
    fn name(&self) -> &'static str {
        "windows"
    }
    fn list_windows(&self) -> anyhow::Result<Vec<WindowInfo>> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "PascalCase")]
        struct P {
            id: u32,
            process_name: String,
            main_window_title: String,
        }
        let out = run(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "@(Get-Process | Where-Object { $_.MainWindowTitle } | \
                 Select-Object Id,ProcessName,MainWindowTitle) | ConvertTo-Json -Compress",
            ],
        )?;
        let ps: Vec<P> = if out.trim().is_empty() {
            vec![]
        } else {
            serde_json::from_str(&out)?
        };
        Ok(ps
            .into_iter()
            .map(|p| WindowInfo {
                id: p.id.to_string(),
                app: p.process_name,
                title: p.main_window_title,
                workspace: String::new(),
                focused: false,
            })
            .collect())
    }
    fn focus(&self, query: &str) -> anyhow::Result<bool> {
        let wins = self.list_windows()?;
        let Some(w) = crate::hypr::find_window(&wins, query) else {
            return Ok(false);
        };
        let pid: u32 = w.id.parse()?; // numeric, safe to interpolate
        let ok = run(
            "powershell",
            &[
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!("(New-Object -ComObject WScript.Shell).AppActivate({pid})"),
            ],
        )?;
        Ok(ok.trim().eq_ignore_ascii_case("true"))
    }
    fn launch(&self, app: &str) -> anyhow::Result<()> {
        let app = app.trim();
        if app.is_empty() || app.chars().any(|c| "&|<>^\"%\r\n".contains(c)) {
            anyhow::bail!("refusing app name with shell metacharacters: {app:?}");
        }
        spawn_detached(&windows_start_argv(&[app.to_string()]))
    }
    fn close_focused(&self) -> anyhow::Result<()> {
        crate::detect_input().key_combo("alt+f4")
    }
    fn switch_workspace(&self, _ws: &str) -> anyhow::Result<()> {
        unsupported("switching virtual desktops", "windows")
    }
}

#[cfg(any(windows, all(target_os = "linux", feature = "x11")))]
pub mod enigo_input {
    use crate::combo::{Combo, Modifier, parse_combo};
    use crate::{InputController, MouseButton};
    use enigo::{Axis, Button, Coordinate, Direction, Enigo, Key, Keyboard, Mouse, Settings};

    pub struct EnigoInput;

    fn enigo() -> anyhow::Result<Enigo> {
        Enigo::new(&Settings::default()).map_err(|e| anyhow::anyhow!("enigo init: {e}"))
    }

    fn key_of(name: &str) -> anyhow::Result<Key> {
        Ok(match name {
            "Return" => Key::Return,
            "Tab" => Key::Tab,
            "Escape" => Key::Escape,
            "space" => Key::Space,
            "BackSpace" => Key::Backspace,
            "Delete" => Key::Delete,
            "Up" => Key::UpArrow,
            "Down" => Key::DownArrow,
            "Left" => Key::LeftArrow,
            "Right" => Key::RightArrow,
            "Home" => Key::Home,
            "End" => Key::End,
            "Page_Up" => Key::PageUp,
            "Page_Down" => Key::PageDown,
            "Control_L" => Key::Control,
            "Alt_L" => Key::Alt,
            "Shift_L" => Key::Shift,
            "Super_L" => Key::Meta,
            "plus" => Key::Unicode('+'),
            "minus" => Key::Unicode('-'),
            "comma" => Key::Unicode(','),
            "period" => Key::Unicode('.'),
            "slash" => Key::Unicode('/'),
            "XF86AudioRaiseVolume" => Key::VolumeUp,
            "XF86AudioLowerVolume" => Key::VolumeDown,
            "XF86AudioMute" => Key::VolumeMute,
            "XF86AudioPlay" => Key::MediaPlayPause,
            "XF86AudioNext" => Key::MediaNextTrack,
            "XF86AudioPrev" => Key::MediaPrevTrack,
            "F1" => Key::F1,
            "F2" => Key::F2,
            "F3" => Key::F3,
            "F4" => Key::F4,
            "F5" => Key::F5,
            "F6" => Key::F6,
            "F7" => Key::F7,
            "F8" => Key::F8,
            "F9" => Key::F9,
            "F10" => Key::F10,
            "F11" => Key::F11,
            "F12" => Key::F12,
            s => {
                let mut c = s.chars();
                match (c.next(), c.next()) {
                    (Some(ch), None) => Key::Unicode(ch),
                    _ => anyhow::bail!("key {s:?} not supported by enigo backend"),
                }
            }
        })
    }

    fn mod_key(m: Modifier) -> Key {
        match m {
            Modifier::Ctrl => Key::Control,
            Modifier::Alt | Modifier::AltGr => Key::Alt,
            Modifier::Shift => Key::Shift,
            Modifier::Super => Key::Meta,
        }
    }

    pub fn press_combo(c: &Combo) -> anyhow::Result<()> {
        let key = key_of(&c.key)?;
        let mut e = enigo()?;
        for m in &c.mods {
            e.key(mod_key(*m), Direction::Press)?;
        }
        let r = e.key(key, Direction::Click);
        for m in c.mods.iter().rev() {
            let _ = e.key(mod_key(*m), Direction::Release);
        }
        r.map_err(Into::into)
    }

    impl InputController for EnigoInput {
        fn name(&self) -> &'static str {
            "enigo"
        }
        fn type_text(&self, text: &str) -> anyhow::Result<()> {
            enigo()?.text(text).map_err(Into::into)
        }
        fn key_combo(&self, combo: &str) -> anyhow::Result<()> {
            press_combo(&parse_combo(combo)?)
        }
        fn click(&self, x: i32, y: i32, button: MouseButton) -> anyhow::Result<()> {
            let mut e = enigo()?;
            e.move_mouse(x, y, Coordinate::Abs)?;
            let b = match button {
                MouseButton::Left => Button::Left,
                MouseButton::Right => Button::Right,
                MouseButton::Middle => Button::Middle,
            };
            e.button(b, Direction::Click).map_err(Into::into)
        }
        fn scroll(&self, dy: i32) -> anyhow::Result<()> {
            enigo()?.scroll(dy, Axis::Vertical).map_err(Into::into)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_wmctrl_fixture() {
        let out = "0x0400000a  0 Navigator.firefox  box Mozilla Firefox\n\
                   0x01e00003 -1 xfce4-panel.Xfce4-panel  box xfce4-panel\n\
                   0x0520000b  2 code.Code  box main.rs - Visual Studio Code\n";
        let w = parse_wmctrl(out, Some(0x0520000b));
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].app, "firefox");
        assert_eq!(w[0].workspace, "1");
        assert!(!w[0].focused);
        assert_eq!(w[1].title, "main.rs - Visual Studio Code");
        assert!(w[1].focused);
    }

    #[test]
    fn windows_start_argv_keeps_args_separate() {
        let v = windows_start_argv(&["notepad".into(), "a b.txt".into()]);
        assert_eq!(v, ["cmd", "/c", "start", "", "notepad", "a b.txt"]);
    }
}
