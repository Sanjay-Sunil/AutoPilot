//! Hyprland backends: window management through `hyprctl` and input through wtype (+ ydotool
//! for pointer events when installed).
//!
//! Hyprland 0.56 with a Lua config accepts Lua dispatch expressions
//! (`hyprctl dispatch 'hl.dsp.focus({...})'`); older/legacy configs use the classic dispatcher
//! names. Like Omarchy's own scripts we try Lua first and fall back to legacy.
use crate::combo::{parse_combo, wtype_args};
use crate::util::{lua_quote, run, run_stdin, shell_join, which};
use crate::{InputController, MouseButton, WindowInfo, WindowManager};
use serde::Deserialize;
use std::process::{Command, Stdio};

#[derive(Debug, Deserialize)]
struct HyprWorkspace {
    #[serde(default)]
    name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HyprClient {
    address: String,
    #[serde(default)]
    class: String,
    #[serde(default)]
    initial_class: String,
    #[serde(default)]
    title: String,
    workspace: HyprWorkspace,
    #[serde(default = "yes")]
    mapped: bool,
    #[serde(default)]
    hidden: bool,
    #[serde(default = "minus_one", rename = "focusHistoryID")]
    focus_history_id: i64,
}

fn yes() -> bool {
    true
}
fn minus_one() -> i64 {
    -1
}

/// Parse `hyprctl -j clients`. Focus comes from `focusHistoryID == 0`.
pub fn parse_clients(json: &[u8]) -> anyhow::Result<Vec<WindowInfo>> {
    let clients: Vec<HyprClient> = serde_json::from_slice(json)?;
    Ok(clients
        .into_iter()
        .filter(|c| c.mapped && !c.hidden)
        .map(|c| WindowInfo {
            id: c.address,
            app: if c.class.is_empty() {
                c.initial_class
            } else {
                c.class
            },
            title: c.title,
            workspace: c.workspace.name,
            focused: c.focus_history_id == 0,
        })
        .collect())
}

/// First window whose app or title contains `query` (case-insensitive); exact app match wins.
pub fn find_window<'a>(wins: &'a [WindowInfo], query: &str) -> Option<&'a WindowInfo> {
    let q = query.trim().to_lowercase();
    if q.is_empty() {
        return None;
    }
    wins.iter()
        .find(|w| w.app.to_lowercase() == q)
        .or_else(|| wins.iter().find(|w| w.app.to_lowercase().contains(&q)))
        .or_else(|| wins.iter().find(|w| w.title.to_lowercase().contains(&q)))
}

/// A Hyprland dispatch: Lua expression plus legacy `hyprctl dispatch` args.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dispatch {
    pub lua: String,
    pub legacy: Vec<String>,
}

pub fn dispatch_focus_window(address: &str) -> anyhow::Result<Dispatch> {
    if !address.starts_with("0x") || !address[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        anyhow::bail!("bad window address {address:?}");
    }
    let target = format!("address:{address}");
    Ok(Dispatch {
        lua: format!("hl.dsp.focus({{ window = {} }})", lua_quote(&target)),
        legacy: vec!["focuswindow".into(), target],
    })
}

pub fn dispatch_close_active() -> Dispatch {
    Dispatch {
        lua: "hl.dsp.window.close()".into(),
        legacy: vec!["killactive".into()],
    }
}

pub fn dispatch_workspace(ws: &str) -> anyhow::Result<Dispatch> {
    let ws = ws.trim();
    let ok = !ws.is_empty()
        && ws.len() <= 64
        && ws
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "+-_:".contains(c));
    if !ok {
        anyhow::bail!("invalid workspace {ws:?} (use a number, name, e+1, special:name)");
    }
    Ok(Dispatch {
        lua: format!("hl.dsp.focus({{ workspace = {} }})", lua_quote(ws)),
        legacy: vec!["workspace".into(), ws.into()],
    })
}

/// Exec through the compositor so the app inherits the session env and gets its own scope.
pub fn dispatch_exec(argv: &[String]) -> anyhow::Result<Dispatch> {
    if argv.is_empty() {
        anyhow::bail!("empty command");
    }
    let cmd = shell_join(argv);
    Ok(Dispatch {
        lua: format!("hl.dsp.exec_cmd({})", lua_quote(&cmd)),
        legacy: vec!["exec".into(), "--".into(), cmd],
    })
}

pub fn dispatch_move_cursor(x: i32, y: i32) -> Dispatch {
    Dispatch {
        lua: format!("hl.dsp.cursor.move({{ x = {x}, y = {y} }})"),
        legacy: vec!["movecursor".into(), x.to_string(), y.to_string()],
    }
}

fn hyprctl_dispatch_ok(args: &[&str]) -> Result<(), String> {
    let out = Command::new("hyprctl")
        .arg("dispatch")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("failed to run hyprctl: {e}"))?;
    let text = String::from_utf8_lossy(&out.stdout);
    let text = text.trim();
    if out.status.success() && (text.is_empty() || text == "ok") {
        Ok(())
    } else {
        Err(format!(
            "{text} {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}

pub fn run_dispatch(d: &Dispatch) -> anyhow::Result<()> {
    match hyprctl_dispatch_ok(&[&d.lua]) {
        Ok(()) => Ok(()),
        Err(lua_err) => {
            let legacy: Vec<&str> = d.legacy.iter().map(String::as_str).collect();
            hyprctl_dispatch_ok(&legacy).map_err(|e| {
                anyhow::anyhow!("hyprctl dispatch failed: lua: {lua_err}; legacy: {e}")
            })
        }
    }
}

pub struct HyprWm;

impl WindowManager for HyprWm {
    fn name(&self) -> &'static str {
        "hyprland"
    }

    fn list_windows(&self) -> anyhow::Result<Vec<WindowInfo>> {
        let out = run("hyprctl", &["-j", "clients"])?;
        parse_clients(out.as_bytes())
    }

    fn focus(&self, query: &str) -> anyhow::Result<bool> {
        let wins = self.list_windows()?;
        let Some(w) = find_window(&wins, query) else {
            return Ok(false);
        };
        run_dispatch(&dispatch_focus_window(&w.id)?)?;
        Ok(true)
    }

    fn launch(&self, app: &str) -> anyhow::Result<()> {
        let argv = crate::resolve_launch(app)?;
        run_dispatch(&dispatch_exec(&crate::wrap_uwsm(argv))?)
    }

    fn close_focused(&self) -> anyhow::Result<()> {
        run_dispatch(&dispatch_close_active())
    }

    fn switch_workspace(&self, ws: &str) -> anyhow::Result<()> {
        run_dispatch(&dispatch_workspace(ws)?)
    }
}

/// Wayland input: wtype for keyboard; pointer via hyprctl movecursor + ydotool.
pub struct WtypeInput {
    pub hyprland: bool,
}

/// ydotool button codes: 0xC0 = press+release of left (0x00), right (0x01), middle (0x02).
pub fn ydotool_click_args(button: MouseButton) -> Vec<String> {
    let code = match button {
        MouseButton::Left => "0xC0",
        MouseButton::Right => "0xC1",
        MouseButton::Middle => "0xC2",
    };
    vec!["click".into(), code.into()]
}

/// Wheel: positive dy scrolls down (screen convention), ydotool's wheel is positive-up.
pub fn ydotool_scroll_args(dy: i32) -> Vec<String> {
    vec![
        "mousemove".into(),
        "--wheel".into(),
        "-x".into(),
        "0".into(),
        "-y".into(),
        (-dy).to_string(),
    ]
}

fn need_ydotool() -> anyhow::Result<()> {
    if which("ydotool") {
        Ok(())
    } else {
        anyhow::bail!(
            "mouse clicks/scroll on Wayland need ydotool: install ydotool and run ydotoold \
             (keyboard input via wtype works without it)"
        )
    }
}

impl InputController for WtypeInput {
    fn name(&self) -> &'static str {
        "wtype"
    }

    fn type_text(&self, text: &str) -> anyhow::Result<()> {
        if text.is_empty() {
            return Ok(());
        }
        // "-" makes wtype read stdin: no argv-length limit, no option injection.
        run_stdin("wtype", &["-"], text.as_bytes())
    }

    fn key_combo(&self, combo: &str) -> anyhow::Result<()> {
        let args = wtype_args(&parse_combo(combo)?);
        run("wtype", &args).map(|_| ())
    }

    fn click(&self, x: i32, y: i32, button: MouseButton) -> anyhow::Result<()> {
        need_ydotool()?;
        if self.hyprland {
            run_dispatch(&dispatch_move_cursor(x, y))?;
        } else {
            run(
                "ydotool",
                &[
                    "mousemove",
                    "--absolute",
                    "-x",
                    &x.to_string(),
                    "-y",
                    &y.to_string(),
                ],
            )?;
        }
        run("ydotool", &ydotool_click_args(button)).map(|_| ())
    }

    fn scroll(&self, dy: i32) -> anyhow::Result<()> {
        need_ydotool()?;
        run("ydotool", &ydotool_scroll_args(dy)).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENTS: &str = r#"[
      {"address":"0x55d1a0","mapped":true,"hidden":false,"at":[0,0],"size":[10,10],
       "workspace":{"id":1,"name":"1"},"floating":false,"monitor":0,"class":"firefox",
       "title":"Mozilla Firefox","initialClass":"firefox","initialTitle":"x","pid":1,
       "xwayland":false,"pinned":false,"fullscreen":0,"focusHistoryID":1},
      {"address":"0x55d1b0","mapped":true,"hidden":false,"workspace":{"id":4,"name":"4"},
       "class":"Alacritty","title":"~/Projects","initialClass":"Alacritty","focusHistoryID":0},
      {"address":"0x55d1c0","mapped":false,"hidden":false,"workspace":{"id":-1,"name":""},
       "class":"ghost","title":"","initialClass":"ghost","focusHistoryID":5},
      {"address":"0x55d1d0","mapped":true,"hidden":false,"workspace":{"id":-98,"name":"special:scratchpad"},
       "class":"","title":"Untitled","initialClass":"org.gnome.Nautilus","focusHistoryID":2}
    ]"#;

    #[test]
    fn parses_clients_fixture() {
        let w = parse_clients(CLIENTS.as_bytes()).unwrap();
        assert_eq!(w.len(), 3);
        assert_eq!(w[0].app, "firefox");
        assert!(!w[0].focused);
        assert!(w[1].focused);
        assert_eq!(w[1].workspace, "4");
        assert_eq!(w[2].app, "org.gnome.Nautilus");
        assert_eq!(w[2].workspace, "special:scratchpad");
        assert_eq!(find_window(&w, "FIREFOX").unwrap().id, "0x55d1a0");
        assert_eq!(find_window(&w, "projects").unwrap().id, "0x55d1b0");
        assert_eq!(find_window(&w, "nautilus").unwrap().id, "0x55d1d0");
        assert!(find_window(&w, "chrome").is_none());
        assert!(find_window(&w, "  ").is_none());
    }

    #[test]
    fn builds_dispatches() {
        let d = dispatch_focus_window("0x55d1a0").unwrap();
        assert_eq!(d.lua, r#"hl.dsp.focus({ window = "address:0x55d1a0" })"#);
        assert_eq!(d.legacy, ["focuswindow", "address:0x55d1a0"]);
        assert!(dispatch_focus_window("0x1;rm").is_err());

        let d = dispatch_workspace("3").unwrap();
        assert_eq!(d.lua, r#"hl.dsp.focus({ workspace = "3" })"#);
        assert_eq!(d.legacy, ["workspace", "3"]);
        assert!(dispatch_workspace("1\"); os.exit() --").is_err());
        assert!(dispatch_workspace("").is_err());

        let argv: Vec<String> = ["uwsm-app", "--", "/opt/My App/app", "it's"]
            .map(String::from)
            .into();
        let d = dispatch_exec(&argv).unwrap();
        let shell = r"uwsm-app -- '/opt/My App/app' 'it'\''s'";
        assert_eq!(d.legacy, ["exec", "--", shell]);
        assert_eq!(d.lua, format!("hl.dsp.exec_cmd({})", lua_quote(shell)));

        assert_eq!(dispatch_close_active().legacy, ["killactive"]);
        assert_eq!(
            dispatch_move_cursor(10, -2).legacy,
            ["movecursor", "10", "-2"]
        );
    }

    #[test]
    fn ydotool_argv() {
        assert_eq!(ydotool_click_args(MouseButton::Right), ["click", "0xC1"]);
        assert_eq!(
            ydotool_scroll_args(3),
            ["mousemove", "--wheel", "-x", "0", "-y", "-3"]
        );
    }

    /// Live, read-only: Lua dispatch path works with a no-op.
    #[test]
    fn live_noop_dispatch() {
        if std::env::var_os("HYPRLAND_INSTANCE_SIGNATURE").is_none() {
            return;
        }
        let d = Dispatch {
            lua: "hl.dsp.no_op()".into(),
            legacy: vec!["__agent_input_no_such_dispatcher".into()],
        };
        if let Err(e) = run_dispatch(&d) {
            eprintln!("note: Lua dispatch unavailable on this Hyprland: {e}");
        }
    }
}
