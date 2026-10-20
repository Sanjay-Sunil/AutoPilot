//! Key-combo parsing ("ctrl+shift+t", "super+1", "enter") and backend argv building.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Modifier {
    Ctrl,
    Alt,
    Shift,
    Super,
    AltGr,
}

impl Modifier {
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "ctrl" | "control" | "ctl" => Self::Ctrl,
            "alt" | "option" | "opt" => Self::Alt,
            "shift" => Self::Shift,
            "super" | "win" | "windows" | "meta" | "cmd" | "command" | "logo" | "mod4" => {
                Self::Super
            }
            "altgr" => Self::AltGr,
            _ => return None,
        })
    }

    /// wtype -M/-m modifier name.
    pub fn wtype(self) -> &'static str {
        match self {
            Self::Ctrl => "ctrl",
            Self::Alt => "alt",
            Self::Shift => "shift",
            Self::Super => "logo",
            Self::AltGr => "altgr",
        }
    }

    /// Keysym for a modifier pressed on its own.
    fn keysym(self) -> &'static str {
        match self {
            Self::Ctrl => "Control_L",
            Self::Alt => "Alt_L",
            Self::Shift => "Shift_L",
            Self::Super => "Super_L",
            Self::AltGr => "ISO_Level3_Shift",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combo {
    pub mods: Vec<Modifier>,
    /// XKB keysym name (e.g. "Return", "l", "F5", "XF86AudioPlay").
    pub key: String,
}

/// Map a friendly key name to an XKB keysym name.
fn keysym(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let s = match lower.as_str() {
        "enter" | "return" | "ret" => "Return",
        "tab" => "Tab",
        "esc" | "escape" => "Escape",
        "space" | "spc" => "space",
        "backspace" | "bksp" => "BackSpace",
        "delete" | "del" => "Delete",
        "insert" | "ins" => "Insert",
        "up" | "arrowup" => "Up",
        "down" | "arrowdown" => "Down",
        "left" | "arrowleft" => "Left",
        "right" | "arrowright" => "Right",
        "home" => "Home",
        "end" => "End",
        "pageup" | "pgup" | "page_up" => "Page_Up",
        "pagedown" | "pgdn" | "page_down" => "Page_Down",
        "menu" => "Menu",
        "print" | "printscreen" | "prtsc" => "Print",
        "capslock" => "Caps_Lock",
        "plus" => "plus",
        "minus" => "minus",
        "comma" => "comma",
        "period" | "dot" => "period",
        "slash" => "slash",
        "volumeup" | "volume_up" => "XF86AudioRaiseVolume",
        "volumedown" | "volume_down" => "XF86AudioLowerVolume",
        "mute" | "volumemute" => "XF86AudioMute",
        "playpause" | "play_pause" | "play" => "XF86AudioPlay",
        "next" | "nexttrack" => "XF86AudioNext",
        "prev" | "previous" | "prevtrack" => "XF86AudioPrev",
        "brightnessup" => "XF86MonBrightnessUp",
        "brightnessdown" => "XF86MonBrightnessDown",
        _ => {
            if let Some(n) = lower.strip_prefix('f').and_then(|n| n.parse::<u8>().ok())
                && (1..=24).contains(&n)
            {
                return Some(format!("F{n}"));
            }
            let mut chars = name.chars();
            return match (chars.next(), chars.next()) {
                // Single printable character: letters lowercased so "ctrl+L" == "ctrl+l".
                (Some('-'), None) => Some("minus".into()),
                (Some(c), None) if !c.is_control() => Some(c.to_lowercase().to_string()),
                // Already a keysym-looking name (e.g. XF86AudioPlay, KP_Enter).
                _ if name.len() <= 32
                    && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') =>
                {
                    Some(name.to_string())
                }
                _ => None,
            };
        }
    };
    Some(s.to_string())
}

/// Parse "ctrl+shift+t". A trailing "++" means the plus key ("ctrl++").
pub fn parse_combo(combo: &str) -> anyhow::Result<Combo> {
    let c = combo.trim();
    if c.is_empty() {
        anyhow::bail!("empty key combo");
    }
    let (body, plus_key) = match c.strip_suffix("++") {
        Some(b) => (b, true),
        None if c == "+" => ("", true),
        None => (c, false),
    };
    let mut parts: Vec<&str> = if body.is_empty() {
        vec![]
    } else {
        body.split('+').map(str::trim).collect()
    };
    if parts.iter().any(|p| p.is_empty()) {
        anyhow::bail!("malformed key combo: {combo:?}");
    }
    let key_part = if plus_key { None } else { parts.pop() };
    let mut mods = Vec::new();
    for p in &parts {
        let m = Modifier::parse(&p.to_ascii_lowercase())
            .ok_or_else(|| anyhow::anyhow!("unknown modifier {p:?} in {combo:?}"))?;
        if !mods.contains(&m) {
            mods.push(m);
        }
    }
    let key = match key_part {
        None => "plus".to_string(),
        Some(k) => match Modifier::parse(&k.to_ascii_lowercase()) {
            // "super" alone, or "ctrl+shift" -> press the last modifier as a key.
            Some(m) => m.keysym().to_string(),
            None => keysym(k).ok_or_else(|| anyhow::anyhow!("unknown key {k:?} in {combo:?}"))?,
        },
    };
    Ok(Combo { mods, key })
}

/// wtype argv (without program name): `-M ctrl -k l -m ctrl`.
pub fn wtype_args(c: &Combo) -> Vec<String> {
    let mut a = Vec::with_capacity(c.mods.len() * 4 + 2);
    for m in &c.mods {
        a.push("-M".into());
        a.push(m.wtype().into());
    }
    a.push("-k".into());
    a.push(c.key.clone());
    for m in c.mods.iter().rev() {
        a.push("-m".into());
        a.push(m.wtype().into());
    }
    a
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        wtype_args(&parse_combo(s).unwrap())
    }

    #[test]
    fn combos_to_wtype() {
        assert_eq!(argv("ctrl+l"), ["-M", "ctrl", "-k", "l", "-m", "ctrl"]);
        assert_eq!(argv("super+1"), ["-M", "logo", "-k", "1", "-m", "logo"]);
        assert_eq!(argv("enter"), ["-k", "Return"]);
        assert_eq!(argv("alt+tab"), ["-M", "alt", "-k", "Tab", "-m", "alt"]);
        assert_eq!(
            argv("Ctrl+Shift+T"),
            [
                "-M", "ctrl", "-M", "shift", "-k", "t", "-m", "shift", "-m", "ctrl"
            ]
        );
        assert_eq!(argv("ctrl++"), ["-M", "ctrl", "-k", "plus", "-m", "ctrl"]);
        assert_eq!(argv("f5"), ["-k", "F5"]);
        assert_eq!(argv("ctrl+-"), ["-M", "ctrl", "-k", "minus", "-m", "ctrl"]);
        assert_eq!(argv("super"), ["-k", "Super_L"]);
        assert_eq!(argv("XF86AudioPlay"), ["-k", "XF86AudioPlay"]);
        assert_eq!(
            argv("win+pgdn"),
            ["-M", "logo", "-k", "Page_Down", "-m", "logo"]
        );
    }

    #[test]
    fn rejects_bad_combos() {
        assert!(parse_combo("").is_err());
        assert!(parse_combo("ctrl+").is_err());
        assert!(parse_combo("hyper+x").is_err());
        assert!(parse_combo("ctrl+not a key").is_err());
        assert!(parse_combo("ctrl+-k").is_err());
    }
}
