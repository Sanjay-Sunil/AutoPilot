//! Rules fast path: a tiny deterministic parser for common one-shot commands.
//! No model, no allocation-heavy regex engine: ~microseconds per message.
//! Anything compound ("... and then ...") or ambiguous returns `None` and goes to the decider.
use serde_json::{Value, json};

#[derive(Debug, Clone, PartialEq)]
pub struct RuleAction {
    pub tool: &'static str,
    pub args: Value,
    /// Short task title shown on the phone.
    pub title: String,
}

fn act(tool: &'static str, args: Value, title: impl Into<String>) -> Option<RuleAction> {
    Some(RuleAction {
        tool,
        args,
        title: title.into(),
    })
}

const LEADING: &[&str] = &[
    "hey autopilot ",
    "autopilot ",
    "hey ",
    "ok ",
    "okay ",
    "please ",
    "can you ",
    "could you ",
    "would you ",
    "pls ",
    "now ",
    "just ",
];
const TRAILING: &[&str] = &[
    " please",
    " pls",
    " now",
    " for me",
    " thanks",
    " thank you",
];

/// Normalised text: `orig` keeps case (for typed text, app names, paths); `low` is the ASCII
/// lowercase twin with identical byte offsets.
struct Text<'a> {
    orig: &'a str,
    low: String,
}

impl<'a> Text<'a> {
    fn new(s: &'a str) -> Self {
        let mut orig = s.trim();
        loop {
            let before = orig.len();
            orig = orig
                .trim_end_matches(['.', '!', '?', ' ', '\n', '\t'])
                .trim_start();
            let low = orig.to_ascii_lowercase();
            for p in LEADING {
                if low.starts_with(p) {
                    orig = orig[p.len()..].trim_start();
                    break;
                }
            }
            let low = orig.to_ascii_lowercase();
            for t in TRAILING {
                if low.ends_with(t) {
                    orig = orig[..orig.len() - t.len()].trim_end();
                    break;
                }
            }
            if orig.len() == before {
                break;
            }
        }
        Self {
            orig,
            low: orig.to_ascii_lowercase(),
        }
    }

    /// If `low` starts with one of `prefixes`, return the original-case remainder (trimmed).
    fn after(&self, prefixes: &[&str]) -> Option<&'a str> {
        prefixes.iter().find_map(|p| {
            self.low
                .starts_with(p)
                .then(|| self.orig[p.len()..].trim())
                .filter(|r| !r.is_empty())
        })
    }

    fn is(&self, options: &[&str]) -> bool {
        options.iter().any(|o| self.low == *o)
    }
}

fn is_compound(low: &str) -> bool {
    [" and ", " then ", ", ", ";", " after ", " before ", " if "]
        .iter()
        .any(|s| low.contains(s))
}

fn strip_quotes(s: &str) -> &str {
    let s = s.trim();
    for (a, b) in [('"', '"'), ('\'', '\''), ('`', '`'), ('“', '”')] {
        if s.len() >= a.len_utf8() + b.len_utf8() && s.starts_with(a) && s.ends_with(b) {
            return &s[a.len_utf8()..s.len() - b.len_utf8()];
        }
    }
    s
}

fn strip_articles(s: &str) -> &str {
    let mut s = s.trim();
    for a in ["the ", "my ", "a ", "an ", "app ", "application "] {
        if s.len() > a.len() && s[..a.len()].eq_ignore_ascii_case(a) {
            s = s[a.len()..].trim_start();
        }
    }
    for t in [" app", " application", " folder", " directory", " dir"] {
        if s.len() > t.len() && s[s.len() - t.len()..].eq_ignore_ascii_case(t) {
            s = s[..s.len() - t.len()].trim_end();
        }
    }
    s
}

fn parse_pct(s: &str) -> Option<u8> {
    let s = s
        .trim()
        .trim_end_matches('%')
        .trim_end_matches(" percent")
        .trim();
    let n: u32 = s.parse().ok()?;
    (n <= 100).then_some(n as u8)
}

fn looks_like_url(s: &str) -> bool {
    if s.contains(' ') {
        return false;
    }
    let l = s.to_ascii_lowercase();
    if l.starts_with("http://") || l.starts_with("https://") {
        return true;
    }
    let host = l.split('/').next().unwrap_or("");
    match host.rsplit_once('.') {
        Some((name, tld)) => {
            !name.is_empty()
                && (2..=6).contains(&tld.len())
                && tld.chars().all(|c| c.is_ascii_alphabetic())
                && !matches!(
                    tld,
                    "txt" | "pdf" | "md" | "png" | "jpg" | "jpeg" | "doc" | "docx" | "sh" | "rs"
                )
        }
        None => false,
    }
}

fn normalize_url(s: &str) -> String {
    let l = s.to_ascii_lowercase();
    if l.starts_with("http://") || l.starts_with("https://") {
        s.to_string()
    } else {
        format!("https://{s}")
    }
}

fn is_app_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 40
        && s.split_whitespace().count() <= 3
        && !s.contains('/')
        && s.chars()
            .all(|c| c.is_alphanumeric() || matches!(c, ' ' | '-' | '_' | '.' | '+'))
}

fn is_key_combo(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 40
        && !s.contains(' ')
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '_'))
}

/// Path argument for fs.list: "my documents folder" -> "documents", "downloads/pdfs" kept.
fn path_arg(s: &str) -> Option<String> {
    let p = strip_quotes(strip_articles(s)).trim().trim_end_matches('/');
    let ok = !p.is_empty()
        && p.len() <= 200
        && !p.starts_with('/')
        && !p.contains("..")
        && !p.contains('\0')
        && p.split_whitespace().count() <= 3;
    ok.then(|| p.to_string())
}

pub fn parse(input: &str) -> Option<RuleAction> {
    if input.len() > 500 || input.contains('\n') {
        return None;
    }
    let t = Text::new(input);
    if t.low.is_empty() {
        return None;
    }

    // ---- free-text payload commands (payload may contain anything, so check these first) ----
    if let Some(rest) = t.after(&["type out ", "type "]) {
        let text = strip_quotes(rest);
        if !text.is_empty() {
            return act("input.type", json!({ "text": text }), "Type text");
        }
    }
    if let Some(rest) = t.after(&["copy "]) {
        let low = rest.to_ascii_lowercase();
        for suffix in [" to the clipboard", " to clipboard", " into the clipboard"] {
            if low.ends_with(suffix) {
                let text = strip_quotes(&rest[..rest.len() - suffix.len()]);
                if !text.is_empty() {
                    return act(
                        "clipboard.set",
                        json!({ "text": text }),
                        "Copy to clipboard",
                    );
                }
            }
        }
    }

    if is_compound(&t.low) {
        return None;
    }

    // ---- keys ----
    if let Some(rest) = t.after(&["press ", "hit ", "push "]) {
        let combo = strip_quotes(rest).to_ascii_lowercase().replace(" + ", "+");
        let combo = combo.trim_end_matches(" key").trim();
        if is_key_combo(combo) {
            return act(
                "input.keys",
                json!({ "combo": combo }),
                format!("Press {combo}"),
            );
        }
        return None;
    }

    // ---- media ----
    if t.is(&[
        "play",
        "pause",
        "play/pause",
        "play pause",
        "resume",
        "resume music",
        "pause music",
        "play music",
        "pause the music",
        "resume the music",
        "pause video",
        "toggle play",
        "stop music",
    ]) {
        return act(
            "system.media",
            json!({ "action": "play_pause" }),
            "Play/pause",
        );
    }
    if t.is(&[
        "next",
        "next track",
        "next song",
        "skip",
        "skip song",
        "skip track",
        "skip this song",
    ]) {
        return act("system.media", json!({ "action": "next" }), "Next track");
    }
    if t.is(&[
        "previous",
        "prev",
        "previous track",
        "previous song",
        "last song",
        "go back a song",
    ]) {
        return act(
            "system.media",
            json!({ "action": "previous" }),
            "Previous track",
        );
    }

    // ---- volume ----
    if t.is(&[
        "mute",
        "unmute",
        "toggle mute",
        "mute audio",
        "mute sound",
        "silence",
    ]) {
        return act(
            "system.volume",
            json!({ "mute_toggle": true }),
            "Toggle mute",
        );
    }
    if t.is(&[
        "volume up",
        "turn up the volume",
        "turn the volume up",
        "turn volume up",
        "louder",
        "increase volume",
        "increase the volume",
        "raise volume",
        "raise the volume",
    ]) {
        return act("system.volume", json!({ "delta": 10 }), "Volume up");
    }
    if t.is(&[
        "volume down",
        "turn down the volume",
        "turn the volume down",
        "turn volume down",
        "quieter",
        "decrease volume",
        "decrease the volume",
        "lower volume",
        "lower the volume",
    ]) {
        return act("system.volume", json!({ "delta": -10 }), "Volume down");
    }
    if let Some(rest) = t.after(&[
        "set the volume to ",
        "set volume to ",
        "set volume ",
        "volume to ",
        "volume at ",
        "volume ",
        "turn the volume to ",
        "turn volume to ",
    ]) && let Some(n) = parse_pct(rest)
    {
        return act(
            "system.volume",
            json!({ "level": n }),
            format!("Volume {n}%"),
        );
    }

    // ---- brightness ----
    if let Some(rest) = t.after(&[
        "set the brightness to ",
        "set brightness to ",
        "set brightness ",
        "brightness to ",
        "brightness at ",
        "brightness ",
        "screen brightness ",
        "dim screen to ",
        "dim the screen to ",
    ]) && let Some(n) = parse_pct(rest)
    {
        return act(
            "system.brightness",
            json!({ "level": n }),
            format!("Brightness {n}%"),
        );
    }

    // ---- lock / suspend ----
    if t.is(&[
        "lock",
        "lock screen",
        "lock the screen",
        "lock my screen",
        "lock the laptop",
        "lock my laptop",
        "lock the computer",
        "lock it",
    ]) {
        return act("system.lock", json!({}), "Lock screen");
    }
    if t.is(&[
        "suspend",
        "suspend the laptop",
        "go to sleep",
        "sleep laptop",
        "put the laptop to sleep",
    ]) {
        return act("system.suspend", json!({}), "Suspend");
    }

    // ---- screen ----
    if t.is(&[
        "screenshot",
        "take a screenshot",
        "take screenshot",
        "screen",
        "show screen",
        "show me the screen",
        "show me my screen",
        "show my screen",
        "show the screen",
        "snapshot",
        "screen snapshot",
    ]) {
        return act("screen.snapshot", json!({}), "Screenshot");
    }

    // ---- info ----
    if t.is(&[
        "battery",
        "battery level",
        "battery status",
        "how much battery",
        "how much battery is left",
        "how much battery do i have",
        "what's my battery",
        "whats my battery",
        "what is my battery",
        "what's the battery",
        "what's the battery level",
        "battery percentage",
        "am i charging",
    ]) {
        return act("system.battery", json!({}), "Battery");
    }
    if t.is(&[
        "what's running",
        "whats running",
        "what is running",
        "list processes",
        "show processes",
        "running processes",
        "process list",
        "top processes",
        "what's using cpu",
        "what's using my cpu",
        "ps",
    ]) {
        return act("process.list", json!({}), "Running processes");
    }
    if t.is(&[
        "system info",
        "system status",
        "cpu usage",
        "memory usage",
        "ram usage",
        "uptime",
        "how's the laptop",
        "how is the laptop doing",
        "status",
    ]) {
        return act("system.info", json!({}), "System info");
    }
    if t.is(&[
        "list windows",
        "show windows",
        "what windows are open",
        "which windows are open",
        "open windows",
        "list open windows",
    ]) {
        return act("window.list", json!({}), "Open windows");
    }
    if t.is(&[
        "what's in my clipboard",
        "whats in my clipboard",
        "what's in the clipboard",
        "show clipboard",
        "read clipboard",
        "get clipboard",
        "paste clipboard",
    ]) {
        return act("clipboard.get", json!({}), "Clipboard");
    }

    // ---- windows / workspaces ----
    if t.is(&[
        "close window",
        "close this window",
        "close the window",
        "close current window",
        "close the current window",
        "close active window",
        "close the active window",
        "close it",
        "close this",
    ]) {
        return act("window.close", json!({}), "Close window");
    }
    if let Some(rest) = t.after(&[
        "switch to workspace ",
        "go to workspace ",
        "move to workspace ",
        "change to workspace ",
        "workspace ",
        "open workspace ",
    ]) {
        let ws = rest.trim_start_matches("number ").trim();
        let ok = !ws.is_empty() && ws.len() <= 20 && ws.chars().all(|c| c.is_alphanumeric());
        return if ok {
            act(
                "workspace.switch",
                json!({ "workspace": ws }),
                format!("Workspace {ws}"),
            )
        } else {
            None
        };
    }
    if let Some(rest) = t.after(&["focus on ", "focus ", "switch to ", "go to ", "bring up "]) {
        let q = strip_articles(rest);
        if looks_like_url(q) && t.low.starts_with("go to ") {
            let url = normalize_url(q);
            return act(
                "browser.navigate",
                json!({ "url": url }),
                format!("Open {q}"),
            );
        }
        if is_app_name(q) {
            let q = q.trim_end_matches(" window").trim();
            return act("window.focus", json!({ "query": q }), format!("Focus {q}"));
        }
        return None;
    }

    // ---- files ----
    if let Some(rest) = t.after(&[
        "list files in ",
        "list the files in ",
        "list my files in ",
        "list files from ",
        "show files in ",
        "show me files in ",
        "show me the files in ",
        "show the files in ",
        "what files are in ",
        "what's in ",
        "whats in ",
        "what is in ",
        "ls ",
        "list ",
    ]) {
        return path_arg(rest).map(|p| RuleAction {
            tool: "fs.list",
            title: format!("List {p}"),
            args: json!({ "path": p }),
        });
    }

    // ---- launch ----
    if let Some(rest) = t.after(&["open up ", "open ", "launch ", "start ", "fire up ", "run "]) {
        let q = strip_articles(rest);
        if looks_like_url(q) {
            let url = normalize_url(q);
            return act(
                "browser.navigate",
                json!({ "url": url }),
                format!("Open {q}"),
            );
        }
        // "open the file report.pdf", "open documents/x" -> not a plain app launch.
        let low = q.to_ascii_lowercase();
        if low.starts_with("file ") || low.starts_with("folder ") || q.contains('.') {
            return None;
        }
        if is_app_name(q) {
            return act("app.launch", json!({ "app": q }), format!("Open {q}"));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tool(s: &str) -> Option<(&'static str, Value)> {
        parse(s).map(|a| (a.tool, a.args))
    }

    #[test]
    fn table() {
        let cases: &[(&str, &str, Value)] = &[
            ("open firefox", "app.launch", json!({"app":"firefox"})),
            ("Open Firefox.", "app.launch", json!({"app":"Firefox"})),
            (
                "please launch spotify",
                "app.launch",
                json!({"app":"spotify"}),
            ),
            (
                "can you open the terminal app please",
                "app.launch",
                json!({"app":"terminal"}),
            ),
            (
                "start visual studio code",
                "app.launch",
                json!({"app":"visual studio code"}),
            ),
            (
                "open github.com",
                "browser.navigate",
                json!({"url":"https://github.com"}),
            ),
            (
                "open https://example.org/x",
                "browser.navigate",
                json!({"url":"https://example.org/x"}),
            ),
            (
                "go to youtube.com",
                "browser.navigate",
                json!({"url":"https://youtube.com"}),
            ),
            ("close window", "window.close", json!({})),
            ("close this window!", "window.close", json!({})),
            (
                "switch to workspace 3",
                "workspace.switch",
                json!({"workspace":"3"}),
            ),
            ("workspace 2", "workspace.switch", json!({"workspace":"2"})),
            (
                "go to workspace number 5",
                "workspace.switch",
                json!({"workspace":"5"}),
            ),
            ("focus firefox", "window.focus", json!({"query":"firefox"})),
            ("switch to slack", "window.focus", json!({"query":"slack"})),
            (
                "focus on the terminal window",
                "window.focus",
                json!({"query":"terminal"}),
            ),
            ("volume up", "system.volume", json!({"delta":10})),
            (
                "turn down the volume",
                "system.volume",
                json!({"delta":-10}),
            ),
            ("volume 40%", "system.volume", json!({"level":40})),
            ("set volume to 75", "system.volume", json!({"level":75})),
            (
                "set the volume to 20 percent",
                "system.volume",
                json!({"level":20}),
            ),
            ("mute", "system.volume", json!({"mute_toggle":true})),
            ("Unmute", "system.volume", json!({"mute_toggle":true})),
            ("brightness 50", "system.brightness", json!({"level":50})),
            (
                "set brightness to 30%",
                "system.brightness",
                json!({"level":30}),
            ),
            ("play", "system.media", json!({"action":"play_pause"})),
            ("pause", "system.media", json!({"action":"play_pause"})),
            ("next track", "system.media", json!({"action":"next"})),
            ("skip", "system.media", json!({"action":"next"})),
            (
                "previous song",
                "system.media",
                json!({"action":"previous"}),
            ),
            ("lock", "system.lock", json!({})),
            ("lock the screen", "system.lock", json!({})),
            ("suspend", "system.suspend", json!({})),
            ("screenshot", "screen.snapshot", json!({})),
            ("show me the screen", "screen.snapshot", json!({})),
            ("take a screenshot please", "screen.snapshot", json!({})),
            ("battery", "system.battery", json!({})),
            ("how much battery is left?", "system.battery", json!({})),
            (
                "list files in Documents",
                "fs.list",
                json!({"path":"Documents"}),
            ),
            (
                "list files in my downloads folder",
                "fs.list",
                json!({"path":"downloads"}),
            ),
            (
                "what's in Downloads/pdfs",
                "fs.list",
                json!({"path":"Downloads/pdfs"}),
            ),
            ("ls Desktop", "fs.list", json!({"path":"Desktop"})),
            ("what's running", "process.list", json!({})),
            ("list processes", "process.list", json!({})),
            ("system info", "system.info", json!({})),
            ("list windows", "window.list", json!({})),
            (
                "copy hello world to clipboard",
                "clipboard.set",
                json!({"text":"hello world"}),
            ),
            (
                "copy \"a, b and c\" to the clipboard",
                "clipboard.set",
                json!({"text":"a, b and c"}),
            ),
            (
                "type Hello, World",
                "input.type",
                json!({"text":"Hello, World"}),
            ),
            (
                "type \"git status\"",
                "input.type",
                json!({"text":"git status"}),
            ),
            ("press ctrl+l", "input.keys", json!({"combo":"ctrl+l"})),
            ("press Enter", "input.keys", json!({"combo":"enter"})),
            (
                "hit ctrl + shift + t",
                "input.keys",
                json!({"combo":"ctrl+shift+t"}),
            ),
            ("what's in my clipboard", "clipboard.get", json!({})),
        ];
        for (input, want_tool, want_args) in cases {
            let got = tool(input);
            assert_eq!(
                got,
                Some((*want_tool, want_args.clone())),
                "input: {input:?}"
            );
        }
    }

    #[test]
    fn no_match_goes_to_decider() {
        for s in [
            "",
            "   ",
            "open firefox and go to github",
            "open firefox, then search for rust",
            "summarize the newest file in Documents",
            "what's the weather like",
            "open the file report.pdf",
            "open report.txt",
            "write me a poem about the sea",
            "list files in /etc",
            "list files in ../../secret",
            "press ctrl+l and type hello", // compound: type comes after press
            "volume 150",
            "brightness max",
            "switch to workspace ../1",
            "launch rm -rf /",
            "why is my laptop slow",
            "delete all my downloads",
        ] {
            assert_eq!(tool(s), None, "input: {s:?}");
        }
        let long = "open ".to_string() + &"x".repeat(600);
        assert_eq!(tool(&long), None);
    }

    #[test]
    fn titles_present() {
        let a = parse("open firefox").unwrap();
        assert_eq!(a.title, "Open firefox");
    }

    #[test]
    fn fast() {
        let start = std::time::Instant::now();
        for _ in 0..10_000 {
            let _ = parse("set the volume to 20 percent please");
            let _ = parse("summarize the newest file in Documents");
        }
        // 20k parses well under a second even in debug builds.
        assert!(start.elapsed().as_millis() < 2000);
    }
}
