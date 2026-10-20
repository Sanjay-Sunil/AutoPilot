//! XDG desktop-entry lookup: resolve "firefox", "vs code", "chrome" to an argv.
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopEntry {
    /// Desktop file id, e.g. "org.mozilla.firefox.desktop".
    pub id: String,
    pub name: String,
    pub generic_name: String,
    pub keywords: Vec<String>,
    pub exec: String,
    pub no_display: bool,
    pub terminal: bool,
}

impl DesktopEntry {
    /// Exec as argv with field codes removed.
    pub fn argv(&self) -> anyhow::Result<Vec<String>> {
        exec_to_argv(&self.exec)
    }
}

/// Parse the `[Desktop Entry]` group. Returns None for hidden/non-application entries.
pub fn parse_desktop_entry(id: &str, content: &str) -> Option<DesktopEntry> {
    let mut in_main = false;
    let mut e = DesktopEntry {
        id: id.to_string(),
        name: String::new(),
        generic_name: String::new(),
        keywords: vec![],
        exec: String::new(),
        no_display: false,
        terminal: false,
    };
    let mut ty = String::new();
    let mut hidden = false;
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_main = line == "[Desktop Entry]";
            continue;
        }
        if !in_main || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        match k {
            "Type" => ty = v.to_string(),
            "Name" => e.name = v.to_string(),
            "GenericName" => e.generic_name = v.to_string(),
            "Keywords" => {
                e.keywords = v
                    .split(';')
                    .filter(|s| !s.is_empty())
                    .map(String::from)
                    .collect()
            }
            "Exec" => e.exec = v.to_string(),
            "NoDisplay" => e.no_display = v == "true",
            "Hidden" => hidden = v == "true",
            "Terminal" => e.terminal = v == "true",
            _ => {}
        }
    }
    (ty == "Application" && !hidden && !e.exec.is_empty() && !e.name.is_empty()).then_some(e)
}

/// Decode desktop-entry string escapes, tokenize Exec quoting rules, drop field codes.
pub fn exec_to_argv(exec: &str) -> anyhow::Result<Vec<String>> {
    // 1) value-level escapes
    let mut v = String::with_capacity(exec.len());
    let mut it = exec.chars();
    while let Some(c) = it.next() {
        if c == '\\' {
            match it.next() {
                Some('s') => v.push(' '),
                Some('n') => v.push('\n'),
                Some('t') => v.push('\t'),
                Some('r') => v.push('\r'),
                Some('\\') => v.push('\\'),
                Some(o) => {
                    v.push('\\');
                    v.push(o)
                }
                None => v.push('\\'),
            }
        } else {
            v.push(c);
        }
    }
    // 2) Exec quoting: whitespace-separated, "double quoted" args with \" \` \$ \\ escapes.
    let mut args: Vec<(String, bool)> = Vec::new();
    let mut cur = String::new();
    let mut has = false;
    let mut quoted = false;
    let mut in_q = false;
    let mut it = v.chars();
    while let Some(c) = it.next() {
        if in_q {
            match c {
                '"' => in_q = false,
                '\\' => match it.next() {
                    Some(n @ ('"' | '`' | '$' | '\\')) => cur.push(n),
                    Some(n) => {
                        cur.push('\\');
                        cur.push(n)
                    }
                    None => anyhow::bail!("dangling escape in Exec"),
                },
                _ => cur.push(c),
            }
        } else if c == '"' {
            in_q = true;
            has = true;
            quoted = true;
        } else if c.is_whitespace() {
            if has {
                args.push((std::mem::take(&mut cur), quoted));
                has = false;
                quoted = false;
            }
        } else {
            cur.push(c);
            has = true;
        }
    }
    if in_q {
        anyhow::bail!("unterminated quote in Exec");
    }
    if has {
        args.push((cur, quoted));
    }
    // 3) field codes
    let mut out = Vec::with_capacity(args.len());
    for (a, quoted) in args {
        if !quoted && a.len() == 2 && a.starts_with('%') && a != "%%" {
            continue; // standalone %f %U %i %c %k ...
        }
        let mut s = String::with_capacity(a.len());
        let mut ch = a.chars();
        while let Some(c) = ch.next() {
            if c == '%' {
                // "%%" -> "%", any other field code is dropped.
                if ch.next() == Some('%') {
                    s.push('%');
                }
            } else {
                s.push(c);
            }
        }
        if !s.is_empty() {
            out.push(s);
        }
    }
    let Some(first) = out.first() else {
        anyhow::bail!("empty Exec");
    };
    if first.starts_with('-') || out.iter().any(|a| a.chars().any(|c| c == '\0')) {
        anyhow::bail!("refusing suspicious Exec line: {exec:?}");
    }
    Ok(out)
}

/// XDG application dirs in priority order (user first).
pub fn xdg_application_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    match std::env::var_os("XDG_DATA_HOME").filter(|v| !v.is_empty()) {
        Some(h) => dirs.push(PathBuf::from(h)),
        None => {
            if let Some(home) = std::env::var_os("HOME") {
                dirs.push(PathBuf::from(home).join(".local/share"));
            }
        }
    }
    let sys = std::env::var("XDG_DATA_DIRS")
        .ok()
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| "/usr/local/share:/usr/share".into());
    dirs.extend(sys.split(':').filter(|s| !s.is_empty()).map(PathBuf::from));
    let mut seen = HashSet::new();
    dirs.into_iter()
        .map(|d| d.join("applications"))
        .filter(|d| seen.insert(d.clone()))
        .collect()
}

/// Load all entries; earlier dirs shadow later ones with the same desktop id.
pub fn load_entries(dirs: &[PathBuf]) -> Vec<DesktopEntry> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for d in dirs {
        walk(d, d, 0, &mut seen, &mut out);
    }
    out
}

fn walk(
    root: &Path,
    dir: &Path,
    depth: u8,
    seen: &mut HashSet<String>,
    out: &mut Vec<DesktopEntry>,
) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for ent in rd.flatten() {
        let p = ent.path();
        let Ok(ft) = ent.file_type() else { continue };
        if ft.is_dir() && depth < 3 {
            walk(root, &p, depth + 1, seen, out);
        } else if p.extension().is_some_and(|e| e == "desktop") {
            let Ok(rel) = p.strip_prefix(root) else {
                continue;
            };
            let id = rel.to_string_lossy().replace('/', "-");
            if !seen.insert(id.clone()) {
                continue;
            }
            if let Ok(content) = std::fs::read_to_string(&p)
                && let Some(e) = parse_desktop_entry(&id, &content)
            {
                out.push(e);
            }
        }
    }
}

fn norm(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

/// Common nicknames -> normalized names to also try.
fn aliases(q: &str) -> &'static [&'static str] {
    match q {
        "chrome" | "googlechrome" => &["googlechrome", "chromium", "chrome"],
        "vscode" | "code" | "visualstudiocode" => &["visualstudiocode", "code", "vscodium"],
        "files" | "filemanager" | "explorer" => &["files", "nautilus", "thunar", "dolphin"],
        "browser" | "web" | "webbrowser" => &["webbrowser"],
        "editor" | "texteditor" => &["texteditor"],
        _ => &[],
    }
}

fn score(e: &DesktopEntry, q: &str) -> u32 {
    let id = norm(e.id.trim_end_matches(".desktop"));
    let id_tail = norm(
        e.id.trim_end_matches(".desktop")
            .rsplit(['.', '-'])
            .next()
            .unwrap_or(""),
    );
    let name = norm(&e.name);
    let exec_base = e
        .argv()
        .ok()
        .and_then(|a| {
            Path::new(&a[0])
                .file_name()
                .map(|f| norm(&f.to_string_lossy()))
        })
        .unwrap_or_default();
    let generic = norm(&e.generic_name);
    let mut s = if name == q || id == q || id_tail == q || exec_base == q {
        100
    } else if name.starts_with(q) || exec_base.starts_with(q) {
        80
    } else if generic == q {
        70
    } else if name.contains(q) || id.contains(q) {
        60
    } else if e.keywords.iter().any(|k| norm(k) == q) {
        50
    } else if generic.contains(q) {
        40
    } else {
        0
    };
    if s > 0 && e.no_display {
        s -= 15;
    }
    s
}

/// Best entry for a free-form query ("firefox", "VS Code", "chrome").
pub fn resolve(query: &str, entries: &[DesktopEntry]) -> Option<DesktopEntry> {
    let q = norm(query);
    if q.is_empty() {
        return None;
    }
    let mut cands: Vec<String> = vec![q.clone()];
    cands.extend(aliases(&q).iter().map(|s| s.to_string()));
    let mut best: Option<(u32, usize, &DesktopEntry)> = None;
    for (rank, c) in cands.iter().enumerate() {
        for e in entries {
            // Aliases rank just below a direct hit.
            let s = score(e, c).saturating_sub(rank as u32);
            if s == 0 {
                continue;
            }
            let better = match best {
                None => true,
                Some((bs, bl, _)) => s > bs || (s == bs && e.name.len() < bl),
            };
            if better {
                best = Some((s, e.name.len(), e));
            }
        }
    }
    best.filter(|(s, _, _)| *s >= 40).map(|(_, _, e)| e.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_field_codes_and_quotes() {
        assert_eq!(
            exec_to_argv("/usr/lib/firefox/firefox %u").unwrap(),
            ["/usr/lib/firefox/firefox"]
        );
        assert_eq!(
            exec_to_argv("code --new-window %F").unwrap(),
            ["code", "--new-window"]
        );
        assert_eq!(
            exec_to_argv(r#""/opt/My App/app" --name=%c %i --x=100%% "a \"q\" b""#).unwrap(),
            ["/opt/My App/app", "--name=", "--x=100%", r#"a "q" b"#]
        );
        // \s decodes to a space at the string level, which then separates Exec args.
        assert_eq!(
            exec_to_argv(r"env\sA=1 prog").unwrap(),
            ["env", "A=1", "prog"]
        );
        assert_eq!(exec_to_argv(r#""a\sb" c"#).unwrap(), ["a b", "c"]);
        assert!(exec_to_argv("%U").is_err());
        assert!(exec_to_argv("\"unterminated").is_err());
        assert!(exec_to_argv("--evil").is_err());
    }

    fn write(dir: &Path, name: &str, body: &str) {
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(dir.join(name), body).unwrap();
    }

    fn app(name: &str, exec: &str, extra: &str) -> String {
        format!(
            "[Desktop Entry]\nType=Application\nName={name}\nExec={exec}\n{extra}\n[Desktop Action new]\nName=Other\nExec=other\n"
        )
    }

    #[test]
    fn resolves_queries_against_fake_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let user = tmp.path().join("user/applications");
        let sys = tmp.path().join("sys/applications");
        write(
            &sys,
            "firefox.desktop",
            &app(
                "Firefox",
                "/usr/lib/firefox/firefox %u",
                "GenericName=Web Browser",
            ),
        );
        write(
            &sys,
            "google-chrome.desktop",
            &app(
                "Google Chrome",
                "/usr/bin/google-chrome-stable %U",
                "GenericName=Web Browser",
            ),
        );
        write(
            &sys,
            "code.desktop",
            &app("Visual Studio Code", "/usr/bin/code %F", "Keywords=vscode;"),
        );
        write(
            &sys,
            "Alacritty.desktop",
            &app("Alacritty", "alacritty", "GenericName=Terminal"),
        );
        write(
            &sys,
            "hidden.desktop",
            &app("Secret", "secret", "Hidden=true"),
        );
        write(
            &sys,
            "link.desktop",
            "[Desktop Entry]\nType=Link\nName=Docs\nURL=x\nExec=x\n",
        );
        // user override shadows the system one
        write(
            &user,
            "firefox.desktop",
            &app("Firefox", "firefox --private %u", ""),
        );
        write(&sys.join("kde"), "foo.desktop", &app("KFoo", "kfoo", ""));

        let entries = load_entries(&[user, sys]);
        let get = |q: &str| resolve(q, &entries).map(|e| e.argv().unwrap());
        assert_eq!(get("firefox").unwrap(), ["firefox", "--private"]);
        assert_eq!(get("FireFox").unwrap(), ["firefox", "--private"]);
        assert_eq!(get("chrome").unwrap(), ["/usr/bin/google-chrome-stable"]);
        assert_eq!(get("vs code").unwrap(), ["/usr/bin/code"]);
        assert_eq!(get("VSCode").unwrap(), ["/usr/bin/code"]);
        assert_eq!(get("visual studio").unwrap(), ["/usr/bin/code"]);
        assert_eq!(get("alacritty").unwrap(), ["alacritty"]);
        assert_eq!(get("kfoo").unwrap(), ["kfoo"]);
        assert!(get("secret").is_none());
        assert!(get("docs").is_none());
        assert!(get("nonexistent-app").is_none());
        assert!(entries.iter().any(|e| e.id == "kde-foo.desktop"));
    }
}
