//! Real tool implementations wired to agent-files / agent-input / agent-browser / agent-capture /
//! sysinfo. Backends are created lazily on first use so idle RAM/CPU stays minimal.
use super::{Tool, ToolOutput, ToolRegistry, args, shell, truncate};
use crate::screen::CaptureSource;
use agent_files::SharedRoots;
use agent_input::{InputController, MouseButton, WindowManager};
use agent_protocol::{RiskTier, Sensitivity};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tokio::sync::OnceCell;

use RiskTier::{Destructive, Read, Write};

pub struct BuiltinCtx {
    pub roots: Option<Arc<SharedRoots>>,
    pub data_dir: PathBuf,
    pub shell_allowlist: Vec<String>,
    pub capture: Arc<CaptureSource>,
}

#[derive(Default)]
struct Lazy {
    wm: OnceLock<Box<dyn WindowManager>>,
    input: OnceLock<Box<dyn InputController>>,
    browser: OnceCell<agent_browser::Browser>,
}

impl Lazy {
    fn wm(&self) -> &dyn WindowManager {
        self.wm.get_or_init(agent_input::detect_wm).as_ref()
    }
    fn input(&self) -> &dyn InputController {
        self.input.get_or_init(agent_input::detect_input).as_ref()
    }
}

const FILES: &[&str] = &["files", "multi_step_task"];
const SHELL: &[&str] = &["shell", "system_info"];
const APPS: &[&str] = &["open_app", "window_control"];
const WIN: &[&str] = &["window_control", "open_app"];
const KEYS: &[&str] = &["type_or_keys", "browser"];
const SYS: &[&str] = &["system_control"];
const INFO: &[&str] = &["system_info"];
const CLIP: &[&str] = &["clipboard"];
const SCREEN: &[&str] = &["screen", "browser"];
const BROWSER: &[&str] = &["browser"];

fn obj(props: Value, required: &[&str]) -> Value {
    json!({ "type": "object", "properties": props, "required": required, "additionalProperties": false })
}

fn roots_of(r: &Option<Arc<SharedRoots>>) -> anyhow::Result<Arc<SharedRoots>> {
    r.clone()
        .ok_or_else(|| anyhow::anyhow!("no shared folders are configured"))
}

/// Case-insensitive root name fix-up: "documents/x" -> "Documents/x".
pub fn fix_root(names: &[String], rel: &str) -> String {
    let rel = rel.trim().trim_start_matches("./").trim_end_matches('/');
    let (first, rest) = rel.split_once('/').unwrap_or((rel, ""));
    match names.iter().find(|n| n.eq_ignore_ascii_case(first)) {
        Some(n) if rest.is_empty() => n.clone(),
        Some(n) => format!("{n}/{rest}"),
        None => rel.to_string(),
    }
}

fn rel_path(roots: &SharedRoots, a: &Value) -> anyhow::Result<String> {
    Ok(fix_root(&roots.names(), args::str(a, "path")?))
}

const EXEC_DENY: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "fish",
    "dash",
    "ksh",
    "csh",
    "tcsh",
    "nu",
    "python",
    "python3",
    "perl",
    "ruby",
    "node",
    "deno",
    "bun",
    "lua",
    "php",
    "rm",
    "dd",
    "mkfs",
    "shred",
    "sudo",
    "su",
    "doas",
    "pkexec",
    "kill",
    "killall",
    "pkill",
    "chmod",
    "chown",
    "curl",
    "wget",
    "nc",
    "ncat",
    "socat",
    "ssh",
    "scp",
    "systemctl",
    "shutdown",
    "reboot",
    "poweroff",
    "eval",
    "exec",
    "env",
    "xargs",
];

pub fn launch_risk(a: &Value) -> RiskTier {
    let Some(app) = args::opt_str(a, "app") else {
        return Read;
    };
    let app = app.trim();
    let simple = !app.is_empty()
        && app.len() <= 64
        && app
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.' | ' '))
        && app.split_whitespace().count() <= 3;
    let first = app
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if simple && !EXEC_DENY.contains(&first.as_str()) {
        Read
    } else {
        Destructive
    }
}

fn trash(data_dir: &Path, path: &Path) -> anyhow::Result<PathBuf> {
    let dir = data_dir.join("trash");
    std::fs::create_dir_all(&dir)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "item".into());
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let dest = dir.join(format!("{ts}-{name}"));
    match std::fs::rename(path, &dest) {
        Ok(()) => Ok(dest),
        Err(e) if path.is_file() => {
            // Cross-device: copy then unlink the single file. Never recursive removal.
            tracing::debug!("rename to trash failed ({e}); copying");
            std::fs::copy(path, &dest)?;
            std::fs::remove_file(path)?;
            Ok(dest)
        }
        Err(e) => anyhow::bail!("cannot move folder to trash: {e}"),
    }
}

fn sysinfo_text() -> String {
    use sysinfo::System;
    let mut s = System::new();
    s.refresh_cpu_usage();
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    s.refresh_cpu_usage();
    s.refresh_memory();
    let gib = |b: u64| b as f64 / 1024f64.powi(3);
    let up = System::uptime();
    format!(
        "CPU {:.0}% | RAM {:.1}/{:.1} GiB | uptime {}h {}m | {} {}",
        s.global_cpu_usage(),
        gib(s.used_memory()),
        gib(s.total_memory()),
        up / 3600,
        (up % 3600) / 60,
        System::host_name().unwrap_or_default(),
        System::long_os_version().unwrap_or_default(),
    )
}

fn process_list(limit: usize) -> String {
    use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
    let mut s = System::new();
    let kind = ProcessRefreshKind::nothing().with_cpu().with_memory();
    s.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
    std::thread::sleep(sysinfo::MINIMUM_CPU_UPDATE_INTERVAL);
    s.refresh_processes_specifics(ProcessesToUpdate::All, true, kind);
    // On Linux sysinfo also lists threads as tasks; keep real processes only.
    let mut v: Vec<_> = s
        .processes()
        .values()
        .filter(|p| p.thread_kind().is_none())
        .collect();
    v.sort_by(|a, b| {
        b.cpu_usage()
            .partial_cmp(&a.cpu_usage())
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(b.memory().cmp(&a.memory()))
    });
    let mut out = format!("{} processes; top by CPU:\n", v.len());
    for p in v.into_iter().take(limit) {
        out.push_str(&format!(
            "{:>7} {:<22} cpu {:>5.1}% mem {:>6} MiB\n",
            p.pid().as_u32(),
            truncate(&p.name().to_string_lossy(), 22),
            p.cpu_usage(),
            p.memory() / (1024 * 1024)
        ));
    }
    out
}

fn process_name(pid: u32) -> Option<String> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};
    let mut s = System::new();
    let pid = Pid::from_u32(pid);
    s.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    s.process(pid)
        .map(|p| p.name().to_string_lossy().into_owned())
}

fn kill_process(pid: u32) -> anyhow::Result<String> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, Signal, System};
    if pid <= 1 || pid == std::process::id() {
        anyhow::bail!("refusing to kill pid {pid}");
    }
    let mut s = System::new();
    let spid = Pid::from_u32(pid);
    s.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[spid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    let p = s
        .process(spid)
        .ok_or_else(|| anyhow::anyhow!("no process with pid {pid}"))?;
    let name = p.name().to_string_lossy().into_owned();
    let ok = p.kill_with(Signal::Term).unwrap_or_else(|| p.kill());
    if ok {
        Ok(format!("Sent SIGTERM to {name} ({pid})."))
    } else {
        anyhow::bail!("failed to signal {name} ({pid})")
    }
}

/// Newest-first listing of finished downloads (Chrome's `.crdownload` partials are marked).
fn list_downloads(dir: &Path, rel: Option<&str>, max: usize) -> String {
    let mut files: Vec<(std::time::SystemTime, String, u64)> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|e| {
            let m = e.metadata().ok()?;
            m.is_file().then(|| {
                (
                    m.modified().unwrap_or(std::time::UNIX_EPOCH),
                    e.file_name().to_string_lossy().into_owned(),
                    m.len(),
                )
            })
        })
        .collect();
    if files.is_empty() {
        return "No downloads yet.".into();
    }
    files.sort_by_key(|f| std::cmp::Reverse(f.0));
    let mut s: String = files
        .iter()
        .take(max)
        .map(|(_, name, len)| {
            let state = if name.ends_with(".crdownload") {
                " (still downloading)"
            } else {
                ""
            };
            match rel {
                Some(r) => format!("{r}/{name} ({len} bytes){state}\n"),
                None => format!("{name} ({len} bytes){state}\n"),
            }
        })
        .collect();
    if rel.is_none() {
        s.push_str("(Saved outside the shared folders; add a Downloads shared folder to send them to the phone.)\n");
    }
    s
}

fn safe_url(u: &str) -> anyhow::Result<String> {
    let u = u.trim();
    let l = u.to_ascii_lowercase();
    if l.starts_with("https://") || l.starts_with("http://") {
        Ok(u.to_string())
    } else if !l.contains("://")
        && !l.contains(' ')
        && l.contains('.')
        && !l.starts_with("javascript:")
    {
        Ok(format!("https://{u}"))
    } else {
        anyhow::bail!("only http(s) URLs are allowed")
    }
}

pub fn registry(ctx: BuiltinCtx) -> ToolRegistry {
    let lazy = Arc::new(Lazy::default());
    let BuiltinCtx {
        roots,
        data_dir,
        shell_allowlist,
        capture,
    } = ctx;
    let mut r = ToolRegistry::new();

    // ---------------- files ----------------
    {
        let roots = roots.clone();
        r.add(
            Tool::new(
                "fs.list",
                "List a folder inside the user's shared folders. Paths look like 'Documents/sub'. Use '' or '/' to list the shared roots.",
                obj(json!({"path": {"type":"string"}}), &["path"]),
                Read,
                FILES,
            )
            .blocking(move |a| {
                let roots = roots_of(&roots)?;
                let p = args::opt_str(&a, "path").unwrap_or("").trim().trim_matches('/');
                if p.is_empty() {
                    return Ok(ToolOutput::text(format!("Shared folders: {}", roots.names().join(", "))));
                }
                let rel = fix_root(&roots.names(), p);
                let mut entries = roots.list(&rel)?;
                entries.sort_by_key(|e| std::cmp::Reverse(e.modified_ms));
                let total = entries.len();
                let mut s = format!("{rel}: {total} entries (newest first)\n");
                for e in entries.iter().take(100) {
                    if e.is_dir {
                        s.push_str(&format!("{}/\n", e.name));
                    } else {
                        s.push_str(&format!("{}  ({} KB)\n", e.name, e.size.div_ceil(1024)));
                    }
                }
                if total > 100 {
                    s.push_str(&format!("... and {} more\n", total - 100));
                }
                Ok(ToolOutput::text(s))
            }),
        );
    }
    {
        let roots = roots.clone();
        r.add(
            Tool::new(
                "fs.read",
                "Read a text file from the shared folders (truncated to max_bytes, default 16000).",
                obj(
                    json!({"path": {"type":"string"}, "max_bytes": {"type":"integer"}}),
                    &["path"],
                ),
                Read,
                FILES,
            )
            .sensitivity(Sensitivity::Medium)
            .blocking(move |a| {
                let roots = roots_of(&roots)?;
                let max = args::opt_i64(&a, "max_bytes")
                    .unwrap_or(16_000)
                    .clamp(1, 64_000) as usize;
                Ok(ToolOutput::text(
                    roots.read_text(&rel_path(&roots, &a)?, max)?,
                ))
            }),
        );
    }
    {
        let roots = roots.clone();
        r.add(
            Tool::new(
                "fs.search",
                "Find files by (case-insensitive) name under a shared folder.",
                obj(
                    json!({"path": {"type":"string"}, "query": {"type":"string"}, "max_results": {"type":"integer"}}),
                    &["path", "query"],
                ),
                Read,
                FILES,
            )
            .blocking(move |a| {
                let roots = roots_of(&roots)?;
                let max = args::opt_i64(&a, "max_results").unwrap_or(50).clamp(1, 200) as usize;
                let hits = roots.search(&rel_path(&roots, &a)?, args::str(&a, "query")?, max)?;
                Ok(ToolOutput::text(if hits.is_empty() {
                    "No matches.".to_string()
                } else {
                    hits.join("\n")
                }))
            }),
        );
    }
    {
        let roots_w = roots.clone();
        let roots_r = roots.clone();
        r.add(
            Tool::new(
                "fs.write",
                "Create or overwrite a text file in the shared folders.",
                obj(
                    json!({"path": {"type":"string"}, "content": {"type":"string"}}),
                    &["path", "content"],
                ),
                Write,
                FILES,
            )
            .risk_with(move |a| {
                // Overwriting an existing file is destructive (spec §10).
                let exists = roots_r.as_ref().and_then(|r| {
                    let rel = rel_path(r, a).ok()?;
                    r.resolve(&rel, true).ok()
                });
                if exists.is_some() { Destructive } else { Write }
            })
            .preview_with(|a| {
                let content = args::opt_str(a, "content").unwrap_or("");
                format!(
                    "write {} ({} bytes):\n{}",
                    args::opt_str(a, "path").unwrap_or("?"),
                    content.len(),
                    truncate(content, 400)
                )
            })
            .blocking(move |a| {
                let roots = roots_of(&roots_w)?;
                let rel = rel_path(&roots, &a)?;
                let content = args::str(&a, "content")?;
                roots.write_text(&rel, content)?;
                Ok(ToolOutput::text(format!(
                    "Wrote {} bytes to {rel}.",
                    content.len()
                )))
            }),
        );
    }
    {
        let roots = roots.clone();
        let dd = data_dir.clone();
        r.add(
            Tool::new(
                "fs.delete",
                "Delete a file or folder in the shared folders (moved to the AutoPilot trash, recoverable).",
                obj(json!({"path": {"type":"string"}}), &["path"]),
                Destructive,
                FILES,
            )
            .preview_with(|a| format!("move to trash: {}", args::opt_str(a, "path").unwrap_or("?")))
            .blocking(move |a| {
                let roots = roots_of(&roots)?;
                let rel = rel_path(&roots, &a)?;
                if !rel.contains('/') {
                    anyhow::bail!("refusing to delete a whole shared root");
                }
                let abs = roots.resolve(&rel, true)?;
                let dest = trash(&dd, &abs)?;
                Ok(ToolOutput::text(format!(
                    "Moved {rel} to trash ({}).",
                    dest.file_name().unwrap_or_default().to_string_lossy()
                )))
            }),
        );
    }

    // ---------------- shell ----------------
    {
        let allow = shell_allowlist.clone();
        r.add(
            Tool::new(
                "shell.run",
                "Run one program with arguments (argv array, no shell, no pipes). 30 s timeout, 8 KB output.",
                obj(json!({"argv": {"type":"array","items":{"type":"string"}}}), &["argv"]),
                Write,
                SHELL,
            )
            .risk_with(move |a| match shell::parse_argv(a) {
                Ok(argv) => shell::classify(&argv, &allow),
                Err(_) => Destructive,
            })
            .preview_with(|a| match shell::parse_argv(a) {
                Ok(argv) => format!("$ {}", shell::preview(&argv)),
                Err(e) => format!("invalid: {e}"),
            })
            .run_async(|a| async move {
                let argv = shell::parse_argv(&a)?;
                let r = shell::run(&argv, shell::TIMEOUT, shell::OUTPUT_CAP).await?;
                let code = r.code.map(|c| c.to_string()).unwrap_or_else(|| "none".into());
                Ok(ToolOutput::text(format!("exit {code}\n{}", r.output)))
            }),
        );
    }

    // ---------------- apps / windows ----------------
    macro_rules! wm_tool {
        ($name:expr, $desc:expr, $schema:expr, $risk:expr, $intents:expr, |$wm:ident, $a:ident| $body:expr) => {{
            let lz = lazy.clone();
            r.add(
                Tool::new($name, $desc, $schema, $risk, $intents).blocking(move |$a| {
                    let $wm = lz.wm();
                    $body
                }),
            );
        }};
    }
    {
        let lz = lazy.clone();
        r.add(
            Tool::new(
                "app.launch",
                "Launch an application by name (e.g. 'firefox', 'spotify').",
                obj(json!({"app": {"type":"string"}}), &["app"]),
                Read,
                APPS,
            )
            .risk_with(launch_risk)
            .blocking(move |a| {
                let app = args::str(&a, "app")?.trim().to_string();
                lz.wm().launch(&app)?;
                Ok(ToolOutput::text(format!("Opened {app}.")))
            }),
        );
    }
    wm_tool!(
        "window.list",
        "List open windows.",
        obj(json!({}), &[]),
        Read,
        WIN,
        |wm, _a| {
            let ws = wm.list_windows()?;
            let mut s = format!("{} windows:\n", ws.len());
            for w in ws {
                s.push_str(&format!(
                    "{}[ws {}] {} — {}\n",
                    if w.focused { "* " } else { "  " },
                    w.workspace,
                    w.app,
                    truncate(&w.title, 80)
                ));
            }
            Ok(ToolOutput::text(s))
        }
    );
    wm_tool!(
        "window.focus",
        "Focus the first window whose app or title matches.",
        obj(json!({"query": {"type":"string"}}), &["query"]),
        Read,
        WIN,
        |wm, a| {
            let q = args::str(&a, "query")?;
            Ok(ToolOutput::text(if wm.focus(q)? {
                format!("Focused {q}.")
            } else {
                format!("No window matching '{q}'.")
            }))
        }
    );
    wm_tool!(
        "window.close",
        "Close the focused window.",
        obj(json!({}), &[]),
        Write,
        WIN,
        |wm, _a| {
            wm.close_focused()?;
            Ok(ToolOutput::text("Closed the window."))
        }
    );
    wm_tool!(
        "workspace.switch",
        "Switch to a workspace (number or name).",
        obj(json!({"workspace": {"type":"string"}}), &["workspace"]),
        Read,
        WIN,
        |wm, a| {
            let ws = a
                .get("workspace")
                .map(|v| {
                    v.as_str()
                        .map(str::to_string)
                        .unwrap_or_else(|| v.to_string())
                })
                .ok_or_else(|| anyhow::anyhow!("missing workspace"))?;
            if ws.is_empty()
                || ws.len() > 32
                || !ws
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
            {
                anyhow::bail!("invalid workspace name");
            }
            wm.switch_workspace(&ws)?;
            Ok(ToolOutput::text(format!("Switched to workspace {ws}.")))
        }
    );

    // ---------------- input ----------------
    {
        let lz = lazy.clone();
        r.add(
            Tool::new(
                "input.type",
                "Type text into the focused window.",
                obj(json!({"text": {"type":"string"}}), &["text"]),
                Write,
                KEYS,
            )
            .preview_with(|a| {
                format!(
                    "type: {}",
                    truncate(args::opt_str(a, "text").unwrap_or(""), 300)
                )
            })
            .blocking(move |a| {
                let t = args::str(&a, "text")?;
                lz.input().type_text(t)?;
                Ok(ToolOutput::text(format!(
                    "Typed {} characters.",
                    t.chars().count()
                )))
            }),
        );
    }
    {
        let lz = lazy.clone();
        r.add(
            Tool::new(
                "input.keys",
                "Press a key combo like 'ctrl+l', 'enter', 'super+1'.",
                obj(json!({"combo": {"type":"string"}}), &["combo"]),
                Write,
                KEYS,
            )
            .blocking(move |a| {
                let c = args::str(&a, "combo")?;
                lz.input().key_combo(c)?;
                Ok(ToolOutput::text(format!("Pressed {c}.")))
            }),
        );
    }
    {
        let lz = lazy.clone();
        r.add(
            Tool::new(
                "input.click",
                "Click at screen coordinates (last resort; prefer structured tools).",
                obj(json!({"x": {"type":"integer"}, "y": {"type":"integer"}, "button": {"type":"string","enum":["left","right","middle"]}}), &["x", "y"]),
                Write,
                &["screen"],
            )
            .blocking(move |a| {
                let (x, y) = (args::i64(&a, "x")? as i32, args::i64(&a, "y")? as i32);
                let b = match args::opt_str(&a, "button").unwrap_or("left") {
                    "right" => MouseButton::Right,
                    "middle" => MouseButton::Middle,
                    _ => MouseButton::Left,
                };
                lz.input().click(x, y, b)?;
                Ok(ToolOutput::text(format!("Clicked at {x},{y}.")))
            }),
        );
    }

    // ---------------- system ----------------
    // Volume/brightness/media are reversible and harmless: read tier so the fast path stays
    // instant. Lock = write, suspend = destructive.
    r.add(
        Tool::new(
            "system.volume",
            "Set volume level (0-100), change it by delta, or toggle mute.",
            obj(json!({"level": {"type":"integer"}, "delta": {"type":"integer"}, "mute_toggle": {"type":"boolean"}}), &[]),
            Read,
            SYS,
        )
        .blocking(|a| {
            use agent_input::system as s;
            if args::opt_bool(&a, "mute_toggle") == Some(true) {
                s::toggle_mute()?;
                Ok(ToolOutput::text("Toggled mute."))
            } else if let Some(l) = args::opt_i64(&a, "level") {
                let l = l.clamp(0, 100) as u8;
                s::set_volume(l)?;
                Ok(ToolOutput::text(format!("Volume set to {l}%.")))
            } else if let Some(d) = args::opt_i64(&a, "delta") {
                let d = d.clamp(-100, 100) as i8;
                s::change_volume(d)?;
                Ok(ToolOutput::text(format!("Volume {}{}%.", if d >= 0 { "+" } else { "" }, d)))
            } else {
                anyhow::bail!("give level, delta or mute_toggle")
            }
        }),
    );
    r.add(
        Tool::new(
            "system.brightness",
            "Set screen brightness (0-100).",
            obj(json!({"level": {"type":"integer"}}), &["level"]),
            Read,
            SYS,
        )
        .blocking(|a| {
            let l = args::i64(&a, "level")?.clamp(1, 100) as u8;
            agent_input::system::set_brightness(l)?;
            Ok(ToolOutput::text(format!("Brightness set to {l}%.")))
        }),
    );
    r.add(
        Tool::new(
            "system.media",
            "Media control: play_pause, next, previous.",
            obj(
                json!({"action": {"type":"string","enum":["play_pause","next","previous"]}}),
                &["action"],
            ),
            Read,
            SYS,
        )
        .blocking(|a| {
            let act = args::str(&a, "action")?;
            if !matches!(act, "play_pause" | "next" | "previous") {
                anyhow::bail!("unknown media action");
            }
            agent_input::system::media(act)?;
            Ok(ToolOutput::text(match act {
                "next" => "Skipped to the next track.",
                "previous" => "Back to the previous track.",
                _ => "Toggled play/pause.",
            }))
        }),
    );
    r.add(
        Tool::new(
            "system.lock",
            "Lock the screen.",
            obj(json!({}), &[]),
            Write,
            SYS,
        )
        .blocking(|_| {
            agent_input::system::lock_screen()?;
            Ok(ToolOutput::text("Screen locked."))
        }),
    );
    r.add(
        Tool::new(
            "system.suspend",
            "Suspend (sleep) the laptop. The agent becomes unreachable.",
            obj(json!({}), &[]),
            Destructive,
            SYS,
        )
        .preview_with(|_| "Suspend the laptop (you will lose the connection until it wakes)".into())
        .blocking(|_| {
            agent_input::system::suspend()?;
            Ok(ToolOutput::text("Suspending."))
        }),
    );
    r.add(
        Tool::new(
            "system.battery",
            "Battery percentage and charging state.",
            obj(json!({}), &[]),
            Read,
            INFO,
        )
        .blocking(|_| {
            Ok(ToolOutput::text(match agent_input::system::battery()? {
                Some((pct, charging)) => format!(
                    "Battery {pct}%{}.",
                    if charging { ", charging" } else { "" }
                ),
                None => "No battery found (desktop or AC only).".to_string(),
            }))
        }),
    );
    r.add(
        Tool::new(
            "system.info",
            "CPU, memory, uptime and OS.",
            obj(json!({}), &[]),
            Read,
            INFO,
        )
        .blocking(|_| Ok(ToolOutput::text(sysinfo_text()))),
    );
    r.add(
        Tool::new(
            "process.list",
            "Top processes by CPU.",
            obj(json!({"limit": {"type":"integer"}}), &[]),
            Read,
            INFO,
        )
        .blocking(|a| {
            let n = args::opt_i64(&a, "limit").unwrap_or(15).clamp(1, 50) as usize;
            Ok(ToolOutput::text(process_list(n)))
        }),
    );
    r.add(
        Tool::new(
            "process.kill",
            "Terminate a process by pid (SIGTERM).",
            obj(json!({"pid": {"type":"integer"}}), &["pid"]),
            Destructive,
            &["system_info", "shell"],
        )
        .preview_with(|a| {
            let pid = args::opt_i64(a, "pid").unwrap_or(-1);
            let name = u32::try_from(pid)
                .ok()
                .and_then(process_name)
                .unwrap_or_else(|| "?".into());
            format!("kill pid {pid} ({name})")
        })
        .blocking(|a| {
            let pid =
                u32::try_from(args::i64(&a, "pid")?).map_err(|_| anyhow::anyhow!("bad pid"))?;
            Ok(ToolOutput::text(kill_process(pid)?))
        }),
    );
    r.add(
        Tool::new(
            "clipboard.get",
            "Read the clipboard text.",
            obj(json!({}), &[]),
            Read,
            CLIP,
        )
        .sensitivity(Sensitivity::High)
        .blocking(|_| {
            Ok(ToolOutput::text(truncate(
                &agent_input::system::clipboard_get()?,
                8000,
            )))
        }),
    );
    r.add(
        Tool::new(
            "clipboard.set",
            "Put text on the clipboard.",
            obj(json!({"text": {"type":"string"}}), &["text"]),
            Write,
            CLIP,
        )
        .preview_with(|a| {
            format!(
                "clipboard <- {}",
                truncate(args::opt_str(a, "text").unwrap_or(""), 300)
            )
        })
        .blocking(|a| {
            let t = args::str(&a, "text")?;
            agent_input::system::clipboard_set(t)?;
            Ok(ToolOutput::text("Copied to the clipboard."))
        }),
    );
    r.add(
        Tool::new(
            "notify.local",
            "Show a desktop notification on the laptop.",
            obj(
                json!({"title": {"type":"string"}, "body": {"type":"string"}}),
                &["title"],
            ),
            Read,
            &["system_control"],
        )
        .blocking(|a| {
            agent_input::system::notify_local(
                args::str(&a, "title")?,
                args::opt_str(&a, "body").unwrap_or(""),
            )?;
            Ok(ToolOutput::text("Notification shown."))
        }),
    );

    // ---------------- screen ----------------
    {
        let cap = capture.clone();
        r.add(
            Tool::new(
                "screen.snapshot",
                "Take a screenshot (sent to the phone; visible to vision models).",
                obj(json!({"max_width": {"type":"integer"}}), &[]),
                Read,
                SCREEN,
            )
            .sensitivity(Sensitivity::Medium)
            .run_async(move |a| {
                let cap = cap.clone();
                async move {
                    let w = args::opt_i64(&a, "max_width")
                        .unwrap_or(1280)
                        .clamp(320, 3840) as u32;
                    let img = cap.capture(w, 60).await?;
                    Ok(ToolOutput {
                        text: format!("Screenshot taken ({}x{}).", img.width, img.height),
                        image: Some(img),
                    })
                }
            }),
        );
    }

    // ---------------- browser ----------------
    let profile = data_dir.join("browser-profile");
    // Downloads go to a shared folder when possible so the phone can fetch them.
    let (dl_dir, dl_rel): (PathBuf, Option<String>) = roots
        .as_ref()
        .and_then(|r| {
            let name = r
                .names()
                .into_iter()
                .find(|n| n.eq_ignore_ascii_case("Downloads"))?;
            let p = r.resolve(&name, true).ok()?;
            Some((p.join("AutoPilot"), Some(format!("{name}/AutoPilot"))))
        })
        .unwrap_or_else(|| (data_dir.join("downloads"), None));
    macro_rules! browser_tool {
        ($name:expr, $desc:expr, $schema:expr, $risk:expr, |$b:ident, $a:ident| $body:expr) => {{
            let lz = lazy.clone();
            let profile = profile.clone();
            let dl = dl_dir.clone();
            r.add(
                Tool::new($name, $desc, $schema, $risk, BROWSER).run_async(move |$a: Value| {
                    let lz = lz.clone();
                    let profile = profile.clone();
                    let dl = dl.clone();
                    async move {
                        let $b = lz
                            .browser
                            .get_or_try_init(|| async {
                                let b = agent_browser::Browser::launch(&profile, false).await?;
                                if let Err(e) = b.set_download_dir(&dl).await {
                                    tracing::warn!("browser downloads disabled: {e}");
                                }
                                anyhow::Ok(b)
                            })
                            .await?;
                        $body
                    }
                }),
            );
        }};
    }
    fn page_line(p: &agent_browser::PageInfo) -> String {
        format!("{} — {}", truncate(&p.title, 80), truncate(&p.url, 120))
    }
    browser_tool!(
        "browser.navigate",
        "Open a URL in the agent's browser.",
        obj(json!({"url": {"type":"string"}}), &["url"]),
        Read,
        |b, a| {
            let url = safe_url(args::str(&a, "url")?)?;
            b.navigate(&url).await?;
            b.settle().await;
            Ok(ToolOutput::text(format!(
                "Opened {}",
                page_line(&b.info().await?)
            )))
        }
    );
    browser_tool!(
        "browser.text",
        "Visible text of the current page.",
        obj(json!({"max_chars": {"type":"integer"}}), &[]),
        Read,
        |b, a| {
            let n = args::opt_i64(&a, "max_chars")
                .unwrap_or(4000)
                .clamp(200, 20_000) as usize;
            Ok(ToolOutput::text(b.page_text(n).await?))
        }
    );
    browser_tool!(
        "browser.elements",
        "Interactive elements (index, role, text) of the current page.",
        obj(json!({"max": {"type":"integer"}}), &[]),
        Read,
        |b, a| {
            let n = args::opt_i64(&a, "max").unwrap_or(40).clamp(1, 200) as usize;
            let els = b.elements(n).await?;
            let s: String = els
                .iter()
                .map(|e| format!("[{}] {} {}\n", e.index, e.role, truncate(&e.text, 80)))
                .collect();
            Ok(ToolOutput::text(if s.is_empty() {
                "No interactive elements.".into()
            } else {
                s
            }))
        }
    );
    browser_tool!(
        "browser.click",
        "Click an element by index from browser.elements.",
        obj(json!({"index": {"type":"integer"}}), &["index"]),
        Write,
        |b, a| {
            let i = args::i64(&a, "index")?.max(0) as usize;
            b.click_index(i).await?;
            Ok(ToolOutput::text(format!(
                "Clicked element {i}. Now on: {}",
                page_line(&b.info().await?)
            )))
        }
    );
    browser_tool!(
        "browser.type",
        "Type into an element by index; submit presses Enter.",
        obj(
            json!({"index": {"type":"integer"}, "text": {"type":"string"}, "submit": {"type":"boolean"}}),
            &["index", "text"]
        ),
        Write,
        |b, a| {
            let i = args::i64(&a, "index")?.max(0) as usize;
            b.type_index(
                i,
                args::str(&a, "text")?,
                args::opt_bool(&a, "submit").unwrap_or(false),
            )
            .await?;
            Ok(ToolOutput::text(format!("Typed into element {i}.")))
        }
    );
    browser_tool!(
        "browser.select",
        "Choose an option in a dropdown (by index from browser.elements) by its visible text.",
        obj(
            json!({"index": {"type":"integer"}, "option": {"type":"string"}}),
            &["index", "option"]
        ),
        Write,
        |b, a| {
            let i = args::i64(&a, "index")?.max(0) as usize;
            let chosen = b.select_index(i, args::str(&a, "option")?).await?;
            Ok(ToolOutput::text(format!(
                "Selected \"{chosen}\" in element {i}."
            )))
        }
    );
    browser_tool!(
        "browser.key",
        "Press a key in the browser's focused element: Enter, Escape, Tab, ArrowDown, ArrowUp, PageDown, Backspace.",
        obj(json!({"key": {"type":"string"}}), &["key"]),
        Write,
        |b, a| {
            let k = args::str(&a, "key")?.trim();
            anyhow::ensure!(
                !k.is_empty() && k.len() <= 20 && k.chars().all(|c| c.is_ascii_alphanumeric()),
                "invalid key name"
            );
            b.press_key(k).await?;
            Ok(ToolOutput::text(format!("Pressed {k}.")))
        }
    );
    browser_tool!(
        "browser.scroll",
        "Scroll the page: up, down, top or bottom.",
        obj(
            json!({"direction": {"type":"string", "enum": ["up", "down", "top", "bottom"]}}),
            &["direction"]
        ),
        Read,
        |b, a| Ok(ToolOutput::text(
            b.scroll(args::str(&a, "direction")?).await?
        ))
    );
    browser_tool!(
        "browser.history",
        "Go back or forward in the browser history.",
        obj(
            json!({"direction": {"type":"string", "enum": ["back", "forward"]}}),
            &["direction"]
        ),
        Read,
        |b, a| {
            let back = args::str(&a, "direction")? != "forward";
            Ok(ToolOutput::text(format!(
                "Now on: {}",
                page_line(&b.history(back).await?)
            )))
        }
    );
    browser_tool!(
        "browser.tabs",
        "List the browser's open tabs (* marks the active one).",
        obj(json!({}), &[]),
        Read,
        |b, _a| {
            let s: String = b
                .tabs()
                .await?
                .iter()
                .enumerate()
                .map(|(i, (p, active))| {
                    format!("[{i}]{} {}\n", if *active { "*" } else { "" }, page_line(p))
                })
                .collect();
            Ok(ToolOutput::text(s))
        }
    );
    browser_tool!(
        "browser.switch_tab",
        "Make a tab (index from browser.tabs) the active one.",
        obj(json!({"index": {"type":"integer"}}), &["index"]),
        Read,
        |b, a| {
            let i = args::i64(&a, "index")?.max(0) as usize;
            Ok(ToolOutput::text(format!(
                "Now on: {}",
                page_line(&b.switch_tab(i).await?)
            )))
        }
    );
    browser_tool!(
        "browser.wait_for",
        "Wait until text appears on the page (max 30 s).",
        obj(
            json!({"text": {"type":"string"}, "timeout_secs": {"type":"integer"}}),
            &["text"]
        ),
        Read,
        |b, a| {
            let t = args::str(&a, "text")?;
            let secs = args::opt_i64(&a, "timeout_secs").unwrap_or(10).clamp(1, 30) as u64;
            let found = b
                .wait_for_text(t, std::time::Duration::from_secs(secs))
                .await?;
            Ok(ToolOutput::text(if found {
                format!("\"{t}\" is on the page.")
            } else {
                format!("\"{t}\" did not appear within {secs}s.")
            }))
        }
    );
    browser_tool!(
        "browser.screenshot",
        "Screenshot of the browser page, sent to the user's phone.",
        obj(json!({}), &[]),
        Read,
        |b, _a| {
            let jpeg = b.screenshot_jpeg(60).await?;
            let (width, height) = agent_capture::jpeg_dimensions(&jpeg)?;
            Ok(ToolOutput {
                text: format!(
                    "Browser screenshot ({width}x{height}) of {}",
                    page_line(&b.info().await?)
                ),
                image: Some(super::Image {
                    jpeg,
                    width,
                    height,
                }),
            })
        }
    );
    {
        let (dir, rel) = (dl_dir.clone(), dl_rel.clone());
        r.add(
            Tool::new(
                "browser.downloads",
                "Recent files the browser downloaded (newest first), with the path to send them to the phone.",
                obj(json!({}), &[]),
                Read,
                BROWSER,
            )
            .blocking(move |_| Ok(ToolOutput::text(list_downloads(&dir, rel.as_deref(), 10)))),
        );
    }

    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> ToolRegistry {
        registry(BuiltinCtx {
            roots: None,
            data_dir: std::env::temp_dir(),
            shell_allowlist: vec!["ls".into()],
            capture: Arc::new(CaptureSource::new(|| panic!("not used"))),
        })
    }

    #[test]
    fn metadata() {
        let r = reg();
        let want = [
            ("fs.list", Read),
            ("fs.read", Read),
            ("fs.search", Read),
            ("fs.write", Write),
            ("fs.delete", Destructive),
            ("shell.run", Write),
            ("app.launch", Read),
            ("window.list", Read),
            ("window.focus", Read),
            ("window.close", Write),
            ("workspace.switch", Read),
            ("input.type", Write),
            ("input.keys", Write),
            ("input.click", Write),
            ("system.volume", Read),
            ("system.brightness", Read),
            ("system.media", Read),
            ("system.lock", Write),
            ("system.suspend", Destructive),
            ("system.battery", Read),
            ("system.info", Read),
            ("process.list", Read),
            ("process.kill", Destructive),
            ("clipboard.get", Read),
            ("clipboard.set", Write),
            ("screen.snapshot", Read),
            ("browser.navigate", Read),
            ("browser.text", Read),
            ("browser.elements", Read),
            ("browser.click", Write),
            ("browser.type", Write),
            ("browser.select", Write),
            ("browser.key", Write),
            ("browser.scroll", Read),
            ("browser.history", Read),
            ("browser.tabs", Read),
            ("browser.switch_tab", Read),
            ("browser.wait_for", Read),
            ("browser.screenshot", Read),
            ("browser.downloads", Read),
            ("notify.local", Read),
        ];
        assert_eq!(r.len(), want.len());
        for (n, risk) in want {
            let t = r.get(n).unwrap_or_else(|| panic!("{n}"));
            assert_eq!(t.base_risk, risk, "{n}");
            assert_eq!(t.schema["type"], "object");
            assert!(
                t.wire_name()
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            );
        }
        assert_eq!(
            r.get("clipboard.get").unwrap().sensitivity,
            Sensitivity::High
        );
        // Every rules-parser tool exists.
        for s in [
            "open firefox",
            "mute",
            "screenshot",
            "lock",
            "list files in Documents",
            "press enter",
            "type x",
            "copy x to clipboard",
            "battery",
            "what's running",
            "go to github.com",
        ] {
            let a = crate::rules::parse(s).unwrap();
            assert!(r.get(a.tool).is_some(), "{}", a.tool);
        }
    }

    #[test]
    fn dynamic_risks() {
        let r = reg();
        let sh = r.get("shell.run").unwrap();
        assert_eq!(sh.risk(&json!({"argv": ["ls", "-la"]})), Write);
        assert_eq!(sh.risk(&json!({"argv": ["cat", "x"]})), Destructive); // not in this allowlist
        assert_eq!(sh.risk(&json!({"argv": "ls"})), Destructive);
        assert_eq!(sh.preview(&json!({"argv": ["ls", "a b"]})), "$ ls 'a b'");
        let l = r.get("app.launch").unwrap();
        assert_eq!(l.risk(&json!({"app": "firefox"})), Read);
        assert_eq!(l.risk(&json!({"app": "bash -c rm"})), Destructive);
        assert_eq!(l.risk(&json!({"app": "/usr/bin/evil"})), Destructive);
        assert_eq!(l.risk(&json!({"app": "sudo"})), Destructive);
        let w = r.get("fs.write").unwrap();
        assert_eq!(
            w.risk(&json!({"path": "Documents/x", "content": ""})),
            Write
        );
    }

    #[test]
    fn helpers() {
        let names = vec!["Documents".to_string(), "Downloads".to_string()];
        assert_eq!(fix_root(&names, "documents/a/b"), "Documents/a/b");
        assert_eq!(fix_root(&names, "DOWNLOADS"), "Downloads");
        assert_eq!(fix_root(&names, "Other/x"), "Other/x");
        assert!(safe_url("javascript:alert(1)").is_err());
        assert!(safe_url("file:///etc/passwd").is_err());
        assert_eq!(safe_url("github.com").unwrap(), "https://github.com");
    }

    #[test]
    fn downloads_listing() {
        let d = std::env::temp_dir().join(format!("ap-dl-{}", uuid::Uuid::new_v4()));
        assert_eq!(
            list_downloads(&d, Some("Downloads/AutoPilot"), 5),
            "No downloads yet."
        );
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("old.pdf"), b"12").unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        std::fs::write(d.join("new.zip.crdownload"), b"1").unwrap();
        let s = list_downloads(&d, Some("Downloads/AutoPilot"), 5);
        assert_eq!(
            s,
            "Downloads/AutoPilot/new.zip.crdownload (1 bytes) (still downloading)\nDownloads/AutoPilot/old.pdf (2 bytes)\n"
        );
        assert!(list_downloads(&d, None, 1).contains("outside the shared folders"));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn trash_moves_not_deletes() {
        let base = std::env::temp_dir().join(format!("ap-trash-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&base).unwrap();
        let f = base.join("a.txt");
        std::fs::write(&f, "x").unwrap();
        let dest = trash(&base.join("data"), &f).unwrap();
        assert!(!f.exists());
        assert_eq!(std::fs::read_to_string(dest).unwrap(), "x");
        std::fs::remove_dir_all(base).unwrap();
    }

    #[tokio::test]
    async fn shell_tool_runs() {
        let r = reg();
        let out = r
            .get("shell.run")
            .unwrap()
            .run(json!({"argv": ["echo", "hi"]}))
            .await
            .unwrap();
        assert!(out.text.contains("exit 0") && out.text.contains("hi"));
    }
}
