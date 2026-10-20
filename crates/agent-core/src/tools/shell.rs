//! `shell.run`: argv only (never a shell), allowlisted + read-only-looking => write tier,
//! anything else => destructive. Hard timeout, capped output, killed on cancel/drop.
use agent_protocol::RiskTier;
use serde_json::Value;
use std::process::Stdio;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const TIMEOUT: Duration = Duration::from_secs(30);
pub const OUTPUT_CAP: usize = 8 * 1024;

pub fn parse_argv(args: &Value) -> anyhow::Result<Vec<String>> {
    let arr = args
        .get("argv")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow::anyhow!("`argv` must be an array of strings"))?;
    let argv: Vec<String> = arr
        .iter()
        .map(|v| v.as_str().map(str::to_string))
        .collect::<Option<_>>()
        .ok_or_else(|| anyhow::anyhow!("`argv` must contain only strings"))?;
    if argv.is_empty() || argv[0].trim().is_empty() {
        anyhow::bail!("`argv` is empty");
    }
    if argv.iter().any(|a| a.contains('\0')) {
        anyhow::bail!("NUL byte in argv");
    }
    Ok(argv)
}

fn first_is(argv: &[String], ok: &[&str]) -> bool {
    argv.get(1).is_some_and(|a| ok.contains(&a.as_str()))
}

/// Heuristic: does this allowlisted command look free of side effects?
pub fn read_only_looking(argv: &[String]) -> bool {
    let prog = argv[0].as_str();
    let has = |flags: &[&str]| argv[1..].iter().any(|a| flags.contains(&a.as_str()));
    match prog {
        "git" => {
            first_is(
                argv,
                &[
                    "status",
                    "log",
                    "diff",
                    "show",
                    "branch",
                    "rev-parse",
                    "ls-files",
                    "blame",
                    "describe",
                    "shortlog",
                    "remote",
                    "tag",
                ],
            ) && !has(&[
                "-d", "-D", "--delete", "add", "remove", "rm", "set-url", "-m", "-M",
            ])
        }
        "find" => !has(&[
            "-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf", "-fls",
            "-fprint0",
        ]),
        "hyprctl" => {
            first_is(
                argv,
                &[
                    "clients",
                    "workspaces",
                    "monitors",
                    "activewindow",
                    "activeworkspace",
                    "devices",
                    "version",
                    "layers",
                    "binds",
                    "cursorpos",
                    "getoption",
                    "-j",
                ],
            ) && !has(&[
                "dispatch", "keyword", "reload", "kill", "setprop", "--batch",
            ])
        }
        "pactl" => argv
            .get(1)
            .is_some_and(|a| a == "list" || a == "info" || a.starts_with("get-")),
        "playerctl" => {
            argv.len() == 1
                || first_is(
                    argv,
                    &[
                        "status",
                        "metadata",
                        "position",
                        "volume",
                        "-l",
                        "--list-all",
                    ],
                ) && !(argv
                    .get(1)
                    .is_some_and(|a| a == "position" || a == "volume")
                    && argv.len() > 2)
        }
        "ip" => argv[1..].iter().all(|a| {
            !matches!(
                a.as_str(),
                "add" | "del" | "delete" | "set" | "flush" | "change" | "replace" | "exec"
            )
        }),
        "ping" => has(&["-c"]) || argv.len() <= 2,
        "nvidia-smi" => !argv[1..].iter().any(|a| {
            a.starts_with("-r")
                || a.starts_with("--gpu-reset")
                || a.starts_with("-pm")
                || a.starts_with("-pl")
                || a.starts_with("-c")
                || a.starts_with("--persistence")
                || a.starts_with("--power-limit")
                || a.starts_with("-ac")
                || a.starts_with("-lgc")
        }),
        "date" => !has(&["-s", "--set"]),
        "tail" => !has(&["-f", "-F", "--follow"]),
        "ls" | "cat" | "df" | "du" | "free" | "uptime" | "whoami" | "uname" | "grep" | "head"
        | "wc" | "ps" => true,
        // Allowlisted by the user but unknown to us: be conservative.
        _ => false,
    }
}

pub fn classify(argv: &[String], allowlist: &[String]) -> RiskTier {
    let prog = argv[0].as_str();
    let bare = !prog.contains('/') && !prog.contains('\\');
    if bare && allowlist.iter().any(|a| a == prog) && read_only_looking(argv) {
        RiskTier::Write
    } else {
        RiskTier::Destructive
    }
}

pub fn preview(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            if a.is_empty()
                || a.contains(|c: char| c.is_whitespace() || "'\"$`\\|&;<>()*?".contains(c))
            {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                a.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

async fn read_capped<R: AsyncRead + Unpin>(r: Option<R>, cap: usize) -> (Vec<u8>, bool) {
    let Some(mut r) = r else {
        return (vec![], false);
    };
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let mut truncated = false;
    loop {
        match r.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = cap.saturating_sub(buf.len());
                buf.extend_from_slice(&chunk[..n.min(room)]);
                if n > room {
                    truncated = true;
                    // Keep draining so the child does not block on a full pipe.
                }
            }
        }
    }
    (buf, truncated)
}

pub struct ShellResult {
    pub code: Option<i32>,
    pub output: String,
    pub timed_out: bool,
}

/// Run argv directly (no shell). Child is killed on timeout or when the future is dropped.
pub async fn run(argv: &[String], timeout: Duration, cap: usize) -> anyhow::Result<ShellResult> {
    let mut cmd = tokio::process::Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(home) = dirs::home_dir() {
        cmd.current_dir(home);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("cannot start `{}`: {e}", argv[0]))?;
    let out = child.stdout.take();
    let err = child.stderr.take();
    let work = async {
        let ((o, ot), (e, et)) = tokio::join!(read_capped(out, cap), read_capped(err, cap / 2));
        let status = child.wait().await;
        (o, ot, e, et, status)
    };
    match tokio::time::timeout(timeout, work).await {
        Ok((o, ot, e, et, status)) => {
            let mut s = String::from_utf8_lossy(&o).into_owned();
            if !e.is_empty() {
                if !s.is_empty() {
                    s.push('\n');
                }
                s.push_str("[stderr] ");
                s.push_str(&String::from_utf8_lossy(&e));
            }
            if ot || et {
                s.push_str("\n[output truncated]");
            }
            Ok(ShellResult {
                code: status.ok().and_then(|s| s.code()),
                output: s,
                timed_out: false,
            })
        }
        Err(_) => Ok(ShellResult {
            code: None,
            output: format!("[killed after {}s timeout]", timeout.as_secs()),
            timed_out: true,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn v(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    fn allow() -> Vec<String> {
        crate::config::DEFAULT_SHELL_ALLOWLIST
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    #[test]
    fn classification() {
        let a = allow();
        for ok in [
            &["ls", "-la"][..],
            &["git", "status"],
            &["git", "log", "-5"],
            &["df", "-h"],
            &["hyprctl", "clients"],
            &["pactl", "get-sink-volume", "@DEFAULT_SINK@"],
            &["find", ".", "-name", "*.rs"],
            &["ping", "-c", "1", "1.1.1.1"],
            &["ip", "addr"],
        ] {
            assert_eq!(classify(&v(ok), &a), RiskTier::Write, "{ok:?}");
        }
        for bad in [
            &["rm", "-rf", "/"][..],
            &["git", "push"],
            &["git", "branch", "-D", "main"],
            &["find", ".", "-delete"],
            &["find", ".", "-exec", "rm", "{}", ";"],
            &["hyprctl", "dispatch", "exec", "rm"],
            &["pactl", "set-sink-volume", "0", "0%"],
            &["/bin/ls"],
            &["bash", "-c", "ls"],
            &["ip", "link", "set", "eth0", "down"],
            &["date", "-s", "2020-01-01"],
            &["tail", "-f", "/var/log/x"],
            &["ping", "1.1.1.1", "-i", "0"],
        ] {
            assert_eq!(classify(&v(bad), &a), RiskTier::Destructive, "{bad:?}");
        }
    }

    #[test]
    fn argv_parsing() {
        assert!(parse_argv(&json!({"argv": []})).is_err());
        assert!(parse_argv(&json!({"argv": "ls -la"})).is_err());
        assert!(parse_argv(&json!({"argv": ["ls", 3]})).is_err());
        assert!(parse_argv(&json!({"argv": ["ls\0"]})).is_err());
        assert_eq!(
            parse_argv(&json!({"argv": ["ls", "-l"]})).unwrap(),
            v(&["ls", "-l"])
        );
        assert_eq!(preview(&v(&["echo", "a b", "$(x)"])), "echo 'a b' '$(x)'");
    }

    #[tokio::test]
    async fn runs_without_shell_with_cap_and_timeout() {
        // No interpolation: "$HOME" stays literal.
        let r = run(&v(&["echo", "$HOME", "a;b"]), TIMEOUT, OUTPUT_CAP)
            .await
            .unwrap();
        assert_eq!(r.output.trim(), "$HOME a;b");
        assert_eq!(r.code, Some(0));
        let r = run(&v(&["head", "-c", "100000", "/dev/zero"]), TIMEOUT, 1024)
            .await
            .unwrap();
        assert!(r.output.len() < 1100);
        assert!(r.output.ends_with("[output truncated]"));
        let r = run(&v(&["sleep", "5"]), Duration::from_millis(100), 1024)
            .await
            .unwrap();
        assert!(r.timed_out);
        assert!(
            run(&v(&["definitely-not-a-program-xyz"]), TIMEOUT, 10)
                .await
                .is_err()
        );
    }
}
