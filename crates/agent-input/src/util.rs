//! Small process helpers. Every external command is spawned with an explicit argv
//! (no shell) unless a function name says otherwise.
use std::ffi::OsStr;
use std::io::Write;
use std::process::{Command, Stdio};

/// True if `bin` is an executable on PATH (cheap stat walk; no subprocess).
pub fn which(bin: &str) -> bool {
    find_in_path(bin).is_some()
}

pub fn find_in_path(bin: &str) -> Option<std::path::PathBuf> {
    if bin.contains('/') || bin.contains('\\') {
        let p = std::path::PathBuf::from(bin);
        return is_exec(&p).then_some(p);
    }
    let paths = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&paths) {
        let p = dir.join(bin);
        if is_exec(&p) {
            return Some(p);
        }
        #[cfg(windows)]
        for ext in ["exe", "cmd", "bat"] {
            let pe = p.with_extension(ext);
            if pe.is_file() {
                return Some(pe);
            }
        }
    }
    None
}

#[cfg(unix)]
fn is_exec(p: &std::path::Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(p)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_exec(p: &std::path::Path) -> bool {
    p.is_file()
}

/// Run a command to completion and return trimmed stdout. Errors include stderr.
pub fn run<S: AsRef<OsStr>>(prog: &str, args: &[S]) -> anyhow::Result<String> {
    let out = Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run {prog}: {e}"))?;
    if !out.status.success() {
        anyhow::bail!(
            "{prog} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

/// Run a command feeding `input` on stdin.
pub fn run_stdin<S: AsRef<OsStr>>(prog: &str, args: &[S], input: &[u8]) -> anyhow::Result<()> {
    let mut child = Command::new(prog)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to run {prog}: {e}"))?;
    child.stdin.take().expect("piped").write_all(input)?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        anyhow::bail!(
            "{prog} failed ({}): {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Spawn detached (new session on unix), not waited on.
pub fn spawn_detached(argv: &[String]) -> anyhow::Result<()> {
    let (prog, rest) = argv
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("empty command"))?;
    let mut cmd = Command::new(prog);
    cmd.args(rest)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to launch {prog}: {e}"))?;
    // Reap in the background so it never becomes a zombie.
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
}

/// POSIX-shell quote one word (single quotes; safe chars left bare).
pub fn shell_quote(s: &str) -> String {
    if !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || "_-./=:,+@%".contains(c))
    {
        return s.to_string();
    }
    format!("'{}'", s.replace('\'', r"'\''"))
}

pub fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Lua string literal; anything outside printable ASCII becomes a `\ddd` byte escape.
pub fn lua_quote(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for b in s.bytes() {
        match b {
            b'"' => o.push_str("\\\""),
            b'\\' => o.push_str("\\\\"),
            0x20..=0x7e => o.push(b as char),
            _ => o.push_str(&format!("\\{b:03}")),
        }
    }
    o.push('"');
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting() {
        assert_eq!(shell_quote("firefox"), "firefox");
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's;rm -rf"), r"'it'\''s;rm -rf'");
        assert_eq!(shell_quote(""), "''");
        assert_eq!(lua_quote("a\"b\\c\n"), r#""a\"b\\c\010""#);
        assert_eq!(lua_quote("é"), r#""\195\169""#);
    }
}
