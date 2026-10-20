//! Talks to `autopilotd`: first over the local control socket (JSON lines), falling back to the CLI
//! (`autopilotd <cmd> --json`) when the socket is unavailable (e.g. on Windows before the named pipe
//! lands, or when the daemon runs under another supervisor).

use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::Command;

pub fn data_dir() -> PathBuf {
    dirs::data_local_dir()
        .unwrap_or_else(|| dirs::home_dir().unwrap_or_default().join(".local/share"))
        .join("autopilot")
}

pub fn socket_path() -> PathBuf {
    data_dir().join("control.sock")
}

/// Send one command object, return the parsed JSON reply. `{"error": "..."}` replies become Err.
pub fn request(cmd: Value) -> Result<Value, String> {
    let reply = match via_socket(&cmd) {
        Ok(v) => v,
        Err(sock_err) => via_cli(&cmd).map_err(|cli_err| {
            format!("daemon unreachable (socket: {sock_err}; cli: {cli_err})")
        })?,
    };
    if let Some(e) = reply.get("error").and_then(Value::as_str) {
        return Err(e.to_owned());
    }
    Ok(reply)
}

#[cfg(unix)]
fn via_socket(cmd: &Value) -> Result<Value, String> {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let mut s = UnixStream::connect(socket_path()).map_err(|e| e.to_string())?;
    let t = Some(Duration::from_secs(5));
    s.set_read_timeout(t).map_err(|e| e.to_string())?;
    s.set_write_timeout(t).map_err(|e| e.to_string())?;
    let mut line = serde_json::to_vec(cmd).map_err(|e| e.to_string())?;
    line.push(b'\n');
    s.write_all(&line).map_err(|e| e.to_string())?;
    let mut buf = String::new();
    // Bound the reply size (pairing replies are small).
    BufReader::new(std::io::Read::take(&s, 1 << 20))
        .read_line(&mut buf)
        .map_err(|e| e.to_string())?;
    serde_json::from_str(buf.trim()).map_err(|e| format!("bad reply: {e}"))
}

#[cfg(not(unix))]
fn via_socket(_cmd: &Value) -> Result<Value, String> {
    Err("control socket not supported on this platform".into())
}

fn daemon_bin() -> PathBuf {
    if let Some(p) = std::env::var_os("AUTOPILOTD") {
        return PathBuf::from(p);
    }
    let local = dirs::home_dir()
        .unwrap_or_default()
        .join(".local/bin/autopilotd");
    if local.is_file() {
        return local;
    }
    PathBuf::from(if cfg!(windows) {
        "autopilotd.exe"
    } else {
        "autopilotd"
    })
}

fn via_cli(cmd: &Value) -> Result<Value, String> {
    let name = cmd.get("cmd").and_then(Value::as_str).unwrap_or_default();
    let args: Vec<String> = match name {
        "pair" => vec!["pair".into(), "--json".into()],
        "kill" => vec!["kill".into()],
        "status" => vec!["status".into(), "--json".into()],
        "devices" => vec!["devices".into(), "--json".into()],
        "revoke" => {
            let pk = cmd.get("pk").and_then(Value::as_str).ok_or("missing pk")?;
            vec!["devices".into(), "revoke".into(), pk.into()]
        }
        other => return Err(format!("no CLI fallback for {other:?}")),
    };
    let out = Command::new(daemon_bin())
        .args(&args)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&out.stderr).trim().to_owned());
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let text = stdout.trim();
    if text.is_empty() {
        return Ok(json!({"ok": true}));
    }
    // Take the last JSON line (the CLI may print a human line first).
    text.lines()
        .rev()
        .find_map(|l| serde_json::from_str(l).ok())
        .ok_or_else(|| "CLI did not print JSON".to_owned())
}

/// Render a pairing URI as an SVG QR code (dark modules on white, with quiet zone).
pub fn qr_svg(uri: &str) -> Result<String, String> {
    let code = qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::M)
        .map_err(|e| e.to_string())?;
    Ok(code
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(280, 280)
        .quiet_zone(true)
        .build())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_renders() {
        let svg = qr_svg("autopilot://pair?d=eyJ0ZXN0Ijp0cnVlfQ").unwrap();
        assert!(svg.starts_with("<?xml") || svg.starts_with("<svg"));
    }

    #[test]
    fn cli_fallback_rejects_unknown() {
        assert!(via_cli(&json!({"cmd": "rm -rf"})).is_err());
    }
}
