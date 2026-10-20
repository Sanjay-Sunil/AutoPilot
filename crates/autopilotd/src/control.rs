//! Local control socket (JSON lines). Unix: `<data_dir>/control.sock` (0600, same-uid peers only).
//! Elsewhere: localhost TCP on an ephemeral port; port + random token in `<data_dir>/control.json`
//! (the token must be the first line).
//!
//! Requests: `{"cmd":"pair"}` (`"wait": false` to return immediately), `{"cmd":"kill"}`,
//! `{"cmd":"status"}`, `{"cmd":"devices"}`, `{"cmd":"revoke","pk":"<b64>"}`.
//! Every response is one line with `"ok": true|false`. `pair` additionally pushes
//! `{"event":"paired","device_name":..,"code":..,"pk_b64":..}` (or `{"event":"expired"}`).
use crate::{DaemonState, now_ms};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tracing::{debug, info, warn};

const MAX_REQUEST_BYTES: u64 = 64 * 1024;

pub fn socket_path(data_dir: &Path) -> PathBuf {
    data_dir.join("control.sock")
}

#[cfg_attr(unix, allow(dead_code))]
fn token_path(data_dir: &Path) -> PathBuf {
    data_dir.join("control.json")
}

/// Removes the socket file on drop.
pub struct ControlGuard(PathBuf);

impl Drop for ControlGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

/// Bind the control endpoint and serve it on a background task.
#[cfg(unix)]
pub async fn start(data_dir: &Path, state: Arc<DaemonState>) -> anyhow::Result<ControlGuard> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let path = socket_path(data_dir);
    if path.exists() {
        if tokio::net::UnixStream::connect(&path).await.is_ok() {
            anyhow::bail!("another autopilotd is already running ({})", path.display());
        }
        std::fs::remove_file(&path)?;
    }
    let listener = tokio::net::UnixListener::bind(&path)?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    let my_uid = std::fs::metadata(data_dir)?.uid();
    info!(path = %path.display(), "control socket ready");
    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(x) => x,
                Err(e) => {
                    warn!("control accept failed: {e}");
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    continue;
                }
            };
            match stream.peer_cred() {
                Ok(c) if c.uid() == my_uid => {}
                _ => {
                    warn!("control connection from another user refused");
                    continue;
                }
            }
            let state = state.clone();
            tokio::spawn(async move { handle_conn(stream, state, None).await });
        }
    });
    Ok(ControlGuard(path))
}

#[cfg(not(unix))]
pub async fn start(data_dir: &Path, state: Arc<DaemonState>) -> anyhow::Result<ControlGuard> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let mut raw = [0u8; 24];
    getrandom_fill(&mut raw);
    let token: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    let path = token_path(data_dir);
    std::fs::write(
        &path,
        serde_json::to_vec(&json!({"port": port, "token": token}))?,
    )?;
    tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let state = state.clone();
            let token = token.clone();
            tokio::spawn(async move { handle_conn(stream, state, Some(token)).await });
        }
    });
    Ok(ControlGuard(path))
}

#[cfg(not(unix))]
fn getrandom_fill(buf: &mut [u8]) {
    // Uuid v4 uses the OS RNG.
    for chunk in buf.chunks_mut(16) {
        let u = uuid::Uuid::new_v4();
        chunk.copy_from_slice(&u.as_bytes()[..chunk.len()]);
    }
}

fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

async fn handle_conn<S>(stream: S, state: Arc<DaemonState>, auth: Option<String>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (r, mut w) = tokio::io::split(stream);
    let mut lines = BufReader::new(r.take(MAX_REQUEST_BYTES)).lines();
    if let Some(expected) = auth {
        match lines.next_line().await {
            Ok(Some(t)) if ct_eq(t.trim(), &expected) => {}
            _ => return,
        }
    }
    while let Ok(Some(line)) = lines.next_line().await {
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let _ = write_line(
                    &mut w,
                    &json!({"ok": false, "error": format!("bad request: {e}")}),
                )
                .await;
                continue;
            }
        };
        let cmd = req["cmd"].as_str().unwrap_or_default().to_string();
        debug!(%cmd, "control request");
        let resp = match cmd.as_str() {
            "status" => {
                let devices = state.trust.lock().await.list().len();
                json!({
                    "ok": true,
                    "laptop_name": state.laptop_name,
                    "laptop_pk": state.keys.public_b64(),
                    "listen": state.listen,
                    "relay": state.relay,
                    "sessions": state.active_sessions.load(Ordering::Relaxed),
                    "devices": devices,
                    "pending_tokens": state.pairing.outstanding(),
                    "uptime_s": state.started.elapsed().as_secs(),
                })
            }
            "devices" => json!({"ok": true, "devices": state.trust.lock().await.list()}),
            "revoke" => match req["pk"].as_str() {
                Some(pk) => match state.trust.lock().await.revoke(pk) {
                    Ok(revoked) => {
                        info!(revoked, "device revoke requested via control socket");
                        json!({"ok": true, "revoked": revoked})
                    }
                    Err(e) => json!({"ok": false, "error": e.to_string()}),
                },
                None => json!({"ok": false, "error": "missing pk"}),
            },
            "kill" => {
                let reason = req["reason"]
                    .as_str()
                    .unwrap_or("kill switch (control socket)");
                warn!("KILL SWITCH via control socket");
                (state.kill)(reason);
                json!({"ok": true})
            }
            "pair" => {
                let mut events = state.pairing.subscribe();
                let info = state.issue_pairing();
                let resp = json!({"ok": true, "uri": info.uri, "qr": info.qr, "expires_at_ms": info.expires_at_ms});
                if write_line(&mut w, &resp).await.is_err() {
                    return;
                }
                if req["wait"].as_bool() == Some(false) {
                    continue;
                }
                let left = Duration::from_millis(info.expires_at_ms.saturating_sub(now_ms()));
                let ev = tokio::select! {
                    r = tokio::time::timeout(left, events.recv()) => match r {
                        Ok(Ok(e)) => json!({"event": "paired", "device_name": e.device_name, "code": e.code, "pk_b64": e.pk_b64}),
                        _ => json!({"event": "expired"}),
                    },
                    // Client hung up (e.g. the tray reads one line and closes): stop waiting.
                    _ = lines.next_line() => return,
                };
                let _ = write_line(&mut w, &ev).await;
                return;
            }
            _ => json!({"ok": false, "error": format!("unknown command {cmd:?}")}),
        };
        if write_line(&mut w, &resp).await.is_err() {
            return;
        }
    }
}

async fn write_line<W: AsyncWrite + Unpin>(w: &mut W, v: &Value) -> std::io::Result<()> {
    let mut b = serde_json::to_vec(v).map_err(std::io::Error::other)?;
    b.push(b'\n');
    w.write_all(&b).await?;
    w.flush().await
}

/// Client side: open the control endpoint, send one request, and return a line reader.
pub struct ControlClient {
    lines: tokio::io::Lines<BufReader<Box<dyn AsyncRead + Unpin + Send>>>,
    _w: Box<dyn AsyncWrite + Unpin + Send>,
}

impl ControlClient {
    pub async fn request(data_dir: &Path, req: &Value) -> anyhow::Result<(Self, Value)> {
        let (r, mut w): (
            Box<dyn AsyncRead + Unpin + Send>,
            Box<dyn AsyncWrite + Unpin + Send>,
        ) = {
            #[cfg(unix)]
            {
                let path = socket_path(data_dir);
                let s = tokio::net::UnixStream::connect(&path).await.map_err(|e| {
                    anyhow::anyhow!(
                        "cannot reach the daemon at {} ({e}); is `autopilotd run` running?",
                        path.display()
                    )
                })?;
                let (r, w) = s.into_split();
                (Box::new(r), Box::new(w))
            }
            #[cfg(not(unix))]
            {
                let info: Value = serde_json::from_slice(&std::fs::read(token_path(data_dir))?)?;
                let port = info["port"].as_u64().unwrap_or(0) as u16;
                let s = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
                let (r, mut w) = s.into_split();
                w.write_all(format!("{}\n", info["token"].as_str().unwrap_or_default()).as_bytes())
                    .await?;
                (Box::new(r), Box::new(w))
            }
        };
        write_line(&mut w, req).await?;
        let mut c = Self {
            lines: BufReader::new(r).lines(),
            _w: w,
        };
        let first = c
            .next()
            .await?
            .ok_or_else(|| anyhow::anyhow!("daemon closed the control connection"))?;
        if first["ok"] != Value::Bool(true) {
            anyhow::bail!(
                "daemon error: {}",
                first["error"].as_str().unwrap_or("unknown")
            );
        }
        Ok((c, first))
    }

    pub async fn next(&mut self) -> anyhow::Result<Option<Value>> {
        match self.lines.next_line().await? {
            Some(l) => Ok(Some(serde_json::from_str(&l)?)),
            None => Ok(None),
        }
    }
}
