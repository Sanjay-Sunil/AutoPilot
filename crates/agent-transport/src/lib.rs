//! Secure session transport: Noise_XX_25519_ChaChaPoly_BLAKE2s over WebSocket (direct LAN/Tailscale
//! or through the backend relay). See docs/protocol.md for the exact wire format.
//! CONTRACT: keep these public signatures; implement bodies.
use agent_protocol::{
    Envelope, MAX_NOISE_MSG, Message, PairClaim, PairResult, PairingQr, Ping, SeqGuard,
};
use anyhow::{Context, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use blake2::{Blake2s256, Digest};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, broadcast, mpsc};
use tokio::time::timeout;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::tungstenite::handshake::server::{ErrorResponse, Request, Response};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tracing::{debug, info, warn};
use uuid::Uuid;
use zeroize::Zeroize;

#[cfg(test)]
mod tests;

/// Noise protocol name (docs/protocol.md).
pub const NOISE_PARAMS: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
/// Noise prologue (docs/protocol.md).
pub const PROLOGUE: &[u8] = b"autopilot/1";
/// Max plaintext per Noise transport message (65_535 - 16 byte tag).
pub const MAX_PLAINTEXT: usize = MAX_NOISE_MSG - 16;
/// Upper bound of the bytes an [`Envelope`] adds around a serialized [`Message`]
/// (`"v":1,` + `"id":"<uuid>",` + `"session":"<uuid>",` + `"seq":<u64>,`).
const ENVELOPE_OVERHEAD: usize = 128;
/// Default pairing token lifetime.
pub const PAIRING_TTL_MS: u64 = 5 * 60 * 1000;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const PAIR_CLAIM_TIMEOUT: Duration = Duration::from_secs(30);
const IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const CLIENT_PING_INTERVAL: Duration = Duration::from_secs(25);
const RELAY_PING_INTERVAL: Duration = Duration::from_secs(30);
const RELAY_DEAD_AFTER: Duration = Duration::from_secs(90);
const RELAY_MAX_BACKOFF: Duration = Duration::from_secs(60);
/// Relay close code: a newer connection of the same role replaced this one.
const RELAY_CLOSE_REPLACED: u16 = 4000;
const MAX_PENDING_TOKENS: usize = 5;
const HANDSHAKES_PER_MINUTE: u32 = 10;
const MAX_CONNECTIONS: usize = 32;
const CHANNEL_DEPTH: usize = 64;

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn noise_builder<'a>() -> anyhow::Result<snow::Builder<'a>> {
    Ok(snow::Builder::new(NOISE_PARAMS.parse()?).prologue(PROLOGUE)?)
}

/// `room = hex(BLAKE2s-256(laptop_static_pk))[0..32]`.
pub fn relay_room(laptop_pk: &[u8]) -> String {
    let mut h = hex::encode(Blake2s256::digest(laptop_pk));
    h.truncate(32);
    h
}

/// Decode a base64url (no padding) X25519 public key.
pub fn decode_pk(pk_b64: &str) -> anyhow::Result<[u8; 32]> {
    let v = B64
        .decode(pk_b64.trim())
        .context("public key is not base64url")?;
    v.try_into()
        .map_err(|_| anyhow!("public key must be 32 bytes"))
}

// ------------------------------------------------------------------------------------------------
// Keys
// ------------------------------------------------------------------------------------------------

/// Laptop/phone static Noise keypair (X25519). Stored 0600 at `path` (keyring later).
pub struct DeviceKeys {
    pub private: [u8; 32],
    pub public: [u8; 32],
}

impl Drop for DeviceKeys {
    fn drop(&mut self) {
        self.private.zeroize();
    }
}

impl DeviceKeys {
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read(path) {
            Ok(mut bytes) => {
                restrict_perms(path)?;
                let res: Result<[u8; 32], _> = bytes.as_slice().try_into();
                bytes.zeroize();
                let private =
                    res.map_err(|_| anyhow!("{}: key file must be 32 bytes", path.display()))?;
                Ok(Self::from_private(private))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if let Some(dir) = path.parent() {
                    create_private_dir(dir)?;
                }
                let keys = Self::generate();
                write_private_file(path, &keys.private, true)?;
                info!(path = %path.display(), "generated new device key");
                Ok(keys)
            }
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn generate() -> Self {
        let mut private = [0u8; 32];
        getrandom::fill(&mut private).expect("OS random number generator");
        Self::from_private(private)
    }

    /// Derive the public key from a private X25519 scalar.
    pub fn from_private(private: [u8; 32]) -> Self {
        let public = x25519_dalek::x25519(private, x25519_dalek::X25519_BASEPOINT_BYTES);
        Self { private, public }
    }

    /// base64url, no padding.
    pub fn public_b64(&self) -> String {
        B64.encode(self.public)
    }
}

/// Create `dir` (and parents); a newly created leaf gets 0700 on unix.
pub fn create_private_dir(dir: &Path) -> anyhow::Result<()> {
    if dir.as_os_str().is_empty() || dir.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn restrict_perms(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            warn!(path = %path.display(), "key file was readable by others; restricting to 0600");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Write `data` to `path` with 0600 permissions (unix). `create_new` refuses to overwrite.
fn write_private_file(path: &Path, data: &[u8], create_new: bool) -> anyhow::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true);
    if create_new {
        opts.create_new(true);
    } else {
        opts.create(true).truncate(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// Trust store
// ------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PairedDevice {
    pub name: String,
    pub pk_b64: String,
    pub paired_at_ms: u64,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct TrustFile {
    v: u8,
    devices: Vec<PairedDevice>,
}

/// Trusted phones, persisted as JSON.
pub struct TrustStore {
    path: PathBuf,
    devices: Vec<PairedDevice>,
    revoked: broadcast::Sender<String>,
}

impl TrustStore {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let devices = match std::fs::read(path) {
            Ok(b) => {
                serde_json::from_slice::<TrustFile>(&b)
                    .with_context(|| format!("parsing {}", path.display()))?
                    .devices
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let (revoked, _) = broadcast::channel(16);
        Ok(Self {
            path: path.to_path_buf(),
            devices,
            revoked,
        })
    }

    pub fn is_trusted(&self, pk_b64: &str) -> bool {
        self.devices.iter().any(|d| d.pk_b64 == pk_b64)
    }

    /// Look up a trusted device by public key.
    pub fn get(&self, pk_b64: &str) -> Option<PairedDevice> {
        self.devices.iter().find(|d| d.pk_b64 == pk_b64).cloned()
    }

    pub fn add(&mut self, d: PairedDevice) -> anyhow::Result<()> {
        decode_pk(&d.pk_b64)?;
        let mut next = self.devices.clone();
        next.retain(|x| x.pk_b64 != d.pk_b64);
        next.push(d);
        self.persist(&next)?;
        self.devices = next;
        Ok(())
    }

    pub fn revoke(&mut self, pk_b64: &str) -> anyhow::Result<bool> {
        let mut next = self.devices.clone();
        next.retain(|x| x.pk_b64 != pk_b64);
        if next.len() == self.devices.len() {
            return Ok(false);
        }
        self.persist(&next)?;
        self.devices = next;
        // Live sessions of this device subscribe to this and close immediately.
        let _ = self.revoked.send(pk_b64.to_string());
        Ok(true)
    }

    pub fn list(&self) -> Vec<PairedDevice> {
        self.devices.clone()
    }

    /// Notifications (public key) whenever a device is revoked.
    pub fn subscribe_revocations(&self) -> broadcast::Receiver<String> {
        self.revoked.subscribe()
    }

    fn persist(&self, devices: &[PairedDevice]) -> anyhow::Result<()> {
        if let Some(dir) = self.path.parent() {
            create_private_dir(dir)?;
        }
        let json = serde_json::to_vec_pretty(&TrustFile {
            v: 1,
            devices: devices.to_vec(),
        })?;
        let mut tmp = self.path.clone().into_os_string();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let _ = std::fs::remove_file(&tmp);
        write_private_file(&tmp, &json, true)?;
        std::fs::rename(&tmp, &self.path)
            .with_context(|| format!("replacing {}", self.path.display()))?;
        #[cfg(unix)]
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            if let Ok(d) = std::fs::File::open(dir) {
                let _ = d.sync_all();
            }
        }
        Ok(())
    }
}

// ------------------------------------------------------------------------------------------------
// Pairing tokens
// ------------------------------------------------------------------------------------------------

struct PendingToken {
    token: [u8; 16],
    expires_at_ms: u64,
}

/// Emitted when a new phone was paired successfully.
#[derive(Debug, Clone)]
pub struct PairingEvent {
    pub device_name: String,
    pub pk_b64: String,
    /// 6-digit confirmation code (same value is shown on the phone).
    pub code: String,
}

/// One-time pairing tokens (random 16 bytes, base64url, short TTL, single use, constant-time compare).
pub struct PairingManager {
    pending: std::sync::Mutex<Vec<PendingToken>>,
    events: broadcast::Sender<PairingEvent>,
}

impl Default for PairingManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PairingManager {
    pub fn new() -> Self {
        let (events, _) = broadcast::channel(8);
        Self {
            pending: std::sync::Mutex::new(Vec::new()),
            events,
        }
    }

    /// Issue a token valid for `ttl_ms`. At most 5 tokens are outstanding (oldest dropped).
    pub fn issue(&self, ttl_ms: u64) -> (String, u64) {
        let mut token = [0u8; 16];
        getrandom::fill(&mut token).expect("OS random number generator");
        let now = now_ms();
        let expires_at_ms = now.saturating_add(ttl_ms);
        let mut p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        p.retain(|t| t.expires_at_ms > now);
        while p.len() >= MAX_PENDING_TOKENS {
            p.remove(0);
        }
        p.push(PendingToken {
            token,
            expires_at_ms,
        });
        (B64.encode(token), expires_at_ms)
    }

    /// Single use: a matching, unexpired token is removed and `true` returned.
    pub fn consume(&self, token: &str) -> bool {
        let Ok(raw) = B64.decode(token.as_bytes()) else {
            return false;
        };
        if raw.len() != 16 {
            return false;
        }
        let now = now_ms();
        let mut p = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let mut found = None;
        for (i, t) in p.iter().enumerate() {
            // Compare against every entry without early exit.
            let eq: bool = t.token.ct_eq(raw.as_slice()).into();
            if eq && t.expires_at_ms > now {
                found = Some(i);
            }
        }
        if let Some(i) = found {
            p.remove(i);
        }
        p.retain(|t| t.expires_at_ms > now);
        found.is_some()
    }

    /// Number of unexpired tokens.
    pub fn outstanding(&self) -> usize {
        let now = now_ms();
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .filter(|t| t.expires_at_ms > now)
            .count()
    }

    /// Subscribe to successful pairings (used to show the confirmation code).
    pub fn subscribe(&self) -> broadcast::Receiver<PairingEvent> {
        self.events.subscribe()
    }
}

/// 6-digit confirmation code derived from the Noise handshake hash (both sides display it).
pub fn confirmation_code(handshake_hash: &[u8]) -> String {
    let d = Blake2s256::digest(handshake_hash);
    let n = u32::from_be_bytes([d[0], d[1], d[2], d[3]]) % 1_000_000;
    format!("{n:06}")
}

/// Build the QR payload and render it as a terminal QR string.
/// Returns `(uri, terminal_qr)` where `uri = autopilot://pair?d=<base64url(json)>`.
pub fn pairing_qr(qr: &PairingQr) -> (String, String) {
    let json = serde_json::to_vec(qr).expect("PairingQr serializes");
    let uri = format!("autopilot://pair?d={}", B64.encode(json));
    let rendered =
        match qrcode::QrCode::with_error_correction_level(uri.as_bytes(), qrcode::EcLevel::M) {
            Ok(code) => {
                use qrcode::render::unicode::Dense1x2;
                code.render::<Dense1x2>()
                    .dark_color(Dense1x2::Light)
                    .light_color(Dense1x2::Dark)
                    .quiet_zone(true)
                    .build()
            }
            Err(e) => format!("(QR code unavailable: {e})"),
        };
    (uri, rendered)
}

// ------------------------------------------------------------------------------------------------
// Sessions
// ------------------------------------------------------------------------------------------------

/// Sender half of an authenticated session. Cloning is cheap; assigns `seq` automatically.
#[derive(Clone)]
pub struct SessionSender {
    pub tx: mpsc::Sender<Message>,
}

impl SessionSender {
    /// Fails if the session is closed or the message would not fit in one Noise message
    /// (callers split large payloads, e.g. `screen.frame` parts).
    pub async fn send(&self, m: Message) -> anyhow::Result<()> {
        let len = serde_json::to_vec(&m)?.len();
        if len + ENVELOPE_OVERHEAD > MAX_PLAINTEXT {
            bail!("message too large for one Noise frame ({len} bytes); split it");
        }
        self.tx.send(m).await.map_err(|_| anyhow!("session closed"))
    }
}

/// An authenticated session with a trusted (or just-paired) phone.
pub struct Session {
    pub session_id: uuid::Uuid,
    pub peer_pk_b64: String,
    pub peer_name: String,
    pub sender: SessionSender,
    /// Decrypted, replay-checked inbound envelopes.
    pub inbound: mpsc::Receiver<Envelope>,
}

pub struct ServerConfig {
    pub listen: String,
    /// Optional relay URL to also register on, e.g. wss://relay.example/relay
    pub relay: Option<String>,
    pub laptop_name: String,
}

// ---- frame link (one WS connection or one relayed phone) ----

enum WsIn {
    Bin(Vec<u8>),
    Text,
    /// Ping/pong or other control frame: proves liveness.
    Activity,
}

enum WsOut {
    Bin(Vec<u8>),
    Close,
}

struct Link {
    rx: mpsc::Receiver<WsIn>,
    tx: mpsc::Sender<WsOut>,
}

impl Link {
    async fn send(&self, b: Vec<u8>) -> anyhow::Result<()> {
        self.tx
            .send(WsOut::Bin(b))
            .await
            .map_err(|_| anyhow!("connection closed"))
    }

    async fn recv_bin(&mut self) -> anyhow::Result<Vec<u8>> {
        loop {
            match self.rx.recv().await {
                Some(WsIn::Bin(b)) => return Ok(b),
                Some(WsIn::Activity) => continue,
                Some(WsIn::Text) => bail!("unexpected text frame"),
                None => bail!("connection closed"),
            }
        }
    }

    async fn close(&self) {
        let _ = self.tx.send(WsOut::Close).await;
    }
}

fn ws_config() -> WebSocketConfig {
    WebSocketConfig::default()
        .max_message_size(Some(MAX_NOISE_MSG))
        .max_frame_size(Some(MAX_NOISE_MSG))
}

/// Split a websocket into reader/writer tasks connected to a [`Link`].
fn spawn_pump<S>(ws: WebSocketStream<S>) -> Link
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut stream) = ws.split();
    let (in_tx, in_rx) = mpsc::channel(CHANNEL_DEPTH);
    let (out_tx, mut out_rx) = mpsc::channel::<WsOut>(CHANNEL_DEPTH);
    tokio::spawn(async move {
        loop {
            let m = tokio::select! {
                m = stream.next() => m,
                _ = in_tx.closed() => break,
            };
            let item = match m {
                Some(Ok(WsMessage::Binary(b))) => WsIn::Bin(b.into()),
                Some(Ok(WsMessage::Text(_))) => WsIn::Text,
                Some(Ok(WsMessage::Close(_))) | Some(Err(_)) | None => break,
                Some(Ok(_)) => WsIn::Activity,
            };
            if in_tx.send(item).await.is_err() {
                break;
            }
        }
    });
    tokio::spawn(async move {
        while let Some(o) = out_rx.recv().await {
            match o {
                WsOut::Bin(b) => {
                    if sink.send(WsMessage::Binary(b.into())).await.is_err() {
                        break;
                    }
                }
                WsOut::Close => break,
            }
        }
        let _ = sink.close().await;
    });
    Link {
        rx: in_rx,
        tx: out_tx,
    }
}

// ---- Noise channel ----

struct SecureChannel {
    noise: snow::TransportState,
    send_seq: u64,
    recv_guard: SeqGuard,
    session: Uuid,
}

impl SecureChannel {
    fn new(noise: snow::TransportState, session: Uuid) -> Self {
        Self {
            noise,
            send_seq: 0,
            recv_guard: SeqGuard::default(),
            session,
        }
    }

    fn seal(&mut self, msg: Message) -> anyhow::Result<Vec<u8>> {
        self.send_seq += 1;
        let env = Envelope::new(self.session, self.send_seq, msg);
        self.seal_envelope(&env)
    }

    fn seal_envelope(&mut self, env: &Envelope) -> anyhow::Result<Vec<u8>> {
        let pt = env.to_json();
        if pt.len() > MAX_PLAINTEXT {
            bail!(
                "plaintext of {} bytes exceeds {MAX_PLAINTEXT}; split it",
                pt.len()
            );
        }
        let mut out = vec![0u8; pt.len() + 16];
        let n = self.noise.write_message(&pt, &mut out)?;
        out.truncate(n);
        Ok(out)
    }

    fn open(&mut self, ct: &[u8]) -> anyhow::Result<Envelope> {
        if ct.len() > MAX_NOISE_MSG || ct.len() < 16 {
            bail!("bad transport message size");
        }
        let mut pt = vec![0u8; ct.len()];
        let n = self
            .noise
            .read_message(ct, &mut pt)
            .map_err(|_| anyhow!("decryption failed"))?;
        let env = Envelope::from_json(&pt[..n]);
        pt.zeroize();
        let env = env?;
        self.recv_guard.check(env.seq)?;
        Ok(env)
    }
}

async fn responder_handshake(
    mut hs: snow::HandshakeState,
    link: &mut Link,
) -> anyhow::Result<(snow::TransportState, [u8; 32], Vec<u8>)> {
    let mut buf = vec![0u8; MAX_NOISE_MSG];
    let m1 = link.recv_bin().await?;
    if hs.read_message(&m1, &mut buf)? != 0 {
        bail!("unexpected handshake payload");
    }
    let n = hs.write_message(&[], &mut buf)?;
    link.send(buf[..n].to_vec()).await?;
    let m3 = link.recv_bin().await?;
    if hs.read_message(&m3, &mut buf)? != 0 {
        bail!("unexpected handshake payload");
    }
    let remote: [u8; 32] = hs
        .get_remote_static()
        .ok_or_else(|| anyhow!("no remote static key"))?
        .try_into()
        .map_err(|_| anyhow!("bad remote static key"))?;
    let hash = hs.get_handshake_hash().to_vec();
    Ok((hs.into_transport_mode()?, remote, hash))
}

async fn initiator_handshake(
    mut hs: snow::HandshakeState,
    link: &mut Link,
    pinned: &[u8; 32],
) -> anyhow::Result<(snow::TransportState, Vec<u8>)> {
    let mut buf = vec![0u8; MAX_NOISE_MSG];
    let n = hs.write_message(&[], &mut buf)?;
    link.send(buf[..n].to_vec()).await?;
    let m2 = link.recv_bin().await?;
    if hs.read_message(&m2, &mut buf)? != 0 {
        bail!("unexpected handshake payload");
    }
    let remote = hs
        .get_remote_static()
        .ok_or_else(|| anyhow!("no remote static key"))?;
    if !bool::from(remote.ct_eq(pinned.as_slice())) {
        bail!("laptop static key does not match the pinned key");
    }
    let n = hs.write_message(&[], &mut buf)?;
    link.send(buf[..n].to_vec()).await?;
    let hash = hs.get_handshake_hash().to_vec();
    Ok((hs.into_transport_mode()?, hash))
}

struct Ctx {
    keys: Arc<DeviceKeys>,
    trust: Arc<tokio::sync::Mutex<TrustStore>>,
    pairing: Arc<PairingManager>,
    sessions: mpsc::Sender<Session>,
    laptop_name: String,
}

fn sanitize_name(name: &str) -> String {
    let s: String = name.chars().filter(|c| !c.is_control()).take(64).collect();
    let s = s.trim();
    if s.is_empty() {
        "phone".to_string()
    } else {
        s.to_string()
    }
}

/// Laptop side of one connection: handshake, trust/pairing check, then the session loop.
async fn responder(ctx: Arc<Ctx>, mut link: Link, origin: String) -> anyhow::Result<()> {
    let hs = noise_builder()?
        .local_private_key(&ctx.keys.private)?
        .build_responder()?;
    let (noise, remote, hash) =
        match timeout(HANDSHAKE_TIMEOUT, responder_handshake(hs, &mut link)).await {
            Ok(r) => r?,
            Err(_) => bail!("handshake timeout"),
        };
    let peer_pk_b64 = B64.encode(remote);
    let session_id = Uuid::new_v4();
    let mut ch = SecureChannel::new(noise, session_id);
    let revocations = ctx.trust.lock().await.subscribe_revocations();
    let known = ctx.trust.lock().await.get(&peer_pk_b64);

    let peer_name = match known {
        Some(d) => d.name,
        None => {
            let ct = match timeout(PAIR_CLAIM_TIMEOUT, link.recv_bin()).await {
                Ok(r) => r?,
                Err(_) => bail!("unknown device sent no pair.claim"),
            };
            let env = ch.open(&ct)?;
            let Message::PairClaim(PairClaim { token, device_name }) = env.msg else {
                link.close().await;
                bail!("unknown device: first message was not pair.claim");
            };
            if !ctx.pairing.consume(&token) {
                let reject = Message::PairResult(PairResult {
                    ok: false,
                    laptop_name: ctx.laptop_name.clone(),
                    reason: Some("invalid or expired pairing token".into()),
                });
                if let Ok(ct) = ch.seal(reject) {
                    let _ = link.send(ct).await;
                }
                link.close().await;
                bail!("pairing rejected: invalid or expired token");
            }
            let name = sanitize_name(&device_name);
            ctx.trust.lock().await.add(PairedDevice {
                name: name.clone(),
                pk_b64: peer_pk_b64.clone(),
                paired_at_ms: now_ms(),
            })?;
            let code = confirmation_code(&hash);
            eprintln!("AutoPilot: paired new device \"{name}\" (confirmation code {code})");
            info!(device = %name, %code, via = %origin, "paired new device");
            let _ = ctx.pairing.events.send(PairingEvent {
                device_name: name.clone(),
                pk_b64: peer_pk_b64.clone(),
                code,
            });
            let ok = Message::PairResult(PairResult {
                ok: true,
                laptop_name: ctx.laptop_name.clone(),
                reason: None,
            });
            link.send(ch.seal(ok)?).await?;
            name
        }
    };

    let (out_tx, out_rx) = mpsc::channel(CHANNEL_DEPTH);
    let (in_tx, in_rx) = mpsc::channel(CHANNEL_DEPTH);
    let session = Session {
        session_id,
        peer_pk_b64: peer_pk_b64.clone(),
        peer_name: peer_name.clone(),
        sender: SessionSender { tx: out_tx },
        inbound: in_rx,
    };
    info!(device = %peer_name, via = %origin, %session_id, "session established");
    ctx.sessions
        .send(session)
        .await
        .map_err(|_| anyhow!("session consumer gone"))?;
    let res = run_session(
        ch,
        link,
        out_rx,
        in_tx,
        LoopRole::Responder {
            trust: ctx.trust.clone(),
            peer_pk_b64,
            revocations,
        },
    )
    .await;
    info!(device = %peer_name, %session_id, "session closed");
    res
}

enum LoopRole {
    Responder {
        trust: Arc<tokio::sync::Mutex<TrustStore>>,
        peer_pk_b64: String,
        revocations: broadcast::Receiver<String>,
    },
    Initiator,
}

async fn next_revocation(role: &mut LoopRole) {
    match role {
        LoopRole::Responder {
            revocations,
            peer_pk_b64,
            trust,
        } => loop {
            match revocations.recv().await {
                Ok(pk) if pk == *peer_pk_b64 => return,
                Ok(_) => {}
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    if !trust.lock().await.is_trusted(peer_pk_b64) {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Closed) => std::future::pending::<()>().await,
            }
        },
        LoopRole::Initiator => std::future::pending().await,
    }
}

/// Encrypted message pump for an established session (both roles).
async fn run_session(
    mut ch: SecureChannel,
    mut link: Link,
    mut out_rx: mpsc::Receiver<Message>,
    in_tx: mpsc::Sender<Envelope>,
    mut role: LoopRole,
) -> anyhow::Result<()> {
    let is_initiator = matches!(role, LoopRole::Initiator);
    let idle = tokio::time::sleep(IDLE_TIMEOUT);
    tokio::pin!(idle);
    let mut ping = tokio::time::interval_at(
        tokio::time::Instant::now() + CLIENT_PING_INTERVAL,
        CLIENT_PING_INTERVAL,
    );
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let res: anyhow::Result<()> = async {
        loop {
            tokio::select! {
                _ = next_revocation(&mut role) => bail!("device revoked"),
                _ = &mut idle => bail!("idle timeout"),
                _ = ping.tick(), if is_initiator => {
                    link.send(ch.seal(Message::Ping(Ping { t_ms: now_ms() }))?).await?;
                }
                item = link.rx.recv() => {
                    let ct = match item {
                        None => return Ok(()),
                        Some(WsIn::Activity) => {
                            idle.as_mut().reset(tokio::time::Instant::now() + IDLE_TIMEOUT);
                            continue;
                        }
                        Some(WsIn::Text) => bail!("unexpected text frame"),
                        Some(WsIn::Bin(b)) => b,
                    };
                    idle.as_mut().reset(tokio::time::Instant::now() + IDLE_TIMEOUT);
                    let env = ch.open(&ct)?;
                    match &role {
                        LoopRole::Responder { trust, peer_pk_b64, .. } => {
                            if !trust.lock().await.is_trusted(peer_pk_b64) {
                                bail!("device no longer trusted");
                            }
                            if !env.session.is_nil() && env.session != ch.session {
                                bail!("session id mismatch");
                            }
                            if let Message::Ping(p) = &env.msg {
                                link.send(ch.seal(Message::Pong(p.clone()))?).await?;
                                continue;
                            }
                        }
                        LoopRole::Initiator => {
                            if ch.session.is_nil() {
                                ch.session = env.session;
                            } else if env.session != ch.session {
                                bail!("session id mismatch");
                            }
                        }
                    }
                    if in_tx.send(env).await.is_err() {
                        return Ok(());
                    }
                }
                m = out_rx.recv() => {
                    let Some(m) = m else { return Ok(()) };
                    match ch.seal(m) {
                        Ok(ct) => link.send(ct).await?,
                        Err(e) => warn!("dropping outbound message: {e}"),
                    }
                }
            }
        }
    }
    .await;
    link.close().await;
    if let Err(e) = &res {
        debug!("session ended: {e}");
    }
    res
}

// ---- server ----

struct RateLimiter {
    per_minute: u32,
    hits: HashMap<IpAddr, (Instant, u32)>,
}

impl RateLimiter {
    fn new(per_minute: u32) -> Self {
        Self {
            per_minute,
            hits: HashMap::new(),
        }
    }

    fn allow(&mut self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(60);
        if self.hits.len() > 4096 {
            self.hits
                .retain(|_, (start, _)| now.duration_since(*start) < window);
        }
        let e = self.hits.entry(ip).or_insert((now, 0));
        if now.duration_since(e.0) >= window {
            *e = (now, 0);
        }
        e.1 += 1;
        e.1 <= self.per_minute
    }
}

#[allow(clippy::result_large_err)]
fn check_path(req: &Request, resp: Response) -> Result<Response, ErrorResponse> {
    if req.uri().path() == "/ws" {
        Ok(resp)
    } else {
        let mut r = ErrorResponse::new(Some("not found".into()));
        *r.status_mut() = tokio_tungstenite::tungstenite::http::StatusCode::NOT_FOUND;
        Err(r)
    }
}

/// Accept phones forever. Unknown static keys must send a valid `pair.claim` as their first
/// message, otherwise the connection is dropped. New sessions are delivered on `sessions`.
pub async fn serve(
    cfg: ServerConfig,
    keys: std::sync::Arc<DeviceKeys>,
    trust: std::sync::Arc<tokio::sync::Mutex<TrustStore>>,
    pairing: std::sync::Arc<PairingManager>,
    sessions: mpsc::Sender<Session>,
) -> anyhow::Result<()> {
    let listener = TcpListener::bind(&cfg.listen)
        .await
        .with_context(|| format!("binding {}", cfg.listen))?;
    serve_listener(
        listener,
        cfg.relay,
        cfg.laptop_name,
        keys,
        trust,
        pairing,
        sessions,
    )
    .await
}

/// Like [`serve`] but on an already bound listener (lets callers/tests use port 0).
pub async fn serve_listener(
    listener: TcpListener,
    relay: Option<String>,
    laptop_name: String,
    keys: Arc<DeviceKeys>,
    trust: Arc<tokio::sync::Mutex<TrustStore>>,
    pairing: Arc<PairingManager>,
    sessions: mpsc::Sender<Session>,
) -> anyhow::Result<()> {
    info!(addr = %listener.local_addr()?, "listening on ws://<addr>/ws");
    let ctx = Arc::new(Ctx {
        keys,
        trust,
        pairing,
        sessions,
        laptop_name,
    });
    if let Some(relay) = relay {
        let ctx = ctx.clone();
        tokio::spawn(relay_loop(relay, ctx));
    }
    let limiter = Arc::new(std::sync::Mutex::new(RateLimiter::new(
        HANDSHAKES_PER_MINUTE,
    )));
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!("accept failed: {e}");
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
        };
        if !limiter
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .allow(addr.ip())
        {
            debug!(peer = %addr, "handshake rate limit exceeded");
            continue;
        }
        let Ok(permit) = slots.clone().try_acquire_owned() else {
            debug!(peer = %addr, "too many connections");
            continue;
        };
        let _ = stream.set_nodelay(true);
        let ctx = ctx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let ws = match timeout(
                HANDSHAKE_TIMEOUT,
                tokio_tungstenite::accept_hdr_async_with_config(
                    stream,
                    check_path,
                    Some(ws_config()),
                ),
            )
            .await
            {
                Ok(Ok(ws)) => ws,
                Ok(Err(e)) => return debug!(peer = %addr, "websocket upgrade failed: {e}"),
                Err(_) => return debug!(peer = %addr, "websocket upgrade timeout"),
            };
            if let Err(e) = responder(ctx, spawn_pump(ws), addr.to_string()).await {
                info!(peer = %addr, "connection closed: {e}");
            }
        });
    }
}

// ---- relay ----

async fn relay_loop(relay: String, ctx: Arc<Ctx>) {
    let url = format!(
        "{}/{}?role=laptop",
        relay.trim_end_matches('/'),
        relay_room(&ctx.keys.public)
    );
    let mut backoff = Duration::from_secs(1);
    loop {
        let started = Instant::now();
        let mut replaced = false;
        match tokio_tungstenite::connect_async_with_config(url.as_str(), Some(ws_config()), true)
            .await
        {
            Ok((ws, _)) => {
                info!("connected to relay");
                if relay_conn(ws, ctx.clone()).await {
                    // 4000: another laptop instance took over this room; avoid flapping.
                    warn!("relay room taken over by another connection (4000); backing off");
                    replaced = true;
                } else {
                    info!("relay connection lost");
                }
            }
            Err(e) => warn!("relay connect failed: {e}"),
        }
        if replaced {
            backoff = RELAY_MAX_BACKOFF;
        } else if started.elapsed() > Duration::from_secs(30) {
            backoff = Duration::from_secs(1);
        }
        let jitter = Duration::from_millis(u64::from(rand_u16() % 500));
        tokio::time::sleep(backoff + jitter).await;
        backoff = (backoff * 2).min(RELAY_MAX_BACKOFF);
    }
}

fn rand_u16() -> u16 {
    let mut b = [0u8; 2];
    let _ = getrandom::fill(&mut b);
    u16::from_le_bytes(b)
}

/// Returns true when the relay closed us with 4000 (replaced by a newer laptop connection).
async fn relay_conn<S>(ws: WebSocketStream<S>, ctx: Arc<Ctx>) -> bool
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sink, mut stream) = ws.split();
    let (out_tx, mut out_rx) = mpsc::channel::<Vec<u8>>(CHANNEL_DEPTH);
    let (stop_tx, mut stop_rx) = tokio::sync::oneshot::channel::<()>();
    let writer = tokio::spawn(async move {
        let mut ping = tokio::time::interval(RELAY_PING_INTERVAL);
        ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let r = tokio::select! {
                _ = &mut stop_rx => break,
                _ = ping.tick() => sink.send(WsMessage::Ping(Vec::new().into())).await,
                b = out_rx.recv() => match b {
                    Some(b) => sink.send(WsMessage::Binary(b.into())).await,
                    None => break,
                },
            };
            if r.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    let generation = Arc::new(AtomicU64::new(0));
    let mut limiter = RateLimiter::new(HANDSHAKES_PER_MINUTE);
    let relay_ip = IpAddr::from([0, 0, 0, 0]);
    let mut current: Option<mpsc::Sender<WsIn>> = None;
    let mut replaced = false;
    loop {
        let m = match timeout(RELAY_DEAD_AFTER, stream.next()).await {
            Err(_) => break,
            Ok(None) | Ok(Some(Err(_))) => break,
            Ok(Some(Ok(m))) => m,
        };
        match m {
            WsMessage::Text(t) if t.as_str() == "peer-connected" => {
                current = None;
                let my_gen = generation.fetch_add(1, Ordering::SeqCst) + 1;
                if !limiter.allow(relay_ip) {
                    debug!("relay handshake rate limit exceeded");
                    continue;
                }
                let (in_tx, in_rx) = mpsc::channel(CHANNEL_DEPTH);
                let (sess_tx, mut sess_rx) = mpsc::channel::<WsOut>(CHANNEL_DEPTH);
                let (gen_ref, out) = (generation.clone(), out_tx.clone());
                tokio::spawn(async move {
                    while let Some(WsOut::Bin(b)) = sess_rx.recv().await {
                        if gen_ref.load(Ordering::SeqCst) != my_gen || out.send(b).await.is_err() {
                            break;
                        }
                    }
                });
                current = Some(in_tx);
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = responder(
                        ctx,
                        Link {
                            rx: in_rx,
                            tx: sess_tx,
                        },
                        "relay".into(),
                    )
                    .await
                    {
                        info!(via = "relay", "connection closed: {e}");
                    }
                });
            }
            WsMessage::Text(_) => {}
            WsMessage::Binary(b) => {
                if let Some(tx) = &current {
                    if tx.send(WsIn::Bin(b.into())).await.is_err() {
                        current = None;
                    }
                }
            }
            WsMessage::Close(frame) => {
                replaced = frame.is_some_and(|f| u16::from(f.code) == RELAY_CLOSE_REPLACED);
                break;
            }
            _ => {}
        }
    }
    generation.fetch_add(1, Ordering::SeqCst);
    drop(current);
    let _ = stop_tx.send(());
    drop(out_tx);
    let _ = writer.await;
    replaced
}

// ---- client ----

/// Client side (used by the CLI test client and integration tests; the phone implements the same in TS).
/// If `pair_token` is Some, sends `pair.claim` first.
pub async fn connect(
    url: &str,
    keys: &DeviceKeys,
    laptop_pk_b64: &str,
    device_name: &str,
    pair_token: Option<String>,
) -> anyhow::Result<Session> {
    Ok(
        connect_with_code(url, keys, laptop_pk_b64, device_name, pair_token)
            .await?
            .0,
    )
}

/// Like [`connect`], also returning the 6-digit confirmation code of this handshake.
pub async fn connect_with_code(
    url: &str,
    keys: &DeviceKeys,
    laptop_pk_b64: &str,
    device_name: &str,
    pair_token: Option<String>,
) -> anyhow::Result<(Session, String)> {
    let pinned = decode_pk(laptop_pk_b64)?;
    let (ws, _) = timeout(
        HANDSHAKE_TIMEOUT,
        tokio_tungstenite::connect_async_with_config(url, Some(ws_config()), true),
    )
    .await
    .map_err(|_| anyhow!("connect timeout"))?
    .with_context(|| format!("connecting to {url}"))?;
    let mut link = spawn_pump(ws);
    let hs = noise_builder()?
        .local_private_key(&keys.private)?
        .build_initiator()?;
    let (noise, hash) = timeout(
        HANDSHAKE_TIMEOUT,
        initiator_handshake(hs, &mut link, &pinned),
    )
    .await
    .map_err(|_| anyhow!("handshake timeout"))??;
    let code = confirmation_code(&hash);
    let mut ch = SecureChannel::new(noise, Uuid::nil());
    let mut peer_name = String::from("laptop");
    if let Some(token) = pair_token {
        link.send(ch.seal(Message::PairClaim(PairClaim {
            token,
            device_name: device_name.to_string(),
        }))?)
        .await?;
        let ct = timeout(PAIR_CLAIM_TIMEOUT, link.recv_bin())
            .await
            .map_err(|_| anyhow!("no pair.result"))??;
        let env = ch.open(&ct)?;
        match env.msg {
            Message::PairResult(PairResult {
                ok: true,
                laptop_name,
                ..
            }) => {
                ch.session = env.session;
                peer_name = laptop_name;
            }
            Message::PairResult(PairResult { reason, .. }) => {
                bail!("pairing rejected: {}", reason.unwrap_or_default())
            }
            _ => bail!("unexpected reply to pair.claim"),
        }
    }
    let (out_tx, out_rx) = mpsc::channel(CHANNEL_DEPTH);
    let (in_tx, in_rx) = mpsc::channel(CHANNEL_DEPTH);
    let session = Session {
        session_id: ch.session,
        peer_pk_b64: laptop_pk_b64.to_string(),
        peer_name,
        sender: SessionSender { tx: out_tx },
        inbound: in_rx,
    };
    tokio::spawn(async move {
        let _ = run_session(ch, link, out_rx, in_tx, LoopRole::Initiator).await;
    });
    Ok((session, code))
}
