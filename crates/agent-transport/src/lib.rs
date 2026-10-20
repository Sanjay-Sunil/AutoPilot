//! Secure session transport: Noise_XX_25519_ChaChaPoly_BLAKE2s over WebSocket (direct LAN/Tailscale
//! or through the backend relay). See docs/protocol.md for the exact wire format.
//! CONTRACT: keep these public signatures; implement bodies.
use agent_protocol::{Envelope, Message, PairingQr};
use std::path::Path;
use tokio::sync::mpsc;

/// Laptop/phone static Noise keypair (X25519). Stored 0600 at `path` (keyring later).
pub struct DeviceKeys { pub private: [u8; 32], pub public: [u8; 32] }
impl DeviceKeys {
    pub fn load_or_create(_path: &Path) -> anyhow::Result<Self> { todo!() }
    pub fn generate() -> Self { todo!() }
    /// base64url, no padding.
    pub fn public_b64(&self) -> String { todo!() }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PairedDevice { pub name: String, pub pk_b64: String, pub paired_at_ms: u64 }

/// Trusted phones, persisted as JSON.
pub struct TrustStore {}
impl TrustStore {
    pub fn load(_path: &Path) -> anyhow::Result<Self> { todo!() }
    pub fn is_trusted(&self, _pk_b64: &str) -> bool { todo!() }
    pub fn add(&mut self, _d: PairedDevice) -> anyhow::Result<()> { todo!() }
    pub fn revoke(&mut self, _pk_b64: &str) -> anyhow::Result<bool> { todo!() }
    pub fn list(&self) -> Vec<PairedDevice> { todo!() }
}

/// One-time pairing tokens (random 16 bytes, base64url, short TTL, single use, constant-time compare).
pub struct PairingManager {}
impl PairingManager {
    pub fn new() -> Self { todo!() }
    pub fn issue(&self, _ttl_ms: u64) -> (String, u64) { todo!() }
    pub fn consume(&self, _token: &str) -> bool { todo!() }
}

/// 6-digit confirmation code derived from the Noise handshake hash (both sides display it).
pub fn confirmation_code(_handshake_hash: &[u8]) -> String { todo!() }

/// Build the QR payload and render it as a terminal QR string.
pub fn pairing_qr(_qr: &PairingQr) -> (String, String) { todo!() }

/// Sender half of an authenticated session. Cloning is cheap; assigns `seq` automatically.
#[derive(Clone)]
pub struct SessionSender { pub tx: mpsc::Sender<Message> }
impl SessionSender {
    pub async fn send(&self, m: Message) -> anyhow::Result<()> { self.tx.send(m).await.map_err(|_| anyhow::anyhow!("session closed")) }
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

/// Accept phones forever. Unknown static keys must send a valid `pair.claim` as their first
/// message, otherwise the connection is dropped. New sessions are delivered on `sessions`.
pub async fn serve(
    _cfg: ServerConfig,
    _keys: std::sync::Arc<DeviceKeys>,
    _trust: std::sync::Arc<tokio::sync::Mutex<TrustStore>>,
    _pairing: std::sync::Arc<PairingManager>,
    _sessions: mpsc::Sender<Session>,
) -> anyhow::Result<()> { todo!() }

/// Client side (used by the CLI test client and integration tests; the phone implements the same in TS).
/// If `pair_token` is Some, sends `pair.claim` first.
pub async fn connect(
    _url: &str,
    _keys: &DeviceKeys,
    _laptop_pk_b64: &str,
    _device_name: &str,
    _pair_token: Option<String>,
) -> anyhow::Result<Session> { todo!() }
