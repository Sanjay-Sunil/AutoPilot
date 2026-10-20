//! AutoPilot daemon internals: session dispatch, local control socket, pairing helpers, config.
//! The binary (`main.rs`) wires these to `agent_core::Agent` and the CLI.
use agent_protocol::{Message, PairingQr};
use agent_transport::{
    DeviceKeys, PAIRING_TTL_MS, PairingManager, Session, TrustStore, pairing_qr,
};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, info, warn};

pub mod control;

/// Boxed async message handler: `(actor, message, outbound) -> ()`.
pub type Handler = Arc<
    dyn Fn(String, Message, mpsc::Sender<Message>) -> Pin<Box<dyn Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// Handler backed by the real agent.
pub fn agent_handler(agent: agent_core::Agent) -> Handler {
    Arc::new(move |actor, msg, out| {
        let agent = agent.clone();
        Box::pin(async move { agent.handle(&actor, msg, out).await })
    })
}

/// Daemon settings that live next to the agent settings in the same TOML file.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(default)]
pub struct DaemonSettings {
    pub listen: Option<String>,
    pub relay: Option<String>,
    pub laptop_name: Option<String>,
}

impl DaemonSettings {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => Ok(toml::from_str(&s)?),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(anyhow::anyhow!("reading {}: {e}", path.display())),
        }
    }
}

pub const DEFAULT_LISTEN: &str = "0.0.0.0:7878";

pub fn default_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("autopilot")
        .join("config.toml")
}

pub fn hostname() -> String {
    gethostname::gethostname().to_string_lossy().into_owned()
}

/// Shared state the control socket operates on.
pub struct DaemonState {
    pub keys: Arc<DeviceKeys>,
    pub trust: Arc<Mutex<TrustStore>>,
    pub pairing: Arc<PairingManager>,
    pub laptop_name: String,
    pub listen: String,
    pub relay: Option<String>,
    pub kill: Arc<dyn Fn(&str) + Send + Sync>,
    pub active_sessions: Arc<AtomicUsize>,
    pub started: Instant,
}

/// A freshly issued pairing token packaged for display.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PairingInfo {
    pub uri: String,
    pub qr: PairingQr,
    pub expires_at_ms: u64,
}

impl DaemonState {
    pub fn issue_pairing(&self) -> PairingInfo {
        let (token, expires_at_ms) = self.pairing.issue(PAIRING_TTL_MS);
        let qr = PairingQr {
            v: 1,
            addrs: lan_addrs(&self.listen),
            relay: self.relay.clone(),
            laptop_pk: self.keys.public_b64(),
            laptop_name: self.laptop_name.clone(),
            token,
            expires_at_ms,
        };
        let (uri, _) = pairing_qr(&qr);
        PairingInfo {
            uri,
            qr,
            expires_at_ms,
        }
    }
}

/// Addresses (`ip:port`) a phone can try for `listen`. Wildcard binds expand to all non-loopback
/// interface addresses (LAN, Tailscale).
pub fn lan_addrs(listen: &str) -> Vec<String> {
    let Ok(sa) = listen.parse::<std::net::SocketAddr>() else {
        return vec![listen.to_string()];
    };
    if !sa.ip().is_unspecified() {
        return vec![sa.to_string()];
    }
    let mut out: Vec<String> = local_ip_address::list_afinet_netifas()
        .map(|v| {
            v.into_iter()
                .map(|(_, ip)| ip)
                .filter(|ip| !ip.is_loopback() && (ip.is_ipv4() || sa.ip().is_ipv6()))
                .filter(|ip| match ip {
                    std::net::IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
                    _ => true,
                })
                .map(|ip| std::net::SocketAddr::new(ip, sa.port()).to_string())
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out.dedup();
    out
}

/// Print a pairing QR + URI + addresses to stdout.
pub fn print_pairing(info: &PairingInfo) {
    let (_, qr) = pairing_qr(&info.qr);
    println!("{qr}");
    println!(
        "Scan with the AutoPilot app, or paste this link:\n  {}",
        info.uri
    );
    println!(
        "Laptop: {}  key: {}",
        info.qr.laptop_name, info.qr.laptop_pk
    );
    for a in &info.qr.addrs {
        println!("  ws://{a}/ws");
    }
    if let Some(r) = &info.qr.relay {
        println!("  relay: {r}");
    }
    let secs = info.expires_at_ms.saturating_sub(now_ms()) / 1000;
    println!("Single-use token, expires in {secs} s. Compare the 6-digit code on both screens.");
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Run every incoming session on its own task: inbound envelopes go to `handler`, whose outbound
/// messages are forwarded to the session.
pub async fn dispatch_sessions(
    mut sessions: mpsc::Receiver<Session>,
    handler: Handler,
    active: Arc<AtomicUsize>,
) {
    while let Some(s) = sessions.recv().await {
        let handler = handler.clone();
        let active = active.clone();
        tokio::spawn(async move {
            active.fetch_add(1, Ordering::Relaxed);
            run_session(s, handler).await;
            active.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn run_session(mut s: Session, handler: Handler) {
    let actor = format!("phone:{}", s.peer_name);
    let (out_tx, mut out_rx) = mpsc::channel::<Message>(64);
    let sender = s.sender.clone();
    let fwd = tokio::spawn(async move {
        while let Some(m) = out_rx.recv().await {
            if let Err(e) = sender.send(m).await {
                if sender.tx.is_closed() {
                    break;
                }
                warn!("outbound message dropped: {e}");
            }
        }
    });
    while let Some(env) = s.inbound.recv().await {
        debug!(actor = %actor, seq = env.seq, "inbound message");
        handler(actor.clone(), env.msg, out_tx.clone()).await;
    }
    drop(out_tx);
    // Outstanding agent tasks may still hold senders; stop forwarding once the session is gone.
    fwd.abort();
    info!(actor = %actor, "session handler finished");
}
