//! Blind relay: `WS /relay/{room}?role=laptop|phone`.
//!
//! Semantics (see docs/protocol.md and docs/architecture.md):
//! - `room` is exactly 32 hex chars (`hex(BLAKE2s-256(laptop_static_pk))[0..32]`), case-insensitive.
//! - At most one laptop and one phone per room. A newer connection of the same role replaces the
//!   older one, which is closed with code 4000.
//! - A phone may only join while the laptop is connected; otherwise it is closed with 4404 and should
//!   retry with backoff. When the laptop leaves (or is replaced) the phone is closed with 4410.
//! - When a phone joins, the laptop receives the text frame `peer-connected` (always before any of
//!   that phone's binary frames), then binary frames are piped 1:1 in both directions.
//! - Frames larger than `max_frame` close the sender with 1009. Text frames from clients close with
//!   1003. No frame for `idle_timeout` closes with 4408.
//! - Frame contents are never parsed, stored, or logged.

use crate::{AppState, Config, ratelimit::RateLimiter};
use axum::{
    body::Bytes,
    extract::{
        ConnectInfo, Path, Query, State,
        ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade},
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures_util::{SinkExt, StreamExt};
use serde::Deserialize;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

pub const PEER_CONNECTED: &str = "peer-connected";

pub mod close {
    pub const UNSUPPORTED: u16 = 1003;
    pub const TOO_BIG: u16 = 1009;
    pub const TRY_AGAIN: u16 = 1013;
    pub const REPLACED: u16 = 4000;
    pub const IDLE: u16 = 4408;
    pub const LAPTOP_OFFLINE: u16 = 4404;
    pub const LAPTOP_GONE: u16 = 4410;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Laptop,
    Phone,
}

#[derive(Debug, Deserialize)]
pub struct RoleQuery {
    role: Option<String>,
}

enum Out {
    Bin(Bytes),
    Text(&'static str),
    Close(u16, &'static str),
}

struct Peer {
    id: u64,
    tx: mpsc::Sender<Out>,
    /// Tells the connection task to close with the given code (dropping it also closes).
    kick: Option<oneshot::Sender<u16>>,
}

impl Peer {
    /// Ask the connection to close with `code`, then drop the handle.
    fn kick(mut self, code: u16) {
        if let Some(k) = self.kick.take() {
            let _ = k.send(code);
        }
    }
}

#[derive(Default)]
struct Room {
    laptop: Option<Peer>,
    phone: Option<Peer>,
}

pub struct RelayState {
    rooms: Mutex<HashMap<String, Room>>,
    next_id: AtomicU64,
    limiter: RateLimiter,
    idle_timeout: Duration,
    max_frame: usize,
    max_rooms: usize,
    trust_forwarded: bool,
}

impl RelayState {
    pub fn new(cfg: &Config) -> Self {
        Self {
            rooms: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            limiter: RateLimiter::new(cfg.rate_per_min, cfg.rate_burst),
            idle_timeout: cfg.idle_timeout,
            max_frame: cfg.max_frame,
            max_rooms: cfg.max_rooms,
            trust_forwarded: cfg.trust_forwarded,
        }
    }

    pub fn room_count(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Room>> {
        self.rooms.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn peer_tx(&self, room: &str, role: Role) -> Option<mpsc::Sender<Out>> {
        let rooms = self.lock();
        let r = rooms.get(room)?;
        match role {
            Role::Laptop => r.laptop.as_ref().map(|p| p.tx.clone()),
            Role::Phone => r.phone.as_ref().map(|p| p.tx.clone()),
        }
    }

    /// Register a connection. Returns Err(close code) if it must be refused.
    fn register(
        &self,
        room: &str,
        role: Role,
        id: u64,
        tx: mpsc::Sender<Out>,
        kick: oneshot::Sender<u16>,
    ) -> Result<(), u16> {
        let mut rooms = self.lock();
        if !rooms.contains_key(room) {
            if role == Role::Phone {
                return Err(close::LAPTOP_OFFLINE);
            }
            if rooms.len() >= self.max_rooms {
                return Err(close::TRY_AGAIN);
            }
        }
        let r = rooms.entry(room.to_owned()).or_default();
        let peer = Peer {
            id,
            tx,
            kick: Some(kick),
        };
        match role {
            Role::Laptop => {
                if let Some(old) = r.laptop.replace(peer) {
                    old.kick(close::REPLACED);
                }
                // Any phone was talking to the previous laptop; its Noise session is dead.
                if let Some(ph) = r.phone.take() {
                    ph.kick(close::LAPTOP_GONE);
                }
            }
            Role::Phone => {
                let Some(laptop) = r.laptop.as_ref() else {
                    return Err(close::LAPTOP_OFFLINE);
                };
                // Enqueued under the lock, so it is ordered before any frame from this phone.
                let _ = laptop.tx.try_send(Out::Text(PEER_CONNECTED));
                if let Some(old) = r.phone.replace(peer) {
                    old.kick(close::REPLACED);
                }
            }
        }
        Ok(())
    }

    fn unregister(&self, room: &str, role: Role, id: u64) {
        let mut rooms = self.lock();
        let Some(r) = rooms.get_mut(room) else { return };
        match role {
            Role::Laptop => {
                if r.laptop.as_ref().is_some_and(|p| p.id == id) {
                    r.laptop = None;
                    if let Some(ph) = r.phone.take() {
                        ph.kick(close::LAPTOP_GONE);
                    }
                }
            }
            Role::Phone => {
                if r.phone.as_ref().is_some_and(|p| p.id == id) {
                    r.phone = None;
                }
            }
        }
        if r.laptop.is_none() && r.phone.is_none() {
            rooms.remove(room);
        }
    }
}

pub fn valid_room(room: &str) -> bool {
    room.len() == 32 && room.bytes().all(|b| b.is_ascii_hexdigit())
}

fn client_ip(peer: SocketAddr, headers: &HeaderMap, trust_forwarded: bool) -> IpAddr {
    if trust_forwarded
        && let Some(ip) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.rsplit(',').next())
            .and_then(|v| v.trim().parse::<IpAddr>().ok())
    {
        return ip;
    }
    peer.ip()
}

pub async fn ws_handler(
    ws: WebSocketUpgrade,
    Path(room): Path<String>,
    Query(q): Query<RoleQuery>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    State(st): State<AppState>,
) -> Response {
    let relay = st.relay.clone();
    if !valid_room(&room) {
        return (StatusCode::BAD_REQUEST, "invalid room").into_response();
    }
    let role = match q.role.as_deref() {
        Some("laptop") => Role::Laptop,
        Some("phone") => Role::Phone,
        _ => return (StatusCode::BAD_REQUEST, "role must be laptop or phone").into_response(),
    };
    let ip = client_ip(addr, &headers, relay.trust_forwarded);
    if !relay.limiter.check(ip) {
        tracing::debug!(%ip, "relay rate limited");
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    let room = room.to_ascii_lowercase();
    // Let tungstenite accept slightly more than our limit so that we can send a proper 1009 close
    // for frames just over it; anything much bigger is cut off by tungstenite itself.
    let hard = relay.max_frame + 1024;
    ws.max_message_size(hard)
        .max_frame_size(hard)
        .on_upgrade(move |socket| run(socket, relay, room, role))
}

async fn run(socket: WebSocket, st: std::sync::Arc<RelayState>, room: String, role: Role) {
    let (mut sink, mut stream) = socket.split();
    let (tx, mut rx) = mpsc::channel::<Out>(64);
    let (kick_tx, mut kick_rx) = oneshot::channel::<u16>();
    let id = st.next_id.fetch_add(1, Ordering::Relaxed);
    let room_tag = &room[..8];

    let writer = tokio::spawn(async move {
        while let Some(o) = rx.recv().await {
            let res = match o {
                Out::Bin(b) => sink.send(Message::Binary(b)).await,
                Out::Text(t) => sink.send(Message::Text(t.into())).await,
                Out::Close(code, reason) => {
                    let _ = sink
                        .send(Message::Close(Some(CloseFrame {
                            code,
                            reason: reason.into(),
                        })))
                        .await;
                    break;
                }
            };
            if res.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });

    let refuse = st.register(&room, role, id, tx.clone(), kick_tx).err();
    if let Some(code) = refuse {
        let reason = match code {
            close::LAPTOP_OFFLINE => "laptop offline",
            _ => "try again later",
        };
        let _ = tx.send(Out::Close(code, reason)).await;
        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), writer).await;
        return;
    }
    tracing::debug!(room = room_tag, ?role, id, "relay join");

    let other = match role {
        Role::Laptop => Role::Phone,
        Role::Phone => Role::Laptop,
    };
    let idle = st.idle_timeout;
    let (code, reason): (u16, &'static str) = loop {
        let msg = tokio::select! {
            k = &mut kick_rx => match k {
                Ok(close::LAPTOP_GONE) => break (close::LAPTOP_GONE, "laptop gone"),
                _ => break (close::REPLACED, "replaced"),
            },
            r = tokio::time::timeout(idle, stream.next()) => match r {
                Err(_) => break (close::IDLE, "idle timeout"),
                Ok(None) | Ok(Some(Err(_))) => break (1000, ""),
                Ok(Some(Ok(m))) => m,
            },
        };
        match msg {
            Message::Binary(b) => {
                if b.len() > st.max_frame {
                    break (close::TOO_BIG, "frame too large");
                }
                // No peer yet / any more: drop silently (phones are closed when the laptop goes).
                if let Some(ptx) = st.peer_tx(&room, other) {
                    // Backpressure: wait for the peer, but never forever.
                    if !matches!(
                        tokio::time::timeout(idle, ptx.send(Out::Bin(b))).await,
                        Ok(Ok(()))
                    ) {
                        tracing::debug!(room = room_tag, "relay peer stalled; dropping frame");
                    }
                }
            }
            Message::Text(_) => break (close::UNSUPPORTED, "binary frames only"),
            Message::Close(_) => break (1000, ""),
            Message::Ping(_) | Message::Pong(_) => {}
        }
    };

    st.unregister(&room, role, id);
    let _ = tx.send(Out::Close(code, reason)).await;
    drop(tx);
    if tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .is_err()
    {
        tracing::debug!(room = room_tag, "relay writer did not finish");
    }
    tracing::debug!(room = room_tag, ?role, id, code, "relay leave");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_validation() {
        assert!(valid_room("0123456789abcdef0123456789ABCDEF"));
        assert!(!valid_room("0123456789abcdef0123456789abcde"));
        assert!(!valid_room("0123456789abcdef0123456789abcdeg"));
        assert!(!valid_room("../../etc/passwd0123456789abcdef"));
    }

    #[test]
    fn forwarded_ip_only_when_trusted() {
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", "6.6.6.6, 1.2.3.4".parse().unwrap());
        assert_eq!(client_ip(peer, &h, false), peer.ip());
        assert_eq!(
            client_ip(peer, &h, true),
            "1.2.3.4".parse::<IpAddr>().unwrap()
        );
    }
}
