//! Integration tests for the blind relay, using real WebSocket clients.

use backend::{AppState, Config};
use futures_util::{SinkExt, StreamExt};
use std::net::SocketAddr;
use std::time::Duration;
use tokio_tungstenite::tungstenite::{Message, protocol::frame::coding::CloseCode};

type Ws =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

const ROOM: &str = "00112233445566778899aabbccddeeff";

async fn start(cfg: Config) -> SocketAddr {
    let state = AppState::new(&cfg);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(
            listener,
            backend::app(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    addr
}

fn test_cfg() -> Config {
    Config {
        rate_per_min: 6000,
        rate_burst: 1000,
        ..Config::default()
    }
}

async fn join(addr: SocketAddr, room: &str, role: &str) -> Ws {
    let url = format!("ws://{addr}/relay/{room}?role={role}");
    tokio_tungstenite::connect_async(url).await.unwrap().0
}

async fn next(ws: &mut Ws) -> Message {
    loop {
        let m = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("timed out waiting for frame")
            .expect("stream ended")
            .expect("ws error");
        if !matches!(m, Message::Ping(_) | Message::Pong(_)) {
            return m;
        }
    }
}

/// Wait until the socket is closed; returns the close code if a close frame was received.
async fn closed(ws: &mut Ws) -> Option<u16> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        match tokio::time::timeout_at(deadline, ws.next()).await {
            Err(_) => panic!("socket not closed in time"),
            Ok(None) | Ok(Some(Err(_))) => return None,
            Ok(Some(Ok(Message::Close(f)))) => return f.map(|f| u16::from(f.code)),
            Ok(Some(Ok(_))) => {}
        }
    }
}

#[tokio::test]
async fn health_ok() {
    let addr = start(test_cfg()).await;
    let mut s = tokio::net::TcpStream::connect(addr).await.unwrap();
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    s.write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).await.unwrap();
    assert!(out.starts_with("HTTP/1.1 200"), "{out}");
    assert!(out.contains("\"status\":\"ok\""));
}

#[tokio::test]
async fn relays_binary_both_ways() {
    let addr = start(test_cfg()).await;
    let mut laptop = join(addr, ROOM, "laptop").await;
    let mut phone = join(addr, ROOM, "phone").await;

    assert_eq!(
        next(&mut laptop).await,
        Message::Text("peer-connected".into())
    );

    phone
        .send(Message::Binary(vec![1, 2, 3].into()))
        .await
        .unwrap();
    assert_eq!(
        next(&mut laptop).await,
        Message::Binary(vec![1, 2, 3].into())
    );

    let big = vec![7u8; 65_535];
    laptop
        .send(Message::Binary(big.clone().into()))
        .await
        .unwrap();
    assert_eq!(next(&mut phone).await, Message::Binary(big.into()));

    // Many frames keep order.
    for i in 0..100u8 {
        phone.send(Message::Binary(vec![i].into())).await.unwrap();
    }
    for i in 0..100u8 {
        assert_eq!(next(&mut laptop).await, Message::Binary(vec![i].into()));
    }
}

#[tokio::test]
async fn rooms_are_isolated() {
    let addr = start(test_cfg()).await;
    let other = "ffeeddccbbaa99887766554433221100";
    let mut l1 = join(addr, ROOM, "laptop").await;
    let mut l2 = join(addr, other, "laptop").await;
    let mut p1 = join(addr, ROOM, "phone").await;
    assert_eq!(next(&mut l1).await, Message::Text("peer-connected".into()));
    p1.send(Message::Binary(vec![9].into())).await.unwrap();
    assert_eq!(next(&mut l1).await, Message::Binary(vec![9].into()));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), l2.next())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn bad_room_and_role_rejected() {
    let addr = start(test_cfg()).await;
    for url in [
        format!("ws://{addr}/relay/short?role=laptop"),
        format!("ws://{addr}/relay/zz112233445566778899aabbccddeeff?role=laptop"),
        format!("ws://{addr}/relay/00112233445566778899aabbccddeeff00?role=laptop"),
        format!("ws://{addr}/relay/{ROOM}?role=admin"),
        format!("ws://{addr}/relay/{ROOM}"),
    ] {
        match tokio_tungstenite::connect_async(&url).await {
            Err(tokio_tungstenite::tungstenite::Error::Http(r)) => {
                assert_eq!(r.status(), 400, "{url}")
            }
            other => panic!("{url}: expected HTTP 400, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn phone_without_laptop_is_closed() {
    let addr = start(test_cfg()).await;
    let mut phone = join(addr, ROOM, "phone").await;
    assert_eq!(closed(&mut phone).await, Some(4404));
}

#[tokio::test]
async fn oversize_frame_closes() {
    let addr = start(test_cfg()).await;
    let mut laptop = join(addr, ROOM, "laptop").await;
    let mut phone = join(addr, ROOM, "phone").await;
    assert_eq!(
        next(&mut laptop).await,
        Message::Text("peer-connected".into())
    );

    phone
        .send(Message::Binary(vec![0u8; 70_001].into()))
        .await
        .unwrap();
    assert_eq!(closed(&mut phone).await, Some(u16::from(CloseCode::Size)));
    // The oversize frame was not forwarded.
    assert!(
        tokio::time::timeout(Duration::from_millis(200), laptop.next())
            .await
            .is_err()
    );

    // Way-oversize frames are cut off by the WS layer (close or reset, never forwarded).
    let mut phone2 = join(addr, ROOM, "phone").await;
    assert_eq!(
        next(&mut laptop).await,
        Message::Text("peer-connected".into())
    );
    let _ = phone2
        .send(Message::Binary(vec![0u8; 1_000_000].into()))
        .await;
    let _ = closed(&mut phone2).await;
}

#[tokio::test]
async fn text_frames_from_clients_close() {
    let addr = start(test_cfg()).await;
    let mut laptop = join(addr, ROOM, "laptop").await;
    laptop.send(Message::Text("hello".into())).await.unwrap();
    assert_eq!(closed(&mut laptop).await, Some(1003));
}

#[tokio::test]
async fn new_phone_replaces_old() {
    let addr = start(test_cfg()).await;
    let mut laptop = join(addr, ROOM, "laptop").await;
    let mut p1 = join(addr, ROOM, "phone").await;
    assert_eq!(
        next(&mut laptop).await,
        Message::Text("peer-connected".into())
    );

    let mut p2 = join(addr, ROOM, "phone").await;
    assert_eq!(
        next(&mut laptop).await,
        Message::Text("peer-connected".into())
    );
    assert_eq!(closed(&mut p1).await, Some(4000));

    p2.send(Message::Binary(vec![42].into())).await.unwrap();
    assert_eq!(next(&mut laptop).await, Message::Binary(vec![42].into()));
    laptop.send(Message::Binary(vec![43].into())).await.unwrap();
    assert_eq!(next(&mut p2).await, Message::Binary(vec![43].into()));
}

#[tokio::test]
async fn laptop_leaving_closes_phone() {
    let addr = start(test_cfg()).await;
    let mut laptop = join(addr, ROOM, "laptop").await;
    let mut phone = join(addr, ROOM, "phone").await;
    assert_eq!(
        next(&mut laptop).await,
        Message::Text("peer-connected".into())
    );
    laptop.close(None).await.unwrap();
    assert_eq!(closed(&mut phone).await, Some(4410));
}

#[tokio::test]
async fn idle_timeout_closes() {
    let addr = start(Config {
        idle_timeout: Duration::from_millis(300),
        ..test_cfg()
    })
    .await;
    let mut laptop = join(addr, ROOM, "laptop").await;
    assert_eq!(closed(&mut laptop).await, Some(4408));
}

#[tokio::test]
async fn per_ip_rate_limit() {
    let addr = start(Config {
        rate_per_min: 1,
        rate_burst: 2,
        ..Config::default()
    })
    .await;
    let room = "abcdefabcdefabcdefabcdefabcdefab";
    let _a = join(addr, room, "laptop").await;
    let _b = join(addr, room, "laptop").await;
    match tokio_tungstenite::connect_async(format!("ws://{addr}/relay/{room}?role=laptop")).await {
        Err(tokio_tungstenite::tungstenite::Error::Http(r)) => assert_eq!(r.status(), 429),
        other => panic!("expected 429, got {other:?}"),
    }
}
