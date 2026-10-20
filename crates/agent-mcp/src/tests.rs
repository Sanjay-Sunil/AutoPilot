use super::*;
use tokio::io::{AsyncBufReadExt, BufReader, duplex};

type Seen = Arc<Mutex<Vec<Value>>>;

/// Minimal in-memory MCP server. Records every message it receives.
fn fake(seen: Seen) -> Connection {
    let (client, server) = duplex(1 << 16);
    let (cr, cw) = tokio::io::split(client);
    let (sr, mut sw) = tokio::io::split(server);
    tokio::spawn(async move {
        // Garbage and a server->client ping before anything else.
        let _ = sw
            .write_all(b"not json\n{\"jsonrpc\":\"2.0\",\"id\":\"s1\",\"method\":\"ping\"}\n")
            .await;
        let mut lines = BufReader::new(sr).lines();
        while let Ok(Some(l)) = lines.next_line().await {
            let m: Value = serde_json::from_str(&l).unwrap();
            seen.lock().unwrap().push(m.clone());
            let (Some(id), Some(method)) = (m.get("id").cloned(), m["method"].as_str()) else {
                continue;
            };
            let p = &m["params"];
            let result = match method {
                "initialize" => json!({ "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": { "tools": {} }, "serverInfo": { "name": "fake", "version": "0" } }),
                "tools/list" if p["cursor"].is_null() => json!({ "tools": [{
                    "name": "echo", "description": "Echo",
                    "inputSchema": { "type": "object", "properties": { "s": { "type": "string" } } },
                    "annotations": { "readOnlyHint": true } }], "nextCursor": "p2" }),
                "tools/list" => json!({ "tools": [{ "name": "wipe" }, { "bad": 1 }] }),
                "tools/call" => match p["name"].as_str().unwrap() {
                    "echo" => json!({ "content": [
                        { "type": "text", "text": p["arguments"]["s"] },
                        { "type": "image", "data": "AAAA", "mimeType": "image/png" }] }),
                    "fail" => {
                        json!({ "content": [{ "type": "text", "text": "nope" }], "isError": true })
                    }
                    "slow" => continue,
                    _ => Value::Null,
                },
                _ => Value::Null,
            };
            let reply = if result.is_null() {
                json!({ "jsonrpc": "2.0", "id": id, "error": { "code": -32602, "message": "unknown tool" } })
            } else {
                json!({ "jsonrpc": "2.0", "id": id, "result": result })
            };
            let mut b = serde_json::to_vec(&reply).unwrap();
            b.push(b'\n');
            if sw.write_all(&b).await.is_err() {
                break;
            }
        }
    });
    Connection::over(cr, cw, None)
}

const T: Duration = Duration::from_secs(5);

#[tokio::test]
async fn handshake_list_and_call() {
    let seen: Seen = Arc::default();
    let c = fake(seen.clone());
    c.initialize(T).await.unwrap();

    let tools = c.list_tools(T).await.unwrap();
    assert_eq!(
        tools.iter().map(|t| t.name.as_str()).collect::<Vec<_>>(),
        ["echo", "wipe"]
    );
    assert_eq!(tools[0].annotations.read_only_hint, Some(true));
    assert_eq!(tools[1].input_schema, json!({ "type": "object" }));

    let r = c.call_tool("echo", json!({ "s": "hi" }), T).await.unwrap();
    assert!(!r.is_error);
    assert_eq!(r.text(), "hi");
    assert_eq!(
        r.content[1],
        Content::Image {
            data: "AAAA".into(),
            mime: "image/png".into()
        }
    );
    assert!(c.call_tool("fail", json!({}), T).await.unwrap().is_error);
    let e = c.call_tool("nope", json!({}), T).await.unwrap_err();
    assert!(e.to_string().contains("unknown tool"), "{e}");

    let seen = seen.lock().unwrap();
    assert!(
        seen.iter()
            .any(|m| m["method"] == "notifications/initialized")
    );
    // The client answered the server's ping.
    assert!(
        seen.iter()
            .any(|m| m["id"] == "s1" && m["result"] == json!({}))
    );
}

#[tokio::test]
async fn timeout_and_drop_send_cancel() {
    let seen: Seen = Arc::default();
    let c = fake(seen.clone());
    c.initialize(T).await.unwrap();
    let e = c
        .call_tool("slow", json!({}), Duration::from_millis(50))
        .await
        .unwrap_err();
    assert!(e.to_string().contains("timed out"), "{e}");
    // Dropped mid-flight (what the kill switch does).
    tokio::select! {
        _ = c.call_tool("slow", json!({}), T) => panic!("slow answered"),
        _ = tokio::time::sleep(Duration::from_millis(50)) => {}
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(c.pending.lock().unwrap().is_empty());
    let cancels: Vec<_> = seen
        .lock()
        .unwrap()
        .iter()
        .filter(|m| m["method"] == "notifications/cancelled")
        .map(|m| m["params"]["requestId"].as_u64().unwrap())
        .collect();
    assert_eq!(cancels.len(), 2);
}

#[tokio::test]
async fn server_exit_fails_requests() {
    let (client, server) = duplex(1024);
    let (cr, cw) = tokio::io::split(client);
    let c = Connection::over(cr, cw, None);
    drop(server);
    let e = c.initialize(T).await.unwrap_err().to_string();
    assert!(e.contains("exited") || e.contains("pipe"), "{e}");
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(c.is_closed());
}

#[tokio::test]
async fn lazy_start_idle_stop_and_cache() {
    let seen: Seen = Arc::default();
    let starts = Arc::new(AtomicUsize::new(0));
    let (s2, st2) = (seen.clone(), starts.clone());
    let dir = std::env::temp_dir().join(format!("agent-mcp-test-{}", std::process::id()));
    let cache = dir.join("fake.tools.json");
    let _ = std::fs::remove_dir_all(&dir);
    let srv = Server::with_connector(
        "fake",
        Arc::new(move || {
            st2.fetch_add(1, Ordering::SeqCst);
            Ok(fake(s2.clone()))
        }),
        ServerOptions {
            idle: Duration::from_millis(200),
            cache: Some(cache.clone()),
            ..Default::default()
        },
    );
    assert!(srv.cached_tools().is_none());
    assert!(!srv.is_running().await);
    assert_eq!(starts.load(Ordering::SeqCst), 0);

    let r = srv.call("echo", json!({ "s": "x" })).await.unwrap();
    assert_eq!(r.text(), "x");
    assert!(srv.is_running().await);
    srv.call("echo", json!({ "s": "y" })).await.unwrap();
    assert_eq!(starts.load(Ordering::SeqCst), 1);
    assert_eq!(srv.list_tools().await.unwrap().len(), 2);
    assert_eq!(srv.cached_tools().unwrap().len(), 2);

    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(!srv.is_running().await, "idle server should stop");
    srv.call("echo", json!({ "s": "z" })).await.unwrap();
    assert_eq!(starts.load(Ordering::SeqCst), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parse_content_kinds() {
    let r = CallResult::parse(&json!({ "content": [
        { "type": "resource", "resource": { "uri": "odoo://res.partner/record/1", "text": "Acme" } },
        { "type": "resource", "resource": { "uri": "odoo://x/record/2/image", "blob": "..." } },
        { "type": "resource_link", "uri": "file:///a" },
        { "type": "audio", "data": "..." }
    ] }));
    assert_eq!(
        r.text(),
        "Acme\n[resource odoo://x/record/2/image]\n[link file:///a]\n[audio content omitted]"
    );
    let r = CallResult::parse(&json!({ "structuredContent": { "n": 1 } }));
    assert_eq!(r.text(), "{\"n\":1}");
}
