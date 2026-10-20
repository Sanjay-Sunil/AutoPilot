//! Unit tests: request building, stream parsing, retries, key lookup, Laya parsing.
//! No real API calls: everything HTTP goes to a wiremock server on 127.0.0.1.
use std::sync::Mutex;
use std::time::Duration;

use serde_json::{Value, json};
use wiremock::matchers::{body_partial_json, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::*;

fn fast_retry() -> RetryPolicy {
    RetryPolicy {
        retries: 2,
        base: Duration::from_millis(5),
        max: Duration::from_millis(20),
    }
}

fn sample_req() -> ChatRequest {
    let mut shot = Msg::tool("call_1", "screenshot taken");
    shot.images = vec![vec![0xFF, 0xD8, 0xFF]];
    let mut user = Msg::user("what's on screen?");
    user.images = vec![vec![1, 2, 3]];
    ChatRequest {
        system: "You are AutoPilot.".into(),
        messages: vec![
            user,
            Msg::assistant(
                "Let me look.",
                vec![ToolCall {
                    id: "call_1".into(),
                    name: "screenshot".into(),
                    arguments: json!({"display": 0}),
                }],
            ),
            shot,
        ],
        tools: vec![ToolSpec {
            name: "screenshot".into(),
            description: "Capture the screen".into(),
            parameters: json!({"type": "object", "properties": {"display": {"type": "integer"}}}),
        }],
        max_tokens: 512,
        temperature: Some(0.2),
    }
}

fn sse(events: &[Value]) -> String {
    events
        .iter()
        .map(|e| {
            format!(
                "event: {}\ndata: {}\n\n",
                e["type"].as_str().unwrap_or("x"),
                e
            )
        })
        .collect()
}

fn collect() -> (std::sync::Arc<Mutex<String>>, impl Fn(&str) + Send + Sync) {
    let buf = std::sync::Arc::new(Mutex::new(String::new()));
    let b2 = buf.clone();
    (buf, move |s: &str| b2.lock().unwrap().push_str(s))
}

// ---------------------------------------------------------------- Claude

#[test]
fn claude_body_tools_cache_images_tool_results() {
    let b = claude::build_body("claude-sonnet-5", &sample_req(), true);
    assert_eq!(b["model"], "claude-sonnet-5");
    assert_eq!(b["stream"], true);
    assert_eq!(b["system"][0]["cache_control"]["type"], "ephemeral");
    assert_eq!(b["tools"][0]["input_schema"]["type"], "object");
    assert_eq!(b["tools"][0]["eager_input_streaming"], true);
    assert!(
        b.get("temperature").is_none(),
        "sonnet-5 rejects sampling params"
    );
    assert_eq!(b["thinking"]["type"], "disabled");
    let m = b["messages"].as_array().unwrap();
    assert_eq!(m.len(), 3);
    assert_eq!(m[0]["content"][0]["type"], "image");
    assert_eq!(m[0]["content"][0]["source"]["media_type"], "image/jpeg");
    assert_eq!(m[0]["content"][0]["source"]["data"], "AQID");
    assert_eq!(m[0]["content"][1]["text"], "what's on screen?");
    assert_eq!(m[1]["content"][1]["type"], "tool_use");
    assert_eq!(m[1]["content"][1]["input"]["display"], 0);
    assert_eq!(m[2]["role"], "user");
    let tr = &m[2]["content"][0];
    assert_eq!(tr["type"], "tool_result");
    assert_eq!(tr["tool_use_id"], "call_1");
    assert_eq!(tr["content"][1]["type"], "image");

    // Older model keeps temperature; no system => cache breakpoint on last tool.
    let mut r = sample_req();
    r.system.clear();
    let b = claude::build_body("claude-haiku-4-5", &r, false);
    assert!((b["temperature"].as_f64().unwrap() - 0.2).abs() < 1e-6);
    assert_eq!(b["tools"][0]["cache_control"]["type"], "ephemeral");
    assert!(b.get("thinking").is_none());
    assert!(b["tools"][0].get("eager_input_streaming").is_none());
}

#[test]
fn claude_merges_parallel_tool_results() {
    let msgs = vec![
        Msg::user("x"),
        Msg::assistant(
            "",
            vec![
                ToolCall {
                    id: "a".into(),
                    name: "t".into(),
                    arguments: json!({}),
                },
                ToolCall {
                    id: "b".into(),
                    name: "t".into(),
                    arguments: json!({}),
                },
            ],
        ),
        Msg::tool("a", "1"),
        Msg::tool("b", "2"),
    ];
    let m = claude::map_messages(&msgs);
    assert_eq!(m.len(), 3);
    assert_eq!(m[2]["content"].as_array().unwrap().len(), 2);
}

#[test]
fn claude_stream_text_and_tool_deltas() {
    let events = [
        json!({"type":"message_start","message":{"usage":{"input_tokens":10,"cache_read_input_tokens":1000,"cache_creation_input_tokens":0,"output_tokens":1}}}),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"Open"}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ing."}}),
        json!({"type":"content_block_stop","index":0}),
        json!({"type":"content_block_start","index":1,"content_block":{"type":"tool_use","id":"toolu_1","name":"open_app","input":{}}}),
        json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"{\"na"}}),
        json!({"type":"content_block_delta","index":1,"delta":{"type":"input_json_delta","partial_json":"me\": \"firefox\"}"}}),
        json!({"type":"content_block_stop","index":1}),
        json!({"type":"message_delta","delta":{"stop_reason":"tool_use"},"usage":{"output_tokens":20}}),
        json!({"type":"message_stop"}),
    ];
    let (buf, f) = collect();
    let mut st = claude::StreamState::default();
    for e in &events {
        st.on_event(e, &f).unwrap();
    }
    let r = st.finish("claude-sonnet-5").unwrap();
    assert_eq!(*buf.lock().unwrap(), "Opening.");
    assert_eq!(r.text, "Opening.");
    assert_eq!(
        r.tool_calls,
        vec![ToolCall {
            id: "toolu_1".into(),
            name: "open_app".into(),
            arguments: json!({"name": "firefox"})
        }]
    );
    assert_eq!(r.usage.input_tokens, 1010);
    assert_eq!(r.usage.output_tokens, 20);
    // 10*2 + 1000*0.2 + 20*10 = 420 per 1e6
    assert!(
        (r.usage.cost_usd - 420e-6).abs() < 1e-12,
        "{}",
        r.usage.cost_usd
    );
}

#[tokio::test]
async fn claude_stream_over_http() {
    let server = MockServer::start().await;
    let body = sse(&[
        json!({"type":"message_start","message":{"usage":{"input_tokens":5,"output_tokens":1}}}),
        json!({"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}),
        json!({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"hi"}}),
        json!({"type":"content_block_stop","index":0}),
        json!({"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":2}}),
    ]);
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .and(header("x-api-key", "test-key"))
        .and(header("anthropic-version", "2023-06-01"))
        .and(body_partial_json(json!({"stream": true})))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-type", "text/event-stream")
                .set_body_string(body),
        )
        .mount(&server)
        .await;
    let p = ClaudeProvider::new("test-key".into(), None)
        .with_base_url(server.uri())
        .with_retry(fast_retry());
    let (buf, f) = collect();
    let r = p.chat_stream(&sample_req(), &f).await.unwrap();
    assert_eq!(r.text, "hi");
    assert_eq!(*buf.lock().unwrap(), "hi");
    assert_eq!(p.model(), "claude-sonnet-5");
}

#[tokio::test]
async fn claude_nonstream_and_retry_on_529_then_ok() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(529).set_body_string("overloaded"))
        .up_to_n_times(2)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/messages"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "type":"message","content":[{"type":"text","text":"ok"},{"type":"tool_use","id":"t1","name":"x","input":{"a":1}}],
            "stop_reason":"tool_use","usage":{"input_tokens":3,"output_tokens":4}})))
        .with_priority(2)
        .mount(&server)
        .await;
    let p = ClaudeProvider::new("k".into(), None)
        .with_base_url(server.uri())
        .with_retry(fast_retry());
    let r = p.chat(&sample_req()).await.unwrap();
    assert_eq!(r.text, "ok");
    assert_eq!(r.tool_calls[0].arguments, json!({"a": 1}));
    assert_eq!(server.received_requests().await.unwrap().len(), 3);
}

#[tokio::test]
async fn retry_gives_up_after_two_retries_and_skips_4xx() {
    let server = MockServer::start().await;
    Mock::given(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "0"))
        .mount(&server)
        .await;
    let p = OpenAiProvider::new("k".into(), None)
        .with_base_url(server.uri())
        .with_retry(fast_retry());
    let e = p.chat(&sample_req()).await.unwrap_err().to_string();
    assert!(e.contains("429"), "{e}");
    assert_eq!(server.received_requests().await.unwrap().len(), 3);

    let server = MockServer::start().await;
    Mock::given(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(400).set_body_string("bad request"))
        .mount(&server)
        .await;
    let p = OpenAiProvider::new("secret-key-123".into(), None)
        .with_base_url(server.uri())
        .with_retry(fast_retry());
    let e = p.chat(&sample_req()).await.unwrap_err().to_string();
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
    assert!(!e.contains("secret-key-123"));
}

#[tokio::test]
async fn retry_on_connect_error() {
    // Bind then drop a listener to get a port that refuses connections.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let p = OllamaProvider::new(format!("http://127.0.0.1:{port}"), "m".into())
        .with_retry(fast_retry());
    let t = std::time::Instant::now();
    let e = p.chat(&sample_req()).await.unwrap_err().to_string();
    assert!(e.contains("request failed"), "{e}");
    assert!(
        t.elapsed() >= Duration::from_millis(15),
        "should have backed off twice"
    );
}

// ---------------------------------------------------------------- OpenAI

#[test]
fn openai_body_tools_images_tool_results() {
    let b = openai::build_body("gpt-6-luna", &sample_req(), true);
    assert_eq!(b["stream_options"]["include_usage"], true);
    assert_eq!(b["max_completion_tokens"], 512);
    assert!(b.get("temperature").is_none());
    assert_eq!(b["tools"][0]["type"], "function");
    assert_eq!(b["tools"][0]["function"]["parameters"]["type"], "object");
    let m = b["messages"].as_array().unwrap();
    assert_eq!(m[0]["role"], "system");
    assert_eq!(
        m[1]["content"][1]["image_url"]["url"],
        "data:image/jpeg;base64,AQID"
    );
    assert_eq!(
        m[2]["tool_calls"][0]["function"]["arguments"],
        "{\"display\":0}"
    );
    assert_eq!(m[3]["role"], "tool");
    assert_eq!(m[3]["tool_call_id"], "call_1");
    assert_eq!(m[4]["role"], "user", "tool images follow as a user turn");
    let b = openai::build_body("gpt-4.1-nano", &sample_req(), false);
    assert!(b["temperature"].is_number());
    assert!(b.get("stream").is_none());
}

#[test]
fn openai_stream_tool_call_deltas() {
    let chunks = [
        json!({"choices":[{"index":0,"delta":{"role":"assistant","content":"Sure"}}]}),
        json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"open_app","arguments":""}}]}}]}),
        json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"name\":"}}]}}]}),
        json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_b","function":{"name":"battery","arguments":"{}"}}]}}]}),
        json!({"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"code\"}"}}]}}]}),
        json!({"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}),
        json!({"choices":[],"usage":{"prompt_tokens":1000,"completion_tokens":100,"prompt_tokens_details":{"cached_tokens":500}}}),
    ];
    let (buf, f) = collect();
    let mut st = openai::StreamState::default();
    for c in &chunks {
        st.on_chunk(c, &f).unwrap();
    }
    let r = st.finish("gpt-6-luna").unwrap();
    assert_eq!(*buf.lock().unwrap(), "Sure");
    assert_eq!(r.tool_calls.len(), 2);
    assert_eq!(
        r.tool_calls[0],
        ToolCall {
            id: "call_a".into(),
            name: "open_app".into(),
            arguments: json!({"name": "code"})
        }
    );
    assert_eq!(r.tool_calls[1].name, "battery");
    // (500*0.10 + 500*0.01 + 100*0.50)/1e6
    assert!(
        (r.usage.cost_usd - 105e-6).abs() < 1e-12,
        "{}",
        r.usage.cost_usd
    );
}

#[tokio::test]
async fn openai_stream_over_http_with_done() {
    let server = MockServer::start().await;
    let body = "data: {\"choices\":[{\"delta\":{\"content\":\"he\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"y\"}}]}\n\ndata: [DONE]\n\n";
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer k"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;
    let p = OpenAiProvider::new("k".into(), Some("gpt-5-mini".into())).with_base_url(server.uri());
    let (buf, f) = collect();
    let r = p.chat_stream(&sample_req(), &f).await.unwrap();
    assert_eq!(r.text, "hey");
    assert_eq!(*buf.lock().unwrap(), "hey");
    assert_eq!(p.model(), "gpt-5-mini");
}

// ---------------------------------------------------------------- Gemini

#[test]
fn gemini_body_and_signature_roundtrip() {
    let mut req = sample_req();
    req.messages[1].tool_calls[0].id = "fc1#ts=SIG==".into();
    req.messages[2].tool_call_id = Some("fc1#ts=SIG==".into());
    let b = gemini::build_body(&req);
    assert_eq!(
        b["systemInstruction"]["parts"][0]["text"],
        "You are AutoPilot."
    );
    assert_eq!(
        b["tools"][0]["functionDeclarations"][0]["name"],
        "screenshot"
    );
    assert_eq!(b["generationConfig"]["maxOutputTokens"], 512);
    let c = b["contents"].as_array().unwrap();
    assert_eq!(c[0]["parts"][1]["inlineData"]["mimeType"], "image/jpeg");
    assert_eq!(c[1]["role"], "model");
    assert_eq!(c[1]["parts"][1]["functionCall"]["id"], "fc1");
    assert_eq!(c[1]["parts"][1]["thoughtSignature"], "SIG==");
    assert_eq!(c[2]["parts"][0]["functionResponse"]["name"], "screenshot");
    assert_eq!(
        c[2]["parts"][0]["functionResponse"]["response"]["content"],
        "screenshot taken"
    );
    assert!(c[2]["parts"][1]["inlineData"].is_object());
}

#[tokio::test]
async fn gemini_stream_over_http() {
    let server = MockServer::start().await;
    let body = sse(&[
        json!({"candidates":[{"content":{"role":"model","parts":[{"text":"Checking"}]}}]}),
        json!({"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"battery","args":{"x":1}},"thoughtSignature":"abc"}]}}],
               "usageMetadata":{"promptTokenCount":100,"candidatesTokenCount":10,"thoughtsTokenCount":5}}),
    ]);
    Mock::given(method("POST"))
        .and(path(
            "/v1beta/models/gemini-3.8-flash:streamGenerateContent",
        ))
        .and(query_param("alt", "sse"))
        .and(header("x-goog-api-key", "gk"))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;
    let p = GeminiProvider::new("gk".into(), None).with_base_url(server.uri());
    let (buf, f) = collect();
    let r = p.chat_stream(&sample_req(), &f).await.unwrap();
    assert_eq!(*buf.lock().unwrap(), "Checking");
    assert_eq!(r.tool_calls[0].name, "battery");
    assert_eq!(r.tool_calls[0].id, "gemini-call-0#ts=abc");
    assert_eq!(r.usage.output_tokens, 15);
    assert!(r.usage.cost_usd > 0.0);
}

// ---------------------------------------------------------------- Ollama

#[test]
fn ollama_body() {
    let b = ollama::build_body("qwen3:4b", &sample_req(), true);
    assert_eq!(b["keep_alive"], "2m");
    assert_eq!(b["stream"], true);
    assert_eq!(b["options"]["num_predict"], 512);
    let m = b["messages"].as_array().unwrap();
    assert_eq!(m[1]["images"][0], "AQID");
    assert_eq!(m[2]["tool_calls"][0]["function"]["arguments"]["display"], 0);
    assert_eq!(m[3]["role"], "tool");
    assert_eq!(m[3]["tool_name"], "screenshot");
}

#[tokio::test]
async fn ollama_ndjson_stream() {
    let server = MockServer::start().await;
    let body = concat!(
        "{\"message\":{\"role\":\"assistant\",\"content\":\"Hel\"},\"done\":false}\n",
        "{\"message\":{\"role\":\"assistant\",\"content\":\"lo\"},\"done\":false}\n",
        "{\"message\":{\"role\":\"assistant\",\"content\":\"\",\"tool_calls\":[{\"function\":{\"name\":\"open_app\",\"arguments\":{\"name\":\"firefox\"}}}]},\"done\":false}\n",
        "{\"message\":{\"role\":\"assistant\",\"content\":\"\"},\"done\":true,\"prompt_eval_count\":42,\"eval_count\":7}"
    );
    Mock::given(method("POST"))
        .and(path("/api/chat"))
        .and(body_partial_json(json!({"keep_alive": "2m"})))
        .respond_with(ResponseTemplate::new(200).set_body_string(body))
        .mount(&server)
        .await;
    let p = OllamaProvider::new(server.uri(), "qwen3:4b".into());
    let (buf, f) = collect();
    let r = p.chat_stream(&sample_req(), &f).await.unwrap();
    assert_eq!(*buf.lock().unwrap(), "Hello");
    assert_eq!(r.tool_calls[0].arguments, json!({"name": "firefox"}));
    assert_eq!((r.usage.input_tokens, r.usage.output_tokens), (42, 7));
    assert_eq!(r.usage.cost_usd, 0.0);
    assert_eq!(p.brain(), Brain::Local);
}

// ---------------------------------------------------------------- keys / prices

#[test]
fn key_lookup_order() {
    let env = |k: &str| match k {
        "GOOGLE_API_KEY" => Some("google".to_owned()),
        "OPENAI_API_KEY" => Some("  ".to_owned()),
        _ => None,
    };
    let kr = |u: &str| Some(format!("ring-{u}"));
    assert_eq!(keys::lookup("gemini", env, kr).as_deref(), Some("google"));
    assert_eq!(
        keys::lookup(
            "gemini",
            |k| (k == "GEMINI_API_KEY").then(|| "gem".into()),
            kr
        )
        .as_deref(),
        Some("gem")
    );
    assert_eq!(
        keys::lookup("openai", env, kr).as_deref(),
        Some("ring-openai"),
        "blank env falls through"
    );
    assert_eq!(
        keys::lookup("claude", env, kr).as_deref(),
        Some("ring-claude")
    );
    assert_eq!(
        keys::lookup("claude", |_| Some("env".into()), kr).as_deref(),
        Some("env")
    );
    assert_eq!(keys::lookup("claude", env, |_| None), None);
    assert_eq!(keys::keyring_user("anthropic"), "claude");
}

#[test]
fn prices() {
    assert_eq!(
        price_per_mtok(Brain::Claude, "claude-sonnet-5"),
        (2.0, 10.0)
    );
    assert_eq!(
        price_per_mtok(Brain::Claude, "claude-opus-5-5"),
        (4.0, 20.0)
    );
    assert_eq!(price_per_mtok(Brain::Claude, "claude-opus-5"), (5.0, 25.0));
    assert_eq!(
        price_per_mtok(Brain::Claude, "claude-haiku-4-5"),
        (1.0, 5.0)
    );
    assert_eq!(price_per_mtok(Brain::Openai, "gpt-6-luna"), (0.10, 0.50));
    assert_eq!(price_per_mtok(Brain::Openai, "gpt-5-mini"), (0.25, 2.0));
    assert_eq!(
        price_per_mtok(Brain::Gemini, "gemini-3.8-flash"),
        (0.75, 3.75)
    );
    assert_eq!(price_per_mtok(Brain::Local, "anything"), (0.0, 0.0));
    assert_eq!(price_per_mtok(Brain::Openai, "future-model"), (2.5, 15.0));
}

// ---------------------------------------------------------------- Laya

fn fixture(name: &str) -> Value {
    let p = format!("{}/tests/fixtures/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
}

#[test]
fn laya_questions_cover_all_intents() {
    let q = laya::decide_questions();
    let crit = q["intent"]["criteria"].as_object().unwrap();
    assert_eq!(crit.len(), INTENTS.len());
    assert!(INTENTS.iter().all(|i| crit.contains_key(*i)));
    assert_eq!(q["needs_cloud"]["type"], "noul");
}

#[tokio::test]
async fn laya_decide_against_mock_with_real_fixture() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/systemone"))
        .and(body_partial_json(json!({"state": {"request": "delete all files in Downloads"}, "questions": {"risk": {"type": "choice"}}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(fixture("laya_delete_downloads.json")))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/health"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"status": "ok"})))
        .mount(&server)
        .await;
    let c = LayaClient::new(server.uri());
    assert!(c.healthy().await);
    let d = c.decide("delete all files in Downloads").await.unwrap();
    assert_eq!(d.intent, "files");
    assert_eq!(d.risk, RiskTier::Destructive);
    assert_eq!(d.sensitivity, Sensitivity::Medium);
    assert!(d.intent_confidence > 0.5);
    assert!(d.needs_cloud < 0.5);
}

#[test]
fn laya_parse_battery_fixture_and_errors() {
    let d = laya::parse_decision(&fixture("laya_battery.json")).unwrap();
    assert_eq!(d.intent, "system_info");
    assert_eq!(d.risk, RiskTier::Read);
    assert_eq!(d.sensitivity, Sensitivity::Low);
    assert!(laya::parse_decision(&json!({"detail": "x"})).is_err());
    let mut bad = fixture("laya_battery.json");
    bad["answers"]["intent"]["choice"] = json!("nope");
    assert!(laya::parse_decision(&bad).is_err());
}

#[tokio::test]
async fn laya_unhealthy_when_down() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    assert!(
        !LayaClient::new(format!("http://127.0.0.1:{port}"))
            .healthy()
            .await
    );
}
