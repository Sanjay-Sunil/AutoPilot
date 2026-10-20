//! Print `LayaClient::decide` results for a few commands against a running `laya-serve`.
//!
//! ```sh
//! cargo run -p agent-llm --example laya_probe -- [base_url] ["extra command" ...]
//! ```
use agent_llm::LayaClient;

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let base = args
        .next()
        .unwrap_or_else(|| "http://127.0.0.1:8765".into());
    let mut cmds: Vec<String> = [
        "open firefox",
        "delete all files in Downloads",
        "write a cover letter for a Rust job",
        "what's my battery",
    ]
    .map(String::from)
    .to_vec();
    cmds.extend(args);

    let laya = LayaClient::new(base.clone()).with_api_key(std::env::var("LAYA_API_KEY").ok());
    if !laya.healthy().await {
        anyhow::bail!("laya-serve not reachable at {base}");
    }
    for c in &cmds {
        match laya.decide(c).await {
            Ok(d) => println!(
                "{:>6}ms  {:<40} intent={} ({:.2}) risk={:?} sensitivity={:?} needs_cloud={:.2}",
                d.latency_ms,
                c,
                d.intent,
                d.intent_confidence,
                d.risk,
                d.sensitivity,
                d.needs_cloud
            ),
            Err(e) => println!("ERR {c}: {e:#}"),
        }
    }
    Ok(())
}
