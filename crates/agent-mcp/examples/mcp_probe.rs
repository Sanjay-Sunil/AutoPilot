//! Start an MCP server over stdio, list its tools, and optionally call one.
//!
//! cargo run -p agent-mcp --example mcp_probe -- uvx mcp-server-odoo
//! MCP_CALL='list_models' MCP_ARGS='{}' cargo run -p agent-mcp --example mcp_probe -- uvx mcp-server-odoo
//!
//! Only PATH/HOME/XDG_* pass through; set server variables as MCP_ENV='K=V,K2=V2'.
use agent_mcp::{Launch, Server, ServerOptions};

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let mut argv = std::env::args().skip(1);
    let command = argv
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: mcp_probe <command> [args...]"))?;
    let env = std::env::var("MCP_ENV")
        .unwrap_or_default()
        .split(',')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    let launch = Launch {
        command,
        args: argv.collect(),
        env,
        cwd: None,
    };
    let srv = Server::new("probe", launch, ServerOptions::default());
    let t = std::time::Instant::now();
    let tools = srv.list_tools().await?;
    println!("{} tools in {:?}", tools.len(), t.elapsed());
    for tool in &tools {
        let a = &tool.annotations;
        println!(
            "  {:32} ro={:?} destructive={:?}  {}",
            tool.name,
            a.read_only_hint,
            a.destructive_hint,
            tool.description.lines().next().unwrap_or("")
        );
    }
    if let Ok(name) = std::env::var("MCP_CALL") {
        let args = std::env::var("MCP_ARGS").unwrap_or_else(|_| "{}".into());
        let r = srv.call(&name, serde_json::from_str(&args)?).await?;
        println!("is_error={}\n{}", r.is_error, r.text());
    }
    Ok(())
}
