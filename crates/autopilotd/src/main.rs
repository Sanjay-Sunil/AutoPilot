use agent_core::{Agent, AgentConfig};
use agent_transport::{DeviceKeys, PairingManager, ServerConfig, TrustStore, create_private_dir};
use autopilotd::control::{self, ControlClient};
use autopilotd::{
    DEFAULT_LISTEN, DaemonSettings, DaemonState, agent_handler, default_config_path, print_pairing,
};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicUsize;
use tokio::sync::{Mutex, mpsc};
use tracing::{error, info};

mod chat;

#[derive(Parser)]
#[command(name = "autopilotd", version, about = "AutoPilot laptop agent daemon")]
struct Cli {
    /// Config file (TOML). Default: ~/.config/autopilot/config.toml
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    /// Machine-readable output (JSON lines) for kill/pair/status/devices/revoke.
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run the daemon.
    Run {
        /// Listen address for direct (LAN/Tailscale) connections. Default 0.0.0.0:7878.
        #[arg(long)]
        listen: Option<String>,
        /// Relay base URL, e.g. wss://relay.example/relay
        #[arg(long)]
        relay: Option<String>,
        /// Print a pairing QR at startup.
        #[arg(long)]
        pair: bool,
    },
    /// Kill switch: stop all running actions and the screen stream.
    Kill {
        #[arg(long)]
        reason: Option<String>,
    },
    /// Issue a one-time pairing token and show the QR code.
    Pair {
        /// Do not wait for the phone to pair (default with --json).
        #[arg(long)]
        no_wait: bool,
        /// Wait for the phone even with --json (prints a second line with the code).
        #[arg(long, conflicts_with = "no_wait")]
        wait: bool,
    },
    /// Show daemon status.
    Status,
    /// List paired devices (`devices revoke <pk>` revokes one).
    Devices {
        #[command(subcommand)]
        cmd: Option<DevicesCmd>,
    },
    /// Revoke a paired device (kills its sessions immediately).
    Revoke { pk: String },
    /// Interactive phone simulator.
    Chat {
        /// e.g. ws://127.0.0.1:7878/ws
        #[arg(long)]
        url: Option<String>,
        /// Laptop static public key (base64url).
        #[arg(long)]
        laptop_pk: Option<String>,
        #[arg(long)]
        pair_token: Option<String>,
        /// A full `autopilot://pair?d=...` link (sets url, key and token).
        #[arg(long)]
        uri: Option<String>,
        #[arg(long, default_value = "sim-phone")]
        name: String,
    },
    /// Manage cloud API keys (stored in the OS keystore).
    Keys {
        #[command(subcommand)]
        cmd: KeysCmd,
    },
    /// Audit log tools.
    Audit {
        #[command(subcommand)]
        cmd: AuditCmd,
    },
}

#[derive(Subcommand)]
enum DevicesCmd {
    /// Revoke a paired device.
    Revoke { pk: String },
}

#[derive(Subcommand)]
enum KeysCmd {
    /// Read the key from stdin (no echo on a terminal) and store it.
    /// `claude`, `openai`, `gemini`, or an MCP plugin secret `mcp:<server>:<ENV_VAR>`.
    Set {
        #[arg(value_parser = parse_key_name)]
        provider: String,
    },
    /// Show which providers have a key (never the key itself).
    List,
}

fn parse_key_name(s: &str) -> Result<String, String> {
    if matches!(s, "claude" | "openai" | "gemini") {
        return Ok(s.to_string());
    }
    let ok = s
        .strip_prefix("mcp:")
        .and_then(|r| r.split_once(':'))
        .is_some_and(|(srv, var)| {
            !srv.is_empty()
                && srv
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')
                && !var.is_empty()
                && var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        });
    if ok {
        Ok(s.to_string())
    } else {
        Err("expected claude, openai, gemini, or mcp:<server>:<ENV_VAR>".into())
    }
}

#[derive(Subcommand)]
enum AuditCmd {
    /// Verify the hash chain of the audit log.
    Verify,
}

fn init_tracing(default: &str) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(false)
        .init();
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    init_tracing(if matches!(cli.cmd, Cmd::Run { .. }) {
        "info"
    } else {
        "warn"
    });
    if let Err(e) = real_main(cli).await {
        eprintln!("error: {e:#}");
        std::process::exit(1);
    }
}

async fn real_main(cli: Cli) -> anyhow::Result<()> {
    let cfg_path = cli.config.clone().unwrap_or_else(default_config_path);
    let load = || AgentConfig::load(&cfg_path);
    let json_out = cli.json;
    match cli.cmd {
        Cmd::Run {
            listen,
            relay,
            pair,
        } => {
            let settings = DaemonSettings::load(&cfg_path)?;
            run(load()?, settings, listen, relay, pair).await
        }
        Cmd::Kill { reason } => {
            let mut req = json!({"cmd": "kill"});
            if let Some(r) = reason {
                req["reason"] = r.into();
            }
            let (_, v) = ControlClient::request(&load()?.data_dir, &req).await?;
            if json_out {
                println!("{v}")
            } else {
                println!("kill switch sent")
            }
            Ok(())
        }
        Cmd::Pair { no_wait, wait } => {
            let wait = if json_out { wait } else { !no_wait };
            pair(&load()?.data_dir, json_out, wait).await
        }
        Cmd::Status => {
            let (_, v) =
                ControlClient::request(&load()?.data_dir, &json!({"cmd": "status"})).await?;
            if json_out {
                println!("{v}")
            } else {
                println!("{}", serde_json::to_string_pretty(&v)?)
            }
            Ok(())
        }
        Cmd::Devices {
            cmd: Some(DevicesCmd::Revoke { pk }),
        }
        | Cmd::Revoke { pk } => {
            let (_, v) =
                ControlClient::request(&load()?.data_dir, &json!({"cmd": "revoke", "pk": pk}))
                    .await?;
            if json_out {
                println!("{v}");
            } else {
                println!(
                    "{}",
                    if v["revoked"] == true {
                        "revoked"
                    } else {
                        "no such device"
                    }
                );
            }
            Ok(())
        }
        Cmd::Devices { cmd: None } => {
            let (_, v) =
                ControlClient::request(&load()?.data_dir, &json!({"cmd": "devices"})).await?;
            if json_out {
                println!("{v}");
                return Ok(());
            }
            let devices = v["devices"].as_array().cloned().unwrap_or_default();
            if devices.is_empty() {
                println!("no paired devices");
            }
            for d in devices {
                println!(
                    "{}  {}  paired_at_ms={}",
                    d["pk_b64"].as_str().unwrap_or(""),
                    d["name"].as_str().unwrap_or(""),
                    d["paired_at_ms"]
                );
            }
            Ok(())
        }
        Cmd::Chat {
            url,
            laptop_pk,
            pair_token,
            uri,
            name,
        } => chat::run(url, laptop_pk, pair_token, uri, name).await,
        Cmd::Keys {
            cmd: KeysCmd::Set { provider },
        } => {
            let key = read_secret(&format!("{provider} API key: "))?;
            let key = key.trim();
            if key.is_empty() {
                anyhow::bail!("empty key");
            }
            agent_llm::set_api_key(&provider, key)?;
            println!("stored {provider} key in the OS keystore");
            Ok(())
        }
        Cmd::Keys { cmd: KeysCmd::List } => {
            for p in ["claude", "openai", "gemini"] {
                let set = agent_llm::api_key(p).is_some();
                println!("{p:8} {}", if set { "configured" } else { "-" });
            }
            Ok(())
        }
        Cmd::Audit {
            cmd: AuditCmd::Verify,
        } => {
            let path = load()?.data_dir.join("audit.db");
            let ok = agent_audit::AuditLog::open(&path)?.verify_chain()?;
            println!(
                "{}: {}",
                path.display(),
                if ok { "chain OK" } else { "CHAIN BROKEN" }
            );
            if !ok {
                std::process::exit(2);
            }
            Ok(())
        }
    }
}

fn read_secret(prompt: &str) -> anyhow::Result<String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        Ok(rpassword::prompt_password(prompt)?)
    } else {
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        Ok(s)
    }
}

async fn pair(data_dir: &std::path::Path, json_out: bool, wait: bool) -> anyhow::Result<()> {
    let no_wait = !wait;
    let req = json!({"cmd": "pair", "wait": wait});
    let (mut c, v) = ControlClient::request(data_dir, &req).await?;
    if json_out {
        println!(
            "{}",
            json!({"ok": true, "uri": v["uri"], "expires_at_ms": v["expires_at_ms"], "qr": v["qr"]})
        );
    } else {
        let info: autopilotd::PairingInfo = serde_json::from_value(v)?;
        print_pairing(&info);
        if !no_wait {
            println!("Waiting for the phone...");
        }
    }
    if no_wait {
        return Ok(());
    }
    match c.next().await? {
        Some(ev) if ev["event"] == "paired" => {
            if json_out {
                println!("{ev}");
            } else {
                println!(
                    "Paired with \"{}\". Confirmation code: {}  (must match the phone)",
                    ev["device_name"].as_str().unwrap_or(""),
                    ev["code"].as_str().unwrap_or("")
                );
            }
            Ok(())
        }
        Some(ev) if json_out => {
            println!("{ev}");
            Ok(())
        }
        _ => anyhow::bail!("pairing token expired"),
    }
}

async fn run(
    cfg: AgentConfig,
    settings: DaemonSettings,
    listen: Option<String>,
    relay: Option<String>,
    pair_at_start: bool,
) -> anyhow::Result<()> {
    let data_dir = cfg.data_dir.clone();
    create_private_dir(&data_dir)?;
    let listen = listen
        .or(settings.listen)
        .unwrap_or_else(|| DEFAULT_LISTEN.to_string());
    let relay = relay.or(settings.relay).filter(|r| !r.trim().is_empty());
    let laptop_name = settings.laptop_name.unwrap_or_else(autopilotd::hostname);

    let keys = Arc::new(DeviceKeys::load_or_create(&data_dir.join("device.key"))?);
    let trust = Arc::new(Mutex::new(TrustStore::load(
        &data_dir.join("trusted.json"),
    )?));
    let pairing = Arc::new(PairingManager::new());
    info!(laptop = %laptop_name, %listen, relay = relay.as_deref().unwrap_or("-"), "starting autopilotd");

    let agent = Agent::new(cfg).await?;
    let active = Arc::new(AtomicUsize::new(0));
    let kill_agent = agent.clone();
    let state = Arc::new(DaemonState {
        keys: keys.clone(),
        trust: trust.clone(),
        pairing: pairing.clone(),
        laptop_name: laptop_name.clone(),
        listen: listen.clone(),
        relay: relay.clone(),
        kill: Arc::new(move |reason: &str| kill_agent.kill(reason)),
        active_sessions: active.clone(),
        started: std::time::Instant::now(),
    });
    let _control = control::start(&data_dir, state.clone()).await?;

    let (stx, srx) = mpsc::channel(8);
    tokio::spawn(autopilotd::dispatch_sessions(
        srx,
        agent_handler(agent.clone()),
        active,
    ));
    let server = tokio::spawn(agent_transport::serve(
        ServerConfig {
            listen,
            relay,
            laptop_name,
        },
        keys,
        trust,
        pairing,
        stx,
    ));

    if pair_at_start {
        print_pairing(&state.issue_pairing());
    }

    let mut server = server;
    tokio::select! {
        r = &mut server => match r {
            Ok(Ok(())) => {}
            Ok(Err(e)) => { error!("transport stopped: {e:#}"); agent.kill("daemon shutdown"); return Err(e); }
            Err(e) => { agent.kill("daemon shutdown"); anyhow::bail!("transport task failed: {e}"); }
        },
        _ = shutdown_signal() => info!("shutting down"),
    }
    agent.kill("daemon shutdown");
    server.abort();
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(_) => return std::future::pending().await,
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = term.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
