//! AutoPilot backend.
//!
//! v1 scope: a *blind* WebSocket relay (`/relay/{room}`) that pipes Noise ciphertext between one
//! laptop and one phone, plus `/health`. The relay never parses, stores, or logs frame contents.
//! The device registry / pairing / passkeys (spec section 11) live behind the `db` feature and are
//! optional: without `DATABASE_URL` the relay runs stateless.

pub mod config;
#[cfg(feature = "db")]
pub mod db;
pub mod ratelimit;
pub mod relay;

use axum::{Json, Router, routing::get};
use std::sync::Arc;

pub use config::Config;
pub use relay::RelayState;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub relay: Arc<RelayState>,
    pub db_enabled: bool,
}

impl AppState {
    pub fn new(cfg: &Config) -> Self {
        Self {
            relay: Arc::new(RelayState::new(cfg)),
            db_enabled: false,
        }
    }
}

async fn health(
    axum::extract::State(st): axum::extract::State<AppState>,
) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
        "rooms": st.relay.room_count(),
        "db": st.db_enabled,
    }))
}

/// Build the HTTP router. Serve it with `into_make_service_with_connect_info::<SocketAddr>()` so
/// the per-IP rate limiter can see the peer address.
pub fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/relay/{room}", get(relay::ws_handler))
        .with_state(state)
}

/// Bind and serve until ctrl-c / SIGTERM.
pub async fn serve(cfg: Config, state: AppState) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    tracing::info!(addr = %listener.local_addr()?, "backend listening");
    axum::serve(
        listener,
        app(state).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! { _ = ctrl_c => {}, _ = term => {} }
    tracing::info!("shutting down");
}
