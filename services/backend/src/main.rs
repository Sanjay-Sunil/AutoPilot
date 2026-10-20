use backend::{AppState, Config};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    let cfg = Config::from_env();
    #[allow(unused_mut)]
    let mut state = AppState::new(&cfg);

    match &cfg.database_url {
        #[cfg(feature = "db")]
        Some(url) => {
            backend::db::connect_and_migrate(url).await?;
            state.db_enabled = true;
            tracing::info!("database connected, migrations applied");
        }
        #[cfg(not(feature = "db"))]
        Some(_) => tracing::warn!("DATABASE_URL set but built without the `db` feature; ignoring"),
        None => tracing::info!("no DATABASE_URL: running relay only"),
    }

    backend::serve(cfg, state).await
}
