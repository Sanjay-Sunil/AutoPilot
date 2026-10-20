//! Optional Postgres device registry (spec section 11). v1 follow-up: pairing tokens, device list,
//! revocation, passkeys, push tokens. The relay never depends on it.

use sqlx::postgres::{PgPool, PgPoolOptions};

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub async fn connect_and_migrate(url: &str) -> anyhow::Result<PgPool> {
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(url)
        .await?;
    MIGRATOR.run(&pool).await?;
    Ok(pool)
}
