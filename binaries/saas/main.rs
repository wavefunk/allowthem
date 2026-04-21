mod config;

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use eyre::Result;
use tracing_subscriber::EnvFilter;

use allowthem_saas::control_db::ControlDb;
use allowthem_saas::{HandleCache, SlugCache, TenantBuilderConfig};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,allowthem=debug")),
        )
        .init();

    let cfg = config::load().map_err(|e| eyre::eyre!("{e}"))?;
    tracing::info!(listen = %cfg.listen, db = %cfg.control_plane_db, "starting allowthem-saas");

    let mfa_key = decode_hex_key(&cfg.mfa_key_hex)?;
    let signing_key = decode_hex_key(&cfg.signing_key_hex)?;
    let csrf_key = decode_hex_key(&cfg.csrf_key_hex)?;

    let control_pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::from_str(&format!(
            "sqlite:{}?mode=rwc",
            cfg.control_plane_db
        ))?
        .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
        .pragma("foreign_keys", "ON"),
    )
    .await?;
    sqlx::migrate!("../crates/saas/migrations")
        .run(&control_pool)
        .await?;
    let control_db = Arc::new(ControlDb::new(control_pool).await?);

    let handle_cache = HandleCache::new(cfg.cache_max_size);
    let slug_cache = SlugCache::new(cfg.cache_max_size, 300);
    let tenant_data_dir = PathBuf::from(&cfg.tenant_data_dir);

    let tenant_config = Arc::new(TenantBuilderConfig {
        mfa_key,
        signing_key,
        csrf_key,
        base_domain: cfg.base_domain.clone(),
    });

    tracing::info!("startup complete");
    let _ = (
        control_db,
        handle_cache,
        slug_cache,
        tenant_data_dir,
        tenant_config,
    );
    Ok(())
}

fn decode_hex_key(hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex).map_err(|e| eyre::eyre!("invalid hex key: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| eyre::eyre!("key must be exactly 32 bytes"))
}
