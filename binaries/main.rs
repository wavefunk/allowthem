mod config;
mod state;

use std::sync::Arc;

use axum::{Router, response::IntoResponse, routing::get};
use chrono::Duration;
use eyre::Result;
use tracing_subscriber::EnvFilter;

use allowthem_core::{AllowThemBuilder, AuthClient, EmbeddedAuthClient};

use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,allowthem=debug")),
        )
        .init();

    // 2. Config
    let config = config::load()?;
    tracing::info!(bind = %config.bind, db = %config.database_url, "starting allowthem");

    // 3. MFA key
    let mfa_key: Option<[u8; 32]> = match &config.mfa_key_hex {
        Some(hex) => Some(decode_mfa_key(hex)?),
        None => None,
    };

    // 4. AllowThem handle
    let mut builder = AllowThemBuilder::new(&config.database_url)
        .session_ttl(Duration::hours(config.session_ttl_hours as i64))
        .cookie_secure(config.cookie_secure)
        .cookie_domain(&config.cookie_domain);
    if let Some(key) = mfa_key {
        builder = builder.mfa_key(key);
    }
    let ath = builder.build().await?;

    // 5. App state
    let auth_client: Arc<dyn AuthClient> =
        Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
    let state = AppState {
        ath,
        auth_client,
        base_url: config.base_url.clone(),
    };

    // 6. Router
    let app = Router::new()
        .route("/health", get(health))
        .with_state(state);

    // 7. Serve
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!("listening on {}", config.bind);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn health() -> impl IntoResponse {
    axum::Json(serde_json::json!({"status": "ok"}))
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install ctrl-c handler");
    tracing::info!("shutdown signal received");
}

fn decode_mfa_key(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        eyre::bail!(
            "mfa_key_hex must be 64 hex chars (32 bytes), got {} chars",
            hex.len()
        );
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| eyre::eyre!("invalid mfa_key_hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| eyre::eyre!("mfa_key_hex decode failed"))
}
