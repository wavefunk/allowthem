mod cli;
mod config;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use dashmap::DashMap;
use eyre::Result;
use serde::Deserialize;
use tracing_subscriber::EnvFilter;

use allowthem_core::LogEmailSender;
use allowthem_saas::control_db::ControlDb;
use allowthem_saas::{
    HandleCache, ManageState, SlugCache, TenantBuilderConfig, TenantRouterState,
    manage_router, pre_warm, tenant_router_middleware,
};
use allowthem_server::{AllRoutesBuilder, build_default_browser_env};

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

    if let Some(cmd) = cli::parse() {
        return cli::run(cmd, &control_db, &handle_cache, &tenant_config, &cfg).await;
    }

    let router_state = TenantRouterState {
        control_db: control_db.clone(),
        slug_cache,
        handle_cache: handle_cache.clone(),
        tenant_data_dir: tenant_data_dir.clone(),
        config: tenant_config.clone(),
        seen_times: Arc::new(DashMap::new()),
    };
    let manage_state = ManageState::new(
        control_db.clone(),
        handle_cache.clone(),
        tenant_data_dir.clone(),
        tenant_config.clone(),
        60,
    );

    let auth_routes = AllRoutesBuilder::new()
        .templates(build_default_browser_env())
        .is_production(cfg.is_production)
        .base_url(&format!("https://{}", cfg.base_domain))
        .email_sender(Arc::new(LogEmailSender) as Arc<dyn allowthem_core::EmailSender>)
        .mfa_issuer(&cfg.base_domain)
        .all_routes()
        .build_for_saas()
        .map_err(|e| eyre::eyre!("{e}"))?;

    let tenant_routes = auth_routes.layer(axum::middleware::from_fn_with_state(
        router_state,
        tenant_router_middleware,
    ));

    let manage_routes = manage_router(manage_state);

    let base_domain = cfg.base_domain.clone();
    let app = Router::new()
        .nest("/manage/v1", manage_routes)
        .route("/health", get(health))
        .route(
            "/internal/verify-domain",
            get(move |Query(p): Query<VerifyParams>| {
                let base = base_domain.clone();
                async move {
                    if p.domain.ends_with(&format!(".{base}")) || p.domain == base {
                        StatusCode::OK
                    } else {
                        StatusCode::NOT_FOUND
                    }
                }
            }),
        )
        .merge(tenant_routes);

    if cfg.pre_migrate_count > 0 {
        pre_warm(
            control_db,
            &handle_cache,
            tenant_data_dir,
            tenant_config,
            cfg.pre_migrate_count.into(),
        )
        .await;
    }

    let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    tracing::info!("listening on {}", cfg.listen);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

async fn health() -> impl IntoResponse {
    axum::Json(serde_json::json!({"status": "ok"}))
}

#[derive(Deserialize)]
struct VerifyParams {
    domain: String,
}

async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigterm = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("SIGINT handler");
    tokio::select! {
        _ = sigterm.recv() => tracing::info!("SIGTERM received, shutting down"),
        _ = sigint.recv()  => tracing::info!("SIGINT received, shutting down"),
    }
}

fn decode_hex_key(hex: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex).map_err(|e| eyre::eyre!("invalid hex key: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| eyre::eyre!("key must be exactly 32 bytes"))
}

#[cfg(test)]
mod tests {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    use super::{health, VerifyParams};

    #[tokio::test]
    async fn health_returns_ok() {
        let app = Router::new().route("/health", get(health));
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn verify_domain_match() {
        let app = make_verify_app("allowthem.io");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/internal/verify-domain?domain=foo.allowthem.io")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn verify_domain_exact_base() {
        let app = make_verify_app("allowthem.io");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/internal/verify-domain?domain=allowthem.io")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn verify_domain_no_match() {
        let app = make_verify_app("allowthem.io");
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/internal/verify-domain?domain=other.io")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    fn make_verify_app(base: &'static str) -> Router {
        Router::new().route(
            "/internal/verify-domain",
            get(move |axum::extract::Query(p): axum::extract::Query<VerifyParams>| async move {
                if p.domain.ends_with(&format!(".{base}")) || p.domain == base {
                    StatusCode::OK
                } else {
                    StatusCode::NOT_FOUND
                }
            }),
        )
    }
}
