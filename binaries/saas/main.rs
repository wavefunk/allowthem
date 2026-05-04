mod cli;
mod config;
mod dashboard;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use axum::Router;
use axum::extract::Query;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use dashmap::DashMap;
use eyre::Result;
use serde::Deserialize;
use tracing_subscriber::EnvFilter;

use allowthem_core::{LogEmailSender, LoggingEventSink};
use allowthem_saas::control_db::ControlDb;
use allowthem_saas::{
    DashboardState, HandleCache, ManageState, SlugCache, TenantBuilderConfig, TenantRouterState,
    manage_router, pre_warm, tenant_router_middleware,
};
use allowthem_server::{AllRoutesBuilder, build_default_browser_env};

use crate::dashboard::quickstart::quickstart_routes;
use crate::dashboard::signup::signup_routes;
use crate::dashboard::{QuickstartCache, SignupState, build_dashboard_env};

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

    // One `Arc<dyn EmailSender>` instance shared across tenant handles,
    // SignupState, and DashboardRouterState (via `from_signup`). Keeps log
    // output and any future swap-in (SMTP, SES) consistent across surfaces.
    let email_sender: Arc<dyn allowthem_core::EmailSender> = Arc::new(LogEmailSender);

    let tenant_config = Arc::new(TenantBuilderConfig {
        mfa_key,
        signing_key,
        csrf_key,
        base_domain: cfg.base_domain.clone(),
        is_production: cfg.is_production,
        email_sender: Some(email_sender.clone()),
        event_sink: Some(Arc::new(LoggingEventSink)),
        mau_sink: None,
    });

    // CLI subcommands handle their own dashboard.db open path. Run them before
    // we open the runtime dashboard handle to avoid duplicate locks on the
    // same file when a CLI invocation is short-lived.
    if let Some(cmd) = cli::parse() {
        return cli::run(cmd, &control_db, &handle_cache, &tenant_config, &cfg).await;
    }

    // Open dashboard.db (create + migrate). Held in DashboardState for the
    // life of the process — not in HandleCache.
    let dashboard_ath = dashboard::open_dashboard_handle(
        &tenant_data_dir,
        &cfg.base_domain,
        cfg.is_production,
        mfa_key,
        signing_key,
        csrf_key,
    )
    .await?;

    let dashboard_state = DashboardState {
        ath: dashboard_ath.clone(),
        control_db: control_db.clone(),
        tenant_data_dir: tenant_data_dir.clone(),
        tenant_config: tenant_config.clone(),
        handle_cache: handle_cache.clone(),
        is_production: cfg.is_production,
    };

    let router_state = TenantRouterState {
        control_db: control_db.clone(),
        slug_cache: slug_cache.clone(),
        handle_cache: handle_cache.clone(),
        tenant_data_dir: tenant_data_dir.clone(),
        config: tenant_config.clone(),
        seen_times: Arc::new(DashMap::new()),
        dashboard_handle: Some(dashboard_ath),
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
        .base_url(format!("https://{}", cfg.base_domain))
        .mfa_issuer(&cfg.base_domain)
        .all_routes()
        .build_for_saas()
        .map_err(|e| eyre::eyre!("{e}"))?;

    let auth_with_middleware = auth_routes.layer(axum::middleware::from_fn_with_state(
        router_state.clone(),
        tenant_router_middleware,
    ));

    // Dashboard onboarding (signup + quickstart) and other dashboard pages
    // (99c.3..99c.6). Both go through the same tenant_router_middleware so
    // the dashboard handle lands in extensions on root-domain requests for
    // the shared `csrf_middleware` + handlers.
    let signup_state = SignupState {
        ath: dashboard_state.ath.clone(),
        control_db: control_db.clone(),
        tenant_data_dir: tenant_data_dir.clone(),
        tenant_config: tenant_config.clone(),
        handle_cache: handle_cache.clone(),
        quickstart_cache: QuickstartCache::new(),
        base_domain: cfg.base_domain.clone(),
        templates: build_dashboard_env(),
        email_sender: email_sender.clone(),
        is_production: cfg.is_production,
    };

    let onboarding_routes =
        signup_routes(signup_state.clone()).merge(quickstart_routes(signup_state.clone()));

    let onboarding_with_middleware = onboarding_routes.layer(axum::middleware::from_fn_with_state(
        router_state.clone(),
        tenant_router_middleware,
    ));

    let dashboard_router_state = dashboard::state::DashboardRouterState::from_signup(
        signup_state.clone(),
        slug_cache.clone(),
    );
    let dashboard_pages = dashboard::dashboard_pages_router(dashboard_router_state).layer(
        axum::middleware::from_fn_with_state(router_state, tenant_router_middleware),
    );

    let manage_routes = manage_router(manage_state);

    // `DashboardState` (the synchronous-CLI shape) is no longer needed
    // separately for the runtime path; sub-task 99c.6's super-admin work
    // may revive it. Hold the binding alive in case a future call site
    // wants it without a re-construction.
    let _dashboard_state = dashboard_state;

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
        .merge(auth_with_middleware)
        .merge(onboarding_with_middleware)
        .merge(dashboard_pages);

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
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use tower::ServiceExt;

    use super::{VerifyParams, health};

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
            get(
                move |axum::extract::Query(p): axum::extract::Query<VerifyParams>| async move {
                    if p.domain.ends_with(&format!(".{base}")) || p.domain == base {
                        StatusCode::OK
                    } else {
                        StatusCode::NOT_FOUND
                    }
                },
            ),
        )
    }
}
