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
    DashboardState, HandleCache, HickoryDnsResolver, ManageState, ManagedEmailConfig,
    ManagedEmailSenderFactory, MauSink, SlugCache, TenantBuilderConfig, TenantRouterState,
    WebhookEventSinkFactory, WebhookWorker, WebhookWorkerConfig, manage_router, pre_warm,
    tenant_router_middleware,
};
use allowthem_server::AllRoutesBuilder;
use allowthem_server::login_routes::LoginOverrides;

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
    let mau_sink = Arc::new(MauSink::new(control_db.clone()));

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
        // Kept as a fallback so existing tests / embedded paths that don't
        // wire the factory still see logging output. The factory below
        // takes precedence at handle-build time when both are present.
        event_sink: Some(Arc::new(LoggingEventSink)),
        // Per-tenant factory: every tenant `AllowThem` handle gets a sink
        // bound to its tenant_id. The sink writes events into
        // `webhook_deliveries`; the WebhookWorker spawned below drains that
        // table and POSTs to subscribers.
        event_sink_factory: Some(Arc::new(WebhookEventSinkFactory::new(
            control_db.pool().clone(),
        ))),
        mau_sink: Some(mau_sink.clone()),
        // Per-tenant email factory: when a Postmark token is configured,
        // build a `ManagedEmailSenderFactory` that dispatches between
        // managed (Postmark), SMTP, and webhook modes per the tenant's
        // `allowthem_email_config` row. Without a token, leave the
        // factory unset and rely on the shared `email_sender` (dev path).
        email_sender_factory: cfg.postmark_server_token.as_ref().map(|token| {
            let deployment = ManagedEmailConfig {
                postmark_server_token: token.clone(),
                base_domain: cfg.base_domain.clone(),
                default_from_local_part: cfg.email_default_from_local_part.clone(),
                timeout: std::time::Duration::from_secs(10),
            };
            Arc::new(ManagedEmailSenderFactory::new(
                control_db.clone(),
                deployment,
                mfa_key,
            )) as Arc<dyn allowthem_saas::EmailSenderFactory>
        }),
    });

    // CLI subcommands handle their own dashboard.db open path. Run them before
    // we open the runtime dashboard handle to avoid duplicate locks on the
    // same file when a CLI invocation is short-lived. The pruner spawn below
    // is intentionally placed _after_ this short-circuit so CLI invocations
    // exit cleanly without an orphaned background task.
    if let Some(cmd) = cli::parse() {
        return cli::run(cmd, &control_db, &handle_cache, &tenant_config, &cfg).await;
    }

    // Spawn the daily MAU pruner. The first interval tick fires immediately;
    // skip it so we don't prune at boot when the DB has just opened. The
    // task is detached — graceful shutdown plumbing across binary tasks
    // doesn't exist yet (eua.2 plan §2.6); when it lands, this loop should
    // adopt the same shutdown signal as the axum server.
    {
        let sink = mau_sink.clone();
        let retention = cfg.mau_retention_months;
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(24 * 60 * 60));
            tick.tick().await; // skip the immediate-fire boot tick
            loop {
                tick.tick().await;
                match sink.prune_old_active_users(retention).await {
                    Ok(n) => tracing::info!(
                        retention_months = retention,
                        pruned_rows = n,
                        "MAU pruner: tenant_active_users sweep complete"
                    ),
                    Err(e) => tracing::warn!(
                        error = %e,
                        "MAU pruner: prune_old_active_users failed"
                    ),
                }
            }
        });
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
    let dns_resolver: Arc<dyn allowthem_saas::DnsResolver> =
        Arc::new(HickoryDnsResolver::new().map_err(|e| eyre::eyre!("{e}"))?);
    let manage_state = ManageState::new(
        control_db.clone(),
        handle_cache.clone(),
        tenant_data_dir.clone(),
        tenant_config.clone(),
        60,
        dns_resolver.clone(),
    );

    // Spawn the hourly domain verification sweep. Mirrors the MAU pruner
    // pattern: skip the immediate-fire tick so we don't hit DNS at boot.
    // Graceful shutdown is not yet wired (eua.2 plan §2.6).
    {
        let sweep_resolver = dns_resolver.clone();
        let sweep_db = control_db.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60 * 60));
            tick.tick().await; // skip the immediate-fire boot tick
            loop {
                tick.tick().await;
                match allowthem_saas::dns::run_one_sweep(sweep_resolver.as_ref(), &sweep_db, 100)
                    .await
                {
                    Ok(stats) => tracing::info!(
                        processed = stats.processed,
                        verified = stats.verified,
                        failed = stats.failed,
                        "domain sweep complete"
                    ),
                    Err(e) => tracing::warn!(error = %e, "domain sweep failed"),
                }
            }
        });
    }

    let auth_routes = AllRoutesBuilder::new()
        .is_production(cfg.is_production)
        .base_url(format!("https://{}", cfg.base_domain))
        .mfa_issuer(&cfg.base_domain)
        .oauth_providers(std::collections::HashMap::new())
        .login_overrides(LoginOverrides {
            signup_url: Some("/signup".to_owned()),
            terms_url: None,
            privacy_url: None,
        })
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
        dns_resolver,
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
        .merge(dashboard_pages)
        .fallback(|| async {
            let html = allowthem_server::render_error_page(
                "Not found",
                "The page you are looking for could not be found.",
            );
            (StatusCode::NOT_FOUND, axum::response::Html(html))
        });

    if cfg.pre_migrate_count > 0 {
        pre_warm(
            control_db.clone(),
            &handle_cache,
            tenant_data_dir,
            tenant_config,
            cfg.pre_migrate_count.into(),
        )
        .await;
    }

    // Background webhook delivery worker. Drains `webhook_deliveries` rows
    // produced by the per-tenant `WebhookEventSink`. Lifetime is bounded by
    // the watch channel below — `axum::serve`'s `with_graceful_shutdown`
    // listens on the same `shutdown_signal()` future, so the worker exits
    // shortly after axum starts draining.
    let (webhook_shutdown_tx, webhook_shutdown_rx) = tokio::sync::watch::channel(false);
    let webhook_worker =
        WebhookWorker::new(control_db.pool().clone(), WebhookWorkerConfig::default());
    let webhook_handle = tokio::spawn(async move {
        webhook_worker.run(webhook_shutdown_rx).await;
    });

    let listener = tokio::net::TcpListener::bind(cfg.listen).await?;
    tracing::info!("listening on {}", cfg.listen);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    // Axum has accepted the shutdown signal — tell the worker to stop and
    // join, so we don't leave an orphaned task during the process tear-down.
    let _ = webhook_shutdown_tx.send(true);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), webhook_handle).await;

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
