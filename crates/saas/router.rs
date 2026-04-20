use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::State;
use axum::http::{Request, StatusCode, header, request::Parts};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use dashmap::DashMap;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePool};

use allowthem_core::AllowThem;

use crate::cache::{HandleCache, SlugCache, TenantMeta};
use crate::control_db::ControlDb;
use crate::error::SaasError;
use crate::tenants::{TenantBuilderConfig, TenantId, TenantStatus};

pub(crate) const RESERVED_SLUGS: &[&str] = &[
    "www",
    "api",
    "admin",
    "auth",
    "manage",
    "oauth",
    "app",
    "dashboard",
    "status",
    "mail",
    "docs",
    "help",
    "support",
    "static",
    "cdn",
    "assets",
    "id",
    "sso",
    "allowthem",
];

pub(crate) fn is_reserved_slug(slug: &str) -> bool {
    RESERVED_SLUGS.contains(&slug)
}

#[derive(Debug, PartialEq)]
pub enum SlugOrRoot {
    Slug(String),
    Root,
}

/// Extract the tenant slug from a Host header value.
///
/// `host_raw` may contain a port (e.g. `"acme.example.com:8080"`). Returns:
/// - `Some(Root)` if host (without port) equals `base_domain` exactly
/// - `Some(Slug(s))` if host is `<s>.<base_domain>` and `s` has no nested dots
/// - `None` for any other host (unknown domain, multi-level subdomain, etc.)
pub fn parse_slug(host_raw: &str, base_domain: &str) -> Option<SlugOrRoot> {
    let host = host_raw
        .split(':')
        .next()
        .unwrap_or(host_raw)
        .to_lowercase();

    if host == base_domain {
        return Some(SlugOrRoot::Root);
    }

    let suffix = format!(".{base_domain}");
    let label = host.strip_suffix(suffix.as_str())?;

    if label.is_empty() || label.contains('.') {
        return None;
    }

    Some(SlugOrRoot::Slug(label.to_owned()))
}

#[derive(Clone)]
pub struct TenantRouterState {
    pub control_db: Arc<ControlDb>,
    pub slug_cache: SlugCache,
    pub handle_cache: HandleCache,
    pub tenant_data_dir: PathBuf,
    pub config: Arc<TenantBuilderConfig>,
    pub seen_times: Arc<DashMap<TenantId, Instant>>,
}

pub async fn tenant_router_middleware(
    State(state): State<TenantRouterState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let host = match request
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h.to_owned(),
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let base_domain = &state.config.base_domain;
    let slug = match parse_slug(&host, base_domain) {
        Some(SlugOrRoot::Slug(s)) => s,
        Some(SlugOrRoot::Root) => return next.run(request).await,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let meta = match state
        .slug_cache
        .get_or_fetch(&slug, || {
            let ctrl = state.control_db.clone();
            let s = slug.clone();
            async move { ctrl.tenant_meta_by_slug(&s).await }
        })
        .await
    {
        Ok(Some(m)) => m,
        Ok(None) => return StatusCode::NOT_FOUND.into_response(),
        Err(e) => {
            tracing::error!(error = %e, slug, "slug cache fetch failed");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if matches!(meta.status, TenantStatus::Deleted) {
        return StatusCode::NOT_FOUND.into_response();
    }

    if matches!(meta.status, TenantStatus::Suspended) {
        request.extensions_mut().insert(meta);
        return next.run(request).await;
    }

    let tenant_id = meta.id;
    let handle = {
        let ctrl = state.control_db.clone();
        let dir = state.tenant_data_dir.clone();
        let cfg = state.config.clone();
        let slug_owned = slug.clone();
        match state
            .handle_cache
            .get_or_init(tenant_id, async move {
                build_handle(ctrl, dir, cfg, tenant_id, &slug_owned).await
            })
            .await
        {
            Ok(h) => h,
            Err(e) => {
                tracing::error!(error = %e, slug = slug.as_str(), "handle cache init failed");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    };

    tracing::debug!(tenant_id = %tenant_id.as_uuid(), slug, "tenant request");

    request.extensions_mut().insert(meta);
    request.extensions_mut().insert(handle);

    debounce_last_seen(&state, tenant_id);

    next.run(request).await
}

pub(crate) async fn build_handle(
    control_db: Arc<ControlDb>,
    tenant_data_dir: PathBuf,
    config: Arc<TenantBuilderConfig>,
    tenant_id: TenantId,
    slug: &str,
) -> Result<AllowThem, SaasError> {
    let tenant = control_db
        .tenant_by_id_raw(tenant_id.as_bytes())
        .await?
        .ok_or(SaasError::TenantNotFound)?;
    build_handle_with_path(&tenant.db_path, &tenant_data_dir, &config, slug).await
}

async fn build_handle_with_path(
    db_file: &str,
    tenant_data_dir: &std::path::Path,
    config: &TenantBuilderConfig,
    slug: &str,
) -> Result<AllowThem, SaasError> {
    let full_path = tenant_data_dir.join(db_file);

    let opts = SqliteConnectOptions::new()
        .filename(&full_path)
        .create_if_missing(false)
        .pragma("foreign_keys", "ON")
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(Duration::from_millis(5000));
    let pool = SqlitePool::connect_with(opts)
        .await
        .map_err(|e| SaasError::ProvisionFailed(e.to_string()))?;

    allowthem_core::AllowThemBuilder::with_pool(pool)
        .mfa_key(config.mfa_key)
        .signing_key(config.signing_key)
        .csrf_key(config.csrf_key)
        .base_url(format!("https://{slug}.{}", config.base_domain))
        .cookie_domain(format!(".{slug}.{}", config.base_domain))
        .build()
        .await
        .map_err(|e| SaasError::ProvisionFailed(e.to_string()))
}

/// Pre-warm the handle cache with the most recently active tenants.
///
/// Called at server startup to avoid cold-cache latency spikes for the first
/// requests to each tenant. Errors per tenant are logged and swallowed so one
/// bad tenant can't block the rest.
pub async fn pre_warm(
    control_db: Arc<ControlDb>,
    cache: &HandleCache,
    tenant_data_dir: PathBuf,
    config: Arc<TenantBuilderConfig>,
    count: i64,
) {
    let ids = match control_db.most_recently_seen_tenants(count).await {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "pre_warm: failed to fetch tenant list");
            return;
        }
    };

    let futs: Vec<_> = ids
        .into_iter()
        .map(|tenant_id| {
            let cache = cache.clone();
            let ctrl = control_db.clone();
            let dir = tenant_data_dir.clone();
            let cfg = config.clone();
            async move {
                let tenant = match ctrl.tenant_by_id_raw(tenant_id.as_bytes()).await {
                    Ok(Some(t)) => t,
                    Ok(None) => {
                        tracing::warn!(
                            tenant_id = %tenant_id.as_uuid(),
                            "pre_warm: tenant not found"
                        );
                        return;
                    }
                    Err(e) => {
                        tracing::warn!(
                            tenant_id = %tenant_id.as_uuid(),
                            error = %e,
                            "pre_warm: fetch failed"
                        );
                        return;
                    }
                };
                let db_file = tenant.db_path.clone();
                let slug = tenant.slug.clone();
                let result = cache
                    .get_or_init(tenant_id, async move {
                        build_handle_with_path(&db_file, &dir, &cfg, &slug).await
                    })
                    .await;
                if let Err(e) = result {
                    tracing::warn!(
                        tenant_id = %tenant_id.as_uuid(),
                        error = %e,
                        "pre_warm: handle init failed"
                    );
                }
            }
        })
        .collect();

    futures::future::join_all(futs).await;
}

pub(crate) fn debounce_last_seen(state: &TenantRouterState, tenant_id: TenantId) {
    const DEBOUNCE: Duration = Duration::from_secs(60);

    let now = Instant::now();
    let last = state.seen_times.get(&tenant_id).map(|v| *v);

    if last.is_some_and(|t| now.duration_since(t) < DEBOUNCE) {
        return;
    }

    state.seen_times.insert(tenant_id, now);

    let ctrl = state.control_db.clone();
    tokio::spawn(async move {
        if let Err(e) = ctrl.touch_last_seen(&tenant_id).await {
            tracing::warn!(error = %e, tenant_id = %tenant_id.as_uuid(), "touch_last_seen failed");
        }
    });
}

/// Extractor that rejects requests for suspended or deleted tenants.
///
/// Returns 503 for suspended tenants, 404 for deleted, and Ok for active tenants
/// or routes without a tenant context (root domain).
#[derive(Debug, Clone)]
pub struct RequireActiveTenant;

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for RequireActiveTenant {
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let Some(meta) = parts.extensions.get::<TenantMeta>() else {
            return Ok(RequireActiveTenant);
        };
        match meta.status {
            TenantStatus::Active => Ok(RequireActiveTenant),
            TenantStatus::Suspended => Err(StatusCode::SERVICE_UNAVAILABLE.into_response()),
            TenantStatus::Deleted => Err(StatusCode::NOT_FOUND.into_response()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::extract::FromRequestParts;
    use axum::http::Request;

    fn base() -> &'static str {
        "example.com"
    }

    #[test]
    fn parse_slug_root_domain_returns_root() {
        assert_eq!(parse_slug("example.com", base()), Some(SlugOrRoot::Root));
    }

    #[test]
    fn parse_slug_subdomain_returns_slug() {
        assert_eq!(
            parse_slug("acme.example.com", base()),
            Some(SlugOrRoot::Slug("acme".into()))
        );
    }

    #[test]
    fn parse_slug_strips_port() {
        assert_eq!(
            parse_slug("acme.example.com:8080", base()),
            Some(SlugOrRoot::Slug("acme".into()))
        );
    }

    #[test]
    fn parse_slug_root_with_port() {
        assert_eq!(
            parse_slug("example.com:443", base()),
            Some(SlugOrRoot::Root)
        );
    }

    #[test]
    fn parse_slug_multi_level_returns_none() {
        assert_eq!(parse_slug("a.b.example.com", base()), None);
    }

    #[test]
    fn parse_slug_unknown_domain_returns_none() {
        assert_eq!(parse_slug("other.io", base()), None);
    }

    #[test]
    fn parse_slug_lowercases_slug() {
        assert_eq!(
            parse_slug("ACME.example.com", base()),
            Some(SlugOrRoot::Slug("acme".into()))
        );
    }

    #[test]
    fn parse_slug_empty_host_returns_none() {
        assert_eq!(parse_slug("", base()), None);
    }

    #[test]
    fn parse_slug_unrelated_subdomain_returns_none() {
        assert_eq!(parse_slug("acme.other.com", base()), None);
    }

    #[test]
    fn parse_slug_does_not_reject_reserved() {
        // Reserved slugs are blocked at provisioning, not at routing time.
        assert_eq!(
            parse_slug("admin.example.com", base()),
            Some(SlugOrRoot::Slug("admin".into()))
        );
    }

    fn make_meta(status: TenantStatus) -> TenantMeta {
        use uuid::Uuid;
        TenantMeta {
            id: TenantId::from(Uuid::nil()),
            status,
            plan_id: vec![],
        }
    }

    async fn make_state() -> TenantRouterState {
        use std::str::FromStr;
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .pragma("foreign_keys", "ON");
        let pool = sqlx::SqlitePool::connect_with(opts).await.unwrap();
        let ctrl = Arc::new(crate::control_db::ControlDb::new(pool).await.unwrap());
        TenantRouterState {
            control_db: ctrl,
            slug_cache: SlugCache::new(10, 60),
            handle_cache: HandleCache::new(10),
            tenant_data_dir: PathBuf::from("/tmp"),
            config: Arc::new(TenantBuilderConfig {
                mfa_key: [0u8; 32],
                signing_key: [0u8; 32],
                csrf_key: [0u8; 32],
                base_domain: "example.com".into(),
            }),
            seen_times: Arc::new(DashMap::new()),
        }
    }

    #[tokio::test]
    async fn extractor_passes_when_no_meta() {
        let (mut parts, _) = Request::new(()).into_parts();
        let result: Result<RequireActiveTenant, _> =
            RequireActiveTenant::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn extractor_passes_when_active() {
        let (mut parts, _) = Request::new(()).into_parts();
        parts.extensions.insert(make_meta(TenantStatus::Active));
        let result: Result<RequireActiveTenant, _> =
            RequireActiveTenant::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn extractor_returns_503_when_suspended() {
        let (mut parts, _) = Request::new(()).into_parts();
        parts.extensions.insert(make_meta(TenantStatus::Suspended));
        let result: Result<RequireActiveTenant, _> =
            RequireActiveTenant::from_request_parts(&mut parts, &()).await;
        let err = result.unwrap_err();
        assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn debounce_inserts_into_seen_times() {
        let state = make_state().await;
        let id = TenantId::from(uuid::Uuid::nil());
        debounce_last_seen(&state, id);
        assert!(state.seen_times.contains_key(&id));
    }

    #[tokio::test]
    async fn debounce_suppresses_rapid_repeat() {
        let state = make_state().await;
        let id = TenantId::from(uuid::Uuid::from_bytes([0x11; 16]));
        debounce_last_seen(&state, id);
        let first_time = *state.seen_times.get(&id).unwrap();
        // Second call within DEBOUNCE window should not update the timestamp.
        debounce_last_seen(&state, id);
        let second_time = *state.seen_times.get(&id).unwrap();
        assert_eq!(first_time, second_time);
    }

    #[tokio::test]
    async fn pre_warm_noop_when_no_active_tenants() {
        let state = make_state().await;
        // Empty DB — most_recently_seen_tenants returns an empty list.
        pre_warm(
            state.control_db.clone(),
            &state.handle_cache,
            state.tenant_data_dir.clone(),
            state.config.clone(),
            10,
        )
        .await;
        // The test passing (no panic, entry_count stays 0) is the assertion.
        assert_eq!(state.handle_cache.entry_count(), 0);
    }

    #[tokio::test]
    async fn pre_warm_swallows_error_for_missing_tenant_db() {
        use uuid::Uuid;
        let state = make_state().await;

        // Insert a tenant row with last_seen_at set so it shows up in pre_warm.
        let plan_row = sqlx::query("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(state.control_db.pool())
            .await
            .unwrap();
        let plan_id: Vec<u8> = sqlx::Row::try_get(&plan_row, "id").unwrap();
        let tid = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path, last_seen_at) \
             VALUES (?1, 'Test', 'pretest', 't@t.com', ?2, 'active', 'pretest.db', datetime('now'))",
        )
        .bind(tid.as_bytes().as_ref())
        .bind(&plan_id)
        .execute(state.control_db.pool())
        .await
        .unwrap();

        // pre_warm should attempt to open pretest.db (which doesn't exist), log the error,
        // and return without panicking.
        pre_warm(
            state.control_db.clone(),
            &state.handle_cache,
            state.tenant_data_dir.clone(),
            state.config.clone(),
            10,
        )
        .await;
    }
}
