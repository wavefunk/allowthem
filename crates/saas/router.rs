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
    let host = host_raw.split(':').next().unwrap_or(host_raw).to_lowercase();

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
    let host = match request.headers().get(header::HOST).and_then(|v| v.to_str().ok()) {
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

async fn build_handle(
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
    let full_path = tenant_data_dir.join(&tenant.db_path);

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
            TenantStatus::Suspended => {
                Err(StatusCode::SERVICE_UNAVAILABLE.into_response())
            }
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
        use crate::tenants::TenantId;
        use uuid::Uuid;
        TenantMeta {
            id: TenantId::from(Uuid::nil()),
            status,
            plan_id: vec![],
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
}
