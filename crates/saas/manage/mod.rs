use std::num::NonZeroU32;
use std::path::PathBuf;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{FromRequestParts, State};
use axum::http::{Request, StatusCode, header, request::Parts};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use governor::Quota;
use governor::RateLimiter;
use governor::clock::{DefaultClock, QuantaInstant};
use governor::middleware::NoOpMiddleware;
use governor::state::keyed::DashMapStateStore;
use sha2::{Digest, Sha256};

use crate::api_keys::{ApiKey, ApiKeyScope};
use crate::cache::HandleCache;
use crate::control_db::ControlDb;
use crate::router::build_handle;
use crate::tenants::TenantBuilderConfig;

type KeyedLimiter =
    RateLimiter<Vec<u8>, DashMapStateStore<Vec<u8>>, DefaultClock, NoOpMiddleware<QuantaInstant>>;

#[derive(Debug, thiserror::Error)]
pub enum ManageError {
    #[error("unauthorized")]
    Unauthorized,
    #[error("forbidden")]
    Forbidden,
    #[error("rate limited")]
    RateLimited(u64),
    #[error("tenant not found")]
    TenantNotFound,
    #[error("not found")]
    NotFound,
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for ManageError {
    fn into_response(self) -> Response {
        match self {
            ManageError::Unauthorized => StatusCode::UNAUTHORIZED.into_response(),
            ManageError::Forbidden => StatusCode::FORBIDDEN.into_response(),
            ManageError::RateLimited(retry) => {
                let mut res = StatusCode::TOO_MANY_REQUESTS.into_response();
                if let Ok(val) = axum::http::HeaderValue::from_str(&retry.to_string()) {
                    res.headers_mut().insert("retry-after", val);
                }
                res
            }
            ManageError::TenantNotFound => StatusCode::NOT_FOUND.into_response(),
            ManageError::NotFound => StatusCode::NOT_FOUND.into_response(),
            ManageError::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

#[derive(Clone)]
pub struct ManageRateLimiter {
    inner: Arc<KeyedLimiter>,
}

impl ManageRateLimiter {
    pub fn new(quota: Quota) -> Self {
        Self {
            inner: Arc::new(RateLimiter::keyed(quota)),
        }
    }

    fn check(&self, key_hash: &[u8]) -> Result<(), ManageError> {
        match self.inner.check_key(&key_hash.to_vec()) {
            Ok(_) => Ok(()),
            Err(not_until) => {
                use governor::clock::Clock;
                let wait = not_until.wait_time_from(DefaultClock::default().now());
                Err(ManageError::RateLimited(wait.as_secs().saturating_add(1)))
            }
        }
    }
}

#[derive(Clone)]
pub struct ManageState {
    pub control_db: Arc<ControlDb>,
    pub handle_cache: HandleCache,
    pub tenant_data_dir: PathBuf,
    pub config: Arc<TenantBuilderConfig>,
    pub rate_limiter: ManageRateLimiter,
}

impl ManageState {
    pub fn new(
        control_db: Arc<ControlDb>,
        handle_cache: HandleCache,
        tenant_data_dir: PathBuf,
        config: Arc<TenantBuilderConfig>,
        requests_per_minute: u32,
    ) -> Self {
        let rpm =
            NonZeroU32::new(requests_per_minute).unwrap_or_else(|| NonZeroU32::new(60).unwrap());
        Self {
            control_db,
            handle_cache,
            tenant_data_dir,
            config,
            rate_limiter: ManageRateLimiter::new(Quota::per_minute(rpm)),
        }
    }
}

/// Authenticates the request via `Authorization: Bearer <key>`.
///
/// On success, inserts `ApiKey` and `AllowThem` handle into request extensions.
pub async fn api_key_auth_middleware(
    State(state): State<ManageState>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    let raw_key = match extract_bearer(req.headers()) {
        Some(k) => k,
        None => return ManageError::Unauthorized.into_response(),
    };

    let key_hash = Sha256::digest(raw_key.as_bytes()).to_vec();
    if let Err(e) = state.rate_limiter.check(&key_hash) {
        return e.into_response();
    }

    let api_key = match state.control_db.verify_api_key(&raw_key).await {
        Ok(Some(k)) => k,
        Ok(None) => return ManageError::Unauthorized.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "api key verification failed");
            return ManageError::Internal(e.to_string()).into_response();
        }
    };

    let tenant_id = api_key.tenant_id;
    let slug = match state.control_db.tenant_by_id(&tenant_id).await {
        Ok(Some(t)) => t.slug,
        Ok(None) => return ManageError::TenantNotFound.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "tenant lookup failed");
            return ManageError::Internal(e.to_string()).into_response();
        }
    };

    let ctrl = state.control_db.clone();
    let dir = state.tenant_data_dir.clone();
    let cfg = state.config.clone();
    let handle = match state
        .handle_cache
        .get_or_init(tenant_id, async move {
            build_handle(ctrl, dir, cfg, tenant_id, &slug).await
        })
        .await
    {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, tenant_id = %tenant_id.as_uuid(), "tenant handle init failed");
            return ManageError::TenantNotFound.into_response();
        }
    };

    req.extensions_mut().insert(api_key);
    req.extensions_mut().insert(handle);
    next.run(req).await
}

fn extract_bearer(headers: &axum::http::HeaderMap) -> Option<String> {
    let val = headers.get(header::AUTHORIZATION)?;
    let s = val.to_str().ok()?;
    let token = s.strip_prefix("Bearer ")?;
    if token.is_empty() {
        return None;
    }
    Some(token.to_owned())
}

/// Extracts the `ApiKey` from extensions and requires `Admin` scope.
#[derive(Debug)]
pub struct AdminKey(pub ApiKey);

impl<S: Send + Sync> FromRequestParts<S> for AdminKey {
    type Rejection = ManageError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, ManageError> {
        let key = parts
            .extensions
            .get::<ApiKey>()
            .ok_or(ManageError::Unauthorized)?;
        if !key.scope.contains(&ApiKeyScope::Admin) {
            return Err(ManageError::Forbidden);
        }
        Ok(AdminKey(key.clone()))
    }
}

pub fn manage_router(state: ManageState) -> axum::Router {
    axum::Router::new()
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            api_key_auth_middleware,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;
    use uuid::Uuid;

    use crate::api_keys::ApiKeyScope;
    use crate::tenants::TenantId;

    async fn make_state(rpm: u32) -> ManageState {
        use std::str::FromStr;
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .pragma("foreign_keys", "ON");
        let pool = sqlx::SqlitePool::connect_with(opts).await.unwrap();
        let ctrl = Arc::new(ControlDb::new(pool).await.unwrap());
        ManageState::new(
            ctrl,
            HandleCache::new(10),
            PathBuf::from("/tmp"),
            Arc::new(TenantBuilderConfig {
                mfa_key: [0u8; 32],
                signing_key: [0u8; 32],
                csrf_key: [0u8; 32],
                base_domain: "example.com".into(),
            }),
            rpm,
        )
    }

    fn test_app(state: ManageState) -> Router {
        Router::new()
            .route("/test", get(|| async { StatusCode::OK }))
            .route_layer(axum::middleware::from_fn_with_state(
                state.clone(),
                api_key_auth_middleware,
            ))
            .with_state(state)
    }

    async fn status_of(app: Router, req: Request<Body>) -> StatusCode {
        let resp = app.oneshot(req).await.unwrap();
        resp.status()
    }

    #[tokio::test]
    async fn missing_auth_header_returns_401() {
        let app = test_app(make_state(60).await);
        let req = Request::get("/test").body(Body::empty()).unwrap();
        assert_eq!(status_of(app, req).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn malformed_bearer_returns_401() {
        let app = test_app(make_state(60).await);
        let req = Request::get("/test")
            .header("Authorization", "Basic abc123")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(app, req).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unknown_key_returns_401() {
        let app = test_app(make_state(60).await);
        let req = Request::get("/test")
            .header("Authorization", "Bearer sak_aGVsbG8gd29ybGQ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(app, req).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn rate_limit_triggers_429() {
        // quota of 1 request per minute
        let state = make_state(1).await;
        // First request: passes rate limit, fails at DB (unknown key → 401)
        let app1 = test_app(state.clone());
        let req1 = Request::get("/test")
            .header("Authorization", "Bearer sak_aGVsbG8gd29ybGQ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(app1, req1).await, StatusCode::UNAUTHORIZED);

        // Second request: same key hash, rate limited → 429
        let app2 = test_app(state.clone());
        let req2 = Request::get("/test")
            .header("Authorization", "Bearer sak_aGVsbG8gd29ybGQ")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(app2, req2).await, StatusCode::TOO_MANY_REQUESTS);
    }

    fn make_api_key(scopes: Vec<ApiKeyScope>) -> ApiKey {
        use crate::api_keys::ApiKeyId;
        use chrono::Utc;
        ApiKey {
            id: ApiKeyId::from_uuid(Uuid::nil()),
            tenant_id: TenantId::from(Uuid::nil()),
            name: "test-key".into(),
            scope: scopes,
            created_at: Utc::now(),
            expires_at: None,
            last_used_at: None,
        }
    }

    #[tokio::test]
    async fn admin_key_extractor_passes_admin_scope() {
        let api_key = make_api_key(vec![ApiKeyScope::Admin]);
        let mut req = axum::http::Request::new(());
        req.extensions_mut().insert(api_key);
        let (mut parts, _) = req.into_parts();
        let result = AdminKey::from_request_parts(&mut parts, &()).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn admin_key_extractor_rejects_missing_key() {
        let req = axum::http::Request::new(());
        let (mut parts, _) = req.into_parts();
        let result = AdminKey::from_request_parts(&mut parts, &()).await;
        assert!(matches!(result.unwrap_err(), ManageError::Unauthorized));
    }

}
