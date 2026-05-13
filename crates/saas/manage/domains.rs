use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::domains::{DomainId, DomainStatus, TenantDomain, normalize_domain};
use crate::error::SaasError;

use super::{AdminKey, ManageError, ManageState};

// ── Response ──────────────────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct DomainResponse {
    pub id: String,
    pub tenant_id: String,
    pub domain: String,
    pub status: DomainStatus,
    pub dns_target: String,
    pub verified_at: Option<String>,
    pub last_error: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl DomainResponse {
    fn from_row(row: &TenantDomain) -> Self {
        let id = Uuid::from_slice(&row.id)
            .map(|u| u.to_string())
            .unwrap_or_default();
        let tenant_id = Uuid::from_slice(&row.tenant_id)
            .map(|u| u.to_string())
            .unwrap_or_default();
        Self {
            id,
            tenant_id,
            domain: row.domain.clone(),
            status: row.status,
            dns_target: row.dns_target.clone(),
            verified_at: row.verified_at.map(|t| t.to_rfc3339()),
            last_error: row.last_error.clone(),
            created_at: row.created_at.to_rfc3339(),
            updated_at: row.updated_at.to_rfc3339(),
        }
    }
}

// ── Error mapping ─────────────────────────────────────────────────────────────

fn map_saas_error(e: SaasError) -> ManageError {
    match e {
        SaasError::DomainAlreadyExists => ManageError::Conflict,
        SaasError::DomainNotFound => ManageError::NotFound,
        SaasError::DomainInvalid(msg) => ManageError::InvalidRequest(msg.to_string()),
        other => ManageError::Internal(other.to_string()),
    }
}

fn parse_domain_id(s: &str) -> Result<DomainId, ManageError> {
    s.parse::<Uuid>()
        .map(DomainId::from)
        .map_err(|_| ManageError::NotFound)
}

// ── Handlers ──────────────────────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct RegisterDomainRequest {
    domain: String,
}

async fn register_domain(
    State(state): State<ManageState>,
    admin: AdminKey,
    Json(req): Json<RegisterDomainRequest>,
) -> Result<(StatusCode, Json<DomainResponse>), ManageError> {
    let tenant_id = admin.0.tenant_id;
    let domain =
        normalize_domain(&req.domain, &state.config.base_domain).map_err(map_saas_error)?;
    let dns_target = format!("custom.{}", state.config.base_domain);
    let row = state
        .control_db
        .create_tenant_domain(&tenant_id, &domain, &dns_target)
        .await
        .map_err(map_saas_error)?;
    Ok((StatusCode::CREATED, Json(DomainResponse::from_row(&row))))
}

async fn list_domains(
    State(state): State<ManageState>,
    admin: AdminKey,
) -> Result<Json<Vec<DomainResponse>>, ManageError> {
    let tenant_id = admin.0.tenant_id;
    let rows = state
        .control_db
        .list_tenant_domains(&tenant_id)
        .await
        .map_err(map_saas_error)?;
    Ok(Json(rows.iter().map(DomainResponse::from_row).collect()))
}

async fn verify_domain_handler(
    State(state): State<ManageState>,
    admin: AdminKey,
    Path(id): Path<String>,
) -> Result<Json<DomainResponse>, ManageError> {
    let tenant_id = admin.0.tenant_id;
    let domain_id = parse_domain_id(&id)?;

    let row = state
        .control_db
        .get_tenant_domain_scoped(&domain_id, &tenant_id)
        .await
        .map_err(map_saas_error)?
        .ok_or(ManageError::NotFound)?;

    crate::dns::verify_domain(
        state.dns_resolver.as_ref(),
        &state.control_db,
        domain_id,
        tenant_id,
        &row.domain,
        &row.dns_target,
    )
    .await
    .map_err(map_saas_error)?;

    // Re-fetch to return the updated status.
    let updated = state
        .control_db
        .get_tenant_domain_scoped(&domain_id, &tenant_id)
        .await
        .map_err(map_saas_error)?
        .ok_or(ManageError::NotFound)?;

    Ok(Json(DomainResponse::from_row(&updated)))
}

async fn delete_domain(
    State(state): State<ManageState>,
    admin: AdminKey,
    Path(id): Path<String>,
) -> Result<StatusCode, ManageError> {
    let tenant_id = admin.0.tenant_id;
    let domain_id = parse_domain_id(&id)?;
    let deleted = state
        .control_db
        .delete_tenant_domain_scoped(&domain_id, &tenant_id)
        .await
        .map_err(map_saas_error)?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ManageError::NotFound)
    }
}

// ── Router ────────────────────────────────────────────────────────────────────

pub fn domain_routes() -> axum::Router<ManageState> {
    use axum::routing::{delete, get, post};
    axum::Router::new()
        .route("/", get(list_domains).post(register_domain))
        .route("/{id}/verify", post(verify_domain_handler))
        .route("/{id}", delete(delete_domain))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use tower::ServiceExt;
    use uuid::Uuid;

    use super::*;
    use crate::api_keys::{ApiKey, ApiKeyId, ApiKeyScope};
    use crate::cache::HandleCache;
    use crate::control_db::ControlDb;
    use crate::dns::MockDnsResolver;
    use crate::manage::ManageState;
    use crate::tenants::{TenantBuilderConfig, TenantId};

    // ── Helpers ───────────────────────────────────────────────────────────────

    async fn make_ctrl() -> Arc<ControlDb> {
        use std::str::FromStr;
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .pragma("foreign_keys", "ON");
        let pool = sqlx::SqlitePool::connect_with(opts).await.unwrap();
        Arc::new(ControlDb::new(pool).await.unwrap())
    }

    /// Insert a tenant row matching the Uuid::nil() ID used by `make_admin_key`.
    async fn seed_tenant(ctrl: &ControlDb) {
        let nil_bytes = Uuid::nil().as_bytes().to_vec();
        let plan_id: Vec<u8> = sqlx::query_scalar("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(ctrl.pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT OR IGNORE INTO tenants \
             (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'Test', 'test', 'test@example.com', ?, 'active', 'test.db')",
        )
        .bind(&nil_bytes)
        .bind(&plan_id)
        .execute(ctrl.pool())
        .await
        .unwrap();
    }

    fn make_tenant_id() -> TenantId {
        TenantId::from(Uuid::nil())
    }

    fn make_admin_key() -> ApiKey {
        ApiKey {
            id: ApiKeyId::from_uuid(Uuid::nil()),
            tenant_id: make_tenant_id(),
            name: "test".into(),
            scope: vec![ApiKeyScope::Admin],
            created_at: Utc::now(),
            expires_at: None,
            last_used_at: None,
        }
    }

    fn make_state(ctrl: Arc<ControlDb>, resolver: Arc<dyn crate::dns::DnsResolver>) -> ManageState {
        ManageState::new(
            ctrl,
            HandleCache::new(1),
            PathBuf::from("/tmp"),
            Arc::new(TenantBuilderConfig {
                mfa_key: [0u8; 32],
                signing_key: [0u8; 32],
                csrf_key: [0u8; 32],
                base_domain: "test.example.com".into(),
                is_production: false,
                email_sender: None,
                event_sink: None,
                event_sink_factory: None,
                mau_sink: None,
                email_sender_factory: None,
            }),
            1000,
            resolver,
        )
    }

    fn test_router(state: ManageState) -> Router {
        Router::<ManageState>::new()
            .merge(domain_routes())
            .layer(axum::Extension(make_admin_key()))
            .with_state(state)
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn list_domains_returns_empty() {
        let ctrl = make_ctrl().await;
        seed_tenant(&ctrl).await;
        let resolver = Arc::new(MockDnsResolver::new());
        let app = test_router(make_state(ctrl, resolver));
        let req = Request::get("/").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn register_domain_returns_201() {
        let ctrl = make_ctrl().await;
        seed_tenant(&ctrl).await;
        let resolver = Arc::new(MockDnsResolver::new());
        let app = test_router(make_state(ctrl, resolver));
        let body = serde_json::json!({ "domain": "auth.myapp.io" }).to_string();
        let req = Request::post("/")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["domain"], "auth.myapp.io");
        assert_eq!(json["status"], "pending_verification");
        assert_eq!(json["dns_target"], "custom.test.example.com");
    }

    #[tokio::test]
    async fn register_domain_conflict_returns_409() {
        let ctrl = make_ctrl().await;
        seed_tenant(&ctrl).await;
        ctrl.create_tenant_domain(
            &make_tenant_id(),
            "auth.myapp.io",
            "custom.test.example.com",
        )
        .await
        .unwrap();
        let resolver = Arc::new(MockDnsResolver::new());
        let app = test_router(make_state(ctrl, resolver));
        let body = serde_json::json!({ "domain": "auth.myapp.io" }).to_string();
        let req = Request::post("/")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn register_domain_invalid_returns_400() {
        let ctrl = make_ctrl().await;
        seed_tenant(&ctrl).await;
        let resolver = Arc::new(MockDnsResolver::new());
        let app = test_router(make_state(ctrl, resolver));
        let body = serde_json::json!({ "domain": "not a domain!!" }).to_string();
        let req = Request::post("/")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn register_domain_base_domain_rejected_returns_400() {
        let ctrl = make_ctrl().await;
        seed_tenant(&ctrl).await;
        let resolver = Arc::new(MockDnsResolver::new());
        let app = test_router(make_state(ctrl, resolver));
        // test.example.com is the base_domain — must be rejected.
        let body = serde_json::json!({ "domain": "test.example.com" }).to_string();
        let req = Request::post("/")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn verify_domain_returns_verified_when_cname_matches() {
        let ctrl = make_ctrl().await;
        seed_tenant(&ctrl).await;
        let row = ctrl
            .create_tenant_domain(
                &make_tenant_id(),
                "auth.myapp.io",
                "custom.test.example.com",
            )
            .await
            .unwrap();
        let domain_id_uuid = Uuid::from_slice(&row.id).unwrap();

        let mock = Arc::new(MockDnsResolver::new());
        mock.queue("auth.myapp.io", Ok(vec!["custom.test.example.com".into()]))
            .await;

        let app = test_router(make_state(ctrl, mock as Arc<dyn crate::dns::DnsResolver>));
        let req = Request::post(format!("/{domain_id_uuid}/verify"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "verified");
    }

    #[tokio::test]
    async fn verify_domain_returns_failed_when_cname_mismatches() {
        let ctrl = make_ctrl().await;
        seed_tenant(&ctrl).await;
        let row = ctrl
            .create_tenant_domain(
                &make_tenant_id(),
                "auth.myapp.io",
                "custom.test.example.com",
            )
            .await
            .unwrap();
        let domain_id_uuid = Uuid::from_slice(&row.id).unwrap();

        let mock = Arc::new(MockDnsResolver::new());
        mock.queue("auth.myapp.io", Ok(vec!["wrong.provider.net".into()]))
            .await;

        let app = test_router(make_state(ctrl, mock as Arc<dyn crate::dns::DnsResolver>));
        let req = Request::post(format!("/{domain_id_uuid}/verify"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "failed");
        assert!(!json["last_error"].is_null());
    }

    #[tokio::test]
    async fn verify_domain_not_found_returns_404() {
        let ctrl = make_ctrl().await;
        seed_tenant(&ctrl).await;
        let resolver = Arc::new(MockDnsResolver::new());
        let app = test_router(make_state(ctrl, resolver));
        let req = Request::post(format!("/{}/verify", Uuid::new_v4()))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn delete_domain_returns_204() {
        let ctrl = make_ctrl().await;
        seed_tenant(&ctrl).await;
        let row = ctrl
            .create_tenant_domain(
                &make_tenant_id(),
                "auth.myapp.io",
                "custom.test.example.com",
            )
            .await
            .unwrap();
        let domain_id_uuid = Uuid::from_slice(&row.id).unwrap();
        let resolver = Arc::new(MockDnsResolver::new());
        let app = test_router(make_state(ctrl, resolver));
        let req = Request::delete(format!("/{domain_id_uuid}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn delete_domain_not_found_returns_404() {
        let ctrl = make_ctrl().await;
        seed_tenant(&ctrl).await;
        let resolver = Arc::new(MockDnsResolver::new());
        let app = test_router(make_state(ctrl, resolver));
        let req = Request::delete(format!("/{}", Uuid::new_v4()))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn register_lowercases_input() {
        let ctrl = make_ctrl().await;
        seed_tenant(&ctrl).await;
        let resolver = Arc::new(MockDnsResolver::new());
        let app = test_router(make_state(ctrl, resolver));
        let body = serde_json::json!({ "domain": "Auth.MYAPP.IO" }).to_string();
        let req = Request::post("/")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["domain"], "auth.myapp.io");
    }

    #[tokio::test]
    async fn list_returns_only_calling_tenants_domains() {
        let ctrl = make_ctrl().await;
        seed_tenant(&ctrl).await;

        // Seed a second tenant directly.
        let other_id = Uuid::new_v4();
        let plan_id: Vec<u8> = sqlx::query_scalar("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(ctrl.pool())
            .await
            .unwrap();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'Other', 'other', 'other@example.com', ?, 'active', 'other.db')",
        )
        .bind(other_id.as_bytes().as_ref())
        .bind(&plan_id)
        .execute(ctrl.pool())
        .await
        .unwrap();

        // Domain belonging to the other tenant.
        ctrl.create_tenant_domain(
            &TenantId::from(other_id),
            "other.domain.com",
            "custom.test.example.com",
        )
        .await
        .unwrap();

        // Domain belonging to the API key's tenant (nil UUID).
        ctrl.create_tenant_domain(
            &make_tenant_id(),
            "mine.domain.com",
            "custom.test.example.com",
        )
        .await
        .unwrap();

        let resolver = Arc::new(MockDnsResolver::new());
        let app = test_router(make_state(ctrl, resolver));
        let req = Request::get("/").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let arr = json.as_array().unwrap();
        assert_eq!(
            arr.len(),
            1,
            "list must only return the calling tenant's domains"
        );
        assert_eq!(arr[0]["domain"], "mine.domain.com");
    }
}
