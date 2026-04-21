use axum::extract::Extension;
use axum::http::StatusCode;
use axum::response::Json;
use serde::{Deserialize, Serialize};

use allowthem_core::AllowThem;
use allowthem_core::error::AuthError;
use allowthem_core::types::PermissionName;

use super::{AdminKey, ManageError, ManageState};

#[derive(Serialize)]
pub struct PermissionResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
}

impl PermissionResponse {
    fn from_permission(p: &allowthem_core::types::Permission) -> Self {
        Self {
            id: p.id.to_string(),
            name: p.name.as_str().to_owned(),
            description: p.description.clone(),
            created_at: p.created_at.to_rfc3339(),
        }
    }
}

#[derive(Deserialize)]
pub struct CreatePermissionRequest {
    name: String,
    description: Option<String>,
}

fn map_auth_error(e: AuthError) -> ManageError {
    match e {
        AuthError::NotFound => ManageError::NotFound,
        AuthError::Conflict(_) => ManageError::Conflict,
        _ => ManageError::Internal(e.to_string()),
    }
}

async fn list(
    Extension(ath): Extension<AllowThem>,
    _admin: AdminKey,
) -> Result<Json<Vec<PermissionResponse>>, ManageError> {
    let perms = ath.db().list_permissions().await.map_err(map_auth_error)?;
    Ok(Json(
        perms
            .iter()
            .map(PermissionResponse::from_permission)
            .collect(),
    ))
}

async fn create(
    Extension(ath): Extension<AllowThem>,
    _admin: AdminKey,
    Json(req): Json<CreatePermissionRequest>,
) -> Result<(StatusCode, Json<PermissionResponse>), ManageError> {
    let name = PermissionName::new(&req.name);
    let perm = ath
        .db()
        .create_permission(&name, req.description.as_deref())
        .await
        .map_err(map_auth_error)?;
    Ok((
        StatusCode::CREATED,
        Json(PermissionResponse::from_permission(&perm)),
    ))
}

pub fn permission_routes() -> axum::Router<ManageState> {
    use axum::routing::get;
    axum::Router::new().route("/", get(list).post(create))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::{Request, StatusCode};
    use chrono::Utc;
    use tower::ServiceExt;

    use allowthem_core::{AllowThem, AllowThemBuilder};

    use super::*;
    use crate::api_keys::{ApiKey, ApiKeyId, ApiKeyScope};
    use crate::cache::HandleCache;
    use crate::control_db::ControlDb;
    use crate::manage::ManageState;
    use crate::tenants::{TenantBuilderConfig, TenantId};
    use uuid::Uuid;

    async fn make_handle() -> AllowThem {
        AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap()
    }

    async fn make_state() -> ManageState {
        use std::str::FromStr;
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .pragma("foreign_keys", "ON");
        let pool = sqlx::SqlitePool::connect_with(opts).await.unwrap();
        let ctrl = Arc::new(ControlDb::new(pool).await.unwrap());
        ManageState::new(
            ctrl,
            HandleCache::new(1),
            PathBuf::from("/tmp"),
            Arc::new(TenantBuilderConfig {
                mfa_key: [0u8; 32],
                signing_key: [0u8; 32],
                csrf_key: [0u8; 32],
                base_domain: "test.example.com".into(),
            }),
            1000,
        )
    }

    fn make_admin_key() -> ApiKey {
        ApiKey {
            id: ApiKeyId::from_uuid(Uuid::nil()),
            tenant_id: TenantId::from(Uuid::nil()),
            name: "test".into(),
            scope: vec![ApiKeyScope::Admin],
            created_at: Utc::now(),
            expires_at: None,
            last_used_at: None,
        }
    }

    async fn test_router(handle: AllowThem) -> Router {
        let state = make_state().await;
        Router::<ManageState>::new()
            .merge(permission_routes())
            .layer(axum::Extension(handle))
            .layer(axum::Extension(make_admin_key()))
            .with_state(state)
    }

    #[tokio::test]
    async fn list_permissions_returns_empty() {
        let h = make_handle().await;
        let app = test_router(h).await;
        let req = Request::get("/").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn create_permission_returns_201() {
        let h = make_handle().await;
        let app = test_router(h).await;
        let body = serde_json::json!({ "name": "read:posts" }).to_string();
        let req = Request::post("/")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "read:posts");
    }

    #[tokio::test]
    async fn create_permission_conflict_returns_409() {
        let h = make_handle().await;
        let name = allowthem_core::types::PermissionName::new("write:posts");
        h.db().create_permission(&name, None).await.unwrap();
        let app = test_router(h).await;
        let body = serde_json::json!({ "name": "write:posts" }).to_string();
        let req = Request::post("/")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }
}
