use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::response::Json;
use serde::{Deserialize, Serialize};

use allowthem_core::AllowThem;
use allowthem_core::error::AuthError;
use allowthem_core::types::{RoleId, RoleName};

use super::{AdminKey, ManageError, ManageState};

#[derive(Serialize)]
pub struct RoleResponse {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub created_at: String,
}

impl RoleResponse {
    fn from_role(r: &allowthem_core::types::Role) -> Self {
        Self {
            id: r.id.to_string(),
            name: r.name.as_str().to_owned(),
            description: r.description.clone(),
            created_at: r.created_at.to_rfc3339(),
        }
    }
}

#[derive(Deserialize)]
pub struct CreateRoleRequest {
    name: String,
    description: Option<String>,
}

#[derive(Deserialize)]
pub struct PatchRoleRequest {
    name: Option<String>,
    description: Option<String>,
}

fn map_auth_error(e: AuthError) -> ManageError {
    match e {
        AuthError::NotFound => ManageError::NotFound,
        AuthError::Conflict(_) => ManageError::Conflict,
        _ => ManageError::Internal(e.to_string()),
    }
}

fn parse_role_id(s: &str) -> Result<RoleId, ManageError> {
    s.parse().map_err(|_| ManageError::NotFound)
}

async fn list(
    Extension(ath): Extension<AllowThem>,
    _admin: AdminKey,
) -> Result<Json<Vec<RoleResponse>>, ManageError> {
    let roles = ath.db().list_roles().await.map_err(map_auth_error)?;
    Ok(Json(roles.iter().map(RoleResponse::from_role).collect()))
}

async fn create(
    Extension(ath): Extension<AllowThem>,
    _admin: AdminKey,
    Json(req): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<RoleResponse>), ManageError> {
    let name = RoleName::new(&req.name);
    let role = ath
        .db()
        .create_role(&name, req.description.as_deref())
        .await
        .map_err(map_auth_error)?;
    Ok((StatusCode::CREATED, Json(RoleResponse::from_role(&role))))
}

async fn update(
    Extension(ath): Extension<AllowThem>,
    _admin: AdminKey,
    Path(id): Path<String>,
    Json(req): Json<PatchRoleRequest>,
) -> Result<Json<RoleResponse>, ManageError> {
    let rid = parse_role_id(&id)?;

    let current = ath
        .db()
        .get_role(&rid)
        .await
        .map_err(map_auth_error)?
        .ok_or(ManageError::NotFound)?;

    let new_name = req
        .name
        .as_deref()
        .map(RoleName::new)
        .unwrap_or_else(|| current.name.clone());
    let new_description = match req.description {
        Some(ref d) => Some(d.as_str()),
        None => current.description.as_deref(),
    };

    let role = ath
        .db()
        .update_role(&rid, &new_name, new_description)
        .await
        .map_err(map_auth_error)?;
    Ok(Json(RoleResponse::from_role(&role)))
}

async fn delete_role(
    Extension(ath): Extension<AllowThem>,
    _admin: AdminKey,
    Path(id): Path<String>,
) -> Result<StatusCode, ManageError> {
    let rid = parse_role_id(&id)?;
    let deleted = ath.db().delete_role(&rid).await.map_err(map_auth_error)?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ManageError::NotFound)
    }
}

pub fn role_routes() -> axum::Router<ManageState> {
    use axum::routing::{get, patch};
    axum::Router::new()
        .route("/", get(list).post(create))
        .route("/{id}", patch(update).delete(delete_role))
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
    use uuid::Uuid;

    use allowthem_core::{AllowThem, AllowThemBuilder};

    use super::*;
    use crate::api_keys::{ApiKey, ApiKeyId, ApiKeyScope};
    use crate::cache::HandleCache;
    use crate::control_db::ControlDb;
    use crate::manage::ManageState;
    use crate::tenants::{TenantBuilderConfig, TenantId};

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
            .merge(role_routes())
            .layer(axum::Extension(handle))
            .layer(axum::Extension(make_admin_key()))
            .with_state(state)
    }

    #[tokio::test]
    async fn list_roles_returns_empty() {
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
    async fn create_role_returns_201() {
        let h = make_handle().await;
        let app = test_router(h).await;
        let body = serde_json::json!({ "name": "editor" }).to_string();
        let req = Request::post("/")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "editor");
    }

    #[tokio::test]
    async fn create_role_conflict_returns_409() {
        let h = make_handle().await;
        let name = allowthem_core::types::RoleName::new("viewer");
        h.db().create_role(&name, None).await.unwrap();
        let app = test_router(h).await;
        let body = serde_json::json!({ "name": "viewer" }).to_string();
        let req = Request::post("/")
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn patch_role_updates_name() {
        let h = make_handle().await;
        let name = allowthem_core::types::RoleName::new("old");
        let role = h.db().create_role(&name, None).await.unwrap();
        let app = test_router(h).await;
        let body = serde_json::json!({ "name": "new" }).to_string();
        let req = Request::patch(format!("/{}", role.id))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["name"], "new");
    }

    #[tokio::test]
    async fn delete_role_returns_204() {
        let h = make_handle().await;
        let name = allowthem_core::types::RoleName::new("todelete");
        let role = h.db().create_role(&name, None).await.unwrap();
        let app = test_router(h).await;
        let req = Request::delete(format!("/{}", role.id))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn delete_role_not_found_returns_404() {
        let h = make_handle().await;
        let app = test_router(h).await;
        let req = Request::delete(format!("/{}", Uuid::nil()))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
