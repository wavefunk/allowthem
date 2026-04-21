use std::collections::HashSet;

use axum::extract::{Extension, Path, Query};
use axum::http::StatusCode;
use axum::response::Json;
use serde::{Deserialize, Serialize};

use allowthem_core::AllowThem;
use allowthem_core::error::AuthError;
use allowthem_core::types::{RoleId, UserId};
use allowthem_core::users::UserCursor;

use super::{AdminKey, ListResponse, ManageError, ManageState};

#[derive(Serialize)]
pub struct UserResponse {
    pub id: String,
    pub email: String,
    pub username: Option<String>,
    pub email_verified: bool,
    pub is_active: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl UserResponse {
    fn from_user(u: &allowthem_core::types::User) -> Self {
        Self {
            id: u.id.to_string(),
            email: u.email.as_str().to_owned(),
            username: u.username.as_ref().map(|n| n.as_str().to_owned()),
            email_verified: u.email_verified,
            is_active: u.is_active,
            created_at: u.created_at.to_rfc3339(),
            updated_at: u.updated_at.to_rfc3339(),
        }
    }
}

#[derive(Deserialize)]
pub struct ListUsersQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Deserialize)]
pub struct PatchUserRequest {
    is_active: Option<bool>,
    role_ids: Option<Vec<String>>,
}

fn map_auth_error(e: AuthError) -> ManageError {
    match e {
        AuthError::NotFound => ManageError::NotFound,
        AuthError::Conflict(_) => ManageError::Conflict,
        _ => ManageError::Internal(e.to_string()),
    }
}

fn parse_user_id(s: &str) -> Result<UserId, ManageError> {
    s.parse().map_err(|_| ManageError::NotFound)
}

async fn list(
    Extension(ath): Extension<AllowThem>,
    _admin: AdminKey,
    Query(q): Query<ListUsersQuery>,
) -> Result<Json<ListResponse<UserResponse>>, ManageError> {
    let limit = q.limit.unwrap_or(50).min(200);
    let cursor: Option<UserCursor> = q
        .cursor
        .as_deref()
        .map(|s| {
            UserCursor::decode(s)
                .ok_or_else(|| ManageError::InvalidRequest("invalid cursor".into()))
        })
        .transpose()?;

    let mut entries = ath
        .db()
        .list_users_paginated(limit + 1, cursor.as_ref())
        .await
        .map_err(map_auth_error)?;

    let has_more = entries.len() > limit as usize;
    if has_more {
        entries.pop();
    }

    let next_cursor = if has_more {
        entries.last().map(|e| UserCursor::from_entry(e).encode())
    } else {
        None
    };

    let items = entries
        .iter()
        .map(|e| UserResponse {
            id: e.id.to_string(),
            email: e.email.as_str().to_owned(),
            username: e.username.as_ref().map(|n| n.as_str().to_owned()),
            email_verified: false,
            is_active: e.is_active,
            created_at: e.created_at.to_rfc3339(),
            updated_at: e.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(ListResponse { items, next_cursor }))
}

async fn get_one(
    Extension(ath): Extension<AllowThem>,
    _admin: AdminKey,
    Path(id): Path<String>,
) -> Result<Json<UserResponse>, ManageError> {
    let uid = parse_user_id(&id)?;
    let user = ath.db().get_user(uid).await.map_err(map_auth_error)?;
    Ok(Json(UserResponse::from_user(&user)))
}

async fn update(
    Extension(ath): Extension<AllowThem>,
    _admin: AdminKey,
    Path(id): Path<String>,
    Json(req): Json<PatchUserRequest>,
) -> Result<Json<UserResponse>, ManageError> {
    let uid = parse_user_id(&id)?;

    if let Some(is_active) = req.is_active {
        ath.db()
            .update_user_active(uid, is_active)
            .await
            .map_err(map_auth_error)?;
    }

    if let Some(role_ids) = req.role_ids {
        let requested: Vec<RoleId> = role_ids
            .iter()
            .map(|s| {
                s.parse()
                    .map_err(|_| ManageError::InvalidRequest(format!("invalid role_id: {s}")))
            })
            .collect::<Result<_, _>>()?;

        let current = ath
            .db()
            .get_user_roles(&uid)
            .await
            .map_err(map_auth_error)?;
        let current_ids: HashSet<RoleId> = current.into_iter().map(|r| r.id).collect();
        let requested_ids: HashSet<RoleId> = requested.into_iter().collect();

        for &id in requested_ids.difference(&current_ids) {
            ath.db()
                .assign_role(&uid, &id)
                .await
                .map_err(map_auth_error)?;
        }
        for &id in current_ids.difference(&requested_ids) {
            ath.db()
                .unassign_role(&uid, &id)
                .await
                .map_err(map_auth_error)?;
        }
    }

    let user = ath.db().get_user(uid).await.map_err(map_auth_error)?;
    Ok(Json(UserResponse::from_user(&user)))
}

async fn delete_user(
    Extension(ath): Extension<AllowThem>,
    _admin: AdminKey,
    Path(id): Path<String>,
) -> Result<StatusCode, ManageError> {
    let uid = parse_user_id(&id)?;
    ath.db().delete_user(uid).await.map_err(map_auth_error)?;
    Ok(StatusCode::NO_CONTENT)
}

pub fn user_routes() -> axum::Router<ManageState> {
    use axum::routing::get;
    axum::Router::new()
        .route("/", get(list))
        .route("/{id}", get(get_one).patch(update).delete(delete_user))
        .route("/{id}/sessions", get(super::sessions::list_for_user))
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

    use allowthem_core::types::Email;
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
            .merge(user_routes())
            .layer(axum::Extension(handle))
            .layer(axum::Extension(make_admin_key()))
            .with_state(state)
    }

    async fn create_user(handle: &AllowThem, tag: u32) -> allowthem_core::types::User {
        let email = Email::new(format!("user{tag}@test.com")).unwrap();
        handle
            .db()
            .create_user(email, "pw123456", None, None)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn list_users_returns_empty() {
        let h = make_handle().await;
        let app = test_router(h).await;
        let req = Request::get("/").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["items"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn list_users_cursor_returns_next() {
        let h = make_handle().await;
        for i in 0..5u32 {
            create_user(&h, i).await;
        }
        let app = test_router(h).await;
        let req = Request::get("/?limit=3").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["items"].as_array().unwrap().len(), 3);
        assert!(!json["next_cursor"].is_null());
    }

    #[tokio::test]
    async fn get_user_returns_data() {
        let h = make_handle().await;
        let user = create_user(&h, 1).await;
        let app = test_router(h).await;
        let req = Request::get(format!("/{}", user.id))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["id"], user.id.to_string());
    }

    #[tokio::test]
    async fn get_user_not_found_returns_404() {
        let h = make_handle().await;
        let app = test_router(h).await;
        let req = Request::get(format!("/{}", Uuid::nil()))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn patch_user_toggles_active() {
        let h = make_handle().await;
        let user = create_user(&h, 2).await;
        let app = test_router(h).await;
        let body = serde_json::json!({ "is_active": false }).to_string();
        let req = Request::patch(format!("/{}", user.id))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["is_active"], false);
    }

    #[tokio::test]
    async fn patch_user_diff_roles() {
        let h = make_handle().await;
        let user = create_user(&h, 3).await;
        let role = h
            .db()
            .create_role(&allowthem_core::types::RoleName::new("editor"), None)
            .await
            .unwrap();
        let app = test_router(h).await;
        let body = serde_json::json!({ "role_ids": [role.id.to_string()] }).to_string();
        let req = Request::patch(format!("/{}", user.id))
            .header("content-type", "application/json")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn delete_user_returns_204() {
        let h = make_handle().await;
        let user = create_user(&h, 4).await;
        let app = test_router(h).await;
        let req = Request::delete(format!("/{}", user.id))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn delete_user_not_found_returns_404() {
        let h = make_handle().await;
        let app = test_router(h).await;
        let req = Request::delete(format!("/{}", Uuid::nil()))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
