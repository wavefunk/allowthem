use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::response::Json;
use serde::Serialize;

use allowthem_core::AllowThem;
use allowthem_core::error::AuthError;
use allowthem_core::types::{SessionId, UserId};

use super::{AdminKey, ManageError, ManageState};

#[derive(Serialize)]
pub struct SessionResponse {
    pub id: String,
    pub user_id: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: String,
    pub created_at: String,
}

fn map_auth_error(e: AuthError) -> ManageError {
    match e {
        AuthError::NotFound => ManageError::NotFound,
        _ => ManageError::Internal(e.to_string()),
    }
}

fn parse_session_id(s: &str) -> Result<SessionId, ManageError> {
    s.parse().map_err(|_| ManageError::NotFound)
}

fn parse_user_id(s: &str) -> Result<UserId, ManageError> {
    s.parse().map_err(|_| ManageError::NotFound)
}

pub(crate) async fn list_for_user(
    Extension(ath): Extension<AllowThem>,
    _admin: AdminKey,
    Path(user_id): Path<String>,
) -> Result<Json<Vec<SessionResponse>>, ManageError> {
    let uid = parse_user_id(&user_id)?;
    let sessions = ath
        .db()
        .list_user_sessions(uid)
        .await
        .map_err(map_auth_error)?;
    let items = sessions
        .iter()
        .map(|s| SessionResponse {
            id: s.id.to_string(),
            user_id: s.user_id.to_string(),
            ip_address: s.ip_address.clone(),
            user_agent: s.user_agent.clone(),
            expires_at: s.expires_at.to_rfc3339(),
            created_at: s.created_at.to_rfc3339(),
        })
        .collect();
    Ok(Json(items))
}

pub(crate) async fn revoke(
    Extension(ath): Extension<AllowThem>,
    _admin: AdminKey,
    Path(session_id): Path<String>,
) -> Result<StatusCode, ManageError> {
    let sid = parse_session_id(&session_id)?;
    let deleted = ath
        .db()
        .delete_session_by_id(sid)
        .await
        .map_err(map_auth_error)?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ManageError::NotFound)
    }
}

pub fn session_routes() -> axum::Router<ManageState> {
    use axum::routing::delete;
    axum::Router::new().route("/{id}", delete(revoke))
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
            .route("/{id}/sessions", axum::routing::get(list_for_user))
            .merge(session_routes())
            .layer(axum::Extension(handle))
            .layer(axum::Extension(make_admin_key()))
            .with_state(state)
    }

    async fn create_user_with_session(
        handle: &AllowThem,
    ) -> (allowthem_core::types::User, allowthem_core::types::Session) {
        use allowthem_core::sessions::{generate_token, hash_token};
        let email = Email::new("sess@test.com".to_owned()).unwrap();
        let user = handle
            .db()
            .create_user(email, "pw123456", None, None)
            .await
            .unwrap();
        let token = generate_token();
        let hash = hash_token(&token);
        let expires_at = Utc::now() + chrono::Duration::hours(1);
        let session = handle
            .db()
            .create_session(user.id, hash, None, None, expires_at)
            .await
            .unwrap();
        (user, session)
    }

    #[tokio::test]
    async fn list_sessions_returns_list() {
        let h = make_handle().await;
        let (user, _session) = create_user_with_session(&h).await;
        let app = test_router(h).await;
        let req = Request::get(format!("/{}/sessions", user.id))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn revoke_session_returns_204() {
        let h = make_handle().await;
        let (_user, session) = create_user_with_session(&h).await;
        let app = test_router(h).await;
        let req = Request::delete(format!("/{}", session.id))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn revoke_session_not_found_returns_404() {
        let h = make_handle().await;
        let app = test_router(h).await;
        let req = Request::delete(format!("/{}", Uuid::nil()))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}
