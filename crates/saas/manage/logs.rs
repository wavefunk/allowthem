use axum::extract::{Extension, Query};
use axum::response::Json;
use serde::{Deserialize, Serialize};

use allowthem_core::AllowThem;
use allowthem_core::audit::AuditCursor;

use super::{AdminKey, ListResponse, ManageError, ManageState};

#[derive(Deserialize)]
pub struct LogsQuery {
    limit: Option<u32>,
    cursor: Option<String>,
}

#[derive(Serialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub event_type: String,
    pub user_id: Option<String>,
    pub user_email: Option<String>,
    pub target_id: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub detail: Option<String>,
    pub created_at: String,
}

pub async fn list(
    Extension(ath): Extension<AllowThem>,
    _admin: AdminKey,
    Query(q): Query<LogsQuery>,
) -> Result<Json<ListResponse<AuditLogEntry>>, ManageError> {
    let limit = q.limit.unwrap_or(50).min(200);

    let cursor: Option<AuditCursor> = q
        .cursor
        .as_deref()
        .map(|s| {
            AuditCursor::decode(s)
                .ok_or_else(|| ManageError::InvalidRequest("invalid cursor".into()))
        })
        .transpose()?;

    let mut entries = ath
        .db()
        .list_audit_paginated(limit + 1, cursor.as_ref())
        .await
        .map_err(|e| ManageError::Internal(e.to_string()))?;

    let has_more = entries.len() > limit as usize;
    if has_more {
        entries.pop();
    }

    let next_cursor = if has_more {
        entries.last().map(|e| AuditCursor::from_entry(e).encode())
    } else {
        None
    };

    let items = entries
        .into_iter()
        .map(|e| AuditLogEntry {
            id: e.id.to_string(),
            event_type: serde_json::to_value(&e.event_type)
                .ok()
                .and_then(|v| v.as_str().map(str::to_owned))
                .unwrap_or_default(),
            user_id: e.user_id.map(|u| u.to_string()),
            user_email: e.user_email,
            target_id: e.target_id,
            ip_address: e.ip_address,
            user_agent: e.user_agent,
            detail: e.detail,
            created_at: e.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(ListResponse { items, next_cursor }))
}

pub fn log_routes() -> axum::Router<ManageState> {
    use axum::routing::get;
    axum::Router::new().route("/", get(list))
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

    use allowthem_core::audit::AuditEvent;
    use allowthem_core::types::Email;
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
            .merge(log_routes())
            .layer(axum::Extension(handle))
            .layer(axum::Extension(make_admin_key()))
            .with_state(state)
    }

    async fn create_audit_entry(handle: &AllowThem, event: AuditEvent) {
        let email = Email::new(format!("log{}@test.com", Uuid::new_v4())).unwrap();
        let user = handle
            .db()
            .create_user(email, "pw123456", None, None)
            .await
            .unwrap();
        handle
            .db()
            .log_audit(event, Some(&user.id), None, None, None, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn list_logs_returns_empty() {
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
    async fn list_logs_cursor_returns_next() {
        let h = make_handle().await;
        for _ in 0..5u32 {
            create_audit_entry(&h, AuditEvent::Login).await;
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
}
