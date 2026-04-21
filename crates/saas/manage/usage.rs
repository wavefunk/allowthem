use axum::extract::State;
use axum::response::Json;

use crate::api_keys::ApiKey;
use crate::control_db::TenantUsage;

use super::{AdminKey, ManageError, ManageState};
use axum::extract::Extension;

pub async fn get_usage(
    State(state): State<ManageState>,
    Extension(api_key): Extension<ApiKey>,
    _admin: AdminKey,
) -> Result<Json<Vec<TenantUsage>>, ManageError> {
    let tenant_id = api_key.tenant_id;
    let usage = state
        .control_db
        .usage_for_tenant(&tenant_id)
        .await
        .map_err(|e| ManageError::Internal(e.to_string()))?;
    Ok(Json(usage))
}

pub fn usage_routes() -> axum::Router<ManageState> {
    use axum::routing::get;
    axum::Router::new().route("/", get(get_usage))
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

    use super::*;
    use crate::api_keys::{ApiKey, ApiKeyId, ApiKeyScope};
    use crate::cache::HandleCache;
    use crate::control_db::ControlDb;
    use crate::manage::ManageState;
    use crate::tenants::{TenantBuilderConfig, TenantId};

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

    async fn test_router(state: ManageState) -> Router {
        Router::<ManageState>::new()
            .merge(usage_routes())
            .layer(axum::Extension(make_admin_key()))
            .with_state(state)
    }

    #[tokio::test]
    async fn usage_returns_empty_for_new_tenant() {
        let state = make_state().await;
        let app = test_router(state).await;
        let req = Request::get("/").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 0);
    }
}
