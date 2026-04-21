use axum::extract::{Extension, Json, Path, Query};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use allowthem_core::AllowThem;
use allowthem_core::applications::{Application, ApplicationCursor, UpdateApplication};
use allowthem_core::error::AuthError;
use allowthem_core::types::{ApplicationId, ClientType};

use super::{ManageError, ManageState};

fn not_found_or_internal(e: AuthError) -> ManageError {
    if matches!(e, AuthError::NotFound) {
        ManageError::NotFound
    } else {
        ManageError::Internal(e.to_string())
    }
}

fn parse_application_id(s: &str) -> Result<ApplicationId, ManageError> {
    s.parse::<Uuid>()
        .map(ApplicationId::from_uuid)
        .map_err(|_| ManageError::NotFound)
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ListQuery {
    #[serde(default = "default_limit")]
    limit: u32,
    cursor: Option<String>,
}

fn default_limit() -> u32 {
    20
}

#[derive(Serialize)]
pub struct ApplicationPage {
    pub items: Vec<Application>,
    pub next_cursor: Option<String>,
}

pub async fn list_applications(
    Extension(ath): Extension<AllowThem>,
    Query(q): Query<ListQuery>,
) -> Result<Json<ApplicationPage>, ManageError> {
    let cursor = match q.cursor {
        None => None,
        Some(ref s) => {
            let cur = ApplicationCursor::decode(s).ok_or_else(|| {
                ManageError::Internal("invalid cursor".into())
            })?;
            Some(cur)
        }
    };

    let limit = q.limit.clamp(1, 200);
    // fetch one extra to determine if there is a next page
    let mut rows = ath
        .db()
        .list_applications_paginated(limit + 1, cursor.as_ref())
        .await
        .map_err(|e| ManageError::Internal(e.to_string()))?;

    let next_cursor = if rows.len() as u32 > limit {
        rows.pop();
        rows.last()
            .map(|last| ApplicationCursor::from_app(last).encode())
    } else {
        None
    };

    Ok(Json(ApplicationPage {
        items: rows,
        next_cursor,
    }))
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct CreateAppBody {
    pub name: String,
    pub client_type: ClientType,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub is_trusted: bool,
    pub logo_url: Option<String>,
    pub primary_color: Option<String>,
}

#[derive(Serialize)]
pub struct CreateAppResponse {
    pub application: Application,
    pub client_secret: Option<String>,
}

pub async fn create_application(
    Extension(ath): Extension<AllowThem>,
    Json(body): Json<CreateAppBody>,
) -> Result<Response, ManageError> {
    let (app, secret) = ath
        .db()
        .create_application(
            body.name,
            body.client_type,
            body.redirect_uris,
            body.is_trusted,
            None,
            body.logo_url,
            body.primary_color,
        )
        .await
        .map_err(|e| match e {
            AuthError::InvalidRedirectUri(_) | AuthError::Validation(_) => {
                ManageError::Internal(e.to_string())
            }
            _ => ManageError::Internal(e.to_string()),
        })?;

    let body = CreateAppResponse {
        application: app,
        client_secret: secret.map(|s| s.as_str().to_owned()),
    };
    Ok((StatusCode::CREATED, Json(body)).into_response())
}

// ---------------------------------------------------------------------------
// Get
// ---------------------------------------------------------------------------

pub async fn get_application(
    Extension(ath): Extension<AllowThem>,
    Path(id): Path<String>,
) -> Result<Json<Application>, ManageError> {
    let app_id = parse_application_id(&id)?;
    let app = ath
        .db()
        .get_application(app_id)
        .await
        .map_err(not_found_or_internal)?;
    Ok(Json(app))
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct UpdateAppBody {
    pub name: String,
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub is_trusted: bool,
    #[serde(default = "default_true")]
    pub is_active: bool,
    pub logo_url: Option<String>,
    pub primary_color: Option<String>,
}

fn default_true() -> bool {
    true
}

pub async fn update_application(
    Extension(ath): Extension<AllowThem>,
    Path(id): Path<String>,
    Json(body): Json<UpdateAppBody>,
) -> Result<StatusCode, ManageError> {
    let app_id = parse_application_id(&id)?;
    ath.db()
        .update_application(
            app_id,
            UpdateApplication {
                name: body.name,
                redirect_uris: body.redirect_uris,
                is_trusted: body.is_trusted,
                is_active: body.is_active,
                logo_url: body.logo_url,
                primary_color: body.primary_color,
            },
        )
        .await
        .map_err(not_found_or_internal)?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

pub async fn delete_application(
    Extension(ath): Extension<AllowThem>,
    Path(id): Path<String>,
) -> Result<StatusCode, ManageError> {
    let app_id = parse_application_id(&id)?;
    ath.db()
        .delete_application(app_id)
        .await
        .map_err(not_found_or_internal)?;
    Ok(StatusCode::NO_CONTENT)
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn application_routes() -> Router<ManageState> {
    Router::new()
        .route("/", get(list_applications).post(create_application))
        .route(
            "/{id}",
            get(get_application)
                .put(update_application)
                .delete(delete_application),
        )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request;
    use tower::ServiceExt;

    use allowthem_core::AllowThemBuilder;

    async fn make_handle() -> AllowThem {
        AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap()
    }

    async fn make_dummy_state() -> ManageState {
        use std::str::FromStr;
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .pragma("foreign_keys", "ON");
        let pool = sqlx::SqlitePool::connect_with(opts).await.unwrap();
        let ctrl = Arc::new(crate::control_db::ControlDb::new(pool).await.unwrap());
        ManageState::new(
            ctrl,
            crate::cache::HandleCache::new(1),
            std::path::PathBuf::from("/tmp"),
            Arc::new(crate::tenants::TenantBuilderConfig {
                mfa_key: [0u8; 32],
                signing_key: [0u8; 32],
                csrf_key: [0u8; 32],
                base_domain: "test.example.com".into(),
            }),
            1000,
        )
    }

    async fn app_router(handle: AllowThem) -> Router {
        let state = make_dummy_state().await;
        Router::<ManageState>::new()
            .merge(application_routes())
            .layer(axum::Extension(handle))
            .with_state(state)
    }

    async fn make_app(handle: &AllowThem, name: &str) -> Application {
        let (app, _) = handle
            .db()
            .create_application(
                name.to_owned(),
                ClientType::Public,
                vec!["https://example.com/callback".to_owned()],
                false,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        app
    }

    // -----------------------------------------------------------------------
    // Core pagination tests (direct)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn list_empty_returns_empty_vec() {
        let h = make_handle().await;
        let result = h.db().list_applications_paginated(20, None).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn list_returns_items_in_created_at_order() {
        let h = make_handle().await;
        make_app(&h, "alpha").await;
        make_app(&h, "beta").await;
        make_app(&h, "gamma").await;
        let result = h.db().list_applications_paginated(20, None).await.unwrap();
        assert_eq!(result.len(), 3);
        // Verify ascending order
        let names: Vec<_> = result.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, vec!["alpha", "beta", "gamma"]);
    }

    #[tokio::test]
    async fn list_cursor_paginates_correctly() {
        let h = make_handle().await;
        make_app(&h, "a1").await;
        make_app(&h, "a2").await;
        make_app(&h, "a3").await;

        let page1 = h.db().list_applications_paginated(2, None).await.unwrap();
        assert_eq!(page1.len(), 2);
        let cursor = ApplicationCursor::from_app(page1.last().unwrap());

        let page2 = h
            .db()
            .list_applications_paginated(2, Some(&cursor))
            .await
            .unwrap();
        assert_eq!(page2.len(), 1);
        assert_eq!(page2[0].name, "a3");
    }

    #[tokio::test]
    async fn cursor_encodes_and_decodes() {
        let h = make_handle().await;
        let app = make_app(&h, "encode-test").await;
        let cursor = ApplicationCursor::from_app(&app);
        let encoded = cursor.encode();
        let decoded = ApplicationCursor::decode(&encoded).unwrap();
        assert_eq!(decoded.id, app.id);
    }

    // -----------------------------------------------------------------------
    // HTTP handler tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn http_list_empty_returns_200() {
        let h = make_handle().await;
        let app = app_router(h).await;
        let req = Request::get("/").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = to_bytes(resp.into_body(), 4096).await.unwrap();
        let page: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(page["items"].as_array().unwrap().len(), 0);
    }

    #[tokio::test]
    async fn http_create_returns_201() {
        let h = make_handle().await;
        let app = app_router(h).await;
        let body = serde_json::json!({
            "name": "My App",
            "client_type": "public",
            "redirect_uris": ["https://example.com/cb"],
        });
        let req = Request::post("/")
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn http_get_missing_returns_404() {
        let h = make_handle().await;
        let app = app_router(h).await;
        let missing_id = Uuid::new_v4();
        let req = Request::get(format!("/{missing_id}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn http_delete_returns_204() {
        let h = make_handle().await;
        let created = make_app(&h, "to-delete").await;
        let app = app_router(h).await;
        let req = Request::delete(format!("/{}", created.id))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn http_update_returns_204() {
        let h = make_handle().await;
        let created = make_app(&h, "to-update").await;
        let app = app_router(h).await;
        let body = serde_json::json!({
            "name": "Updated Name",
            "redirect_uris": ["https://example.com/updated"],
            "is_trusted": false,
            "is_active": true,
        });
        let req = Request::put(format!("/{}", created.id))
            .header("Content-Type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
}
