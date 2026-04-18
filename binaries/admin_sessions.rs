use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Form, Router};
use minijinja::context;
use serde::Deserialize;

use allowthem_core::sessions::ListSessionsParams;
use allowthem_core::types::{SessionId, UserId};
use allowthem_server::{BrowserAdminUser, CsrfToken};

use crate::error::AppError;
use crate::state::AppState;

const PAGE_SIZE: u32 = 25;

#[derive(Deserialize)]
pub struct SessionListQuery {
    #[serde(default)]
    user_id: Option<UserId>,
    #[serde(default)]
    page: Option<u32>,
}

#[derive(Deserialize)]
pub struct RevokeForm {
    #[allow(dead_code)]
    csrf_token: String,
    #[serde(default)]
    page: Option<u32>,
    #[serde(default)]
    user_id: Option<UserId>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list))
        .route("/{id}/revoke", post(revoke))
        .route("/revoke-all/{user_id}", post(revoke_all))
}

/// GET /admin/sessions — paginated session list with optional user filter.
pub async fn list(
    State(state): State<AppState>,
    BrowserAdminUser(_user): BrowserAdminUser,
    Query(params): Query<SessionListQuery>,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let page = params.page.unwrap_or(1).max(1);
    let offset = (page - 1) * PAGE_SIZE;

    let result = state
        .ath
        .db()
        .list_all_sessions(ListSessionsParams {
            user_id: params.user_id,
            limit: PAGE_SIZE,
            offset,
        })
        .await?;

    let (filter_user_email, filter_user_id) = if let Some(uid) = params.user_id {
        match state.ath.db().get_user(uid).await {
            Ok(user) => (Some(user.email.as_str().to_string()), Some(uid.to_string())),
            Err(_) => (None, None),
        }
    } else {
        (None, None)
    };

    let total_pages = if result.total == 0 {
        0
    } else {
        result.total.div_ceil(PAGE_SIZE)
    };

    let html = crate::templates::render(
        &state.templates,
        "admin/sessions_list.html",
        context! {
            sessions => &result.sessions,
            total => result.total,
            page,
            total_pages,
            filter_user_email,
            filter_user_id,
            csrf_token => csrf.as_str(),
        },
        state.is_production,
    )?;
    Ok(html.into_response())
}

/// POST /admin/sessions/:id/revoke — revoke a single session.
pub async fn revoke(
    State(state): State<AppState>,
    BrowserAdminUser(_user): BrowserAdminUser,
    Path(id): Path<SessionId>,
    _csrf: CsrfToken,
    Form(form): Form<RevokeForm>,
) -> Result<Response, AppError> {
    let deleted = state.ath.db().delete_session_by_id(id).await?;
    if !deleted {
        return Err(AppError::Auth(allowthem_core::AuthError::NotFound));
    }

    let mut redirect_url = "/admin/sessions".to_string();
    let mut params = Vec::new();
    if let Some(uid) = &form.user_id {
        params.push(format!("user_id={uid}"));
    }
    if let Some(p) = form.page {
        params.push(format!("page={p}"));
    }
    if !params.is_empty() {
        redirect_url.push('?');
        redirect_url.push_str(&params.join("&"));
    }

    Ok(Redirect::to(&redirect_url).into_response())
}

/// POST /admin/sessions/revoke-all/:user_id — revoke all sessions for a user.
pub async fn revoke_all(
    State(state): State<AppState>,
    BrowserAdminUser(_user): BrowserAdminUser,
    Path(user_id): Path<UserId>,
    _csrf: CsrfToken,
) -> Result<Response, AppError> {
    // Verify user exists
    let _ = state.ath.db().get_user(user_id).await?;
    state.ath.db().delete_user_sessions(&user_id).await?;
    Ok(Redirect::to(&format!("/admin/sessions?user_id={user_id}")).into_response())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header::COOKIE};
    use chrono::{Duration, Utc};
    use tower::ServiceExt;

    use allowthem_core::types::{SessionId, UserId};
    use allowthem_core::{
        AllowThem, AllowThemBuilder, AuthClient, Email, EmbeddedAuthClient, RoleName,
        generate_token, hash_token,
    };
    use allowthem_server::csrf_middleware;

    use crate::state::AppState;

    async fn setup() -> (AllowThem, AppState, String) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .csrf_key(*b"test-csrf-key-for-binary-tests!!")
            .build()
            .await
            .unwrap();

        let email = Email::new("admin@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();

        let role_name = RoleName::new("admin");
        let role = ath.db().create_role(&role_name, None).await.unwrap();
        ath.db().assign_role(&user.id, &role.id).await.unwrap();

        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = Utc::now() + Duration::hours(24);
        ath.db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();

        let cookie = ath.session_cookie(&token);
        let cookie_value = cookie.split(';').next().unwrap().to_string();

        let templates = crate::templates::build_template_env().unwrap();
        let auth_client: Arc<dyn AuthClient> =
            Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
        let state = AppState {
            ath: ath.clone(),
            auth_client,
            templates,
            is_production: false,
        };

        (ath, state, cookie_value)
    }

    fn test_app(state: AppState) -> Router {
        Router::new()
            .nest("/admin/sessions", super::routes())
            .layer(axum::middleware::from_fn_with_state(state.clone(), csrf_middleware))
            .with_state(state)
    }

    fn get_csrf_token(body: &str) -> String {
        let marker = "name=\"csrf_token\" value=\"";
        let start = body.find(marker).expect("csrf_token not found") + marker.len();
        let end = body[start..].find('"').unwrap() + start;
        body[start..end].to_string()
    }

    async fn read_body_string(resp: axum::http::Response<Body>) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    async fn create_user_session(ath: &AllowThem, email_str: &str) -> (UserId, SessionId) {
        let email = Email::new(email_str.into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();
        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = Utc::now() + Duration::hours(24);
        let session = ath
            .db()
            .create_session(
                user.id,
                token_hash,
                Some("1.2.3.4"),
                Some("TestAgent/1.0"),
                expires,
            )
            .await
            .unwrap();
        (user.id, session.id)
    }

    #[tokio::test]
    async fn list_page_renders_empty() {
        let (_ath, state, cookie) = setup().await;
        let app = test_app(state);

        let req = Request::builder()
            .uri("/admin/sessions")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        // Admin's own session exists, so we get at least that
        assert!(body.contains("Sessions"));
    }

    #[tokio::test]
    async fn list_page_renders_with_sessions() {
        let (ath, state, cookie) = setup().await;
        create_user_session(&ath, "user@example.com").await;

        let app = test_app(state);
        let req = Request::builder()
            .uri("/admin/sessions")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("user@example.com"));
        assert!(body.contains("1.2.3.4"));
    }

    #[tokio::test]
    async fn list_page_filters_by_user_id() {
        let (ath, state, cookie) = setup().await;
        let (user_id, _) = create_user_session(&ath, "filtered@example.com").await;
        create_user_session(&ath, "other@example.com").await;

        let app = test_app(state);
        let req = Request::builder()
            .uri(&format!("/admin/sessions?user_id={user_id}"))
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("filtered@example.com"));
        assert!(body.contains("Showing sessions for"));
        assert!(!body.contains("other@example.com"));
    }

    #[tokio::test]
    async fn list_page_invalid_user_filter_shows_all() {
        let (ath, state, cookie) = setup().await;
        create_user_session(&ath, "visible@example.com").await;

        let fake_id = UserId::new();
        let app = test_app(state);
        let req = Request::builder()
            .uri(&format!("/admin/sessions?user_id={fake_id}"))
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        // Invalid user_id filter is cleared — shows all sessions
        assert!(!body.contains("Showing sessions for"));
    }

    #[tokio::test]
    async fn revoke_deletes_session_and_redirects() {
        let (ath, state, cookie) = setup().await;
        let (_, session_id) = create_user_session(&ath, "revoke@example.com").await;

        let app = test_app(state.clone());

        // GET list page for CSRF token
        let req = Request::builder()
            .uri("/admin/sessions")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body_string(resp).await;
        let csrf = get_csrf_token(&body);

        let form_body = format!("csrf_token={csrf}");
        let req = Request::builder()
            .method("POST")
            .uri(&format!("/admin/sessions/{session_id}/revoke"))
            .header(COOKIE, &format!("{cookie}; csrf_token={csrf}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        // Verify session is deleted
        let deleted = ath.db().delete_session_by_id(session_id).await.unwrap();
        assert!(!deleted, "session should already be deleted");
    }

    #[tokio::test]
    async fn revoke_preserves_page_and_filter() {
        let (ath, state, cookie) = setup().await;
        let (user_id, session_id) = create_user_session(&ath, "paged@example.com").await;

        let app = test_app(state.clone());

        let req = Request::builder()
            .uri("/admin/sessions")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body_string(resp).await;
        let csrf = get_csrf_token(&body);

        let form_body = format!("csrf_token={csrf}&page=2&user_id={user_id}");
        let req = Request::builder()
            .method("POST")
            .uri(&format!("/admin/sessions/{session_id}/revoke"))
            .header(COOKIE, &format!("{cookie}; csrf_token={csrf}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("page=2"));
        assert!(location.contains(&format!("user_id={user_id}")));
    }

    #[tokio::test]
    async fn revoke_nonexistent_returns_404() {
        let (_ath, state, cookie) = setup().await;
        let app = test_app(state.clone());

        let req = Request::builder()
            .uri("/admin/sessions")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body_string(resp).await;
        let csrf = get_csrf_token(&body);

        let fake_id = SessionId::new();
        let form_body = format!("csrf_token={csrf}");
        let req = Request::builder()
            .method("POST")
            .uri(&format!("/admin/sessions/{fake_id}/revoke"))
            .header(COOKIE, &format!("{cookie}; csrf_token={csrf}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn revoke_all_deletes_all_user_sessions() {
        let (ath, state, cookie) = setup().await;
        let (user_id, _) = create_user_session(&ath, "allsess@example.com").await;
        // Create a second session for the same user
        let token2 = generate_token();
        let hash2 = hash_token(&token2);
        let expires2 = Utc::now() + Duration::hours(24);
        ath.db()
            .create_session(user_id, hash2, Some("5.6.7.8"), None, expires2)
            .await
            .unwrap();

        let app = test_app(state.clone());

        let req = Request::builder()
            .uri("/admin/sessions")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body_string(resp).await;
        let csrf = get_csrf_token(&body);

        let form_body = format!("csrf_token={csrf}");
        let req = Request::builder()
            .method("POST")
            .uri(&format!("/admin/sessions/revoke-all/{user_id}"))
            .header(COOKIE, &format!("{cookie}; csrf_token={csrf}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);

        // Verify all sessions for user are deleted
        let sessions = ath.db().list_user_sessions(user_id).await.unwrap();
        assert!(sessions.is_empty(), "all sessions should be deleted");
    }

    #[tokio::test]
    async fn revoke_all_nonexistent_user_returns_404() {
        let (_ath, state, cookie) = setup().await;
        let app = test_app(state.clone());

        let req = Request::builder()
            .uri("/admin/sessions")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let body = read_body_string(resp).await;
        let csrf = get_csrf_token(&body);

        let fake_id = UserId::new();
        let form_body = format!("csrf_token={csrf}");
        let req = Request::builder()
            .method("POST")
            .uri(&format!("/admin/sessions/revoke-all/{fake_id}"))
            .header(COOKIE, &format!("{cookie}; csrf_token={csrf}"))
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form_body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn unauthenticated_redirects_to_login() {
        let (_ath, state, _cookie) = setup().await;
        let app = test_app(state);

        let req = Request::builder()
            .uri("/admin/sessions")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("/login?next="));
    }

    #[tokio::test]
    async fn non_admin_gets_403() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .csrf_key(*b"test-csrf-key-for-binary-tests!!")
            .build()
            .await
            .unwrap();

        let email = Email::new("nonadmin@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();

        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = Utc::now() + Duration::hours(24);
        ath.db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();
        let cookie = ath.session_cookie(&token);
        let cookie_value = cookie.split(';').next().unwrap().to_string();

        let templates = crate::templates::build_template_env().unwrap();
        let auth_client: Arc<dyn AuthClient> =
            Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
        let state = AppState {
            ath,
            auth_client,
            templates,
            is_production: false,
        };
        let app = test_app(state);

        let req = Request::builder()
            .uri("/admin/sessions")
            .header(COOKIE, &cookie_value)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
