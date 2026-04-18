use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::header::COOKIE;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};

use allowthem_core::{AuthClient, RoleName, User, parse_session_cookie};

use crate::error::{AuthExtractError, BrowserAdminForbidden, BrowserAuthRedirect};

/// Axum extractor that provides the authenticated user.
///
/// Reads the session cookie, validates the session (with sliding-window
/// renewal), and fetches the user. Rejects with 401 if not authenticated.
///
/// Usage: `AuthUser(user): AuthUser` in handler arguments.
pub struct AuthUser(pub User);

impl<S> FromRequestParts<S> for AuthUser
where
    Arc<dyn AuthClient>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthExtractError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let client = <Arc<dyn AuthClient>>::from_ref(state);

        let cookie_header = parts
            .headers
            .get(COOKIE)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthExtractError::Unauthenticated)?;

        let token = parse_session_cookie(cookie_header, client.session_cookie_name())
            .ok_or(AuthExtractError::Unauthenticated)?;

        let user = client
            .validate_session(&token)
            .await
            .map_err(AuthExtractError::Internal)?
            .ok_or(AuthExtractError::Unauthenticated)?;

        Ok(AuthUser(user))
    }
}

/// Axum extractor that optionally provides the authenticated user.
///
/// Same flow as [`AuthUser`] but wraps `Option<User>` and never rejects.
/// Returns `None` when not authenticated. Returns `Some(user)` when valid.
/// Internal errors (database failures) are logged and treated as `None`.
///
/// Usage: `OptionalAuthUser(user): OptionalAuthUser` in handler arguments.
pub struct OptionalAuthUser(pub Option<User>);

impl<S> FromRequestParts<S> for OptionalAuthUser
where
    Arc<dyn AuthClient>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match AuthUser::from_request_parts(parts, state).await {
            Ok(AuthUser(user)) => Ok(OptionalAuthUser(Some(user))),
            Err(AuthExtractError::Internal(err)) => {
                tracing::error!("auth extraction error: {err}");
                Ok(OptionalAuthUser(None))
            }
            Err(_) => Ok(OptionalAuthUser(None)),
        }
    }
}

/// Axum extractor for browser-facing routes that require authentication.
///
/// Same session validation as [`AuthUser`], but rejects with a 303 redirect
/// to `/login?next={path}` instead of a JSON 401. Use this for routes that
/// render HTML — unauthenticated users are sent to the login page and
/// returned to the original path after logging in.
pub struct BrowserAuthUser(pub User);

impl<S> FromRequestParts<S> for BrowserAuthUser
where
    Arc<dyn AuthClient>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = BrowserAuthRedirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let redirect = BrowserAuthRedirect::new(parts.uri.path());
        let client = <Arc<dyn AuthClient>>::from_ref(state);

        let cookie_header = parts
            .headers
            .get(COOKIE)
            .and_then(|v| v.to_str().ok())
            .ok_or(redirect)?;

        let redirect = BrowserAuthRedirect::new(parts.uri.path());
        let token =
            parse_session_cookie(cookie_header, client.session_cookie_name()).ok_or(redirect)?;

        let redirect = BrowserAuthRedirect::new(parts.uri.path());
        let user = client
            .validate_session(&token)
            .await
            .map_err(|err| {
                tracing::error!("auth extraction error: {err}");
                BrowserAuthRedirect::new(parts.uri.path())
            })?
            .ok_or(redirect)?;

        Ok(BrowserAuthUser(user))
    }
}

/// Axum extractor for admin browser routes.
///
/// Validates the session cookie and checks the `admin` role. Rejects with
/// a redirect to `/login` if unauthenticated, or a 403 HTML response if
/// authenticated but not an admin.
pub struct BrowserAdminUser(pub User);

impl<S> FromRequestParts<S> for BrowserAdminUser
where
    Arc<dyn AuthClient>: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let client = <Arc<dyn AuthClient>>::from_ref(state);

        // 1. Session validation — same flow as BrowserAuthUser
        let cookie_header = parts
            .headers
            .get(COOKIE)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| BrowserAuthRedirect::new(parts.uri.path()).into_response())?;

        let token = parse_session_cookie(cookie_header, client.session_cookie_name())
            .ok_or_else(|| BrowserAuthRedirect::new(parts.uri.path()).into_response())?;

        let user = client
            .validate_session(&token)
            .await
            .map_err(|err| {
                tracing::error!("auth extraction error: {err}");
                BrowserAuthRedirect::new(parts.uri.path()).into_response()
            })?
            .ok_or_else(|| BrowserAuthRedirect::new(parts.uri.path()).into_response())?;

        // 2. Admin role check
        let admin_role = RoleName::new("admin");
        let is_admin = client
            .check_role(&user.id, &admin_role)
            .await
            .map_err(|err| {
                tracing::error!("role check error: {err}");
                BrowserAdminForbidden.into_response()
            })?;

        if !is_admin {
            return Err(BrowserAdminForbidden.into_response());
        }

        Ok(BrowserAdminUser(user))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use allowthem_core::{
        AllowThem, AllowThemBuilder, AuthClient, Email, EmbeddedAuthClient, RoleName,
        generate_token, hash_token,
    };
    use axum::extract::FromRef;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::{Json, Router};
    use chrono::{Duration, Utc};
    use tower::ServiceExt;

    #[derive(Clone)]
    struct TestState {
        auth: Arc<dyn AuthClient>,
    }

    impl FromRef<TestState> for Arc<dyn AuthClient> {
        fn from_ref(s: &TestState) -> Self {
            Arc::clone(&s.auth)
        }
    }

    /// Build an AllowThem, create a test user with an active session,
    /// and return (AllowThem, cookie_header_value).
    async fn test_setup() -> (AllowThem, String) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let email = Email::new("test@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
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
        // session_cookie returns a Set-Cookie value; extract just the name=value
        // for the Cookie request header (everything before the first ';').
        let cookie_value = cookie.split(';').next().unwrap().to_string();
        (ath, cookie_value)
    }

    fn test_app(ath: AllowThem) -> Router {
        let auth: Arc<dyn AuthClient> = Arc::new(EmbeddedAuthClient::new(ath, "/login"));
        let state = TestState { auth };
        Router::new()
            .route("/protected", get(protected_handler))
            .route("/optional", get(optional_handler))
            .route("/browser", get(browser_handler))
            .route("/admin", get(admin_handler))
            .with_state(state)
    }

    async fn protected_handler(AuthUser(user): AuthUser) -> Json<serde_json::Value> {
        Json(serde_json::json!({"email": user.email}))
    }

    async fn optional_handler(OptionalAuthUser(user): OptionalAuthUser) -> Json<serde_json::Value> {
        Json(serde_json::json!({"user": user.map(|u| u.email)}))
    }

    async fn browser_handler(BrowserAuthUser(user): BrowserAuthUser) -> Json<serde_json::Value> {
        Json(serde_json::json!({"email": user.email}))
    }

    async fn admin_handler(BrowserAdminUser(user): BrowserAdminUser) -> Json<serde_json::Value> {
        Json(serde_json::json!({"email": user.email}))
    }

    async fn read_body(resp: axum::http::Response<axum::body::Body>) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn no_cookie_returns_401() {
        let (ath, _) = test_setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/protected")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "unauthenticated");
    }

    #[tokio::test]
    async fn garbage_cookie_returns_401() {
        let (ath, _) = test_setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/protected")
            .header(COOKIE, "allowthem_session=garbage")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn valid_session_returns_user() {
        let (ath, cookie_value) = test_setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/protected")
            .header(COOKIE, &cookie_value)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert_eq!(body["email"], "test@example.com");
    }

    #[tokio::test]
    async fn expired_session_returns_401() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let email = Email::new("expired@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();

        let token = generate_token();
        let token_hash = hash_token(&token);
        // Session already expired
        let expires = Utc::now() - Duration::hours(1);
        ath.db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();

        let cookie = ath.session_cookie(&token);
        let cookie_value = cookie.split(';').next().unwrap().to_string();
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/protected")
            .header(COOKIE, &cookie_value)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn inactive_user_returns_401() {
        let (ath, cookie_value) = test_setup().await;

        // Deactivate the user
        let email = Email::new("test@example.com".into()).unwrap();
        let user = ath.db().get_user_by_email(&email).await.unwrap();
        ath.db().update_user_active(user.id, false).await.unwrap();

        let app = test_app(ath);

        let req = Request::builder()
            .uri("/protected")
            .header(COOKIE, &cookie_value)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "unauthenticated");
    }

    #[tokio::test]
    async fn optional_no_cookie_returns_none() {
        let (ath, _) = test_setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/optional")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert!(body["user"].is_null());
    }

    #[tokio::test]
    async fn optional_valid_session_returns_user() {
        let (ath, cookie_value) = test_setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/optional")
            .header(COOKIE, &cookie_value)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert_eq!(body["user"], "test@example.com");
    }

    // --- BrowserAuthUser tests ---

    #[tokio::test]
    async fn browser_auth_no_cookie_redirects() {
        let (ath, _) = test_setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/browser")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers().get("location").unwrap(),
            "/login?next=/browser"
        );
    }

    #[tokio::test]
    async fn browser_auth_valid_session_returns_user() {
        let (ath, cookie_value) = test_setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/browser")
            .header(COOKIE, &cookie_value)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert_eq!(body["email"], "test@example.com");
    }

    #[tokio::test]
    async fn browser_auth_expired_session_redirects() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let email = Email::new("expired@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();

        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = Utc::now() - Duration::hours(1);
        ath.db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();

        let cookie = ath.session_cookie(&token);
        let cookie_value = cookie.split(';').next().unwrap().to_string();
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/browser")
            .header(COOKIE, &cookie_value)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers().get("location").unwrap(),
            "/login?next=/browser"
        );
    }

    // --- BrowserAdminUser tests ---

    #[tokio::test]
    async fn browser_admin_user_unauthenticated_redirects() {
        let (ath, _) = test_setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/admin")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers().get("location").unwrap(),
            "/login?next=/admin"
        );
    }

    #[tokio::test]
    async fn browser_admin_user_non_admin_gets_403() {
        let (ath, cookie_value) = test_setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/admin")
            .header(COOKIE, &cookie_value)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn browser_admin_user_admin_succeeds() {
        let (ath, cookie_value) = test_setup().await;

        // Create admin role and assign to the test user
        let role_name = RoleName::new("admin");
        let role = ath.db().create_role(&role_name, None).await.unwrap();
        let email = Email::new("test@example.com".into()).unwrap();
        let user = ath.db().get_user_by_email(&email).await.unwrap();
        ath.db().assign_role(&user.id, &role.id).await.unwrap();

        let app = test_app(ath);

        let req = Request::builder()
            .uri("/admin")
            .header(COOKIE, &cookie_value)
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert_eq!(body["email"], "test@example.com");
    }
}
