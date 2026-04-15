use axum::extract::{FromRef, FromRequestParts};
use axum::http::header::COOKIE;
use axum::http::request::Parts;

use allowthem_core::{AllowThem, AuthError, User};

use crate::error::AuthExtractError;

/// Axum extractor that provides the authenticated user.
///
/// Reads the session cookie, validates the session (with sliding-window
/// renewal), and fetches the user. Rejects with 401 if not authenticated.
///
/// Usage: `AuthUser(user): AuthUser` in handler arguments.
pub struct AuthUser(pub User);

impl<S> FromRequestParts<S> for AuthUser
where
    AllowThem: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = AuthExtractError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let ath = AllowThem::from_ref(state);

        let cookie_header = parts
            .headers
            .get(COOKIE)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthExtractError::Unauthenticated)?;

        let token = ath
            .parse_session_cookie(cookie_header)
            .ok_or(AuthExtractError::Unauthenticated)?;

        let session = ath
            .db()
            .validate_session(&token, ath.session_config().ttl)
            .await
            .map_err(AuthExtractError::Internal)?
            .ok_or(AuthExtractError::Unauthenticated)?;

        let user = ath
            .db()
            .get_user(session.user_id)
            .await
            .map_err(|e| match e {
                AuthError::NotFound => AuthExtractError::Unauthenticated,
                other => AuthExtractError::Internal(other),
            })?;

        if !user.is_active {
            return Err(AuthExtractError::Inactive);
        }

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
    AllowThem: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::{AllowThemBuilder, Email, generate_token, hash_token};
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::{Json, Router};
    use chrono::{Duration, Utc};
    use tower::ServiceExt;

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
        // session_cookie returns a Set-Cookie value; extract just the name=value
        // for the Cookie request header (everything before the first ';').
        let cookie_value = cookie.split(';').next().unwrap().to_string();
        (ath, cookie_value)
    }

    fn test_app(ath: AllowThem) -> Router {
        Router::new()
            .route("/protected", get(protected_handler))
            .route("/optional", get(optional_handler))
            .with_state(ath)
    }

    async fn protected_handler(AuthUser(user): AuthUser) -> Json<serde_json::Value> {
        Json(serde_json::json!({"email": user.email}))
    }

    async fn optional_handler(
        OptionalAuthUser(user): OptionalAuthUser,
    ) -> Json<serde_json::Value> {
        Json(serde_json::json!({"user": user.map(|u| u.email)}))
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
            .create_user(email, "password123", None)
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
        assert_eq!(body["error"], "account inactive");
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
}
