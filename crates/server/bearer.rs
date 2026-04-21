use axum::extract::FromRequestParts;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;

use allowthem_core::{AllowThem, User};

use crate::error::AuthExtractError;

/// Axum extractor that validates an API bearer token.
///
/// Reads the `Authorization: Bearer <token>` header, validates the token
/// against the database, and returns the authenticated user.
///
/// Rejects with 401 if the header is absent, malformed, the token is unknown
/// or expired, or the user is inactive.
///
/// This extractor requires `AllowThem: FromRef<S>` (not `Arc<dyn AuthClient>`)
/// because API tokens are an embedded-mode feature not part of the auth trait.
///
/// Usage: `BearerAuthUser(user): BearerAuthUser` in handler arguments.
pub struct BearerAuthUser(pub User);

impl<S: Send + Sync> FromRequestParts<S> for BearerAuthUser {
    type Rejection = AuthExtractError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let ath = parts
            .extensions
            .get::<AllowThem>()
            .cloned()
            .ok_or(AuthExtractError::Unauthenticated)?;

        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthExtractError::Unauthenticated)?;

        let raw_token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AuthExtractError::Unauthenticated)?;

        let (user_id, _token_info) = ath
            .db()
            .validate_api_token(raw_token)
            .await
            .map_err(AuthExtractError::Internal)?
            .ok_or(AuthExtractError::Unauthenticated)?;

        let user = ath.db().get_user(user_id).await.map_err(|e| match e {
            allowthem_core::AuthError::NotFound => AuthExtractError::Unauthenticated,
            other => AuthExtractError::Internal(other),
        })?;

        if !user.is_active {
            return Err(AuthExtractError::Unauthenticated);
        }

        Ok(BearerAuthUser(user))
    }
}

#[cfg(test)]
mod tests {
    use axum::Json;
    use axum::Router;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use chrono::{Duration, Utc};
    use tower::ServiceExt;

    use allowthem_core::{AllowThem, AllowThemBuilder, Email};

    use super::*;

    async fn test_setup() -> (AllowThem, String) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let email = Email::new("bearer@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();

        let (raw, _) = ath
            .db()
            .create_api_token(user.id, "test-token", None, None)
            .await
            .unwrap();

        (ath, raw)
    }

    fn test_app(ath: AllowThem) -> Router {
        Router::new().route("/bearer", get(bearer_handler)).layer(
            axum::middleware::from_fn_with_state(ath, crate::cors::inject_ath_into_extensions),
        )
    }

    async fn bearer_handler(BearerAuthUser(user): BearerAuthUser) -> Json<serde_json::Value> {
        Json(serde_json::json!({"email": user.email}))
    }

    async fn read_body(resp: axum::http::Response<axum::body::Body>) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_no_auth_header_returns_401() {
        let (ath, _) = test_setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/bearer")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_malformed_bearer_returns_401() {
        let (ath, _) = test_setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/bearer")
            .header(AUTHORIZATION, "Token abc123")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_invalid_token_returns_401() {
        let (ath, _) = test_setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/bearer")
            .header(AUTHORIZATION, "Bearer garbage-token-xyz")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_valid_bearer_returns_user() {
        let (ath, raw_token) = test_setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/bearer")
            .header(AUTHORIZATION, format!("Bearer {raw_token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert_eq!(body["email"], "bearer@example.com");
    }

    #[tokio::test]
    async fn test_expired_token_returns_401() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let email = Email::new("expired-bearer@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();

        let past = Utc::now() - Duration::hours(1);
        let (raw, _) = ath
            .db()
            .create_api_token(user.id, "expired", Some(past), None)
            .await
            .unwrap();

        let app = test_app(ath);

        let req = Request::builder()
            .uri("/bearer")
            .header(AUTHORIZATION, format!("Bearer {raw}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_inactive_user_returns_401() {
        let (ath, raw_token) = test_setup().await;

        let email = Email::new("bearer@example.com".into()).unwrap();
        let user = ath.db().get_user_by_email(&email).await.unwrap();
        ath.db().update_user_active(user.id, false).await.unwrap();

        let app = test_app(ath);

        let req = Request::builder()
            .uri("/bearer")
            .header(AUTHORIZATION, format!("Bearer {raw_token}"))
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "unauthenticated");
    }
}
