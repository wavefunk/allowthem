use axum::extract::FromRef;
use axum::extract::FromRequestParts;
use axum::http::StatusCode;
use axum::http::header::AUTHORIZATION;
use axum::http::request::Parts;
use axum::response::{IntoResponse, Response};

use allowthem_core::{AccessTokenClaims, AccessTokenError, AllowThem, AuthError};

/// Rejection type for the `OAuthBearerToken` extractor.
///
/// Returns 401 with `WWW-Authenticate: Bearer` headers per RFC 6750.
pub enum OAuthBearerError {
    /// No Authorization header or not a Bearer token.
    Missing,
    /// Token is expired.
    Expired,
    /// Token signature is invalid or kid is unknown.
    InvalidToken(String),
    /// Internal error during validation.
    Internal,
}

impl IntoResponse for OAuthBearerError {
    fn into_response(self) -> Response {
        let (status, www_auth) = match self {
            Self::Missing => (
                StatusCode::UNAUTHORIZED,
                "Bearer realm=\"allowthem\"".to_string(),
            ),
            Self::Expired => (
                StatusCode::UNAUTHORIZED,
                "Bearer realm=\"allowthem\", error=\"invalid_token\", \
                 error_description=\"token expired\""
                    .to_string(),
            ),
            Self::InvalidToken(desc) => (
                StatusCode::UNAUTHORIZED,
                format!(
                    "Bearer realm=\"allowthem\", error=\"invalid_token\", \
                     error_description=\"{desc}\""
                ),
            ),
            Self::Internal => {
                tracing::error!("internal error during OAuth bearer validation");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Bearer realm=\"allowthem\", error=\"server_error\"".to_string(),
                )
            }
        };

        let mut response = status.into_response();
        if let Ok(value) = www_auth.parse() {
            response
                .headers_mut()
                .insert("WWW-Authenticate", value);
        }
        response
    }
}

/// Axum extractor that validates an OAuth2 RS256 access token.
///
/// Reads `Authorization: Bearer <jwt>`, validates the RS256 signature,
/// checks expiry and issuer, and returns the validated claims.
///
/// Rejects with 401 and `WWW-Authenticate: Bearer` header per RFC 6750.
pub struct OAuthBearerToken(pub AccessTokenClaims);

impl<S> FromRequestParts<S> for OAuthBearerToken
where
    AllowThem: FromRef<S>,
    S: Send + Sync,
{
    type Rejection = OAuthBearerError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let ath = AllowThem::from_ref(state);

        let auth_header = parts
            .headers
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .ok_or(OAuthBearerError::Missing)?;

        let jwt = auth_header
            .strip_prefix("Bearer ")
            .ok_or(OAuthBearerError::Missing)?;

        let base_url = ath.base_url().map_err(|_| OAuthBearerError::Internal)?;

        let claims = ath
            .db()
            .validate_access_token(jwt, base_url)
            .await
            .map_err(|e| match e {
                AuthError::AccessToken(AccessTokenError::Expired) => OAuthBearerError::Expired,
                AuthError::AccessToken(AccessTokenError::InvalidSignature) => {
                    OAuthBearerError::InvalidToken("invalid signature".into())
                }
                AuthError::AccessToken(AccessTokenError::UnknownKid(_)) => {
                    OAuthBearerError::InvalidToken("unknown signing key".into())
                }
                AuthError::AccessToken(AccessTokenError::InvalidClaims(msg)) => {
                    OAuthBearerError::InvalidToken(msg)
                }
                AuthError::AccessToken(AccessTokenError::MalformedToken(msg)) => {
                    OAuthBearerError::InvalidToken(msg)
                }
                _ => OAuthBearerError::Internal,
            })?;

        Ok(OAuthBearerToken(claims))
    }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::extract::FromRef;
    use axum::http::{Request, StatusCode};
    use axum::response::Json;
    use axum::routing::get;
    use tower::ServiceExt;

    use allowthem_core::{AllowThem, AllowThemBuilder};

    use super::*;

    #[derive(Clone)]
    struct TestState {
        ath: AllowThem,
    }

    impl FromRef<TestState> for AllowThem {
        fn from_ref(s: &TestState) -> Self {
            s.ath.clone()
        }
    }

    async fn test_setup() -> (AllowThem, Router) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .base_url("https://auth.example.com")
            .build()
            .await
            .unwrap();

        let state = TestState { ath: ath.clone() };
        let app = Router::new()
            .route(
                "/test",
                get(|OAuthBearerToken(claims): OAuthBearerToken| async move {
                    Json(serde_json::json!({"sub": claims.sub.to_string()}))
                }),
            )
            .with_state(state);

        (ath, app)
    }

    #[tokio::test]
    async fn test_missing_auth_header_returns_401_with_www_authenticate() {
        let (_, app) = test_setup().await;

        let req = Request::builder()
            .uri("/test")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let www_auth = resp
            .headers()
            .get("WWW-Authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www_auth.contains("Bearer realm=\"allowthem\""));
    }

    #[tokio::test]
    async fn test_malformed_bearer_returns_401() {
        let (_, app) = test_setup().await;

        let req = Request::builder()
            .uri("/test")
            .header(AUTHORIZATION, "Token abc123")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_invalid_jwt_returns_401() {
        let (_, app) = test_setup().await;

        let req = Request::builder()
            .uri("/test")
            .header(AUTHORIZATION, "Bearer not.a.jwt")
            .body(axum::body::Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
}
