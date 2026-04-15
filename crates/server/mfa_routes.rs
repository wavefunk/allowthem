use axum::extract::{Extension, State};
use axum::http::header::COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use allowthem_core::types::User;
use allowthem_core::{AllowThem, AuthError};

#[derive(Clone)]
struct MfaConfig {
    issuer: String,
}

/// Create a router with MFA setup route handlers.
///
/// Returns a `Router<AllowThem>` with three endpoints:
/// - `POST /mfa/setup` — generates TOTP secret, returns otpauth URI and base32 secret
/// - `POST /mfa/confirm` — validates TOTP code, enables MFA, returns recovery codes
/// - `POST /mfa/disable` — disables MFA, deletes secret and recovery codes
///
/// All endpoints require an authenticated session (cookie-based).
/// The `issuer` parameter is used in the otpauth URI (e.g., "allowthem").
pub fn mfa_routes(issuer: String) -> Router<AllowThem> {
    let config = MfaConfig { issuer };
    Router::new()
        .route("/mfa/setup", post(setup))
        .route("/mfa/confirm", post(confirm))
        .route("/mfa/disable", post(disable))
        .layer(Extension(config))
}

async fn authenticated_user(
    ath: &AllowThem,
    headers: &HeaderMap,
) -> Result<User, (StatusCode, Json<Value>)> {
    let cookie = headers
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthenticated"})),
            )
        })?;

    let token = ath.parse_session_cookie(cookie).ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthenticated"})),
        )
    })?;

    let ttl = ath.session_config().ttl;
    let session = ath
        .db()
        .validate_session(&token, ttl)
        .await
        .map_err(|e| {
            tracing::error!("session validation error: {e}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal error"})),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthenticated"})),
            )
        })?;

    match ath.db().get_user(session.user_id).await {
        Ok(user) if user.is_active => Ok(user),
        Ok(_) => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthenticated"})),
        )),
        Err(AuthError::NotFound) => Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthenticated"})),
        )),
        Err(e) => {
            tracing::error!("user lookup error: {e}");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal error"})),
            ))
        }
    }
}

fn map_mfa_error(err: AuthError) -> (StatusCode, Json<Value>) {
    match err {
        AuthError::MfaAlreadyEnabled => (
            StatusCode::CONFLICT,
            Json(json!({"error": "MFA is already enabled"})),
        ),
        AuthError::MfaNotEnabled => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "MFA is not enabled"})),
        ),
        AuthError::InvalidTotpCode => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid TOTP code"})),
        ),
        AuthError::MfaNotConfigured | AuthError::MfaEncryption(_) => {
            tracing::error!("MFA error: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal error"})),
            )
        }
        other => {
            tracing::error!("unexpected error in MFA route: {other}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal error"})),
            )
        }
    }
}

/// POST /mfa/setup
///
/// Generates a TOTP secret for the authenticated user. Returns the otpauth URI
/// (for QR code rendering) and the base32-encoded secret.
async fn setup(
    State(ath): State<AllowThem>,
    Extension(config): Extension<MfaConfig>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let user = authenticated_user(&ath, &headers).await?;

    let secret_b32 = ath
        .create_mfa_secret(user.id)
        .await
        .map_err(map_mfa_error)?;

    let uri = allowthem_core::totp::totp_uri(&secret_b32, user.email.as_str(), &config.issuer);

    Ok((
        StatusCode::OK,
        Json(json!({
            "secret": secret_b32,
            "otpauth_uri": uri,
        })),
    ))
}

#[derive(Deserialize)]
struct ConfirmBody {
    code: String,
}

/// POST /mfa/confirm
///
/// Validates the TOTP code against the user's pending secret. If valid,
/// enables MFA and returns 10 recovery codes (shown once).
async fn confirm(
    State(ath): State<AllowThem>,
    headers: HeaderMap,
    Json(body): Json<ConfirmBody>,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let user = authenticated_user(&ath, &headers).await?;

    let recovery_codes = ath
        .enable_mfa(user.id, &body.code)
        .await
        .map_err(map_mfa_error)?;

    Ok((
        StatusCode::OK,
        Json(json!({
            "message": "MFA enabled",
            "recovery_codes": recovery_codes,
        })),
    ))
}

/// POST /mfa/disable
///
/// Disables MFA for the authenticated user. Deletes the secret and all recovery codes.
async fn disable(
    State(ath): State<AllowThem>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<Value>), (StatusCode, Json<Value>)> {
    let user = authenticated_user(&ath, &headers).await?;

    ath.disable_mfa(user.id).await.map_err(map_mfa_error)?;

    Ok((StatusCode::OK, Json(json!({"message": "MFA disabled"}))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::handle::AllowThemBuilder;
    use allowthem_core::sessions::{generate_token, hash_token};
    use allowthem_core::types::Email;
    use axum::body::Body;
    use axum::http::Request;
    use chrono::{Duration, Utc};
    use totp_rs::{Algorithm, Secret, TOTP};
    use tower::ServiceExt;

    const TEST_MFA_KEY: [u8; 32] = [0x42; 32];

    async fn test_app() -> (AllowThem, Router) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .mfa_key(TEST_MFA_KEY)
            .build()
            .await
            .unwrap();

        let routes = mfa_routes("allowthem-test".into());
        let app = routes.with_state(ath.clone());
        (ath, app)
    }

    async fn create_user_session(ath: &AllowThem) -> (allowthem_core::types::UserId, String) {
        let email = Email::new("mfa-user@example.com".to_string()).unwrap();
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

        let cookie = format!("{}={}", ath.session_config().cookie_name, token.as_str());
        (user.id, cookie)
    }

    async fn read_body(resp: axum::http::Response<Body>) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn setup_returns_otpauth_uri() {
        let (ath, app) = test_app().await;
        let (_user_id, cookie) = create_user_session(&ath).await;

        let req = Request::builder()
            .method("POST")
            .uri("/mfa/setup")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        let uri = body["otpauth_uri"].as_str().unwrap();
        assert!(uri.starts_with("otpauth://totp/"));
        assert!(uri.contains("allowthem-test"));
        assert!(body["secret"].as_str().is_some());
    }

    #[tokio::test]
    async fn confirm_with_valid_code_enables_mfa() {
        let (ath, app) = test_app().await;
        let (user_id, cookie) = create_user_session(&ath).await;

        // Step 1: Setup
        let secret_b32 = ath.create_mfa_secret(user_id).await.unwrap();

        // Step 2: Generate a valid code
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(secret_b32).to_bytes().unwrap(),
            None,
            String::new(),
        )
        .unwrap();
        let valid_code = totp.generate_current().unwrap();

        // Step 3: Confirm
        let req = Request::builder()
            .method("POST")
            .uri("/mfa/confirm")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .body(Body::from(format!(r#"{{"code":"{valid_code}"}}"#)))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert_eq!(body["message"], "MFA enabled");
        let codes = body["recovery_codes"].as_array().unwrap();
        assert_eq!(codes.len(), 10);

        // Verify MFA is actually enabled
        let enabled = ath.has_mfa_enabled(user_id).await.unwrap();
        assert!(enabled);
    }

    #[tokio::test]
    async fn confirm_with_invalid_code_fails() {
        let (ath, app) = test_app().await;
        let (user_id, cookie) = create_user_session(&ath).await;

        ath.create_mfa_secret(user_id).await.unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/mfa/confirm")
            .header("cookie", &cookie)
            .header("content-type", "application/json")
            .body(Body::from(r#"{"code":"000000"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "invalid TOTP code");
    }

    #[tokio::test]
    async fn disable_removes_mfa() {
        let (ath, app) = test_app().await;
        let (user_id, cookie) = create_user_session(&ath).await;

        // Setup and enable MFA via core methods
        let secret_b32 = ath.create_mfa_secret(user_id).await.unwrap();
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(secret_b32).to_bytes().unwrap(),
            None,
            String::new(),
        )
        .unwrap();
        let code = totp.generate_current().unwrap();
        ath.enable_mfa(user_id, &code).await.unwrap();

        // Disable via route
        let req = Request::builder()
            .method("POST")
            .uri("/mfa/disable")
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert_eq!(body["message"], "MFA disabled");

        let enabled = ath.has_mfa_enabled(user_id).await.unwrap();
        assert!(!enabled);
    }

    #[tokio::test]
    async fn setup_requires_auth() {
        let (_ath, app) = test_app().await;

        let req = Request::builder()
            .method("POST")
            .uri("/mfa/setup")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "unauthenticated");
    }
}
