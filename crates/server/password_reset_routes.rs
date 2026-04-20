use std::sync::Arc;

use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Deserialize;
use serde_json::{Value, json};

use allowthem_core::types::Email;
use allowthem_core::{AllowThem, EmailSender};

#[derive(Clone)]
struct PasswordResetConfig {
    email_sender: Arc<dyn EmailSender>,
    base_url: String,
}

/// Create a router with password reset JSON API handlers.
///
/// Returns a `Router<AllowThem>` with three endpoints namespaced under `/api`
/// to avoid colliding with the browser form surface in
/// [`crate::password_reset_page_routes`]:
/// - `POST /api/forgot-password` — initiates reset flow (always returns 200)
/// - `GET /api/reset-password?token=...` — validates a reset token
/// - `POST /api/reset-password` — executes the password reset
///
/// The caller provides an `EmailSender` for delivering reset emails and a
/// `base_url` used to construct the reset link in the email.
///
/// Mount into your app:
/// ```ignore
/// let reset_routes = password_reset_routes(sender, base_url);
/// let app = Router::new()
///     .merge(reset_routes)
///     .with_state(ath);
/// ```
pub fn password_reset_routes(
    email_sender: Arc<dyn EmailSender>,
    base_url: String,
) -> Router<AllowThem> {
    let config = PasswordResetConfig {
        email_sender,
        base_url,
    };
    Router::new()
        .route("/api/forgot-password", post(forgot_password))
        .route(
            "/api/reset-password",
            get(validate_reset).post(execute_reset),
        )
        .layer(Extension(config))
}

#[derive(Deserialize)]
struct ForgotPasswordBody {
    email: String,
}

/// POST /api/forgot-password
///
/// Always returns 200 regardless of whether the email exists.
/// This prevents email enumeration attacks.
async fn forgot_password(
    State(ath): State<AllowThem>,
    Extension(config): Extension<PasswordResetConfig>,
    Json(body): Json<ForgotPasswordBody>,
) -> (StatusCode, Json<Value>) {
    let email = match Email::new(body.email) {
        Ok(e) => e,
        Err(_) => {
            return (
                StatusCode::OK,
                Json(
                    json!({"message": "If an account with that email exists, a password reset link has been sent."}),
                ),
            );
        }
    };

    if let Err(err) = ath
        .db()
        .send_password_reset(&email, &config.base_url, &*config.email_sender)
        .await
    {
        tracing::error!("password reset email error: {err}");
    }

    (
        StatusCode::OK,
        Json(
            json!({"message": "If an account with that email exists, a password reset link has been sent."}),
        ),
    )
}

#[derive(Deserialize)]
struct ResetTokenQuery {
    token: String,
}

/// GET /api/reset-password?token=...
///
/// Validates a reset token without consuming it.
async fn validate_reset(
    State(ath): State<AllowThem>,
    Query(q): Query<ResetTokenQuery>,
) -> (StatusCode, Json<Value>) {
    match ath.db().validate_reset_token(&q.token).await {
        Ok(Some(_)) => (StatusCode::OK, Json(json!({"valid": true}))),
        Ok(None) => (StatusCode::OK, Json(json!({"valid": false}))),
        Err(err) => {
            tracing::error!("reset token validation error: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal error"})),
            )
        }
    }
}

#[derive(Deserialize)]
struct ResetPasswordBody {
    token: String,
    new_password: String,
}

/// POST /api/reset-password
///
/// Executes the password reset: validates the token, hashes the new password,
/// updates the user, and marks the token as used.
async fn execute_reset(
    State(ath): State<AllowThem>,
    Json(body): Json<ResetPasswordBody>,
) -> (StatusCode, Json<Value>) {
    match ath
        .db()
        .execute_reset(&body.token, &body.new_password)
        .await
    {
        Ok(true) => (
            StatusCode::OK,
            Json(json!({"message": "Password has been reset."})),
        ),
        Ok(false) => (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid or expired token"})),
        ),
        Err(err) => {
            tracing::error!("password reset error: {err}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": "internal error"})),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::{AllowThemBuilder, LogEmailSender};
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn test_app() -> (AllowThem, Router) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let sender: Arc<dyn EmailSender> = Arc::new(LogEmailSender);
        let routes = password_reset_routes(sender, "https://example.com".into());
        let app = routes.with_state(ath.clone());
        (ath, app)
    }

    async fn create_user(ath: &AllowThem, email_str: &str) {
        let email = Email::new(email_str.into()).unwrap();
        ath.db()
            .create_user(email, "initial-password", None, None)
            .await
            .unwrap();
    }

    async fn read_body(resp: axum::http::Response<Body>) -> Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn forgot_password_valid_email_returns_200() {
        let (ath, app) = test_app().await;
        create_user(&ath, "user@example.com").await;

        let req = Request::builder()
            .method("POST")
            .uri("/api/forgot-password")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"email":"user@example.com"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains("password reset link")
        );
    }

    #[tokio::test]
    async fn forgot_password_unknown_email_returns_200() {
        let (_ath, app) = test_app().await;

        let req = Request::builder()
            .method("POST")
            .uri("/api/forgot-password")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"email":"nobody@example.com"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert!(
            body["message"]
                .as_str()
                .unwrap()
                .contains("password reset link")
        );
    }

    #[tokio::test]
    async fn validate_reset_valid_token_returns_true() {
        let (ath, app) = test_app().await;
        create_user(&ath, "reset@example.com").await;

        let email = Email::new("reset@example.com".into()).unwrap();
        let raw_token = ath
            .db()
            .create_password_reset(&email)
            .await
            .unwrap()
            .unwrap();

        let req = Request::builder()
            .uri(format!("/api/reset-password?token={raw_token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert_eq!(body["valid"], true);
    }

    #[tokio::test]
    async fn validate_reset_invalid_token_returns_false() {
        let (_ath, app) = test_app().await;

        let req = Request::builder()
            .uri("/api/reset-password?token=garbage-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert_eq!(body["valid"], false);
    }

    #[tokio::test]
    async fn execute_reset_valid_token_changes_password() {
        let (ath, app) = test_app().await;
        create_user(&ath, "reset@example.com").await;

        let email = Email::new("reset@example.com".into()).unwrap();
        let raw_token = ath
            .db()
            .create_password_reset(&email)
            .await
            .unwrap()
            .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/api/reset-password")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"token":"{raw_token}","new_password":"new-secure-pass"}}"#
            )))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert!(body["message"].as_str().unwrap().contains("reset"));

        // Verify the new password works.
        let user = ath.db().find_for_login("reset@example.com").await.unwrap();
        let valid = allowthem_core::password::verify_password(
            "new-secure-pass",
            user.password_hash.as_ref().unwrap(),
        )
        .unwrap();
        assert!(valid, "new password must verify after reset");
    }

    #[tokio::test]
    async fn execute_reset_used_token_fails() {
        let (ath, app) = test_app().await;
        create_user(&ath, "reset@example.com").await;

        let email = Email::new("reset@example.com".into()).unwrap();
        let raw_token = ath
            .db()
            .create_password_reset(&email)
            .await
            .unwrap()
            .unwrap();

        // First reset — succeeds.
        ath.db()
            .execute_reset(&raw_token, "first-password")
            .await
            .unwrap();

        // Second reset with same token — must fail.
        let req = Request::builder()
            .method("POST")
            .uri("/api/reset-password")
            .header("content-type", "application/json")
            .body(Body::from(format!(
                r#"{{"token":"{raw_token}","new_password":"second-password"}}"#
            )))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "invalid or expired token");
    }
}
