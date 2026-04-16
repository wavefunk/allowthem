use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use allowthem_core::AuthError;

/// Error type for authentication extractor failures.
///
/// Implements `IntoResponse` to produce appropriate HTTP error responses.
/// Used as the `Rejection` type for [`AuthUser`](crate::AuthUser).
#[derive(Debug)]
pub enum AuthExtractError {
    /// No valid session. Covers: missing cookie, invalid token, expired
    /// session, orphaned session (user deleted), or inactive user.
    Unauthenticated,
    /// Database or internal error during extraction.
    Internal(AuthError),
}

impl IntoResponse for AuthExtractError {
    fn into_response(self) -> Response {
        match self {
            Self::Unauthenticated => (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({"error": "unauthenticated"})),
            )
                .into_response(),
            Self::Internal(err) => {
                tracing::error!("auth extraction error: {err}");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    axum::Json(json!({"error": "internal error"})),
                )
                    .into_response()
            }
        }
    }
}

/// Rejection type for [`BrowserAuthUser`](crate::BrowserAuthUser).
///
/// Redirects unauthenticated browser requests to the login page with a
/// `?next=` parameter preserving the originally requested path.
#[derive(Debug)]
pub struct BrowserAuthRedirect(pub(crate) String);

impl BrowserAuthRedirect {
    pub fn new(path: &str) -> Self {
        Self(format!("/login?next={path}"))
    }
}

impl IntoResponse for BrowserAuthRedirect {
    fn into_response(self) -> Response {
        (
            StatusCode::SEE_OTHER,
            [(axum::http::header::LOCATION, self.0)],
        )
            .into_response()
    }
}

/// 403 Forbidden response for authenticated non-admin users.
///
/// Returns a minimal HTML body. No template needed — this is a guard page,
/// not a user-facing feature.
pub struct BrowserAdminForbidden;

impl IntoResponse for BrowserAdminForbidden {
    fn into_response(self) -> Response {
        (
            StatusCode::FORBIDDEN,
            axum::response::Html("<h1>403 Forbidden</h1><p>Admin access required.</p>"),
        )
            .into_response()
    }
}
