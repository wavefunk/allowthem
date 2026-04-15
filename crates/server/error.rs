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
    /// session, orphaned session (user deleted).
    Unauthenticated,
    /// User exists but `is_active == false`.
    Inactive,
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
            Self::Inactive => (
                StatusCode::UNAUTHORIZED,
                axum::Json(json!({"error": "account inactive"})),
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
