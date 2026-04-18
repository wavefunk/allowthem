use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug)]
pub enum BrowserError {
    Template(minijinja::Error),
    Auth(allowthem_core::AuthError),
}

impl From<minijinja::Error> for BrowserError {
    fn from(err: minijinja::Error) -> Self {
        BrowserError::Template(err)
    }
}

impl From<allowthem_core::AuthError> for BrowserError {
    fn from(err: allowthem_core::AuthError) -> Self {
        BrowserError::Auth(err)
    }
}

impl IntoResponse for BrowserError {
    fn into_response(self) -> Response {
        match self {
            BrowserError::Template(e) => {
                tracing::error!(error = %e, "template render failed");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            BrowserError::Auth(allowthem_core::AuthError::NotFound) => {
                StatusCode::NOT_FOUND.into_response()
            }
            BrowserError::Auth(allowthem_core::AuthError::Validation(msg)) => {
                tracing::warn!(error = %msg, "validation error");
                (StatusCode::UNPROCESSABLE_ENTITY, msg).into_response()
            }
            BrowserError::Auth(e) => {
                tracing::error!(error = %e, "auth error");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}
