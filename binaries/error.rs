use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

#[derive(Debug)]
pub enum AppError {
    Template(minijinja::Error),
    Auth(allowthem_core::AuthError),
}

impl From<minijinja::Error> for AppError {
    fn from(err: minijinja::Error) -> Self {
        AppError::Template(err)
    }
}

impl From<allowthem_core::AuthError> for AppError {
    fn from(err: allowthem_core::AuthError) -> Self {
        AppError::Auth(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Template(e) => {
                tracing::error!(error = %e, "template render failed");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
            AppError::Auth(e) => {
                tracing::error!(error = %e, "auth error");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}
