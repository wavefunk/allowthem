use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub enum AppError {
    Template(minijinja::Error),
}

impl From<minijinja::Error> for AppError {
    fn from(err: minijinja::Error) -> Self {
        AppError::Template(err)
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        match self {
            AppError::Template(e) => {
                tracing::error!(error = %e, "template render failed");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            }
        }
    }
}
