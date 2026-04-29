use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};

/// Minimal styled HTML used as a fallback when the template environment is
/// not available (e.g. inside `IntoResponse` for `BrowserError`). Keeps the
/// same visual tone as `error.html` without requiring a template render.
const FALLBACK_ERROR_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{TITLE}} — allowthem</title>
  <link rel="stylesheet" href="/__allowthem/static/css/01-tokens.css">
  <link rel="stylesheet" href="/__allowthem/static/css/02-base.css">
  <link rel="stylesheet" href="/__allowthem/static/css/03-layout.css">
  <link rel="stylesheet" href="/__allowthem/static/css/04-components.css">
  <link rel="stylesheet" href="/__allowthem/static/css/05-utilities.css">
</head>
<body class="wf-auth" style="display:flex;align-items:center;justify-content:center;min-height:100vh">
  <main class="wf-auth-form" style="max-width:460px;width:100%">
    <div class="wf-auth-wrap">
      <h1>{{TITLE}}</h1>
      <p class="wf-auth-sub">{{MESSAGE}}</p>
      <p class="wf-caption wf-mt-5"><a href="/">Return home</a></p>
    </div>
  </main>
</body>
</html>"#;

/// Build a static error page by replacing placeholders in the fallback HTML.
fn static_error_page(title: &str, message: &str) -> String {
    FALLBACK_ERROR_HTML
        .replace("{{TITLE}}", title)
        .replace("{{MESSAGE}}", message)
}

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
                let html = static_error_page(
                    "Internal error",
                    "Something went wrong while rendering this page.",
                );
                (StatusCode::INTERNAL_SERVER_ERROR, Html(html)).into_response()
            }
            BrowserError::Auth(allowthem_core::AuthError::NotFound) => {
                let html = static_error_page(
                    "Not found",
                    "The page you are looking for could not be found.",
                );
                (StatusCode::NOT_FOUND, Html(html)).into_response()
            }
            BrowserError::Auth(allowthem_core::AuthError::Validation(msg)) => {
                tracing::warn!(error = %msg, "validation error");
                let html = static_error_page("Validation error", &msg);
                (StatusCode::UNPROCESSABLE_ENTITY, Html(html)).into_response()
            }
            BrowserError::Auth(e) => {
                tracing::error!(error = %e, "auth error");
                let html = static_error_page(
                    "Internal error",
                    "Something went wrong. Please try again later.",
                );
                (StatusCode::INTERNAL_SERVER_ERROR, Html(html)).into_response()
            }
        }
    }
}
