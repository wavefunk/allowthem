//! Dashboard signup flow.
//!
//! - `GET /signup` — render the signup form.
//! - `POST /signup` — process signup (lands in Step 9).
//! - `GET /signup/slug-check` — HTMX live availability check (Step 8).
//!
//! All three routes go through the standard `csrf_middleware` so the form
//! gets a CsrfToken in extensions and POST validation rejects mismatches.

use axum::Router;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;

use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::{CsrfToken, csrf_middleware};

use super::SignupState;
use super::auth_helpers::is_authenticated;

pub fn signup_routes(state: SignupState) -> Router {
    Router::new()
        .route("/signup", get(get_signup).post(post_signup))
        .route("/signup/slug-check", get(get_slug_check))
        .layer(axum::middleware::from_fn(csrf_middleware))
        .with_state(state)
}

async fn get_signup(
    State(state): State<SignupState>,
    csrf: CsrfToken,
    headers: HeaderMap,
) -> Result<Response, BrowserError> {
    if is_authenticated(&state.ath, &headers).await {
        return Ok(redirect_to("/"));
    }
    let html = render_signup_form(&state, csrf.as_str(), "", "", "", None)?;
    Ok(no_store(html.into_response()))
}

// post_signup + get_slug_check ship in Steps 8 + 9. For now, return a
// placeholder so the router shape compiles.
async fn post_signup(_state: State<SignupState>, _csrf: CsrfToken) -> Response {
    StatusCode::NOT_IMPLEMENTED.into_response()
}

async fn get_slug_check(_state: State<SignupState>) -> Response {
    StatusCode::NOT_IMPLEMENTED.into_response()
}

/// Render the signup form into a full HTML page.
fn render_signup_form(
    state: &SignupState,
    csrf_token: &str,
    email: &str,
    tenant_name: &str,
    slug: &str,
    error: Option<&str>,
) -> Result<axum::response::Html<String>, BrowserError> {
    let tmpl = state.templates.get_template("signup.html")?;
    let html = tmpl.render(minijinja::context! {
        csrf_token => csrf_token,
        email => email,
        tenant_name => tenant_name,
        slug => slug,
        error => error.unwrap_or(""),
    })?;
    Ok(axum::response::Html(html))
}

fn redirect_to(location: &str) -> Response {
    (
        StatusCode::SEE_OTHER,
        [(axum::http::header::LOCATION, location)],
    )
        .into_response()
}

/// Wrap a response with `Cache-Control: no-store, Pragma: no-cache`.
///
/// The signup form and the quickstart page both use this to prevent the
/// rendered secret bytes (and any other once-only state) from being
/// retained by shared caches or the browser bfcache.
pub(super) fn no_store(mut resp: Response) -> Response {
    let h = resp.headers_mut();
    h.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    h.insert(
        axum::http::header::PRAGMA,
        axum::http::HeaderValue::from_static("no-cache"),
    );
    resp
}
