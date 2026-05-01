//! Dashboard signup flow.
//!
//! - `GET /signup` — render the signup form.
//! - `POST /signup` — process signup (lands in Step 9).
//! - `GET /signup/slug-check` — HTMX live availability check (Step 8).
//!
//! All three routes go through the standard `csrf_middleware` so the form
//! gets a CsrfToken in extensions and POST validation rejects mismatches.

use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use minijinja::Environment;
use serde::Deserialize;

use allowthem_core::error::AuthError;
use allowthem_saas::{SaasError, validate_slug};
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

#[derive(Deserialize)]
struct SlugCheckQuery {
    slug: String,
}

/// HTMX-driven live slug availability check. Returns a small fragment
/// (green check / red error). Server-side validation on POST is the
/// source of truth — this is a UX hint, never security.
async fn get_slug_check(
    State(state): State<SignupState>,
    Query(q): Query<SlugCheckQuery>,
) -> Result<Response, BrowserError> {
    let slug = q.slug.trim().to_lowercase();
    let env = state.templates.as_ref();

    // `validate_slug` already checks the reserved list internally
    // (crates/saas/tenants.rs:17-19), so one call covers format + reserved.
    let html = match validate_slug(&slug) {
        Err(SaasError::SlugReserved) => render_slug_err(env, "Reserved")?,
        Err(SaasError::SlugInvalid(_)) => {
            render_slug_err(env, "Use 3–40 lowercase letters, digits, or `-`")?
        }
        Err(other) => return Err(saas_to_browser_error(other)),
        Ok(()) => match state.control_db.tenant_by_slug(&slug).await {
            Ok(Some(_)) => render_slug_err(env, "Already taken")?,
            Ok(None) => render_slug_ok(env, &slug)?,
            Err(e) => return Err(saas_to_browser_error(e)),
        },
    };
    Ok(html.into_response())
}

fn render_slug_ok(
    env: &Environment<'static>,
    slug: &str,
) -> Result<axum::response::Html<String>, BrowserError> {
    let tmpl = env.get_template("_partials/_slug_check_ok.html")?;
    let html = tmpl.render(minijinja::context! { slug => slug })?;
    Ok(axum::response::Html(html))
}

fn render_slug_err(
    env: &Environment<'static>,
    msg: &str,
) -> Result<axum::response::Html<String>, BrowserError> {
    let tmpl = env.get_template("_partials/_slug_check_err.html")?;
    let html = tmpl.render(minijinja::context! { msg => msg })?;
    Ok(axum::response::Html(html))
}

/// Bridge a `SaasError` into the existing `BrowserError` types without
/// modifying `crates/server`. `BrowserError::Auth(AuthError::Validation(_))`
/// renders as a 422 page; that's the closest user-facing fit for a
/// non-Slug Saas error reaching this handler.
fn saas_to_browser_error(err: SaasError) -> BrowserError {
    BrowserError::Auth(AuthError::Validation(err.to_string()))
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
