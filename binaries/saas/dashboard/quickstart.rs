//! Dashboard quickstart page.
//!
//! - `GET /quickstart/{token}` — render the credentials + snippets page,
//!   gated on the dashboard session and a matching cache entry.
//! - `POST /quickstart/{token}/dismiss` — drop the cache entry, redirect
//!   home.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use allowthem_core::User;
use allowthem_core::types::UserId;
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::{CsrfToken, csrf_middleware};

use super::SignupState;
use super::quickstart_cache::QuickstartEntry;
use super::signup::no_store;

pub fn quickstart_routes(state: SignupState) -> Router {
    Router::new()
        .route(
            "/quickstart/{token}",
            get(get_quickstart),
        )
        .route(
            "/quickstart/{token}/dismiss",
            post(post_dismiss),
        )
        .layer(axum::middleware::from_fn(csrf_middleware))
        .with_state(state)
}

async fn get_quickstart(
    State(state): State<SignupState>,
    Path(token): Path<String>,
    csrf: CsrfToken,
    headers: HeaderMap,
) -> Result<Response, BrowserError> {
    let user = match current_dashboard_user(&state, &headers).await? {
        Some(u) => u,
        None => return Ok(redirect_to_login()),
    };
    let entry = match state.quickstart_cache.get(&token).await {
        Some(e) if e.dashboard_user_id == user.id => e,
        _ => return Ok(StatusCode::NOT_FOUND.into_response()),
    };

    let html = render_quickstart(&state, csrf.as_str(), &token, &entry)?;
    Ok(no_store(html.into_response()))
}

async fn post_dismiss(
    State(state): State<SignupState>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Result<Response, BrowserError> {
    let user = match current_dashboard_user(&state, &headers).await? {
        Some(u) => u,
        None => return Ok(redirect_to_login()),
    };
    // Bind dismiss to the session, like get_quickstart, so a stolen URL
    // can't wipe someone else's secret prematurely.
    if let Some(entry) = state.quickstart_cache.get(&token).await
        && entry.dashboard_user_id == user.id
    {
        state.quickstart_cache.evict(&token).await;
    }
    Ok((StatusCode::SEE_OTHER, [(header::LOCATION, "/")]).into_response())
}

/// Resolve the `Cookie` header on the request to a dashboard `User`, or
/// `None` if no valid session is present. Mirrors the logic in
/// `crates/server/extractors.rs:30-46` but inline so we don't take an
/// `Arc<dyn AuthClient>` dependency.
async fn current_dashboard_user(
    state: &SignupState,
    headers: &HeaderMap,
) -> Result<Option<User>, BrowserError> {
    let Some(cookie_header) = headers.get(header::COOKIE).and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    let Some(token) = state.ath.parse_session_cookie(cookie_header) else {
        return Ok(None);
    };
    let ttl = state.ath.session_config().ttl;
    let session = match state.ath.db().validate_session(&token, ttl).await? {
        Some(s) => s,
        None => return Ok(None),
    };
    let user_id: UserId = session.user_id;
    let user = state.ath.db().get_user(user_id).await?;
    Ok(Some(user))
}

fn render_quickstart(
    state: &SignupState,
    csrf_token: &str,
    token: &str,
    entry: &QuickstartEntry,
) -> Result<axum::response::Html<String>, BrowserError> {
    // Default app's redirect URI matches `provision_tenant`'s placeholder.
    let redirect_uri = "http://localhost/callback";
    let tmpl = state.templates.get_template("quickstart.html")?;
    let html = tmpl.render(minijinja::context! {
        csrf_token => csrf_token,
        token => token,
        slug => &entry.slug,
        issuer => &entry.issuer,
        client_id => &entry.client_id,
        client_secret => &entry.client_secret,
        redirect_uri => redirect_uri,
    })?;
    Ok(axum::response::Html(html))
}

fn redirect_to_login() -> Response {
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, "/login?next=/")],
    )
        .into_response()
}
