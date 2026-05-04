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

use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::{CsrfToken, csrf_middleware};

use super::SignupState;
use super::auth_helpers::current_dashboard_user;
use super::quickstart_cache::QuickstartEntry;
use super::signup::no_store;

pub fn quickstart_routes(state: SignupState) -> Router {
    Router::new()
        .route("/quickstart/{token}", get(get_quickstart))
        .route("/quickstart/{token}/dismiss", post(post_dismiss))
        .layer(axum::middleware::from_fn(csrf_middleware))
        .with_state(state)
}

async fn get_quickstart(
    State(state): State<SignupState>,
    Path(token): Path<String>,
    csrf: CsrfToken,
    headers: HeaderMap,
) -> Result<Response, BrowserError> {
    let user = match current_dashboard_user(&state.ath, &headers).await? {
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
    let user = match current_dashboard_user(&state.ath, &headers).await? {
        Some(u) => u,
        None => return Ok(redirect_to_login()),
    };
    // Bind dismiss to the session, like get_quickstart, so a stolen URL
    // can't wipe someone else's secret prematurely.
    let slug = if let Some(entry) = state.quickstart_cache.get(&token).await
        && entry.dashboard_user_id == user.id
    {
        let slug = entry.slug.clone();
        state.quickstart_cache.evict(&token).await;
        slug
    } else {
        // Token not found or belongs to another user; fall back to the
        // tenant list rather than leaving the user stranded at root.
        return Ok(
            (StatusCode::SEE_OTHER, [(header::LOCATION, "/signup")]).into_response(),
        );
    };
    Ok((
        StatusCode::SEE_OTHER,
        [(header::LOCATION, format!("/t/{slug}/applications"))],
    )
        .into_response())
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
        base_domain => &state.base_domain,
        client_id => &entry.client_id,
        client_secret => &entry.client_secret,
        redirect_uri => redirect_uri,
    })?;
    Ok(axum::response::Html(html))
}

fn redirect_to_login() -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, "/login?next=/")]).into_response()
}
