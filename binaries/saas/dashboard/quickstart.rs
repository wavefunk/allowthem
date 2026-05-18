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
use super::views::{self, QuickstartPageView, QuickstartSnippetView};

struct QuickstartSnippet {
    label: &'static str,
    code: String,
    language: &'static str,
    active: bool,
}

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

    let html = render_quickstart(&state, csrf.as_str(), &token, &entry, user.email.as_str())?;
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
        return Ok((StatusCode::SEE_OTHER, [(header::LOCATION, "/signup")]).into_response());
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
    status_session: &str,
) -> Result<axum::response::Html<String>, BrowserError> {
    // Default app's redirect URI matches `provision_tenant`'s placeholder.
    let redirect_uri = "http://localhost/callback";
    let snippet_tabs = quickstart_snippets(state, entry, redirect_uri);
    let snippets: Vec<QuickstartSnippetView<'_>> = snippet_tabs
        .iter()
        .map(|snippet| QuickstartSnippetView {
            label: snippet.label,
            code: snippet.code.as_str(),
            language: snippet.language,
            active: snippet.active,
        })
        .collect();
    views::quickstart_page(&QuickstartPageView {
        csrf_token,
        token,
        slug: &entry.slug,
        issuer: &entry.issuer,
        base_domain: &state.base_domain,
        client_id: &entry.client_id,
        client_secret: &entry.client_secret,
        redirect_uri,
        snippets: &snippets,
        status_session: Some(status_session),
        is_production: state.is_production,
    })
}

fn quickstart_snippets(
    state: &SignupState,
    entry: &QuickstartEntry,
    redirect_uri: &str,
) -> Vec<QuickstartSnippet> {
    let curl = [
        "# Discover the OIDC config".to_owned(),
        format!("curl {}/.well-known/openid-configuration", entry.issuer),
        String::new(),
        "Exchange an authorization code for tokens after capturing the callback code".to_owned(),
        format!("curl -X POST {}/oauth/token \\", entry.issuer),
        format!("  -u '{}:{}' \\", entry.client_id, entry.client_secret),
        "  -d 'grant_type=authorization_code' \\".to_owned(),
        "  -d 'code=<CODE_FROM_REDIRECT>' \\".to_owned(),
        format!("  -d 'redirect_uri={redirect_uri}'"),
    ]
    .join("\n");

    let browser = [
        "// Browser — PKCE authorization code flow".to_owned(),
        "import { createAllowthemClient } from '@allowthem/js';".to_owned(),
        String::new(),
        "const auth = createAllowthemClient({".to_owned(),
        format!("  domain: '{}.{}',", entry.slug, state.base_domain),
        format!("  clientId: '{}',", entry.client_id),
        "  redirectUri: window.location.origin + '/callback',".to_owned(),
        "});".to_owned(),
        String::new(),
        "await auth.loginWithRedirect();".to_owned(),
    ]
    .join("\n");

    let server = [
        "// Server — verify access tokens via JWKS".to_owned(),
        "import { createAllowthemVerifier } from '@allowthem/js/server';".to_owned(),
        String::new(),
        "const verifier = createAllowthemVerifier({".to_owned(),
        format!("  issuer: '{}',", entry.issuer),
        format!("  audience: '{}',", entry.client_id),
        "});".to_owned(),
        String::new(),
        "const claims = await verifier.verify(accessToken);".to_owned(),
    ]
    .join("\n");

    let rust = [
        "// Rust — confidential client".to_owned(),
        "use allowthem_client::AllowthemClient;".to_owned(),
        String::new(),
        "let client = AllowthemClient::builder()".to_owned(),
        format!("    .issuer(\"{}\")", entry.issuer),
        format!("    .client_id(\"{}\")", entry.client_id),
        format!("    .client_secret(\"{}\")", entry.client_secret),
        "    .build()".to_owned(),
        "    .await?;".to_owned(),
    ]
    .join("\n");

    vec![
        QuickstartSnippet {
            label: "curl",
            code: curl,
            language: "shell",
            active: true,
        },
        QuickstartSnippet {
            label: "Browser (JS/TS)",
            code: browser,
            language: "typescript",
            active: false,
        },
        QuickstartSnippet {
            label: "Server (JS/TS)",
            code: server,
            language: "typescript",
            active: false,
        },
        QuickstartSnippet {
            label: "Rust",
            code: rust,
            language: "rust",
            active: false,
        },
    ]
}

fn redirect_to_login() -> Response {
    (StatusCode::SEE_OTHER, [(header::LOCATION, "/login?next=/")]).into_response()
}
