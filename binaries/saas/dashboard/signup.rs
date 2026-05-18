//! Dashboard signup flow.
//!
//! - `GET /signup` — render the signup form.
//! - `POST /signup` — process signup (lands in Step 9).
//! - `GET /signup/slug-check` — HTMX live availability check (Step 8).
//!
//! All three routes go through the standard `csrf_middleware` so the form
//! gets a CsrfToken in extensions and POST validation rejects mismatches.

use std::collections::HashMap;

use axum::Form;
use axum::Router;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use minijinja::Environment;
use serde::Deserialize;

use allowthem_core::Email;
use allowthem_core::error::AuthError;
use allowthem_saas::{
    DashboardSignupError, DashboardSignupParams, DashboardState, SaasError, TenantId,
    dashboard_signup, validate_slug,
};
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::{CsrfToken, csrf_middleware};

use super::QuickstartEntry;
use super::SignupState;
use super::auth_helpers::is_authenticated;

const MIN_PASSWORD_LEN: usize = 8;
const MAX_TENANT_NAME_LEN: usize = 80;

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

/// POST /signup — validate the form, run the cross-DB chain via
/// `dashboard_signup`, stash the new app's plaintext secret in the
/// quickstart cache, then redirect with the dashboard session cookie.
///
/// The cross-DB chain (create dashboard user → provision tenant → mint
/// session) lives in `crates/saas/dashboard.rs` (created by 99c.1). The
/// handler here is thin glue: validate the form, call the helper, on
/// success do the audit + cache stash + 303; on error map back to a
/// re-rendered form.
async fn post_signup(
    State(state): State<SignupState>,
    csrf: CsrfToken,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Response, BrowserError> {
    if is_authenticated(&state.ath, &headers).await {
        return Ok(redirect_to("/"));
    }

    // 1. Pull + cheap-validate fields. We don't echo password back.
    let email_raw = form.get("email").map(String::as_str).unwrap_or("").trim();
    let password = form.get("password").map(String::as_str).unwrap_or("");
    let password_confirm = form
        .get("password_confirm")
        .map(String::as_str)
        .unwrap_or("");
    let tenant_name = form
        .get("tenant_name")
        .map(String::as_str)
        .unwrap_or("")
        .trim();
    let slug = form
        .get("slug")
        .map(String::as_str)
        .unwrap_or("")
        .trim()
        .to_lowercase();

    if password != password_confirm {
        return form_err(
            &state,
            &csrf,
            email_raw,
            tenant_name,
            &slug,
            "Passwords do not match.",
        );
    }
    if password.len() < MIN_PASSWORD_LEN {
        return form_err(
            &state,
            &csrf,
            email_raw,
            tenant_name,
            &slug,
            "Password must be at least 8 characters.",
        );
    }
    if tenant_name.is_empty() || tenant_name.len() > MAX_TENANT_NAME_LEN {
        return form_err(
            &state,
            &csrf,
            email_raw,
            tenant_name,
            &slug,
            "Workspace name must be 1–80 characters.",
        );
    }
    if let Err(e) = validate_slug(&slug) {
        let msg = match e {
            SaasError::SlugReserved => "That workspace URL is reserved. Pick another.",
            SaasError::SlugInvalid(_) => {
                "Workspace URL must be 3–40 lowercase letters, digits, or `-`."
            }
            _ => "Invalid workspace URL.",
        };
        return form_err(&state, &csrf, email_raw, tenant_name, &slug, msg);
    }
    if Email::new(email_raw.to_string()).is_err() {
        return form_err(
            &state,
            &csrf,
            email_raw,
            tenant_name,
            &slug,
            "Enter a valid email.",
        );
    }

    // 2. Project SignupState → DashboardState and run the chain.
    let dashboard_state = DashboardState {
        ath: state.ath.clone(),
        control_db: state.control_db.clone(),
        tenant_data_dir: state.tenant_data_dir.clone(),
        tenant_config: state.tenant_config.clone(),
        handle_cache: state.handle_cache.clone(),
        is_production: state.is_production,
    };
    let result = match dashboard_signup(
        &dashboard_state,
        DashboardSignupParams {
            email: email_raw.to_string(),
            password: password.to_string(),
            tenant_name: tenant_name.to_string(),
            tenant_slug: slug.clone(),
        },
    )
    .await
    {
        Ok(r) => r,
        Err(DashboardSignupError::EmailTaken) => {
            return form_err(
                &state,
                &csrf,
                email_raw,
                tenant_name,
                &slug,
                "We can't create your account. If you already have one, log in.",
            );
        }
        Err(DashboardSignupError::InvalidEmail) => {
            return form_err(
                &state,
                &csrf,
                email_raw,
                tenant_name,
                &slug,
                "Enter a valid email.",
            );
        }
        Err(DashboardSignupError::ProvisionFailed(saas_err)) => {
            let msg = match saas_err {
                SaasError::SlugTaken => "That workspace URL was just taken. Pick another.",
                SaasError::SlugReserved => "That workspace URL is reserved. Pick another.",
                SaasError::SlugInvalid(_) => {
                    "Workspace URL must be 3–40 lowercase letters, digits, or `-`."
                }
                other => {
                    tracing::error!(error = %other, "dashboard_signup provision failure");
                    "We couldn't set up your workspace. Please try again."
                }
            };
            return form_err(&state, &csrf, email_raw, tenant_name, &slug, msg);
        }
        Err(DashboardSignupError::Auth(e)) => return Err(BrowserError::Auth(e)),
    };

    // 3. Convert the new tenant id (BLOB → UUID → TenantId) for the cache.
    let tenant_id = match result.provision.tenant.id_as_uuid().map(TenantId::from) {
        Some(t) => t,
        None => {
            return Err(BrowserError::Auth(AuthError::Validation(
                "tenant id was not a valid UUID".into(),
            )));
        }
    };

    // 4. Stash the quickstart entry. Plaintext secret lives in the cache only.
    let issuer = format!("https://{}.{}", slug, state.base_domain);
    let client_id = result.provision.client_id.clone();
    let entry = QuickstartEntry {
        dashboard_user_id: result.user.id,
        slug: slug.clone(),
        client_id: client_id.clone(),
        client_secret: result.provision.client_secret.as_str().to_owned(),
        issuer,
    };
    let token = state.quickstart_cache.put(entry).await;

    // 5. Audit (fire-and-forget; logged on failure).
    let ctx = serde_json::json!({
        "slug": slug,
        "name": tenant_name,
        "client_id": client_id,
    });
    if let Err(e) = state
        .control_db
        .log_control_audit(email_raw, "tenant.provisioned", Some(&tenant_id), &ctx)
        .await
    {
        tracing::error!(error = %e, "log_control_audit failed");
    }

    // 6. 303 to /quickstart/<token>, with the session cookie minted by the
    //    helper.
    let location = format!("/quickstart/{token}");
    Ok((
        StatusCode::SEE_OTHER,
        [
            (axum::http::header::SET_COOKIE, result.set_cookie),
            (axum::http::header::LOCATION, location),
        ],
    )
        .into_response())
}

/// Re-render the form with prior values + a flash message.
fn form_err(
    state: &SignupState,
    csrf: &CsrfToken,
    email: &str,
    tenant_name: &str,
    slug: &str,
    error: &str,
) -> Result<Response, BrowserError> {
    let html = render_signup_form(state, csrf.as_str(), email, tenant_name, slug, Some(error))?;
    Ok(no_store(html.into_response()))
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
