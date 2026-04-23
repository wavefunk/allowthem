use std::sync::Arc;

use axum::Form;
use axum::Router;
use axum::extract::{Extension, Query};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::Uri;
use axum::http::header::{LOCATION, SET_COOKIE, USER_AGENT};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use chrono::Utc;
use minijinja::{Environment, context};
use serde::Deserialize;

use allowthem_core::applications::BrandingConfig;
use allowthem_core::totp::totp_uri;
use allowthem_core::{AllowThem, AuditEvent, AuthError, sessions};

use crate::branding::{DefaultBranding, branding_context, default_branding_ref, resolve_branding};
use crate::browser_error::BrowserError;
use crate::csrf::CsrfToken;
use crate::error::BrowserAuthRedirect;

/// Error shown when a wrong TOTP code is entered during MFA setup confirmation.
const SETUP_INVALID_CODE: &str = "Invalid TOTP code";

/// Error shown when a wrong TOTP code is entered on the MFA challenge page.
const CHALLENGE_INVALID_TOTP: &str = "Invalid TOTP or recovery code";

/// Error shown when a wrong recovery code is entered on the MFA challenge page.
const CHALLENGE_INVALID_RECOVERY: &str = "Invalid recovery code";

#[derive(Clone)]
struct MfaPageConfig {
    templates: Arc<Environment<'static>>,
    is_production: bool,
    base_url: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
}

/// Extract the host from a base URL for use as the TOTP issuer.
///
/// Strips the scheme and path, and also strips the port (the totp-rs
/// library rejects issuer strings containing colons).
fn derive_issuer(base_url: &str) -> String {
    base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("allowthem")
        .split(':')
        .next()
        .unwrap_or("allowthem")
        .to_string()
}

/// Validate session cookie and return the authenticated user.
///
/// On failure, returns a 303 redirect to `/login?next={path}` — matching
/// `BrowserAuthUser` rejection semantics without requiring `Arc<dyn AuthClient>`
/// in the router state.
async fn require_browser_user(
    ath: &AllowThem,
    headers: &HeaderMap,
    path: &str,
) -> Result<allowthem_core::types::User, Response> {
    let cookie_header = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| BrowserAuthRedirect::new(path).into_response())?;

    let token = ath
        .parse_session_cookie(cookie_header)
        .ok_or_else(|| BrowserAuthRedirect::new(path).into_response())?;

    let ttl = ath.session_config().ttl;
    let session = ath
        .db()
        .validate_session(&token, ttl)
        .await
        .map_err(|err| {
            tracing::error!("session validation error: {err}");
            BrowserAuthRedirect::new(path).into_response()
        })?
        .ok_or_else(|| BrowserAuthRedirect::new(path).into_response())?;

    match ath.db().get_user(session.user_id).await {
        Ok(user) if user.is_active => Ok(user),
        Ok(_) => Err(BrowserAuthRedirect::new(path).into_response()),
        Err(AuthError::NotFound) => Err(BrowserAuthRedirect::new(path).into_response()),
        Err(err) => {
            tracing::error!("user lookup error: {err}");
            Err(BrowserAuthRedirect::new(path).into_response())
        }
    }
}

// ---------------------------------------------------------------------------
// Setup-side routes (authenticated, CSRF-protected)
// ---------------------------------------------------------------------------

/// Render just the `_auth_main_mfa_setup.html` partial plus the
/// `_auth_oob_head.html` OOB head swap, for HTMX fragment responses.
///
/// The `.wf-note` style used by the TOTP info box lives in the shell's
/// `<head>` `<style>` block. Fragment responses don't update `<head>`,
/// but mfa_setup is always reached from an authenticated /settings page,
/// so the full page (and its head styles) loads before any HX swap.
fn render_mfa_setup_fragment(
    config: &MfaPageConfig,
    csrf_token: &str,
    totp_uri: &str,
    secret: &str,
    error: &str,
    branding: Option<&BrandingConfig>,
) -> Result<axum::response::Html<String>, BrowserError> {
    let ctx = context! {
        csrf_token,
        totp_uri,
        secret,
        error,
        is_production => config.is_production,
        page_title => "Set up two-factor authentication — allowthem",
        status_hint => "ENABLE 2FA",
        ..branding_context(branding),
    };

    let main = crate::browser_templates::render(
        &config.templates,
        "_partials/_auth_main_mfa_setup.html",
        ctx.clone(),
    )?;
    let oob =
        crate::browser_templates::render(&config.templates, "_partials/_auth_oob_head.html", ctx)?;
    Ok(axum::response::Html(format!("{}{}", main.0, oob.0)))
}

/// Render just the `_auth_main_mfa_recovery.html` partial plus the
/// `_auth_oob_head.html` OOB head swap, for HTMX fragment responses.
///
/// The `.wf-recovery-grid` layout is scoped to the partial via an inline
/// `<style>` (too specific to promote into `kit.css`), so unlike the setup
/// and challenge flows, this fragment carries its own grid styles and is
/// safe even if it's ever swapped into a context that hasn't loaded the
/// full shell head.
fn render_mfa_recovery_fragment(
    config: &MfaPageConfig,
    recovery_codes: &[String],
    branding: Option<&BrandingConfig>,
) -> Result<axum::response::Html<String>, BrowserError> {
    let ctx = context! {
        recovery_codes,
        is_production => config.is_production,
        page_title => "Recovery codes — allowthem",
        status_hint => "RECOVERY CODES",
        ..branding_context(branding),
    };

    let main = crate::browser_templates::render(
        &config.templates,
        "_partials/_auth_main_mfa_recovery.html",
        ctx.clone(),
    )?;
    let oob =
        crate::browser_templates::render(&config.templates, "_partials/_auth_oob_head.html", ctx)?;
    Ok(axum::response::Html(format!("{}{}", main.0, oob.0)))
}

/// GET /settings/mfa/setup — show QR URI, base32 secret, and TOTP code input.
///
/// Idempotent: if a pending (non-enabled) secret exists, reuses it.
/// Only creates a new secret on first visit.
async fn get_mfa_setup(
    Extension(ath): Extension<AllowThem>,
    Extension(config): Extension<MfaPageConfig>,
    default_branding: Option<Extension<Arc<DefaultBranding>>>,
    uri: Uri,
    csrf: CsrfToken,
    headers: HeaderMap,
) -> Result<Response, BrowserError> {
    let user = match require_browser_user(&ath, &headers, uri.path()).await {
        Ok(u) => u,
        Err(redirect) => return Ok(redirect),
    };

    let default = default_branding_ref(&default_branding);
    let branding = resolve_branding(&ath, None, default).await;

    // Reuse pending secret if one exists; create only on first visit
    let secret = match ath.get_pending_mfa_secret(user.id).await? {
        Some(s) => s,
        None => ath.create_mfa_secret(user.id).await?,
    };

    let issuer = derive_issuer(&config.base_url);
    let uri = totp_uri(&secret, user.email.as_str(), &issuer);

    if crate::hx::is_hx_request(&headers) {
        let html = render_mfa_setup_fragment(
            &config,
            csrf.as_str(),
            &uri,
            &secret,
            "",
            branding.as_ref(),
        )?;
        return Ok(html.into_response());
    }

    let html = crate::browser_templates::render(
        &config.templates,
        "mfa_setup.html",
        context! {
            csrf_token => csrf.as_str(),
            secret => &secret,
            totp_uri => &uri,
            error => "",
            is_production => config.is_production,
            ..branding_context(branding.as_ref()),
        },
    )?;
    Ok(html.into_response())
}

#[derive(Deserialize)]
pub struct MfaConfirmForm {
    code: String,
    #[allow(dead_code)]
    csrf_token: String,
}

/// POST /settings/mfa/confirm — verify TOTP code and enable MFA.
///
/// On success, renders recovery codes page directly (no redirect).
/// On failure, re-renders setup page with error.
async fn post_mfa_confirm(
    Extension(ath): Extension<AllowThem>,
    Extension(config): Extension<MfaPageConfig>,
    default_branding: Option<Extension<Arc<DefaultBranding>>>,
    uri: Uri,
    csrf: CsrfToken,
    headers: HeaderMap,
    Form(form): Form<MfaConfirmForm>,
) -> Result<Response, BrowserError> {
    let user = match require_browser_user(&ath, &headers, uri.path()).await {
        Ok(u) => u,
        Err(redirect) => return Ok(redirect),
    };

    let default = default_branding_ref(&default_branding);
    let branding = resolve_branding(&ath, None, default).await;

    let ip = client_ip(&headers);
    let ua = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());

    match ath.enable_mfa(user.id, &form.code).await {
        Ok(recovery_codes) => {
            let _ = ath
                .db()
                .log_audit(
                    AuditEvent::MfaEnabled,
                    Some(&user.id),
                    None,
                    ip.as_deref(),
                    ua,
                    None,
                )
                .await;

            if crate::hx::is_hx_request(&headers) {
                let html =
                    render_mfa_recovery_fragment(&config, &recovery_codes, branding.as_ref())?;
                return Ok(html.into_response());
            }

            let html = crate::browser_templates::render(
                &config.templates,
                "mfa_recovery.html",
                context! {
                    recovery_codes => &recovery_codes,
                    is_production => config.is_production,
                    ..branding_context(branding.as_ref()),
                },
            )?;
            Ok(html.into_response())
        }
        Err(allowthem_core::AuthError::InvalidTotpCode) => {
            // Re-render setup page with error
            let secret = ath
                .get_pending_mfa_secret(user.id)
                .await?
                .unwrap_or_default();
            let issuer = derive_issuer(&config.base_url);
            let uri = totp_uri(&secret, user.email.as_str(), &issuer);

            let html = crate::browser_templates::render(
                &config.templates,
                "mfa_setup.html",
                context! {
                    csrf_token => csrf.as_str(),
                    secret => &secret,
                    totp_uri => &uri,
                    error => SETUP_INVALID_CODE,
                    is_production => config.is_production,
                    ..branding_context(branding.as_ref()),
                },
            )?;
            Ok(html.into_response())
        }
        Err(e) => Err(BrowserError::Auth(e)),
    }
}

#[derive(Deserialize)]
pub struct MfaDisableForm {
    #[allow(dead_code)]
    csrf_token: String,
}

/// POST /settings/mfa/disable — disable MFA and redirect to settings.
async fn post_mfa_disable(
    Extension(ath): Extension<AllowThem>,
    uri: Uri,
    headers: HeaderMap,
    Form(_form): Form<MfaDisableForm>,
) -> Result<Response, BrowserError> {
    let user = match require_browser_user(&ath, &headers, uri.path()).await {
        Ok(u) => u,
        Err(redirect) => return Ok(redirect),
    };

    let ip = client_ip(&headers);
    let ua = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());

    ath.disable_mfa(user.id).await?;

    let _ = ath
        .db()
        .log_audit(
            AuditEvent::MfaDisabled,
            Some(&user.id),
            None,
            ip.as_deref(),
            ua,
            None,
        )
        .await;

    Ok((StatusCode::SEE_OTHER, [(LOCATION, "/settings".to_string())]).into_response())
}

// ---------------------------------------------------------------------------
// Challenge routes (mid-login, no session — outside CSRF layer)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ChallengeQuery {
    token: String,
}

/// Render just the `_auth_main_mfa_challenge.html` partial plus the
/// `_auth_oob_head.html` OOB head swap, for HTMX fragment responses.
///
/// The CSS-only recovery-code toggle's `<style>` lives in the shell's
/// `<head>`. Fragment responses don't update `<head>`, but mfa_challenge
/// is always reached mid-flow from /login, so the full page (and its
/// head styles) loads before any HX swap; re-rendering via fragment
/// on errors is safe because the styles are already in the document.
fn render_mfa_challenge_fragment(
    config: &MfaPageConfig,
    mfa_token: &str,
    error: &str,
    branding: Option<&BrandingConfig>,
) -> Result<axum::response::Html<String>, BrowserError> {
    let ctx = context! {
        mfa_token,
        error,
        is_production => config.is_production,
        page_title => "Two-factor authentication — allowthem",
        status_hint => "TWO-FACTOR",
        ..branding_context(branding),
    };

    let main = crate::browser_templates::render(
        &config.templates,
        "_partials/_auth_main_mfa_challenge.html",
        ctx.clone(),
    )?;
    let oob =
        crate::browser_templates::render(&config.templates, "_partials/_auth_oob_head.html", ctx)?;
    Ok(axum::response::Html(format!("{}{}", main.0, oob.0)))
}

/// GET /mfa/challenge — render TOTP code input form.
async fn get_mfa_challenge(
    Extension(ath): Extension<AllowThem>,
    Extension(config): Extension<MfaPageConfig>,
    default_branding: Option<Extension<Arc<DefaultBranding>>>,
    headers: HeaderMap,
    Query(query): Query<ChallengeQuery>,
) -> Result<Response, BrowserError> {
    // Validate token is still alive (don't consume it)
    let user_id = ath.db().validate_mfa_challenge(&query.token).await?;
    if user_id.is_none() {
        // Invalid or expired token — redirect to login
        return Ok((StatusCode::SEE_OTHER, [(LOCATION, "/login".to_string())]).into_response());
    }

    let default = default_branding_ref(&default_branding);
    let branding = resolve_branding(&ath, None, default).await;

    if crate::hx::is_hx_request(&headers) {
        let html = render_mfa_challenge_fragment(&config, &query.token, "", branding.as_ref())?;
        return Ok(html.into_response());
    }

    let html = crate::browser_templates::render(
        &config.templates,
        "mfa_challenge.html",
        context! {
            mfa_token => &query.token,
            error => "",
            is_production => config.is_production,
            ..branding_context(branding.as_ref()),
        },
    )?;
    Ok(html.into_response())
}

#[derive(Deserialize)]
pub struct MfaChallengeForm {
    mfa_token: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    recovery_code: Option<String>,
    #[serde(default)]
    use_recovery: Option<String>,
}

/// POST /mfa/challenge — verify TOTP code or recovery code, create session.
async fn post_mfa_challenge(
    Extension(ath): Extension<AllowThem>,
    Extension(config): Extension<MfaPageConfig>,
    default_branding: Option<Extension<Arc<DefaultBranding>>>,
    headers: HeaderMap,
    Form(form): Form<MfaChallengeForm>,
) -> Result<Response, BrowserError> {
    let default = default_branding_ref(&default_branding);
    let branding = resolve_branding(&ath, None, default).await;
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string());
    let ua = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());

    // 1. Validate challenge token
    let user_id = match ath.db().validate_mfa_challenge(&form.mfa_token).await? {
        Some(uid) => uid,
        None => {
            return Ok((StatusCode::SEE_OTHER, [(LOCATION, "/login".to_string())]).into_response());
        }
    };

    // 2. Branch: recovery code vs TOTP
    let use_recovery = form.use_recovery.is_some();
    let verified = if use_recovery {
        let code = form.recovery_code.as_deref().unwrap_or("");
        ath.verify_recovery_code(user_id, code).await?
    } else {
        let code = form.code.as_deref().unwrap_or("");
        ath.verify_totp(user_id, code).await?
    };

    if !verified {
        // Log failure
        let _ = ath
            .db()
            .log_audit(
                AuditEvent::MfaChallengeFailed,
                Some(&user_id),
                None,
                ip.as_deref(),
                ua,
                None,
            )
            .await;

        let error_msg = if use_recovery {
            CHALLENGE_INVALID_RECOVERY
        } else {
            CHALLENGE_INVALID_TOTP
        };

        let html = crate::browser_templates::render(
            &config.templates,
            "mfa_challenge.html",
            context! {
                mfa_token => &form.mfa_token,
                error => error_msg,
                is_production => config.is_production,
                ..branding_context(branding.as_ref()),
            },
        )?;
        return Ok(html.into_response());
    }

    // 3. Success: consume challenge, create session
    ath.db().consume_mfa_challenge(&form.mfa_token).await?;

    let _ = ath
        .db()
        .log_audit(
            AuditEvent::MfaChallengeSuccess,
            Some(&user_id),
            None,
            ip.as_deref(),
            ua,
            None,
        )
        .await;

    // Emit Login to maintain the invariant that every session creation
    // produces a Login audit event, consistent with the non-MFA login path.
    let _ = ath
        .db()
        .log_audit(
            AuditEvent::Login,
            Some(&user_id),
            None,
            ip.as_deref(),
            ua,
            None,
        )
        .await;

    let token = sessions::generate_token();
    let token_hash = sessions::hash_token(&token);
    let ttl = ath.session_config().ttl;
    let expires_at = Utc::now() + ttl;
    ath.db()
        .create_session(user_id, token_hash, ip.as_deref(), ua, expires_at)
        .await?;

    let cookie = ath.session_cookie(&token);

    Ok((
        StatusCode::SEE_OTHER,
        [(SET_COOKIE, cookie), (LOCATION, "/".to_string())],
    )
        .into_response())
}

// ---------------------------------------------------------------------------
// Public router constructors
// ---------------------------------------------------------------------------

/// Build a router for MFA setup routes (authenticated, CSRF-protected).
///
/// Mounts:
/// - GET  /settings/mfa/setup
/// - POST /settings/mfa/confirm
/// - POST /settings/mfa/disable
pub fn mfa_setup_routes(
    templates: Arc<Environment<'static>>,
    is_production: bool,
    base_url: String,
) -> Router<()> {
    let cfg = MfaPageConfig {
        templates,
        is_production,
        base_url,
    };
    Router::new()
        .route("/settings/mfa/setup", get(get_mfa_setup))
        .route("/settings/mfa/confirm", post(post_mfa_confirm))
        .route("/settings/mfa/disable", post(post_mfa_disable))
        .layer(Extension(cfg))
}

/// Build a router for the MFA challenge route (mid-login, no session).
///
/// Mounts:
/// - GET  /mfa/challenge
/// - POST /mfa/challenge
pub fn mfa_challenge_routes(
    templates: Arc<Environment<'static>>,
    is_production: bool,
) -> Router<()> {
    let cfg = MfaPageConfig {
        templates,
        is_production,
        base_url: String::new(),
    };
    Router::new()
        .route(
            "/mfa/challenge",
            get(get_mfa_challenge).post(post_mfa_challenge),
        )
        .layer(Extension(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use chrono::{Duration, Utc};
    use totp_rs::{Algorithm, Secret, TOTP};
    use tower::ServiceExt;

    use allowthem_core::{AllowThemBuilder, Email, generate_token, hash_token};

    const TEST_MFA_KEY: [u8; 32] = [0x42; 32];

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    async fn setup() -> AllowThem {
        AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .mfa_key(TEST_MFA_KEY)
            .csrf_key(*b"test-csrf-key-for-binary-tests!!")
            .build()
            .await
            .unwrap()
    }

    /// Build a router that exercises only the MFA routes (no login).
    /// Setup-side routes are CSRF-protected; challenge routes are not.
    fn test_app(ath: AllowThem) -> Router {
        let templates = crate::browser_templates::build_default_browser_env();
        Router::new()
            .merge(mfa_setup_routes(
                templates.clone(),
                false,
                "http://127.0.0.1:3100".into(),
            ))
            .layer(axum::middleware::from_fn(crate::csrf::csrf_middleware))
            .merge(mfa_challenge_routes(templates, false))
            .layer(axum::middleware::from_fn_with_state(
                ath.clone(),
                crate::cors::inject_ath_into_extensions,
            ))
    }

    async fn create_session(ath: &AllowThem) -> (allowthem_core::types::UserId, String) {
        let email = Email::new("mfa-test@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "pass", None, None)
            .await
            .unwrap();
        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = Utc::now() + Duration::hours(24);
        ath.db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();
        let cookie = ath.session_cookie(&token);
        let cookie_val = cookie.split(';').next().unwrap().to_string();
        (user.id, cookie_val)
    }

    /// Acquire a CSRF token by hitting the setup GET endpoint and parsing it from HTML.
    async fn get_csrf(app: &Router, session_cookie: &str) -> String {
        let req = Request::builder()
            .uri("/settings/mfa/setup")
            .header(header::COOKIE, session_cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(bytes.to_vec()).unwrap();
        let marker = "name=\"csrf_token\" value=\"";
        let start = html.find(marker).expect("csrf_token not found in HTML") + marker.len();
        let end = html[start..].find('"').unwrap() + start;
        html[start..end].to_string()
    }

    /// Create a user with MFA enabled. Returns (totp, recovery_codes).
    async fn enable_mfa_for_user(
        ath: &AllowThem,
        user_id: allowthem_core::types::UserId,
    ) -> (TOTP, Vec<String>) {
        let secret_b32 = ath.create_mfa_secret(user_id).await.unwrap();
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(secret_b32).to_bytes().unwrap(),
            None,
            String::new(),
        )
        .unwrap();
        let code = totp.generate_current().unwrap();
        let recovery_codes = ath.enable_mfa(user_id, &code).await.unwrap();
        (totp, recovery_codes)
    }

    // ---------------------------------------------------------------------------
    // derive_issuer — pure function, no I/O
    // ---------------------------------------------------------------------------

    #[test]
    fn derive_issuer_strips_http_scheme() {
        assert_eq!(derive_issuer("http://example.com"), "example.com");
    }

    #[test]
    fn derive_issuer_strips_https_scheme() {
        assert_eq!(
            derive_issuer("https://auth.example.com"),
            "auth.example.com"
        );
    }

    #[test]
    fn derive_issuer_strips_port() {
        // totp-rs rejects issuer strings containing colons; port must be removed.
        assert_eq!(derive_issuer("http://127.0.0.1:3100"), "127.0.0.1");
    }

    #[test]
    fn derive_issuer_strips_path() {
        assert_eq!(
            derive_issuer("https://auth.example.com/some/path"),
            "auth.example.com"
        );
    }

    // ---------------------------------------------------------------------------
    // GET /settings/mfa/setup — idempotency
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn get_mfa_setup_renders_secret() {
        let ath = setup().await;
        let app = test_app(ath.clone());
        let (_, cookie) = create_session(&ath).await;

        let csrf = get_csrf(&app, &cookie).await;
        let req = Request::builder()
            .uri("/settings/mfa/setup")
            .header(header::COOKIE, format!("{cookie}; csrf_token={csrf}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            html.contains("totp-secret"),
            "setup page must show secret element"
        );
        // The totp_uri value is HTML-escaped by MiniJinja; check the testid container exists.
        assert!(
            html.contains("totp-uri"),
            "setup page must show QR URI container"
        );
    }

    #[tokio::test]
    async fn get_mfa_setup_is_idempotent() {
        // Two GETs must return the same secret so wrong-code-then-retry works.
        let ath = setup().await;
        let app = test_app(ath.clone());
        let (_, cookie) = create_session(&ath).await;
        let csrf = get_csrf(&app, &cookie).await;

        let secret_of = |html: String| -> String {
            // Extract the text content of the <code data-testid="totp-secret"> element.
            // The template renders the element with additional class attributes before >,
            // so split on the data-testid attribute value then find the closing > to skip
            // all attributes, then read up to </code>.
            let after_attr = html
                .split("data-testid=\"totp-secret\"")
                .nth(1)
                .expect("totp-secret element not found in HTML");
            let after_tag_close = after_attr
                .splitn(2, '>')
                .nth(1)
                .expect("closing > of totp-secret element not found");
            after_tag_close.split('<').next().unwrap_or("").to_string()
        };

        let req1 = Request::builder()
            .uri("/settings/mfa/setup")
            .header(header::COOKIE, format!("{cookie}; csrf_token={csrf}"))
            .body(Body::empty())
            .unwrap();
        let resp1 = app.clone().oneshot(req1).await.unwrap();
        let html1 = String::from_utf8(
            axum::body::to_bytes(resp1.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        let req2 = Request::builder()
            .uri("/settings/mfa/setup")
            .header(header::COOKIE, format!("{cookie}; csrf_token={csrf}"))
            .body(Body::empty())
            .unwrap();
        let resp2 = app.clone().oneshot(req2).await.unwrap();
        let html2 = String::from_utf8(
            axum::body::to_bytes(resp2.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();

        assert_eq!(
            secret_of(html1),
            secret_of(html2),
            "repeated GET /settings/mfa/setup must return the same pending secret"
        );
    }

    // ---------------------------------------------------------------------------
    // POST /settings/mfa/confirm
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn post_mfa_confirm_invalid_code_shows_error_and_does_not_enable() {
        let ath = setup().await;
        let app = test_app(ath.clone());
        let (user_id, cookie) = create_session(&ath).await;

        // Trigger secret creation via GET (idempotency path)
        let csrf = get_csrf(&app, &cookie).await;

        let body_str = format!("code=000000&csrf_token={csrf}");
        let req = Request::builder()
            .method("POST")
            .uri("/settings/mfa/confirm")
            .header(header::COOKIE, format!("{cookie}; csrf_token={csrf}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body_str))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let html = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            html.contains(SETUP_INVALID_CODE),
            "wrong code must show setup error"
        );
        assert!(
            !ath.has_mfa_enabled(user_id).await.unwrap(),
            "MFA must not be enabled after wrong code"
        );
    }

    #[tokio::test]
    async fn post_mfa_confirm_valid_code_enables_mfa_and_renders_recovery_codes() {
        let ath = setup().await;
        let app = test_app(ath.clone());
        let (user_id, cookie) = create_session(&ath).await;

        let csrf = get_csrf(&app, &cookie).await;

        // Create and retrieve the pending secret
        let secret = ath.create_mfa_secret(user_id).await.unwrap();
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(secret).to_bytes().unwrap(),
            None,
            String::new(),
        )
        .unwrap();
        let code = totp.generate_current().unwrap();

        let body_str = format!("code={code}&csrf_token={csrf}");
        let req = Request::builder()
            .method("POST")
            .uri("/settings/mfa/confirm")
            .header(header::COOKIE, format!("{cookie}; csrf_token={csrf}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body_str))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let html = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            html.contains("recovery-code"),
            "success must render recovery codes"
        );
        assert!(
            ath.has_mfa_enabled(user_id).await.unwrap(),
            "MFA must be enabled after valid confirm"
        );
    }

    // ---------------------------------------------------------------------------
    // POST /settings/mfa/disable
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn post_mfa_disable_removes_mfa_and_redirects() {
        let ath = setup().await;
        let app = test_app(ath.clone());
        let (user_id, cookie) = create_session(&ath).await;
        enable_mfa_for_user(&ath, user_id).await;

        // Derive CSRF token from the session token (HMAC path — no Set-Cookie on GET).
        let session_token_val = cookie.split('=').nth(1).unwrap().to_string();
        let session_token = allowthem_core::types::SessionToken::from_encoded(session_token_val);
        let csrf =
            allowthem_core::derive_csrf_token(&session_token, b"test-csrf-key-for-binary-tests!!");

        let body_str = format!("csrf_token={csrf}");
        let req = Request::builder()
            .method("POST")
            .uri("/settings/mfa/disable")
            .header(header::COOKIE, &cookie)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body_str))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/settings");
        assert!(
            !ath.has_mfa_enabled(user_id).await.unwrap(),
            "MFA must be disabled after disable POST"
        );
    }

    // ---------------------------------------------------------------------------
    // GET /mfa/challenge
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn get_mfa_challenge_with_invalid_token_redirects_to_login() {
        let ath = setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/mfa/challenge?token=not-a-real-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/login");
    }

    #[tokio::test]
    async fn get_mfa_challenge_with_valid_token_renders_form() {
        let ath = setup().await;
        let app = test_app(ath.clone());
        let (user_id, _) = create_session(&ath).await;
        enable_mfa_for_user(&ath, user_id).await;

        let token = ath.db().create_mfa_challenge(user_id).await.unwrap();
        let req = Request::builder()
            .uri(format!("/mfa/challenge?token={token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let html = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            html.contains("name=\"code\""),
            "challenge form must have code input"
        );
        assert!(
            html.contains("mfa_token"),
            "challenge form must embed mfa_token hidden field"
        );
    }

    #[tokio::test]
    async fn get_mfa_challenge_hx_request_returns_fragment() {
        let ath = setup().await;
        let app = test_app(ath.clone());
        let (user_id, _) = create_session(&ath).await;
        enable_mfa_for_user(&ath, user_id).await;

        let token = ath.db().create_mfa_challenge(user_id).await.unwrap();
        let req = Request::builder()
            .uri(format!("/mfa/challenge?token={token}"))
            .header("HX-Request", "true")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let html = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            html.contains("<main class=\"wf-auth-form\">"),
            "HX response must be a fragment starting at <main>"
        );
        assert!(
            !html.contains("<html"),
            "HX response must not render the full shell"
        );
    }

    #[test]
    fn render_mfa_setup_fragment_composes_main_and_oob_head() {
        let templates = crate::browser_templates::build_default_browser_env();
        let config = MfaPageConfig {
            templates,
            is_production: false,
            base_url: "http://127.0.0.1:3100".into(),
        };
        let html = render_mfa_setup_fragment(
            &config,
            "csrf-tok",
            "otpauth://totp/allowthem:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=allowthem",
            "JBSWY3DPEHPK3PXP",
            "",
            None,
        )
        .unwrap()
        .0;
        assert!(
            html.contains("<main class=\"wf-auth-form\">"),
            "fragment must include the <main> root"
        );
        assert!(
            html.contains("<title hx-swap-oob=\"true\">"),
            "fragment must include the OOB <title> tag"
        );
        assert!(
            html.contains("id=\"wf-screen-label\""),
            "fragment must include the OOB #wf-screen-label span"
        );
        assert!(
            html.contains("ENABLE 2FA"),
            "fragment must include the ENABLE 2FA status hint"
        );
        assert!(
            html.contains("JBSWY3DPEHPK3PXP"),
            "fragment must include the base32 secret"
        );
    }

    #[tokio::test]
    async fn get_mfa_setup_hx_request_returns_fragment() {
        let ath = setup().await;
        let app = test_app(ath.clone());
        let (_, cookie) = create_session(&ath).await;
        let csrf = get_csrf(&app, &cookie).await;

        let req = Request::builder()
            .uri("/settings/mfa/setup")
            .header(header::COOKIE, format!("{cookie}; csrf_token={csrf}"))
            .header("HX-Request", "true")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let html = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            html.contains("<main class=\"wf-auth-form\">"),
            "HX response must be a fragment starting at <main>"
        );
        assert!(
            !html.contains("<html"),
            "HX response must not render the full shell"
        );
    }

    #[test]
    fn render_mfa_recovery_fragment_composes_main_and_oob_head() {
        let templates = crate::browser_templates::build_default_browser_env();
        let config = MfaPageConfig {
            templates,
            is_production: false,
            base_url: "http://127.0.0.1:3100".into(),
        };
        let codes = vec!["AAAA-BBBB".to_string(), "CCCC-DDDD".to_string()];
        let html = render_mfa_recovery_fragment(&config, &codes, None)
            .unwrap()
            .0;
        assert!(
            html.contains("<main class=\"wf-auth-form\">"),
            "fragment must include the <main> root"
        );
        assert!(
            html.contains("<title hx-swap-oob=\"true\">"),
            "fragment must include the OOB <title> tag"
        );
        assert!(
            html.contains("id=\"wf-screen-label\""),
            "fragment must include the OOB #wf-screen-label span"
        );
        assert!(
            html.contains("RECOVERY CODES"),
            "fragment must include the RECOVERY CODES status hint"
        );
        assert!(
            html.contains("AAAA-BBBB"),
            "fragment must include the rendered recovery codes"
        );
        assert!(
            html.contains("wf-recovery-grid"),
            "fragment must include the scoped recovery grid styles"
        );
    }

    #[tokio::test]
    async fn post_mfa_confirm_hx_request_returns_recovery_fragment() {
        let ath = setup().await;
        let app = test_app(ath.clone());
        let (user_id, cookie) = create_session(&ath).await;
        let csrf = get_csrf(&app, &cookie).await;

        let secret = ath.create_mfa_secret(user_id).await.unwrap();
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            Secret::Encoded(secret).to_bytes().unwrap(),
            None,
            String::new(),
        )
        .unwrap();
        let code = totp.generate_current().unwrap();

        let body_str = format!("code={code}&csrf_token={csrf}");
        let req = Request::builder()
            .method("POST")
            .uri("/settings/mfa/confirm")
            .header(header::COOKIE, format!("{cookie}; csrf_token={csrf}"))
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header("HX-Request", "true")
            .body(Body::from(body_str))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let html = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            html.contains("<main class=\"wf-auth-form\">"),
            "HX response must be a fragment starting at <main>"
        );
        assert!(
            !html.contains("<html"),
            "HX response must not render the full shell"
        );
        assert!(
            html.contains("recovery-code"),
            "HX response must render the recovery codes"
        );
    }

    #[test]
    fn render_mfa_challenge_fragment_composes_main_and_oob_head() {
        let templates = crate::browser_templates::build_default_browser_env();
        let config = MfaPageConfig {
            templates,
            is_production: false,
            base_url: String::new(),
        };
        let html = render_mfa_challenge_fragment(&config, "mfa-token-abc", "", None)
            .unwrap()
            .0;
        assert!(
            html.contains("<main class=\"wf-auth-form\">"),
            "fragment must include the <main> root"
        );
        assert!(
            html.contains("<title hx-swap-oob=\"true\">"),
            "fragment must include the OOB <title> tag"
        );
        assert!(
            html.contains("id=\"wf-screen-label\""),
            "fragment must include the OOB #wf-screen-label span"
        );
        assert!(
            html.contains("TWO-FACTOR"),
            "fragment must include the TWO-FACTOR status hint"
        );
    }

    // ---------------------------------------------------------------------------
    // POST /mfa/challenge
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn post_mfa_challenge_invalid_token_redirects_to_login() {
        let ath = setup().await;
        let app = test_app(ath);

        let body_str = "mfa_token=garbage&code=123456";
        let req = Request::builder()
            .method("POST")
            .uri("/mfa/challenge")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body_str))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/login");
    }

    #[tokio::test]
    async fn post_mfa_challenge_wrong_totp_does_not_consume_challenge() {
        // Retry must be possible after a wrong code.
        let ath = setup().await;
        let app = test_app(ath.clone());
        let (user_id, _) = create_session(&ath).await;
        enable_mfa_for_user(&ath, user_id).await;

        let token = ath.db().create_mfa_challenge(user_id).await.unwrap();

        let body_str = format!("mfa_token={token}&code=000000");
        let req = Request::builder()
            .method("POST")
            .uri("/mfa/challenge")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body_str))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let html = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            html.contains(CHALLENGE_INVALID_TOTP),
            "wrong code must show TOTP error"
        );

        // Challenge must still be valid (not consumed) so the user can retry
        let still_valid = ath.db().validate_mfa_challenge(&token).await.unwrap();
        assert!(
            still_valid.is_some(),
            "challenge must survive a failed attempt"
        );
    }

    #[tokio::test]
    async fn post_mfa_challenge_valid_totp_creates_session_and_emits_login() {
        let ath = setup().await;
        let app = test_app(ath.clone());
        let (user_id, _) = create_session(&ath).await;
        let (totp, _) = enable_mfa_for_user(&ath, user_id).await;

        let token = ath.db().create_mfa_challenge(user_id).await.unwrap();
        let code = totp.generate_current().unwrap();

        let body_str = format!("mfa_token={token}&code={code}");
        let req = Request::builder()
            .method("POST")
            .uri("/mfa/challenge")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body_str))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/");
        assert!(
            resp.headers().get(header::SET_COOKIE).is_some(),
            "session cookie must be set on success"
        );

        // Challenge must be consumed
        let consumed = ath.db().validate_mfa_challenge(&token).await.unwrap();
        assert!(
            consumed.is_none(),
            "challenge must be consumed after success"
        );

        // Both MfaChallengeSuccess and Login must be in the audit log
        let entries = ath.db().get_audit_log(Some(&user_id), 50, 0).await.unwrap();
        let event_types: Vec<&allowthem_core::AuditEvent> =
            entries.iter().map(|e| &e.event_type).collect();
        assert!(
            event_types.contains(&&allowthem_core::AuditEvent::MfaChallengeSuccess),
            "MfaChallengeSuccess must be in audit log"
        );
        assert!(
            event_types.contains(&&allowthem_core::AuditEvent::Login),
            "Login must be in audit log after MFA challenge success"
        );
    }

    #[tokio::test]
    async fn post_mfa_challenge_wrong_recovery_code_shows_error() {
        let ath = setup().await;
        let app = test_app(ath.clone());
        let (user_id, _) = create_session(&ath).await;
        enable_mfa_for_user(&ath, user_id).await;

        let token = ath.db().create_mfa_challenge(user_id).await.unwrap();

        let body_str = format!("mfa_token={token}&recovery_code=AAAAAAAA&use_recovery=on");
        let req = Request::builder()
            .method("POST")
            .uri("/mfa/challenge")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body_str))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let html = String::from_utf8(
            axum::body::to_bytes(resp.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(
            html.contains(CHALLENGE_INVALID_RECOVERY),
            "wrong recovery code must show recovery error"
        );
    }
}
