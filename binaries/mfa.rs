use axum::Form;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::http::header::{LOCATION, SET_COOKIE, USER_AGENT};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use minijinja::context;
use serde::Deserialize;

use allowthem_core::totp::totp_uri;
use allowthem_core::{AuditEvent, sessions};
use allowthem_server::{BrowserAuthUser, CsrfToken};

use crate::error::AppError;
use crate::state::AppState;
use crate::templates::render;

/// Error shown when a wrong TOTP code is entered during MFA setup confirmation.
const SETUP_INVALID_CODE: &str = "Invalid TOTP code";

/// Error shown when a wrong TOTP code is entered on the MFA challenge page.
const CHALLENGE_INVALID_TOTP: &str = "Invalid TOTP or recovery code";

/// Error shown when a wrong recovery code is entered on the MFA challenge page.
const CHALLENGE_INVALID_RECOVERY: &str = "Invalid recovery code";

// ---------------------------------------------------------------------------
// Setup-side routes (authenticated, CSRF-protected)
// ---------------------------------------------------------------------------

/// GET /settings/mfa/setup — show QR URI, base32 secret, and TOTP code input.
///
/// Idempotent: if a pending (non-enabled) secret exists, reuses it.
/// Only creates a new secret on first visit.
pub async fn get_mfa_setup(
    State(state): State<AppState>,
    BrowserAuthUser(user): BrowserAuthUser,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    // Reuse pending secret if one exists; create only on first visit
    let secret = match state.ath.get_pending_mfa_secret(user.id).await? {
        Some(s) => s,
        None => state.ath.create_mfa_secret(user.id).await?,
    };

    let issuer = derive_issuer(&state.base_url);
    let uri = totp_uri(&secret, user.email.as_str(), &issuer);

    let html = render(
        &state.templates,
        "mfa_setup.html",
        context! {
            csrf_token => csrf.as_str(),
            secret => &secret,
            totp_uri => &uri,
            error => "",
        },
        state.is_production,
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
pub async fn post_mfa_confirm(
    State(state): State<AppState>,
    BrowserAuthUser(user): BrowserAuthUser,
    csrf: CsrfToken,
    headers: axum::http::HeaderMap,
    Form(form): Form<MfaConfirmForm>,
) -> Result<Response, AppError> {
    let ip = client_ip(&headers);
    let ua = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());

    match state.ath.enable_mfa(user.id, &form.code).await {
        Ok(recovery_codes) => {
            let _ = state
                .ath
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

            let html = render(
                &state.templates,
                "mfa_recovery.html",
                context! {
                    recovery_codes => &recovery_codes,
                },
                state.is_production,
            )?;
            Ok(html.into_response())
        }
        Err(allowthem_core::AuthError::InvalidTotpCode) => {
            // Re-render setup page with error
            let secret = state
                .ath
                .get_pending_mfa_secret(user.id)
                .await?
                .unwrap_or_default();
            let issuer = derive_issuer(&state.base_url);
            let uri = totp_uri(&secret, user.email.as_str(), &issuer);

            let html = render(
                &state.templates,
                "mfa_setup.html",
                context! {
                    csrf_token => csrf.as_str(),
                    secret => &secret,
                    totp_uri => &uri,
                    error => SETUP_INVALID_CODE,
                },
                state.is_production,
            )?;
            Ok(html.into_response())
        }
        Err(e) => Err(AppError::Auth(e)),
    }
}

#[derive(Deserialize)]
pub struct MfaDisableForm {
    #[allow(dead_code)]
    csrf_token: String,
}

/// POST /settings/mfa/disable — disable MFA and redirect to settings.
pub async fn post_mfa_disable(
    State(state): State<AppState>,
    BrowserAuthUser(user): BrowserAuthUser,
    headers: axum::http::HeaderMap,
    Form(_form): Form<MfaDisableForm>,
) -> Result<Response, AppError> {
    let ip = client_ip(&headers);
    let ua = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());

    state.ath.disable_mfa(user.id).await?;

    let _ = state
        .ath
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

/// GET /mfa/challenge — render TOTP code input form.
pub async fn get_mfa_challenge(
    State(state): State<AppState>,
    Query(query): Query<ChallengeQuery>,
) -> Result<Response, AppError> {
    // Validate token is still alive (don't consume it)
    let user_id = state.ath.db().validate_mfa_challenge(&query.token).await?;
    if user_id.is_none() {
        // Invalid or expired token — redirect to login
        return Ok(
            (StatusCode::SEE_OTHER, [(LOCATION, "/login".to_string())]).into_response(),
        );
    }

    let html = render(
        &state.templates,
        "mfa_challenge.html",
        context! {
            mfa_token => &query.token,
            error => "",
        },
        state.is_production,
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
pub async fn post_mfa_challenge(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Form(form): Form<MfaChallengeForm>,
) -> Result<Response, AppError> {
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string());
    let ua = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());

    // 1. Validate challenge token
    let user_id = match state
        .ath
        .db()
        .validate_mfa_challenge(&form.mfa_token)
        .await?
    {
        Some(uid) => uid,
        None => {
            return Ok(
                (StatusCode::SEE_OTHER, [(LOCATION, "/login".to_string())]).into_response(),
            );
        }
    };

    // 2. Branch: recovery code vs TOTP
    let use_recovery = form.use_recovery.is_some();
    let verified = if use_recovery {
        let code = form.recovery_code.as_deref().unwrap_or("");
        state.ath.verify_recovery_code(user_id, code).await?
    } else {
        let code = form.code.as_deref().unwrap_or("");
        state.ath.verify_totp(user_id, code).await?
    };

    if !verified {
        // Log failure
        let _ = state
            .ath
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

        let html = render(
            &state.templates,
            "mfa_challenge.html",
            context! {
                mfa_token => &form.mfa_token,
                error => error_msg,
            },
            state.is_production,
        )?;
        return Ok(html.into_response());
    }

    // 3. Success: consume challenge, create session
    state
        .ath
        .db()
        .consume_mfa_challenge(&form.mfa_token)
        .await?;

    let _ = state
        .ath
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
    let _ = state
        .ath
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
    let ttl = state.ath.session_config().ttl;
    let expires_at = Utc::now() + ttl;
    state
        .ath
        .db()
        .create_session(user_id, token_hash, ip.as_deref(), ua, expires_at)
        .await?;

    let cookie = state.ath.session_cookie(&token);

    Ok((
        StatusCode::SEE_OTHER,
        [
            (SET_COOKIE, cookie),
            (LOCATION, "/".to_string()),
        ],
    )
        .into_response())
}

fn client_ip(headers: &axum::http::HeaderMap) -> Option<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::get;
    use chrono::{Duration, Utc};
    use totp_rs::{Algorithm, Secret, TOTP};
    use tower::ServiceExt;

    use allowthem_core::{
        AllowThemBuilder, AuthClient, Email, EmbeddedAuthClient, LogEmailSender, generate_token,
        hash_token,
    };
    use allowthem_server::csrf_middleware;

    use crate::state::AppState;

    const TEST_MFA_KEY: [u8; 32] = [0x42; 32];

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    async fn setup() -> AppState {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .mfa_key(TEST_MFA_KEY)
            .csrf_key(*b"test-csrf-key-for-binary-tests!!")
            .build()
            .await
            .unwrap();
        let auth_client: Arc<dyn AuthClient> =
            Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
        let templates = crate::templates::build_template_env().unwrap();
        AppState {
            ath,
            auth_client,
            base_url: "http://127.0.0.1:3100".into(),
            templates,
            is_production: false,
            login_attempts: Arc::new(dashmap::DashMap::new()),
            max_login_attempts: 10,
            rate_limit_window_secs: 900,
            email_sender: Arc::new(LogEmailSender),
            oauth_providers: Vec::new(),
        }
    }

    /// Build a router that exercises only the MFA routes (no login).
    /// Setup-side routes are CSRF-protected; challenge routes are not.
    fn test_app(state: AppState) -> Router {
        Router::new()
            .route("/settings/mfa/setup", get(super::get_mfa_setup))
            .route("/settings/mfa/confirm", axum::routing::post(super::post_mfa_confirm))
            .route("/settings/mfa/disable", axum::routing::post(super::post_mfa_disable))
            .layer(axum::middleware::from_fn_with_state(state.clone(), csrf_middleware))
            .route(
                "/mfa/challenge",
                get(super::get_mfa_challenge).post(super::post_mfa_challenge),
            )
            .with_state(state)
    }

    async fn create_session(state: &AppState) -> (allowthem_core::types::UserId, String) {
        let email = Email::new("mfa-test@example.com".into()).unwrap();
        let user = state.ath.db().create_user(email, "pass", None).await.unwrap();
        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = Utc::now() + Duration::hours(24);
        state
            .ath
            .db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();
        let cookie = state.ath.session_cookie(&token);
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

    /// Create a user with MFA enabled. Returns (user_id, totp, recovery_codes).
    async fn enable_mfa_for_user(
        state: &AppState,
        user_id: allowthem_core::types::UserId,
    ) -> (TOTP, Vec<String>) {
        let secret_b32 = state.ath.create_mfa_secret(user_id).await.unwrap();
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
        let recovery_codes = state.ath.enable_mfa(user_id, &code).await.unwrap();
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
        assert_eq!(derive_issuer("https://auth.example.com"), "auth.example.com");
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
        let state = setup().await;
        let app = test_app(state.clone());
        let (_, cookie) = create_session(&state).await;

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
        assert!(html.contains("totp-secret"), "setup page must show secret element");
        // The totp_uri value is HTML-escaped by MiniJinja; check the testid container exists.
        assert!(html.contains("totp-uri"), "setup page must show QR URI container");
    }

    #[tokio::test]
    async fn get_mfa_setup_is_idempotent() {
        // Two GETs must return the same secret so wrong-code-then-retry works.
        let state = setup().await;
        let app = test_app(state.clone());
        let (_, cookie) = create_session(&state).await;
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
            after_tag_close
                .split('<')
                .next()
                .unwrap_or("")
                .to_string()
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
        let state = setup().await;
        let app = test_app(state.clone());
        let (user_id, cookie) = create_session(&state).await;

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
            !state.ath.has_mfa_enabled(user_id).await.unwrap(),
            "MFA must not be enabled after wrong code"
        );
    }

    #[tokio::test]
    async fn post_mfa_confirm_valid_code_enables_mfa_and_renders_recovery_codes() {
        let state = setup().await;
        let app = test_app(state.clone());
        let (user_id, cookie) = create_session(&state).await;

        let csrf = get_csrf(&app, &cookie).await;

        // Create and retrieve the pending secret
        let secret = state.ath.create_mfa_secret(user_id).await.unwrap();
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
            state.ath.has_mfa_enabled(user_id).await.unwrap(),
            "MFA must be enabled after valid confirm"
        );
    }

    // ---------------------------------------------------------------------------
    // POST /settings/mfa/disable
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn post_mfa_disable_removes_mfa_and_redirects() {
        let state = setup().await;
        let app = test_app(state.clone());
        let (user_id, cookie) = create_session(&state).await;
        enable_mfa_for_user(&state, user_id).await;

        // Derive CSRF token from the session token (HMAC path — no Set-Cookie on GET).
        let session_token_val = cookie.split('=').nth(1).unwrap().to_string();
        let session_token =
            allowthem_core::types::SessionToken::from_encoded(session_token_val);
        let csrf = allowthem_core::derive_csrf_token(
            &session_token,
            b"test-csrf-key-for-binary-tests!!",
        );

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
            !state.ath.has_mfa_enabled(user_id).await.unwrap(),
            "MFA must be disabled after disable POST"
        );
    }

    // ---------------------------------------------------------------------------
    // GET /mfa/challenge
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn get_mfa_challenge_with_invalid_token_redirects_to_login() {
        let state = setup().await;
        let app = test_app(state);

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
        let state = setup().await;
        let app = test_app(state.clone());
        let (user_id, _) = create_session(&state).await;
        enable_mfa_for_user(&state, user_id).await;

        let token = state.ath.db().create_mfa_challenge(user_id).await.unwrap();
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
        assert!(html.contains("name=\"code\""), "challenge form must have code input");
        assert!(
            html.contains("mfa_token"),
            "challenge form must embed mfa_token hidden field"
        );
    }

    // ---------------------------------------------------------------------------
    // POST /mfa/challenge
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn post_mfa_challenge_invalid_token_redirects_to_login() {
        let state = setup().await;
        let app = test_app(state);

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
        let state = setup().await;
        let app = test_app(state.clone());
        let (user_id, _) = create_session(&state).await;
        enable_mfa_for_user(&state, user_id).await;

        let token = state.ath.db().create_mfa_challenge(user_id).await.unwrap();

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
        assert!(html.contains(CHALLENGE_INVALID_TOTP), "wrong code must show TOTP error");

        // Challenge must still be valid (not consumed) so the user can retry
        let still_valid = state
            .ath
            .db()
            .validate_mfa_challenge(&token)
            .await
            .unwrap();
        assert!(still_valid.is_some(), "challenge must survive a failed attempt");
    }

    #[tokio::test]
    async fn post_mfa_challenge_valid_totp_creates_session_and_emits_login() {
        let state = setup().await;
        let app = test_app(state.clone());
        let (user_id, _) = create_session(&state).await;
        let (totp, _) = enable_mfa_for_user(&state, user_id).await;

        let token = state.ath.db().create_mfa_challenge(user_id).await.unwrap();
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
        let consumed = state
            .ath
            .db()
            .validate_mfa_challenge(&token)
            .await
            .unwrap();
        assert!(consumed.is_none(), "challenge must be consumed after success");

        // Both MfaChallengeSuccess and Login must be in the audit log
        let entries = state
            .ath
            .db()
            .get_audit_log(Some(&user_id), 50, 0)
            .await
            .unwrap();
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
        let state = setup().await;
        let app = test_app(state.clone());
        let (user_id, _) = create_session(&state).await;
        enable_mfa_for_user(&state, user_id).await;

        let token = state.ath.db().create_mfa_challenge(user_id).await.unwrap();

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
