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

    let issuer = state
        .base_url
        .trim_start_matches("https://")
        .trim_start_matches("http://")
        .split('/')
        .next()
        .unwrap_or("allowthem")
        .to_string();
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
            let issuer = state
                .base_url
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or("allowthem")
                .to_string();
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
