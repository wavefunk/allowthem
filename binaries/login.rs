use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use axum::Form;
use axum::extract::{ConnectInfo, Query, State};
use axum::http::StatusCode;
use axum::http::header::{COOKIE, SET_COOKIE, USER_AGENT};
use axum::response::{Html, IntoResponse, Response};
use chrono::Utc;
use minijinja::context;
use serde::Deserialize;

use allowthem_core::password::verify_password;
use allowthem_core::sessions;
use allowthem_core::{AuditEvent, PasswordHash, SessionToken};
use allowthem_server::CsrfToken;

use crate::error::AppError;
use crate::state::AppState;
use crate::templates::render;

const MAX_LOGIN_ATTEMPTS: u32 = 10;
const RATE_LIMIT_WINDOW_SECS: u64 = 900; // 15 minutes

/// Generic error shown for all credential failures.
const LOGIN_ERROR: &str = "Invalid email/username or password.";

/// Pre-computed Argon2id hash for timing equalization when a user is not found.
/// The actual value doesn't matter — we just need `verify_password()` to run its
/// full Argon2id computation so the response time is consistent.
const DUMMY_HASH: &str =
    "$argon2id$v=19$m=19456,t=2,p=1$ldQz3PJVzDn06G+Bzin5Ew$IaOeOaTQjgM1uJpHDULCxq8r6pj2OqvY/lcKo6Fv3IM";

#[derive(Deserialize)]
pub struct LoginQuery {
    next: Option<String>,
}

#[derive(Deserialize)]
pub struct LoginForm {
    identifier: String,
    password: String,
    next: Option<String>,
    #[allow(dead_code)]
    csrf_token: String,
}

/// Open redirect protection: only allow paths starting with `/`, reject
/// protocol-relative (`//`) and absolute URLs with schemes (`://`).
fn validate_next(next: &str) -> &str {
    if next.starts_with('/') && !next.starts_with("//") && !next.contains("://") {
        next
    } else {
        "/"
    }
}

fn extract_session_token(
    ath: &allowthem_core::AllowThem,
    headers: &axum::http::HeaderMap,
) -> Option<SessionToken> {
    headers
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| ath.parse_session_cookie(v))
}

fn render_login_form(
    state: &AppState,
    csrf_token: &str,
    identifier: &str,
    next: Option<&str>,
    error: &str,
) -> Result<Html<String>, AppError> {
    let next_val = next.map(validate_next).unwrap_or("");
    render(
        &state.templates,
        "login.html",
        context! {
            csrf_token,
            next => next_val,
            error,
            identifier,
        },
        state.is_production,
    )
}

fn is_rate_limited(state: &AppState, ip: IpAddr) -> bool {
    if let Some(entry) = state.login_attempts.get(&ip) {
        let (count, window_start) = *entry;
        if window_start.elapsed().as_secs() > RATE_LIMIT_WINDOW_SECS {
            return false;
        }
        count >= MAX_LOGIN_ATTEMPTS
    } else {
        false
    }
}

fn record_login_failure(state: &AppState, ip: IpAddr) {
    let now = Instant::now();
    state
        .login_attempts
        .entry(ip)
        .and_modify(|(count, window_start)| {
            if window_start.elapsed().as_secs() > RATE_LIMIT_WINDOW_SECS {
                *count = 1;
                *window_start = now;
            } else {
                *count += 1;
            }
        })
        .or_insert((1, now));
}

fn record_login_success(state: &AppState, ip: IpAddr) {
    state.login_attempts.remove(&ip);
}

/// GET /login — render the login form, or redirect if already authenticated.
pub async fn get_login(
    State(state): State<AppState>,
    csrf: CsrfToken,
    Query(query): Query<LoginQuery>,
    headers: axum::http::HeaderMap,
) -> Result<Response, AppError> {
    // If already authenticated, redirect
    if let Some(token) = extract_session_token(&state.ath, &headers) {
        if state.ath.db().lookup_session(&token).await?.is_some() {
            let dest = query.next.as_deref().map(validate_next).unwrap_or("/");
            return Ok((
                StatusCode::SEE_OTHER,
                [(axum::http::header::LOCATION, dest.to_string())],
            )
                .into_response());
        }
    }

    let html = render_login_form(&state, csrf.as_str(), "", query.next.as_deref(), "")?;
    Ok(html.into_response())
}

/// POST /login — validate credentials, create session on success.
pub async fn post_login(
    State(state): State<AppState>,
    csrf: CsrfToken,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<Response, AppError> {
    let ip = addr.ip();
    let ua = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());
    let ip_str = ip.to_string();

    // 1. Rate limit check
    if is_rate_limited(&state, ip) {
        let html = render_login_form(
            &state,
            csrf.as_str(),
            &form.identifier,
            form.next.as_deref(),
            "Too many login attempts. Please try again later.",
        )?;
        return Ok((StatusCode::TOO_MANY_REQUESTS, html).into_response());
    }

    let identifier = form.identifier.trim();
    if identifier.is_empty() {
        let html = render_login_form(&state, csrf.as_str(), "", form.next.as_deref(), LOGIN_ERROR)?;
        return Ok(html.into_response());
    }

    // 2. Look up user
    let dummy = PasswordHash::new_unchecked(DUMMY_HASH.to_string());
    let user = state.ath.db().find_for_login(identifier).await;

    match user {
        Ok(user) => {
            let hash = user.password_hash.as_ref().unwrap_or(&dummy);
            let password_ok = verify_password(&form.password, hash).unwrap_or(false);

            if password_ok && user.is_active {
                // Success
                record_login_success(&state, ip);

                let token = sessions::generate_token();
                let token_hash = sessions::hash_token(&token);
                let ttl = state.ath.session_config().ttl;
                let expires_at = Utc::now() + ttl;
                state
                    .ath
                    .db()
                    .create_session(user.id, token_hash, Some(&ip_str), ua, expires_at)
                    .await?;

                let cookie = state.ath.session_cookie(&token);
                let _ = state
                    .ath
                    .db()
                    .log_audit(
                        AuditEvent::Login,
                        Some(&user.id),
                        None,
                        Some(&ip_str),
                        ua,
                        None,
                    )
                    .await;

                let dest = form.next.as_deref().map(validate_next).unwrap_or("/");
                Ok((
                    StatusCode::SEE_OTHER,
                    [
                        (SET_COOKIE, cookie),
                        (axum::http::header::LOCATION, dest.to_string()),
                    ],
                )
                    .into_response())
            } else {
                // Wrong password or inactive user
                let _ = state
                    .ath
                    .db()
                    .log_audit(
                        AuditEvent::LoginFailed,
                        Some(&user.id),
                        None,
                        Some(&ip_str),
                        ua,
                        Some(identifier),
                    )
                    .await;
                record_login_failure(&state, ip);

                let html = render_login_form(
                    &state,
                    csrf.as_str(),
                    identifier,
                    form.next.as_deref(),
                    LOGIN_ERROR,
                )?;
                Ok(html.into_response())
            }
        }
        Err(allowthem_core::AuthError::NotFound) => {
            // Timing equalization: run verify against dummy hash
            let _ = verify_password(&form.password, &dummy);

            let _ = state
                .ath
                .db()
                .log_audit(
                    AuditEvent::LoginFailed,
                    None,
                    None,
                    Some(&ip_str),
                    ua,
                    Some(identifier),
                )
                .await;
            record_login_failure(&state, ip);

            let html = render_login_form(
                &state,
                csrf.as_str(),
                identifier,
                form.next.as_deref(),
                LOGIN_ERROR,
            )?;
            Ok(html.into_response())
        }
        Err(e) => Err(AppError::Auth(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use allowthem_core::{AllowThemBuilder, AuthClient, Email, EmbeddedAuthClient};

    #[test]
    fn validate_next_allows_simple_paths() {
        assert_eq!(validate_next("/dashboard"), "/dashboard");
        assert_eq!(validate_next("/search?q=foo"), "/search?q=foo");
        assert_eq!(validate_next("/a/b/c"), "/a/b/c");
    }

    #[test]
    fn validate_next_rejects_open_redirects() {
        assert_eq!(validate_next("https://evil.com"), "/");
        assert_eq!(validate_next("//evil.com"), "/");
        assert_eq!(validate_next(""), "/");
        assert_eq!(validate_next("relative/path"), "/");
        assert_eq!(validate_next("/ok/path://thing"), "/");
        assert_eq!(validate_next("http://evil.com/foo"), "/");
    }

}
