use axum::extract::State;
use axum::http::header::USER_AGENT;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Form;
use chrono::Utc;
use minijinja::context;
use serde::Deserialize;

use allowthem_core::{
    AuditEvent, AuthError, Email, Username, generate_token, hash_token,
};
use allowthem_server::CsrfToken;

use crate::error::AppError;
use crate::state::AppState;

const MIN_PASSWORD_LEN: usize = 8;

#[derive(Deserialize)]
pub struct RegisterForm {
    email: String,
    password: String,
    password_confirm: String,
    #[serde(default)]
    username: String,
}

/// GET /register — render the registration form.
///
/// If the user already has a valid session, redirects to `/`.
pub async fn get_register(
    State(state): State<AppState>,
    user: allowthem_server::OptionalAuthUser,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    if user.0.is_some() {
        return Ok((
            StatusCode::SEE_OTHER,
            [(axum::http::header::LOCATION, "/")],
        )
            .into_response());
    }

    let html = crate::templates::render(
        &state.templates,
        "register.html",
        context! {
            csrf_token => csrf.as_str(),
            email => "",
            username => "",
        },
        state.is_production,
    )?;
    Ok(html.into_response())
}

/// POST /register — validate input, create user, start session, redirect.
pub async fn post_register(
    State(state): State<AppState>,
    csrf: CsrfToken,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> Result<Response, AppError> {
    // 1. Validate passwords match
    if form.password != form.password_confirm {
        return render_form_error(&state, &csrf, &form, "Passwords do not match");
    }

    // 2. Validate password length
    if form.password.len() < MIN_PASSWORD_LEN {
        return render_form_error(
            &state,
            &csrf,
            &form,
            "Password must be at least 8 characters",
        );
    }

    // 3. Parse email
    let email = match Email::new(form.email.clone()) {
        Ok(e) => e,
        Err(_) => {
            return render_form_error(&state, &csrf, &form, "Invalid email address");
        }
    };

    // 4. Parse username
    let trimmed = form.username.trim();
    let username = if trimmed.is_empty() {
        None
    } else {
        Some(Username::new(trimmed))
    };

    // 5. Create user
    let user = match state.ath.db().create_user(email, &form.password, username).await {
        Ok(u) => u,
        Err(AuthError::Conflict(ref msg)) if msg.contains("email") => {
            return render_form_error(
                &state,
                &csrf,
                &form,
                "An account with this email already exists",
            );
        }
        Err(AuthError::Conflict(ref msg)) if msg.contains("username") => {
            return render_form_error(
                &state,
                &csrf,
                &form,
                "This username is already taken",
            );
        }
        Err(e) => return Err(AppError::Auth(e)),
    };

    // 6. Create session
    let token = generate_token();
    let token_hash = hash_token(&token);
    let expires_at = Utc::now() + state.ath.session_config().ttl;
    let ip = client_ip(&headers);
    let ua = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());

    state
        .ath
        .db()
        .create_session(user.id, token_hash, ip.as_deref(), ua, expires_at)
        .await?;

    // 7. Log audit event
    if let Err(e) = state
        .ath
        .db()
        .log_audit(
            AuditEvent::Register,
            Some(&user.id),
            None,
            ip.as_deref(),
            ua,
            None,
        )
        .await
    {
        tracing::error!(error = %e, "failed to log registration audit event");
    }

    // 8. Set session cookie and redirect
    let cookie = state.ath.session_cookie(&token);
    Ok((
        StatusCode::SEE_OTHER,
        [
            (axum::http::header::SET_COOKIE, cookie),
            (axum::http::header::LOCATION, "/".to_string()),
        ],
    )
        .into_response())
}

/// Re-render the registration form with an error message and preserved input.
fn render_form_error(
    state: &AppState,
    csrf: &CsrfToken,
    form: &RegisterForm,
    error: &str,
) -> Result<Response, AppError> {
    let html = crate::templates::render(
        &state.templates,
        "register.html",
        context! {
            csrf_token => csrf.as_str(),
            error => error,
            email => &form.email,
            username => &form.username,
        },
        state.is_production,
    )?;
    Ok(html.into_response())
}

fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
}
