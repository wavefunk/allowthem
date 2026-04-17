use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::USER_AGENT;
use axum::response::{Html, IntoResponse, Response};
use minijinja::context;
use serde::Deserialize;

use allowthem_core::types::UserId;
use allowthem_core::{AuditEvent, AuthError, Email, OAuthAccountInfo, Username};
use allowthem_server::{BrowserAuthUser, CsrfToken};

use crate::error::AppError;
use crate::state::AppState;

const MIN_PASSWORD_LEN: usize = 8;

#[derive(Deserialize)]
pub struct ProfileForm {
    email: String,
    #[serde(default)]
    username: String,
    #[allow(dead_code)]
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct PasswordForm {
    current_password: String,
    new_password: String,
    new_password_confirm: String,
    #[allow(dead_code)]
    csrf_token: String,
}

struct SettingsContext {
    email: String,
    username: String,
    profile_error: String,
    profile_success: String,
    password_error: String,
    password_success: String,
    oauth_accounts: Vec<OAuthAccountInfo>,
    mfa_enabled: bool,
    mfa_recovery_remaining: i64,
}

fn render_settings(
    state: &AppState,
    csrf_token: &str,
    ctx: &SettingsContext,
) -> Result<Html<String>, AppError> {
    crate::templates::render(
        &state.templates,
        "settings.html",
        context! {
            csrf_token,
            email => &ctx.email,
            username => &ctx.username,
            profile_error => &ctx.profile_error,
            profile_success => &ctx.profile_success,
            password_error => &ctx.password_error,
            password_success => &ctx.password_success,
            oauth_accounts => &ctx.oauth_accounts,
            mfa_enabled => ctx.mfa_enabled,
            mfa_recovery_remaining => ctx.mfa_recovery_remaining,
        },
        state.is_production,
    )
}

async fn fetch_account_data(
    state: &AppState,
    user_id: UserId,
) -> Result<(Vec<OAuthAccountInfo>, bool, i64), AppError> {
    let oauth_accounts = state.ath.db().get_user_oauth_accounts(user_id).await?;
    let mfa_enabled = state.ath.db().has_mfa_enabled(user_id).await?;
    let mfa_recovery_remaining = if mfa_enabled {
        state.ath.db().remaining_recovery_codes(user_id).await?
    } else {
        0
    };
    Ok((oauth_accounts, mfa_enabled, mfa_recovery_remaining))
}

fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
}

/// GET /settings — render the settings page for the authenticated user.
pub async fn get_settings(
    State(state): State<AppState>,
    BrowserAuthUser(user): BrowserAuthUser,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let (oauth_accounts, mfa_enabled, mfa_recovery_remaining) =
        fetch_account_data(&state, user.id).await?;

    let ctx = SettingsContext {
        email: user.email.as_str().to_string(),
        username: user
            .username
            .as_ref()
            .map_or(String::new(), |u| u.as_str().to_string()),
        profile_error: String::new(),
        profile_success: String::new(),
        password_error: String::new(),
        password_success: String::new(),
        oauth_accounts,
        mfa_enabled,
        mfa_recovery_remaining,
    };
    let html = render_settings(&state, csrf.as_str(), &ctx)?;
    Ok(html.into_response())
}

/// POST /settings — update email and/or username.
pub async fn post_settings(
    State(state): State<AppState>,
    BrowserAuthUser(user): BrowserAuthUser,
    csrf: CsrfToken,
    headers: HeaderMap,
    axum::Form(form): axum::Form<ProfileForm>,
) -> Result<Response, AppError> {
    // 1. Parse email
    let email = match Email::new(form.email.clone()) {
        Ok(e) => e,
        Err(_) => {
            let (oauth_accounts, mfa_enabled, mfa_recovery_remaining) =
                fetch_account_data(&state, user.id).await?;
            let ctx = SettingsContext {
                email: form.email,
                username: form.username,
                profile_error: "Invalid email address".into(),
                profile_success: String::new(),
                password_error: String::new(),
                password_success: String::new(),
                oauth_accounts,
                mfa_enabled,
                mfa_recovery_remaining,
            };
            return Ok(render_settings(&state, csrf.as_str(), &ctx)?.into_response());
        }
    };

    // 2. Parse username
    let trimmed = form.username.trim();
    let username = if trimmed.is_empty() {
        None
    } else {
        Some(Username::new(trimmed))
    };

    // 3. Update email if changed
    if email != user.email {
        match state.ath.db().update_user_email(user.id, email).await {
            Ok(()) => {}
            Err(AuthError::Conflict(ref msg)) if msg.contains("email") => {
                let (oauth_accounts, mfa_enabled, mfa_recovery_remaining) =
                    fetch_account_data(&state, user.id).await?;
                let ctx = SettingsContext {
                    email: form.email,
                    username: form.username,
                    profile_error: "An account with this email already exists".into(),
                    profile_success: String::new(),
                    password_error: String::new(),
                    password_success: String::new(),
                    oauth_accounts,
                    mfa_enabled,
                    mfa_recovery_remaining,
                };
                return Ok(render_settings(&state, csrf.as_str(), &ctx)?.into_response());
            }
            Err(e) => return Err(AppError::Auth(e)),
        }
    }

    // 4. Update username if changed
    // Note: if email update succeeded but username update fails, the email change
    // is already persisted. This non-atomicity is acceptable for M34 — SQLite does
    // not easily support transactional conflict handling across separate UPDATEs.
    let current_username = user.username.as_ref().map(|u| u.as_str());
    let new_username = username.as_ref().map(|u| u.as_str());
    if current_username != new_username {
        match state.ath.db().update_user_username(user.id, username).await {
            Ok(()) => {}
            Err(AuthError::Conflict(ref msg)) if msg.contains("username") => {
                let (oauth_accounts, mfa_enabled, mfa_recovery_remaining) =
                    fetch_account_data(&state, user.id).await?;
                let ctx = SettingsContext {
                    email: form.email,
                    username: form.username,
                    profile_error: "This username is already taken".into(),
                    profile_success: String::new(),
                    password_error: String::new(),
                    password_success: String::new(),
                    oauth_accounts,
                    mfa_enabled,
                    mfa_recovery_remaining,
                };
                return Ok(render_settings(&state, csrf.as_str(), &ctx)?.into_response());
            }
            Err(e) => return Err(AppError::Auth(e)),
        }
    }

    // 5. Audit log
    let ip = client_ip(&headers);
    let ua = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());
    let _ = state
        .ath
        .db()
        .log_audit(
            AuditEvent::UserUpdated,
            Some(&user.id),
            None,
            ip.as_deref(),
            ua,
            None,
        )
        .await;

    // 6. Re-render with success — use form values for display (they reflect the new state)
    let (oauth_accounts, mfa_enabled, mfa_recovery_remaining) =
        fetch_account_data(&state, user.id).await?;
    let ctx = SettingsContext {
        email: form.email,
        username: form.username,
        profile_error: String::new(),
        profile_success: "Profile updated".into(),
        password_error: String::new(),
        password_success: String::new(),
        oauth_accounts,
        mfa_enabled,
        mfa_recovery_remaining,
    };
    Ok(render_settings(&state, csrf.as_str(), &ctx)?.into_response())
}

/// POST /settings/password — change password with session rotation.
pub async fn post_change_password(
    State(state): State<AppState>,
    BrowserAuthUser(user): BrowserAuthUser,
    csrf: CsrfToken,
    headers: HeaderMap,
    axum::Form(form): axum::Form<PasswordForm>,
) -> Result<Response, AppError> {
    let ip = client_ip(&headers);
    let ua = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());

    // 1. Validate new password length
    if form.new_password.len() < MIN_PASSWORD_LEN {
        let (oauth_accounts, mfa_enabled, mfa_recovery_remaining) =
            fetch_account_data(&state, user.id).await?;
        let ctx = SettingsContext {
            email: user.email.as_str().to_string(),
            username: user
                .username
                .as_ref()
                .map_or(String::new(), |u| u.as_str().to_string()),
            profile_error: String::new(),
            profile_success: String::new(),
            password_error: "New password must be at least 8 characters".into(),
            password_success: String::new(),
            oauth_accounts,
            mfa_enabled,
            mfa_recovery_remaining,
        };
        return Ok(render_settings(&state, csrf.as_str(), &ctx)?.into_response());
    }

    // 2. Validate passwords match
    if form.new_password != form.new_password_confirm {
        let (oauth_accounts, mfa_enabled, mfa_recovery_remaining) =
            fetch_account_data(&state, user.id).await?;
        let ctx = SettingsContext {
            email: user.email.as_str().to_string(),
            username: user
                .username
                .as_ref()
                .map_or(String::new(), |u| u.as_str().to_string()),
            profile_error: String::new(),
            profile_success: String::new(),
            password_error: "New passwords do not match".into(),
            password_success: String::new(),
            oauth_accounts,
            mfa_enabled,
            mfa_recovery_remaining,
        };
        return Ok(render_settings(&state, csrf.as_str(), &ctx)?.into_response());
    }

    // 3. Verify current password
    let fetched_user = state.ath.db().find_for_login(user.email.as_str()).await?;

    let password_ok = match fetched_user.password_hash {
        Some(ref h) => {
            allowthem_core::password::verify_password(&form.current_password, h).unwrap_or(false)
        }
        None => false,
    };

    if !password_ok {
        let (oauth_accounts, mfa_enabled, mfa_recovery_remaining) =
            fetch_account_data(&state, user.id).await?;
        let ctx = SettingsContext {
            email: user.email.as_str().to_string(),
            username: user
                .username
                .as_ref()
                .map_or(String::new(), |u| u.as_str().to_string()),
            profile_error: String::new(),
            profile_success: String::new(),
            password_error: "Current password is incorrect".into(),
            password_success: String::new(),
            oauth_accounts,
            mfa_enabled,
            mfa_recovery_remaining,
        };
        return Ok(render_settings(&state, csrf.as_str(), &ctx)?.into_response());
    }

    // 4. Update password
    state
        .ath
        .db()
        .update_user_password(user.id, &form.new_password)
        .await?;

    // 5. Invalidate all sessions + create fresh one
    state.ath.db().delete_user_sessions(&user.id).await?;

    let token = allowthem_core::generate_token();
    let token_hash = allowthem_core::hash_token(&token);
    let expires_at = chrono::Utc::now() + state.ath.session_config().ttl;
    state
        .ath
        .db()
        .create_session(user.id, token_hash, ip.as_deref(), ua, expires_at)
        .await?;
    let cookie = state.ath.session_cookie(&token);

    // 6. Audit log
    let _ = state
        .ath
        .db()
        .log_audit(
            AuditEvent::PasswordChange,
            Some(&user.id),
            None,
            ip.as_deref(),
            ua,
            None,
        )
        .await;

    // 7. Render success page with Set-Cookie header for new session
    let (oauth_accounts, mfa_enabled, mfa_recovery_remaining) =
        fetch_account_data(&state, user.id).await?;
    let ctx = SettingsContext {
        email: user.email.as_str().to_string(),
        username: user
            .username
            .as_ref()
            .map_or(String::new(), |u| u.as_str().to_string()),
        profile_error: String::new(),
        profile_success: String::new(),
        password_error: String::new(),
        password_success: "Password changed successfully".into(),
        oauth_accounts,
        mfa_enabled,
        mfa_recovery_remaining,
    };
    let html = render_settings(&state, csrf.as_str(), &ctx)?;

    Ok(([(axum::http::header::SET_COOKIE, cookie)], html).into_response())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::{get, post};
    use tower::ServiceExt;

    use allowthem_core::{
        AllowThem, AllowThemBuilder, AuditEvent, AuthClient, Email, EmbeddedAuthClient, Username,
        generate_token, hash_token, parse_session_cookie,
    };
    use allowthem_server::csrf_middleware;

    use crate::state::AppState;

    async fn setup() -> (AllowThem, AppState, String) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();
        let auth_client: Arc<dyn AuthClient> =
            Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
        let templates = crate::templates::build_template_env().unwrap();

        let email = Email::new("user@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", Some(Username::new("testuser")))
            .await
            .unwrap();

        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = chrono::Utc::now() + chrono::Duration::hours(24);
        ath.db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();
        let set_cookie = ath.session_cookie(&token);
        let cookie_value = set_cookie.split(';').next().unwrap().to_string();

        let state = AppState {
            ath: ath.clone(),
            auth_client,
            base_url: "http://localhost:3000".into(),
            templates,
            is_production: false,
            login_attempts: Arc::new(dashmap::DashMap::new()),
            max_login_attempts: 10,
            rate_limit_window_secs: 900,
        };
        (ath, state, cookie_value)
    }

    fn test_app(state: AppState) -> Router {
        Router::new()
            .route(
                "/settings",
                get(super::get_settings).post(super::post_settings),
            )
            .route("/settings/password", post(super::post_change_password))
            .layer(axum::middleware::from_fn(csrf_middleware))
            .with_state(state)
    }

    async fn get_csrf_token(app: &Router, cookie: &str) -> String {
        let req = Request::builder()
            .uri("/settings")
            .header(header::COOKIE, cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        set_cookie
            .split(';')
            .next()
            .unwrap()
            .split('=')
            .nth(1)
            .unwrap()
            .to_string()
    }

    async fn body_string(resp: axum::http::Response<Body>) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    fn profile_request(
        csrf: &str,
        session_cookie: &str,
        email: &str,
        username: &str,
    ) -> Request<Body> {
        let enc = |s: &str| s.replace('@', "%40");
        let body = format!(
            "csrf_token={}&email={}&username={}",
            csrf,
            enc(email),
            enc(username),
        );
        Request::builder()
            .method("POST")
            .uri("/settings")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                header::COOKIE,
                format!("{session_cookie}; csrf_token={csrf}"),
            )
            .body(Body::from(body))
            .unwrap()
    }

    fn password_request(
        csrf: &str,
        session_cookie: &str,
        current: &str,
        new: &str,
        confirm: &str,
    ) -> Request<Body> {
        let body = format!(
            "csrf_token={csrf}&current_password={current}&new_password={new}&new_password_confirm={confirm}",
        );
        Request::builder()
            .method("POST")
            .uri("/settings/password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(
                header::COOKIE,
                format!("{session_cookie}; csrf_token={csrf}"),
            )
            .body(Body::from(body))
            .unwrap()
    }

    // --- GET /settings tests ---

    #[tokio::test]
    async fn get_settings_renders_page() {
        let (_, state, cookie) = setup().await;
        let app = test_app(state);
        let req = Request::builder()
            .uri("/settings")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("user@example.com"));
        assert!(html.contains("testuser"));
        assert!(html.contains("Settings"));
    }

    #[tokio::test]
    async fn get_settings_unauthenticated_redirects() {
        let (_, state, _) = setup().await;
        let app = test_app(state);
        let req = Request::builder()
            .uri("/settings")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            resp.headers().get("location").unwrap(),
            "/login?next=/settings"
        );
    }

    #[tokio::test]
    async fn get_settings_shows_csrf_token() {
        let (_, state, cookie) = setup().await;
        let app = test_app(state);
        let req = Request::builder()
            .uri("/settings")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let html = body_string(resp).await;
        assert!(html.contains("name=\"csrf_token\""));
    }

    #[tokio::test]
    async fn get_settings_shows_oauth_section() {
        let (_, state, cookie) = setup().await;
        let app = test_app(state);
        let req = Request::builder()
            .uri("/settings")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let html = body_string(resp).await;
        assert!(html.contains("Linked accounts"));
        assert!(html.contains("No linked accounts"));
    }

    #[tokio::test]
    async fn get_settings_shows_mfa_section() {
        let (_, state, cookie) = setup().await;
        let app = test_app(state);
        let req = Request::builder()
            .uri("/settings")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let html = body_string(resp).await;
        assert!(html.contains("Two-factor authentication"));
        assert!(html.contains("Not configured"));
    }

    // --- POST /settings (profile) tests ---

    #[tokio::test]
    async fn post_settings_updates_email() {
        let (ath, state, cookie) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app, &cookie).await;
        let req = profile_request(&csrf, &cookie, "new@example.com", "testuser");
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("Profile updated"));

        let email = Email::new("new@example.com".into()).unwrap();
        let user = ath.db().get_user_by_email(&email).await;
        assert!(user.is_ok());
    }

    #[tokio::test]
    async fn post_settings_updates_username() {
        let (ath, state, cookie) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app, &cookie).await;
        let req = profile_request(&csrf, &cookie, "user@example.com", "newname");
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let username = Username::new("newname");
        let user = ath.db().get_user_by_username(&username).await;
        assert!(user.is_ok());
    }

    #[tokio::test]
    async fn post_settings_clears_username() {
        let (ath, state, cookie) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app, &cookie).await;
        let req = profile_request(&csrf, &cookie, "user@example.com", "");
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let email = Email::new("user@example.com".into()).unwrap();
        let user = ath.db().get_user_by_email(&email).await.unwrap();
        assert!(user.username.is_none());
    }

    #[tokio::test]
    async fn post_settings_duplicate_email_shows_error() {
        let (ath, state, cookie) = setup().await;
        let other_email = Email::new("other@example.com".into()).unwrap();
        ath.db()
            .create_user(other_email, "password123", None)
            .await
            .unwrap();

        let app = test_app(state);
        let csrf = get_csrf_token(&app, &cookie).await;
        let req = profile_request(&csrf, &cookie, "other@example.com", "testuser");
        let resp = app.oneshot(req).await.unwrap();
        let html = body_string(resp).await;
        assert!(html.contains("An account with this email already exists"));
    }

    #[tokio::test]
    async fn post_settings_duplicate_username_shows_error() {
        let (ath, state, cookie) = setup().await;
        let other_email = Email::new("other@example.com".into()).unwrap();
        ath.db()
            .create_user(other_email, "password123", Some(Username::new("taken")))
            .await
            .unwrap();

        let app = test_app(state);
        let csrf = get_csrf_token(&app, &cookie).await;
        let req = profile_request(&csrf, &cookie, "user@example.com", "taken");
        let resp = app.oneshot(req).await.unwrap();
        let html = body_string(resp).await;
        assert!(html.contains("This username is already taken"));
    }

    #[tokio::test]
    async fn post_settings_invalid_email_shows_error() {
        let (_, state, cookie) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app, &cookie).await;
        let req = profile_request(&csrf, &cookie, "not-an-email", "testuser");
        let resp = app.oneshot(req).await.unwrap();
        let html = body_string(resp).await;
        assert!(html.contains("Invalid email address"));
    }

    #[tokio::test]
    async fn post_settings_no_changes_succeeds() {
        let (_, state, cookie) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app, &cookie).await;
        let req = profile_request(&csrf, &cookie, "user@example.com", "testuser");
        let resp = app.oneshot(req).await.unwrap();
        let html = body_string(resp).await;
        assert!(html.contains("Profile updated"));
    }

    #[tokio::test]
    async fn post_settings_logs_audit() {
        let (ath, state, cookie) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app, &cookie).await;
        let req = profile_request(&csrf, &cookie, "user@example.com", "testuser");
        app.oneshot(req).await.unwrap();

        let entries = ath.db().get_audit_log(None, 10, 0).await.unwrap();
        let updated = entries
            .iter()
            .find(|e| e.event_type == AuditEvent::UserUpdated);
        assert!(
            updated.is_some(),
            "UserUpdated audit event should be recorded"
        );
    }

    #[tokio::test]
    async fn post_settings_requires_csrf() {
        let (_, state, cookie) = setup().await;
        let app = test_app(state);
        let body = "email=user%40example.com&username=testuser";
        let req = Request::builder()
            .method("POST")
            .uri("/settings")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &cookie)
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // --- POST /settings/password tests ---

    #[tokio::test]
    async fn post_password_change_success() {
        let (ath, state, cookie) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app, &cookie).await;
        let req = password_request(
            &csrf,
            &cookie,
            "password123",
            "newpassword456",
            "newpassword456",
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("Password changed successfully"));

        // Verify new password works
        let email = Email::new("user@example.com".into()).unwrap();
        let user = ath.db().get_user_by_email(&email).await.unwrap();
        let user_with_hash = ath.db().find_for_login(user.email.as_str()).await.unwrap();
        let ok = allowthem_core::password::verify_password(
            "newpassword456",
            user_with_hash.password_hash.as_ref().unwrap(),
        )
        .unwrap();
        assert!(ok, "new password should verify");
    }

    #[tokio::test]
    async fn post_password_wrong_current() {
        let (_, state, cookie) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app, &cookie).await;
        let req = password_request(
            &csrf,
            &cookie,
            "wrongpassword",
            "newpassword456",
            "newpassword456",
        );
        let resp = app.oneshot(req).await.unwrap();
        let html = body_string(resp).await;
        assert!(html.contains("Current password is incorrect"));
    }

    #[tokio::test]
    async fn post_password_too_short() {
        let (_, state, cookie) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app, &cookie).await;
        let req = password_request(&csrf, &cookie, "password123", "abc", "abc");
        let resp = app.oneshot(req).await.unwrap();
        let html = body_string(resp).await;
        assert!(html.contains("New password must be at least 8 characters"));
    }

    #[tokio::test]
    async fn post_password_mismatch() {
        let (_, state, cookie) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app, &cookie).await;
        let req = password_request(
            &csrf,
            &cookie,
            "password123",
            "newpassword1",
            "newpassword2",
        );
        let resp = app.oneshot(req).await.unwrap();
        let html = body_string(resp).await;
        assert!(html.contains("New passwords do not match"));
    }

    #[tokio::test]
    async fn post_password_invalidates_other_sessions() {
        let (ath, state, cookie) = setup().await;

        // Create a second session
        let email = Email::new("user@example.com".into()).unwrap();
        let user = ath.db().get_user_by_email(&email).await.unwrap();
        let token2 = generate_token();
        let token2_hash = hash_token(&token2);
        let expires = chrono::Utc::now() + chrono::Duration::hours(24);
        ath.db()
            .create_session(user.id, token2_hash, None, None, expires)
            .await
            .unwrap();

        let app = test_app(state);
        let csrf = get_csrf_token(&app, &cookie).await;
        let req = password_request(
            &csrf,
            &cookie,
            "password123",
            "newpassword456",
            "newpassword456",
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // The old second session should be gone
        let session2 = ath.db().lookup_session(&token2).await.unwrap();
        assert!(session2.is_none(), "old session should be invalidated");

        // The response should have a new session cookie
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("allowthem_session"));
    }

    #[tokio::test]
    async fn post_password_new_cookie_authenticates() {
        let (_, state, cookie) = setup().await;
        let app = test_app(state.clone());
        let csrf = get_csrf_token(&app, &cookie).await;
        let req = password_request(
            &csrf,
            &cookie,
            "password123",
            "newpassword456",
            "newpassword456",
        );
        let resp = app.oneshot(req).await.unwrap();

        // Extract the new session cookie
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        let new_token = parse_session_cookie(set_cookie, "allowthem_session")
            .expect("new session cookie should be present");
        let new_cookie = format!("allowthem_session={}", new_token.as_str());

        // Use the new cookie to access GET /settings on a fresh router with same state
        let app2 = test_app(state);
        let req = Request::builder()
            .uri("/settings")
            .header(header::COOKIE, &new_cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app2.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("user@example.com"));
    }

    #[tokio::test]
    async fn post_password_logs_audit() {
        let (ath, state, cookie) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app, &cookie).await;
        let req = password_request(
            &csrf,
            &cookie,
            "password123",
            "newpassword456",
            "newpassword456",
        );
        app.oneshot(req).await.unwrap();

        let entries = ath.db().get_audit_log(None, 10, 0).await.unwrap();
        let pw_change = entries
            .iter()
            .find(|e| e.event_type == AuditEvent::PasswordChange);
        assert!(
            pw_change.is_some(),
            "PasswordChange audit event should be recorded"
        );
    }

    #[tokio::test]
    async fn post_password_requires_csrf() {
        let (_, state, cookie) = setup().await;
        let app = test_app(state);
        let body = "current_password=pass&new_password=newpass123&new_password_confirm=newpass123";
        let req = Request::builder()
            .method("POST")
            .uri("/settings/password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, &cookie)
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_password_oauth_only_user_shows_error() {
        // OAuth-only users have no password_hash — attempting to change password
        // must return "Current password is incorrect", not a crash or 500.
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();
        let auth_client: Arc<dyn AuthClient> =
            Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
        let templates = crate::templates::build_template_env().unwrap();

        let email = Email::new("oauth@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_oauth_user(email, "google", "google-uid-123")
            .await
            .unwrap();

        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = chrono::Utc::now() + chrono::Duration::hours(24);
        ath.db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();
        let set_cookie = ath.session_cookie(&token);
        let cookie = set_cookie.split(';').next().unwrap().to_string();

        let state = AppState {
            ath: ath.clone(),
            auth_client,
            base_url: "http://localhost:3000".into(),
            templates,
            is_production: false,
            login_attempts: Arc::new(dashmap::DashMap::new()),
            max_login_attempts: 10,
            rate_limit_window_secs: 900,
        };

        let app = test_app(state);
        let csrf = get_csrf_token(&app, &cookie).await;
        let req = password_request(
            &csrf,
            &cookie,
            "anypassword",
            "newpassword456",
            "newpassword456",
        );
        let resp = app.oneshot(req).await.unwrap();
        let html = body_string(resp).await;
        assert!(html.contains("Current password is incorrect"));
    }
}
