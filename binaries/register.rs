use axum::Form;
use axum::extract::State;
use axum::http::header::USER_AGENT;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::Utc;
use minijinja::context;
use serde::Deserialize;

use allowthem_core::{AuditEvent, AuthError, Email, Username, generate_token, hash_token};
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
        return Ok((StatusCode::SEE_OTHER, [(axum::http::header::LOCATION, "/")]).into_response());
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
    let user = match state
        .ath
        .db()
        .create_user(email, &form.password, username)
        .await
    {
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
            return render_form_error(&state, &csrf, &form, "This username is already taken");
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::get;
    use tower::ServiceExt;

    use allowthem_core::{
        AllowThem, AllowThemBuilder, AuditEvent, AuthClient, Email, EmbeddedAuthClient, Username,
        parse_session_cookie,
    };
    use allowthem_server::csrf_middleware;

    use crate::state::AppState;

    async fn setup() -> (AllowThem, AppState) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();
        let auth_client: Arc<dyn AuthClient> =
            Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
        let templates = crate::templates::build_template_env().unwrap();
        let state = AppState {
            ath: ath.clone(),
            auth_client,
            base_url: "http://localhost:3000".into(),
            templates,
            is_production: false,
            login_attempts: Arc::new(dashmap::DashMap::new()),
        };
        (ath, state)
    }

    fn test_app(state: AppState) -> Router {
        Router::new()
            .route(
                "/register",
                get(super::get_register).post(super::post_register),
            )
            .layer(axum::middleware::from_fn(csrf_middleware))
            .with_state(state)
    }

    /// Send GET /register, extract the csrf_token cookie value from Set-Cookie.
    async fn get_csrf_token(app: &Router) -> String {
        let req = Request::builder()
            .uri("/register")
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
        // Parse "csrf_token=<value>; ..." -> "<value>"
        set_cookie
            .split(';')
            .next()
            .unwrap()
            .split('=')
            .nth(1)
            .unwrap()
            .to_string()
    }

    fn register_request(
        csrf: &str,
        email: &str,
        password: &str,
        confirm: &str,
        username: &str,
    ) -> Request<Body> {
        // Minimal URL-encoding: replace @ with %40 for email addresses.
        // Test values use simple ASCII, so this is sufficient.
        let enc = |s: &str| s.replace('@', "%40");
        let body = format!(
            "csrf_token={}&email={}&password={}&password_confirm={}&username={}",
            csrf,
            enc(email),
            enc(password),
            enc(confirm),
            enc(username),
        );
        Request::builder()
            .method("POST")
            .uri("/register")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_token={}", csrf))
            .body(Body::from(body))
            .unwrap()
    }

    async fn body_string(resp: axum::http::Response<Body>) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn get_register_renders_form() {
        let (_, state) = setup().await;
        let app = test_app(state);
        let req = Request::builder()
            .uri("/register")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("<form"));
        assert!(html.contains("csrf_token"));
        assert!(html.contains("name=\"email\""));
        assert!(html.contains("name=\"password\""));
        assert!(html.contains("name=\"password_confirm\""));
    }

    #[tokio::test]
    async fn post_register_success_redirects() {
        let (_, state) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(&csrf, "test@example.com", "password123", "password123", "");
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/");
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(set_cookie.contains("allowthem_session"));
    }

    #[tokio::test]
    async fn post_register_creates_user() {
        let (ath, state) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(
            &csrf,
            "new@example.com",
            "password123",
            "password123",
            "myuser",
        );
        app.oneshot(req).await.unwrap();

        let email = Email::new("new@example.com".into()).unwrap();
        let user = ath.db().get_user_by_email(&email).await.unwrap();
        assert_eq!(user.email, email);
        assert_eq!(user.username.as_ref().map(|u| u.as_str()), Some("myuser"));
    }

    #[tokio::test]
    async fn post_register_creates_session() {
        let (ath, state) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(&csrf, "sess@example.com", "password123", "password123", "");
        let resp = app.oneshot(req).await.unwrap();

        // Extract session token from Set-Cookie header and verify in DB
        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        let token = parse_session_cookie(set_cookie, "allowthem_session")
            .expect("session cookie should be present");
        let session = ath.db().lookup_session(&token).await.unwrap();
        assert!(session.is_some(), "session should exist in DB");
    }

    #[tokio::test]
    async fn post_register_logs_audit() {
        let (ath, state) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(&csrf, "audit@example.com", "password123", "password123", "");
        app.oneshot(req).await.unwrap();

        let entries = ath.db().get_audit_log(None, 10, 0).await.unwrap();
        let register_entry = entries
            .iter()
            .find(|e| e.event_type == AuditEvent::Register);
        assert!(
            register_entry.is_some(),
            "register audit event should be recorded"
        );
    }

    #[tokio::test]
    async fn post_register_password_mismatch() {
        let (_, state) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(
            &csrf,
            "mismatch@example.com",
            "password123",
            "different456",
            "",
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("Passwords do not match"));
        assert!(html.contains("mismatch@example.com"));
    }

    #[tokio::test]
    async fn post_register_password_too_short() {
        let (_, state) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(&csrf, "short@example.com", "abc", "abc", "");
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("Password must be at least 8 characters"));
    }

    #[tokio::test]
    async fn post_register_invalid_email() {
        let (_, state) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(&csrf, "not-an-email", "password123", "password123", "");
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("Invalid email address"));
    }

    #[tokio::test]
    async fn post_register_duplicate_email() {
        let (ath, state) = setup().await;
        // Pre-create user with this email
        let email = Email::new("dupe@example.com".into()).unwrap();
        ath.db()
            .create_user(email, "existing123", None)
            .await
            .unwrap();

        let app = test_app(state);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(&csrf, "dupe@example.com", "password123", "password123", "");
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("An account with this email already exists"));
    }

    #[tokio::test]
    async fn post_register_duplicate_username() {
        let (ath, state) = setup().await;
        let email = Email::new("first@example.com".into()).unwrap();
        ath.db()
            .create_user(email, "existing123", Some(Username::new("taken")))
            .await
            .unwrap();

        let app = test_app(state);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(
            &csrf,
            "second@example.com",
            "password123",
            "password123",
            "taken",
        );
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("This username is already taken"));
    }

    #[tokio::test]
    async fn post_register_session_cookie_authenticates() {
        // Verify the session cookie issued on registration is usable for auth —
        // not just that a session row exists in the DB.
        let (ath, state) = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app).await;
        let req = register_request(&csrf, "auth@example.com", "password123", "password123", "");
        let resp = app.oneshot(req).await.unwrap();

        let set_cookie = resp
            .headers()
            .get(header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        let token = parse_session_cookie(set_cookie, "allowthem_session")
            .expect("session cookie should be present");

        // validate_session should return Some(user) — cookie is live
        let ttl = ath.session_config().ttl;
        let session_result = ath.db().validate_session(&token, ttl).await.unwrap();
        assert!(
            session_result.is_some(),
            "session cookie issued at registration should be valid"
        );
    }

    #[tokio::test]
    async fn get_register_logged_in_redirects_to_root() {
        // Authenticated users hitting GET /register are sent to / instead of
        // seeing the form.
        use allowthem_core::{generate_token, hash_token};
        use chrono::{Duration, Utc};

        let (ath, state) = setup().await;

        // Create a user and an active session.
        let email = Email::new("loggedin@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();
        let token = generate_token();
        let token_hash = hash_token(&token);
        ath.db()
            .create_session(
                user.id,
                token_hash,
                None,
                None,
                Utc::now() + Duration::hours(24),
            )
            .await
            .unwrap();
        let set_cookie = ath.session_cookie(&token);
        let cookie_value = set_cookie.split(';').next().unwrap().to_string();

        let app = test_app(state);
        let req = Request::builder()
            .uri("/register")
            .header(header::COOKIE, cookie_value)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/");
    }

    #[tokio::test]
    async fn post_register_without_csrf_returns_403() {
        let (_, state) = setup().await;
        let app = test_app(state);
        let body = "email=test%40example.com&password=password123&password_confirm=password123";
        let req = Request::builder()
            .method("POST")
            .uri("/register")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
