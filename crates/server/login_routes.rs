use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use axum::Form;
use axum::Router;
use axum::extract::{ConnectInfo, Extension, Query};
use axum::http::header::{COOKIE, SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use chrono::Utc;
use dashmap::DashMap;
use minijinja::{Environment, context};
use serde::Deserialize;

use allowthem_core::applications::BrandingConfig;
#[cfg(test)]
use allowthem_core::applications::CreateApplicationParams;
use allowthem_core::password::verify_password;
use allowthem_core::sessions;
use allowthem_core::types::ClientId;
use allowthem_core::{AllowThem, AuditEvent, PasswordHash, SessionToken};

use crate::branding::{compute_accent_variants, default_accents, lookup_branding};
use crate::browser_error::BrowserError;
use crate::csrf::CsrfToken;

/// Generic error shown for all credential failures.
const LOGIN_ERROR: &str = "Invalid email or password.";

/// Pre-computed Argon2id hash for timing equalization when a user is not found.
/// The actual value doesn't matter — we just need `verify_password()` to run its
/// full Argon2id computation so the response time is consistent.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$ldQz3PJVzDn06G+Bzin5Ew$IaOeOaTQjgM1uJpHDULCxq8r6pj2OqvY/lcKo6Fv3IM";

#[derive(Clone)]
struct LoginConfig {
    templates: Arc<Environment<'static>>,
    is_production: bool,
    login_attempts: Arc<DashMap<IpAddr, (u32, Instant)>>,
    max_login_attempts: u32,
    rate_limit_window_secs: u64,
    oauth_providers: Vec<String>,
}

#[derive(Deserialize)]
struct LoginQuery {
    next: Option<String>,
    client_id: Option<ClientId>,
}

#[derive(Deserialize)]
struct LoginForm {
    identifier: String,
    password: String,
    next: Option<String>,
    client_id: Option<ClientId>,
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

fn extract_session_token(ath: &AllowThem, headers: &HeaderMap) -> Option<SessionToken> {
    headers
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| ath.parse_session_cookie(v))
}

fn render_login_form(
    config: &LoginConfig,
    csrf_token: &str,
    identifier: &str,
    next: Option<&str>,
    error: &str,
    client_id: Option<&ClientId>,
    branding: Option<&BrandingConfig>,
) -> Result<Html<String>, BrowserError> {
    let next_val = next.map(validate_next).unwrap_or("");
    let (accent, accent_hover, accent_ring) = branding
        .and_then(|b| b.primary_color.as_deref())
        .map(compute_accent_variants)
        .unwrap_or_else(default_accents);

    crate::browser_templates::render(
        &config.templates,
        "login.html",
        context! {
            csrf_token,
            next => next_val,
            error,
            identifier,
            client_id => client_id.map(|c| c.as_str()),
            app_name => branding.map(|b| b.application_name.as_str()),
            logo_url => branding.and_then(|b| b.logo_url.as_deref()),
            accent,
            accent_hover,
            accent_ring,
            oauth_providers => &config.oauth_providers,
            is_production => config.is_production,
        },
    )
}

fn is_rate_limited(config: &LoginConfig, ip: IpAddr) -> bool {
    if let Some(entry) = config.login_attempts.get(&ip) {
        let (count, window_start) = *entry;
        if window_start.elapsed().as_secs() > config.rate_limit_window_secs {
            return false;
        }
        count >= config.max_login_attempts
    } else {
        false
    }
}

fn record_login_failure(config: &LoginConfig, ip: IpAddr) {
    let now = Instant::now();
    config
        .login_attempts
        .entry(ip)
        .and_modify(|(count, window_start)| {
            if window_start.elapsed().as_secs() > config.rate_limit_window_secs {
                *count = 1;
                *window_start = now;
            } else {
                *count += 1;
            }
        })
        .or_insert((1, now));
}

fn record_login_success(config: &LoginConfig, ip: IpAddr) {
    config.login_attempts.remove(&ip);
}

/// GET /login — render the login form, or redirect if already authenticated.
async fn get_login(
    Extension(ath): Extension<AllowThem>,
    Extension(config): Extension<LoginConfig>,
    csrf: CsrfToken,
    Query(query): Query<LoginQuery>,
    headers: HeaderMap,
) -> Result<Response, BrowserError> {
    // If already authenticated, redirect
    if let Some(token) = extract_session_token(&ath, &headers)
        && ath.db().lookup_session(&token).await?.is_some()
    {
        let dest = query.next.as_deref().map(validate_next).unwrap_or("/");
        return Ok((
            StatusCode::SEE_OTHER,
            [(axum::http::header::LOCATION, dest.to_string())],
        )
            .into_response());
    }

    let branding = lookup_branding(&ath, query.client_id.as_ref()).await;
    let html = render_login_form(
        &config,
        csrf.as_str(),
        "",
        query.next.as_deref(),
        "",
        query.client_id.as_ref(),
        branding.as_ref(),
    )?;
    Ok(html.into_response())
}

/// POST /login — validate credentials, create session on success.
async fn post_login(
    Extension(ath): Extension<AllowThem>,
    Extension(config): Extension<LoginConfig>,
    csrf: CsrfToken,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(form): Form<LoginForm>,
) -> Result<Response, BrowserError> {
    let ip = addr.ip();
    let ua = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());
    let ip_str = ip.to_string();
    let branding = lookup_branding(&ath, form.client_id.as_ref()).await;

    // 1. Rate limit check
    if is_rate_limited(&config, ip) {
        let html = render_login_form(
            &config,
            csrf.as_str(),
            &form.identifier,
            form.next.as_deref(),
            "Too many login attempts. Please try again later.",
            form.client_id.as_ref(),
            branding.as_ref(),
        )?;
        return Ok((StatusCode::TOO_MANY_REQUESTS, html).into_response());
    }

    let identifier = form.identifier.trim();
    if identifier.is_empty() {
        let html = render_login_form(
            &config,
            csrf.as_str(),
            "",
            form.next.as_deref(),
            LOGIN_ERROR,
            form.client_id.as_ref(),
            branding.as_ref(),
        )?;
        return Ok(html.into_response());
    }

    // 2. Look up user
    let dummy = PasswordHash::new_unchecked(DUMMY_HASH.to_string());
    let user = ath.db().find_for_login(identifier).await;

    match user {
        Ok(user) => {
            let hash = user.password_hash.as_ref().unwrap_or(&dummy);
            let password_ok = verify_password(&form.password, hash).unwrap_or(false);

            if password_ok && user.is_active {
                // Success
                record_login_success(&config, ip);

                // MFA gate: if user has MFA enabled, redirect to challenge page
                if ath.has_mfa_enabled(user.id).await? {
                    let mfa_token = ath.db().create_mfa_challenge(user.id).await?;
                    let dest = format!("/mfa/challenge?token={mfa_token}");
                    return Ok((
                        StatusCode::SEE_OTHER,
                        [(axum::http::header::LOCATION, dest)],
                    )
                        .into_response());
                }

                let token = sessions::generate_token();
                let token_hash = sessions::hash_token(&token);
                let ttl = ath.session_config().ttl;
                let expires_at = Utc::now() + ttl;
                ath.db()
                    .create_session(user.id, token_hash, Some(&ip_str), ua, expires_at)
                    .await?;

                let cookie = ath.session_cookie(&token);
                let _ = ath
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
                let _ = ath
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
                record_login_failure(&config, ip);

                let html = render_login_form(
                    &config,
                    csrf.as_str(),
                    identifier,
                    form.next.as_deref(),
                    LOGIN_ERROR,
                    form.client_id.as_ref(),
                    branding.as_ref(),
                )?;
                Ok(html.into_response())
            }
        }
        Err(allowthem_core::AuthError::NotFound) => {
            // Timing equalization: run verify against dummy hash
            let _ = verify_password(&form.password, &dummy);

            let _ = ath
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
            record_login_failure(&config, ip);

            let html = render_login_form(
                &config,
                csrf.as_str(),
                identifier,
                form.next.as_deref(),
                LOGIN_ERROR,
                form.client_id.as_ref(),
                branding.as_ref(),
            )?;
            Ok(html.into_response())
        }
        Err(e) => Err(BrowserError::Auth(e)),
    }
}

pub fn login_routes(
    templates: Arc<Environment<'static>>,
    is_production: bool,
    max_login_attempts: u32,
    rate_limit_window_secs: u64,
    oauth_providers: Vec<String>,
) -> Router<()> {
    let cfg = LoginConfig {
        templates,
        is_production,
        login_attempts: Arc::new(DashMap::new()),
        max_login_attempts,
        rate_limit_window_secs,
        oauth_providers,
    };
    Router::new()
        .route("/login", get(get_login).post(post_login))
        .layer(Extension(cfg))
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::Router;
    use axum::body::Body;
    use axum::extract::connect_info::MockConnectInfo;
    use axum::http::{Request, StatusCode, header};
    use chrono::Duration;
    use tower::ServiceExt;

    use allowthem_core::types::ClientType;
    use allowthem_core::{AllowThemBuilder, Email, generate_token, hash_token};

    async fn setup() -> (AllowThem, LoginConfig) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .csrf_key(*b"test-csrf-key-for-binary-tests!!")
            .build()
            .await
            .unwrap();
        let templates = crate::browser_templates::build_default_browser_env();
        let config = LoginConfig {
            templates,
            is_production: false,
            login_attempts: Arc::new(DashMap::new()),
            max_login_attempts: 10,
            rate_limit_window_secs: 900,
            oauth_providers: Vec::new(),
        };
        (ath, config)
    }

    fn test_app(ath: AllowThem, config: LoginConfig) -> Router {
        login_routes(
            config.templates.clone(),
            config.is_production,
            config.max_login_attempts,
            config.rate_limit_window_secs,
            config.oauth_providers.clone(),
        )
        .layer(axum::middleware::from_fn(crate::csrf::csrf_middleware))
        .layer(MockConnectInfo(SocketAddr::from(([127, 0, 0, 1], 0))))
        .layer(axum::middleware::from_fn_with_state(
            ath.clone(),
            crate::cors::inject_ath_into_extensions,
        ))
    }

    async fn get_csrf_token(app: &Router) -> String {
        let req = Request::builder()
            .uri("/login")
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

    fn login_request(
        csrf: &str,
        identifier: &str,
        password: &str,
        next: Option<&str>,
    ) -> Request<Body> {
        let mut body = format!(
            "identifier={}&password={}&csrf_token={}",
            identifier, password, csrf
        );
        if let Some(n) = next {
            body.push_str(&format!("&next={}", n));
        }
        Request::builder()
            .method("POST")
            .uri("/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_pre={}", csrf))
            .body(Body::from(body))
            .unwrap()
    }

    async fn create_user(ath: &AllowThem, email: &str, password: &str) {
        let email = Email::new(email.into()).unwrap();
        ath.db()
            .create_user(email, password, None, None)
            .await
            .unwrap();
    }

    // --- Unit tests ---

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

    // --- Integration tests ---

    #[tokio::test]
    async fn get_login_renders_form() {
        let (ath, config) = setup().await;
        let app = test_app(ath, config);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("<form"), "should contain a form");
        assert!(html.contains("csrf_token"), "should contain csrf_token");
        assert!(
            html.contains("identifier"),
            "should contain identifier input"
        );
    }

    #[tokio::test]
    async fn get_login_redirects_when_authenticated() {
        let (ath, config) = setup().await;

        let email = Email::new("auth@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "pass123", None, None)
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
        let cookie_val = cookie.split(';').next().unwrap();

        let app = test_app(ath, config);
        let req = Request::builder()
            .uri("/login")
            .header(header::COOKIE, cookie_val)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/");
    }

    #[tokio::test]
    async fn get_login_preserves_next_param() {
        let (ath, config) = setup().await;
        let app = test_app(ath, config);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/login?next=/dashboard")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        // MiniJinja auto-escapes / as &#x2f; in attribute values
        assert!(
            html.contains("name=\"next\""),
            "should contain next hidden field"
        );
        assert!(
            html.contains("dashboard"),
            "next field should contain dashboard"
        );
    }

    #[tokio::test]
    async fn post_login_success_redirects() {
        let (ath, config) = setup().await;
        create_user(&ath, "login@example.com", "correcthorse").await;
        let app = test_app(ath, config);

        let csrf = get_csrf_token(&app).await;
        let req = login_request(&csrf, "login@example.com", "correcthorse", None);
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/");
        assert!(
            resp.headers().get(SET_COOKIE).is_some(),
            "should set session cookie"
        );
    }

    #[tokio::test]
    async fn post_login_success_redirects_to_next() {
        let (ath, config) = setup().await;
        create_user(&ath, "next@example.com", "correcthorse").await;
        let app = test_app(ath, config);

        let csrf = get_csrf_token(&app).await;
        let req = login_request(
            &csrf,
            "next@example.com",
            "correcthorse",
            Some("/dashboard"),
        );
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/dashboard");
    }

    #[tokio::test]
    async fn post_login_wrong_password_shows_error() {
        let (ath, config) = setup().await;
        create_user(&ath, "wrong@example.com", "correcthorse").await;
        let app = test_app(ath, config);

        let csrf = get_csrf_token(&app).await;
        let req = login_request(&csrf, "wrong@example.com", "wrongpassword", None);
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains(LOGIN_ERROR), "should show generic error");
        assert!(
            html.contains("wrong@example.com"),
            "should pre-fill identifier"
        );
    }

    #[tokio::test]
    async fn post_login_nonexistent_user_shows_error() {
        let (ath, config) = setup().await;
        let app = test_app(ath, config);

        let csrf = get_csrf_token(&app).await;
        let req = login_request(&csrf, "nobody@example.com", "anypassword", None);
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            html.contains(LOGIN_ERROR),
            "should show same generic error as wrong password"
        );
    }

    #[tokio::test]
    async fn post_login_inactive_user_shows_error() {
        let (ath, config) = setup().await;
        let email = Email::new("inactive@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "correcthorse", None, None)
            .await
            .unwrap();
        ath.db().update_user_active(user.id, false).await.unwrap();

        let app = test_app(ath, config);
        let csrf = get_csrf_token(&app).await;
        let req = login_request(&csrf, "inactive@example.com", "correcthorse", None);
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            html.contains(LOGIN_ERROR),
            "inactive user should get generic error"
        );
    }

    #[tokio::test]
    async fn post_login_rate_limit() {
        let (ath, config) = setup().await;
        let app = test_app(ath, config);

        let csrf = get_csrf_token(&app).await;

        // Exhaust rate limit
        for _ in 0..10_u32 {
            let req = login_request(&csrf, "nobody@example.com", "wrong", None);
            let _ = app.clone().oneshot(req).await.unwrap();
        }

        // Next attempt should be rate limited
        let req = login_request(&csrf, "nobody@example.com", "wrong", None);
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Too many login attempts"));
    }

    #[tokio::test]
    async fn post_login_csrf_required() {
        let (ath, config) = setup().await;
        let app = test_app(ath, config);

        let req = Request::builder()
            .method("POST")
            .uri("/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from("identifier=test&password=test"))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    #[ignore = "TODO(task-7): re-enable after resolve_accent migration"]
    async fn login_with_client_id_shows_branding() {
        let (ath, config) = setup().await;
        let (app, _) = ath
            .db()
            .create_application(CreateApplicationParams {
                name: "BrandedApp".into(),
                client_type: ClientType::Confidential,
                redirect_uris: vec!["https://example.com/cb".into()],
                is_trusted: false,
                created_by: None,
                logo_url: Some("https://cdn.example.com/logo.png".into()),
                primary_color: Some("#ff6600".into()),
                accent_hex: None,
                accent_ink: None,
                forced_mode: None,
                font_css_url: None,
                font_family: None,
                splash_text: None,
                splash_image_url: None,
                splash_primitive: None,
                splash_url: None,
                shader_cell_scale: None,
            })
            .await
            .unwrap();
        let router = test_app(ath, config);

        let req = Request::builder()
            .uri(&format!("/login?client_id={}", app.client_id))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("BrandedApp"), "should show app name");
        assert!(html.contains("<img"), "should show logo");
        assert!(html.contains("#ff6600"), "should have accent color");
    }

    #[tokio::test]
    #[ignore = "TODO(task-7): re-enable after resolve_accent migration"]
    async fn login_without_client_id_shows_default() {
        let (ath, config) = setup().await;
        let router = test_app(ath, config);

        let req = Request::builder()
            .uri("/login")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(!html.contains("<img"), "no logo without client_id");
        assert!(html.contains("#2563eb"), "should have default blue");
    }

    #[tokio::test]
    #[ignore = "TODO(task-7): re-enable after resolve_accent migration"]
    async fn login_with_invalid_client_id_shows_default() {
        let (ath, config) = setup().await;
        let router = test_app(ath, config);

        let req = Request::builder()
            .uri("/login?client_id=ath_nonexistent")
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(!html.contains("<img"), "no logo for invalid client_id");
        assert!(html.contains("#2563eb"), "should fall back to default blue");
    }

    #[tokio::test]
    #[ignore = "TODO(task-7): re-enable after resolve_accent migration"]
    async fn branded_login_post_failure_preserves_branding() {
        let (ath, config) = setup().await;
        create_user(&ath, "branded@example.com", "correcthorse").await;
        let (app, _) = ath
            .db()
            .create_application(CreateApplicationParams {
                name: "BrandedPost".into(),
                client_type: ClientType::Confidential,
                redirect_uris: vec!["https://example.com/cb".into()],
                is_trusted: false,
                created_by: None,
                logo_url: None,
                primary_color: Some("#ff6600".into()),
                accent_hex: None,
                accent_ink: None,
                forced_mode: None,
                font_css_url: None,
                font_family: None,
                splash_text: None,
                splash_image_url: None,
                splash_primitive: None,
                splash_url: None,
                shader_cell_scale: None,
            })
            .await
            .unwrap();
        let router = test_app(ath, config);

        let csrf = get_csrf_token(&router).await;
        let body_str = format!(
            "identifier=branded%40example.com&password=wrong&csrf_token={}&client_id={}",
            csrf, app.client_id,
        );
        let req = Request::builder()
            .method("POST")
            .uri("/login")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_pre={}", csrf))
            .body(Body::from(body_str))
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            html.contains("BrandedPost"),
            "app name preserved after error"
        );
        assert!(
            html.contains("#ff6600"),
            "accent color preserved after error"
        );
    }

    #[tokio::test]
    async fn post_login_with_mfa_enabled_redirects_to_challenge_without_session() {
        // When a user has MFA enabled, correct credentials must NOT create a session —
        // they must redirect to /mfa/challenge?token=... instead.
        const MFA_KEY: [u8; 32] = [0x42; 32];
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .mfa_key(MFA_KEY)
            .csrf_key(*b"test-csrf-key-for-binary-tests!!")
            .build()
            .await
            .unwrap();
        let config = LoginConfig {
            templates: crate::browser_templates::build_default_browser_env(),
            is_production: false,
            login_attempts: Arc::new(DashMap::new()),
            max_login_attempts: 10,
            rate_limit_window_secs: 900,
            oauth_providers: Vec::new(),
        };

        // Create user and enable MFA
        create_user(&ath, "mfa-gate@example.com", "correcthorse").await;
        let user = ath
            .db()
            .find_for_login("mfa-gate@example.com")
            .await
            .unwrap();
        let secret = ath.create_mfa_secret(user.id).await.unwrap();
        use totp_rs::{Algorithm, Secret, TOTP};
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
        ath.enable_mfa(user.id, &code).await.unwrap();

        let app = test_app(ath, config);
        let csrf = get_csrf_token(&app).await;
        let req = login_request(&csrf, "mfa-gate@example.com", "correcthorse", None);
        let resp = app.oneshot(req).await.unwrap();

        // Must redirect to MFA challenge page, not to /
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(
            location.starts_with("/mfa/challenge?token="),
            "MFA gate must redirect to /mfa/challenge, got: {location}"
        );
        // Must NOT set a session cookie
        assert!(
            resp.headers().get(SET_COOKIE).is_none(),
            "MFA gate must not set a session cookie before TOTP is verified"
        );
    }

    #[tokio::test]
    async fn login_register_link_carries_client_id() {
        let (ath, config) = setup().await;
        let (app, _) = ath
            .db()
            .create_application(CreateApplicationParams {
                name: "LinkApp".into(),
                client_type: ClientType::Confidential,
                redirect_uris: vec!["https://example.com/cb".into()],
                is_trusted: false,
                created_by: None,
                logo_url: None,
                primary_color: None,
                accent_hex: None,
                accent_ink: None,
                forced_mode: None,
                font_css_url: None,
                font_family: None,
                splash_text: None,
                splash_image_url: None,
                splash_primitive: None,
                splash_url: None,
                shader_cell_scale: None,
            })
            .await
            .unwrap();
        let router = test_app(ath, config);

        let req = Request::builder()
            .uri(&format!("/login?client_id={}", app.client_id))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            html.contains(&format!("/register?client_id={}", app.client_id)),
            "register link should carry client_id"
        );
    }
}
