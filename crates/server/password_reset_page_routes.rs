use std::sync::Arc;

use axum::Form;
use axum::Router;
use axum::extract::{Extension, Query};
use axum::http::HeaderMap;
use axum::http::StatusCode;
use axum::http::header::COOKIE;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use minijinja::{Environment, context};
use serde::Deserialize;

use allowthem_core::{AllowThem, Email, EmailSender};

use crate::browser_error::BrowserError;
use crate::csrf::CsrfToken;

const MIN_PASSWORD_LEN: usize = 8;

#[derive(Clone)]
struct PasswordResetPageConfig {
    templates: Arc<Environment<'static>>,
    is_production: bool,
    email_sender: Arc<dyn EmailSender>,
    base_url: String,
}

#[derive(Deserialize)]
pub struct ResetTokenQuery {
    token: Option<String>,
}

#[derive(Deserialize)]
pub struct ForgotPasswordForm {
    email: String,
    #[allow(dead_code)]
    csrf_token: String,
}

#[derive(Deserialize)]
pub struct ResetPasswordForm {
    token: String,
    new_password: String,
    confirm_password: String,
    #[allow(dead_code)]
    csrf_token: String,
}

/// Render just the `_auth_main_forgot_password.html` partial plus the
/// `_auth_oob_head.html` OOB head swap, for HTMX fragment responses.
fn render_forgot_password_fragment(
    config: &PasswordResetPageConfig,
    csrf_token: &str,
    error: &str,
    success: bool,
) -> Result<Html<String>, BrowserError> {
    let ctx = context! {
        csrf_token,
        success,
        error,
        is_production => config.is_production,
        page_title => "Forgot password — allowthem",
        status_hint => "FORGOT PASSWORD",
    };

    let main = crate::browser_templates::render(
        &config.templates,
        "_partials/_auth_main_forgot_password.html",
        ctx.clone(),
    )?;
    let oob = crate::browser_templates::render(
        &config.templates,
        "_partials/_auth_oob_head.html",
        ctx,
    )?;
    Ok(Html(format!("{}{}", main.0, oob.0)))
}

/// GET /forgot-password — render the email input form.
async fn get_forgot_password(
    Extension(ath): Extension<AllowThem>,
    Extension(config): Extension<PasswordResetPageConfig>,
    headers: HeaderMap,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    if is_authenticated(&ath, &headers).await {
        return Ok((StatusCode::SEE_OTHER, [(axum::http::header::LOCATION, "/")]).into_response());
    }

    if crate::hx::is_hx_request(&headers) {
        let html = render_forgot_password_fragment(&config, csrf.as_str(), "", false)?;
        return Ok(html.into_response());
    }

    let html = crate::browser_templates::render(
        &config.templates,
        "forgot_password.html",
        context! {
            csrf_token => csrf.as_str(),
            success => false,
            error => "",
            is_production => config.is_production,
        },
    )?;
    Ok(html.into_response())
}

/// POST /forgot-password — initiate reset; always render success to prevent enumeration.
async fn post_forgot_password(
    Extension(ath): Extension<AllowThem>,
    Extension(config): Extension<PasswordResetPageConfig>,
    csrf: CsrfToken,
    Form(form): Form<ForgotPasswordForm>,
) -> Result<Response, BrowserError> {
    let email = match Email::new(form.email.clone()) {
        Ok(e) => e,
        Err(_) => {
            let html = crate::browser_templates::render(
                &config.templates,
                "forgot_password.html",
                context! {
                    csrf_token => csrf.as_str(),
                    success => false,
                    error => "Please enter a valid email address.",
                    is_production => config.is_production,
                },
            )?;
            return Ok(html.into_response());
        }
    };

    let sender: &dyn EmailSender = &*config.email_sender;
    if let Err(err) = ath
        .db()
        .send_password_reset(&email, &config.base_url, sender)
        .await
    {
        tracing::error!("password reset email error: {err}");
    }

    let html = crate::browser_templates::render(
        &config.templates,
        "forgot_password.html",
        context! {
            csrf_token => csrf.as_str(),
            success => true,
            error => "",
            is_production => config.is_production,
        },
    )?;
    Ok(html.into_response())
}

/// GET /auth/reset-password?token=... — validate token and render form or error state.
async fn get_reset_password(
    Extension(ath): Extension<AllowThem>,
    Extension(config): Extension<PasswordResetPageConfig>,
    csrf: CsrfToken,
    Query(query): Query<ResetTokenQuery>,
) -> Result<Response, BrowserError> {
    let token = match query.token {
        Some(ref t) if !t.is_empty() => t.clone(),
        _ => {
            let html = crate::browser_templates::render(
                &config.templates,
                "reset_password.html",
                context! {
                    csrf_token => csrf.as_str(),
                    token => "",
                    invalid_token => true,
                    success => false,
                    error => "",
                    is_production => config.is_production,
                },
            )?;
            return Ok(html.into_response());
        }
    };

    let valid = ath.db().validate_reset_token(&token).await?;

    if valid.is_some() {
        let html = crate::browser_templates::render(
            &config.templates,
            "reset_password.html",
            context! {
                csrf_token => csrf.as_str(),
                token,
                invalid_token => false,
                success => false,
                error => "",
                is_production => config.is_production,
            },
        )?;
        Ok(html.into_response())
    } else {
        let html = crate::browser_templates::render(
            &config.templates,
            "reset_password.html",
            context! {
                csrf_token => csrf.as_str(),
                token => "",
                invalid_token => true,
                success => false,
                error => "",
                is_production => config.is_production,
            },
        )?;
        Ok(html.into_response())
    }
}

/// POST /auth/reset-password — execute the password reset.
async fn post_reset_password(
    Extension(ath): Extension<AllowThem>,
    Extension(config): Extension<PasswordResetPageConfig>,
    csrf: CsrfToken,
    Form(form): Form<ResetPasswordForm>,
) -> Result<Response, BrowserError> {
    // Validate: passwords match
    if form.new_password != form.confirm_password {
        let html = crate::browser_templates::render(
            &config.templates,
            "reset_password.html",
            context! {
                csrf_token => csrf.as_str(),
                token => form.token,
                invalid_token => false,
                success => false,
                error => "Passwords do not match",
                is_production => config.is_production,
            },
        )?;
        return Ok(html.into_response());
    }

    // Validate: password length
    if form.new_password.len() < MIN_PASSWORD_LEN {
        let html = crate::browser_templates::render(
            &config.templates,
            "reset_password.html",
            context! {
                csrf_token => csrf.as_str(),
                token => form.token,
                invalid_token => false,
                success => false,
                error => "Password must be at least 8 characters",
                is_production => config.is_production,
            },
        )?;
        return Ok(html.into_response());
    }

    match ath
        .db()
        .execute_reset(&form.token, &form.new_password)
        .await?
    {
        true => {
            let html = crate::browser_templates::render(
                &config.templates,
                "reset_password.html",
                context! {
                    csrf_token => csrf.as_str(),
                    token => "",
                    invalid_token => false,
                    success => true,
                    error => "",
                    is_production => config.is_production,
                },
            )?;
            Ok(html.into_response())
        }
        false => {
            let html = crate::browser_templates::render(
                &config.templates,
                "reset_password.html",
                context! {
                    csrf_token => csrf.as_str(),
                    token => "",
                    invalid_token => true,
                    success => false,
                    error => "",
                    is_production => config.is_production,
                },
            )?;
            Ok(html.into_response())
        }
    }
}

/// Returns true if the request carries a valid session cookie.
async fn is_authenticated(ath: &AllowThem, headers: &HeaderMap) -> bool {
    let Some(cookie_header) = headers.get(COOKIE).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(token) = ath.parse_session_cookie(cookie_header) else {
        return false;
    };
    let ttl = ath.session_config().ttl;
    ath.db()
        .validate_session(&token, ttl)
        .await
        .unwrap_or(None)
        .is_some()
}

pub fn password_reset_page_routes(
    templates: Arc<Environment<'static>>,
    is_production: bool,
    email_sender: Arc<dyn EmailSender>,
    base_url: String,
) -> Router<()> {
    let cfg = PasswordResetPageConfig {
        templates,
        is_production,
        email_sender,
        base_url,
    };
    Router::new()
        .route(
            "/forgot-password",
            get(get_forgot_password).post(post_forgot_password),
        )
        .route(
            "/auth/reset-password",
            get(get_reset_password).post(post_reset_password),
        )
        .layer(Extension(cfg))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use tower::ServiceExt;

    use allowthem_core::{AllowThem, AllowThemBuilder, Email, LogEmailSender};

    use super::{PasswordResetPageConfig, password_reset_page_routes, render_forgot_password_fragment};

    async fn setup() -> (AllowThem, PasswordResetPageConfig) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .csrf_key(*b"test-csrf-key-for-binary-tests!!")
            .build()
            .await
            .unwrap();
        let templates = crate::browser_templates::build_default_browser_env();
        let config = PasswordResetPageConfig {
            templates,
            is_production: false,
            email_sender: Arc::new(LogEmailSender),
            base_url: "http://localhost:3000".into(),
        };
        (ath, config)
    }

    fn test_app(ath: AllowThem, config: PasswordResetPageConfig) -> Router {
        password_reset_page_routes(
            config.templates.clone(),
            config.is_production,
            config.email_sender.clone(),
            config.base_url.clone(),
        )
        .layer(axum::middleware::from_fn(crate::csrf::csrf_middleware))
        .layer(axum::middleware::from_fn_with_state(
            ath.clone(),
            crate::cors::inject_ath_into_extensions,
        ))
    }

    async fn get_csrf_token(app: &Router, path: &str) -> String {
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
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

    async fn create_user_and_token(ath: &AllowThem, email_str: &str) -> String {
        let email = Email::new(email_str.into()).unwrap();
        ath.db()
            .create_user(email.clone(), "OldPass123!", None, None)
            .await
            .unwrap();
        ath.db()
            .create_password_reset(&email)
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn get_forgot_password_renders_form() {
        let (ath, config) = setup().await;
        let app = test_app(ath, config);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/forgot-password")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("<form"));
        assert!(html.contains("name=\"email\""));
    }

    #[tokio::test]
    async fn post_forgot_password_valid_email_shows_success() {
        let (ath, config) = setup().await;
        let email = Email::new("reset@example.com".into()).unwrap();
        ath.db()
            .create_user(email, "Pass123!", None, None)
            .await
            .unwrap();
        let app = test_app(ath, config);
        let csrf = get_csrf_token(&app, "/forgot-password").await;

        let req = Request::builder()
            .method("POST")
            .uri("/forgot-password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_pre={csrf}"))
            .body(Body::from(format!(
                "email=reset%40example.com&csrf_token={csrf}"
            )))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("If an account with that email exists"));
    }

    #[tokio::test]
    async fn post_forgot_password_unknown_email_shows_success() {
        let (ath, config) = setup().await;
        let app = test_app(ath, config);
        let csrf = get_csrf_token(&app, "/forgot-password").await;

        let req = Request::builder()
            .method("POST")
            .uri("/forgot-password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_pre={csrf}"))
            .body(Body::from(format!(
                "email=nobody%40example.com&csrf_token={csrf}"
            )))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("If an account with that email exists"));
    }

    #[tokio::test]
    async fn post_forgot_password_invalid_email_shows_error() {
        let (ath, config) = setup().await;
        let app = test_app(ath, config);
        let csrf = get_csrf_token(&app, "/forgot-password").await;

        let req = Request::builder()
            .method("POST")
            .uri("/forgot-password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_pre={csrf}"))
            .body(Body::from(format!("email=notanemail&csrf_token={csrf}")))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("Please enter a valid email address."));
    }

    #[tokio::test]
    async fn get_reset_password_valid_token_renders_form() {
        let (ath, config) = setup().await;
        let token = create_user_and_token(&ath, "tok@example.com").await;
        let app = test_app(ath, config);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri(format!("/auth/reset-password?token={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("name=\"new_password\""));
        assert!(html.contains("name=\"confirm_password\""));
    }

    #[tokio::test]
    async fn get_reset_password_invalid_token_shows_error() {
        let (ath, config) = setup().await;
        let app = test_app(ath, config);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/auth/reset-password?token=invalidtoken")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("invalid or has expired"));
        assert!(!html.contains("name=\"new_password\""));
    }

    #[tokio::test]
    async fn post_reset_password_passwords_mismatch_shows_error() {
        let (ath, config) = setup().await;
        let token = create_user_and_token(&ath, "mismatch@example.com").await;
        let app = test_app(ath, config);
        let csrf = get_csrf_token(&app, &format!("/auth/reset-password?token={token}")).await;

        let req = Request::builder()
            .method("POST")
            .uri("/auth/reset-password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_pre={csrf}"))
            .body(Body::from(format!(
                "token={token}&new_password=NewPass999!&confirm_password=Different1!&csrf_token={csrf}"
            )))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("Passwords do not match"));
    }

    #[tokio::test]
    async fn post_reset_password_too_short_shows_error() {
        let (ath, config) = setup().await;
        let token = create_user_and_token(&ath, "short@example.com").await;
        let app = test_app(ath, config);
        let csrf = get_csrf_token(&app, &format!("/auth/reset-password?token={token}")).await;

        let req = Request::builder()
            .method("POST")
            .uri("/auth/reset-password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_pre={csrf}"))
            .body(Body::from(format!(
                "token={token}&new_password=short&confirm_password=short&csrf_token={csrf}"
            )))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("Password must be at least 8 characters"));
    }

    #[tokio::test]
    async fn post_reset_password_success_shows_confirmation() {
        let (ath, config) = setup().await;
        let token = create_user_and_token(&ath, "success@example.com").await;
        let app = test_app(ath, config);
        let csrf = get_csrf_token(&app, &format!("/auth/reset-password?token={token}")).await;

        let req = Request::builder()
            .method("POST")
            .uri("/auth/reset-password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_pre={csrf}"))
            .body(Body::from(format!(
                "token={token}&new_password=NewPass999!&confirm_password=NewPass999!&csrf_token={csrf}"
            )))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("Your password has been reset"));
    }

    #[tokio::test]
    async fn post_reset_password_used_token_shows_invalid() {
        let (ath, config) = setup().await;
        let token = create_user_and_token(&ath, "used@example.com").await;
        // Consume the token directly via DB
        ath.db()
            .execute_reset(&token, "AlreadyUsed1!")
            .await
            .unwrap();

        let app = test_app(ath, config);
        let csrf = get_csrf_token(&app, "/forgot-password").await;

        let req = Request::builder()
            .method("POST")
            .uri("/auth/reset-password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_pre={csrf}"))
            .body(Body::from(format!(
                "token={token}&new_password=NewPass999!&confirm_password=NewPass999!&csrf_token={csrf}"
            )))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("invalid or has expired"));
    }

    #[tokio::test]
    async fn get_forgot_password_logged_in_redirects_to_root() {
        use allowthem_core::{generate_token, hash_token};
        use chrono::{Duration, Utc};

        let (ath, config) = setup().await;

        // Create a user and an active session
        let email = Email::new("loggedin@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
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
        let session_cookie = ath.session_cookie(&token);
        let cookie_value = session_cookie.split(';').next().unwrap().to_string();

        let app = test_app(ath, config);
        let req = Request::builder()
            .uri("/forgot-password")
            .header(header::COOKIE, cookie_value)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/");
    }

    #[tokio::test]
    async fn get_forgot_password_hx_request_returns_fragment() {
        let (ath, config) = setup().await;
        let app = test_app(ath, config);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/forgot-password")
                    .header("HX-Request", "true")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(
            html.contains("<main class=\"wf-auth-form\">"),
            "HX response must be a fragment starting at <main>"
        );
        assert!(
            !html.contains("<html"),
            "HX response must not render the full shell"
        );
    }

    #[tokio::test]
    async fn render_forgot_password_fragment_composes_main_and_oob_head() {
        let (_ath, config) = setup().await;
        let html = render_forgot_password_fragment(&config, "tok", "", false)
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
    }
}
