use axum::Form;
use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use minijinja::context;
use serde::Deserialize;

use allowthem_core::{Email, EmailSender};
use allowthem_server::CsrfToken;

use crate::error::AppError;
use crate::state::AppState;
use crate::templates::render;

const MIN_PASSWORD_LEN: usize = 8;

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

/// GET /forgot-password — render the email input form.
pub async fn get_forgot_password(
    State(state): State<AppState>,
    user: allowthem_server::OptionalAuthUser,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    if user.0.is_some() {
        return Ok(
            (StatusCode::SEE_OTHER, [(axum::http::header::LOCATION, "/")]).into_response(),
        );
    }

    let html = render(
        &state.templates,
        "forgot_password.html",
        context! {
            csrf_token => csrf.as_str(),
            success => false,
            error => "",
        },
        state.is_production,
    )?;
    Ok(html.into_response())
}

/// POST /forgot-password — initiate reset; always render success to prevent enumeration.
pub async fn post_forgot_password(
    State(state): State<AppState>,
    csrf: CsrfToken,
    Form(form): Form<ForgotPasswordForm>,
) -> Result<Response, AppError> {
    let email = match Email::new(form.email.clone()) {
        Ok(e) => e,
        Err(_) => {
            let html = render(
                &state.templates,
                "forgot_password.html",
                context! {
                    csrf_token => csrf.as_str(),
                    success => false,
                    error => "Please enter a valid email address.",
                },
                state.is_production,
            )?;
            return Ok(html.into_response());
        }
    };

    let sender: &dyn EmailSender = &*state.email_sender;
    if let Err(err) = state
        .ath
        .db()
        .send_password_reset(&email, &state.base_url, sender)
        .await
    {
        tracing::error!("password reset email error: {err}");
    }

    let html = render(
        &state.templates,
        "forgot_password.html",
        context! {
            csrf_token => csrf.as_str(),
            success => true,
            error => "",
        },
        state.is_production,
    )?;
    Ok(html.into_response())
}

/// GET /auth/reset-password?token=... — validate token and render form or error state.
pub async fn get_reset_password(
    State(state): State<AppState>,
    csrf: CsrfToken,
    Query(query): Query<ResetTokenQuery>,
) -> Result<Response, AppError> {
    let token = match query.token {
        Some(ref t) if !t.is_empty() => t.clone(),
        _ => {
            let html = render(
                &state.templates,
                "reset_password.html",
                context! {
                    csrf_token => csrf.as_str(),
                    token => "",
                    invalid_token => true,
                    success => false,
                    error => "",
                },
                state.is_production,
            )?;
            return Ok(html.into_response());
        }
    };

    let valid = state.ath.db().validate_reset_token(&token).await?;

    if valid.is_some() {
        let html = render(
            &state.templates,
            "reset_password.html",
            context! {
                csrf_token => csrf.as_str(),
                token,
                invalid_token => false,
                success => false,
                error => "",
            },
            state.is_production,
        )?;
        Ok(html.into_response())
    } else {
        let html = render(
            &state.templates,
            "reset_password.html",
            context! {
                csrf_token => csrf.as_str(),
                token => "",
                invalid_token => true,
                success => false,
                error => "",
            },
            state.is_production,
        )?;
        Ok(html.into_response())
    }
}

/// POST /auth/reset-password — execute the password reset.
pub async fn post_reset_password(
    State(state): State<AppState>,
    csrf: CsrfToken,
    Form(form): Form<ResetPasswordForm>,
) -> Result<Response, AppError> {
    // Validate: passwords match
    if form.new_password != form.confirm_password {
        let html = render(
            &state.templates,
            "reset_password.html",
            context! {
                csrf_token => csrf.as_str(),
                token => form.token,
                invalid_token => false,
                success => false,
                error => "Passwords do not match",
            },
            state.is_production,
        )?;
        return Ok(html.into_response());
    }

    // Validate: password length
    if form.new_password.len() < MIN_PASSWORD_LEN {
        let html = render(
            &state.templates,
            "reset_password.html",
            context! {
                csrf_token => csrf.as_str(),
                token => form.token,
                invalid_token => false,
                success => false,
                error => "Password must be at least 8 characters",
            },
            state.is_production,
        )?;
        return Ok(html.into_response());
    }

    match state
        .ath
        .db()
        .execute_reset(&form.token, &form.new_password)
        .await?
    {
        true => {
            let html = render(
                &state.templates,
                "reset_password.html",
                context! {
                    csrf_token => csrf.as_str(),
                    token => "",
                    invalid_token => false,
                    success => true,
                    error => "",
                },
                state.is_production,
            )?;
            Ok(html.into_response())
        }
        false => {
            let html = render(
                &state.templates,
                "reset_password.html",
                context! {
                    csrf_token => csrf.as_str(),
                    token => "",
                    invalid_token => true,
                    success => false,
                    error => "",
                },
                state.is_production,
            )?;
            Ok(html.into_response())
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use axum::routing::get;
    use tower::ServiceExt;

    use allowthem_core::{AllowThemBuilder, AuthClient, Email, EmbeddedAuthClient, LogEmailSender};
    use allowthem_server::csrf_middleware;

    use crate::state::AppState;

    async fn setup() -> AppState {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();
        let auth_client: Arc<dyn AuthClient> =
            Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
        let templates = crate::templates::build_template_env().unwrap();
        AppState {
            ath,
            auth_client,
            base_url: "http://localhost:3000".into(),
            templates,
            is_production: false,
            login_attempts: Arc::new(dashmap::DashMap::new()),
            max_login_attempts: 10,
            rate_limit_window_secs: 900,
            email_sender: Arc::new(LogEmailSender),
        }
    }

    fn test_app(state: AppState) -> Router {
        Router::new()
            .route(
                "/forgot-password",
                get(super::get_forgot_password).post(super::post_forgot_password),
            )
            .route(
                "/auth/reset-password",
                get(super::get_reset_password).post(super::post_reset_password),
            )
            .layer(axum::middleware::from_fn(csrf_middleware))
            .with_state(state)
    }

    async fn get_csrf_token(app: &Router, path: &str) -> String {
        let req = Request::builder()
            .uri(path)
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

    async fn create_user_and_token(state: &AppState, email_str: &str) -> String {
        let email = Email::new(email_str.into()).unwrap();
        state
            .ath
            .db()
            .create_user(email.clone(), "OldPass123!", None)
            .await
            .unwrap();
        state
            .ath
            .db()
            .create_password_reset(&email)
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn get_forgot_password_renders_form() {
        let state = setup().await;
        let app = test_app(state);
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
        let state = setup().await;
        let email = Email::new("reset@example.com".into()).unwrap();
        state
            .ath
            .db()
            .create_user(email, "Pass123!", None)
            .await
            .unwrap();
        let app = test_app(state);
        let csrf = get_csrf_token(&app, "/forgot-password").await;

        let req = Request::builder()
            .method("POST")
            .uri("/forgot-password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_token={csrf}"))
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
        let state = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app, "/forgot-password").await;

        let req = Request::builder()
            .method("POST")
            .uri("/forgot-password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_token={csrf}"))
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
        let state = setup().await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app, "/forgot-password").await;

        let req = Request::builder()
            .method("POST")
            .uri("/forgot-password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_token={csrf}"))
            .body(Body::from(format!("email=notanemail&csrf_token={csrf}")))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("Please enter a valid email address."));
    }

    #[tokio::test]
    async fn get_reset_password_valid_token_renders_form() {
        let state = setup().await;
        let token = create_user_and_token(&state, "tok@example.com").await;
        let app = test_app(state);

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
        let state = setup().await;
        let app = test_app(state);

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
        let state = setup().await;
        let token = create_user_and_token(&state, "mismatch@example.com").await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app, &format!("/auth/reset-password?token={token}")).await;

        let req = Request::builder()
            .method("POST")
            .uri("/auth/reset-password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_token={csrf}"))
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
        let state = setup().await;
        let token = create_user_and_token(&state, "short@example.com").await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app, &format!("/auth/reset-password?token={token}")).await;

        let req = Request::builder()
            .method("POST")
            .uri("/auth/reset-password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_token={csrf}"))
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
        let state = setup().await;
        let token = create_user_and_token(&state, "success@example.com").await;
        let app = test_app(state);
        let csrf = get_csrf_token(&app, &format!("/auth/reset-password?token={token}")).await;

        let req = Request::builder()
            .method("POST")
            .uri("/auth/reset-password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_token={csrf}"))
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
        let state = setup().await;
        let token = create_user_and_token(&state, "used@example.com").await;
        // Consume the token directly via DB
        state
            .ath
            .db()
            .execute_reset(&token, "AlreadyUsed1!")
            .await
            .unwrap();

        let app = test_app(state);
        let csrf = get_csrf_token(&app, "/forgot-password").await;

        let req = Request::builder()
            .method("POST")
            .uri("/auth/reset-password")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .header(header::COOKIE, format!("csrf_token={csrf}"))
            .body(Body::from(format!(
                "token={token}&new_password=NewPass999!&confirm_password=NewPass999!&csrf_token={csrf}"
            )))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let html = body_string(resp).await;
        assert!(html.contains("invalid or has expired"));
    }
}
