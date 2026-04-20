use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Extension, Path, Query, State};
use axum::http::StatusCode;
use axum::http::header::COOKIE;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{Duration, Utc};
use serde::Deserialize;
use serde_json::json;

use allowthem_core::oauth::{generate_pkce_verifier, pkce_challenge};
use allowthem_core::types::Email;
use allowthem_core::{
    AllowThem, AuthError, AuthEvent, AuthEventSender, EventContext, OAuthAccountInfo,
    OAuthProvider, RegisteredEvent, RegistrationSource,
};
use allowthem_core::{generate_token, hash_token, parse_session_cookie};

use crate::events::{client_ip, publish};

#[derive(Clone)]
struct OAuthConfig {
    providers: Arc<HashMap<String, Box<dyn OAuthProvider>>>,
    base_url: String,
    events_tx: Option<AuthEventSender>,
}

/// Validate a post-login redirect to prevent open redirects.
/// Must start with `/`, must NOT start with `//`, must not contain `://`.
/// Returns `/` for invalid or missing values.
fn sanitize_redirect(next: Option<&str>) -> String {
    match next {
        Some(path) if path.starts_with('/') && !path.starts_with("//") && !path.contains("://") => {
            path.to_string()
        }
        _ => "/".to_string(),
    }
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    next: Option<String>,
}

async fn authorize(
    State(ath): State<AllowThem>,
    Extension(config): Extension<OAuthConfig>,
    Path(provider_name): Path<String>,
    Query(query): Query<AuthorizeQuery>,
) -> Response {
    let provider = match config.providers.get(&provider_name) {
        Some(p) => p,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "unknown provider"})),
            )
                .into_response();
        }
    };

    let verifier = generate_pkce_verifier();
    let challenge = pkce_challenge(&verifier);
    let redirect_uri = format!("{}/oauth/{}/callback", config.base_url, provider_name);

    let post_login = query.next.as_deref().map(|n| sanitize_redirect(Some(n)));
    let post_login_ref = post_login.as_deref();

    let raw_state = match ath
        .db()
        .create_oauth_state(
            &provider_name,
            &redirect_uri,
            &verifier,
            post_login_ref,
            None,
        )
        .await
    {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    let url = provider.authorize_url(&redirect_uri, &raw_state, &challenge);
    Redirect::temporary(&url).into_response()
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: String,
    state: String,
}

async fn callback(
    State(ath): State<AllowThem>,
    Extension(config): Extension<OAuthConfig>,
    Path(provider_name): Path<String>,
    Query(query): Query<CallbackQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    // Validate state
    let state_info = match ath.db().validate_oauth_state(&query.state).await {
        Ok(Some(info)) => info,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "OAuth state invalid or expired"})),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    // Verify provider matches
    if state_info.provider != provider_name {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "provider mismatch"})),
        )
            .into_response();
    }

    let provider = match config.providers.get(&provider_name) {
        Some(p) => p,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "unknown provider"})),
            )
                .into_response();
        }
    };

    // Exchange code for access token
    let access_token = match provider
        .exchange_code(
            &query.code,
            &state_info.redirect_uri,
            &state_info.pkce_verifier,
        )
        .await
    {
        Ok(t) => t,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    // Fetch user info
    let user_info = match provider.user_info(&access_token).await {
        Ok(info) => info,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    // If this is a linking callback, link the provider to the existing user.
    if let Some(linking_user_id) = state_info.linking_user_id {
        match ath
            .db()
            .link_oauth_account(
                linking_user_id,
                &provider_name,
                &user_info.provider_user_id,
                &user_info.email,
            )
            .await
        {
            Ok(()) => {}
            Err(AuthError::Conflict(_)) => {
                return (
                    StatusCode::CONFLICT,
                    Json(json!({"error": "This provider account is already linked to another user."})),
                )
                    .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({"error": e.to_string()})),
                )
                    .into_response();
            }
        }

        let redirect_to = state_info.post_login_redirect.as_deref().unwrap_or("/");
        return Redirect::temporary(redirect_to).into_response();
    }

    // Standard login flow: find or create user.
    let user = match ath
        .db()
        .find_user_by_oauth(&provider_name, &user_info.provider_user_id)
        .await
    {
        Ok(Some(u)) => u,
        Ok(None) => {
            // Try email-based linking if email is verified
            if user_info.email_verified {
                let email = match Email::new(user_info.email.clone()) {
                    Ok(e) => e,
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": e.to_string()})),
                        )
                            .into_response();
                    }
                };

                match ath.db().get_user_by_email(&email).await {
                    Ok(existing) => {
                        // Link the OAuth account to the existing user
                        if let Err(e) = ath
                            .db()
                            .link_oauth_account(
                                existing.id,
                                &provider_name,
                                &user_info.provider_user_id,
                                &user_info.email,
                            )
                            .await
                        {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Json(json!({"error": e.to_string()})),
                            )
                                .into_response();
                        }
                        existing
                    }
                    Err(AuthError::NotFound) => {
                        // Create new OAuth user
                        let new_user = match ath
                            .db()
                            .create_oauth_user(email, &provider_name, &user_info.provider_user_id)
                            .await
                        {
                            Ok(u) => u,
                            Err(AuthError::Conflict(_)) => {
                                return (
                                    StatusCode::BAD_REQUEST,
                                    Json(json!({"error": "An account with this email already exists. Please log in with your password or use a provider that verifies your email."})),
                                )
                                    .into_response()
                            }
                            Err(e) => {
                                return (
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    Json(json!({"error": e.to_string()})),
                                )
                                    .into_response()
                            }
                        };
                        publish(config.events_tx.as_ref(), || {
                            AuthEvent::Registered(RegisteredEvent::new(
                                new_user.clone(),
                                RegistrationSource::OAuth {
                                    provider: provider_name.clone(),
                                },
                                EventContext::new(
                                    client_ip(&headers),
                                    headers
                                        .get(axum::http::header::USER_AGENT)
                                        .and_then(|v| v.to_str().ok())
                                        .map(str::to_owned),
                                    config.base_url.clone(),
                                    Utc::now(),
                                ),
                            ))
                        });
                        new_user
                    }
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": e.to_string()})),
                        )
                            .into_response();
                    }
                }
            } else {
                // Email not verified -- create new user without linking
                let email = match Email::new(user_info.email.clone()) {
                    Ok(e) => e,
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": e.to_string()})),
                        )
                            .into_response();
                    }
                };

                let new_user = match ath
                    .db()
                    .create_oauth_user(email, &provider_name, &user_info.provider_user_id)
                    .await
                {
                    Ok(u) => u,
                    Err(AuthError::Conflict(_)) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "An account with this email already exists. Please log in with your password or use a provider that verifies your email."})),
                        )
                            .into_response()
                    }
                    Err(e) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": e.to_string()})),
                        )
                            .into_response()
                    }
                };
                publish(config.events_tx.as_ref(), || {
                    AuthEvent::Registered(RegisteredEvent::new(
                        new_user.clone(),
                        RegistrationSource::OAuth {
                            provider: provider_name.clone(),
                        },
                        EventContext::new(
                            client_ip(&headers),
                            headers
                                .get(axum::http::header::USER_AGENT)
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned),
                            config.base_url.clone(),
                            Utc::now(),
                        ),
                    ))
                });
                new_user
            }
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    // Create session
    let token = generate_token();
    let token_hash = hash_token(&token);
    let expires_at = Utc::now() + Duration::hours(24);

    if let Err(e) = ath
        .db()
        .create_session(user.id, token_hash, None, None, expires_at)
        .await
    {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response();
    }

    let cookie = ath.session_cookie(&token);
    let redirect_to = state_info.post_login_redirect.as_deref().unwrap_or("/");

    let mut response = Redirect::temporary(redirect_to).into_response();
    response.headers_mut().insert(
        axum::http::header::SET_COOKIE,
        cookie.parse().expect("valid cookie header"),
    );
    response
}

// ---------------------------------------------------------------------------
// Session extraction helper (used by link/unlink/list handlers)
// ---------------------------------------------------------------------------

/// Extract and validate the session from the Cookie header. Returns the user
/// or a 401 response.
#[allow(clippy::result_large_err)]
async fn require_session(
    ath: &AllowThem,
    headers: &axum::http::HeaderMap,
) -> Result<allowthem_core::User, Response> {
    let cookie_str = headers
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthenticated"})),
            )
                .into_response()
        })?;

    let token =
        parse_session_cookie(cookie_str, ath.session_config().cookie_name).ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthenticated"})),
            )
                .into_response()
        })?;

    let session = ath
        .db()
        .validate_session(&token, ath.session_config().ttl)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response()
        })?
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(json!({"error": "unauthenticated"})),
            )
                .into_response()
        })?;

    let user = ath.db().get_user(session.user_id).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response()
    })?;

    if user.is_active {
        Ok(user)
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthenticated"})),
        )
            .into_response())
    }
}

// ---------------------------------------------------------------------------
// Account linking routes
// ---------------------------------------------------------------------------

/// `GET /oauth/:provider/link` — authenticated user initiates provider linking.
async fn link_authorize(
    State(ath): State<AllowThem>,
    Extension(config): Extension<OAuthConfig>,
    Path(provider_name): Path<String>,
    Query(query): Query<AuthorizeQuery>,
    headers: axum::http::HeaderMap,
) -> Response {
    let user = match require_session(&ath, &headers).await {
        Ok(u) => u,
        Err(r) => return r,
    };

    let provider = match config.providers.get(&provider_name) {
        Some(p) => p,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "unknown provider"})),
            )
                .into_response();
        }
    };

    let verifier = generate_pkce_verifier();
    let challenge = pkce_challenge(&verifier);
    let redirect_uri = format!("{}/oauth/{}/callback", config.base_url, provider_name);

    let post_login = query.next.as_deref().map(|n| sanitize_redirect(Some(n)));
    let post_login_ref = post_login.as_deref();

    let raw_state = match ath
        .db()
        .create_oauth_state(
            &provider_name,
            &redirect_uri,
            &verifier,
            post_login_ref,
            Some(user.id),
        )
        .await
    {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string()})),
            )
                .into_response();
        }
    };

    let url = provider.authorize_url(&redirect_uri, &raw_state, &challenge);
    Redirect::temporary(&url).into_response()
}

#[derive(Deserialize)]
struct UnlinkBody {
    provider: String,
}

/// `POST /oauth/unlink` — authenticated user removes a linked provider.
async fn unlink(
    State(ath): State<AllowThem>,
    headers: axum::http::HeaderMap,
    Json(body): Json<UnlinkBody>,
) -> Response {
    let user = match require_session(&ath, &headers).await {
        Ok(u) => u,
        Err(r) => return r,
    };

    match ath.db().unlink_oauth_account(user.id, &body.provider).await {
        Ok(true) => StatusCode::NO_CONTENT.into_response(),
        Ok(false) => (
            StatusCode::NOT_FOUND,
            Json(json!({"error": "no linked account for this provider"})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// `GET /account/linked-providers` — authenticated user lists linked OAuth accounts.
async fn list_linked_providers(
    State(ath): State<AllowThem>,
    headers: axum::http::HeaderMap,
) -> Response {
    let user = match require_session(&ath, &headers).await {
        Ok(u) => u,
        Err(r) => return r,
    };

    match ath.db().get_user_oauth_accounts(user.id).await {
        Ok(accounts) => {
            let items: Vec<serde_json::Value> = accounts
                .into_iter()
                .map(|a: OAuthAccountInfo| {
                    json!({
                        "provider": a.provider,
                        "provider_user_id": a.provider_user_id,
                        "email": a.email,
                        "created_at": a.created_at,
                    })
                })
                .collect();
            Json(json!({ "accounts": items })).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
            .into_response(),
    }
}

/// Create a router with OAuth authorize and callback routes.
///
/// `providers` maps provider names (e.g. `"google"`) to their implementations.
/// `base_url` is used to construct callback redirect URIs.
pub fn oauth_routes(
    providers: HashMap<String, Box<dyn OAuthProvider>>,
    base_url: String,
    events_tx: Option<AuthEventSender>,
) -> Router<AllowThem> {
    let config = OAuthConfig {
        providers: Arc::new(providers),
        base_url,
        events_tx,
    };
    Router::new()
        .route("/oauth/{provider}/authorize", get(authorize))
        .route("/oauth/{provider}/callback", get(callback))
        .route("/oauth/{provider}/link", get(link_authorize))
        .route("/oauth/unlink", post(unlink))
        .route("/account/linked-providers", get(list_linked_providers))
        .layer(Extension(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::auth_client::AuthFuture;
    use allowthem_core::oauth::OAuthUserInfo;
    use allowthem_core::{AllowThemBuilder, OAuthProvider};
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    struct MockOAuthProvider;

    impl OAuthProvider for MockOAuthProvider {
        fn name(&self) -> &str {
            "mock"
        }

        fn authorize_url(&self, redirect_uri: &str, state: &str, pkce_challenge: &str) -> String {
            format!(
                "https://mock.provider/authorize?redirect_uri={}&state={}&code_challenge={}",
                redirect_uri, state, pkce_challenge
            )
        }

        fn exchange_code<'a>(
            &'a self,
            _code: &'a str,
            _redirect_uri: &'a str,
            _pkce_verifier: &'a str,
        ) -> AuthFuture<'a, String> {
            Box::pin(async { Ok("mock-access-token".to_string()) })
        }

        fn user_info<'a>(&'a self, _access_token: &'a str) -> AuthFuture<'a, OAuthUserInfo> {
            Box::pin(async {
                Ok(OAuthUserInfo {
                    provider_user_id: "mock-uid-123".to_string(),
                    email: "oauth@example.com".to_string(),
                    email_verified: true,
                    name: Some("Mock User".to_string()),
                })
            })
        }
    }

    async fn test_app() -> (AllowThem, Router) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let mut providers: HashMap<String, Box<dyn OAuthProvider>> = HashMap::new();
        providers.insert("mock".to_string(), Box::new(MockOAuthProvider));

        let routes = oauth_routes(providers, "https://example.com".into(), None);
        let app = routes.with_state(ath.clone());
        (ath, app)
    }

    // --- sanitize_redirect tests ---

    #[test]
    fn sanitize_redirect_valid_path() {
        assert_eq!(sanitize_redirect(Some("/dashboard")), "/dashboard");
    }

    #[test]
    fn sanitize_redirect_root() {
        assert_eq!(sanitize_redirect(Some("/")), "/");
    }

    #[test]
    fn sanitize_redirect_protocol_relative() {
        assert_eq!(sanitize_redirect(Some("//evil.com")), "/");
    }

    #[test]
    fn sanitize_redirect_absolute_url() {
        assert_eq!(sanitize_redirect(Some("https://evil.com")), "/");
    }

    #[test]
    fn sanitize_redirect_scheme_in_path() {
        assert_eq!(sanitize_redirect(Some("/foo://bar")), "/");
    }

    #[test]
    fn sanitize_redirect_none() {
        assert_eq!(sanitize_redirect(None), "/");
    }

    #[test]
    fn sanitize_redirect_no_leading_slash() {
        assert_eq!(sanitize_redirect(Some("dashboard")), "/");
    }

    // --- Route tests ---

    #[tokio::test]
    async fn authorize_redirects_to_provider() {
        let (_ath, app) = test_app().await;

        let req = Request::builder()
            .uri("/oauth/mock/authorize")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(
            location.contains("mock.provider/authorize"),
            "should redirect to mock provider"
        );
        assert!(location.contains("state="), "should include state");
        assert!(
            location.contains("code_challenge="),
            "should include PKCE challenge"
        );
    }

    #[tokio::test]
    async fn authorize_unknown_provider_returns_404() {
        let (_ath, app) = test_app().await;

        let req = Request::builder()
            .uri("/oauth/unknown/authorize")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn callback_creates_new_user_and_session() {
        let (ath, app) = test_app().await;

        let redirect_uri = "https://example.com/oauth/mock/callback";
        let raw_state = ath
            .db()
            .create_oauth_state("mock", redirect_uri, "test-verifier", None, None)
            .await
            .unwrap();

        let uri = format!("/oauth/mock/callback?code=mock-code&state={}", raw_state);
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        assert!(resp.headers().contains_key("set-cookie"));

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(location, "/");

        // Verify user was created
        let email = Email::new("oauth@example.com".into()).unwrap();
        let user = ath.db().get_user_by_email(&email).await.unwrap();
        assert_eq!(user.email.as_str(), "oauth@example.com");
    }

    #[tokio::test]
    async fn callback_returns_existing_user_on_repeat_login() {
        let (ath, app) = test_app().await;

        // Create OAuth user first
        let email = Email::new("oauth@example.com".into()).unwrap();
        let original = ath
            .db()
            .create_oauth_user(email, "mock", "mock-uid-123")
            .await
            .unwrap();

        let redirect_uri = "https://example.com/oauth/mock/callback";
        let raw_state = ath
            .db()
            .create_oauth_state("mock", redirect_uri, "test-verifier", None, None)
            .await
            .unwrap();

        let uri = format!("/oauth/mock/callback?code=mock-code&state={}", raw_state);
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

        // Verify it's the same user
        let found = ath
            .db()
            .find_user_by_oauth("mock", "mock-uid-123")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, original.id);
    }

    #[tokio::test]
    async fn callback_links_existing_password_user_by_email() {
        let (ath, app) = test_app().await;

        // Create password user with same email
        let email = Email::new("oauth@example.com".into()).unwrap();
        let pw_user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();

        let redirect_uri = "https://example.com/oauth/mock/callback";
        let raw_state = ath
            .db()
            .create_oauth_state("mock", redirect_uri, "test-verifier", None, None)
            .await
            .unwrap();

        let uri = format!("/oauth/mock/callback?code=mock-code&state={}", raw_state);
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

        // Verify the linked user is the same password user
        let found = ath
            .db()
            .find_user_by_oauth("mock", "mock-uid-123")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.id, pw_user.id);
    }

    #[tokio::test]
    async fn callback_invalid_state_returns_400() {
        let (_ath, app) = test_app().await;

        let req = Request::builder()
            .uri("/oauth/mock/callback?code=x&state=garbage")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn callback_respects_post_login_redirect() {
        let (ath, app) = test_app().await;

        let redirect_uri = "https://example.com/oauth/mock/callback";
        let raw_state = ath
            .db()
            .create_oauth_state(
                "mock",
                redirect_uri,
                "test-verifier",
                Some("/settings"),
                None,
            )
            .await
            .unwrap();

        let uri = format!("/oauth/mock/callback?code=mock-code&state={}", raw_state);
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert_eq!(location, "/settings");
    }

    // ---------------------------------------------------------------------------
    // Account-linking route tests
    // ---------------------------------------------------------------------------

    /// Build a session cookie for a given user.
    async fn make_session_cookie(ath: &AllowThem) -> (allowthem_core::User, String) {
        use allowthem_core::{Email, generate_token, hash_token};
        use chrono::Duration;

        let email = Email::new("linked-user@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();

        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires_at = chrono::Utc::now() + Duration::hours(24);
        ath.db()
            .create_session(user.id, token_hash, None, None, expires_at)
            .await
            .unwrap();

        let set_cookie = ath.session_cookie(&token);
        let cookie_value = set_cookie.split(';').next().unwrap().to_string();
        (user, cookie_value)
    }

    #[tokio::test]
    async fn link_authorize_requires_authentication() {
        let (_ath, app) = test_app().await;

        let req = Request::builder()
            .uri("/oauth/mock/link")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn link_authorize_redirects_to_provider_when_authenticated() {
        let (ath, app) = test_app().await;
        let (_user, cookie) = make_session_cookie(&ath).await;

        let req = Request::builder()
            .uri("/oauth/mock/link")
            .header("Cookie", &cookie)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("mock.provider/authorize"));
    }

    #[tokio::test]
    async fn callback_with_linking_user_id_links_provider() {
        let (ath, app) = test_app().await;
        let (user, _cookie) = make_session_cookie(&ath).await;

        // Create a state with linking_user_id set
        let redirect_uri = "https://example.com/oauth/mock/callback";
        let raw_state = ath
            .db()
            .create_oauth_state("mock", redirect_uri, "test-verifier", None, Some(user.id))
            .await
            .unwrap();

        let uri = format!("/oauth/mock/callback?code=mock-code&state={}", raw_state);
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        // Should redirect (no new session, just linked)
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);
        // Should NOT set a new session cookie (link flow doesn't create session)
        assert!(!resp.headers().contains_key("set-cookie"));

        // Provider should now be linked to the user
        let found = ath
            .db()
            .find_user_by_oauth("mock", "mock-uid-123")
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, user.id);
    }

    #[tokio::test]
    async fn unlink_requires_authentication() {
        let (_ath, app) = test_app().await;

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/unlink")
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"provider":"mock"}"#))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn unlink_removes_linked_provider() {
        let (ath, app) = test_app().await;
        let (user, cookie) = make_session_cookie(&ath).await;

        // Link mock provider first
        ath.db()
            .link_oauth_account(user.id, "mock", "mock-uid-123", "linked-user@example.com")
            .await
            .unwrap();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/unlink")
            .header("Cookie", &cookie)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"provider":"mock"}"#))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);

        // Verify unlinked
        let found = ath
            .db()
            .find_user_by_oauth("mock", "mock-uid-123")
            .await
            .unwrap();
        assert!(found.is_none());
    }

    #[tokio::test]
    async fn unlink_returns_404_when_not_linked() {
        let (ath, app) = test_app().await;
        let (_user, cookie) = make_session_cookie(&ath).await;

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/unlink")
            .header("Cookie", &cookie)
            .header("Content-Type", "application/json")
            .body(Body::from(r#"{"provider":"mock"}"#))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn list_linked_providers_requires_authentication() {
        let (_ath, app) = test_app().await;

        let req = Request::builder()
            .uri("/account/linked-providers")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn list_linked_providers_returns_linked_accounts() {
        let (ath, app) = test_app().await;
        let (user, cookie) = make_session_cookie(&ath).await;

        ath.db()
            .link_oauth_account(user.id, "mock", "mock-uid-123", "linked-user@example.com")
            .await
            .unwrap();

        let req = Request::builder()
            .uri("/account/linked-providers")
            .header("Cookie", &cookie)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let accounts = body["accounts"].as_array().unwrap();
        assert_eq!(accounts.len(), 1);
        assert_eq!(accounts[0]["provider"], "mock");
    }

    #[tokio::test]
    async fn list_linked_providers_returns_empty_when_none_linked() {
        let (ath, app) = test_app().await;
        let (_user, cookie) = make_session_cookie(&ath).await;

        let req = Request::builder()
            .uri("/account/linked-providers")
            .header("Cookie", &cookie)
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let accounts = body["accounts"].as_array().unwrap();
        assert!(accounts.is_empty());
    }

    #[tokio::test]
    async fn callback_with_already_linked_provider_returns_conflict() {
        let (ath, app) = test_app().await;

        // Create another user who already has mock-uid-123 linked
        let email2 = Email::new("other@example.com".into()).unwrap();
        let other_user = ath
            .db()
            .create_oauth_user(email2, "mock", "mock-uid-123")
            .await
            .unwrap();

        // Create a different user who tries to link the same provider account
        let email1 = Email::new("first@example.com".into()).unwrap();
        let linking_user = ath
            .db()
            .create_user(email1, "password123", None, None)
            .await
            .unwrap();
        let _ = other_user;

        let redirect_uri = "https://example.com/oauth/mock/callback";
        let raw_state = ath
            .db()
            .create_oauth_state(
                "mock",
                redirect_uri,
                "test-verifier",
                None,
                Some(linking_user.id),
            )
            .await
            .unwrap();

        let uri = format!("/oauth/mock/callback?code=mock-code&state={}", raw_state);
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    // ---------------------------------------------------------------------------
    // Lifecycle event tests
    // ---------------------------------------------------------------------------

    async fn test_app_with_events() -> (
        AllowThem,
        Router,
        allowthem_core::AuthEventReceiver,
    ) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let mut providers: HashMap<String, Box<dyn OAuthProvider>> = HashMap::new();
        providers.insert("mock".to_string(), Box::new(MockOAuthProvider));

        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let routes = oauth_routes(providers, "https://example.com".into(), Some(tx));
        let app = routes.with_state(ath.clone());
        (ath, app, rx)
    }

    #[tokio::test]
    async fn callback_fresh_user_publishes_oauth_registered() {
        let (ath, app, mut rx) = test_app_with_events().await;

        let redirect_uri = "https://example.com/oauth/mock/callback";
        let raw_state = ath
            .db()
            .create_oauth_state("mock", redirect_uri, "test-verifier", None, None)
            .await
            .unwrap();

        let uri = format!("/oauth/mock/callback?code=mock-code&state={}", raw_state);
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

        let event = tokio::time::timeout(std::time::Duration::from_millis(200), rx.recv())
            .await
            .expect("event received before timeout")
            .expect("channel sender still alive");

        match event {
            AuthEvent::Registered(e) => {
                assert_eq!(e.user.email.as_str(), "oauth@example.com");
                match e.source {
                    RegistrationSource::OAuth { provider } => assert_eq!(provider, "mock"),
                    other => panic!("expected OAuth source, got {other:?}"),
                }
                assert_eq!(e.ctx.base_url, "https://example.com");
            }
            other => panic!("unexpected event variant: {other:?}"),
        }
    }

    #[tokio::test]
    async fn callback_linking_existing_email_does_not_publish() {
        let (ath, app, mut rx) = test_app_with_events().await;

        // Pre-create a password user with the same email the mock provider returns.
        let email = Email::new("oauth@example.com".into()).unwrap();
        ath.db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();

        let redirect_uri = "https://example.com/oauth/mock/callback";
        let raw_state = ath
            .db()
            .create_oauth_state("mock", redirect_uri, "test-verifier", None, None)
            .await
            .unwrap();

        let uri = format!("/oauth/mock/callback?code=mock-code&state={}", raw_state);
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

        // No event should arrive — the OAuth identity was linked to an existing user.
        let got = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        match got {
            Err(_) | Ok(None) => {}
            Ok(Some(event)) => panic!("expected no event, got {event:?}"),
        }
    }

    #[tokio::test]
    async fn callback_returning_oauth_user_does_not_publish() {
        let (ath, app, mut rx) = test_app_with_events().await;

        // Pre-create an OAuth user so find_user_by_oauth returns a hit.
        let email = Email::new("oauth@example.com".into()).unwrap();
        ath.db()
            .create_oauth_user(email, "mock", "mock-uid-123")
            .await
            .unwrap();

        let redirect_uri = "https://example.com/oauth/mock/callback";
        let raw_state = ath
            .db()
            .create_oauth_state("mock", redirect_uri, "test-verifier", None, None)
            .await
            .unwrap();

        let uri = format!("/oauth/mock/callback?code=mock-code&state={}", raw_state);
        let req = Request::builder().uri(&uri).body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TEMPORARY_REDIRECT);

        let got = tokio::time::timeout(std::time::Duration::from_millis(50), rx.recv()).await;
        match got {
            Err(_) | Ok(None) => {}
            Ok(Some(event)) => panic!("expected no event for returning OAuth user, got {event:?}"),
        }
    }
}
