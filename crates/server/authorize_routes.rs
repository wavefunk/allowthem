use axum::extract::State;
use axum::http::header::COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{Form, Json};
use serde::Deserialize;
use serde_json::json;
use url::Url;

use allowthem_core::applications::{Application, BrandingConfig, validate_redirect_uri};
use allowthem_core::authorization::{
    generate_authorization_code, hash_authorization_code, validate_scopes,
};
use allowthem_core::types::{ClientId, UserId};
use allowthem_core::{AllowThem, AuthError};

// ---------------------------------------------------------------------------
// OAuth2 error codes (RFC 6749 Section 4.1.2.1)
// ---------------------------------------------------------------------------

enum OAuthErrorCode {
    InvalidRequest,
    AccessDenied,
    UnsupportedResponseType,
    InvalidScope,
    ServerError,
}

impl OAuthErrorCode {
    fn as_str(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "invalid_request",
            Self::AccessDenied => "access_denied",
            Self::UnsupportedResponseType => "unsupported_response_type",
            Self::InvalidScope => "invalid_scope",
            Self::ServerError => "server_error",
        }
    }
}

// ---------------------------------------------------------------------------
// Request / response types
// ---------------------------------------------------------------------------

/// Result of the full authorization check: either a redirect response
/// or a signal that the consent screen should be rendered.
pub enum AuthorizeOutcome {
    /// Redirect the user (success with code, error, or login redirect).
    Redirect(Response),
    /// Consent is needed — render the consent screen.
    ConsentNeeded(Box<ConsentNeededData>),
}

pub struct ConsentNeededData {
    pub context: ConsentContext,
    pub params: ValidatedAuthorize,
}

/// Query parameters for GET /oauth/authorize.
/// All fields are Option so we can produce specific error messages for each.
/// RF-2: client_id is `Option<ClientId>` — ClientId derives Deserialize,
/// so Axum deserializes it directly without needing `new_unchecked`.
#[derive(Deserialize)]
pub struct AuthorizeParams {
    pub client_id: Option<ClientId>,
    pub redirect_uri: Option<String>,
    pub response_type: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub nonce: Option<String>,
}

/// Form body for POST /oauth/authorize (consent submission).
#[derive(Deserialize)]
pub struct ConsentSubmission {
    client_id: Option<ClientId>,
    redirect_uri: Option<String>,
    response_type: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
    consent: String,
    /// CSRF token — validated by the CSRF middleware layer before this handler.
    #[allow(dead_code)]
    csrf_token: Option<String>,
}

/// Data for the consent screen. M39 produces this; M40 renders it.
pub struct ConsentContext {
    pub branding: BrandingConfig,
    pub scopes: Vec<String>,
}

/// Validated parameters after all authorization checks pass.
pub struct ValidatedAuthorize {
    pub application: Application,
    pub redirect_uri: String,
    pub scopes: Vec<String>,
    pub state: String,
    pub code_challenge: String,
    pub code_challenge_method: String,
    pub nonce: Option<String>,
}

// ---------------------------------------------------------------------------
// Redirect and error helpers
// ---------------------------------------------------------------------------

/// Build a successful authorization redirect: `redirect_uri?code=...&state=...`
fn success_redirect(redirect_uri: &str, code: &str, state: &str, status: StatusCode) -> Response {
    let mut url = Url::parse(redirect_uri).expect("redirect_uri was pre-validated");
    url.query_pairs_mut()
        .append_pair("code", code)
        .append_pair("state", state);
    (status, [("location", url.as_str().to_string())]).into_response()
}

/// Build an error redirect: `redirect_uri?error=...&error_description=...&state=...`
fn error_redirect(
    redirect_uri: &str,
    error: OAuthErrorCode,
    description: &str,
    state: &str,
    status: StatusCode,
) -> Response {
    let mut url = Url::parse(redirect_uri).expect("redirect_uri was pre-validated");
    url.query_pairs_mut()
        .append_pair("error", error.as_str())
        .append_pair("error_description", description)
        .append_pair("state", state);
    (status, [("location", url.as_str().to_string())]).into_response()
}

/// Build a display error response (shown to user, not redirected).
fn display_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"error": message}))).into_response()
}

// ---------------------------------------------------------------------------
// Session resolution (RF-1: correct pattern from oauth_routes.rs:360-420)
// ---------------------------------------------------------------------------

/// Resolve the authenticated user from session cookie, or None if not authenticated.
/// Uses the same pattern as `require_session` in oauth_routes.rs:
/// session_config().cookie_name -> db().validate_session() -> db().get_user() -> is_active check
pub async fn resolve_user(
    ath: &AllowThem,
    headers: &HeaderMap,
) -> Result<Option<allowthem_core::User>, AuthError> {
    let cookie_str = match headers.get(COOKIE).and_then(|v| v.to_str().ok()) {
        Some(c) => c,
        None => return Ok(None),
    };

    let token =
        match allowthem_core::parse_session_cookie(cookie_str, ath.session_config().cookie_name) {
            Some(t) => t,
            None => return Ok(None),
        };

    let session = match ath
        .db()
        .validate_session(&token, ath.session_config().ttl)
        .await?
    {
        Some(s) => s,
        None => return Ok(None),
    };

    match ath.db().get_user(session.user_id).await {
        Ok(user) if user.is_active => Ok(Some(user)),
        Ok(_) => Ok(None),
        Err(AuthError::NotFound) => Ok(None),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// Shared validation
// ---------------------------------------------------------------------------

/// Validate authorization request parameters (steps 1-7 from the spec).
/// Steps 1-3 return display errors. Steps 4-7 return redirect errors.
pub async fn validate_authorize_params(
    ath: &AllowThem,
    params: &AuthorizeParams,
) -> Result<ValidatedAuthorize, Response> {
    // Step 1: Validate client_id
    let client_id = params
        .client_id
        .as_ref()
        .ok_or_else(|| display_error(StatusCode::BAD_REQUEST, "missing client_id"))?;

    let application = ath
        .db()
        .get_application_by_client_id(client_id)
        .await
        .map_err(|e| match e {
            AuthError::NotFound => display_error(StatusCode::BAD_REQUEST, "unknown client_id"),
            _ => display_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        })?;

    // Step 2: Validate application is active
    if !application.is_active {
        return Err(display_error(
            StatusCode::BAD_REQUEST,
            "application is inactive",
        ));
    }

    // Step 3: Validate redirect_uri
    let redirect_uri = params.redirect_uri.as_deref().unwrap_or("");
    if redirect_uri.is_empty() {
        return Err(display_error(
            StatusCode::BAD_REQUEST,
            "missing redirect_uri",
        ));
    }
    let registered = application
        .redirect_uri_list()
        .map_err(|_| display_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))?;
    validate_redirect_uri(redirect_uri, &registered)
        .map_err(|_| display_error(StatusCode::BAD_REQUEST, "redirect_uri not registered"))?;

    // From here, redirect_uri is trusted — errors redirect to it.
    let redirect_uri = redirect_uri.to_string();

    // Step 4: Validate state (required — new provider, no legacy clients)
    let state = match params.state.as_deref() {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => {
            return Err(error_redirect(
                &redirect_uri,
                OAuthErrorCode::InvalidRequest,
                "missing state parameter",
                "",
                StatusCode::FOUND,
            ));
        }
    };

    // Step 5: Validate response_type
    if params.response_type.as_deref() != Some("code") {
        return Err(error_redirect(
            &redirect_uri,
            OAuthErrorCode::UnsupportedResponseType,
            "response_type must be code",
            &state,
            StatusCode::FOUND,
        ));
    }

    // Step 6: Validate scope
    let scope_str = params.scope.as_deref().unwrap_or("");
    let scopes = validate_scopes(scope_str).map_err(|e| {
        error_redirect(
            &redirect_uri,
            OAuthErrorCode::InvalidScope,
            &e.to_string(),
            &state,
            StatusCode::FOUND,
        )
    })?;

    // Step 7: Validate PKCE
    let code_challenge = match params.code_challenge.as_deref() {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => {
            return Err(error_redirect(
                &redirect_uri,
                OAuthErrorCode::InvalidRequest,
                "missing code_challenge (PKCE required)",
                &state,
                StatusCode::FOUND,
            ));
        }
    };
    let code_challenge_method = params.code_challenge_method.as_deref().unwrap_or("");
    if code_challenge_method != "S256" {
        return Err(error_redirect(
            &redirect_uri,
            OAuthErrorCode::InvalidRequest,
            "code_challenge_method must be S256",
            &state,
            StatusCode::FOUND,
        ));
    }

    Ok(ValidatedAuthorize {
        application,
        redirect_uri,
        scopes,
        state,
        code_challenge,
        code_challenge_method: "S256".to_string(),
        nonce: params.nonce.clone(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a query string from authorize params for the login redirect.
fn build_authorize_query_string(params: &AuthorizeParams) -> String {
    let mut pairs = url::form_urlencoded::Serializer::new(String::new());
    if let Some(ref v) = params.client_id {
        pairs.append_pair("client_id", v.as_str());
    }
    if let Some(ref v) = params.redirect_uri {
        pairs.append_pair("redirect_uri", v);
    }
    if let Some(ref v) = params.response_type {
        pairs.append_pair("response_type", v);
    }
    if let Some(ref v) = params.scope {
        pairs.append_pair("scope", v);
    }
    if let Some(ref v) = params.state {
        pairs.append_pair("state", v);
    }
    if let Some(ref v) = params.code_challenge {
        pairs.append_pair("code_challenge", v);
    }
    if let Some(ref v) = params.code_challenge_method {
        pairs.append_pair("code_challenge_method", v);
    }
    if let Some(ref v) = params.nonce {
        pairs.append_pair("nonce", v);
    }
    pairs.finish()
}

/// Build a login redirect preserving the full authorize URL in ?next=
fn login_redirect(params: &AuthorizeParams) -> Response {
    let full_uri = format!("/oauth/authorize?{}", build_authorize_query_string(params));
    let encoded: String = url::form_urlencoded::byte_serialize(full_uri.as_bytes()).collect();
    let mut redirect = format!("/login?next={encoded}");
    if let Some(ref cid) = params.client_id {
        redirect.push_str("&client_id=");
        redirect.push_str(cid.as_str());
    }
    (StatusCode::SEE_OTHER, [("location", redirect)]).into_response()
}

/// Generate an authorization code, store it, and redirect with code+state.
pub async fn issue_code_and_redirect(
    ath: &AllowThem,
    validated: &ValidatedAuthorize,
    user_id: UserId,
    status: StatusCode,
) -> Response {
    let raw_code = generate_authorization_code();
    let code_hash = hash_authorization_code(&raw_code);

    match ath
        .db()
        .create_authorization_code(
            validated.application.id,
            user_id,
            &code_hash,
            &validated.redirect_uri,
            &validated.scopes,
            &validated.code_challenge,
            &validated.code_challenge_method,
            validated.nonce.as_deref(),
        )
        .await
    {
        Ok(_) => success_redirect(&validated.redirect_uri, &raw_code, &validated.state, status),
        Err(_) => error_redirect(
            &validated.redirect_uri,
            OAuthErrorCode::ServerError,
            "internal error",
            &validated.state,
            status,
        ),
    }
}

// ---------------------------------------------------------------------------
// Authorization check (used by binaries/consent.rs GET handler)
// ---------------------------------------------------------------------------

/// Run the full authorization flow: validate params, check session,
/// check consent, and either produce a redirect or signal consent needed.
pub async fn check_authorization(
    ath: &AllowThem,
    headers: &HeaderMap,
    params: &AuthorizeParams,
) -> AuthorizeOutcome {
    let validated = match validate_authorize_params(ath, params).await {
        Ok(v) => v,
        Err(resp) => return AuthorizeOutcome::Redirect(resp),
    };

    // Check if user is authenticated
    let user = match resolve_user(ath, headers).await {
        Ok(Some(u)) => u,
        Ok(None) => return AuthorizeOutcome::Redirect(login_redirect(params)),
        Err(_) => {
            return AuthorizeOutcome::Redirect(error_redirect(
                &validated.redirect_uri,
                OAuthErrorCode::ServerError,
                "internal error",
                &validated.state,
                StatusCode::FOUND,
            ));
        }
    };

    // Check consent
    let needs_consent = if validated.application.is_trusted {
        false
    } else {
        match ath
            .db()
            .has_sufficient_consent(user.id, validated.application.id, &validated.scopes)
            .await
        {
            Ok(has) => !has,
            Err(_) => {
                return AuthorizeOutcome::Redirect(error_redirect(
                    &validated.redirect_uri,
                    OAuthErrorCode::ServerError,
                    "internal error",
                    &validated.state,
                    StatusCode::FOUND,
                ));
            }
        }
    };

    if needs_consent {
        let context = ConsentContext {
            branding: validated.application.branding(),
            scopes: validated.scopes.clone(),
        };
        return AuthorizeOutcome::ConsentNeeded(Box::new(ConsentNeededData {
            context,
            params: validated,
        }));
    }

    // Consent exists or app is trusted — generate code and redirect
    AuthorizeOutcome::Redirect(
        issue_code_and_redirect(ath, &validated, user.id, StatusCode::FOUND).await,
    )
}

pub async fn authorize_post(
    State(ath): State<AllowThem>,
    headers: HeaderMap,
    Form(form): Form<ConsentSubmission>,
) -> Response {
    // Re-validate all authorization parameters (defense-in-depth)
    let params = AuthorizeParams {
        client_id: form.client_id,
        redirect_uri: form.redirect_uri,
        response_type: form.response_type,
        scope: form.scope,
        state: form.state,
        code_challenge: form.code_challenge,
        code_challenge_method: form.code_challenge_method,
        nonce: form.nonce,
    };
    let validated = match validate_authorize_params(&ath, &params).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Verify user is authenticated (RF-1: correct session resolution pattern)
    let user = match resolve_user(&ath, &headers).await {
        Ok(Some(u)) => u,
        Ok(None) => return login_redirect(&params),
        Err(_) => {
            return error_redirect(
                &validated.redirect_uri,
                OAuthErrorCode::ServerError,
                "internal error",
                &validated.state,
                StatusCode::SEE_OTHER,
            );
        }
    };

    // Handle consent decision
    if form.consent != "approve" {
        return error_redirect(
            &validated.redirect_uri,
            OAuthErrorCode::AccessDenied,
            "user denied consent",
            &validated.state,
            StatusCode::SEE_OTHER,
        );
    }

    // Upsert consent
    if ath
        .db()
        .upsert_consent(user.id, validated.application.id, &validated.scopes)
        .await
        .is_err()
    {
        return error_redirect(
            &validated.redirect_uri,
            OAuthErrorCode::ServerError,
            "internal error",
            &validated.state,
            StatusCode::SEE_OTHER,
        );
    }

    // Generate code and redirect (POST uses 303 See Other)
    issue_code_and_redirect(&ath, &validated, user.id, StatusCode::SEE_OTHER).await
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::handle::AllowThemBuilder;
    use allowthem_core::types::Email;
    use axum::Router;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::post;
    use tower::ServiceExt;

    async fn test_ath() -> AllowThem {
        AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap()
    }

    async fn setup_application(ath: &AllowThem) -> Application {
        let email = Email::new("admin@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();

        let (app, _) = ath
            .db()
            .create_application(
                "TestApp".to_string(),
                vec!["https://example.com/callback".to_string()],
                false,
                Some(user.id),
                None,
                None,
            )
            .await
            .unwrap();
        app
    }

    fn authorize_params(app: &Application) -> AuthorizeParams {
        AuthorizeParams {
            client_id: Some(app.client_id.clone()),
            redirect_uri: Some("https://example.com/callback".into()),
            response_type: Some("code".into()),
            scope: Some("openid profile".into()),
            state: Some("xyz".into()),
            code_challenge: Some("abc123".into()),
            code_challenge_method: Some("S256".into()),
            nonce: None,
        }
    }

    /// Extract a redirect response from AuthorizeOutcome, panicking if consent.
    fn expect_redirect(outcome: AuthorizeOutcome) -> Response {
        match outcome {
            AuthorizeOutcome::Redirect(resp) => resp,
            AuthorizeOutcome::ConsentNeeded(_) => {
                panic!("expected Redirect, got ConsentNeeded")
            }
        }
    }

    async fn read_body(resp: axum::http::Response<Body>) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    // Helper: create a user, session, and return (user_id, session_cookie_header)
    async fn create_session(
        ath: &AllowThem,
        email: &str,
    ) -> (allowthem_core::types::UserId, String) {
        let email = Email::new(email.into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();
        let token = allowthem_core::generate_token();
        let hash = allowthem_core::hash_token(&token);
        let expires = chrono::Utc::now() + chrono::Duration::hours(24);
        ath.db()
            .create_session(user.id, hash, None, None, expires)
            .await
            .unwrap();
        let cookie = format!("allowthem_session={}", token.as_str());
        (user.id, cookie)
    }

    fn headers_with_cookie(cookie: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("cookie", cookie.parse().unwrap());
        headers
    }

    // Display error tests (steps 1-3)

    #[tokio::test]
    async fn missing_client_id_returns_400() {
        let ath = test_ath().await;
        let params = AuthorizeParams {
            client_id: None,
            redirect_uri: Some("x".into()),
            response_type: Some("code".into()),
            scope: Some("openid".into()),
            state: Some("s".into()),
            code_challenge: Some("c".into()),
            code_challenge_method: Some("S256".into()),
            nonce: None,
        };
        let resp = expect_redirect(check_authorization(&ath, &HeaderMap::new(), &params).await);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "missing client_id");
    }

    #[tokio::test]
    async fn unknown_client_id_returns_400() {
        let ath = test_ath().await;
        let params = AuthorizeParams {
            client_id: serde_json::from_value(serde_json::json!("ath_nonexistent")).ok(),
            redirect_uri: Some("x".into()),
            response_type: Some("code".into()),
            scope: Some("openid".into()),
            state: Some("s".into()),
            code_challenge: Some("c".into()),
            code_challenge_method: Some("S256".into()),
            nonce: None,
        };
        let resp = expect_redirect(check_authorization(&ath, &HeaderMap::new(), &params).await);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "unknown client_id");
    }

    #[tokio::test]
    async fn unregistered_redirect_uri_returns_400() {
        let ath = test_ath().await;
        let application = setup_application(&ath).await;
        let params = AuthorizeParams {
            client_id: Some(application.client_id.clone()),
            redirect_uri: Some("https://evil.example.com/callback".into()),
            response_type: Some("code".into()),
            scope: Some("openid".into()),
            state: Some("s".into()),
            code_challenge: Some("c".into()),
            code_challenge_method: Some("S256".into()),
            nonce: None,
        };
        let resp = expect_redirect(check_authorization(&ath, &HeaderMap::new(), &params).await);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "redirect_uri not registered");
    }

    // Redirect error tests (steps 4-7)

    #[tokio::test]
    async fn missing_state_redirects_with_error() {
        let ath = test_ath().await;
        let application = setup_application(&ath).await;
        let params = AuthorizeParams {
            client_id: Some(application.client_id.clone()),
            redirect_uri: Some("https://example.com/callback".into()),
            response_type: Some("code".into()),
            scope: Some("openid".into()),
            state: None,
            code_challenge: Some("c".into()),
            code_challenge_method: Some("S256".into()),
            nonce: None,
        };
        let resp = expect_redirect(check_authorization(&ath, &HeaderMap::new(), &params).await);
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn bad_response_type_redirects_with_error() {
        let ath = test_ath().await;
        let application = setup_application(&ath).await;
        let params = AuthorizeParams {
            client_id: Some(application.client_id.clone()),
            redirect_uri: Some("https://example.com/callback".into()),
            response_type: Some("token".into()),
            scope: Some("openid".into()),
            state: Some("s".into()),
            code_challenge: Some("c".into()),
            code_challenge_method: Some("S256".into()),
            nonce: None,
        };
        let resp = expect_redirect(check_authorization(&ath, &HeaderMap::new(), &params).await);
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=unsupported_response_type"));
        assert!(location.contains("state=s"));
    }

    #[tokio::test]
    async fn invalid_scope_redirects_with_error() {
        let ath = test_ath().await;
        let application = setup_application(&ath).await;
        let params = AuthorizeParams {
            client_id: Some(application.client_id.clone()),
            redirect_uri: Some("https://example.com/callback".into()),
            response_type: Some("code".into()),
            scope: Some("profile".into()),
            state: Some("s".into()),
            code_challenge: Some("c".into()),
            code_challenge_method: Some("S256".into()),
            nonce: None,
        };
        let resp = expect_redirect(check_authorization(&ath, &HeaderMap::new(), &params).await);
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_scope"));
    }

    #[tokio::test]
    async fn missing_pkce_redirects_with_error() {
        let ath = test_ath().await;
        let application = setup_application(&ath).await;
        let params = AuthorizeParams {
            client_id: Some(application.client_id.clone()),
            redirect_uri: Some("https://example.com/callback".into()),
            response_type: Some("code".into()),
            scope: Some("openid".into()),
            state: Some("s".into()),
            code_challenge: None,
            code_challenge_method: None,
            nonce: None,
        };
        let resp = expect_redirect(check_authorization(&ath, &HeaderMap::new(), &params).await);
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
        assert!(location.contains("PKCE"));
    }

    // Unauthenticated user redirects to login

    #[tokio::test]
    async fn unauthenticated_redirects_to_login() {
        let ath = test_ath().await;
        let application = setup_application(&ath).await;
        let params = authorize_params(&application);
        let resp = expect_redirect(check_authorization(&ath, &HeaderMap::new(), &params).await);
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("/login?next="));
        assert!(location.contains("oauth%2Fauthorize"));
    }

    // Authenticated user with trusted app skips consent

    #[tokio::test]
    async fn trusted_app_skips_consent_and_redirects_with_code() {
        let ath = test_ath().await;
        let (_, cookie) = create_session(&ath, "trusted@example.com").await;
        let headers = headers_with_cookie(&cookie);

        let (trusted_app, _) = ath
            .db()
            .create_application(
                "TrustedApp".to_string(),
                vec!["https://trusted.example.com/callback".to_string()],
                true,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let params = AuthorizeParams {
            client_id: Some(trusted_app.client_id.clone()),
            redirect_uri: Some("https://trusted.example.com/callback".into()),
            response_type: Some("code".into()),
            scope: Some("openid profile".into()),
            state: Some("xyz".into()),
            code_challenge: Some("abc123".into()),
            code_challenge_method: Some("S256".into()),
            nonce: None,
        };

        let resp = expect_redirect(check_authorization(&ath, &headers, &params).await);
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("code="));
        assert!(location.contains("state=xyz"));
        assert!(location.starts_with("https://trusted.example.com/callback"));
    }

    // Authenticated user without consent gets ConsentNeeded

    #[tokio::test]
    async fn untrusted_app_without_consent_returns_consent_needed() {
        let ath = test_ath().await;
        let (_, cookie) = create_session(&ath, "consent@example.com").await;
        let headers = headers_with_cookie(&cookie);
        let application = setup_application(&ath).await;
        let params = authorize_params(&application);

        let outcome = check_authorization(&ath, &headers, &params).await;
        match outcome {
            AuthorizeOutcome::ConsentNeeded(data) => {
                assert_eq!(data.context.branding.application_name, "TestApp");
                assert_eq!(data.context.scopes, vec!["openid", "profile"]);
            }
            AuthorizeOutcome::Redirect(_) => panic!("expected ConsentNeeded, got Redirect"),
        }
    }

    // Inactive application returns display error

    #[tokio::test]
    async fn inactive_application_returns_400() {
        let ath = test_ath().await;
        let application = setup_application(&ath).await;

        sqlx::query("UPDATE allowthem_applications SET is_active = 0 WHERE id = ?")
            .bind(application.id)
            .execute(ath.db().pool())
            .await
            .unwrap();

        let params = AuthorizeParams {
            client_id: Some(application.client_id.clone()),
            redirect_uri: Some("https://example.com/callback".into()),
            response_type: Some("code".into()),
            scope: Some("openid".into()),
            state: Some("s".into()),
            code_challenge: Some("c".into()),
            code_challenge_method: Some("S256".into()),
            nonce: None,
        };
        let resp = expect_redirect(check_authorization(&ath, &HeaderMap::new(), &params).await);
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "application is inactive");
    }

    // Wrong code_challenge_method redirects with error

    #[tokio::test]
    async fn wrong_pkce_method_redirects_with_error() {
        let ath = test_ath().await;
        let application = setup_application(&ath).await;
        let params = AuthorizeParams {
            client_id: Some(application.client_id.clone()),
            redirect_uri: Some("https://example.com/callback".into()),
            response_type: Some("code".into()),
            scope: Some("openid".into()),
            state: Some("s".into()),
            code_challenge: Some("c".into()),
            code_challenge_method: Some("plain".into()),
            nonce: None,
        };
        let resp = expect_redirect(check_authorization(&ath, &HeaderMap::new(), &params).await);
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
        assert!(location.contains("state=s"));
    }

    // Existing consent skips the consent screen

    #[tokio::test]
    async fn existing_consent_skips_consent_screen() {
        let ath = test_ath().await;
        let (user_id, cookie) = create_session(&ath, "existing_consent@example.com").await;
        let headers = headers_with_cookie(&cookie);
        let application = setup_application(&ath).await;

        ath.db()
            .upsert_consent(
                user_id,
                application.id,
                &["openid".to_string(), "profile".to_string()],
            )
            .await
            .unwrap();

        let params = authorize_params(&application);
        let resp = expect_redirect(check_authorization(&ath, &headers, &params).await);
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("code="));
        assert!(location.contains("state=xyz"));
    }

    // POST handler tests — use a minimal router with just post(authorize_post)

    fn post_app(ath: AllowThem) -> Router {
        Router::new()
            .route("/oauth/authorize", post(authorize_post))
            .with_state(ath)
    }

    #[tokio::test]
    async fn post_approve_creates_code_and_redirects_303() {
        let ath = test_ath().await;
        let app = post_app(ath.clone());
        let (_, cookie) = create_session(&ath, "post_approve@example.com").await;
        let application = setup_application(&ath).await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", application.client_id.as_str())
            .append_pair("redirect_uri", "https://example.com/callback")
            .append_pair("response_type", "code")
            .append_pair("scope", "openid profile")
            .append_pair("state", "mystate")
            .append_pair("code_challenge", "mychallenge")
            .append_pair("code_challenge_method", "S256")
            .append_pair("consent", "approve")
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/authorize")
            .header("cookie", &cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("https://example.com/callback"));
        assert!(location.contains("code="));
        assert!(location.contains("state=mystate"));
    }

    #[tokio::test]
    async fn post_deny_redirects_with_access_denied_303() {
        let ath = test_ath().await;
        let app = post_app(ath.clone());
        let (_, cookie) = create_session(&ath, "post_deny@example.com").await;
        let application = setup_application(&ath).await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", application.client_id.as_str())
            .append_pair("redirect_uri", "https://example.com/callback")
            .append_pair("response_type", "code")
            .append_pair("scope", "openid profile")
            .append_pair("state", "mystate")
            .append_pair("code_challenge", "mychallenge")
            .append_pair("code_challenge_method", "S256")
            .append_pair("consent", "deny")
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/authorize")
            .header("cookie", &cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=access_denied"));
        assert!(location.contains("state=mystate"));
    }

    #[tokio::test]
    async fn post_unauthenticated_redirects_to_login() {
        let ath = test_ath().await;
        let app = post_app(ath.clone());
        let application = setup_application(&ath).await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", application.client_id.as_str())
            .append_pair("redirect_uri", "https://example.com/callback")
            .append_pair("response_type", "code")
            .append_pair("scope", "openid")
            .append_pair("state", "s")
            .append_pair("code_challenge", "c")
            .append_pair("code_challenge_method", "S256")
            .append_pair("consent", "approve")
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/authorize")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("/login?next="));
    }

    #[tokio::test]
    async fn post_with_invalid_client_id_returns_400() {
        let ath = test_ath().await;
        let app = post_app(ath.clone());
        let (_, cookie) = create_session(&ath, "post_revalidate@example.com").await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", "ath_nonexistent")
            .append_pair("redirect_uri", "https://example.com/callback")
            .append_pair("response_type", "code")
            .append_pair("scope", "openid")
            .append_pair("state", "s")
            .append_pair("code_challenge", "c")
            .append_pair("code_challenge_method", "S256")
            .append_pair("consent", "approve")
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/authorize")
            .header("cookie", &cookie)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "unknown client_id");
    }
}
