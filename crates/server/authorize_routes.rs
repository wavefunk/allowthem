use axum::extract::{Query, State};
use axum::http::header::COOKIE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Form, Json, Router};
use serde::Deserialize;
use serde_json::json;
use url::Url;

use allowthem_core::applications::{validate_redirect_uri, Application};
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

/// Query parameters for GET /oauth/authorize.
/// All fields are Option so we can produce specific error messages for each.
/// RF-2: client_id is `Option<ClientId>` — ClientId derives Deserialize,
/// so Axum deserializes it directly without needing `new_unchecked`.
#[derive(Deserialize)]
pub struct AuthorizeParams {
    client_id: Option<ClientId>,
    redirect_uri: Option<String>,
    response_type: Option<String>,
    scope: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    nonce: Option<String>,
}

/// Form body for POST /oauth/authorize (consent submission).
#[derive(Deserialize)]
struct ConsentSubmission {
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
    pub application_name: String,
    pub logo_url: Option<String>,
    pub primary_color: Option<String>,
    pub scopes: Vec<String>,
}

/// Internal validated parameters after all checks pass.
struct ValidatedAuthorize {
    application: Application,
    redirect_uri: String,
    scopes: Vec<String>,
    state: String,
    code_challenge: String,
    code_challenge_method: String,
    nonce: Option<String>,
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
async fn resolve_user(
    ath: &AllowThem,
    headers: &HeaderMap,
) -> Result<Option<allowthem_core::User>, AuthError> {
    let cookie_str = match headers.get(COOKIE).and_then(|v| v.to_str().ok()) {
        Some(c) => c,
        None => return Ok(None),
    };

    let token = match allowthem_core::parse_session_cookie(
        cookie_str,
        ath.session_config().cookie_name,
    ) {
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
async fn validate_authorize_params(
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
    let redirect_uri = params
        .redirect_uri
        .as_deref()
        .unwrap_or("");
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
            ))
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
            ))
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
    let redirect = format!("/login?next={encoded}");
    (StatusCode::SEE_OTHER, [("location", redirect)]).into_response()
}

/// Generate an authorization code, store it, and redirect with code+state.
async fn issue_code_and_redirect(
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
// Handlers
// ---------------------------------------------------------------------------

async fn authorize_get(
    State(ath): State<AllowThem>,
    headers: HeaderMap,
    Query(params): Query<AuthorizeParams>,
) -> Response {
    let validated = match validate_authorize_params(&ath, &params).await {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // Check if user is authenticated (RF-1: correct session resolution pattern)
    let user = match resolve_user(&ath, &headers).await {
        Ok(Some(u)) => u,
        Ok(None) => return login_redirect(&params),
        Err(_) => {
            return error_redirect(
                &validated.redirect_uri,
                OAuthErrorCode::ServerError,
                "internal error",
                &validated.state,
                StatusCode::FOUND,
            )
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
                return error_redirect(
                    &validated.redirect_uri,
                    OAuthErrorCode::ServerError,
                    "internal error",
                    &validated.state,
                    StatusCode::FOUND,
                )
            }
        }
    };

    if needs_consent {
        // Return consent context as JSON. M40 will replace with rendered HTML.
        let ctx = ConsentContext {
            application_name: validated.application.name.clone(),
            logo_url: validated.application.logo_url.clone(),
            primary_color: validated.application.primary_color.clone(),
            scopes: validated.scopes.clone(),
        };
        return (
            StatusCode::OK,
            Json(json!({
                "consent_required": true,
                "application_name": ctx.application_name,
                "logo_url": ctx.logo_url,
                "primary_color": ctx.primary_color,
                "scopes": ctx.scopes,
                "authorize_params": {
                    "client_id": validated.application.client_id.as_str(),
                    "redirect_uri": &validated.redirect_uri,
                    "response_type": "code",
                    "scope": validated.scopes.join(" "),
                    "state": &validated.state,
                    "code_challenge": &validated.code_challenge,
                    "code_challenge_method": &validated.code_challenge_method,
                    "nonce": &validated.nonce,
                },
            })),
        )
            .into_response();
    }

    // Consent exists or app is trusted — generate code and redirect
    issue_code_and_redirect(&ath, &validated, user.id, StatusCode::FOUND).await
}

async fn authorize_post(
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
            )
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
// Router
// ---------------------------------------------------------------------------

pub fn authorize_routes() -> Router<AllowThem> {
    Router::new().route("/oauth/authorize", get(authorize_get).post(authorize_post))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::handle::AllowThemBuilder;
    use allowthem_core::types::Email;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    async fn test_app() -> (AllowThem, Router) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let routes = authorize_routes();
        let app = routes.with_state(ath.clone());
        (ath, app)
    }

    async fn setup_application(ath: &AllowThem) -> Application {
        let email = Email::new("admin@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None)
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

    fn authorize_uri(app: &Application) -> String {
        format!(
            "/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid+profile&state=xyz&code_challenge=abc123&code_challenge_method=S256",
            app.client_id.as_str(),
            url::form_urlencoded::byte_serialize(b"https://example.com/callback").collect::<String>()
        )
    }

    async fn read_status(resp: axum::http::Response<Body>) -> StatusCode {
        resp.status()
    }

    async fn read_body(resp: axum::http::Response<Body>) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    // Display error tests (steps 1-3)

    #[tokio::test]
    async fn missing_client_id_returns_400() {
        let (_ath, app) = test_app().await;
        let req = Request::builder()
            .method("GET")
            .uri("/oauth/authorize?redirect_uri=x&response_type=code&scope=openid&state=s&code_challenge=c&code_challenge_method=S256")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "missing client_id");
    }

    #[tokio::test]
    async fn unknown_client_id_returns_400() {
        let (_ath, app) = test_app().await;
        let req = Request::builder()
            .method("GET")
            .uri("/oauth/authorize?client_id=ath_nonexistent&redirect_uri=x&response_type=code&scope=openid&state=s&code_challenge=c&code_challenge_method=S256")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "unknown client_id");
    }

    #[tokio::test]
    async fn unregistered_redirect_uri_returns_400() {
        let (ath, app) = test_app().await;
        let application = setup_application(&ath).await;
        let req = Request::builder()
            .method("GET")
            .uri(&format!(
                "/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid&state=s&code_challenge=c&code_challenge_method=S256",
                application.client_id.as_str(),
                "https://evil.example.com/callback"
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "redirect_uri not registered");
    }

    // Redirect error tests (steps 4-7)

    #[tokio::test]
    async fn missing_state_redirects_with_error() {
        let (ath, app) = test_app().await;
        let application = setup_application(&ath).await;
        let req = Request::builder()
            .method("GET")
            .uri(&format!(
                "/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid&code_challenge=c&code_challenge_method=S256",
                application.client_id.as_str(),
                url::form_urlencoded::byte_serialize(b"https://example.com/callback").collect::<String>()
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
    }

    #[tokio::test]
    async fn bad_response_type_redirects_with_error() {
        let (ath, app) = test_app().await;
        let application = setup_application(&ath).await;
        let req = Request::builder()
            .method("GET")
            .uri(&format!(
                "/oauth/authorize?client_id={}&redirect_uri={}&response_type=token&scope=openid&state=s&code_challenge=c&code_challenge_method=S256",
                application.client_id.as_str(),
                url::form_urlencoded::byte_serialize(b"https://example.com/callback").collect::<String>()
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=unsupported_response_type"));
        assert!(location.contains("state=s"));
    }

    #[tokio::test]
    async fn invalid_scope_redirects_with_error() {
        let (ath, app) = test_app().await;
        let application = setup_application(&ath).await;
        let req = Request::builder()
            .method("GET")
            .uri(&format!(
                "/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope=profile&state=s&code_challenge=c&code_challenge_method=S256",
                application.client_id.as_str(),
                url::form_urlencoded::byte_serialize(b"https://example.com/callback").collect::<String>()
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_scope"));
    }

    #[tokio::test]
    async fn missing_pkce_redirects_with_error() {
        let (ath, app) = test_app().await;
        let application = setup_application(&ath).await;
        let req = Request::builder()
            .method("GET")
            .uri(&format!(
                "/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid&state=s",
                application.client_id.as_str(),
                url::form_urlencoded::byte_serialize(b"https://example.com/callback").collect::<String>()
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
        assert!(location.contains("PKCE"));
    }

    // Unauthenticated user redirects to login

    #[tokio::test]
    async fn unauthenticated_redirects_to_login() {
        let (ath, app) = test_app().await;
        let application = setup_application(&ath).await;
        let uri = authorize_uri(&application);
        let req = Request::builder()
            .method("GET")
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("/login?next="));
        // Verify the authorize URL is preserved in the next parameter
        assert!(location.contains("oauth%2Fauthorize"));
    }

    // Authenticated user with trusted app skips consent

    #[tokio::test]
    async fn trusted_app_skips_consent_and_redirects_with_code() {
        let (ath, app) = test_app().await;

        // Create user and get a session
        let email = Email::new("trusted@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None)
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

        // Create a trusted application
        let (trusted_app, _) = ath
            .db()
            .create_application(
                "TrustedApp".to_string(),
                vec!["https://trusted.example.com/callback".to_string()],
                true,
                Some(user.id),
                None,
                None,
            )
            .await
            .unwrap();

        let uri = format!(
            "/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid+profile&state=xyz&code_challenge=abc123&code_challenge_method=S256",
            trusted_app.client_id.as_str(),
            url::form_urlencoded::byte_serialize(b"https://trusted.example.com/callback").collect::<String>()
        );

        let req = Request::builder()
            .method("GET")
            .uri(&uri)
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("code="));
        assert!(location.contains("state=xyz"));
        assert!(location.starts_with("https://trusted.example.com/callback"));
    }

    // Authenticated user without consent sees consent screen

    #[tokio::test]
    async fn untrusted_app_without_consent_shows_consent_screen() {
        let (ath, app) = test_app().await;

        let email = Email::new("consent@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None)
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

        let application = setup_application(&ath).await;
        let uri = authorize_uri(&application);

        let req = Request::builder()
            .method("GET")
            .uri(&uri)
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert_eq!(body["consent_required"], true);
        assert_eq!(body["application_name"], "TestApp");
    }

    // Helper: create a user, session, and return (user_id, session_cookie)
    async fn create_session(ath: &AllowThem, email: &str) -> (allowthem_core::types::UserId, String) {
        let email = Email::new(email.into()).unwrap();
        let user = ath.db().create_user(email, "password123", None).await.unwrap();
        let token = allowthem_core::generate_token();
        let hash = allowthem_core::hash_token(&token);
        let expires = chrono::Utc::now() + chrono::Duration::hours(24);
        ath.db().create_session(user.id, hash, None, None, expires).await.unwrap();
        let cookie = format!("allowthem_session={}", token.as_str());
        (user.id, cookie)
    }

    // Inactive application returns display error

    #[tokio::test]
    async fn inactive_application_returns_400() {
        let (ath, app) = test_app().await;
        let application = setup_application(&ath).await;

        // Deactivate the application
        sqlx::query("UPDATE allowthem_applications SET is_active = 0 WHERE id = ?")
            .bind(application.id)
            .execute(ath.db().pool())
            .await
            .unwrap();

        let req = Request::builder()
            .method("GET")
            .uri(&format!(
                "/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid&state=s&code_challenge=c&code_challenge_method=S256",
                application.client_id.as_str(),
                url::form_urlencoded::byte_serialize(b"https://example.com/callback").collect::<String>()
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "application is inactive");
    }

    // Wrong code_challenge_method redirects with error

    #[tokio::test]
    async fn wrong_pkce_method_redirects_with_error() {
        let (ath, app) = test_app().await;
        let application = setup_application(&ath).await;
        let req = Request::builder()
            .method("GET")
            .uri(&format!(
                "/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid&state=s&code_challenge=c&code_challenge_method=plain",
                application.client_id.as_str(),
                url::form_urlencoded::byte_serialize(b"https://example.com/callback").collect::<String>()
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("error=invalid_request"));
        assert!(location.contains("state=s"));
    }

    // Existing consent skips the consent screen

    #[tokio::test]
    async fn existing_consent_skips_consent_screen() {
        let (ath, app) = test_app().await;
        let (user_id, cookie) = create_session(&ath, "existing_consent@example.com").await;
        let application = setup_application(&ath).await;

        // Pre-grant consent for the scopes that will be requested
        ath.db()
            .upsert_consent(
                user_id,
                application.id,
                &["openid".to_string(), "profile".to_string()],
            )
            .await
            .unwrap();

        let uri = authorize_uri(&application);
        let req = Request::builder()
            .method("GET")
            .uri(&uri)
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        // Should redirect with code, not show consent screen
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.contains("code="));
        assert!(location.contains("state=xyz"));
    }

    // POST handler: approve flow

    #[tokio::test]
    async fn post_approve_creates_code_and_redirects_303() {
        let (ath, app) = test_app().await;
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

    // POST handler: deny flow

    #[tokio::test]
    async fn post_deny_redirects_with_access_denied_303() {
        let (ath, app) = test_app().await;
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

    // POST handler: unauthenticated redirects to login

    #[tokio::test]
    async fn post_unauthenticated_redirects_to_login() {
        let (ath, app) = test_app().await;
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

    // POST handler: re-validates parameters (defense-in-depth)

    #[tokio::test]
    async fn post_with_invalid_client_id_returns_400() {
        let (ath, app) = test_app().await;
        let (_, cookie) = create_session(&ath, "post_revalidate@example.com").await;
        // Application not created — client_id won't exist
        let _ = ath; // silence warning

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
        // Display error — client_id validation fails before redirect
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "unknown client_id");
    }
}
