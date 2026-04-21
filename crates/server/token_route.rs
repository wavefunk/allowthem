use axum::extract::Extension;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Form, Json, Router};
use base64ct::{Base64, Encoding};
use serde::Deserialize;
use serde_json::json;

use allowthem_core::password::verify_password;
use allowthem_core::types::{ClientId, ClientType};
use allowthem_core::{
    AllowThem, AuthError, TokenError, exchange_authorization_code, exchange_refresh_token,
};

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenParams {
    grant_type: Option<String>,
    // authorization_code grant
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    // refresh_token grant
    refresh_token: Option<String>,
    scope: Option<String>,
    // client credentials (both grants)
    client_id: Option<ClientId>,
    client_secret: Option<String>,
}

// ---------------------------------------------------------------------------
// Client credential extraction
// ---------------------------------------------------------------------------

fn extract_client_credentials(
    headers: &HeaderMap,
    params: &TokenParams,
) -> Result<(ClientId, Option<String>), TokenError> {
    if let Some(auth_header) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok())
        && let Some(encoded) = auth_header.strip_prefix("Basic ")
    {
        let decoded = Base64::decode_vec(encoded)
            .map_err(|_| TokenError::InvalidClient("malformed Basic credentials".into()))?;
        let decoded_str = String::from_utf8(decoded)
            .map_err(|_| TokenError::InvalidClient("malformed Basic credentials".into()))?;
        let (id_str, secret_str) = decoded_str
            .split_once(':')
            .ok_or_else(|| TokenError::InvalidClient("malformed Basic credentials".into()))?;
        let client_id: ClientId =
            serde_json::from_value::<ClientId>(serde_json::Value::String(id_str.to_string()))
                .map_err(|_| {
                    TokenError::InvalidClient("invalid client_id in Basic credentials".into())
                })?;
        let secret = if secret_str.is_empty() {
            None
        } else {
            Some(secret_str.to_string())
        };
        return Ok((client_id, secret));
    }

    let client_id = params
        .client_id
        .clone()
        .ok_or_else(|| TokenError::InvalidClient("missing client credentials".into()))?;
    let secret = params
        .client_secret
        .as_ref()
        .filter(|s| !s.is_empty())
        .cloned();
    Ok((client_id, secret))
}

// ---------------------------------------------------------------------------
// Error response
// ---------------------------------------------------------------------------

fn token_error_response(error: &TokenError) -> Response {
    let (status, error_code, description) = match error {
        TokenError::InvalidClient(desc) => {
            (StatusCode::UNAUTHORIZED, "invalid_client", desc.as_str())
        }
        TokenError::InvalidGrant(desc) => (StatusCode::BAD_REQUEST, "invalid_grant", desc.as_str()),
        TokenError::InvalidRequest(desc) => {
            (StatusCode::BAD_REQUEST, "invalid_request", desc.as_str())
        }
        TokenError::UnsupportedGrantType => (
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "unsupported grant_type",
        ),
        TokenError::ServerError(desc) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            desc.as_str(),
        ),
    };

    let body = json!({"error": error_code, "error_description": description});
    let mut resp = (status, Json(body)).into_response();

    if matches!(error, TokenError::InvalidClient(_)) {
        resp.headers_mut().insert(
            "WWW-Authenticate",
            "Basic realm=\"allowthem\"".parse().expect("valid header"),
        );
    }

    resp.headers_mut()
        .insert("Cache-Control", "no-store".parse().expect("valid header"));
    resp.headers_mut()
        .insert("Pragma", "no-cache".parse().expect("valid header"));
    resp
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

async fn token(
    Extension(ath): Extension<AllowThem>,
    headers: HeaderMap,
    Form(params): Form<TokenParams>,
) -> Response {
    // 1. Extract client credentials
    let (client_id, maybe_secret) = match extract_client_credentials(&headers, &params) {
        Ok(creds) => creds,
        Err(e) => return token_error_response(&e),
    };

    // 2. Look up application
    let application = match ath.db().get_application_by_client_id(&client_id).await {
        Ok(app) => app,
        Err(AuthError::NotFound) => {
            return token_error_response(&TokenError::InvalidClient("unknown client_id".into()));
        }
        Err(_) => return token_error_response(&TokenError::ServerError("internal error".into())),
    };

    // 3. Authenticate based on client type
    match application.client_type {
        ClientType::Confidential => {
            let secret = match maybe_secret {
                Some(s) => s,
                None => {
                    return token_error_response(&TokenError::InvalidClient(
                        "missing client_secret".into(),
                    ));
                }
            };
            // client_secret_hash is always Some for Confidential — invariant from create_application
            match verify_password(&secret, application.client_secret_hash.as_ref().unwrap()) {
                Ok(true) => {}
                _ => {
                    return token_error_response(&TokenError::InvalidClient(
                        "invalid client_secret".into(),
                    ));
                }
            }
        }
        ClientType::Public => {
            if maybe_secret.is_some() {
                return token_error_response(&TokenError::InvalidClient(
                    "public clients must not send client_secret".into(),
                ));
            }
        }
    }

    if !application.is_active {
        return token_error_response(&TokenError::InvalidClient("application is inactive".into()));
    }

    // 3. Get signing key and issuer (shared by both grant types)
    let (signing_key, private_key_pem) = match ath.get_decrypted_signing_key().await {
        Ok(pair) => pair,
        Err(AuthError::NotFound) => {
            return token_error_response(&TokenError::ServerError("no active signing key".into()));
        }
        Err(e) => return token_error_response(&TokenError::ServerError(e.to_string())),
    };

    let issuer = match ath.base_url() {
        Ok(url) => url,
        Err(e) => return token_error_response(&TokenError::ServerError(e.to_string())),
    };

    // 4. Dispatch on grant_type
    match params.grant_type.as_deref() {
        Some("authorization_code") => {
            handle_authorization_code(
                ath.db(),
                params,
                signing_key,
                private_key_pem,
                &application,
                issuer,
            )
            .await
        }
        Some("refresh_token") => {
            handle_refresh_token(
                ath.db(),
                params,
                signing_key,
                private_key_pem,
                &application,
                issuer,
            )
            .await
        }
        _ => token_error_response(&TokenError::UnsupportedGrantType),
    }
}

async fn handle_authorization_code(
    db: &allowthem_core::db::Db,
    params: TokenParams,
    signing_key: allowthem_core::SigningKey,
    private_key_pem: String,
    application: &allowthem_core::applications::Application,
    issuer: &str,
) -> Response {
    let code = match params.code.as_deref() {
        Some(c) if !c.is_empty() => c,
        _ => {
            return token_error_response(&TokenError::InvalidRequest(
                "missing code parameter".into(),
            ));
        }
    };
    let redirect_uri = match params.redirect_uri.as_deref() {
        Some(r) if !r.is_empty() => r,
        _ => {
            return token_error_response(&TokenError::InvalidRequest(
                "missing redirect_uri parameter".into(),
            ));
        }
    };
    let code_verifier = match params.code_verifier.as_deref() {
        Some(v) if !v.is_empty() => v,
        _ => {
            return token_error_response(&TokenError::InvalidRequest(
                "missing code_verifier parameter".into(),
            ));
        }
    };

    match exchange_authorization_code(
        db,
        code,
        redirect_uri,
        code_verifier,
        application,
        issuer,
        &signing_key,
        &private_key_pem,
    )
    .await
    {
        Ok(token_response) => token_success_response(token_response),
        Err(e) => token_error_response(&e),
    }
}

async fn handle_refresh_token(
    db: &allowthem_core::db::Db,
    params: TokenParams,
    signing_key: allowthem_core::SigningKey,
    private_key_pem: String,
    application: &allowthem_core::applications::Application,
    issuer: &str,
) -> Response {
    let raw_token = match params.refresh_token.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => {
            return token_error_response(&TokenError::InvalidRequest(
                "missing refresh_token parameter".into(),
            ));
        }
    };

    let requested_scopes = params.scope.as_deref();

    match exchange_refresh_token(
        db,
        raw_token,
        requested_scopes,
        application,
        issuer,
        &signing_key,
        &private_key_pem,
    )
    .await
    {
        Ok(token_response) => token_success_response(token_response),
        Err(e) => token_error_response(&e),
    }
}

fn token_success_response(token_response: allowthem_core::TokenResponse) -> Response {
    let mut resp = (StatusCode::OK, Json(token_response)).into_response();
    resp.headers_mut()
        .insert("Cache-Control", "no-store".parse().expect("valid header"));
    resp.headers_mut()
        .insert("Pragma", "no-cache".parse().expect("valid header"));
    resp
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn token_route() -> Router<()> {
    Router::new().route("/oauth/token", post(token))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::authorization::{generate_authorization_code, hash_authorization_code};
    use allowthem_core::handle::AllowThemBuilder;
    use allowthem_core::types::Email;
    use axum::body::Body;
    use axum::http::Request;
    use sha2::{Digest, Sha256};
    use tower::ServiceExt;

    const ENC_KEY: [u8; 32] = [0x42; 32];
    const ISSUER: &str = "https://auth.example.com";

    async fn test_app() -> (AllowThem, Router) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .signing_key(ENC_KEY)
            .base_url(ISSUER)
            .build()
            .await
            .unwrap();

        let key = ath.db().create_signing_key(&ENC_KEY).await.unwrap();
        ath.db().activate_signing_key(key.id).await.unwrap();

        let routes = token_route();
        let app = routes.layer(axum::middleware::from_fn_with_state(
            ath.clone(),
            crate::cors::inject_ath_into_extensions,
        ));
        (ath, app)
    }

    async fn setup_code_exchange(
        ath: &AllowThem,
    ) -> (
        allowthem_core::applications::Application,
        String,
        String,
        String,
        String,
    ) {
        let email = Email::new("token_test@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();

        let (app, client_secret) = ath
            .db()
            .create_application(
                "TokenTestApp".to_string(),
                ClientType::Confidential,
                vec!["https://example.com/callback".to_string()],
                false,
                Some(user.id),
                None,
                None,
            )
            .await
            .unwrap();
        let raw_secret = client_secret
            .expect("confidential app has secret")
            .as_str()
            .to_string();

        let code_verifier = "test_verifier_with_enough_entropy_1234567890abcdef";
        let digest = Sha256::digest(code_verifier.as_bytes());
        let code_challenge = base64ct::Base64UrlUnpadded::encode_string(&digest);

        let raw_code = generate_authorization_code();
        let code_hash = hash_authorization_code(&raw_code);
        ath.db()
            .create_authorization_code(
                app.id,
                user.id,
                &code_hash,
                "https://example.com/callback",
                &["openid".to_string(), "profile".to_string()],
                &code_challenge,
                "S256",
                None,
            )
            .await
            .unwrap();

        (
            app,
            raw_secret,
            raw_code,
            code_verifier.to_string(),
            "https://example.com/callback".to_string(),
        )
    }

    fn build_token_body(
        app: &allowthem_core::applications::Application,
        secret: &str,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
    ) -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", code)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("code_verifier", verifier)
            .append_pair("client_id", app.client_id.as_str())
            .append_pair("client_secret", secret)
            .finish()
    }

    async fn read_body(resp: axum::http::Response<Body>) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
    }

    #[tokio::test]
    async fn valid_code_exchange_returns_200() {
        let (ath, app) = test_app().await;
        let (application, secret, code, verifier, redirect_uri) = setup_code_exchange(&ath).await;
        let body = build_token_body(&application, &secret, &code, &verifier, &redirect_uri);

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let cache_control = resp
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache_control, "no-store");

        let body = read_body(resp).await;
        assert_eq!(body["token_type"], "Bearer");
        assert_eq!(body["expires_in"], 3600);
        assert!(body["access_token"].is_string());
        assert!(body["refresh_token"].is_string());
        assert!(body["id_token"].is_string());
    }

    #[tokio::test]
    async fn missing_grant_type_returns_400() {
        let (ath, app) = test_app().await;
        let (application, secret, code, verifier, redirect_uri) = setup_code_exchange(&ath).await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("code", &code)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("code_verifier", &verifier)
            .append_pair("client_id", application.client_id.as_str())
            .append_pair("client_secret", &secret)
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn invalid_client_id_returns_401_with_www_authenticate() {
        let (_ath, app) = test_app().await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", "test")
            .append_pair("redirect_uri", "https://example.com/callback")
            .append_pair("code_verifier", "test")
            .append_pair("client_id", "ath_nonexistent")
            .append_pair("client_secret", "wrong")
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let www_auth = resp
            .headers()
            .get("www-authenticate")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(www_auth.contains("Basic"));

        let body = read_body(resp).await;
        assert_eq!(body["error"], "invalid_client");
    }

    #[tokio::test]
    async fn wrong_client_secret_returns_401() {
        let (ath, app) = test_app().await;
        let (application, _, code, verifier, redirect_uri) = setup_code_exchange(&ath).await;

        let body = build_token_body(
            &application,
            "wrong_secret",
            &code,
            &verifier,
            &redirect_uri,
        );
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn basic_auth_valid() {
        let (ath, app) = test_app().await;
        let (application, secret, code, verifier, redirect_uri) = setup_code_exchange(&ath).await;

        let credentials = format!("{}:{}", application.client_id.as_str(), secret);
        let encoded = Base64::encode_string(credentials.as_bytes());

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", &code)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("code_verifier", &verifier)
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("authorization", format!("Basic {encoded}"))
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn basic_auth_malformed_returns_401() {
        let (_ath, app) = test_app().await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", "test")
            .append_pair("redirect_uri", "https://example.com/callback")
            .append_pair("code_verifier", "test")
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .header("authorization", "Basic not-valid-base64!!!")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn wrong_code_verifier_returns_400() {
        let (ath, app) = test_app().await;
        let (application, secret, code, _, redirect_uri) = setup_code_exchange(&ath).await;

        let body = build_token_body(
            &application,
            &secret,
            &code,
            "wrong_verifier",
            &redirect_uri,
        );
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn wrong_redirect_uri_returns_400() {
        let (ath, app) = test_app().await;
        let (application, secret, code, verifier, _) = setup_code_exchange(&ath).await;

        let body = build_token_body(
            &application,
            &secret,
            &code,
            &verifier,
            "https://evil.example.com/callback",
        );
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn wrong_grant_type_returns_400() {
        let (ath, app) = test_app().await;
        let (application, secret, code, verifier, redirect_uri) = setup_code_exchange(&ath).await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("code", &code)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("code_verifier", &verifier)
            .append_pair("client_id", application.client_id.as_str())
            .append_pair("client_secret", &secret)
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "unsupported_grant_type");
    }

    #[tokio::test]
    async fn missing_code_returns_400() {
        let (ath, app) = test_app().await;
        let (application, secret, _, verifier, redirect_uri) = setup_code_exchange(&ath).await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("code_verifier", &verifier)
            .append_pair("client_id", application.client_id.as_str())
            .append_pair("client_secret", &secret)
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "invalid_request");
    }

    #[tokio::test]
    async fn missing_redirect_uri_returns_400() {
        let (ath, app) = test_app().await;
        let (application, secret, code, verifier, _) = setup_code_exchange(&ath).await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", &code)
            .append_pair("code_verifier", &verifier)
            .append_pair("client_id", application.client_id.as_str())
            .append_pair("client_secret", &secret)
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "invalid_request");
    }

    #[tokio::test]
    async fn missing_code_verifier_returns_400() {
        let (ath, app) = test_app().await;
        let (application, secret, code, _, redirect_uri) = setup_code_exchange(&ath).await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", &code)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("client_id", application.client_id.as_str())
            .append_pair("client_secret", &secret)
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "invalid_request");
    }

    #[tokio::test]
    async fn missing_client_credentials_returns_401() {
        let (_ath, app) = test_app().await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", "test")
            .append_pair("redirect_uri", "https://example.com/callback")
            .append_pair("code_verifier", "test")
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body = read_body(resp).await;
        assert_eq!(body["error"], "invalid_client");
    }

    #[tokio::test]
    async fn success_response_has_pragma_no_cache() {
        let (ath, app) = test_app().await;
        let (application, secret, code, verifier, redirect_uri) = setup_code_exchange(&ath).await;
        let body = build_token_body(&application, &secret, &code, &verifier, &redirect_uri);

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let pragma = resp.headers().get("pragma").unwrap().to_str().unwrap();
        assert_eq!(pragma, "no-cache");
    }

    fn build_refresh_body(
        application: &allowthem_core::applications::Application,
        secret: &str,
        refresh_token: &str,
    ) -> String {
        url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("refresh_token", refresh_token)
            .append_pair("client_id", application.client_id.as_str())
            .append_pair("client_secret", secret)
            .finish()
    }

    #[tokio::test]
    async fn refresh_token_grant_returns_200() {
        let (ath, app) = test_app().await;
        let (application, secret, code, verifier, redirect_uri) = setup_code_exchange(&ath).await;

        // First: exchange authorization code
        let body = build_token_body(&application, &secret, &code, &verifier, &redirect_uri);
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let initial = read_body(resp).await;
        let refresh_token = initial["refresh_token"].as_str().unwrap().to_string();

        // Second: use the refresh token
        let body = build_refresh_body(&application, &secret, &refresh_token);
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let cache_control = resp
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(cache_control, "no-store");

        let json = read_body(resp).await;
        assert_eq!(json["token_type"], "Bearer");
        assert_eq!(json["expires_in"], 3600);
        assert!(json["access_token"].is_string());
        assert!(json["refresh_token"].is_string());
        assert!(json["id_token"].is_string());
    }

    #[tokio::test]
    async fn refresh_token_new_token_differs_from_old() {
        let (ath, app) = test_app().await;
        let (application, secret, code, verifier, redirect_uri) = setup_code_exchange(&ath).await;

        let body = build_token_body(&application, &secret, &code, &verifier, &redirect_uri);
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let first = read_body(resp).await;
        let first_refresh = first["refresh_token"].as_str().unwrap().to_string();

        let body = build_refresh_body(&application, &secret, &first_refresh);
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let second = read_body(resp).await;
        let second_refresh = second["refresh_token"].as_str().unwrap().to_string();

        assert_ne!(
            first_refresh, second_refresh,
            "rotated refresh token must differ"
        );
    }

    #[tokio::test]
    async fn refresh_token_missing_returns_400() {
        let (ath, app) = test_app().await;
        let (application, secret, _, _, _) = setup_code_exchange(&ath).await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "refresh_token")
            .append_pair("client_id", application.client_id.as_str())
            .append_pair("client_secret", &secret)
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = read_body(resp).await;
        assert_eq!(json["error"], "invalid_request");
    }

    #[tokio::test]
    async fn refresh_token_reuse_returns_400() {
        let (ath, app) = test_app().await;
        let (application, secret, code, verifier, redirect_uri) = setup_code_exchange(&ath).await;

        let body = build_token_body(&application, &secret, &code, &verifier, &redirect_uri);
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let initial = read_body(resp).await;
        let refresh_token = initial["refresh_token"].as_str().unwrap().to_string();

        // First use — succeeds, revokes old token
        let body = build_refresh_body(&application, &secret, &refresh_token);
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let _ = app.clone().oneshot(req).await.unwrap();

        // Second use — fails, token was revoked
        let body = build_refresh_body(&application, &secret, &refresh_token);
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = read_body(resp).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn refresh_token_invalid_token_returns_400() {
        let (ath, app) = test_app().await;
        let (application, secret, _, _, _) = setup_code_exchange(&ath).await;

        let body = build_refresh_body(&application, &secret, "totally_garbage_token");
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = read_body(resp).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn refresh_token_wrong_client_returns_400() {
        let (ath, app) = test_app().await;
        let (application, secret, code, verifier, redirect_uri) = setup_code_exchange(&ath).await;

        // Obtain refresh token for app_a
        let body = build_token_body(&application, &secret, &code, &verifier, &redirect_uri);
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        let initial = read_body(resp).await;
        let refresh_token = initial["refresh_token"].as_str().unwrap().to_string();

        // Create app_b
        let email_b = allowthem_core::types::Email::new("other_http@example.com".into()).unwrap();
        let user_b = ath
            .db()
            .create_user(email_b, "password123", None, None)
            .await
            .unwrap();
        let (app_b, secret_b) = ath
            .db()
            .create_application(
                "OtherApp".to_string(),
                ClientType::Confidential,
                vec!["https://other.example.com/callback".to_string()],
                false,
                Some(user_b.id),
                None,
                None,
            )
            .await
            .unwrap();
        let raw_secret_b = secret_b
            .expect("confidential app has secret")
            .as_str()
            .to_string();

        // Try to use app_a's refresh token as app_b
        let body = build_refresh_body(&app_b, &raw_secret_b, &refresh_token);
        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = read_body(resp).await;
        assert_eq!(json["error"], "invalid_grant");
    }

    #[tokio::test]
    async fn unsupported_grant_type_returns_400() {
        let (ath, app) = test_app().await;
        let (application, secret, _, _, _) = setup_code_exchange(&ath).await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("client_id", application.client_id.as_str())
            .append_pair("client_secret", &secret)
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = read_body(resp).await;
        assert_eq!(json["error"], "unsupported_grant_type");
    }

    async fn setup_public_client_code_exchange(
        ath: &AllowThem,
    ) -> (
        allowthem_core::applications::Application,
        String,
        String,
        String,
    ) {
        let email =
            allowthem_core::types::Email::new("public_client_test@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();

        let (app, _secret) = ath
            .db()
            .create_application(
                "PublicApp".to_string(),
                ClientType::Public,
                vec!["https://example.com/callback".to_string()],
                false,
                Some(user.id),
                None,
                None,
            )
            .await
            .unwrap();

        let code_verifier = "public_client_verifier_with_enough_entropy_1234567890";
        let digest = sha2::Sha256::digest(code_verifier.as_bytes());
        let code_challenge = base64ct::Base64UrlUnpadded::encode_string(&digest);

        let raw_code = allowthem_core::authorization::generate_authorization_code();
        let code_hash = allowthem_core::authorization::hash_authorization_code(&raw_code);
        ath.db()
            .create_authorization_code(
                app.id,
                user.id,
                &code_hash,
                "https://example.com/callback",
                &["openid".to_string()],
                &code_challenge,
                "S256",
                None,
            )
            .await
            .unwrap();

        (
            app,
            raw_code,
            code_verifier.to_string(),
            "https://example.com/callback".to_string(),
        )
    }

    #[tokio::test]
    async fn public_client_gets_token_without_secret() {
        let (ath, app) = test_app().await;
        let (application, code, verifier, redirect_uri) =
            setup_public_client_code_exchange(&ath).await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", &code)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("code_verifier", &verifier)
            .append_pair("client_id", application.client_id.as_str())
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let json = read_body(resp).await;
        assert!(json["access_token"].is_string());
    }

    #[tokio::test]
    async fn public_client_rejected_when_secret_present() {
        let (ath, app) = test_app().await;
        let (application, code, verifier, redirect_uri) =
            setup_public_client_code_exchange(&ath).await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", &code)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("code_verifier", &verifier)
            .append_pair("client_id", application.client_id.as_str())
            .append_pair("client_secret", "should-not-be-here")
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let json = read_body(resp).await;
        assert_eq!(json["error"], "invalid_client");
    }

    #[tokio::test]
    async fn public_client_rejected_when_code_verifier_missing() {
        let (ath, app) = test_app().await;
        let (application, code, _, redirect_uri) = setup_public_client_code_exchange(&ath).await;

        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "authorization_code")
            .append_pair("code", &code)
            .append_pair("redirect_uri", &redirect_uri)
            .append_pair("client_id", application.client_id.as_str())
            .finish();

        let req = Request::builder()
            .method("POST")
            .uri("/oauth/token")
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let json = read_body(resp).await;
        assert_eq!(json["error"], "invalid_request");
    }
}
