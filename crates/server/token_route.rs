use axum::extract::State;
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Form, Json, Router};
use base64ct::{Base64, Encoding};
use serde::Deserialize;
use serde_json::json;

use allowthem_core::password::verify_password;
use allowthem_core::types::ClientId;
use allowthem_core::{AllowThem, AuthError, TokenError, exchange_authorization_code};

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenParams {
    grant_type: Option<String>,
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    client_id: Option<ClientId>,
    client_secret: Option<String>,
}

// ---------------------------------------------------------------------------
// Client credential extraction
// ---------------------------------------------------------------------------

fn extract_client_credentials(
    headers: &HeaderMap,
    params: &TokenParams,
) -> Result<(ClientId, String), TokenError> {
    if let Some(auth_header) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        if let Some(encoded) = auth_header.strip_prefix("Basic ") {
            let decoded = Base64::decode_vec(encoded)
                .map_err(|_| TokenError::InvalidClient("malformed Basic credentials".into()))?;
            let decoded_str = String::from_utf8(decoded)
                .map_err(|_| TokenError::InvalidClient("malformed Basic credentials".into()))?;
            let (id_str, secret) = decoded_str
                .split_once(':')
                .ok_or_else(|| TokenError::InvalidClient("malformed Basic credentials".into()))?;
            let client_id: ClientId =
                serde_json::from_value::<ClientId>(serde_json::Value::String(
                    id_str.to_string(),
                ))
                .map_err(|_| {
                    TokenError::InvalidClient("invalid client_id in Basic credentials".into())
                })?;
            return Ok((client_id, secret.to_string()));
        }
    }

    let client_id = params
        .client_id
        .clone()
        .ok_or_else(|| TokenError::InvalidClient("missing client credentials".into()))?;
    let client_secret = params
        .client_secret
        .clone()
        .ok_or_else(|| TokenError::InvalidClient("missing client credentials".into()))?;
    Ok((client_id, client_secret))
}

// ---------------------------------------------------------------------------
// Error response
// ---------------------------------------------------------------------------

fn token_error_response(error: &TokenError) -> Response {
    let (status, error_code, description) = match error {
        TokenError::InvalidClient(desc) => {
            (StatusCode::UNAUTHORIZED, "invalid_client", desc.as_str())
        }
        TokenError::InvalidGrant(desc) => {
            (StatusCode::BAD_REQUEST, "invalid_grant", desc.as_str())
        }
        TokenError::InvalidRequest(desc) => {
            (StatusCode::BAD_REQUEST, "invalid_request", desc.as_str())
        }
        TokenError::UnsupportedGrantType => (
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "only authorization_code is supported",
        ),
        TokenError::ServerError(desc) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "server_error", desc.as_str())
        }
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
    State(ath): State<AllowThem>,
    headers: HeaderMap,
    Form(params): Form<TokenParams>,
) -> Response {
    // 1. Extract client credentials
    let (client_id, client_secret) = match extract_client_credentials(&headers, &params) {
        Ok(creds) => creds,
        Err(e) => return token_error_response(&e),
    };

    // 2. Authenticate client
    let application = match ath.db().get_application_by_client_id(&client_id).await {
        Ok(app) => app,
        Err(AuthError::NotFound) => {
            return token_error_response(&TokenError::InvalidClient(
                "unknown client_id".into(),
            ))
        }
        Err(_) => {
            return token_error_response(&TokenError::ServerError("internal error".into()))
        }
    };

    match verify_password(&client_secret, &application.client_secret_hash) {
        Ok(true) => {}
        _ => {
            return token_error_response(&TokenError::InvalidClient(
                "invalid client_secret".into(),
            ))
        }
    }

    if !application.is_active {
        return token_error_response(&TokenError::InvalidClient(
            "application is inactive".into(),
        ));
    }

    // 3. Validate grant_type
    if params.grant_type.as_deref() != Some("authorization_code") {
        return token_error_response(&TokenError::UnsupportedGrantType);
    }

    // 4. Validate required params
    let code = match params.code.as_deref() {
        Some(c) if !c.is_empty() => c,
        _ => {
            return token_error_response(&TokenError::InvalidRequest(
                "missing code parameter".into(),
            ))
        }
    };
    let redirect_uri = match params.redirect_uri.as_deref() {
        Some(r) if !r.is_empty() => r,
        _ => {
            return token_error_response(&TokenError::InvalidRequest(
                "missing redirect_uri parameter".into(),
            ))
        }
    };
    let code_verifier = match params.code_verifier.as_deref() {
        Some(v) if !v.is_empty() => v,
        _ => {
            return token_error_response(&TokenError::InvalidRequest(
                "missing code_verifier parameter".into(),
            ))
        }
    };

    // 5. Get signing key and decrypted PEM
    let (signing_key, private_key_pem) = match ath.get_decrypted_signing_key().await {
        Ok(pair) => pair,
        Err(AuthError::NotFound) => {
            return token_error_response(&TokenError::ServerError(
                "no active signing key".into(),
            ))
        }
        Err(e) => return token_error_response(&TokenError::ServerError(e.to_string())),
    };

    // 6. Get issuer
    let issuer = match ath.base_url() {
        Ok(url) => url,
        Err(e) => return token_error_response(&TokenError::ServerError(e.to_string())),
    };

    // 7. Exchange authorization code for tokens
    match exchange_authorization_code(
        ath.db(),
        code,
        redirect_uri,
        code_verifier,
        &application,
        issuer,
        &signing_key,
        &private_key_pem,
    )
    .await
    {
        Ok(token_response) => {
            let mut resp = (StatusCode::OK, Json(token_response)).into_response();
            resp.headers_mut()
                .insert("Cache-Control", "no-store".parse().expect("valid header"));
            resp.headers_mut()
                .insert("Pragma", "no-cache".parse().expect("valid header"));
            resp
        }
        Err(e) => token_error_response(&e),
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn token_route() -> Router<AllowThem> {
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
        let app = routes.with_state(ath.clone());
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
            .create_user(email, "password123", None)
            .await
            .unwrap();

        let (app, client_secret) = ath
            .db()
            .create_application(
                "TokenTestApp".to_string(),
                vec!["https://example.com/callback".to_string()],
                false,
                Some(user.id),
                None,
                None,
            )
            .await
            .unwrap();
        let raw_secret = client_secret.as_str().to_string();

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
        let (application, secret, code, verifier, redirect_uri) =
            setup_code_exchange(&ath).await;
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
        let (application, secret, code, verifier, redirect_uri) =
            setup_code_exchange(&ath).await;

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

        let body =
            build_token_body(&application, "wrong_secret", &code, &verifier, &redirect_uri);
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
        let (application, secret, code, verifier, redirect_uri) =
            setup_code_exchange(&ath).await;

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

        let body = build_token_body(&application, &secret, &code, "wrong_verifier", &redirect_uri);
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
        let (application, secret, code, verifier, redirect_uri) =
            setup_code_exchange(&ath).await;

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
        let (application, secret, code, verifier, redirect_uri) =
            setup_code_exchange(&ath).await;
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
}
