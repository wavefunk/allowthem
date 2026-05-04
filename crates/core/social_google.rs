//! Google `SocialProvider` implementation.
//!
//! ## Token URL injection for tests
//!
//! The Google token endpoint is hardcoded to `https://oauth2.googleapis.com/token`
//! in the public `new()` constructor. Tests that need to point at a wiremock server
//! use the crate-private `new_with_token_url()` constructor instead. This avoids
//! the `OnceLock`-override pattern which is parallel-test-hostile.

use base64ct::{Base64UrlUnpadded, Encoding};
use serde::Deserialize;
use url::Url;

use crate::auth_client::AuthFuture;
use crate::error::AuthError;
use crate::social_providers::{ProviderType, SocialProvider, SocialProviderConfig, SocialUserInfo};

// ── Struct ────────────────────────────────────────────────────────────────────

/// Google OAuth 2.0 + OIDC social provider.
///
/// Constructed from a [`SocialProviderConfig`] via [`Self::new`]. The
/// `exchange_code` method returns the `id_token` JWT from the token
/// response; `fetch_user_info` decodes it locally — no second HTTP call.
#[derive(Debug)]
pub struct GoogleSocialProvider {
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
    http: reqwest::Client,
    /// Token endpoint URL. Always `https://oauth2.googleapis.com/token` in
    /// production; overridden in tests via `new_with_token_url`.
    token_url: String,
}

// ── Private claims struct ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct GoogleIdTokenClaims {
    sub: String,
    email: String,
    email_verified: bool,
    name: Option<String>,
    picture: Option<String>,
}

// ── Constructors ──────────────────────────────────────────────────────────────

impl GoogleSocialProvider {
    /// Build a `GoogleSocialProvider` from a decrypted config.
    ///
    /// Returns `AuthError::Validation` if `provider_type` is not `Google`
    /// or `scopes` is empty.
    pub fn new(config: SocialProviderConfig) -> Result<Self, AuthError> {
        Self::new_with_token_url(config, "https://oauth2.googleapis.com/token".into())
    }

    /// Like [`Self::new`] but with an overrideable token endpoint URL.
    ///
    /// Used by tests to point at a wiremock server.
    pub(crate) fn new_with_token_url(
        config: SocialProviderConfig,
        token_url: String,
    ) -> Result<Self, AuthError> {
        if config.provider_type != ProviderType::Google {
            return Err(AuthError::Validation(
                "provider_type mismatch: expected Google".into(),
            ));
        }
        if config.scopes.is_empty() {
            return Err(AuthError::Validation("scopes must not be empty".into()));
        }
        let http = reqwest::Client::builder()
            .user_agent("allowthem-oauth")
            .build()
            .map_err(|e| AuthError::Validation(format!("reqwest client build failed: {e}")))?;
        Ok(Self {
            client_id: config.client_id,
            client_secret: config.client_secret,
            scopes: config.scopes,
            http,
            token_url,
        })
    }
}

// ── SocialProvider impl ───────────────────────────────────────────────────────

impl SocialProvider for GoogleSocialProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Google
    }

    fn authorize_url(&self, redirect_uri: &str, state: &str, pkce_challenge: &str) -> String {
        let mut url =
            Url::parse("https://accounts.google.com/o/oauth2/v2/auth").expect("static URL");
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", &self.scopes.join(" "))
            .append_pair("state", state)
            .append_pair("code_challenge", pkce_challenge)
            .append_pair("code_challenge_method", "S256");
        url.into()
    }

    fn exchange_code<'a>(
        &'a self,
        code: &'a str,
        redirect_uri: &'a str,
        pkce_verifier: &'a str,
    ) -> AuthFuture<'a, String> {
        Box::pin(async move {
            let resp = self
                .http
                .post(&self.token_url)
                .form(&[
                    ("code", code),
                    ("client_id", self.client_id.as_str()),
                    ("client_secret", self.client_secret.as_str()),
                    ("redirect_uri", redirect_uri),
                    ("grant_type", "authorization_code"),
                    ("code_verifier", pkce_verifier),
                ])
                .send()
                .await
                .map_err(|e| AuthError::OAuthHttp(format!("{e}")))?;

            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(AuthError::OAuthTokenExchange(format!("{status}: {body}")));
            }

            let json: serde_json::Value = resp
                .json()
                .await
                .map_err(|e| AuthError::OAuthHttp(format!("{e}")))?;

            json.get("id_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_owned())
                .ok_or_else(|| {
                    AuthError::OAuthTokenExchange(
                        "missing id_token in Google token response".into(),
                    )
                })
        })
    }

    fn fetch_user_info<'a>(&'a self, access_token: &'a str) -> AuthFuture<'a, SocialUserInfo> {
        Box::pin(async move {
            let claims = decode_id_token(access_token)?;
            Ok(SocialUserInfo {
                provider_user_id: claims.sub,
                email: claims.email,
                email_verified: claims.email_verified,
                name: claims.name,
                avatar_url: claims.picture,
            })
        })
    }
}

// ── id_token decode helper ────────────────────────────────────────────────────

fn decode_id_token(token: &str) -> Result<GoogleIdTokenClaims, AuthError> {
    // A JWT is exactly three base64url segments separated by '.'.
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::OAuthUserInfoFetch("malformed id_token".into()));
    }
    let raw = Base64UrlUnpadded::decode_vec(parts[1]).map_err(|_| {
        AuthError::OAuthUserInfoFetch("id_token payload is not valid base64url".into())
    })?;
    serde_json::from_slice::<GoogleIdTokenClaims>(&raw).map_err(|e| {
        AuthError::OAuthUserInfoFetch(format!("id_token payload JSON parse error: {e}"))
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SocialProviderId;

    fn google_config() -> SocialProviderConfig {
        SocialProviderConfig {
            id: SocialProviderId::new(),
            provider_type: ProviderType::Google,
            display_name: "Google".into(),
            client_id: "test-client-id".into(),
            client_secret: "test-client-secret".into(),
            scopes: vec!["openid".into(), "email".into()],
            enabled: true,
            priority: 0,
            config: None,
        }
    }

    // ── Constructor validation ────────────────────────────────────────────────

    #[test]
    fn new_rejects_provider_type_mismatch() {
        let mut cfg = google_config();
        cfg.provider_type = ProviderType::Github;
        let err = GoogleSocialProvider::new(cfg).unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    #[test]
    fn new_rejects_empty_scopes() {
        let mut cfg = google_config();
        cfg.scopes = vec![];
        let err = GoogleSocialProvider::new(cfg).unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    // ── authorize_url ─────────────────────────────────────────────────────────

    #[test]
    fn authorize_url_contains_required_params() {
        let provider = GoogleSocialProvider::new(google_config()).unwrap();
        let url = provider.authorize_url("https://example.com/callback", "mystate", "mychallenge");
        assert!(url.contains("client_id=test-client-id"), "url: {url}");
        assert!(url.contains("redirect_uri="), "url: {url}");
        assert!(url.contains("response_type=code"), "url: {url}");
        assert!(url.contains("state=mystate"), "url: {url}");
        assert!(url.contains("code_challenge=mychallenge"), "url: {url}");
        assert!(url.contains("code_challenge_method=S256"), "url: {url}");
    }

    #[test]
    fn authorize_url_uses_config_scopes_joined_by_space() {
        let provider = GoogleSocialProvider::new(google_config()).unwrap();
        let url = provider.authorize_url("https://example.com/callback", "s", "c");
        // url crate percent-encodes spaces as %20 in query values
        assert!(
            url.contains("scope=openid+email") || url.contains("scope=openid%20email"),
            "url: {url}"
        );
    }

    #[test]
    fn authorize_url_does_not_leak_client_secret() {
        let provider = GoogleSocialProvider::new(google_config()).unwrap();
        let url = provider.authorize_url("https://example.com/callback", "s", "c");
        assert!(!url.contains("test-client-secret"), "url: {url}");
    }

    // ── fetch_user_info (id_token decoding) ──────────────────────────────────

    fn make_id_token(payload: &serde_json::Value) -> String {
        let header = Base64UrlUnpadded::encode_string(b"{\"alg\":\"RS256\"}");
        let body = Base64UrlUnpadded::encode_string(payload.to_string().as_bytes());
        format!("{header}.{body}.fakesig")
    }

    #[tokio::test]
    async fn decode_id_token_extracts_claims() {
        let payload = serde_json::json!({
            "sub": "google-user-123",
            "email": "user@example.com",
            "email_verified": true,
            "name": "Test User",
            "picture": "https://example.com/photo.jpg"
        });
        let provider = GoogleSocialProvider::new(google_config()).unwrap();
        let info = provider
            .fetch_user_info(&make_id_token(&payload))
            .await
            .unwrap();
        assert_eq!(info.provider_user_id, "google-user-123");
        assert_eq!(info.email, "user@example.com");
        assert!(info.email_verified);
        assert_eq!(info.name.as_deref(), Some("Test User"));
        assert_eq!(
            info.avatar_url.as_deref(),
            Some("https://example.com/photo.jpg")
        );
    }

    #[tokio::test]
    async fn decode_id_token_rejects_malformed_token() {
        let provider = GoogleSocialProvider::new(google_config()).unwrap();
        let err = provider.fetch_user_info("only.two").await.unwrap_err();
        assert!(matches!(err, AuthError::OAuthUserInfoFetch(_)));
    }

    #[tokio::test]
    async fn decode_id_token_rejects_invalid_base64() {
        let provider = GoogleSocialProvider::new(google_config()).unwrap();
        let err = provider
            .fetch_user_info("header.!!!invalid!!!.sig")
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::OAuthUserInfoFetch(_)));
    }

    #[tokio::test]
    async fn decode_id_token_rejects_non_json_payload() {
        let payload_b64 = Base64UrlUnpadded::encode_string(b"not json at all");
        let token = format!("header.{payload_b64}.sig");
        let provider = GoogleSocialProvider::new(google_config()).unwrap();
        let err = provider.fetch_user_info(&token).await.unwrap_err();
        assert!(matches!(err, AuthError::OAuthUserInfoFetch(_)));
    }

    #[tokio::test]
    async fn decode_id_token_email_unverified_propagates() {
        let payload = serde_json::json!({
            "sub": "u1",
            "email": "u@example.com",
            "email_verified": false,
        });
        let provider = GoogleSocialProvider::new(google_config()).unwrap();
        let info = provider
            .fetch_user_info(&make_id_token(&payload))
            .await
            .unwrap();
        assert!(!info.email_verified);
    }

    #[tokio::test]
    async fn decode_id_token_picture_maps_to_avatar_url() {
        let payload = serde_json::json!({
            "sub": "u1",
            "email": "u@example.com",
            "email_verified": true,
            "picture": "https://cdn.example.com/avatar.png"
        });
        let provider = GoogleSocialProvider::new(google_config()).unwrap();
        let info = provider
            .fetch_user_info(&make_id_token(&payload))
            .await
            .unwrap();
        assert_eq!(
            info.avatar_url.as_deref(),
            Some("https://cdn.example.com/avatar.png")
        );
    }

    // ── HTTP tests (wiremock) ─────────────────────────────────────────────────

    #[tokio::test]
    async fn exchange_code_extracts_id_token_on_success() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "unused-access",
                "id_token": "header.payload.sig",
                "token_type": "Bearer"
            })))
            .mount(&server)
            .await;

        let token_url = format!("{}/token", server.uri());
        let provider =
            GoogleSocialProvider::new_with_token_url(google_config(), token_url).unwrap();
        let id_token = provider
            .exchange_code("mycode", "https://example.com/cb", "pkce_v")
            .await
            .unwrap();
        assert_eq!(id_token, "header.payload.sig");
    }

    #[tokio::test]
    async fn exchange_code_returns_token_exchange_error_on_4xx() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant"
            })))
            .mount(&server)
            .await;

        let token_url = format!("{}/token", server.uri());
        let provider =
            GoogleSocialProvider::new_with_token_url(google_config(), token_url).unwrap();
        let err = provider
            .exchange_code("badcode", "https://example.com/cb", "v")
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::OAuthTokenExchange(_)));
    }

    #[tokio::test]
    async fn exchange_code_returns_token_exchange_error_on_missing_id_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "some-access-token",
                "token_type": "Bearer"
            })))
            .mount(&server)
            .await;

        let token_url = format!("{}/token", server.uri());
        let provider =
            GoogleSocialProvider::new_with_token_url(google_config(), token_url).unwrap();
        let err = provider
            .exchange_code("code", "https://example.com/cb", "v")
            .await
            .unwrap_err();
        match err {
            AuthError::OAuthTokenExchange(msg) => {
                assert!(msg.contains("missing id_token"), "got: {msg}");
            }
            other => panic!("expected OAuthTokenExchange, got {other:?}"),
        }
    }
}
