//! GitHub `SocialProvider` implementation.
//!
//! ## Base URL injection for tests
//!
//! Two base URLs are hardcoded in the public `new()` constructor:
//! - `oauth_base_url` → `https://github.com/login/oauth` (token exchange)
//! - `api_base_url`   → `https://api.github.com` (user + emails lookup)
//!
//! Tests that need to point at a wiremock server use the crate-private
//! `new_with_base_urls()` constructor instead. This avoids the `OnceLock`
//! override pattern which is parallel-test-hostile.

use serde::Deserialize;
use url::Url;

use crate::auth_client::AuthFuture;
use crate::error::AuthError;
use crate::social_providers::{ProviderType, SocialProvider, SocialProviderConfig, SocialUserInfo};

// ── Struct ────────────────────────────────────────────────────────────────────

/// GitHub OAuth 2.0 social provider.
///
/// Constructed from a [`SocialProviderConfig`] via [`Self::new`].
/// `fetch_user_info` always calls both `/user` and `/user/emails`; the
/// latter provides the verified primary email (per plan §3.2).
#[derive(Debug)]
pub struct GitHubSocialProvider {
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
    http: reqwest::Client,
    /// Base URL for OAuth endpoints: `{oauth_base_url}/access_token` etc.
    /// Always `https://github.com/login/oauth` in production.
    oauth_base_url: String,
    /// Base URL for API endpoints: `{api_base_url}/user` etc.
    /// Always `https://api.github.com` in production.
    api_base_url: String,
}

// ── Private response structs ──────────────────────────────────────────────────

#[derive(Deserialize)]
struct GitHubTokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize)]
struct GitHubUser {
    id: i64,
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

// ── Constructors ──────────────────────────────────────────────────────────────

impl GitHubSocialProvider {
    /// Build a `GitHubSocialProvider` from a decrypted config.
    ///
    /// Returns `AuthError::Validation` if `provider_type` is not `Github`
    /// or `scopes` is empty.
    pub fn new(config: SocialProviderConfig) -> Result<Self, AuthError> {
        Self::new_with_base_urls(
            config,
            "https://github.com/login/oauth".into(),
            "https://api.github.com".into(),
        )
    }

    /// Like [`Self::new`] but with overrideable base URLs.
    ///
    /// Used by tests to point at a wiremock server.
    pub(crate) fn new_with_base_urls(
        config: SocialProviderConfig,
        oauth_base_url: String,
        api_base_url: String,
    ) -> Result<Self, AuthError> {
        if config.provider_type != ProviderType::Github {
            return Err(AuthError::Validation(
                "provider_type mismatch: expected Github".into(),
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
            oauth_base_url,
            api_base_url,
        })
    }
}

// ── SocialProvider impl ───────────────────────────────────────────────────────

impl SocialProvider for GitHubSocialProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::Github
    }

    fn authorize_url(&self, redirect_uri: &str, state: &str, pkce_challenge: &str) -> String {
        let mut url = Url::parse("https://github.com/login/oauth/authorize").expect("static URL");
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("state", state)
            .append_pair("scope", &self.scopes.join(" "))
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
            let token_url = format!("{}/access_token", self.oauth_base_url);
            let resp = self
                .http
                .post(&token_url)
                .header("Accept", "application/json")
                .form(&[
                    ("client_id", self.client_id.as_str()),
                    ("client_secret", self.client_secret.as_str()),
                    ("code", code),
                    ("redirect_uri", redirect_uri),
                    ("code_verifier", pkce_verifier),
                ])
                .send()
                .await
                .map_err(|e| AuthError::OAuthHttp(format!("{e}")))?;

            let token_resp: GitHubTokenResponse = resp
                .json()
                .await
                .map_err(|e| AuthError::OAuthHttp(format!("{e}")))?;

            if let Some(err) = token_resp.error {
                let desc = token_resp.error_description.unwrap_or_default();
                return Err(AuthError::OAuthTokenExchange(format!("{err}: {desc}")));
            }

            token_resp
                .access_token
                .ok_or_else(|| AuthError::OAuthTokenExchange("missing access_token".into()))
        })
    }

    fn fetch_user_info<'a>(&'a self, access_token: &'a str) -> AuthFuture<'a, SocialUserInfo> {
        Box::pin(async move {
            // Step 1: GET /user for profile fields (id, name, avatar_url).
            // Do not read the `email` field — always use /user/emails instead.
            let user_url = format!("{}/user", self.api_base_url);
            let user: GitHubUser = self
                .http
                .get(&user_url)
                .bearer_auth(access_token)
                .send()
                .await
                .map_err(|e| AuthError::OAuthHttp(format!("{e}")))?
                .json()
                .await
                .map_err(|e| AuthError::OAuthHttp(format!("{e}")))?;

            // Step 2: GET /user/emails for verified primary email.
            let emails_url = format!("{}/user/emails", self.api_base_url);
            let emails: Vec<GitHubEmail> = self
                .http
                .get(&emails_url)
                .bearer_auth(access_token)
                .send()
                .await
                .map_err(|e| AuthError::OAuthHttp(format!("{e}")))?
                .json()
                .await
                .map_err(|e| AuthError::OAuthHttp(format!("{e}")))?;

            let primary_email = emails
                .into_iter()
                .find(|e| e.primary && e.verified)
                .ok_or_else(|| {
                    AuthError::OAuthUserInfoFetch(
                        "no verified primary email on GitHub account".into(),
                    )
                })?;

            Ok(SocialUserInfo {
                provider_user_id: user.id.to_string(),
                email: primary_email.email,
                email_verified: true,
                name: user.name,
                avatar_url: user.avatar_url,
            })
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SocialProviderId;

    fn github_config() -> SocialProviderConfig {
        SocialProviderConfig {
            id: SocialProviderId::new(),
            provider_type: ProviderType::Github,
            display_name: "GitHub".into(),
            client_id: "test-client-id".into(),
            client_secret: "test-client-secret".into(),
            scopes: vec!["user:email".into(), "read:user".into()],
            enabled: true,
            priority: 0,
            config: None,
        }
    }

    // ── Constructor validation ────────────────────────────────────────────────

    #[test]
    fn new_rejects_provider_type_mismatch() {
        let mut cfg = github_config();
        cfg.provider_type = ProviderType::Google;
        let err = GitHubSocialProvider::new(cfg).unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    #[test]
    fn new_rejects_empty_scopes() {
        let mut cfg = github_config();
        cfg.scopes = vec![];
        let err = GitHubSocialProvider::new(cfg).unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    // ── authorize_url ─────────────────────────────────────────────────────────

    #[test]
    fn authorize_url_contains_required_params() {
        let provider = GitHubSocialProvider::new(github_config()).unwrap();
        let url = provider.authorize_url("https://example.com/callback", "mystate", "mychallenge");
        assert!(url.contains("client_id=test-client-id"), "url: {url}");
        assert!(url.contains("redirect_uri="), "url: {url}");
        assert!(url.contains("state=mystate"), "url: {url}");
        assert!(url.contains("code_challenge=mychallenge"), "url: {url}");
        assert!(url.contains("code_challenge_method=S256"), "url: {url}");
    }

    #[test]
    fn authorize_url_uses_config_scopes_joined_by_space() {
        let provider = GitHubSocialProvider::new(github_config()).unwrap();
        let url = provider.authorize_url("https://example.com/callback", "s", "c");
        assert!(
            url.contains("scope=user%3Aemail") || url.contains("scope=user:email"),
            "url: {url}"
        );
    }

    #[test]
    fn authorize_url_does_not_leak_client_secret() {
        let provider = GitHubSocialProvider::new(github_config()).unwrap();
        let url = provider.authorize_url("https://example.com/callback", "s", "c");
        assert!(!url.contains("test-client-secret"), "url: {url}");
    }

    // ── HTTP tests (wiremock) ─────────────────────────────────────────────────

    async fn setup_server() -> (wiremock::MockServer, String, String) {
        let server = wiremock::MockServer::start().await;
        let oauth_url = server.uri();
        let api_url = server.uri();
        (server, oauth_url, api_url)
    }

    #[tokio::test]
    async fn exchange_code_extracts_access_token_on_success() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let (server, oauth_url, api_url) = setup_server().await;
        Mock::given(method("POST"))
            .and(path("/access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ghs_test_token",
                "token_type": "bearer",
                "scope": "user:email"
            })))
            .mount(&server)
            .await;

        let provider =
            GitHubSocialProvider::new_with_base_urls(github_config(), oauth_url, api_url).unwrap();
        let token = provider
            .exchange_code("mycode", "https://example.com/cb", "v")
            .await
            .unwrap();
        assert_eq!(token, "ghs_test_token");
    }

    #[tokio::test]
    async fn exchange_code_returns_error_when_github_returns_error_field() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let (server, oauth_url, api_url) = setup_server().await;
        Mock::given(method("POST"))
            .and(path("/access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "error": "bad_verification_code",
                "error_description": "The code passed is incorrect or expired."
            })))
            .mount(&server)
            .await;

        let provider =
            GitHubSocialProvider::new_with_base_urls(github_config(), oauth_url, api_url).unwrap();
        let err = provider
            .exchange_code("badcode", "https://example.com/cb", "v")
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::OAuthTokenExchange(_)));
    }

    #[tokio::test]
    async fn exchange_code_returns_error_when_access_token_missing() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let (server, oauth_url, api_url) = setup_server().await;
        Mock::given(method("POST"))
            .and(path("/access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token_type": "bearer"
            })))
            .mount(&server)
            .await;

        let provider =
            GitHubSocialProvider::new_with_base_urls(github_config(), oauth_url, api_url).unwrap();
        let err = provider
            .exchange_code("code", "https://example.com/cb", "v")
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::OAuthTokenExchange(_)));
    }

    #[tokio::test]
    async fn fetch_user_info_combines_user_and_emails_endpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let (server, oauth_url, api_url) = setup_server().await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 42,
                "name": "Test User",
                "avatar_url": "https://avatars.example.com/u/42"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/emails"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"email": "test@example.com", "primary": true, "verified": true}
            ])))
            .mount(&server)
            .await;

        let provider =
            GitHubSocialProvider::new_with_base_urls(github_config(), oauth_url, api_url).unwrap();
        let info = provider.fetch_user_info("token123").await.unwrap();
        assert_eq!(info.provider_user_id, "42");
        assert_eq!(info.email, "test@example.com");
        assert!(info.email_verified);
        assert_eq!(info.name.as_deref(), Some("Test User"));
        assert_eq!(
            info.avatar_url.as_deref(),
            Some("https://avatars.example.com/u/42")
        );
    }

    #[tokio::test]
    async fn fetch_user_info_picks_primary_verified_email_when_multiple() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let (server, oauth_url, api_url) = setup_server().await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 7,
                "name": null,
                "avatar_url": null
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/emails"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"email": "secondary@example.com", "primary": false, "verified": true},
                {"email": "primary@example.com",   "primary": true,  "verified": true},
                {"email": "unverified@example.com","primary": false, "verified": false}
            ])))
            .mount(&server)
            .await;

        let provider =
            GitHubSocialProvider::new_with_base_urls(github_config(), oauth_url, api_url).unwrap();
        let info = provider.fetch_user_info("tok").await.unwrap();
        assert_eq!(info.email, "primary@example.com");
    }

    #[tokio::test]
    async fn fetch_user_info_errors_when_no_primary_verified_email() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let (server, oauth_url, api_url) = setup_server().await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 5, "name": null, "avatar_url": null
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/emails"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"email": "nope@example.com", "primary": true, "verified": false}
            ])))
            .mount(&server)
            .await;

        let provider =
            GitHubSocialProvider::new_with_base_urls(github_config(), oauth_url, api_url).unwrap();
        let err = provider.fetch_user_info("tok").await.unwrap_err();
        assert!(matches!(err, AuthError::OAuthUserInfoFetch(_)));
    }

    #[tokio::test]
    async fn fetch_user_info_propagates_avatar_url() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let (server, oauth_url, api_url) = setup_server().await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 99,
                "name": "Avatar User",
                "avatar_url": "https://cdn.example.com/avatar99.png"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/emails"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"email": "avatar@example.com", "primary": true, "verified": true}
            ])))
            .mount(&server)
            .await;

        let provider =
            GitHubSocialProvider::new_with_base_urls(github_config(), oauth_url, api_url).unwrap();
        let info = provider.fetch_user_info("tok").await.unwrap();
        assert_eq!(
            info.avatar_url.as_deref(),
            Some("https://cdn.example.com/avatar99.png")
        );
    }

    #[tokio::test]
    async fn fetch_user_info_does_not_use_user_email_field() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        // /user returns a public email; /user/emails has a *different* primary email.
        // The impl must use the /user/emails result.
        let (server, oauth_url, api_url) = setup_server().await;
        Mock::given(method("GET"))
            .and(path("/user"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id": 11,
                "name": "Split User",
                "avatar_url": null,
                "email": "public@example.com"
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/user/emails"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
                {"email": "private@example.com", "primary": true, "verified": true}
            ])))
            .mount(&server)
            .await;

        let provider =
            GitHubSocialProvider::new_with_base_urls(github_config(), oauth_url, api_url).unwrap();
        let info = provider.fetch_user_info("tok").await.unwrap();
        assert_eq!(
            info.email, "private@example.com",
            "must use /user/emails, not /user.email"
        );
    }
}
