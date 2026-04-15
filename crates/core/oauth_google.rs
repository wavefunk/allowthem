use serde::Deserialize;
use url::Url;

use crate::auth_client::AuthFuture;
use crate::error::AuthError;
use crate::oauth::{OAuthProvider, OAuthUserInfo};

// ---------------------------------------------------------------------------
// GoogleProvider
// ---------------------------------------------------------------------------

/// OAuth2 authorization-code + PKCE provider for Google.
pub struct GoogleProvider {
    client_id: String,
    client_secret: String,
    http: reqwest::Client,
}

impl GoogleProvider {
    pub fn new(client_id: impl Into<String>, client_secret: impl Into<String>) -> Self {
        Self {
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            http: reqwest::Client::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Response shapes
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct UserInfoResponse {
    sub: String,
    email: String,
    email_verified: bool,
    name: Option<String>,
}

// ---------------------------------------------------------------------------
// OAuthProvider impl
// ---------------------------------------------------------------------------

impl OAuthProvider for GoogleProvider {
    fn name(&self) -> &str {
        "google"
    }

    fn authorize_url(&self, redirect_uri: &str, state: &str, pkce_challenge: &str) -> String {
        let mut url =
            Url::parse("https://accounts.google.com/o/oauth2/v2/auth").expect("static URL");
        url.query_pairs_mut()
            .append_pair("client_id", &self.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("response_type", "code")
            .append_pair("scope", "openid email profile")
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
                .post("https://oauth2.googleapis.com/token")
                .form(&[
                    ("code", code),
                    ("client_id", &self.client_id),
                    ("client_secret", &self.client_secret),
                    ("redirect_uri", redirect_uri),
                    ("grant_type", "authorization_code"),
                    ("code_verifier", pkce_verifier),
                ])
                .send()
                .await
                .map_err(|e| AuthError::OAuthHttp(e.to_string()))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(AuthError::OAuthTokenExchange(format!("{status}: {body}")));
            }

            let token: TokenResponse = resp
                .json()
                .await
                .map_err(|e| AuthError::OAuthTokenExchange(e.to_string()))?;

            Ok(token.access_token)
        })
    }

    fn user_info<'a>(&'a self, access_token: &'a str) -> AuthFuture<'a, OAuthUserInfo> {
        Box::pin(async move {
            let resp = self
                .http
                .get("https://www.googleapis.com/oauth2/v3/userinfo")
                .bearer_auth(access_token)
                .send()
                .await
                .map_err(|e| AuthError::OAuthHttp(e.to_string()))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(AuthError::OAuthUserInfoFetch(format!("{status}: {body}")));
            }

            let info: UserInfoResponse = resp
                .json()
                .await
                .map_err(|e| AuthError::OAuthUserInfoFetch(e.to_string()))?;

            Ok(OAuthUserInfo {
                provider_user_id: info.sub,
                email: info.email,
                email_verified: info.email_verified,
                name: info.name,
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_provider() -> GoogleProvider {
        GoogleProvider::new("test-client-id", "test-client-secret")
    }

    #[test]
    fn name_returns_google() {
        assert_eq!(make_provider().name(), "google");
    }

    #[test]
    fn authorize_url_contains_required_params() {
        let p = make_provider();
        let url = p.authorize_url("https://example.com/callback", "state-abc", "challenge-xyz");

        assert!(url.contains("client_id=test-client-id"), "client_id");
        assert!(
            url.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"),
            "redirect_uri encoded"
        );
        assert!(url.contains("response_type=code"), "response_type");
        assert!(
            url.contains("scope=openid+email+profile")
                || url.contains("scope=openid%20email%20profile"),
            "scope"
        );
        assert!(url.contains("state=state-abc"), "state");
        assert!(
            url.contains("code_challenge=challenge-xyz"),
            "code_challenge"
        );
        assert!(url.contains("code_challenge_method=S256"), "method");
    }

    #[test]
    fn authorize_url_starts_with_google_endpoint() {
        let p = make_provider();
        let url = p.authorize_url("https://example.com/cb", "s", "c");
        assert!(
            url.starts_with("https://accounts.google.com/o/oauth2/v2/auth"),
            "unexpected base: {url}"
        );
    }

    #[test]
    fn new_accepts_string_and_str() {
        let _p1 = GoogleProvider::new("id".to_string(), "secret".to_string());
        let _p2 = GoogleProvider::new("id", "secret");
    }
}
