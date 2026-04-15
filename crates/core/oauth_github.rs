use serde::Deserialize;

use crate::auth_client::AuthFuture;
use crate::error::AuthError;
use crate::oauth::{OAuthProvider, OAuthUserInfo};

/// GitHub OAuth2 provider.
///
/// Implements the authorization code flow with PKCE against GitHub's OAuth endpoints.
/// Requires a GitHub OAuth App with client_id and client_secret.
pub struct GitHubProvider {
    client_id: String,
    client_secret: String,
    client: reqwest::Client,
}

impl GitHubProvider {
    pub fn new(client_id: String, client_secret: String) -> Self {
        let client = reqwest::Client::builder()
            .user_agent("allowthem-oauth")
            .build()
            .expect("failed to build HTTP client");
        Self {
            client_id,
            client_secret,
            client,
        }
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize)]
struct GitHubUser {
    id: i64,
    email: Option<String>,
    name: Option<String>,
}

#[derive(Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

impl OAuthProvider for GitHubProvider {
    fn name(&self) -> &str {
        "github"
    }

    fn authorize_url(&self, redirect_uri: &str, state: &str, pkce_challenge: &str) -> String {
        format!(
            "https://github.com/login/oauth/authorize\
             ?client_id={}\
             &redirect_uri={}\
             &state={}\
             &scope=user:email\
             &code_challenge={}\
             &code_challenge_method=S256",
            self.client_id, redirect_uri, state, pkce_challenge,
        )
    }

    fn exchange_code<'a>(
        &'a self,
        code: &'a str,
        redirect_uri: &'a str,
        pkce_verifier: &'a str,
    ) -> AuthFuture<'a, String> {
        Box::pin(async move {
            let resp = self
                .client
                .post("https://github.com/login/oauth/access_token")
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
                .map_err(|e| AuthError::OAuthHttp(e.to_string()))?;

            let token_resp: TokenResponse = resp
                .json()
                .await
                .map_err(|e| AuthError::OAuthTokenExchange(e.to_string()))?;

            if let Some(err) = token_resp.error {
                let desc = token_resp.error_description.unwrap_or_default();
                return Err(AuthError::OAuthTokenExchange(format!("{err}: {desc}")));
            }

            token_resp
                .access_token
                .ok_or_else(|| AuthError::OAuthTokenExchange("missing access_token".into()))
        })
    }

    fn user_info<'a>(&'a self, access_token: &'a str) -> AuthFuture<'a, OAuthUserInfo> {
        Box::pin(async move {
            let user: GitHubUser = self
                .client
                .get("https://api.github.com/user")
                .bearer_auth(access_token)
                .send()
                .await
                .map_err(|e| AuthError::OAuthHttp(e.to_string()))?
                .json()
                .await
                .map_err(|e| AuthError::OAuthUserInfoFetch(e.to_string()))?;

            // GitHub often returns email: null when the user's email is private.
            // Fall back to the /user/emails endpoint.
            let (email, email_verified) = if let Some(ref e) = user.email {
                // Public email — GitHub only exposes it if the user chose to make it
                // public, which means it is verified.
                (e.clone(), true)
            } else {
                let emails: Vec<GitHubEmail> = self
                    .client
                    .get("https://api.github.com/user/emails")
                    .bearer_auth(access_token)
                    .send()
                    .await
                    .map_err(|e| AuthError::OAuthHttp(e.to_string()))?
                    .json()
                    .await
                    .map_err(|e| AuthError::OAuthUserInfoFetch(e.to_string()))?;

                let primary = emails
                    .iter()
                    .find(|e| e.primary && e.verified)
                    .or_else(|| emails.iter().find(|e| e.verified));

                match primary {
                    Some(entry) => (entry.email.clone(), entry.verified),
                    None => {
                        return Err(AuthError::OAuthUserInfoFetch(
                            "no verified email found on GitHub account".into(),
                        ));
                    }
                }
            };

            Ok(OAuthUserInfo {
                provider_user_id: user.id.to_string(),
                email,
                email_verified,
                name: user.name,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_provider() -> GitHubProvider {
        GitHubProvider::new("test-client-id".into(), "test-secret".into())
    }

    #[test]
    fn name_returns_github() {
        let p = test_provider();
        assert_eq!(p.name(), "github");
    }

    #[test]
    fn authorize_url_contains_required_params() {
        let p = test_provider();
        let url = p.authorize_url(
            "https://example.com/oauth/github/callback",
            "test-state-value",
            "test-challenge-value",
        );

        assert!(url.starts_with("https://github.com/login/oauth/authorize"));
        assert!(url.contains("client_id=test-client-id"));
        assert!(url.contains("redirect_uri=https://example.com/oauth/github/callback"));
        assert!(url.contains("state=test-state-value"));
        assert!(url.contains("code_challenge=test-challenge-value"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("scope=user:email"));
    }

    #[test]
    fn authorize_url_does_not_contain_secret() {
        let p = test_provider();
        let url = p.authorize_url("https://example.com/cb", "state", "challenge");
        assert!(
            !url.contains("test-secret"),
            "authorize URL must never contain client_secret"
        );
    }
}
