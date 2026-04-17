//! allowthem-client: External-mode AuthClient that validates RS256 JWTs
//! locally via JWKS and talks to the allowthem server for code exchange.

mod jwks;

use std::sync::Arc;

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use rand::TryRngCore;
use rand::rngs::OsRng;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use allowthem_core::{
    AuthClient, AuthError, AuthFuture, Email, PermissionName, RoleName, SessionToken, User, UserId,
    Username,
};

use crate::jwks::JwksManager;

// ---------------------------------------------------------------------------
// Internal claims types for JWT deserialization
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct ExternalAccessTokenClaims {
    sub: String,
    #[allow(dead_code)]
    iss: String,
    #[allow(dead_code)]
    aud: String,
    exp: i64,
    iat: i64,
    #[allow(dead_code)]
    scope: String,
    email: String,
    email_verified: bool,
    #[serde(default)]
    username: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    permissions: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct MinimalClaims {
    sub: String,
}

// ---------------------------------------------------------------------------
// Claims cache
// ---------------------------------------------------------------------------

struct CachedClaims {
    roles: Vec<String>,
    permissions: Vec<String>,
    expires_at: i64,
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// PKCE and state for an authorization request.
///
/// The `code_verifier` must be stored (e.g., in a cookie or session)
/// until the callback handler calls `exchange_code`.
pub struct AuthorizeRequest {
    pub code_verifier: String,
    pub state: String,
}

/// Response from the token endpoint after authorization code exchange.
#[derive(Debug, Deserialize)]
pub struct TokenExchangeResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: String,
    pub id_token: String,
}

// ---------------------------------------------------------------------------
// ExternalAuthClient
// ---------------------------------------------------------------------------

struct ExternalAuthClientInner {
    base_url: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    expected_issuer: String,
    session_cookie_name: &'static str,
    http: reqwest::Client,
    jwks: JwksManager,
    claims_cache: DashMap<UserId, CachedClaims>,
    login_url: String,
    scopes: String,
}

/// External-mode AuthClient that validates RS256 JWTs locally
/// and talks to the allowthem server for code exchange.
///
/// Cheap to clone (Arc internals).
#[derive(Clone)]
pub struct ExternalAuthClient {
    inner: Arc<ExternalAuthClientInner>,
}

/// Builder for constructing an `ExternalAuthClient`.
pub struct ExternalAuthClientBuilder {
    base_url: String,
    client_id: String,
    client_secret: String,
    redirect_uri: String,
    login_url: String,
    session_cookie_name: Option<&'static str>,
    scopes: Option<String>,
}

impl ExternalAuthClientBuilder {
    /// Create a builder for an external auth client.
    ///
    /// - `base_url`: allowthem server URL (e.g., `"https://auth.wavefunk.io"`)
    /// - `client_id`: OAuth client ID from the application registry
    /// - `client_secret`: OAuth client secret
    /// - `redirect_uri`: the consuming project's OIDC callback URL
    /// - `login_url`: local path to redirect unauthenticated users (e.g., `"/auth/login"`)
    pub fn new(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        login_url: impl Into<String>,
    ) -> Self {
        Self {
            base_url: base_url.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            login_url: login_url.into(),
            session_cookie_name: None,
            scopes: None,
        }
    }

    /// Override session cookie name. Default: `"allowthem_session"`.
    pub fn cookie_name(mut self, name: &'static str) -> Self {
        self.session_cookie_name = Some(name);
        self
    }

    /// Override requested scopes. Default: `"openid profile email"`.
    pub fn scopes(mut self, scopes: impl Into<String>) -> Self {
        self.scopes = Some(scopes.into());
        self
    }

    /// Build the client. Fetches JWKS on first use, not at build time.
    pub fn build(self) -> ExternalAuthClient {
        let http = reqwest::Client::new();
        let jwks = JwksManager::new(&self.base_url, http.clone());
        let expected_issuer = self.base_url.clone();

        ExternalAuthClient {
            inner: Arc::new(ExternalAuthClientInner {
                base_url: self.base_url,
                client_id: self.client_id,
                client_secret: self.client_secret,
                redirect_uri: self.redirect_uri,
                expected_issuer,
                session_cookie_name: self.session_cookie_name.unwrap_or("allowthem_session"),
                http,
                jwks,
                claims_cache: DashMap::new(),
                login_url: self.login_url,
                scopes: self.scopes.unwrap_or_else(|| "openid profile email".into()),
            }),
        }
    }
}

impl ExternalAuthClient {
    /// Shorthand for `ExternalAuthClientBuilder::new(...)`.
    pub fn builder(
        base_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        login_url: impl Into<String>,
    ) -> ExternalAuthClientBuilder {
        ExternalAuthClientBuilder::new(base_url, client_id, client_secret, redirect_uri, login_url)
    }

    /// Generate PKCE challenge and state for an authorization request.
    ///
    /// Returns the full authorize URL and the `AuthorizeRequest` containing
    /// the `code_verifier` and `state` for later verification.
    pub fn authorize_url(&self) -> (String, AuthorizeRequest) {
        // Generate code_verifier: 32 random bytes, base64url-encoded
        let mut verifier_bytes = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut verifier_bytes)
            .expect("OS RNG unavailable");
        let code_verifier = Base64UrlUnpadded::encode_string(&verifier_bytes);

        // code_challenge = BASE64URL(SHA256(code_verifier))
        let digest = Sha256::digest(code_verifier.as_bytes());
        let code_challenge = Base64UrlUnpadded::encode_string(&digest);

        // Generate state: 32 random bytes, base64url-encoded
        let mut state_bytes = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut state_bytes)
            .expect("OS RNG unavailable");
        let state = Base64UrlUnpadded::encode_string(&state_bytes);

        let url = format!(
            "{}/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&code_challenge={}&code_challenge_method=S256&state={}",
            self.inner.base_url,
            urlencoded(&self.inner.client_id),
            urlencoded(&self.inner.redirect_uri),
            urlencoded(&self.inner.scopes),
            urlencoded(&code_challenge),
            urlencoded(&state),
        );

        (
            url,
            AuthorizeRequest {
                code_verifier,
                state,
            },
        )
    }

    /// Exchange an authorization code for tokens.
    pub async fn exchange_code(
        &self,
        code: &str,
        code_verifier: &str,
        redirect_uri: &str,
    ) -> Result<TokenExchangeResponse, AuthError> {
        let url = format!("{}/oauth/token", self.inner.base_url);

        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("code_verifier", code_verifier),
            ("client_id", &self.inner.client_id),
            ("client_secret", &self.inner.client_secret),
        ];

        let resp = self
            .inner
            .http
            .post(&url)
            .form(&params)
            .send()
            .await
            .map_err(|e| AuthError::OAuthHttp(e.to_string()))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(AuthError::OAuthTokenExchange(format!("{status}: {body}")));
        }

        resp.json::<TokenExchangeResponse>()
            .await
            .map_err(|e| AuthError::OAuthHttp(e.to_string()))
    }
}

// ---------------------------------------------------------------------------
// AuthClient trait implementation
// ---------------------------------------------------------------------------

impl AuthClient for ExternalAuthClient {
    fn validate_session<'a>(&'a self, token: &'a SessionToken) -> AuthFuture<'a, Option<User>> {
        Box::pin(async move {
            let jwt = token.as_str();

            // 1. Decode header for kid
            let header = match jsonwebtoken::decode_header(jwt) {
                Ok(h) => h,
                Err(_) => return Ok(None),
            };
            let kid = match header.kid {
                Some(k) => k,
                None => return Ok(None),
            };

            // 2. Get decoding key from JWKS cache
            let decoding_key = match self.inner.jwks.get_decoding_key(&kid).await {
                Ok(Some(key)) => key,
                Ok(None) => return Ok(None),
                Err(e) => return Err(e),
            };

            // 3. Validate JWT — check iss, aud, exp
            let mut validation = Validation::new(Algorithm::RS256);
            validation.set_issuer(&[&self.inner.expected_issuer]);
            validation.set_audience(&[&self.inner.client_id]);
            validation.leeway = 0;

            let token_data = match jsonwebtoken::decode::<ExternalAccessTokenClaims>(
                jwt,
                &decoding_key,
                &validation,
            ) {
                Ok(td) => td,
                Err(_) => return Ok(None),
            };

            let claims = token_data.claims;

            // 4. Parse sub as UserId
            let sub_uuid = match Uuid::parse_str(&claims.sub) {
                Ok(u) => u,
                Err(_) => return Ok(None),
            };
            let user_id = UserId::from_uuid(sub_uuid);

            // 5. Build User from claims
            let email = match Email::new(claims.email) {
                Ok(e) => e,
                Err(_) => return Ok(None),
            };
            let ts = DateTime::from_timestamp(claims.iat, 0).unwrap_or_else(Utc::now);
            let user = User {
                id: user_id,
                email,
                username: claims.username.map(Username::new),
                password_hash: None,
                email_verified: claims.email_verified,
                is_active: true,
                created_at: ts,
                updated_at: ts,
            };

            // 6. Cache claims for check_role/check_permission
            self.inner.claims_cache.insert(
                user_id,
                CachedClaims {
                    roles: claims.roles,
                    permissions: claims.permissions,
                    expires_at: claims.exp,
                },
            );

            Ok(Some(user))
        })
    }

    fn check_role<'a>(&'a self, user_id: &'a UserId, role: &'a RoleName) -> AuthFuture<'a, bool> {
        Box::pin(async move {
            let now = Utc::now().timestamp();
            match self.inner.claims_cache.get(user_id) {
                Some(cached) if cached.expires_at > now => {
                    Ok(cached.roles.iter().any(|r| r == role.as_str()))
                }
                _ => Ok(false),
            }
        })
    }

    fn check_permission<'a>(
        &'a self,
        user_id: &'a UserId,
        permission: &'a PermissionName,
    ) -> AuthFuture<'a, bool> {
        Box::pin(async move {
            let now = Utc::now().timestamp();
            match self.inner.claims_cache.get(user_id) {
                Some(cached) if cached.expires_at > now => {
                    Ok(cached.permissions.iter().any(|p| p == permission.as_str()))
                }
                _ => Ok(false),
            }
        })
    }

    fn resolve_highest_role<'a>(
        &'a self,
        user_id: &'a UserId,
        hierarchy: &'a [&str],
    ) -> AuthFuture<'a, Option<String>> {
        Box::pin(async move {
            let now = Utc::now().timestamp();
            match self.inner.claims_cache.get(user_id) {
                Some(cached) if cached.expires_at > now => {
                    for &name in hierarchy {
                        if cached.roles.iter().any(|r| r == name) {
                            return Ok(Some(name.to_owned()));
                        }
                    }
                    Ok(None)
                }
                _ => Ok(None),
            }
        })
    }

    fn logout<'a>(&'a self, token: &'a SessionToken) -> AuthFuture<'a, ()> {
        Box::pin(async move {
            let jwt = token.as_str();
            // Decode without signature verification to extract sub
            let mut insecure = Validation::new(Algorithm::RS256);
            insecure.insecure_disable_signature_validation();
            insecure.validate_aud = false;
            insecure.validate_exp = false;
            if let Ok(data) = jsonwebtoken::decode::<MinimalClaims>(
                jwt,
                &DecodingKey::from_secret(&[]),
                &insecure,
            ) && let Ok(uuid) = Uuid::parse_str(&data.claims.sub)
            {
                self.inner.claims_cache.remove(&UserId::from_uuid(uuid));
            }
            Ok(())
        })
    }

    fn login_url(&self) -> &str {
        &self.inner.login_url
    }

    fn session_cookie_name(&self) -> &str {
        self.inner.session_cookie_name
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Minimal URL encoding for query parameters.
fn urlencoded(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "%20")
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace('+', "%2B")
        .replace('/', "%2F")
        .replace(':', "%3A")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_builder() -> ExternalAuthClient {
        ExternalAuthClient::builder(
            "https://auth.example.com",
            "ath_test_client",
            "test_secret",
            "https://myapp.example.com/callback",
            "/auth/login",
        )
        .build()
    }

    #[test]
    fn builder_defaults() {
        let client = test_builder();
        assert_eq!(client.session_cookie_name(), "allowthem_session");
        assert_eq!(client.login_url(), "/auth/login");
    }

    #[test]
    fn builder_overrides() {
        let client = ExternalAuthClient::builder(
            "https://auth.example.com",
            "ath_test",
            "secret",
            "https://app.example.com/cb",
            "/login",
        )
        .cookie_name("my_session")
        .scopes("openid")
        .build();

        assert_eq!(client.session_cookie_name(), "my_session");
        assert_eq!(client.inner.scopes, "openid");
    }

    #[test]
    fn authorize_url_contains_pkce() {
        let client = test_builder();
        let (url, req) = client.authorize_url();
        assert!(url.contains("code_challenge="));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("state="));
        assert!(!req.code_verifier.is_empty());
        assert!(!req.state.is_empty());
    }

    #[test]
    fn authorize_url_unique_per_call() {
        let client = test_builder();
        let (_, req1) = client.authorize_url();
        let (_, req2) = client.authorize_url();
        assert_ne!(req1.code_verifier, req2.code_verifier);
        assert_ne!(req1.state, req2.state);
    }

    #[test]
    fn clone_is_cheap() {
        let client = test_builder();
        let _clone = client.clone();
    }
}
