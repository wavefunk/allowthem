//! Custom OIDC `SocialProvider` implementation.
//!
//! Constructed from a `SocialProviderConfig` whose `config` JSON object carries
//! either a `discovery_url` (auto-discover all three endpoints) or explicit
//! `authorize_url`, `token_url`, `userinfo_url` fields.
//!
//! When both `discovery_url` and explicit endpoints are present, the explicit
//! endpoints win and a `tracing::debug!` is emitted.
//!
//! Discovery documents are cached per provider instance with a [`DISCOVERY_TTL`]
//! TTL and lazily refreshed inside async trait methods. The cache uses
//! `std::sync::RwLock` (not `tokio::sync::RwLock`) so the synchronous
//! `authorize_url` trait method can read it without a blocking-context contract.
//!
//! ## Email requirement
//!
//! The OIDC core spec does not mandate the `email` claim. This implementation
//! **does** require it — `fetch_user_info` returns `AuthError::OAuthUserInfoFetch`
//! when `email` is absent from the userinfo response, because the downstream
//! account-linking flow needs an email address.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use serde::Deserialize;
use url::Url;

use crate::auth_client::AuthFuture;
use crate::error::AuthError;
use crate::social_providers::{ProviderType, SocialProvider, SocialProviderConfig, SocialUserInfo};

/// TTL for cached OIDC discovery documents.
///
/// After this duration, the next `exchange_code` or `fetch_user_info` call
/// will re-fetch the discovery document. `authorize_url` (sync) reads the
/// cached doc regardless of staleness — TTL refresh is not possible inside a
/// sync method.
pub const DISCOVERY_TTL: Duration = Duration::from_secs(60 * 60); // 1 hour

// ── Discovery document ────────────────────────────────────────────────────────

/// Parsed OIDC discovery document. Only the three endpoints this impl uses are
/// required; everything else in the JSON is ignored.
///
/// Maps from the wire names (`authorization_endpoint`, `token_endpoint`,
/// `userinfo_endpoint`) to shorter, idiomatic field names.
#[derive(Debug, Clone)]
pub struct DiscoveryDoc {
    pub authorize_url: String,
    pub token_url: String,
    pub userinfo_url: String,
}

/// Raw deserialization target for the `.well-known/openid-configuration` body.
///
/// Uses the exact field names from OpenID Connect Discovery 1.0 § 4.
#[derive(Deserialize)]
struct DiscoveryDocRaw {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
}

impl From<DiscoveryDocRaw> for DiscoveryDoc {
    fn from(raw: DiscoveryDocRaw) -> Self {
        Self {
            authorize_url: raw.authorization_endpoint,
            token_url: raw.token_endpoint,
            userinfo_url: raw.userinfo_endpoint,
        }
    }
}

// ── Discovery cache (private) ─────────────────────────────────────────────────

/// Per-instance cache of a fetched discovery document plus its fetch timestamp.
///
/// Wrapped in a `std::sync::RwLock` on the provider struct. The lock is held
/// only for a short swap; HTTP I/O happens outside any held lock.
#[derive(Debug)]
struct DiscoveryCache {
    doc: DiscoveryDoc,
    refreshed_at: Instant,
}

// ── Config parsing helpers ────────────────────────────────────────────────────

/// Internal representation after parsing `SocialProviderConfig::config`.
#[derive(Debug)]
enum CustomOidcEndpoints {
    /// Fetch all three endpoints via OIDC discovery.
    Discovery(String),
    /// Use caller-supplied endpoint URLs directly.
    Pinned(DiscoveryDoc),
}

fn parse_custom_oidc_config(
    value: Option<&serde_json::Value>,
) -> Result<CustomOidcEndpoints, AuthError> {
    let val = value
        .ok_or_else(|| AuthError::Validation("custom_oidc requires a config object".into()))?;

    let obj = val
        .as_object()
        .ok_or_else(|| AuthError::Validation("custom_oidc config must be a JSON object".into()))?;

    let discovery_url = get_opt_str(obj, "discovery_url")?;
    let authorize_url = get_opt_str(obj, "authorize_url")?;
    let token_url = get_opt_str(obj, "token_url")?;
    let userinfo_url = get_opt_str(obj, "userinfo_url")?;

    let has_explicit = authorize_url.is_some() || token_url.is_some() || userinfo_url.is_some();

    if has_explicit {
        // All three explicit endpoints must be present.
        let authorize = authorize_url.ok_or_else(|| {
            AuthError::Validation("missing one of authorize_url/token_url/userinfo_url".into())
        })?;
        let token = token_url.ok_or_else(|| {
            AuthError::Validation("missing one of authorize_url/token_url/userinfo_url".into())
        })?;
        let userinfo = userinfo_url.ok_or_else(|| {
            AuthError::Validation("missing one of authorize_url/token_url/userinfo_url".into())
        })?;

        validate_url(authorize, "authorize_url")?;
        validate_url(token, "token_url")?;
        validate_url(userinfo, "userinfo_url")?;

        if discovery_url.is_some() {
            tracing::debug!("custom_oidc: explicit endpoints override discovery_url");
        }

        return Ok(CustomOidcEndpoints::Pinned(DiscoveryDoc {
            authorize_url: authorize.to_owned(),
            token_url: token.to_owned(),
            userinfo_url: userinfo.to_owned(),
        }));
    }

    // No explicit endpoints — require discovery_url.
    let discovery = discovery_url.ok_or_else(|| {
        AuthError::Validation(
            "custom_oidc config requires either discovery_url or all of \
             authorize_url/token_url/userinfo_url"
                .into(),
        )
    })?;

    validate_url(discovery, "discovery_url")?;

    Ok(CustomOidcEndpoints::Discovery(discovery.to_owned()))
}

fn get_opt_str<'a>(
    obj: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<&'a str>, AuthError> {
    match obj.get(field) {
        None => Ok(None),
        Some(v) => v
            .as_str()
            .ok_or_else(|| AuthError::Validation(format!("{field} must be a string")))
            .map(Some),
    }
}

fn validate_url(url: &str, field: &str) -> Result<(), AuthError> {
    Url::parse(url)
        .map(|_| ())
        .map_err(|_| AuthError::Validation(format!("{field} is not a valid URL")))
}

// ── UserInfo claims ───────────────────────────────────────────────────────────

/// Raw claims from the OIDC `/userinfo` endpoint.
///
/// Standard OIDC claim names are preferred; non-standard alternates are
/// checked for `name` (`preferred_username`, `nickname`) and `avatar_url`
/// (`picture`, `avatar_url`). Any field not listed here is ignored.
#[derive(Deserialize)]
struct UserInfoClaims {
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    preferred_username: Option<String>,
    nickname: Option<String>,
    picture: Option<String>,
    avatar_url: Option<String>,
}

fn map_user_info(claims: UserInfoClaims) -> Result<SocialUserInfo, AuthError> {
    let email = claims
        .email
        .ok_or_else(|| AuthError::OAuthUserInfoFetch("userinfo missing email".into()))?;
    let name = claims
        .name
        .or(claims.preferred_username)
        .or(claims.nickname);
    let avatar_url = claims.picture.or(claims.avatar_url);
    Ok(SocialUserInfo {
        provider_user_id: claims.sub,
        email,
        email_verified: claims.email_verified.unwrap_or(false),
        name,
        avatar_url,
    })
}

// ── Struct ────────────────────────────────────────────────────────────────────

/// Generic OIDC-compliant social provider.
///
/// Supports any IdP that publishes an OIDC discovery document or accepts
/// explicit `authorize_url` / `token_url` / `userinfo_url` configuration.
///
/// Exactly one of `discovery` / `pinned_endpoints` is `Some` after
/// construction; the other is always `None`.
pub struct CustomOidcSocialProvider {
    client_id: String,
    client_secret: String,
    scopes: Vec<String>,
    http: reqwest::Client,

    /// `Some(_)` when constructed from `discovery_url`; the lock holds
    /// the most-recently-fetched doc plus its `refreshed_at`.
    ///
    /// Uses `std::sync::RwLock`, not `tokio::sync::RwLock`, so
    /// `authorize_url` (sync) can read the cache without a
    /// blocking-context contract. Lock contention is bounded to the swap;
    /// HTTP I/O happens outside any held lock.
    discovery: Option<RwLock<DiscoveryCache>>,

    /// `Some(_)` when constructed from explicit endpoints. Mutually
    /// exclusive with `discovery`.
    pinned_endpoints: Option<DiscoveryDoc>,

    /// Original discovery URL; used to refresh the cache. `None` when
    /// `pinned_endpoints` is set.
    discovery_url: Option<String>,

    /// How long a cached discovery document is considered fresh.
    /// Defaults to [`DISCOVERY_TTL`]; overrideable in tests.
    ttl: Duration,
}

// ── Debug (redacts client_secret) ────────────────────────────────────────────

impl std::fmt::Debug for CustomOidcSocialProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CustomOidcSocialProvider")
            .field("client_id", &self.client_id)
            .field("client_secret", &"[redacted]")
            .field("scopes", &self.scopes)
            .field("discovery_url", &self.discovery_url)
            .field("ttl", &self.ttl)
            .finish_non_exhaustive()
    }
}

// ── Constructor + internal helpers ────────────────────────────────────────────

impl CustomOidcSocialProvider {
    /// Build a `CustomOidcSocialProvider` from a decrypted config.
    ///
    /// For the `discovery_url` path this performs one HTTP round-trip to
    /// fetch the discovery document. The HTTP client is built with a
    /// 15-second timeout and a `User-Agent: allowthem-oauth` header.
    ///
    /// Returns `AuthError::Validation` for config problems;
    /// `AuthError::OAuthHttp` for discovery-fetch failures.
    pub async fn new(config: SocialProviderConfig) -> Result<Self, AuthError> {
        if config.provider_type != ProviderType::CustomOidc {
            return Err(AuthError::Validation(
                "provider_type mismatch: expected CustomOidc".into(),
            ));
        }
        if config.scopes.is_empty() {
            return Err(AuthError::Validation("scopes must not be empty".into()));
        }

        let endpoints = parse_custom_oidc_config(config.config.as_ref())?;

        let http = reqwest::Client::builder()
            .user_agent("allowthem-oauth")
            .timeout(Duration::from_secs(15))
            .build()
            .map_err(|e| AuthError::Validation(format!("reqwest client build failed: {e}")))?;

        match endpoints {
            CustomOidcEndpoints::Discovery(url) => {
                let doc = fetch_discovery(&http, &url).await?;
                let cache = RwLock::new(DiscoveryCache {
                    doc,
                    refreshed_at: Instant::now(),
                });
                Ok(Self {
                    client_id: config.client_id,
                    client_secret: config.client_secret,
                    scopes: config.scopes,
                    http,
                    discovery: Some(cache),
                    pinned_endpoints: None,
                    discovery_url: Some(url),
                    ttl: DISCOVERY_TTL,
                })
            }
            CustomOidcEndpoints::Pinned(doc) => Ok(Self {
                client_id: config.client_id,
                client_secret: config.client_secret,
                scopes: config.scopes,
                http,
                discovery: None,
                pinned_endpoints: Some(doc),
                discovery_url: None,
                ttl: DISCOVERY_TTL,
            }),
        }
    }

    /// Return the current discovery endpoints, refreshing the cache if
    /// the TTL has elapsed.
    ///
    /// On refresh failure the stale endpoints are returned and a
    /// `tracing::warn!` is emitted — better to attempt the downstream call
    /// with old endpoints than to fail outright.
    async fn current_endpoints(&self) -> Result<DiscoveryDoc, AuthError> {
        if let Some(ref doc) = self.pinned_endpoints {
            return Ok(doc.clone());
        }

        let lock = self
            .discovery
            .as_ref()
            .expect("discovery cache populated by new()");

        // Clone snapshot under a short read-lock; drop the guard before any await.
        let (doc, refreshed_at) = {
            let g = lock.read().unwrap();
            (g.doc.clone(), g.refreshed_at)
        };

        if refreshed_at.elapsed() > self.ttl {
            let url = self
                .discovery_url
                .as_deref()
                .expect("discovery_url set whenever discovery cache is set");
            match fetch_discovery(&self.http, url).await {
                Ok(new_doc) => {
                    let mut g = lock.write().unwrap();
                    *g = DiscoveryCache {
                        doc: new_doc.clone(),
                        refreshed_at: Instant::now(),
                    };
                    return Ok(new_doc);
                }
                Err(e) => {
                    tracing::warn!(
                        "custom_oidc: discovery refresh failed: {e}; serving stale endpoints"
                    );
                }
            }
        }

        Ok(doc)
    }

    /// Return the cached endpoints synchronously.
    ///
    /// Used by `authorize_url` which cannot `.await`. Returns the cached
    /// endpoint regardless of staleness — TTL refresh is not possible in a
    /// sync method.
    ///
    /// # Panics
    ///
    /// Panics on an internal invariant violation: `new()` always populates
    /// exactly one of `pinned_endpoints` / `discovery`.
    fn cached_endpoints_or_fail(&self) -> DiscoveryDoc {
        if let Some(ref doc) = self.pinned_endpoints {
            return doc.clone();
        }
        self.discovery
            .as_ref()
            .expect("discovery cache populated by new()")
            .read()
            .unwrap()
            .doc
            .clone()
    }

    /// Override the discovery TTL. Only available in `#[cfg(test)]`.
    #[cfg(test)]
    pub(crate) fn set_discovery_ttl(&mut self, ttl: Duration) {
        self.ttl = ttl;
    }
}

// ── Discovery fetch helper ────────────────────────────────────────────────────

async fn fetch_discovery(http: &reqwest::Client, url: &str) -> Result<DiscoveryDoc, AuthError> {
    let resp = http
        .get(url)
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|e| AuthError::OAuthHttp(format!("discovery fetch failed: {e}")))?;

    let status = resp.status();
    if !status.is_success() {
        return Err(AuthError::OAuthHttp(format!("discovery fetch {status}")));
    }

    // Parse to serde_json::Value first so field-missing errors map to
    // AuthError::Validation (per spec: all three endpoints are required).
    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| AuthError::OAuthHttp(format!("discovery fetch JSON parse failed: {e}")))?;

    let obj = json
        .as_object()
        .ok_or_else(|| AuthError::OAuthHttp("discovery document is not a JSON object".into()))?;

    let authorize_url = obj
        .get("authorization_endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            AuthError::Validation("discovery doc is missing authorization_endpoint".into())
        })?
        .to_owned();

    let token_url = obj
        .get("token_endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::Validation("discovery doc is missing token_endpoint".into()))?
        .to_owned();

    let userinfo_url = obj
        .get("userinfo_endpoint")
        .and_then(|v| v.as_str())
        .ok_or_else(|| AuthError::Validation("discovery doc is missing userinfo_endpoint".into()))?
        .to_owned();

    Ok(DiscoveryDoc {
        authorize_url,
        token_url,
        userinfo_url,
    })
}

// ── SocialProvider impl ───────────────────────────────────────────────────────

impl SocialProvider for CustomOidcSocialProvider {
    fn provider_type(&self) -> ProviderType {
        ProviderType::CustomOidc
    }

    /// Build the OIDC authorization redirect URL.
    ///
    /// Reads from the cached discovery doc (sync read-lock). The cache is
    /// always populated by `new()`, so the doc may be stale if the IdP
    /// rotated endpoints after the last refresh, but endpoint rotation within
    /// a single TTL window is an IdP misconfiguration, not a normal event.
    fn authorize_url(&self, redirect_uri: &str, state: &str, pkce_challenge: &str) -> String {
        let endpoints = self.cached_endpoints_or_fail();
        let mut url = Url::parse(&endpoints.authorize_url)
            .expect("authorize_url is a valid URL — validated in new()");
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
            let endpoints = self.current_endpoints().await?;
            let resp = self
                .http
                .post(&endpoints.token_url)
                .header("Accept", "application/json")
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

            json.get("access_token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_owned())
                .ok_or_else(|| {
                    AuthError::OAuthTokenExchange("token response missing access_token".into())
                })
        })
    }

    fn fetch_user_info<'a>(&'a self, access_token: &'a str) -> AuthFuture<'a, SocialUserInfo> {
        Box::pin(async move {
            let endpoints = self.current_endpoints().await?;
            let resp = self
                .http
                .get(&endpoints.userinfo_url)
                .bearer_auth(access_token)
                .send()
                .await
                .map_err(|e| AuthError::OAuthHttp(format!("{e}")))?;

            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                return Err(AuthError::OAuthUserInfoFetch(format!("{status}: {body}")));
            }

            let claims: UserInfoClaims = resp.json().await.map_err(|e| {
                AuthError::OAuthUserInfoFetch(format!("userinfo parse failed: {e}"))
            })?;

            map_user_info(claims)
        })
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::SocialProviderId;

    // ── Test helpers ──────────────────────────────────────────────────────────

    fn pinned_config() -> SocialProviderConfig {
        SocialProviderConfig {
            id: SocialProviderId::new(),
            provider_type: ProviderType::CustomOidc,
            display_name: "Test OIDC".into(),
            client_id: "test-client-id".into(),
            client_secret: "test-client-secret".into(),
            scopes: vec!["openid".into(), "email".into()],
            enabled: true,
            priority: 0,
            config: Some(serde_json::json!({
                "authorize_url": "https://idp.example.com/authorize",
                "token_url": "https://idp.example.com/token",
                "userinfo_url": "https://idp.example.com/userinfo",
            })),
        }
    }

    fn discovery_config(discovery_url: &str) -> SocialProviderConfig {
        SocialProviderConfig {
            id: SocialProviderId::new(),
            provider_type: ProviderType::CustomOidc,
            display_name: "Test OIDC".into(),
            client_id: "test-client-id".into(),
            client_secret: "test-client-secret".into(),
            scopes: vec!["openid".into(), "email".into()],
            enabled: true,
            priority: 0,
            config: Some(serde_json::json!({ "discovery_url": discovery_url })),
        }
    }

    async fn mount_discovery_doc(server: &wiremock::MockServer) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorization_endpoint": format!("{base}/authorize"),
                "token_endpoint": format!("{base}/token"),
                "userinfo_endpoint": format!("{base}/userinfo"),
            })))
            .mount(server)
            .await;
    }

    // ── DiscoveryDoc / DiscoveryDocRaw ─────────────────────────────────────────

    #[test]
    fn discovery_doc_from_raw_renames_endpoints() {
        let raw = DiscoveryDocRaw {
            authorization_endpoint: "https://idp.example.com/authorize".to_owned(),
            token_endpoint: "https://idp.example.com/token".to_owned(),
            userinfo_endpoint: "https://idp.example.com/userinfo".to_owned(),
        };
        let doc = DiscoveryDoc::from(raw);
        assert_eq!(doc.authorize_url, "https://idp.example.com/authorize");
        assert_eq!(doc.token_url, "https://idp.example.com/token");
        assert_eq!(doc.userinfo_url, "https://idp.example.com/userinfo");
    }

    // ── Constructor validation ────────────────────────────────────────────────

    #[tokio::test]
    async fn new_rejects_provider_type_mismatch() {
        let mut cfg = pinned_config();
        cfg.provider_type = ProviderType::Google;
        let err = CustomOidcSocialProvider::new(cfg).await.unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    #[tokio::test]
    async fn new_rejects_empty_scopes() {
        let mut cfg = pinned_config();
        cfg.scopes = vec![];
        let err = CustomOidcSocialProvider::new(cfg).await.unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    // ── parse_custom_oidc_config ───────────────────────────────────────────────

    #[test]
    fn parse_config_rejects_none() {
        let err = parse_custom_oidc_config(None).unwrap_err();
        assert!(matches!(err, AuthError::Validation(ref m) if m.contains("requires a config")));
    }

    #[test]
    fn parse_config_rejects_empty_object() {
        let v = serde_json::json!({});
        let err = parse_custom_oidc_config(Some(&v)).unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    #[test]
    fn parse_config_rejects_partial_explicit_endpoints() {
        let v = serde_json::json!({
            "authorize_url": "https://idp.example.com/authorize",
            "token_url": "https://idp.example.com/token",
            // missing userinfo_url
        });
        let err = parse_custom_oidc_config(Some(&v)).unwrap_err();
        assert!(matches!(err, AuthError::Validation(ref m) if m.contains("missing one of")));
    }

    #[test]
    fn parse_config_rejects_invalid_url() {
        let v = serde_json::json!({
            "authorize_url": "not-a-url",
            "token_url": "https://idp.example.com/token",
            "userinfo_url": "https://idp.example.com/userinfo",
        });
        let err = parse_custom_oidc_config(Some(&v)).unwrap_err();
        assert!(matches!(err, AuthError::Validation(ref m) if m.contains("not a valid URL")));
    }

    #[test]
    fn parse_config_pinned_endpoints_path() {
        let v = serde_json::json!({
            "authorize_url": "https://idp.example.com/authorize",
            "token_url": "https://idp.example.com/token",
            "userinfo_url": "https://idp.example.com/userinfo",
        });
        let result = parse_custom_oidc_config(Some(&v)).unwrap();
        assert!(matches!(result, CustomOidcEndpoints::Pinned(_)));
    }

    #[test]
    fn parse_config_discovery_path() {
        let v = serde_json::json!({
            "discovery_url": "https://idp.example.com/.well-known/openid-configuration",
        });
        let result = parse_custom_oidc_config(Some(&v)).unwrap();
        assert!(matches!(result, CustomOidcEndpoints::Discovery(_)));
    }

    #[test]
    fn parse_config_explicit_overrides_discovery() {
        let v = serde_json::json!({
            "discovery_url": "https://idp.example.com/.well-known/openid-configuration",
            "authorize_url": "https://idp.example.com/authorize",
            "token_url": "https://idp.example.com/token",
            "userinfo_url": "https://idp.example.com/userinfo",
        });
        // Explicit endpoints win; result is Pinned, not Discovery.
        let result = parse_custom_oidc_config(Some(&v)).unwrap();
        assert!(matches!(result, CustomOidcEndpoints::Pinned(_)));
    }

    #[test]
    fn parse_config_partial_explicit_with_discovery_url_still_errors() {
        // discovery_url + only two explicit fields → explicit wins path → missing
        // one error, not a silent fallback to discovery.
        let v = serde_json::json!({
            "discovery_url": "https://idp.example.com/.well-known/openid-configuration",
            "authorize_url": "https://idp.example.com/authorize",
            "token_url": "https://idp.example.com/token",
            // missing userinfo_url
        });
        let err = parse_custom_oidc_config(Some(&v)).unwrap_err();
        assert!(matches!(err, AuthError::Validation(ref m) if m.contains("missing one of")));
    }

    // ── authorize_url ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn authorize_url_includes_required_params() {
        let provider = CustomOidcSocialProvider::new(pinned_config())
            .await
            .unwrap();
        let url =
            provider.authorize_url("https://app.example.com/callback", "mystate", "mychallenge");
        assert!(url.contains("client_id=test-client-id"), "url: {url}");
        assert!(url.contains("redirect_uri="), "url: {url}");
        assert!(url.contains("response_type=code"), "url: {url}");
        assert!(url.contains("state=mystate"), "url: {url}");
        assert!(url.contains("code_challenge=mychallenge"), "url: {url}");
        assert!(url.contains("code_challenge_method=S256"), "url: {url}");
    }

    #[tokio::test]
    async fn authorize_url_uses_config_scopes_joined_by_space() {
        let provider = CustomOidcSocialProvider::new(pinned_config())
            .await
            .unwrap();
        let url = provider.authorize_url("https://app.example.com/callback", "s", "c");
        // url crate percent-encodes spaces as + or %20 in query values
        assert!(
            url.contains("scope=openid+email") || url.contains("scope=openid%20email"),
            "url: {url}"
        );
    }

    // ── UserInfo claim mapping ────────────────────────────────────────────────

    #[test]
    fn userinfo_claim_mapping_uses_name_when_present() {
        let claims = UserInfoClaims {
            sub: "u1".into(),
            email: Some("u@example.com".into()),
            email_verified: Some(true),
            name: Some("Alice Smith".into()),
            preferred_username: Some("alice".into()),
            nickname: Some("al".into()),
            picture: None,
            avatar_url: None,
        };
        let info = map_user_info(claims).unwrap();
        assert_eq!(info.name.as_deref(), Some("Alice Smith"));
    }

    #[test]
    fn userinfo_claim_mapping_falls_back_to_preferred_username() {
        let claims = UserInfoClaims {
            sub: "u1".into(),
            email: Some("u@example.com".into()),
            email_verified: None,
            name: None,
            preferred_username: Some("alice".into()),
            nickname: Some("al".into()),
            picture: None,
            avatar_url: None,
        };
        let info = map_user_info(claims).unwrap();
        assert_eq!(info.name.as_deref(), Some("alice"));
    }

    #[test]
    fn userinfo_claim_mapping_falls_back_to_nickname() {
        let claims = UserInfoClaims {
            sub: "u1".into(),
            email: Some("u@example.com".into()),
            email_verified: None,
            name: None,
            preferred_username: None,
            nickname: Some("al".into()),
            picture: None,
            avatar_url: None,
        };
        let info = map_user_info(claims).unwrap();
        assert_eq!(info.name.as_deref(), Some("al"));
    }

    #[test]
    fn userinfo_claim_mapping_avatar_falls_back_to_avatar_url() {
        let claims = UserInfoClaims {
            sub: "u1".into(),
            email: Some("u@example.com".into()),
            email_verified: None,
            name: None,
            preferred_username: None,
            nickname: None,
            picture: None,
            avatar_url: Some("https://cdn.example.com/u1.png".into()),
        };
        let info = map_user_info(claims).unwrap();
        assert_eq!(
            info.avatar_url.as_deref(),
            Some("https://cdn.example.com/u1.png")
        );
    }

    #[test]
    fn userinfo_email_verified_defaults_to_false_when_absent() {
        let claims = UserInfoClaims {
            sub: "u1".into(),
            email: Some("u@example.com".into()),
            email_verified: None,
            name: None,
            preferred_username: None,
            nickname: None,
            picture: None,
            avatar_url: None,
        };
        let info = map_user_info(claims).unwrap();
        assert!(!info.email_verified);
    }

    #[test]
    fn userinfo_missing_email_returns_error() {
        let claims = UserInfoClaims {
            sub: "u1".into(),
            email: None,
            email_verified: None,
            name: None,
            preferred_username: None,
            nickname: None,
            picture: None,
            avatar_url: None,
        };
        let err = map_user_info(claims).unwrap_err();
        assert!(matches!(err, AuthError::OAuthUserInfoFetch(ref m) if m.contains("missing email")));
    }

    // ── Wiremock HTTP tests ───────────────────────────────────────────────────

    #[tokio::test]
    async fn new_fetches_discovery_doc_on_construct() {
        let server = wiremock::MockServer::start().await;
        mount_discovery_doc(&server).await;
        let base = server.uri();
        let discovery_url = format!("{base}/.well-known/openid-configuration");

        let provider = CustomOidcSocialProvider::new(discovery_config(&discovery_url))
            .await
            .unwrap();
        let doc = provider.current_endpoints().await.unwrap();
        assert_eq!(doc.authorize_url, format!("{base}/authorize"));
        assert_eq!(doc.token_url, format!("{base}/token"));
        assert_eq!(doc.userinfo_url, format!("{base}/userinfo"));
    }

    #[tokio::test]
    async fn new_returns_oauth_http_on_discovery_404() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let url = format!("{}/.well-known/openid-configuration", server.uri());
        let err = CustomOidcSocialProvider::new(discovery_config(&url))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::OAuthHttp(_)));
    }

    #[tokio::test]
    async fn new_returns_oauth_http_on_discovery_malformed_json() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json at all {{"))
            .mount(&server)
            .await;

        let url = format!("{}/.well-known/openid-configuration", server.uri());
        let err = CustomOidcSocialProvider::new(discovery_config(&url))
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::OAuthHttp(_)));
    }

    #[tokio::test]
    async fn new_returns_validation_on_discovery_doc_missing_endpoint() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        // Valid JSON but missing `userinfo_endpoint`
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorization_endpoint": "https://idp.example.com/authorize",
                "token_endpoint": "https://idp.example.com/token",
            })))
            .mount(&server)
            .await;

        let url = format!("{}/.well-known/openid-configuration", server.uri());
        let err = CustomOidcSocialProvider::new(discovery_config(&url))
            .await
            .unwrap_err();
        assert!(
            matches!(&err, AuthError::Validation(m) if m.contains("userinfo_endpoint")),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn discovery_cache_does_not_refetch_within_ttl() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorization_endpoint": format!("{base}/authorize"),
                "token_endpoint": format!("{base}/token"),
                "userinfo_endpoint": format!("{base}/userinfo"),
            })))
            .expect(1) // exactly one request: the one in new()
            .mount(&server)
            .await;

        let url = format!("{base}/.well-known/openid-configuration");
        let provider = CustomOidcSocialProvider::new(discovery_config(&url))
            .await
            .unwrap();
        // Two more calls — both served from cache (TTL = 1 hour)
        let _ = provider.current_endpoints().await.unwrap();
        let _ = provider.current_endpoints().await.unwrap();
        // wiremock verifies expect(1) on server drop
    }

    #[tokio::test]
    async fn discovery_cache_refreshes_after_ttl() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        let base = server.uri();
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorization_endpoint": format!("{base}/authorize"),
                "token_endpoint": format!("{base}/token"),
                "userinfo_endpoint": format!("{base}/userinfo"),
            })))
            .expect(2) // one at construction, one after TTL expiry
            .mount(&server)
            .await;

        let url = format!("{base}/.well-known/openid-configuration");
        let mut provider = CustomOidcSocialProvider::new(discovery_config(&url))
            .await
            .unwrap();
        provider.set_discovery_ttl(Duration::from_millis(1));

        // Wait well past the 1 ms TTL.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let _ = provider.current_endpoints().await.unwrap();
        // wiremock verifies expect(2) on server drop
    }

    #[tokio::test]
    async fn discovery_cache_keeps_stale_doc_on_refresh_failure() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        let base = server.uri();

        // First request succeeds — wiremock matches in registration order,
        // so this mock (registered first) wins for the initial fetch.
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "authorization_endpoint": format!("{base}/authorize"),
                "token_endpoint": format!("{base}/token"),
                "userinfo_endpoint": format!("{base}/userinfo"),
            })))
            .up_to_n_times(1)
            .mount(&server)
            .await;

        // All subsequent requests (TTL-refresh attempts) return 500.
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let url = format!("{base}/.well-known/openid-configuration");
        let mut provider = CustomOidcSocialProvider::new(discovery_config(&url))
            .await
            .unwrap();
        provider.set_discovery_ttl(Duration::from_millis(1));

        tokio::time::sleep(Duration::from_millis(50)).await;

        // Refresh fails (500), but stale doc is returned — no error.
        let doc = provider.current_endpoints().await.unwrap();
        assert_eq!(doc.token_url, format!("{base}/token"));
    }

    #[tokio::test]
    async fn pinned_endpoints_never_make_http_requests() {
        use wiremock::matchers::any;
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        // Any request to the mock server should NOT happen
        Mock::given(any())
            .respond_with(ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;

        // Pinned config uses no network at construction or query time
        let provider = CustomOidcSocialProvider::new(pinned_config())
            .await
            .unwrap();
        let _ = provider.current_endpoints().await.unwrap();
        let _ = provider.current_endpoints().await.unwrap();
        // wiremock verifies expect(0) on server drop
    }

    #[tokio::test]
    async fn exchange_code_posts_correct_form_and_returns_access_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "oidc-access-token",
                "token_type": "Bearer",
            })))
            .mount(&server)
            .await;

        mount_discovery_doc(&server).await;
        let base = server.uri();
        let provider = CustomOidcSocialProvider::new(discovery_config(&format!(
            "{base}/.well-known/openid-configuration"
        )))
        .await
        .unwrap();

        let token = provider
            .exchange_code("mycode", "https://app.example.com/cb", "verifier")
            .await
            .unwrap();
        assert_eq!(token, "oidc-access-token");
    }

    #[tokio::test]
    async fn exchange_code_returns_error_on_4xx() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant"
            })))
            .mount(&server)
            .await;

        mount_discovery_doc(&server).await;
        let base = server.uri();
        let provider = CustomOidcSocialProvider::new(discovery_config(&format!(
            "{base}/.well-known/openid-configuration"
        )))
        .await
        .unwrap();

        let err = provider
            .exchange_code("badcode", "https://app.example.com/cb", "v")
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::OAuthTokenExchange(_)));
    }

    #[tokio::test]
    async fn exchange_code_returns_error_on_missing_access_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "token_type": "Bearer"
                // access_token absent
            })))
            .mount(&server)
            .await;

        mount_discovery_doc(&server).await;
        let base = server.uri();
        let provider = CustomOidcSocialProvider::new(discovery_config(&format!(
            "{base}/.well-known/openid-configuration"
        )))
        .await
        .unwrap();

        let err = provider
            .exchange_code("code", "https://app.example.com/cb", "v")
            .await
            .unwrap_err();
        assert!(
            matches!(&err, AuthError::OAuthTokenExchange(m) if m.contains("missing access_token")),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn fetch_user_info_maps_standard_claims() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sub": "user-sub-123",
                "email": "alice@example.com",
                "email_verified": true,
                "name": "Alice Smith",
                "picture": "https://cdn.example.com/alice.jpg",
            })))
            .mount(&server)
            .await;

        mount_discovery_doc(&server).await;
        let base = server.uri();
        let provider = CustomOidcSocialProvider::new(discovery_config(&format!(
            "{base}/.well-known/openid-configuration"
        )))
        .await
        .unwrap();

        let info = provider.fetch_user_info("my-access-token").await.unwrap();
        assert_eq!(info.provider_user_id, "user-sub-123");
        assert_eq!(info.email, "alice@example.com");
        assert!(info.email_verified);
        assert_eq!(info.name.as_deref(), Some("Alice Smith"));
        assert_eq!(
            info.avatar_url.as_deref(),
            Some("https://cdn.example.com/alice.jpg")
        );
    }

    #[tokio::test]
    async fn fetch_user_info_maps_non_standard_name_and_avatar() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sub": "u2",
                "email": "bob@example.com",
                // name absent; preferred_username present
                "preferred_username": "bob42",
                // picture absent; avatar_url present (non-standard)
                "avatar_url": "https://cdn.example.com/bob.png",
            })))
            .mount(&server)
            .await;

        mount_discovery_doc(&server).await;
        let base = server.uri();
        let provider = CustomOidcSocialProvider::new(discovery_config(&format!(
            "{base}/.well-known/openid-configuration"
        )))
        .await
        .unwrap();

        let info = provider.fetch_user_info("token").await.unwrap();
        assert_eq!(info.name.as_deref(), Some("bob42"));
        assert_eq!(
            info.avatar_url.as_deref(),
            Some("https://cdn.example.com/bob.png")
        );
    }

    #[tokio::test]
    async fn fetch_user_info_returns_error_on_missing_email() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sub": "u3",
                // email absent
            })))
            .mount(&server)
            .await;

        mount_discovery_doc(&server).await;
        let base = server.uri();
        let provider = CustomOidcSocialProvider::new(discovery_config(&format!(
            "{base}/.well-known/openid-configuration"
        )))
        .await
        .unwrap();

        let err = provider.fetch_user_info("token").await.unwrap_err();
        assert!(matches!(err, AuthError::OAuthUserInfoFetch(ref m) if m.contains("missing email")));
    }

    #[tokio::test]
    async fn fetch_user_info_returns_error_on_4xx() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, ResponseTemplate};

        let server = wiremock::MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(401).set_body_string("Unauthorized"))
            .mount(&server)
            .await;

        mount_discovery_doc(&server).await;
        let base = server.uri();
        let provider = CustomOidcSocialProvider::new(discovery_config(&format!(
            "{base}/.well-known/openid-configuration"
        )))
        .await
        .unwrap();

        let err = provider.fetch_user_info("bad-token").await.unwrap_err();
        assert!(matches!(err, AuthError::OAuthUserInfoFetch(_)));
    }
}
