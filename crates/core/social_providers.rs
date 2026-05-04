//! DB-backed social-login provider configuration and runtime surface.
//!
//! ## Relationship to `OAuthProvider`
//!
//! [`crate::oauth::OAuthProvider`] is the *static-config* trait used by the
//! existing auth flow: provider instances are constructed once at startup
//! from environment/builder config and stored in a
//! `HashMap<String, Box<dyn OAuthProvider>>`. That path remains
//! **unchanged** in this task and Epic 7m5.1.
//!
//! [`SocialProvider`] is the *DB-backed* future direction: per-tenant
//! provider configuration is stored in `allowthem_social_providers` with an
//! encrypted client secret. 7m5.2 will provide concrete impls
//! (`Google`, `GitHub`, …) and migrate the runtime auth flow to use this
//! trait. Until then the two traits coexist.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::auth_client::AuthFuture;
use crate::types::SocialProviderId;

// ── ProviderType ─────────────────────────────────────────────────────────────

/// Discriminator for a social-login provider.
///
/// Stored in SQLite as TEXT via `sqlx::Type`. The `lowercase` rename
/// produces `google`, `github`, `apple`, `microsoft`; `CustomOidc` needs an
/// explicit rename because `lowercase` would emit `customoidc`.
///
/// **Deviation from spec §10.3**: the spec uses `'oidc'`; bd uses
/// `'custom_oidc'` — more explicit and avoids confusion with the OIDC
/// *protocol* that all built-in providers also use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
pub enum ProviderType {
    Google,
    Github,   // stored as "github" (not "git_hub")
    Apple,
    Microsoft,
    #[sqlx(rename = "custom_oidc")]
    #[serde(rename = "custom_oidc")]
    CustomOidc,
}

// ── SocialUserInfo ────────────────────────────────────────────────────────────

/// Normalised user identity returned by every [`SocialProvider`] impl.
///
/// Wider than [`crate::oauth::OAuthUserInfo`]: adds `avatar_url`.
#[derive(Debug, Clone)]
pub struct SocialUserInfo {
    pub provider_user_id: String,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

// ── SocialProviderRow ─────────────────────────────────────────────────────────

/// Raw database row from `allowthem_social_providers`.
///
/// Secrets are still encrypted; `scopes` and `config` are raw JSON strings.
/// Use [`crate::db::Db::social_provider_to_config`] to decrypt and parse.
///
/// **Column name note**: the column is `enabled` (not `is_enabled`); this
/// deviates from spec §10.3 but matches bd and the project's convention.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct SocialProviderRow {
    pub id: SocialProviderId,
    pub provider_type: ProviderType,
    pub display_name: String,
    pub client_id: String,
    pub client_secret_enc: Vec<u8>,
    pub client_secret_nonce: Vec<u8>,
    pub scopes: String,          // raw JSON array string
    pub enabled: bool,
    pub priority: i64,
    pub config: Option<String>,  // raw JSON, custom_oidc only
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── SocialProviderConfig ──────────────────────────────────────────────────────

/// Runtime form of a social provider — secret decrypted, scopes parsed.
///
/// Produced by [`crate::db::Db::social_provider_to_config`].
/// This is the form 7m5.2 will use when constructing a
/// `Box<dyn SocialProvider>` for an inbound OAuth callback.
///
/// `config` carries custom-OIDC endpoint URLs as a JSON object shaped like:
/// ```json
/// {
///   "discovery_url": "https://issuer/.well-known/openid-configuration",
///   "authorize_url": "https://issuer/oauth/authorize",
///   "token_url": "https://issuer/oauth/token",
///   "userinfo_url": "https://issuer/oauth/userinfo"
/// }
/// ```
/// Built-in providers (`Google`, `Github`, `Apple`, `Microsoft`) leave
/// `config` as `None`. Validation that the shape matches `provider_type` is
/// the impl's responsibility (7m5.3 for `CustomOidc`).
///
/// **Key rotation note**: the `mfa_key` used to encrypt provider secrets is
/// the same AES-256-GCM key as for MFA secrets (spec §11 lists per-tenant
/// root-key derivation as a non-goal). Key rotation requires re-encrypting
/// all rows.
#[derive(Debug, Clone)]
pub struct SocialProviderConfig {
    pub id: SocialProviderId,
    pub provider_type: ProviderType,
    pub display_name: String,
    pub client_id: String,
    pub client_secret: String,             // decrypted
    pub scopes: Vec<String>,               // parsed from JSON
    pub enabled: bool,
    pub priority: i64,
    pub config: Option<serde_json::Value>,
}

// ── SocialProvider trait ──────────────────────────────────────────────────────

/// Runtime surface every DB-backed social-login provider must implement.
///
/// Implementations are constructed from a [`SocialProviderConfig`] and are
/// stateless after construction — configuration is stored internally.
///
/// **Trait is `dyn`-safe**: no generics in method signatures, no `Self` in
/// return types. Verified by the compile-time check in `#[cfg(test)]`.
pub trait SocialProvider: Send + Sync {
    /// Which provider type this instance represents.
    fn provider_type(&self) -> ProviderType;

    /// Build the provider's authorization redirect URL.
    fn authorize_url(&self, redirect_uri: &str, state: &str, pkce_challenge: &str) -> String;

    /// Exchange an authorization code for an access token.
    ///
    /// Returns the raw access token string. Network errors map to
    /// `AuthError::OAuthExchange` (defined in 7m5.2).
    fn exchange_code<'a>(
        &'a self,
        code: &'a str,
        redirect_uri: &'a str,
        pkce_verifier: &'a str,
    ) -> AuthFuture<'a, String>;

    /// Fetch the authenticated user's identity using the access token.
    fn fetch_user_info<'a>(&'a self, access_token: &'a str) -> AuthFuture<'a, SocialUserInfo>;
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time proof that SocialProvider is dyn-compatible.
    fn _assert_object_safe(_: &dyn SocialProvider) {}
}
