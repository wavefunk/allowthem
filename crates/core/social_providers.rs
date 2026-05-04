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
    Github, // stored as "github" (not "git_hub")
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
    pub scopes: String, // raw JSON array string
    pub enabled: bool,
    pub priority: i64,
    pub config: Option<String>, // raw JSON, custom_oidc only
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
    pub client_secret: String, // decrypted
    pub scopes: Vec<String>,   // parsed from JSON
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

// ── Factory ───────────────────────────────────────────────────────────────────

use crate::error::AuthError;

/// Construct a `Box<dyn SocialProvider>` from a decrypted [`SocialProviderConfig`].
///
/// Dispatch table:
///
/// | `provider_type` | impl                         |
/// |-----------------|------------------------------|
/// | `Google`        | [`crate::social_google::GoogleSocialProvider`] |
/// | `Github`        | [`crate::social_github::GitHubSocialProvider`] |
/// | `CustomOidc`    | `Err` — lands in **7m5.3**   |
/// | `Apple`/`Microsoft` | `Err` — deferred         |
///
/// **`async fn` rationale**: the `CustomOidc` branch (7m5.3) needs to `await`
/// an OIDC discovery fetch at construction time. Declaring `async fn` now means
/// 7m5.3 can add the real impl without changing the public signature or all
/// existing call sites.
pub async fn build_social_provider(
    config: SocialProviderConfig,
) -> Result<Box<dyn SocialProvider>, AuthError> {
    match config.provider_type {
        ProviderType::Google => Ok(Box::new(crate::social_google::GoogleSocialProvider::new(
            config,
        )?)),
        ProviderType::Github => Ok(Box::new(crate::social_github::GitHubSocialProvider::new(
            config,
        )?)),
        ProviderType::CustomOidc => Err(AuthError::Validation(
            "custom_oidc provider not yet supported (epic 7m5.3)".into(),
        )),
        ProviderType::Apple | ProviderType::Microsoft => Err(AuthError::Validation(format!(
            "provider type {:?} not yet supported",
            config.provider_type
        ))),
    }
}

// ── Db CRUD ───────────────────────────────────────────────────────────────────

use crate::db::Db;
use crate::social_provider_encrypt::{decrypt_split, encrypt_split};

/// Map a SQLite UNIQUE constraint violation on `(provider_type, display_name)`
/// to `AuthError::Conflict`. Other errors pass through as `AuthError::Database`.
fn map_unique_violation(err: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(ref db_err) = err {
        let msg = db_err.message();
        if msg.contains("UNIQUE constraint failed") {
            return AuthError::Conflict(
                "a provider with that type and display name already exists".into(),
            );
        }
    }
    AuthError::Database(err)
}

impl Db {
    /// Insert a new social provider. Encrypts `client_secret` before write.
    ///
    /// `scopes` is stored as a JSON array. `config` is serialised to JSON and
    /// stored only for custom OIDC providers; pass `None` for built-ins.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_social_provider(
        &self,
        provider_type: ProviderType,
        display_name: &str,
        client_id: &str,
        client_secret: &str,
        scopes: &[String],
        config: Option<&serde_json::Value>,
        priority: i64,
        mfa_key: &[u8; 32],
    ) -> Result<SocialProviderId, AuthError> {
        let id = SocialProviderId::new();
        let enc = encrypt_split(client_secret.as_bytes(), mfa_key)?;
        let scopes_json = serde_json::to_string(scopes).expect("Vec<String> serializes to JSON");
        let config_json =
            config.map(|v| serde_json::to_string(v).expect("serde_json::Value serializes to JSON"));
        sqlx::query(
            "INSERT INTO allowthem_social_providers \
             (id, provider_type, display_name, client_id, \
              client_secret_enc, client_secret_nonce, scopes, priority, config) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(provider_type)
        .bind(display_name)
        .bind(client_id)
        .bind(enc.ciphertext)
        .bind(enc.nonce.to_vec())
        .bind(scopes_json)
        .bind(priority)
        .bind(config_json)
        .execute(self.pool())
        .await
        .map_err(map_unique_violation)?;
        Ok(id)
    }

    /// List all social providers ordered by `priority ASC, created_at ASC`.
    pub async fn list_social_providers(&self) -> Result<Vec<SocialProviderRow>, AuthError> {
        sqlx::query_as::<_, SocialProviderRow>(
            "SELECT id, provider_type, display_name, client_id, \
              client_secret_enc, client_secret_nonce, scopes, enabled, \
              priority, config, created_at, updated_at \
             FROM allowthem_social_providers \
             ORDER BY priority ASC, created_at ASC",
        )
        .fetch_all(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// List enabled social providers ordered by `priority ASC, created_at ASC`.
    pub async fn list_enabled_social_providers(&self) -> Result<Vec<SocialProviderRow>, AuthError> {
        sqlx::query_as::<_, SocialProviderRow>(
            "SELECT id, provider_type, display_name, client_id, \
              client_secret_enc, client_secret_nonce, scopes, enabled, \
              priority, config, created_at, updated_at \
             FROM allowthem_social_providers \
             WHERE enabled = 1 \
             ORDER BY priority ASC, created_at ASC",
        )
        .fetch_all(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Get a provider by ID. Returns `AuthError::NotFound` if not found.
    pub async fn get_social_provider(
        &self,
        id: SocialProviderId,
    ) -> Result<SocialProviderRow, AuthError> {
        sqlx::query_as::<_, SocialProviderRow>(
            "SELECT id, provider_type, display_name, client_id, \
              client_secret_enc, client_secret_nonce, scopes, enabled, \
              priority, config, created_at, updated_at \
             FROM allowthem_social_providers WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await
        .map_err(AuthError::Database)?
        .ok_or(AuthError::NotFound)
    }

    /// Update editable fields. Pass `None` to leave a field unchanged.
    ///
    /// `client_secret = Some("...")` re-encrypts with a fresh nonce.
    /// `config = Some(None)` sets the column to NULL.
    /// A call with all-`None` params is a no-op (returns `Ok(())`).
    ///
    /// Follows the string-building + `Box::leak` dynamic-SQL pattern from
    /// `users.rs::search_users`. SET clauses are collected as `&'static str`
    /// literals and joined; bind values are applied in the same order via
    /// chained `q = q.bind(...)` calls.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_social_provider(
        &self,
        id: SocialProviderId,
        display_name: Option<&str>,
        client_id: Option<&str>,
        client_secret: Option<&str>,
        scopes: Option<&[String]>,
        enabled: Option<bool>,
        priority: Option<i64>,
        config: Option<Option<&serde_json::Value>>,
        mfa_key: &[u8; 32],
    ) -> Result<(), AuthError> {
        // Encrypt before touching the query builder so errors surface early.
        let enc = match client_secret {
            Some(s) => Some(encrypt_split(s.as_bytes(), mfa_key)?),
            None => None,
        };
        let scopes_json =
            scopes.map(|s| serde_json::to_string(s).expect("Vec<String> serializes to JSON"));
        // `config: Option<Option<&Value>>`
        //   None          → skip column
        //   Some(None)    → set to NULL  (bind None::<String>)
        //   Some(Some(v)) → set to JSON  (bind Some(json_string))
        let config_json: Option<Option<String>> =
            config.map(|c| c.map(|v| serde_json::to_string(v).expect("Value serializes to JSON")));

        let mut set_clauses: Vec<&'static str> = Vec::new();
        if display_name.is_some() {
            set_clauses.push("display_name = ?");
        }
        if client_id.is_some() {
            set_clauses.push("client_id = ?");
        }
        if enc.is_some() {
            set_clauses.push("client_secret_enc = ?");
            set_clauses.push("client_secret_nonce = ?");
        }
        if scopes_json.is_some() {
            set_clauses.push("scopes = ?");
        }
        if enabled.is_some() {
            set_clauses.push("enabled = ?");
        }
        if priority.is_some() {
            set_clauses.push("priority = ?");
        }
        if config_json.is_some() {
            set_clauses.push("config = ?");
        }

        if set_clauses.is_empty() {
            return Ok(());
        }

        set_clauses.push("updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now')");

        let sql: &'static str = Box::leak(
            format!(
                "UPDATE allowthem_social_providers SET {} WHERE id = ?",
                set_clauses.join(", ")
            )
            .into_boxed_str(),
        );

        // Bind values in the same order as the SET clauses above.
        let mut q = sqlx::query(sql);
        if let Some(v) = display_name {
            q = q.bind(v);
        }
        if let Some(v) = client_id {
            q = q.bind(v);
        }
        if let Some(ref e) = enc {
            q = q.bind(e.ciphertext.clone());
            q = q.bind(e.nonce.to_vec());
        }
        if let Some(v) = scopes_json {
            q = q.bind(v);
        }
        if let Some(v) = enabled {
            q = q.bind(v);
        }
        if let Some(v) = priority {
            q = q.bind(v);
        }
        if let Some(v) = config_json {
            q = q.bind(v);
        }
        q = q.bind(id);

        q.execute(self.pool()).await.map_err(map_unique_violation)?;
        Ok(())
    }

    /// Delete a provider by ID. Returns `true` if a row was deleted.
    pub async fn delete_social_provider(&self, id: SocialProviderId) -> Result<bool, AuthError> {
        let result = sqlx::query("DELETE FROM allowthem_social_providers WHERE id = ?")
            .bind(id)
            .execute(self.pool())
            .await
            .map_err(AuthError::Database)?;
        Ok(result.rows_affected() > 0)
    }

    /// Decrypt a row's secret and parse its scopes/config into the runtime form.
    ///
    /// Not async — performs no DB I/O. Pure transformation. Placed on `Db` for
    /// API consistency so callers write `db.social_provider_to_config(row, key)`
    /// without importing a separate helper. `&self` is unused in the body.
    pub fn social_provider_to_config(
        &self,
        row: SocialProviderRow,
        mfa_key: &[u8; 32],
    ) -> Result<SocialProviderConfig, AuthError> {
        let secret_bytes =
            decrypt_split(&row.client_secret_nonce, &row.client_secret_enc, mfa_key)?;
        let client_secret =
            String::from_utf8(secret_bytes).map_err(|e| AuthError::MfaEncryption(e.to_string()))?;
        let scopes: Vec<String> =
            serde_json::from_str(&row.scopes).map_err(|e| AuthError::Validation(e.to_string()))?;
        let config: Option<serde_json::Value> = row
            .config
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(|e| AuthError::Validation(e.to_string()))?;
        Ok(SocialProviderConfig {
            id: row.id,
            provider_type: row.provider_type,
            display_name: row.display_name,
            client_id: row.client_id,
            client_secret,
            scopes,
            enabled: row.enabled,
            priority: row.priority,
            config,
        })
    }
}

// ── AllowThem wrappers ────────────────────────────────────────────────────────

use crate::handle::AllowThem;

impl AllowThem {
    /// Create a social provider. Reads `mfa_key` from the builder config.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_social_provider(
        &self,
        provider_type: ProviderType,
        display_name: &str,
        client_id: &str,
        client_secret: &str,
        scopes: &[String],
        config: Option<&serde_json::Value>,
        priority: i64,
    ) -> Result<SocialProviderId, AuthError> {
        self.db()
            .create_social_provider(
                provider_type,
                display_name,
                client_id,
                client_secret,
                scopes,
                config,
                priority,
                self.mfa_key()?,
            )
            .await
    }

    /// List all social providers.
    pub async fn list_social_providers(&self) -> Result<Vec<SocialProviderRow>, AuthError> {
        self.db().list_social_providers().await
    }

    /// List only enabled social providers.
    pub async fn list_enabled_social_providers(&self) -> Result<Vec<SocialProviderRow>, AuthError> {
        self.db().list_enabled_social_providers().await
    }

    /// Get a provider row by ID.
    pub async fn get_social_provider(
        &self,
        id: SocialProviderId,
    ) -> Result<SocialProviderRow, AuthError> {
        self.db().get_social_provider(id).await
    }

    /// Fetch a provider row and decrypt its secret in one call.
    ///
    /// Used by the OAuth callback path (7m5.2) when building a
    /// `Box<dyn SocialProvider>` for an inbound request.
    pub async fn get_social_provider_decrypted(
        &self,
        id: SocialProviderId,
    ) -> Result<SocialProviderConfig, AuthError> {
        let row = self.db().get_social_provider(id).await?;
        self.db().social_provider_to_config(row, self.mfa_key()?)
    }

    /// Update editable fields. See [`Db::update_social_provider`] for semantics.
    #[allow(clippy::too_many_arguments)]
    pub async fn update_social_provider(
        &self,
        id: SocialProviderId,
        display_name: Option<&str>,
        client_id: Option<&str>,
        client_secret: Option<&str>,
        scopes: Option<&[String]>,
        enabled: Option<bool>,
        priority: Option<i64>,
        config: Option<Option<&serde_json::Value>>,
    ) -> Result<(), AuthError> {
        self.db()
            .update_social_provider(
                id,
                display_name,
                client_id,
                client_secret,
                scopes,
                enabled,
                priority,
                config,
                self.mfa_key()?,
            )
            .await
    }

    /// Delete a provider by ID.
    pub async fn delete_social_provider(&self, id: SocialProviderId) -> Result<bool, AuthError> {
        self.db().delete_social_provider(id).await
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handle::{AllowThem, AllowThemBuilder};

    const TEST_KEY: [u8; 32] = [0x42u8; 32];
    const OTHER_KEY: [u8; 32] = [0x99u8; 32];

    async fn setup() -> AllowThem {
        AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .mfa_key(TEST_KEY)
            .build()
            .await
            .unwrap()
    }

    async fn setup_no_key() -> AllowThem {
        AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap()
    }

    // ── Dyn-safety ───────────────────────────────────────────────────────────

    // Compile-time proof that SocialProvider is dyn-compatible.
    fn _assert_object_safe(_: &dyn SocialProvider) {}

    // ── Stub impl for trait shape tests ─────────────────────────────────────

    struct StubProvider {
        ptype: ProviderType,
    }

    impl SocialProvider for StubProvider {
        fn provider_type(&self) -> ProviderType {
            self.ptype
        }
        fn authorize_url(&self, _r: &str, _s: &str, _p: &str) -> String {
            "https://example.com/authorize".into()
        }
        fn exchange_code<'a>(
            &'a self,
            _code: &'a str,
            _redirect_uri: &'a str,
            _pkce_verifier: &'a str,
        ) -> AuthFuture<'a, String> {
            Box::pin(async move { Ok("stub-token".into()) })
        }
        fn fetch_user_info<'a>(&'a self, _access_token: &'a str) -> AuthFuture<'a, SocialUserInfo> {
            Box::pin(async move {
                Ok(SocialUserInfo {
                    provider_user_id: "p1".into(),
                    email: "stub@example.com".into(),
                    email_verified: true,
                    name: None,
                    avatar_url: None,
                })
            })
        }
    }

    #[tokio::test]
    async fn stub_provider_dyn_dispatch() {
        let p: Box<dyn SocialProvider> = Box::new(StubProvider {
            ptype: ProviderType::Google,
        });
        assert_eq!(p.provider_type(), ProviderType::Google);
        let token = p.exchange_code("c", "r", "v").await.unwrap();
        assert_eq!(token, "stub-token");
        let info = p.fetch_user_info(&token).await.unwrap();
        assert_eq!(info.email, "stub@example.com");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    fn default_scopes() -> Vec<String> {
        vec!["openid".into(), "email".into()]
    }

    async fn create_google(ath: &AllowThem, display_name: &str) -> SocialProviderId {
        ath.create_social_provider(
            ProviderType::Google,
            display_name,
            "client-id",
            "client-secret",
            &default_scopes(),
            None,
            0,
        )
        .await
        .unwrap()
    }

    // ── CRUD tests ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn create_then_get_round_trip() {
        let ath = setup().await;
        let id = ath
            .create_social_provider(
                ProviderType::Google,
                "Google Login",
                "my-client-id",
                "supersecret",
                &default_scopes(),
                None,
                10,
            )
            .await
            .unwrap();

        let config = ath.get_social_provider_decrypted(id).await.unwrap();
        assert_eq!(config.client_id, "my-client-id");
        assert_eq!(config.client_secret, "supersecret");
        assert_eq!(config.scopes, default_scopes());
        assert_eq!(config.priority, 10);
        assert!(config.enabled);
        assert_eq!(config.provider_type, ProviderType::Google);
        assert_eq!(config.display_name, "Google Login");
        assert!(config.config.is_none());
    }

    #[tokio::test]
    async fn list_orders_by_priority() {
        let ath = setup().await;
        let db = ath.db();
        for (name, pri) in [("P5", 5i64), ("P1", 1), ("P3", 3)] {
            db.create_social_provider(
                ProviderType::Google,
                name,
                "cid",
                "sec",
                &default_scopes(),
                None,
                pri,
                &TEST_KEY,
            )
            .await
            .unwrap();
        }
        let rows = db.list_social_providers().await.unwrap();
        let priorities: Vec<i64> = rows.iter().map(|r| r.priority).collect();
        assert_eq!(priorities, vec![1, 3, 5]);
    }

    #[tokio::test]
    async fn list_enabled_filters_disabled() {
        let ath = setup().await;
        let db = ath.db();
        let enabled_id = db
            .create_social_provider(
                ProviderType::Google,
                "Enabled",
                "cid",
                "sec",
                &default_scopes(),
                None,
                0,
                &TEST_KEY,
            )
            .await
            .unwrap();
        let disabled_id = db
            .create_social_provider(
                ProviderType::Github,
                "Disabled",
                "cid2",
                "sec2",
                &default_scopes(),
                None,
                0,
                &TEST_KEY,
            )
            .await
            .unwrap();
        // Disable the second one
        db.update_social_provider(
            disabled_id,
            None,
            None,
            None,
            None,
            Some(false),
            None,
            None,
            &TEST_KEY,
        )
        .await
        .unwrap();

        let enabled = db.list_enabled_social_providers().await.unwrap();
        assert_eq!(enabled.len(), 1);
        assert_eq!(enabled[0].id, enabled_id);
    }

    #[tokio::test]
    async fn update_partial_display_name() {
        let ath = setup().await;
        let id = create_google(&ath, "Old Name").await;
        ath.update_social_provider(id, Some("New Name"), None, None, None, None, None, None)
            .await
            .unwrap();
        let row = ath.db().get_social_provider(id).await.unwrap();
        assert_eq!(row.display_name, "New Name");
        assert_eq!(row.client_id, "client-id");
    }

    #[tokio::test]
    async fn update_secret_re_encrypts_with_fresh_nonce() {
        let ath = setup().await;
        let id = create_google(&ath, "G").await;
        let before = ath.db().get_social_provider(id).await.unwrap();

        ath.update_social_provider(id, None, None, Some("new-secret"), None, None, None, None)
            .await
            .unwrap();

        let after = ath.db().get_social_provider(id).await.unwrap();
        assert_ne!(
            before.client_secret_nonce, after.client_secret_nonce,
            "nonce must change on secret rotation"
        );
        let config = ath.get_social_provider_decrypted(id).await.unwrap();
        assert_eq!(config.client_secret, "new-secret");
    }

    #[tokio::test]
    async fn delete_returns_true_on_hit_false_on_miss() {
        let ath = setup().await;
        let id = create_google(&ath, "G").await;
        assert!(ath.delete_social_provider(id).await.unwrap());
        assert!(!ath.delete_social_provider(id).await.unwrap());
    }

    #[tokio::test]
    async fn unique_index_blocks_duplicate_type_displayname() {
        let ath = setup().await;
        create_google(&ath, "Google").await;
        let err = ath
            .create_social_provider(
                ProviderType::Google,
                "Google",
                "other-cid",
                "sec",
                &default_scopes(),
                None,
                0,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Conflict(_)));
    }

    #[tokio::test]
    async fn decrypt_with_wrong_mfa_key_fails() {
        let ath = setup().await;
        let id = create_google(&ath, "G").await;
        let row = ath.db().get_social_provider(id).await.unwrap();
        let err = ath
            .db()
            .social_provider_to_config(row, &OTHER_KEY)
            .unwrap_err();
        assert!(matches!(err, AuthError::MfaEncryption(_)));
    }

    #[tokio::test]
    async fn create_without_mfa_key_returns_mfa_not_configured() {
        let ath = setup_no_key().await;
        let err = ath
            .create_social_provider(
                ProviderType::Google,
                "G",
                "cid",
                "sec",
                &default_scopes(),
                None,
                0,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::MfaNotConfigured));
    }

    #[tokio::test]
    async fn provider_type_all_variants_round_trip_through_sqlite() {
        let ath = setup().await;
        let db = ath.db();
        let variants = [
            (ProviderType::Google, "google-rt"),
            (ProviderType::Github, "github-rt"),
            (ProviderType::Apple, "apple-rt"),
            (ProviderType::Microsoft, "microsoft-rt"),
            (ProviderType::CustomOidc, "customoidc-rt"),
        ];
        for (ptype, name) in variants {
            let id = db
                .create_social_provider(
                    ptype,
                    name,
                    "cid",
                    "sec",
                    &default_scopes(),
                    None,
                    0,
                    &TEST_KEY,
                )
                .await
                .unwrap();
            let row = db.get_social_provider(id).await.unwrap();
            assert_eq!(row.provider_type, ptype, "round-trip for {ptype:?}");
        }
    }

    #[tokio::test]
    async fn scopes_and_config_are_valid_json_as_stored() {
        let ath = setup().await;
        let db = ath.db();
        let cfg_val =
            serde_json::json!({"discovery_url": "https://issuer/.well-known/openid-configuration"});
        let id = db
            .create_social_provider(
                ProviderType::CustomOidc,
                "OIDC",
                "cid",
                "sec",
                &default_scopes(),
                Some(&cfg_val),
                0,
                &TEST_KEY,
            )
            .await
            .unwrap();
        let row = db.get_social_provider(id).await.unwrap();
        // scopes is valid JSON
        let parsed_scopes: Vec<String> =
            serde_json::from_str(&row.scopes).expect("scopes column must be valid JSON array");
        assert_eq!(parsed_scopes, default_scopes());
        // config is valid JSON
        let raw_config = row.config.expect("config must be Some");
        let _: serde_json::Value =
            serde_json::from_str(&raw_config).expect("config column must be valid JSON");
    }

    #[tokio::test]
    async fn check_constraint_blocks_invalid_provider_type() {
        let ath = setup().await;
        let db = ath.db();
        let err = sqlx::query(
            "INSERT INTO allowthem_social_providers \
             (id, provider_type, display_name, client_id, \
              client_secret_enc, client_secret_nonce, scopes) \
             VALUES (?, 'badprovider', 'x', 'y', X'00', X'00', '[]')",
        )
        .bind(SocialProviderId::new())
        .execute(db.pool())
        .await
        .unwrap_err();
        assert!(
            matches!(err, sqlx::Error::Database(_)),
            "CHECK constraint must fire for invalid provider_type"
        );
    }

    #[tokio::test]
    async fn check_constraint_blocks_invalid_enabled_value() {
        let ath = setup().await;
        let db = ath.db();
        let err = sqlx::query(
            "INSERT INTO allowthem_social_providers \
             (id, provider_type, display_name, client_id, \
              client_secret_enc, client_secret_nonce, scopes, enabled) \
             VALUES (?, 'google', 'x', 'y', X'00', X'00', '[]', 2)",
        )
        .bind(SocialProviderId::new())
        .execute(db.pool())
        .await
        .unwrap_err();
        assert!(
            matches!(err, sqlx::Error::Database(_)),
            "CHECK constraint must fire for enabled = 2"
        );
    }

    #[tokio::test]
    async fn encryption_round_trip_via_db_boundary() {
        // Verifies that the bytes written by create_social_provider are the
        // correct wire format for decrypt_split — not just opaque via to_config.
        use crate::social_provider_encrypt::decrypt_split;
        let ath = setup().await;
        let id = create_google(&ath, "Wire").await;
        let row = ath.db().get_social_provider(id).await.unwrap();
        let bytes =
            decrypt_split(&row.client_secret_nonce, &row.client_secret_enc, &TEST_KEY).unwrap();
        assert_eq!(bytes, b"client-secret");
    }

    // ── build_social_provider factory ─────────────────────────────────────────

    fn make_config(provider_type: ProviderType, scopes: Vec<String>) -> SocialProviderConfig {
        use crate::types::SocialProviderId;
        SocialProviderConfig {
            id: SocialProviderId::new(),
            provider_type,
            display_name: "Test".into(),
            client_id: "cid".into(),
            client_secret: "sec".into(),
            scopes,
            enabled: true,
            priority: 0,
            config: None,
        }
    }

    #[tokio::test]
    async fn build_social_provider_dispatches_to_google() {
        let cfg = make_config(ProviderType::Google, vec!["openid".into()]);
        let provider = build_social_provider(cfg).await.unwrap();
        assert_eq!(provider.provider_type(), ProviderType::Google);
    }

    #[tokio::test]
    async fn build_social_provider_dispatches_to_github() {
        let cfg = make_config(ProviderType::Github, vec!["user:email".into()]);
        let provider = build_social_provider(cfg).await.unwrap();
        assert_eq!(provider.provider_type(), ProviderType::Github);
    }

    #[tokio::test]
    async fn build_social_provider_rejects_custom_oidc_with_validation_error() {
        let cfg = make_config(ProviderType::CustomOidc, vec!["openid".into()]);
        // Box<dyn SocialProvider> doesn't impl Debug, so use match instead of unwrap_err.
        let err = match build_social_provider(cfg).await {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        };
        match err {
            AuthError::Validation(msg) => {
                assert!(msg.contains("custom_oidc"), "got: {msg}");
                assert!(msg.contains("7m5.3"), "got: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn build_social_provider_rejects_apple_with_validation_error() {
        let cfg = make_config(ProviderType::Apple, vec!["openid".into()]);
        let err = match build_social_provider(cfg).await {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        };
        assert!(matches!(err, AuthError::Validation(_)));
    }

    #[tokio::test]
    async fn build_social_provider_rejects_microsoft_with_validation_error() {
        let cfg = make_config(ProviderType::Microsoft, vec!["openid".into()]);
        let err = match build_social_provider(cfg).await {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        };
        assert!(matches!(err, AuthError::Validation(_)));
    }

    #[tokio::test]
    async fn build_social_provider_propagates_constructor_error_from_inner() {
        // Google config with empty scopes — inner constructor returns Validation.
        let cfg = make_config(ProviderType::Google, vec![]);
        let err = match build_social_provider(cfg).await {
            Err(e) => e,
            Ok(_) => panic!("expected Err, got Ok"),
        };
        match err {
            AuthError::Validation(msg) => {
                assert!(msg.contains("scopes must not be empty"), "got: {msg}");
            }
            other => panic!("expected Validation, got {other:?}"),
        }
    }
}
