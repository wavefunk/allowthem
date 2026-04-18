use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use rand::TryRngCore;
use rand::rngs::OsRng;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::auth_client::AuthFuture;
use crate::db::Db;
use crate::error::AuthError;
use crate::types::{Email, OAuthAccountId, OAuthStateId, User, UserId};
use crate::users::map_unique_violation;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Information returned by a provider after fetching user info.
#[derive(Debug, Clone)]
pub struct OAuthUserInfo {
    pub provider_user_id: String,
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
}

/// Stored state returned when validating an OAuth callback.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct OAuthStateInfo {
    pub provider: String,
    pub redirect_uri: String,
    pub pkce_verifier: String,
    pub post_login_redirect: Option<String>,
    /// Non-null for the link flow: the authenticated user that initiated linking.
    /// Null for the standard login/register flow.
    pub linking_user_id: Option<UserId>,
}

/// A linked OAuth account for a user — provider name, provider user id, and email.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct OAuthAccountInfo {
    pub provider: String,
    pub provider_user_id: String,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

// ---------------------------------------------------------------------------
// OAuthProvider trait
// ---------------------------------------------------------------------------

/// Abstraction over an OAuth2 authorization code flow provider.
///
/// Each provider (Google, GitHub, etc.) implements this trait. The server
/// crate stores providers in a `HashMap<String, Box<dyn OAuthProvider>>`
/// keyed by provider name.
pub trait OAuthProvider: Send + Sync {
    /// Provider name, lowercase. Used as the URL path segment and the
    /// `provider` column in `oauth_accounts`.
    fn name(&self) -> &str;

    /// Build the authorization URL the user should be redirected to.
    fn authorize_url(&self, redirect_uri: &str, state: &str, pkce_challenge: &str) -> String;

    /// Exchange an authorization code for an access token.
    fn exchange_code<'a>(
        &'a self,
        code: &'a str,
        redirect_uri: &'a str,
        pkce_verifier: &'a str,
    ) -> AuthFuture<'a, String>;

    /// Fetch user information from the provider using the access token.
    fn user_info<'a>(&'a self, access_token: &'a str) -> AuthFuture<'a, OAuthUserInfo>;
}

// ---------------------------------------------------------------------------
// PKCE utilities
// ---------------------------------------------------------------------------

/// Generate a random PKCE code verifier (43 chars, base64url-unpadded).
pub fn generate_pkce_verifier() -> String {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG unavailable");
    Base64UrlUnpadded::encode_string(&bytes)
}

/// Derive the S256 PKCE code challenge from a verifier.
///
/// `code_challenge = BASE64URL(SHA256(code_verifier))`
pub fn pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    Base64UrlUnpadded::encode_string(&digest)
}

// ---------------------------------------------------------------------------
// State helpers (private)
// ---------------------------------------------------------------------------

/// Generate a random state parameter (43 chars, base64url-unpadded).
fn generate_state() -> String {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG unavailable");
    Base64UrlUnpadded::encode_string(&bytes)
}

/// SHA-256 hex hash of a raw state string.
fn hash_state(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    format!("{digest:x}")
}

// ---------------------------------------------------------------------------
// Db methods — OAuth state
// ---------------------------------------------------------------------------

impl Db {
    /// Create an OAuth state record. Returns the raw state value (for the authorize URL).
    ///
    /// `linking_user_id` is `Some` when initiating the account-linking flow (the user is
    /// already authenticated and wants to add a provider). It is `None` for the standard
    /// login/register flow.
    pub async fn create_oauth_state(
        &self,
        provider: &str,
        redirect_uri: &str,
        pkce_verifier: &str,
        post_login_redirect: Option<&str>,
        linking_user_id: Option<UserId>,
    ) -> Result<String, AuthError> {
        let raw_state = generate_state();
        let state_hash = hash_state(&raw_state);
        let id = OAuthStateId::new();
        let expires_at = (Utc::now() + Duration::minutes(10))
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();

        sqlx::query(
            "INSERT INTO allowthem_oauth_states \
             (id, state_hash, provider, redirect_uri, pkce_verifier, post_login_redirect, expires_at, linking_user_id) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(&state_hash)
        .bind(provider)
        .bind(redirect_uri)
        .bind(pkce_verifier)
        .bind(post_login_redirect)
        .bind(&expires_at)
        .bind(linking_user_id)
        .execute(self.pool())
        .await?;

        Ok(raw_state)
    }

    /// Validate and consume an OAuth state. Returns the stored info
    /// or None if invalid/expired. Atomically deletes to prevent reuse.
    pub async fn validate_oauth_state(
        &self,
        raw_state: &str,
    ) -> Result<Option<OAuthStateInfo>, AuthError> {
        let state_hash = hash_state(raw_state);
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        sqlx::query_as::<_, OAuthStateInfo>(
            "DELETE FROM allowthem_oauth_states \
             WHERE state_hash = ? AND expires_at > ? \
             RETURNING provider, redirect_uri, pkce_verifier, post_login_redirect, linking_user_id",
        )
        .bind(&state_hash)
        .bind(&now)
        .fetch_optional(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    // -----------------------------------------------------------------------
    // Db methods — OAuth users and accounts
    // -----------------------------------------------------------------------

    /// Create a user via OAuth -- no password.
    ///
    /// Creates the user (password_hash = NULL) and the oauth_accounts row
    /// in a single transaction. Returns the created User.
    pub async fn create_oauth_user(
        &self,
        email: Email,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<User, AuthError> {
        let user_id = UserId::new();
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let mut tx = self.pool().begin().await.map_err(AuthError::Database)?;

        sqlx::query(
            "INSERT INTO allowthem_users \
             (id, email, username, password_hash, email_verified, is_active, created_at, updated_at) \
             VALUES (?, ?, NULL, NULL, 0, 1, ?, ?)",
        )
        .bind(user_id)
        .bind(&email)
        .bind(&now)
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(map_unique_violation)?;

        sqlx::query(
            "INSERT INTO allowthem_oauth_accounts \
             (id, user_id, provider, provider_user_id, email, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(OAuthAccountId::new())
        .bind(user_id)
        .bind(provider)
        .bind(provider_user_id)
        .bind(email.as_str())
        .bind(&now)
        .execute(&mut *tx)
        .await
        .map_err(map_unique_violation)?;

        tx.commit().await.map_err(AuthError::Database)?;

        self.get_user(user_id).await
    }

    /// Link an OAuth identity to an existing user.
    pub async fn link_oauth_account(
        &self,
        user_id: UserId,
        provider: &str,
        provider_user_id: &str,
        email: &str,
    ) -> Result<(), AuthError> {
        sqlx::query(
            "INSERT INTO allowthem_oauth_accounts \
             (id, user_id, provider, provider_user_id, email) \
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(OAuthAccountId::new())
        .bind(user_id)
        .bind(provider)
        .bind(provider_user_id)
        .bind(email)
        .execute(self.pool())
        .await
        .map_err(map_unique_violation)?;

        Ok(())
    }

    /// Find an allowthem user by provider + provider_user_id.
    pub async fn find_user_by_oauth(
        &self,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<Option<User>, AuthError> {
        sqlx::query_as::<_, User>(
            "SELECT u.id, u.email, u.username, NULL as password_hash, \
             u.email_verified, u.is_active, u.created_at, u.updated_at, u.custom_data \
             FROM allowthem_users u \
             INNER JOIN allowthem_oauth_accounts oa ON oa.user_id = u.id \
             WHERE oa.provider = ? AND oa.provider_user_id = ?",
        )
        .bind(provider)
        .bind(provider_user_id)
        .fetch_optional(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// List all OAuth accounts linked to a user.
    pub async fn get_user_oauth_accounts(
        &self,
        user_id: UserId,
    ) -> Result<Vec<OAuthAccountInfo>, AuthError> {
        sqlx::query_as::<_, OAuthAccountInfo>(
            "SELECT provider, provider_user_id, email, created_at \
             FROM allowthem_oauth_accounts \
             WHERE user_id = ? \
             ORDER BY created_at ASC",
        )
        .bind(user_id)
        .fetch_all(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Remove an OAuth account link for a user + provider.
    ///
    /// Returns `true` if a row was deleted, `false` if no link existed.
    pub async fn unlink_oauth_account(
        &self,
        user_id: UserId,
        provider: &str,
    ) -> Result<bool, AuthError> {
        let result =
            sqlx::query("DELETE FROM allowthem_oauth_accounts WHERE user_id = ? AND provider = ?")
                .bind(user_id)
                .bind(provider)
                .execute(self.pool())
                .await
                .map_err(AuthError::Database)?;

        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::Db;

    async fn test_db() -> Db {
        Db::connect("sqlite::memory:").await.expect("in-memory db")
    }

    // --- PKCE tests ---

    #[test]
    fn pkce_verifier_is_43_chars() {
        let v = generate_pkce_verifier();
        assert_eq!(v.len(), 43);
    }

    #[test]
    fn pkce_challenge_is_deterministic() {
        let v = generate_pkce_verifier();
        let c1 = pkce_challenge(&v);
        let c2 = pkce_challenge(&v);
        assert_eq!(c1, c2);
    }

    #[test]
    fn pkce_challenge_is_base64url() {
        let v = generate_pkce_verifier();
        let c = pkce_challenge(&v);
        assert!(!c.contains('+'), "must not contain +");
        assert!(!c.contains('/'), "must not contain /");
        assert!(!c.contains('='), "must not contain =");
    }

    #[test]
    fn pkce_challenge_differs_from_verifier() {
        let v = generate_pkce_verifier();
        let c = pkce_challenge(&v);
        assert_ne!(v, c);
    }

    // --- State lifecycle tests ---

    #[tokio::test]
    async fn create_state_returns_nonempty_string() {
        let db = test_db().await;
        let state = db
            .create_oauth_state(
                "google",
                "https://example.com/callback",
                "verifier123",
                None,
                None,
            )
            .await
            .expect("create state");
        assert!(!state.is_empty());
    }

    #[tokio::test]
    async fn validate_state_returns_info_for_valid_state() {
        let db = test_db().await;
        let raw = db
            .create_oauth_state(
                "google",
                "https://example.com/cb",
                "my-verifier",
                None,
                None,
            )
            .await
            .expect("create");
        let info = db.validate_oauth_state(&raw).await.expect("validate");
        assert!(info.is_some());
        let info = info.unwrap();
        assert_eq!(info.provider, "google");
        assert_eq!(info.redirect_uri, "https://example.com/cb");
        assert_eq!(info.pkce_verifier, "my-verifier");
    }

    #[tokio::test]
    async fn validate_state_is_single_use() {
        let db = test_db().await;
        let raw = db
            .create_oauth_state("github", "https://example.com/cb", "v", None, None)
            .await
            .expect("create");
        let first = db.validate_oauth_state(&raw).await.expect("first");
        assert!(first.is_some());
        let second = db.validate_oauth_state(&raw).await.expect("second");
        assert!(second.is_none(), "state must be single-use");
    }

    #[tokio::test]
    async fn validate_state_returns_none_for_garbage() {
        let db = test_db().await;
        let result = db
            .validate_oauth_state("not-a-real-state")
            .await
            .expect("validate");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn validate_state_preserves_post_login_redirect() {
        let db = test_db().await;
        let raw = db
            .create_oauth_state(
                "google",
                "https://example.com/cb",
                "v",
                Some("/settings"),
                None,
            )
            .await
            .expect("create");
        let info = db
            .validate_oauth_state(&raw)
            .await
            .expect("validate")
            .unwrap();
        assert_eq!(info.post_login_redirect.as_deref(), Some("/settings"));
    }

    #[tokio::test]
    async fn validate_state_returns_none_for_post_login_redirect_when_not_set() {
        let db = test_db().await;
        let raw = db
            .create_oauth_state("google", "https://example.com/cb", "v", None, None)
            .await
            .expect("create");
        let info = db
            .validate_oauth_state(&raw)
            .await
            .expect("validate")
            .unwrap();
        assert!(info.post_login_redirect.is_none());
    }

    // --- OAuth user tests ---

    #[tokio::test]
    async fn create_oauth_user_creates_user_without_password() {
        let db = test_db().await;
        let email = Email::new("oauth@example.com".into()).unwrap();
        let user = db
            .create_oauth_user(email, "google", "gid-123")
            .await
            .expect("create oauth user");
        assert!(user.password_hash.is_none());
        assert_eq!(user.email.as_str(), "oauth@example.com");
    }

    #[tokio::test]
    async fn create_oauth_user_creates_linked_account() {
        let db = test_db().await;
        let email = Email::new("linked@example.com".into()).unwrap();
        let user = db
            .create_oauth_user(email, "google", "gid-456")
            .await
            .expect("create");
        let found = db
            .find_user_by_oauth("google", "gid-456")
            .await
            .expect("find");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, user.id);
    }

    #[tokio::test]
    async fn create_oauth_user_conflict_on_duplicate_email() {
        let db = test_db().await;
        let email = Email::new("dup@example.com".into()).unwrap();
        db.create_user(email.clone(), "password123", None)
            .await
            .expect("create password user");
        let result = db.create_oauth_user(email, "google", "gid-789").await;
        assert!(matches!(result, Err(AuthError::Conflict(_))));
    }

    #[tokio::test]
    async fn link_oauth_account_links_to_existing_user() {
        let db = test_db().await;
        let email = Email::new("link@example.com".into()).unwrap();
        let user = db
            .create_user(email, "password123", None)
            .await
            .expect("create user");
        db.link_oauth_account(user.id, "github", "gh-111", "link@example.com")
            .await
            .expect("link");
        let found = db
            .find_user_by_oauth("github", "gh-111")
            .await
            .expect("find");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, user.id);
    }

    #[tokio::test]
    async fn link_oauth_account_conflict_on_duplicate_provider_id() {
        let db = test_db().await;
        let email = Email::new("duplink@example.com".into()).unwrap();
        let user = db
            .create_user(email, "password123", None)
            .await
            .expect("create");
        db.link_oauth_account(user.id, "github", "gh-dup", "duplink@example.com")
            .await
            .expect("first link");
        let result = db
            .link_oauth_account(user.id, "github", "gh-dup", "duplink@example.com")
            .await;
        assert!(matches!(result, Err(AuthError::Conflict(_))));
    }

    #[tokio::test]
    async fn find_user_by_oauth_returns_none_when_not_linked() {
        let db = test_db().await;
        let result = db
            .find_user_by_oauth("github", "nonexistent")
            .await
            .expect("find");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn find_user_by_oauth_does_not_return_password_hash() {
        let db = test_db().await;
        let email = Email::new("nopw@example.com".into()).unwrap();
        db.create_oauth_user(email, "google", "gid-nopw")
            .await
            .expect("create");
        let user = db
            .find_user_by_oauth("google", "gid-nopw")
            .await
            .expect("find")
            .unwrap();
        assert!(user.password_hash.is_none());
    }

    // --- linking_user_id state tests ---

    #[tokio::test]
    async fn validate_state_preserves_linking_user_id() {
        let db = test_db().await;
        let user_id = UserId::new();
        let raw = db
            .create_oauth_state("google", "https://example.com/cb", "v", None, Some(user_id))
            .await
            .expect("create");
        let info = db
            .validate_oauth_state(&raw)
            .await
            .expect("validate")
            .unwrap();
        assert_eq!(info.linking_user_id, Some(user_id));
    }

    #[tokio::test]
    async fn validate_state_linking_user_id_is_none_for_login_flow() {
        let db = test_db().await;
        let raw = db
            .create_oauth_state("google", "https://example.com/cb", "v", None, None)
            .await
            .expect("create");
        let info = db
            .validate_oauth_state(&raw)
            .await
            .expect("validate")
            .unwrap();
        assert!(info.linking_user_id.is_none());
    }

    // --- get_user_oauth_accounts tests ---

    #[tokio::test]
    async fn get_user_oauth_accounts_returns_linked_providers() {
        let db = test_db().await;
        let email = Email::new("accts@example.com".into()).unwrap();
        let user = db
            .create_user(email, "password123", None)
            .await
            .expect("create");
        db.link_oauth_account(user.id, "google", "g-1", "accts@example.com")
            .await
            .expect("link google");
        db.link_oauth_account(user.id, "github", "gh-1", "accts@example.com")
            .await
            .expect("link github");

        let accounts = db
            .get_user_oauth_accounts(user.id)
            .await
            .expect("list accounts");
        assert_eq!(accounts.len(), 2);
        let providers: Vec<&str> = accounts.iter().map(|a| a.provider.as_str()).collect();
        assert!(providers.contains(&"google"));
        assert!(providers.contains(&"github"));
    }

    #[tokio::test]
    async fn get_user_oauth_accounts_returns_empty_for_no_links() {
        let db = test_db().await;
        let email = Email::new("nolinks@example.com".into()).unwrap();
        let user = db
            .create_user(email, "password123", None)
            .await
            .expect("create");

        let accounts = db
            .get_user_oauth_accounts(user.id)
            .await
            .expect("list accounts");
        assert!(accounts.is_empty());
    }

    // --- unlink_oauth_account tests ---

    #[tokio::test]
    async fn unlink_oauth_account_removes_link() {
        let db = test_db().await;
        let email = Email::new("unlink@example.com".into()).unwrap();
        let user = db
            .create_user(email, "password123", None)
            .await
            .expect("create");
        db.link_oauth_account(user.id, "google", "g-unlink", "unlink@example.com")
            .await
            .expect("link");

        let removed = db
            .unlink_oauth_account(user.id, "google")
            .await
            .expect("unlink");
        assert!(removed, "should return true when row deleted");

        let found = db
            .find_user_by_oauth("google", "g-unlink")
            .await
            .expect("find");
        assert!(found.is_none(), "link should be gone");
    }

    #[tokio::test]
    async fn unlink_oauth_account_returns_false_when_not_linked() {
        let db = test_db().await;
        let email = Email::new("notlinked@example.com".into()).unwrap();
        let user = db
            .create_user(email, "password123", None)
            .await
            .expect("create");

        let removed = db
            .unlink_oauth_account(user.id, "google")
            .await
            .expect("unlink");
        assert!(!removed, "should return false when nothing deleted");
    }
}
