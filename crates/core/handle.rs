use std::sync::Arc;

use chrono::Duration;
use sqlx::SqlitePool;

use crate::db::Db;
use crate::error::AuthError;
use crate::sessions::{self, SessionConfig};
use crate::types::{SessionToken, User};

/// Outcome of a successful login or session creation.
pub struct LoginOutcome {
    pub user: User,
    pub token: SessionToken,
    /// Value for the `Set-Cookie` response header.
    pub set_cookie: String,
}

/// Error type for builder construction and validation failures.
#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    /// Database connection or migration failure.
    #[error("database error: {0}")]
    Database(#[from] AuthError),

    /// Invalid builder configuration.
    /// Reserved for future validation; not currently produced.
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),
}

enum PoolSource {
    Url(String),
    Pool(SqlitePool),
}

/// Builder for constructing a configured [`AllowThem`] handle.
pub struct AllowThemBuilder {
    pool_source: PoolSource,
    session_ttl: Option<Duration>,
    cookie_name: Option<&'static str>,
    cookie_secure: Option<bool>,
    cookie_domain: String,
    mfa_key: Option<[u8; 32]>,
    signing_key: Option<[u8; 32]>,
    base_url: Option<String>,
}

impl AllowThemBuilder {
    /// Start building from a database URL.
    ///
    /// At build time, calls `Db::connect(url)` which creates the pool,
    /// sets pragmas (foreign_keys, WAL, busy_timeout), and runs migrations.
    pub fn new(url: impl Into<String>) -> Self {
        Self {
            pool_source: PoolSource::Url(url.into()),
            session_ttl: None,
            cookie_name: None,
            cookie_secure: None,
            cookie_domain: String::new(),
            mfa_key: None,
            signing_key: None,
            base_url: None,
        }
    }

    /// Start building from an existing pool.
    ///
    /// At build time, calls `Db::new(pool)` which runs migrations.
    /// The caller is responsible for pragma configuration on their pool.
    pub fn with_pool(pool: SqlitePool) -> Self {
        Self {
            pool_source: PoolSource::Pool(pool),
            session_ttl: None,
            cookie_name: None,
            cookie_secure: None,
            cookie_domain: String::new(),
            mfa_key: None,
            signing_key: None,
            base_url: None,
        }
    }

    /// Override session TTL. Default: 24 hours.
    pub fn session_ttl(mut self, ttl: Duration) -> Self {
        self.session_ttl = Some(ttl);
        self
    }

    /// Override session cookie name. Default: `"allowthem_session"`.
    pub fn cookie_name(mut self, name: &'static str) -> Self {
        self.cookie_name = Some(name);
        self
    }

    /// Set the Secure attribute on session cookies.
    ///
    /// Default: `true`. Set to `false` for local development over HTTP.
    pub fn cookie_secure(mut self, secure: bool) -> Self {
        self.cookie_secure = Some(secure);
        self
    }

    /// Set the Domain attribute on session cookies.
    ///
    /// Default: empty (omitted). When set, the cookie is sent to the domain
    /// and all its subdomains.
    pub fn cookie_domain(mut self, domain: impl Into<String>) -> Self {
        self.cookie_domain = domain.into();
        self
    }

    /// Set the AES-256-GCM encryption key for MFA secrets.
    ///
    /// When not set, all MFA operations return `AuthError::MfaNotConfigured`.
    /// This keeps MFA opt-in for embedded integrators who don't need it.
    pub fn mfa_key(mut self, key: [u8; 32]) -> Self {
        self.mfa_key = Some(key);
        self
    }

    /// Set the AES-256-GCM encryption key for RS256 signing key storage.
    ///
    /// Required for OIDC/standalone mode. When not set, all signing key
    /// operations return `AuthError::SigningKeyNotConfigured`.
    pub fn signing_key(mut self, key: [u8; 32]) -> Self {
        self.signing_key = Some(key);
        self
    }

    /// Set the base URL (issuer) for the OIDC provider.
    ///
    /// Required for standalone mode. Used as the `iss` claim in tokens
    /// and for issuer validation on incoming access tokens.
    /// When not set, OIDC operations return `AuthError::BaseUrlNotConfigured`.
    pub fn base_url(mut self, url: impl Into<String>) -> Self {
        self.base_url = Some(url.into());
        self
    }

    /// Construct the [`AllowThem`] handle.
    ///
    /// Connects to (or wraps) the database, runs migrations, and assembles
    /// the session configuration from overrides plus defaults.
    pub async fn build(self) -> Result<AllowThem, BuildError> {
        let db = match self.pool_source {
            PoolSource::Url(url) => Db::connect(&url).await?,
            PoolSource::Pool(pool) => Db::new(pool).await?,
        };

        let defaults = SessionConfig::default();
        let session_config = SessionConfig {
            ttl: self.session_ttl.unwrap_or(defaults.ttl),
            cookie_name: self.cookie_name.unwrap_or(defaults.cookie_name),
            secure: self.cookie_secure.unwrap_or(defaults.secure),
        };

        Ok(AllowThem {
            inner: Arc::new(Inner {
                db,
                session_config,
                cookie_domain: self.cookie_domain,
                mfa_key: self.mfa_key,
                signing_key: self.signing_key,
                base_url: self.base_url,
            }),
        })
    }
}

struct Inner {
    db: Db,
    session_config: SessionConfig,
    cookie_domain: String,
    mfa_key: Option<[u8; 32]>,
    signing_key: Option<[u8; 32]>,
    base_url: Option<String>,
}

/// Configured allowthem handle.
///
/// Bundles a `Db`, `SessionConfig`, and cookie domain into a single value
/// that is cheaply cloneable and safe to share across Axum handlers via
/// `State<AllowThem>` or `Extension<AllowThem>`.
#[derive(Clone)]
pub struct AllowThem {
    inner: Arc<Inner>,
}

impl AllowThem {
    /// Access the underlying database handle.
    ///
    /// Escape hatch for callers who need direct `Db` access for operations
    /// not yet wrapped by `AllowThem` methods (e.g., user CRUD, role management).
    pub fn db(&self) -> &Db {
        &self.inner.db
    }

    /// Access the session configuration.
    pub fn session_config(&self) -> &SessionConfig {
        &self.inner.session_config
    }

    /// Build a `Set-Cookie` header value for the given session token.
    ///
    /// Uses the stored `SessionConfig` and cookie domain. Delegates to
    /// `sessions::session_cookie()`.
    pub fn session_cookie(&self, token: &SessionToken) -> String {
        sessions::session_cookie(token, &self.inner.session_config, &self.inner.cookie_domain)
    }

    /// Returns the MFA encryption key, or `Err(MfaNotConfigured)` if not set.
    pub(crate) fn mfa_key(&self) -> Result<&[u8; 32], AuthError> {
        self.inner
            .mfa_key
            .as_ref()
            .ok_or(AuthError::MfaNotConfigured)
    }

    /// Returns the signing key encryption key, or `Err(SigningKeyNotConfigured)` if not set.
    pub(crate) fn signing_key(&self) -> Result<&[u8; 32], AuthError> {
        self.inner
            .signing_key
            .as_ref()
            .ok_or(AuthError::SigningKeyNotConfigured)
    }

    /// Returns the base URL (issuer), or `Err(BaseUrlNotConfigured)` if not set.
    pub fn base_url(&self) -> Result<&str, AuthError> {
        self.inner
            .base_url
            .as_deref()
            .ok_or(AuthError::BaseUrlNotConfigured)
    }

    /// Fetch the active signing key and decrypt its private key PEM.
    ///
    /// Combines the encryption key, active key lookup, and decryption into
    /// a single call. Keeps the raw encryption key private to the core crate.
    pub async fn get_decrypted_signing_key(
        &self,
    ) -> Result<(crate::signing_keys::SigningKey, String), AuthError> {
        let enc_key = self.signing_key()?;
        let key = self.db().get_active_signing_key().await?;
        let pem = crate::signing_keys::decrypt_private_key(&key, enc_key)?;
        Ok((key, pem))
    }

    /// Build a `Set-Cookie` header value that expires the session cookie.
    ///
    /// Returns `Max-Age=0` with the same cookie name, path, domain, and flags
    /// used by `session_cookie()`. Pass this as the `Set-Cookie` header on a
    /// logout response to clear the browser's stored session cookie.
    pub fn clear_session_cookie(&self) -> String {
        sessions::clear_session_cookie(&self.inner.session_config, &self.inner.cookie_domain)
    }

    /// Extract the session token from a `Cookie` header value.
    ///
    /// Uses the stored cookie name. Delegates to `sessions::parse_session_cookie()`.
    pub fn parse_session_cookie(&self, cookie_header: &str) -> Option<SessionToken> {
        sessions::parse_session_cookie(cookie_header, self.inner.session_config.cookie_name)
    }
}

#[cfg(test)]
mod tests {
    use sqlx::sqlite::SqliteConnectOptions;
    use std::str::FromStr;

    use super::*;
    use crate::sessions::generate_token;
    use crate::types::Email;

    #[tokio::test]
    async fn build_with_url_defaults() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();

        let config = ath.session_config();
        assert_eq!(config.ttl, Duration::hours(24));
        assert_eq!(config.cookie_name, "allowthem_session");
        assert!(config.secure);

        let token = generate_token();
        let cookie = ath.session_cookie(&token);
        assert!(!cookie.contains("; Domain="));
    }

    #[tokio::test]
    async fn build_with_pool() {
        let opts = SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .pragma("foreign_keys", "ON");
        let pool = sqlx::SqlitePool::connect_with(opts).await.unwrap();

        let ath = AllowThemBuilder::with_pool(pool).build().await.unwrap();

        let email = Email::new("test@example.com".into()).unwrap();
        let user = ath.db().create_user(email, "password123", None).await;
        assert!(user.is_ok());
    }

    #[tokio::test]
    async fn build_with_overrides() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .session_ttl(Duration::hours(48))
            .cookie_name("my_session")
            .cookie_secure(false)
            .cookie_domain("example.com")
            .build()
            .await
            .unwrap();

        let config = ath.session_config();
        assert_eq!(config.ttl, Duration::hours(48));
        assert_eq!(config.cookie_name, "my_session");
        assert!(!config.secure);
    }

    #[tokio::test]
    async fn session_cookie_uses_config() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_name("custom")
            .cookie_secure(false)
            .cookie_domain("example.com")
            .build()
            .await
            .unwrap();

        let token = generate_token();
        let cookie = ath.session_cookie(&token);

        assert!(cookie.contains("custom="));
        assert!(cookie.contains("; Domain=example.com"));
        assert!(!cookie.contains("; Secure"));
    }

    #[tokio::test]
    async fn clear_session_cookie_defaults() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();

        let cookie = ath.clear_session_cookie();
        assert!(cookie.starts_with("allowthem_session=;"));
        assert!(cookie.contains("; Max-Age=0"));
        assert!(!cookie.contains("; Domain="));
        assert!(cookie.contains("; Secure"));
    }

    #[tokio::test]
    async fn clear_session_cookie_name_matches_session_cookie() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_name("app_session")
            .build()
            .await
            .unwrap();

        let token = generate_token();
        let set = ath.session_cookie(&token);
        let clear = ath.clear_session_cookie();

        // Both must share the same cookie name prefix so the browser matches them.
        assert!(set.starts_with("app_session="));
        assert!(clear.starts_with("app_session=;"));
        assert!(clear.contains("; Path=/"));
        assert!(clear.contains("; Max-Age=0"));
    }

    #[tokio::test]
    async fn clear_session_cookie_with_domain_and_no_secure() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_name("my_session")
            .cookie_secure(false)
            .cookie_domain("example.com")
            .build()
            .await
            .unwrap();

        let cookie = ath.clear_session_cookie();
        assert!(cookie.starts_with("my_session=;"));
        assert!(cookie.contains("; Max-Age=0"));
        assert!(cookie.contains("; Domain=example.com"));
        assert!(!cookie.contains("; Secure"));
    }

    #[tokio::test]
    async fn parse_session_cookie_uses_config() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_name("custom")
            .build()
            .await
            .unwrap();

        let header = "custom=abc123; other=xyz";
        let result = ath.parse_session_cookie(header);

        assert!(result.is_some());
        assert_eq!(result.unwrap().as_str(), "abc123");
    }

    #[tokio::test]
    async fn build_with_bad_url_fails() {
        let result = AllowThemBuilder::new("not-a-url").build().await;

        assert!(result.is_err());
        assert!(matches!(result.err().unwrap(), BuildError::Database(_)));
    }

    #[tokio::test]
    async fn clone_shares_state() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();
        let ath2 = ath.clone();

        let email = Email::new("shared@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();

        let found = ath2.db().get_user(user.id).await;
        assert!(found.is_ok());
        assert_eq!(found.unwrap().id, user.id);
    }

    #[tokio::test]
    async fn signing_key_not_configured_returns_error() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();
        let result = ath.signing_key();
        assert!(matches!(
            result,
            Err(crate::error::AuthError::SigningKeyNotConfigured)
        ));
    }

    #[tokio::test]
    async fn base_url_not_configured_returns_error() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();
        let result = ath.base_url();
        assert!(matches!(
            result,
            Err(crate::error::AuthError::BaseUrlNotConfigured)
        ));
    }

    #[tokio::test]
    async fn base_url_configured_returns_value() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .base_url("https://auth.example.com")
            .build()
            .await
            .unwrap();
        let result = ath.base_url();
        assert!(matches!(result, Ok("https://auth.example.com")));
    }
}
