use std::sync::Arc;

use chrono::Duration;
use sqlx::SqlitePool;

use crate::db::Db;
use crate::error::AuthError;
use crate::sessions::{self, SessionConfig};
use crate::types::SessionToken;

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
            }),
        })
    }
}

struct Inner {
    db: Db,
    session_config: SessionConfig,
    cookie_domain: String,
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
        assert!(matches!(result.unwrap_err(), BuildError::Database(_)));
    }

    #[tokio::test]
    async fn clone_shares_state() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();
        let ath2 = ath.clone();

        let email = Email::new("shared@example.com".into()).unwrap();
        let user = ath.db().create_user(email, "password123", None).await.unwrap();

        let found = ath2.db().get_user(user.id).await;
        assert!(found.is_ok());
        assert_eq!(found.unwrap().id, user.id);
    }
}
