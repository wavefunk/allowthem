use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use sqlx::SqlitePool;

use crate::db::Db;
use crate::email::{EmailMessage, EmailSender, EmailTemplate, NoopEmailSender, fallback_username};
use crate::error::AuthError;
use crate::event_sink::{AuthEvent, EventSink, NoopEventSink};
use crate::sessions::{self, SessionConfig};
use crate::types::{Email, SessionToken, User, UserId};

/// Callback type for active authentication events.
///
/// Invoked after every active auth event (successful login, OAuth callback
/// completion, MFA/TOTP completion, OIDC access token issuance). Passive
/// events (session validation, token refresh) do **not** fire this.
///
/// The callback must not block. Use a channel-send if heavy work is needed.
/// Panics are caught and logged; they never propagate to the caller.
pub type OnUserActive = Arc<dyn Fn(UserId, DateTime<Utc>) + Send + Sync>;

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
    csrf_key: Option<[u8; 32]>,
    base_url: Option<String>,
    on_user_active: Option<OnUserActive>,
    email_sender: Option<Box<dyn EmailSender>>,
    event_sink: Option<Box<dyn EventSink>>,
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
            csrf_key: None,
            base_url: None,
            on_user_active: None,
            email_sender: None,
            event_sink: None,
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
            csrf_key: None,
            base_url: None,
            on_user_active: None,
            email_sender: None,
            event_sink: None,
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

    /// Set the HMAC key for session-bound CSRF token derivation.
    ///
    /// Required for `csrf_middleware` in `crates/server`. If not set,
    /// `csrf_middleware` returns 500. Use 32 random bytes distinct from
    /// `mfa_key` and `signing_key`.
    pub fn csrf_key(mut self, key: [u8; 32]) -> Self {
        self.csrf_key = Some(key);
        self
    }

    /// Register a callback invoked after every active authentication event.
    ///
    /// "Active" means: successful password login, OAuth callback completion,
    /// MFA/TOTP completion, and OIDC access token issuance (authorization code
    /// exchange). Session validation, token refresh, and API token checks do
    /// **not** fire the callback.
    ///
    /// The callback must not block. Use a channel-send if heavy work is needed.
    /// Panics inside the callback are caught, logged via `tracing::error!`, and
    /// never propagated to the caller.
    ///
    /// Primarily used by the SaaS binary to record MAU into the control plane.
    pub fn on_user_active(mut self, callback: OnUserActive) -> Self {
        self.on_user_active = Some(callback);
        self
    }

    /// Register the email sender used by every email-bearing flow
    /// (password reset, email verification, invitations, MFA recovery).
    ///
    /// Default is [`NoopEmailSender`], which silently drops messages — call
    /// this method for any production deployment. A `tracing::warn!` is
    /// emitted at build time if the default is left in place.
    ///
    /// Email flows that compose URLs (`send_password_reset_email`,
    /// `send_verification_email`) also require [`base_url`] to be set.
    ///
    /// [`base_url`]: AllowThemBuilder::base_url
    pub fn email_sender(mut self, sender: Box<dyn EmailSender>) -> Self {
        self.email_sender = Some(sender);
        self
    }

    /// Register the event sink that fires for every state-changing auth
    /// operation.
    ///
    /// Default is [`NoopEventSink`] (silent). The SaaS binary will register a
    /// sink that writes rows to `webhook_deliveries` for outbound HTTP delivery
    /// (epic 7xw.2). Embedded integrators that do not need webhook delivery can
    /// leave this unset.
    pub fn event_sink(mut self, sink: Box<dyn EventSink>) -> Self {
        self.event_sink = Some(sink);
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

        let email_sender = self.email_sender.unwrap_or_else(|| {
            tracing::warn!(
                "no email_sender configured; defaulting to NoopEmailSender — \
                 outgoing emails (password reset, verification, invitation, \
                 MFA recovery) will be silently dropped",
            );
            Box::new(NoopEmailSender)
        });

        let event_sink = self.event_sink.unwrap_or_else(|| Box::new(NoopEventSink));

        Ok(AllowThem {
            inner: Arc::new(Inner {
                db,
                session_config,
                cookie_domain: self.cookie_domain,
                mfa_key: self.mfa_key,
                signing_key: self.signing_key,
                csrf_key: self.csrf_key,
                base_url: self.base_url,
                on_user_active: self.on_user_active,
                email_sender,
                event_sink,
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
    csrf_key: Option<[u8; 32]>,
    base_url: Option<String>,
    on_user_active: Option<OnUserActive>,
    email_sender: Box<dyn EmailSender>,
    event_sink: Box<dyn EventSink>,
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

    pub fn csrf_key(&self) -> Result<&[u8; 32], AuthError> {
        self.inner
            .csrf_key
            .as_ref()
            .ok_or(AuthError::CsrfKeyNotConfigured)
    }

    /// Return a reference to the `on_user_active` callback, if configured.
    ///
    /// Used to pass the callback into free functions (e.g.
    /// `exchange_authorization_code`) that do not receive the full `AllowThem`
    /// handle.
    pub fn on_user_active(&self) -> Option<&OnUserActive> {
        self.inner.on_user_active.as_ref()
    }

    /// Borrow the configured email sender.
    ///
    /// Defaults to [`NoopEmailSender`] unless overridden via
    /// [`AllowThemBuilder::email_sender`].
    pub fn email_sender(&self) -> &dyn EmailSender {
        &*self.inner.email_sender
    }

    /// Borrow the configured event sink.
    ///
    /// Defaults to [`NoopEventSink`] unless overridden via
    /// [`AllowThemBuilder::event_sink`].
    pub fn event_sink(&self) -> &dyn EventSink {
        &*self.inner.event_sink
    }

    /// Emit an event to the configured sink.
    ///
    /// Awaits the sink's `emit` future. Returns when the sink finishes
    /// (typically a single local DB write or a noop). The sink contract
    /// forbids panics and errors; this method is unconditionally infallible.
    pub async fn emit_event(&self, event: AuthEvent) {
        self.event_sink().emit(&event).await;
    }

    // -------------------------------------------------------------------------
    // Email-sending helpers
    // -------------------------------------------------------------------------

    /// Send a password reset email to the given address.
    ///
    /// Creates a reset token, composes the reset URL from [`base_url`], and
    /// sends a `PasswordReset` template. Returns `Ok(())` silently if no user
    /// exists for that email (enumeration prevention). Requires [`base_url`] to
    /// be configured; returns `Err(BaseUrlNotConfigured)` otherwise.
    ///
    /// [`base_url`]: AllowThemBuilder::base_url
    pub async fn send_password_reset_email(&self, email: &Email) -> Result<(), AuthError> {
        let raw_token = match self.db().create_password_reset(email).await? {
            None => return Ok(()),
            Some(t) => t,
        };

        let username = match self.db().get_user_by_email(email).await {
            Ok(user) => fallback_username(&user),
            Err(_) => email
                .as_str()
                .split('@')
                .next()
                .unwrap_or("there")
                .to_owned(),
        };

        let reset_url = format!(
            "{}/auth/reset-password?token={}",
            self.base_url()?,
            raw_token
        );
        let message = EmailMessage {
            to: email.as_str().to_owned(),
            subject: "Reset your password".to_owned(),
            template: EmailTemplate::PasswordReset {
                url: reset_url,
                username,
            },
        };

        self.email_sender()
            .send(&message)
            .await
            .map_err(|e| AuthError::Email(e.to_string()))
    }

    /// Send an email verification link to the given user.
    ///
    /// Creates a verification token, composes the verification URL from
    /// [`base_url`], and sends an `EmailVerification` template. Requires
    /// [`base_url`] to be configured.
    ///
    /// [`base_url`]: AllowThemBuilder::base_url
    pub async fn send_verification_email(
        &self,
        user_id: UserId,
        email: &Email,
    ) -> Result<(), AuthError> {
        let raw_token = self.db().create_email_verification(user_id).await?;

        let username = match self.db().get_user(user_id).await {
            Ok(user) => fallback_username(&user),
            Err(_) => email
                .as_str()
                .split('@')
                .next()
                .unwrap_or("there")
                .to_owned(),
        };

        let verify_url = format!("{}/auth/verify-email?token={}", self.base_url()?, raw_token);
        let message = EmailMessage {
            to: email.as_str().to_owned(),
            subject: "Verify your email address".to_owned(),
            template: EmailTemplate::EmailVerification {
                url: verify_url,
                username,
            },
        };

        self.email_sender()
            .send(&message)
            .await
            .map_err(|e| AuthError::Email(e.to_string()))
    }

    /// Send an invitation email to the given address.
    ///
    /// Creates an invitation token in the database and sends an `Invitation`
    /// template. `invitation_url` must be pre-composed by the caller — the
    /// URL format varies by deployment (the saas binary uses
    /// `https://{base_domain}/invite/{token}`; standalone server may differ).
    /// `invited_by` is the `UserId` of the inviter; their display name is
    /// resolved from the database and used in the template. On lookup failure,
    /// falls back to `"your team"`.
    pub async fn send_invitation_email(
        &self,
        email: &Email,
        invitation_url: &str,
        invited_by: UserId,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), AuthError> {
        self.db()
            .create_invitation(Some(email), None, Some(invited_by), expires_at)
            .await?;

        let inviter_name = match self.db().get_user(invited_by).await {
            Ok(user) => fallback_username(&user),
            Err(_) => "your team".to_owned(),
        };

        let message = EmailMessage {
            to: email.as_str().to_owned(),
            subject: format!("You've been invited by {inviter_name}"),
            template: EmailTemplate::Invitation {
                url: invitation_url.to_owned(),
                invited_by: inviter_name,
            },
        };

        self.email_sender()
            .send(&message)
            .await
            .map_err(|e| AuthError::Email(e.to_string()))
    }

    /// Send MFA recovery codes to the given user via email.
    ///
    /// Looks up the user by `user_id` to determine recipient address and
    /// username. Sends an `MfaRecovery` template with the supplied codes. Does
    /// **not** write to the database — code generation and persistence are the
    /// caller's responsibility (see `Db::enable_mfa`).
    pub async fn send_mfa_recovery_email(
        &self,
        user_id: UserId,
        codes: Vec<String>,
    ) -> Result<(), AuthError> {
        let user = self.db().get_user(user_id).await?;
        let username = fallback_username(&user);

        let message = EmailMessage {
            to: user.email.as_str().to_owned(),
            subject: "Your MFA recovery codes".to_owned(),
            template: EmailTemplate::MfaRecovery { codes, username },
        };

        self.email_sender()
            .send(&message)
            .await
            .map_err(|e| AuthError::Email(e.to_string()))
    }

    /// Fire the `on_user_active` callback, if configured.
    ///
    /// Call this immediately after a session row or access token is durably
    /// written, for active auth events only. Panics from the callback are
    /// caught and logged; they never propagate to the caller.
    pub fn notify_user_active(&self, user_id: UserId) {
        let Some(cb) = self.inner.on_user_active.as_ref() else {
            return;
        };
        let now = Utc::now();
        let cb = cb.clone();
        if let Err(_payload) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || cb(user_id, now)))
        {
            tracing::error!(user_id = %user_id, "on_user_active callback panicked");
        }
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

    /// Authenticate with credentials and create a session.
    ///
    /// Returns `Err(AuthError::InvalidCredentials)` for any credential failure —
    /// unknown identifier, wrong password, no local password hash (SSO-only
    /// account), or inactive user — to prevent account enumeration.
    ///
    /// Records an `AuditEvent::Login` on success. IP and user-agent are not
    /// available at this layer; callers who need them in the audit log should
    /// use the low-level `Db` methods directly.
    pub async fn login(&self, identifier: &str, password: &str) -> Result<LoginOutcome, AuthError> {
        use crate::audit::AuditEvent;
        use crate::password::verify_password;

        let user = self
            .db()
            .find_for_login(identifier)
            .await
            .map_err(|e| match e {
                AuthError::NotFound => AuthError::InvalidCredentials,
                other => other,
            })?;

        if !user.is_active {
            return Err(AuthError::InvalidCredentials);
        }

        let hash = user
            .password_hash
            .as_ref()
            .ok_or(AuthError::InvalidCredentials)?;

        if !verify_password(password, hash)? {
            return Err(AuthError::InvalidCredentials);
        }

        let token = sessions::generate_token();
        let token_hash = sessions::hash_token(&token);
        let expires_at = Utc::now() + self.inner.session_config.ttl;
        self.db()
            .create_session(user.id, token_hash, None, None, expires_at)
            .await?;

        let _ = self
            .db()
            .log_audit(AuditEvent::Login, Some(&user.id), None, None, None, None)
            .await;

        self.notify_user_active(user.id);
        self.emit_event(AuthEvent::new(
            "session.created",
            Some(user.id),
            serde_json::json!({ "user_id": user.id }),
        ))
        .await;

        let set_cookie = self.session_cookie(&token);
        Ok(LoginOutcome {
            user,
            token,
            set_cookie,
        })
    }

    /// Create a session for an already-authenticated user.
    ///
    /// Does not verify credentials. Intended for use after OAuth, TOTP, or
    /// other non-password authentication flows. The calling flow is responsible
    /// for audit logging.
    pub async fn create_session_cookie(&self, user_id: UserId) -> Result<LoginOutcome, AuthError> {
        let user = self.db().get_user(user_id).await?;
        let token = sessions::generate_token();
        let token_hash = sessions::hash_token(&token);
        let expires_at = Utc::now() + self.inner.session_config.ttl;
        self.db()
            .create_session(user_id, token_hash, None, None, expires_at)
            .await?;

        self.notify_user_active(user_id);
        self.emit_event(AuthEvent::new(
            "session.created",
            Some(user_id),
            serde_json::json!({ "user_id": user_id }),
        ))
        .await;

        let set_cookie = self.session_cookie(&token);
        Ok(LoginOutcome {
            user,
            token,
            set_cookie,
        })
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
        let user = ath.db().create_user(email, "password123", None, None).await;
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
            .create_user(email, "password123", None, None)
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

    #[tokio::test]
    async fn login_success() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let email = Email::new("login@example.com".into()).unwrap();
        ath.db()
            .create_user(email, "secret", None, None)
            .await
            .unwrap();

        let outcome = ath.login("login@example.com", "secret").await.unwrap();
        assert_eq!(outcome.user.email.as_str(), "login@example.com");
        assert!(!outcome.token.as_str().is_empty());
        assert!(outcome.set_cookie.contains("allowthem_session="));
    }

    #[tokio::test]
    async fn login_wrong_password() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();

        let email = Email::new("wp@example.com".into()).unwrap();
        ath.db()
            .create_user(email, "correct", None, None)
            .await
            .unwrap();

        let result = ath.login("wp@example.com", "wrong").await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn login_unknown_identifier() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();

        let result = ath.login("nobody@example.com", "any").await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn login_inactive_user() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();

        let email = Email::new("inactive@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "secret", None, None)
            .await
            .unwrap();
        ath.db().update_user_active(user.id, false).await.unwrap();

        let result = ath.login("inactive@example.com", "secret").await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn login_no_password_hash() {
        use crate::types::UserId;

        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();

        // Insert a user directly with password_hash = NULL (SSO-only account).
        // UserId uses UUID v7; bind it properly so SQLx can round-trip it.
        let id = UserId::new();
        let now = chrono::Utc::now()
            .format("%Y-%m-%dT%H:%M:%S%.3fZ")
            .to_string();
        sqlx::query(
            "INSERT INTO allowthem_users \
             (id, email, username, password_hash, email_verified, is_active, created_at, updated_at) \
             VALUES (?, 'sso@example.com', NULL, NULL, 1, 1, ?, ?)",
        )
        .bind(id)
        .bind(&now)
        .bind(&now)
        .execute(ath.db().pool())
        .await
        .unwrap();

        let result = ath.login("sso@example.com", "any").await;
        assert!(matches!(result, Err(AuthError::InvalidCredentials)));
    }

    #[tokio::test]
    async fn create_session_cookie_success() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let email = Email::new("sess@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "secret", None, None)
            .await
            .unwrap();

        let outcome = ath.create_session_cookie(user.id).await.unwrap();
        assert_eq!(outcome.user.id, user.id);
        assert!(!outcome.token.as_str().is_empty());
        assert!(outcome.set_cookie.contains("allowthem_session="));

        // Session must exist in DB
        let session = ath.db().lookup_session(&outcome.token).await.unwrap();
        assert!(session.is_some());
    }

    #[tokio::test]
    async fn create_session_cookie_unknown_user() {
        use crate::types::UserId;

        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();

        let result = ath.create_session_cookie(UserId::new()).await;
        assert!(matches!(result, Err(AuthError::NotFound)));
    }

    // -- on_user_active callback tests ------------------------------------------

    #[tokio::test]
    async fn on_user_active_default_is_none() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();
        assert!(ath.on_user_active().is_none());
    }

    #[tokio::test]
    async fn on_user_active_builder_stores_callback() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        let counter = Arc::new(AtomicU64::new(0));
        let c = counter.clone();
        let cb: OnUserActive = Arc::new(move |_uid, _ts| {
            c.fetch_add(1, Ordering::Relaxed);
        });

        let ath = AllowThemBuilder::new("sqlite::memory:")
            .on_user_active(cb)
            .build()
            .await
            .unwrap();

        assert!(ath.on_user_active().is_some());
    }

    #[tokio::test]
    async fn on_user_active_fires_on_login_success() {
        use std::sync::{Arc, Mutex};

        let captured: Arc<Mutex<Vec<(UserId, DateTime<Utc>)>>> = Arc::new(Mutex::new(Vec::new()));
        let cap = captured.clone();
        let cb: OnUserActive = Arc::new(move |uid, ts| {
            cap.lock().unwrap().push((uid, ts));
        });

        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .on_user_active(cb)
            .build()
            .await
            .unwrap();

        let email = Email::new("active@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "hunter2", None, None)
            .await
            .unwrap();

        let before = Utc::now();
        ath.login("active@example.com", "hunter2").await.unwrap();
        let after = Utc::now();

        let events = captured.lock().unwrap();
        assert_eq!(events.len(), 1, "callback must fire exactly once");
        assert_eq!(events[0].0, user.id, "callback receives correct UserId");
        assert!(
            events[0].1 >= before && events[0].1 <= after,
            "callback timestamp must be within the test window"
        );
    }

    #[tokio::test]
    async fn on_user_active_no_fire_on_login_wrong_password() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        let counter = Arc::new(AtomicU64::new(0));
        let c = counter.clone();
        let cb: OnUserActive = Arc::new(move |_uid, _ts| {
            c.fetch_add(1, Ordering::Relaxed);
        });

        let ath = AllowThemBuilder::new("sqlite::memory:")
            .on_user_active(cb)
            .build()
            .await
            .unwrap();

        let email = Email::new("wrongpw@example.com".into()).unwrap();
        ath.db()
            .create_user(email, "correct", None, None)
            .await
            .unwrap();

        let _ = ath.login("wrongpw@example.com", "wrong").await;
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn on_user_active_no_fire_on_login_unknown_identifier() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        let counter = Arc::new(AtomicU64::new(0));
        let c = counter.clone();
        let cb: OnUserActive = Arc::new(move |_uid, _ts| {
            c.fetch_add(1, Ordering::Relaxed);
        });

        let ath = AllowThemBuilder::new("sqlite::memory:")
            .on_user_active(cb)
            .build()
            .await
            .unwrap();

        let _ = ath.login("nobody@example.com", "any").await;
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn on_user_active_no_fire_on_login_inactive_user() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        let counter = Arc::new(AtomicU64::new(0));
        let c = counter.clone();
        let cb: OnUserActive = Arc::new(move |_uid, _ts| {
            c.fetch_add(1, Ordering::Relaxed);
        });

        let ath = AllowThemBuilder::new("sqlite::memory:")
            .on_user_active(cb)
            .build()
            .await
            .unwrap();

        let email = Email::new("inact@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "secret", None, None)
            .await
            .unwrap();
        ath.db().update_user_active(user.id, false).await.unwrap();

        let _ = ath.login("inact@example.com", "secret").await;
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn on_user_active_no_fire_on_login_no_password_hash() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        let counter = Arc::new(AtomicU64::new(0));
        let c = counter.clone();
        let cb: OnUserActive = Arc::new(move |_uid, _ts| {
            c.fetch_add(1, Ordering::Relaxed);
        });

        let ath = AllowThemBuilder::new("sqlite::memory:")
            .on_user_active(cb)
            .build()
            .await
            .unwrap();

        let id = UserId::new();
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();
        sqlx::query(
            "INSERT INTO allowthem_users \
             (id, email, username, password_hash, email_verified, is_active, created_at, updated_at) \
             VALUES (?, 'sso2@example.com', NULL, NULL, 1, 1, ?, ?)",
        )
        .bind(id)
        .bind(&now)
        .bind(&now)
        .execute(ath.db().pool())
        .await
        .unwrap();

        let _ = ath.login("sso2@example.com", "any").await;
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn on_user_active_fires_on_create_session_cookie() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        let counter = Arc::new(AtomicU64::new(0));
        let c = counter.clone();
        let cb: OnUserActive = Arc::new(move |_uid, _ts| {
            c.fetch_add(1, Ordering::Relaxed);
        });

        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .on_user_active(cb)
            .build()
            .await
            .unwrap();

        let email = Email::new("csc@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "pass", None, None)
            .await
            .unwrap();

        ath.create_session_cookie(user.id).await.unwrap();
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn on_user_active_no_fire_on_create_session_cookie_unknown_user() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        let counter = Arc::new(AtomicU64::new(0));
        let c = counter.clone();
        let cb: OnUserActive = Arc::new(move |_uid, _ts| {
            c.fetch_add(1, Ordering::Relaxed);
        });

        let ath = AllowThemBuilder::new("sqlite::memory:")
            .on_user_active(cb)
            .build()
            .await
            .unwrap();

        let _ = ath.create_session_cookie(UserId::new()).await;
        assert_eq!(counter.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn on_user_active_no_fire_on_session_validation() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        let counter = Arc::new(AtomicU64::new(0));
        let c = counter.clone();
        let cb: OnUserActive = Arc::new(move |_uid, _ts| {
            c.fetch_add(1, Ordering::Relaxed);
        });

        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .on_user_active(cb)
            .build()
            .await
            .unwrap();

        let email = Email::new("passive@example.com".into()).unwrap();
        ath.db()
            .create_user(email, "pass", None, None)
            .await
            .unwrap();

        let outcome = ath.login("passive@example.com", "pass").await.unwrap();
        // Counter is 1 after the login fire.
        assert_eq!(counter.load(Ordering::Relaxed), 1);

        // Session validation is a passive event — counter must not change.
        let _ = ath
            .db()
            .validate_session(&outcome.token, Duration::hours(24))
            .await
            .unwrap();
        assert_eq!(
            counter.load(Ordering::Relaxed),
            1,
            "session validation must not fire callback"
        );
    }

    #[tokio::test]
    async fn on_user_active_panic_does_not_propagate() {
        let cb: OnUserActive = Arc::new(|_uid, _ts| {
            panic!("intentional test panic in on_user_active callback");
        });

        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .on_user_active(cb)
            .build()
            .await
            .unwrap();

        let email = Email::new("panic@example.com".into()).unwrap();
        ath.db()
            .create_user(email, "pass", None, None)
            .await
            .unwrap();

        // Suppress the default panic hook output so test output stays clean.
        let prev_hook = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let result = ath.login("panic@example.com", "pass").await;
        std::panic::set_hook(prev_hook);

        assert!(
            result.is_ok(),
            "panic in callback must not propagate to caller"
        );
    }

    // ---- EmailSender integration tests ----

    /// A test-only sender that captures every message delivered to it.
    struct CapturingSender(std::sync::Arc<std::sync::Mutex<Vec<crate::email::EmailMessage>>>);

    impl crate::email::EmailSender for CapturingSender {
        fn send<'a>(
            &'a self,
            message: &'a crate::email::EmailMessage,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), crate::error::AuthError>> + Send + 'a>,
        > {
            self.0.lock().unwrap().push(message.clone());
            Box::pin(std::future::ready(Ok(())))
        }
    }

    fn capturing_sender() -> (
        Box<dyn crate::email::EmailSender>,
        std::sync::Arc<std::sync::Mutex<Vec<crate::email::EmailMessage>>>,
    ) {
        let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let sender = CapturingSender(captured.clone());
        (Box::new(sender), captured)
    }

    /// A test-only sender that always returns an error.
    struct FailingSender;

    impl crate::email::EmailSender for FailingSender {
        fn send<'a>(
            &'a self,
            _message: &'a crate::email::EmailMessage,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<(), crate::error::AuthError>> + Send + 'a>,
        > {
            Box::pin(std::future::ready(Err(crate::error::AuthError::Email(
                "injected failure".into(),
            ))))
        }
    }

    async fn make_user_with_username(ath: &AllowThem, email_str: &str, username: Option<&str>) {
        let email = Email::new(email_str.into()).unwrap();
        ath.db()
            .create_user(
                email,
                "password",
                username.map(|s| crate::types::Username::new(s)),
                None,
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn email_sender_default_is_noop_and_succeeds() {
        // Build without email_sender — defaults to NoopEmailSender.
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .base_url("https://example.com")
            .build()
            .await
            .unwrap();

        // NoopEmailSender::send always returns Ok(()).
        let msg = crate::email::EmailMessage {
            to: "nobody@example.com".into(),
            subject: "test".into(),
            template: crate::email::EmailTemplate::PasswordReset {
                url: "https://example.com/reset".into(),
                username: "nobody".into(),
            },
        };
        let result = ath.email_sender().send(&msg).await;
        assert!(result.is_ok(), "NoopEmailSender must return Ok");
    }

    #[tokio::test]
    async fn email_sender_custom_sender_installed() {
        let (sender_box, captured) = capturing_sender();
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .base_url("https://example.com")
            .email_sender(sender_box)
            .build()
            .await
            .unwrap();

        let msg = crate::email::EmailMessage {
            to: "test@example.com".into(),
            subject: "subject".into(),
            template: crate::email::EmailTemplate::PasswordReset {
                url: "https://example.com/reset".into(),
                username: "test".into(),
            },
        };
        ath.email_sender().send(&msg).await.unwrap();
        assert_eq!(captured.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn send_password_reset_email_builds_correct_template() {
        let (sender_box, captured) = capturing_sender();
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .base_url("https://example.com")
            .email_sender(sender_box)
            .build()
            .await
            .unwrap();
        make_user_with_username(&ath, "reset@example.com", Some("alice")).await;

        let email = Email::new("reset@example.com".into()).unwrap();
        ath.send_password_reset_email(&email).await.unwrap();

        let msgs = captured.lock().unwrap();
        assert_eq!(msgs.len(), 1);
        let msg = &msgs[0];
        assert_eq!(msg.to, "reset@example.com");
        assert_eq!(msg.subject, "Reset your password");
        match &msg.template {
            crate::email::EmailTemplate::PasswordReset { url, username } => {
                assert!(
                    url.contains("https://example.com"),
                    "URL must contain base_url"
                );
                assert!(
                    url.contains("/auth/reset-password?token="),
                    "URL must have path"
                );
                assert_eq!(username, "alice");
            }
            other => panic!("expected PasswordReset template, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_verification_email_builds_correct_template() {
        let (sender_box, captured) = capturing_sender();
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .base_url("https://example.com")
            .email_sender(sender_box)
            .build()
            .await
            .unwrap();
        let email = Email::new("verify@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(
                email.clone(),
                "pass",
                Some(crate::types::Username::new("bob")),
                None,
            )
            .await
            .unwrap();

        ath.send_verification_email(user.id, &email).await.unwrap();

        let msgs = captured.lock().unwrap();
        assert_eq!(msgs.len(), 1);
        let msg = &msgs[0];
        assert_eq!(msg.to, "verify@example.com");
        assert_eq!(msg.subject, "Verify your email address");
        match &msg.template {
            crate::email::EmailTemplate::EmailVerification { url, username } => {
                assert!(url.contains("https://example.com"));
                assert!(url.contains("/auth/verify-email?token="));
                assert_eq!(username, "bob");
            }
            other => panic!("expected EmailVerification template, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_password_reset_email_username_fallback_uses_email_local_part() {
        let (sender_box, captured) = capturing_sender();
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .base_url("https://example.com")
            .email_sender(sender_box)
            .build()
            .await
            .unwrap();
        // Create user with no username — fallback must use email local part.
        make_user_with_username(&ath, "noname@example.com", None).await;

        let email = Email::new("noname@example.com".into()).unwrap();
        ath.send_password_reset_email(&email).await.unwrap();

        let msgs = captured.lock().unwrap();
        let msg = &msgs[0];
        match &msg.template {
            crate::email::EmailTemplate::PasswordReset { username, .. } => {
                assert_eq!(username, "noname", "must fall back to email local part");
            }
            other => panic!("expected PasswordReset, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sender_error_propagates_as_auth_error_email() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .base_url("https://example.com")
            .email_sender(Box::new(FailingSender))
            .build()
            .await
            .unwrap();
        make_user_with_username(&ath, "fail@example.com", Some("fail")).await;

        let email = Email::new("fail@example.com".into()).unwrap();
        let result = ath.send_password_reset_email(&email).await;
        assert!(
            matches!(result, Err(crate::error::AuthError::Email(_))),
            "sender error must surface as AuthError::Email"
        );
    }

    #[tokio::test]
    async fn send_password_reset_email_silent_on_unknown_email() {
        let (sender_box, captured) = capturing_sender();
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .base_url("https://example.com")
            .email_sender(sender_box)
            .build()
            .await
            .unwrap();

        let email = Email::new("ghost@example.com".into()).unwrap();
        let result = ath.send_password_reset_email(&email).await;
        assert!(result.is_ok(), "must return Ok for unknown email");
        assert!(
            captured.lock().unwrap().is_empty(),
            "no email must be sent for unknown address"
        );
    }

    #[tokio::test]
    async fn send_invitation_email_creates_invitation_and_sends() {
        use crate::types::UserId;

        let (sender_box, captured) = capturing_sender();
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .base_url("https://example.com")
            .email_sender(sender_box)
            .build()
            .await
            .unwrap();

        // Create the inviter.
        let inviter_email = Email::new("inviter@example.com".into()).unwrap();
        let inviter = ath
            .db()
            .create_user(
                inviter_email,
                "pass",
                Some(crate::types::Username::new("Alice")),
                None,
            )
            .await
            .unwrap();
        let inviter_id: UserId = inviter.id;

        let invitee = Email::new("invitee@example.com".into()).unwrap();
        let invite_url = "https://example.com/invite/tok123";
        let expires_at = chrono::Utc::now() + chrono::Duration::hours(48);

        ath.send_invitation_email(&invitee, invite_url, inviter_id, expires_at)
            .await
            .unwrap();

        // One email sent.
        let msgs = captured.lock().unwrap();
        assert_eq!(msgs.len(), 1);
        let msg = &msgs[0];
        assert_eq!(msg.to, "invitee@example.com");
        match &msg.template {
            crate::email::EmailTemplate::Invitation { url, invited_by } => {
                assert_eq!(url, invite_url);
                assert_eq!(invited_by, "Alice");
            }
            other => panic!("expected Invitation template, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_mfa_recovery_email_sends_codes_without_db_write() {
        let (sender_box, captured) = capturing_sender();
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .base_url("https://example.com")
            .email_sender(sender_box)
            .build()
            .await
            .unwrap();

        let email = Email::new("mfa@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(
                email,
                "pass",
                Some(crate::types::Username::new("carol")),
                None,
            )
            .await
            .unwrap();

        let codes = vec!["code-1".into(), "code-2".into(), "code-3".into()];
        ath.send_mfa_recovery_email(user.id, codes.clone())
            .await
            .unwrap();

        let msgs = captured.lock().unwrap();
        assert_eq!(msgs.len(), 1);
        let msg = &msgs[0];
        assert_eq!(msg.to, "mfa@example.com");
        assert_eq!(msg.subject, "Your MFA recovery codes");
        match &msg.template {
            crate::email::EmailTemplate::MfaRecovery {
                codes: sent_codes,
                username,
            } => {
                assert_eq!(sent_codes, &codes, "codes must be forwarded as-is");
                assert_eq!(username, "carol");
            }
            other => panic!("expected MfaRecovery template, got {other:?}"),
        }
    }
}
