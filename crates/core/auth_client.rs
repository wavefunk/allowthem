use std::future::Future;
use std::pin::Pin;

use crate::error::AuthError;
use crate::handle::AllowThem;
use crate::types::{PermissionName, RoleName, SessionToken, User, UserId};

/// Convenience alias for boxed futures returned by `AuthClient` methods.
pub type AuthFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, AuthError>> + Send + 'a>>;

/// Abstraction over embedded and external authentication modes.
///
/// Consuming projects use this trait instead of `AllowThem` directly, enabling
/// a config-flag switch between embedded mode (local SQLite) and external mode
/// (OIDC/JWT, Block 11) without changing handler or middleware code.
///
/// All session validation, role/permission checks, and logout flow through
/// this trait. Login is intentionally excluded — embedded mode handles
/// credentials directly, external mode redirects to OIDC.
pub trait AuthClient: Send + Sync {
    /// Validate a session token and return the active user.
    ///
    /// Returns `Ok(None)` when the token is invalid, expired, or the user is
    /// inactive. Returns `Err` only on infrastructure failures (DB, network).
    fn validate_session<'a>(&'a self, token: &'a SessionToken) -> AuthFuture<'a, Option<User>>;

    /// Check whether a user has the given role.
    fn check_role<'a>(&'a self, user_id: &'a UserId, role: &'a RoleName) -> AuthFuture<'a, bool>;

    /// Check whether a user has the given permission (direct or via role).
    fn check_permission<'a>(
        &'a self,
        user_id: &'a UserId,
        permission: &'a PermissionName,
    ) -> AuthFuture<'a, bool>;

    /// Invalidate a session. Fire-and-forget — non-existent sessions are not errors.
    fn logout<'a>(&'a self, token: &'a SessionToken) -> AuthFuture<'a, ()>;

    /// The URL/path where users should be directed to log in.
    fn login_url(&self) -> &str;

    /// The cookie name used for session tokens.
    fn session_cookie_name(&self) -> &str;
}

/// `AuthClient` implementation backed by an embedded `AllowThem` handle.
///
/// Wraps an `AllowThem` and a login URL. Consuming projects that also need
/// direct `AllowThem` access (login flow, registration, cookie generation) can
/// keep a separate clone in their state — cloning `AllowThem` is cheap (Arc).
pub struct EmbeddedAuthClient {
    ath: AllowThem,
    login_url: String,
}

impl EmbeddedAuthClient {
    /// Create a new `EmbeddedAuthClient`.
    ///
    /// `login_url` is the local path (e.g. `"/login"`) where unauthenticated
    /// users should be redirected.
    pub fn new(ath: AllowThem, login_url: impl Into<String>) -> Self {
        Self {
            ath,
            login_url: login_url.into(),
        }
    }
}

impl AuthClient for EmbeddedAuthClient {
    fn validate_session<'a>(&'a self, token: &'a SessionToken) -> AuthFuture<'a, Option<User>> {
        Box::pin(async move {
            let ttl = self.ath.session_config().ttl;
            let session = match self.ath.db().validate_session(token, ttl).await? {
                Some(s) => s,
                None => return Ok(None),
            };
            match self.ath.db().get_user(session.user_id).await {
                Ok(user) if user.is_active => Ok(Some(user)),
                Ok(_) => Ok(None),                    // inactive
                Err(AuthError::NotFound) => Ok(None), // orphaned session
                Err(e) => Err(e),
            }
        })
    }

    fn check_role<'a>(&'a self, user_id: &'a UserId, role: &'a RoleName) -> AuthFuture<'a, bool> {
        Box::pin(async move { self.ath.db().has_role(user_id, role).await })
    }

    fn check_permission<'a>(
        &'a self,
        user_id: &'a UserId,
        permission: &'a PermissionName,
    ) -> AuthFuture<'a, bool> {
        Box::pin(async move { self.ath.db().has_permission(user_id, permission).await })
    }

    fn logout<'a>(&'a self, token: &'a SessionToken) -> AuthFuture<'a, ()> {
        Box::pin(async move {
            let _ = self.ath.db().delete_session(token).await?;
            Ok(())
        })
    }

    fn login_url(&self) -> &str {
        &self.login_url
    }

    fn session_cookie_name(&self) -> &str {
        self.ath.session_config().cookie_name
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use chrono::{Duration, Utc};

    use super::*;
    use crate::handle::AllowThemBuilder;
    use crate::sessions::{generate_token, hash_token};
    use crate::types::{Email, PermissionName, RoleName};

    async fn setup() -> EmbeddedAuthClient {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();
        EmbeddedAuthClient::new(ath, "/login")
    }

    #[tokio::test]
    async fn validate_session_valid_token_returns_user() {
        let client = setup().await;
        let email = Email::new("valid@example.com".into()).unwrap();
        let user = client
            .ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();

        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = Utc::now() + Duration::hours(24);
        client
            .ath
            .db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();

        let result = client.validate_session(&token).await.unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().email.as_str(), "valid@example.com");
    }

    #[tokio::test]
    async fn validate_session_expired_token_returns_none() {
        let client = setup().await;
        let email = Email::new("expired@example.com".into()).unwrap();
        let user = client
            .ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();

        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = Utc::now() - Duration::hours(1);
        client
            .ath
            .db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();

        let result = client.validate_session(&token).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn validate_session_invalid_token_returns_none() {
        let client = setup().await;
        let token = generate_token();
        let result = client.validate_session(&token).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn validate_session_inactive_user_returns_none() {
        let client = setup().await;
        let email = Email::new("inactive@example.com".into()).unwrap();
        let user = client
            .ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();

        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = Utc::now() + Duration::hours(24);
        client
            .ath
            .db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();

        client
            .ath
            .db()
            .update_user_active(user.id, false)
            .await
            .unwrap();

        let result = client.validate_session(&token).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn validate_session_deleted_user_returns_none() {
        let client = setup().await;
        let email = Email::new("deleted@example.com".into()).unwrap();
        let user = client
            .ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();

        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = Utc::now() + Duration::hours(24);
        client
            .ath
            .db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();

        client.ath.db().delete_user(user.id).await.unwrap();

        let result = client.validate_session(&token).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn check_role_returns_true_when_assigned() {
        let client = setup().await;
        let email = Email::new("roleuser@example.com".into()).unwrap();
        let user = client
            .ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();

        let rn = RoleName::new("admin");
        let role = client.ath.db().create_role(&rn, None).await.unwrap();
        client
            .ath
            .db()
            .assign_role(&user.id, &role.id)
            .await
            .unwrap();

        let result = client.check_role(&user.id, &rn).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn check_role_returns_false_when_not_assigned() {
        let client = setup().await;
        let email = Email::new("norole@example.com".into()).unwrap();
        let user = client
            .ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();

        let rn = RoleName::new("admin");
        let result = client.check_role(&user.id, &rn).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn check_permission_returns_true_direct() {
        let client = setup().await;
        let email = Email::new("permdirect@example.com".into()).unwrap();
        let user = client
            .ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();

        let pn = PermissionName::new("posts:write");
        let perm = client.ath.db().create_permission(&pn, None).await.unwrap();
        client
            .ath
            .db()
            .assign_permission_to_user(&user.id, &perm.id)
            .await
            .unwrap();

        let result = client.check_permission(&user.id, &pn).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn check_permission_returns_true_via_role() {
        let client = setup().await;
        let email = Email::new("permviarole@example.com".into()).unwrap();
        let user = client
            .ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();

        let rn = RoleName::new("editor");
        let role = client.ath.db().create_role(&rn, None).await.unwrap();

        let pn = PermissionName::new("posts:read");
        let perm = client.ath.db().create_permission(&pn, None).await.unwrap();
        client
            .ath
            .db()
            .assign_permission_to_role(&role.id, &perm.id)
            .await
            .unwrap();

        client
            .ath
            .db()
            .assign_role(&user.id, &role.id)
            .await
            .unwrap();

        let result = client.check_permission(&user.id, &pn).await.unwrap();
        assert!(result);
    }

    #[tokio::test]
    async fn check_permission_returns_false_when_missing() {
        let client = setup().await;
        let email = Email::new("noperm@example.com".into()).unwrap();
        let user = client
            .ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();

        let pn = PermissionName::new("posts:delete");
        let result = client.check_permission(&user.id, &pn).await.unwrap();
        assert!(!result);
    }

    #[tokio::test]
    async fn logout_deletes_session() {
        let client = setup().await;
        let email = Email::new("logout@example.com".into()).unwrap();
        let user = client
            .ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();

        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = Utc::now() + Duration::hours(24);
        client
            .ath
            .db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();

        client.logout(&token).await.unwrap();

        let result = client.validate_session(&token).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn logout_nonexistent_token_succeeds() {
        let client = setup().await;
        let token = generate_token();
        let result = client.logout(&token).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn login_url_returns_configured_path() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();
        let client = EmbeddedAuthClient::new(ath, "/login");
        assert_eq!(client.login_url(), "/login");
    }

    #[tokio::test]
    async fn session_cookie_name_returns_config_name() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();
        let client = EmbeddedAuthClient::new(ath, "/login");
        assert_eq!(client.session_cookie_name(), "allowthem_session");

        let ath_custom = AllowThemBuilder::new("sqlite::memory:")
            .cookie_name("my_session")
            .build()
            .await
            .unwrap();
        let client_custom = EmbeddedAuthClient::new(ath_custom, "/login");
        assert_eq!(client_custom.session_cookie_name(), "my_session");
    }

    // Verify it works as Arc<dyn AuthClient>
    #[tokio::test]
    async fn works_as_arc_dyn_auth_client() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();
        let _client: Arc<dyn AuthClient> = Arc::new(EmbeddedAuthClient::new(ath, "/login"));
    }
}
