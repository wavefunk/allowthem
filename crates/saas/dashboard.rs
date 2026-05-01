//! Dashboard auth dogfooding primitives.
//!
//! The dashboard is *not* a tenant — it is the SaaS control plane's own UI,
//! backed by a dedicated `dashboard.db` and using the same allowthem auth
//! surface as everything else. This module exposes the cookie-name helper,
//! the [`DashboardState`] handle bundle, and the cross-DB signup primitive
//! ([`dashboard_signup`]) that the dashboard's HTTP handlers (in 99c.2)
//! call. The HTTP handlers stay thin glue; the cross-DB chain lives here.

use std::path::PathBuf;
use std::sync::Arc;

use allowthem_core::error::AuthError;
use allowthem_core::types::UserId;
use allowthem_core::{AllowThem, Email, User};

use crate::cache::HandleCache;
use crate::control_db::ControlDb;
use crate::error::SaasError;
use crate::tenants::{ProvisionResult, TenantBuilderConfig};

/// Cookie name for dashboard sessions.
///
/// Production uses the `__Host-` prefix, which forbids `Domain` and requires
/// `Secure` — both already true under SaaS deployment via Caddy (parent spec
/// §6.2). Dev keeps the plain name so HTTP localhost workflows work.
pub fn dashboard_cookie_name(is_production: bool) -> &'static str {
    if is_production {
        "__Host-allowthem_dashboard_session"
    } else {
        "allowthem_dashboard_session"
    }
}

/// Bundle of references the dashboard handlers need at runtime.
///
/// Built once at process startup (see `binaries/saas/main.rs`) and held in
/// process state for the life of the program. Cheap to clone — every field
/// is either an `Arc` or a clone-cheap moka cache handle.
#[derive(Clone)]
pub struct DashboardState {
    /// The dashboard's own AllowThem handle, backed by `dashboard.db`.
    pub ath: AllowThem,
    /// Control-plane DB — needed to look up tenants, members, and provision.
    pub control_db: Arc<ControlDb>,
    /// Tenant data dir + builder config — needed to call `provision_tenant`.
    pub tenant_data_dir: PathBuf,
    pub tenant_config: Arc<TenantBuilderConfig>,
    /// Shared with the tenant-router middleware so freshly provisioned
    /// tenants land in the cache immediately.
    pub handle_cache: HandleCache,
    /// Mirrors `TenantBuilderConfig.is_production`. Convenience for handlers
    /// that need to pick cookie names without dereferencing through `Arc`.
    pub is_production: bool,
}

/// Inputs to [`dashboard_signup`].
pub struct DashboardSignupParams {
    pub email: String,
    pub password: String,
    pub tenant_name: String,
    pub tenant_slug: String,
}

/// Outputs of a successful [`dashboard_signup`].
pub struct DashboardSignupResult {
    /// Newly created dashboard user (in `dashboard.db`).
    pub user: User,
    /// New tenant artifacts: `Tenant`, per-tenant `AllowThem`, default OIDC
    /// application's client_id and one-time client_secret.
    pub provision: ProvisionResult,
    /// `Set-Cookie` header value for the new dashboard session.
    pub set_cookie: String,
}

/// Errors discriminated by the signup HTTP handler.
#[derive(Debug, thiserror::Error)]
pub enum DashboardSignupError {
    #[error("invalid email")]
    InvalidEmail,
    #[error("email already in use")]
    EmailTaken,
    #[error("provision failed: {0}")]
    ProvisionFailed(SaasError),
    #[error(transparent)]
    Auth(AuthError),
}

/// Cross-DB signup chain.
///
/// 1. Create the dashboard user in `dashboard.db`. Surfaces duplicate-email
///    *before* any tenant artifacts exist (most common failure mode).
/// 2. Call `provision_tenant` — atomic in the control plane (inserts
///    `tenants` + `tenant_members(owner)` in one txn, creates `<uuid>.db`,
///    builds the per-tenant `AllowThem`, registers the default OIDC app).
/// 3. On step-2 failure, compensate by deleting the dashboard user from
///    step 1. Compensation failure is logged but does not mask the original
///    error — the user can retry with a different email.
/// 4. Mint a session cookie for the new dashboard user.
pub async fn dashboard_signup(
    state: &DashboardState,
    params: DashboardSignupParams,
) -> Result<DashboardSignupResult, DashboardSignupError> {
    // Step 1: validate + create dashboard user.
    let email = Email::new(params.email.clone()).map_err(|_| DashboardSignupError::InvalidEmail)?;

    let user = state
        .ath
        .db()
        .create_user(email.clone(), &params.password, None, None)
        .await
        .map_err(|e| match e {
            AuthError::Conflict(ref msg) if msg.contains("email") => {
                DashboardSignupError::EmailTaken
            }
            other => DashboardSignupError::Auth(other),
        })?;

    // Step 2: provision tenant + owner member (atomic in control plane).
    let provision = match state
        .control_db
        .provision_tenant(
            params.tenant_name,
            params.tenant_slug,
            email.as_str().to_owned(),
            &state.tenant_data_dir,
            &state.tenant_config,
        )
        .await
    {
        Ok(p) => p,
        Err(e) => {
            // Compensate: delete the dashboard user we created in step 1.
            // Delete cascades sessions / user_roles / user_permissions via FK,
            // so a retry with the same email works cleanly.
            if let Err(del_err) = state.ath.db().delete_user(user.id).await {
                tracing::error!(
                    user_id = %user.id, error = %del_err,
                    "dashboard_signup: rollback delete_user failed; orphan user"
                );
            }
            return Err(DashboardSignupError::ProvisionFailed(e));
        }
    };

    // Step 3: mint a session for the new user. AllowThem::create_session_cookie
    // (crates/core/handle.rs:349) returns LoginOutcome { user, token, set_cookie }.
    let outcome = state
        .ath
        .create_session_cookie(user.id)
        .await
        .map_err(DashboardSignupError::Auth)?;

    Ok(DashboardSignupResult {
        user: outcome.user,
        provision,
        set_cookie: outcome.set_cookie,
    })
}

/// Errors for [`provision_tenant_for_user`].
#[derive(Debug, thiserror::Error)]
pub enum ProvisionForUserError {
    #[error("dashboard user not found")]
    UserNotFound,
    #[error(transparent)]
    Provision(#[from] SaasError),
    #[error(transparent)]
    Auth(#[from] AuthError),
}

/// Provision a tenant for an *already-existing* dashboard user.
///
/// Used when an authenticated dashboard user creates a second workspace, or
/// after a previous signup partially failed. No compensation: if provisioning
/// fails, the dashboard user is unchanged.
pub async fn provision_tenant_for_user(
    state: &DashboardState,
    user_id: UserId,
    tenant_name: String,
    tenant_slug: String,
) -> Result<ProvisionResult, ProvisionForUserError> {
    let user = state
        .ath
        .db()
        .get_user(user_id)
        .await
        .map_err(|e| match e {
            AuthError::NotFound => ProvisionForUserError::UserNotFound,
            other => ProvisionForUserError::Auth(other),
        })?;

    let result = state
        .control_db
        .provision_tenant(
            tenant_name,
            tenant_slug,
            user.email.as_str().to_owned(),
            &state.tenant_data_dir,
            &state.tenant_config,
        )
        .await?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::AllowThemBuilder;
    use sqlx::SqlitePool;

    async fn test_dashboard_state() -> (DashboardState, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("tempdir");

        let dashboard_pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let ath = AllowThemBuilder::with_pool(dashboard_pool)
            .mfa_key([1u8; 32])
            .signing_key([2u8; 32])
            .csrf_key([3u8; 32])
            .base_url("https://example.com")
            .cookie_name(dashboard_cookie_name(false))
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let control_pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        let control_db = Arc::new(ControlDb::new(control_pool).await.unwrap());

        let state = DashboardState {
            ath,
            control_db,
            tenant_data_dir: dir.path().to_path_buf(),
            tenant_config: Arc::new(TenantBuilderConfig {
                mfa_key: [1u8; 32],
                signing_key: [2u8; 32],
                csrf_key: [3u8; 32],
                base_domain: "example.com".into(),
                is_production: false,
            }),
            handle_cache: HandleCache::new(10),
            is_production: false,
        };
        (state, dir)
    }

    #[test]
    fn dashboard_cookie_name_prod_uses_host_prefix() {
        assert_eq!(
            dashboard_cookie_name(true),
            "__Host-allowthem_dashboard_session"
        );
    }

    #[test]
    fn dashboard_cookie_name_dev_drops_prefix() {
        assert_eq!(dashboard_cookie_name(false), "allowthem_dashboard_session");
    }

    #[tokio::test]
    async fn signup_happy_path() {
        let (state, _dir) = test_dashboard_state().await;
        let result = dashboard_signup(
            &state,
            DashboardSignupParams {
                email: "owner@acme.com".into(),
                password: "supersecret".into(),
                tenant_name: "Acme".into(),
                tenant_slug: "acme".into(),
            },
        )
        .await
        .expect("signup");

        // Dashboard user exists.
        let email = Email::new("owner@acme.com".into()).unwrap();
        let dashboard_user = state.ath.db().get_user_by_email(&email).await.unwrap();
        assert_eq!(dashboard_user.id, result.user.id);

        // Tenant + owner member exist.
        let tenant = state
            .control_db
            .tenant_by_slug("acme")
            .await
            .unwrap()
            .unwrap();
        let (role, accepted_at): (String, Option<String>) = sqlx::query_as(
            "SELECT role, accepted_at FROM tenant_members WHERE tenant_id = ?1 AND email = ?2",
        )
        .bind(tenant.id.as_slice())
        .bind("owner@acme.com")
        .fetch_one(state.control_db.pool())
        .await
        .unwrap();
        assert_eq!(role, "owner");
        assert!(accepted_at.is_some());

        // Session cookie minted.
        assert!(result.set_cookie.contains("allowthem_dashboard_session="));
    }

    #[tokio::test]
    async fn signup_slug_conflict_compensates_dashboard_user() {
        let (state, _dir) = test_dashboard_state().await;

        // Pre-insert a tenant with the slug we'll race against. Easiest path:
        // run signup once with that slug, then signup again with a *different*
        // email to force step 2 to fail with SlugTaken.
        dashboard_signup(
            &state,
            DashboardSignupParams {
                email: "first@acme.com".into(),
                password: "supersecret".into(),
                tenant_name: "Acme".into(),
                tenant_slug: "acme".into(),
            },
        )
        .await
        .expect("first signup");

        let result = dashboard_signup(
            &state,
            DashboardSignupParams {
                email: "second@acme.com".into(),
                password: "supersecret".into(),
                tenant_name: "Acme Two".into(),
                tenant_slug: "acme".into(), // collide
            },
        )
        .await;
        let Err(err) = result else {
            panic!("second signup must fail");
        };
        assert!(matches!(
            err,
            DashboardSignupError::ProvisionFailed(SaasError::SlugTaken)
        ));

        // Compensation removed the second dashboard user.
        let email = Email::new("second@acme.com".into()).unwrap();
        let res = state.ath.db().get_user_by_email(&email).await;
        assert!(matches!(res, Err(AuthError::NotFound)));

        // Control plane has exactly one tenant.
        let tenants = state.control_db.list_tenants().await.unwrap();
        assert_eq!(tenants.len(), 1);
    }

    #[tokio::test]
    async fn signup_email_taken() {
        let (state, _dir) = test_dashboard_state().await;

        // Pre-insert a dashboard user.
        let email = Email::new("dup@acme.com".into()).unwrap();
        state
            .ath
            .db()
            .create_user(email, "pw123456", None, None)
            .await
            .unwrap();

        let result = dashboard_signup(
            &state,
            DashboardSignupParams {
                email: "dup@acme.com".into(),
                password: "anotherpw".into(),
                tenant_name: "Dup".into(),
                tenant_slug: "dup".into(),
            },
        )
        .await;
        let Err(err) = result else {
            panic!("expected EmailTaken");
        };
        assert!(matches!(err, DashboardSignupError::EmailTaken));

        // No tenant artifacts created.
        let tenants = state.control_db.list_tenants().await.unwrap();
        assert!(tenants.is_empty());
    }

    #[tokio::test]
    async fn signup_invalid_email() {
        let (state, _dir) = test_dashboard_state().await;
        let result = dashboard_signup(
            &state,
            DashboardSignupParams {
                email: "not-an-email".into(),
                password: "supersecret".into(),
                tenant_name: "X".into(),
                tenant_slug: "xyz".into(),
            },
        )
        .await;
        let Err(err) = result else {
            panic!("expected InvalidEmail");
        };
        assert!(matches!(err, DashboardSignupError::InvalidEmail));
    }

    #[tokio::test]
    async fn provision_tenant_for_user_happy_path() {
        let (state, _dir) = test_dashboard_state().await;
        let email = Email::new("alice@acme.com".into()).unwrap();
        let user = state
            .ath
            .db()
            .create_user(email, "supersecret", None, None)
            .await
            .unwrap();

        let result =
            provision_tenant_for_user(&state, user.id, "Alice Co".into(), "alice-co".into())
                .await
                .expect("provision_tenant_for_user");

        assert_eq!(result.tenant.slug, "alice-co");
        assert_eq!(result.tenant.owner_email, "alice@acme.com");
    }

    #[tokio::test]
    async fn provision_tenant_for_user_user_not_found() {
        let (state, _dir) = test_dashboard_state().await;
        let result =
            provision_tenant_for_user(&state, UserId::new(), "Ghost".into(), "ghost".into()).await;
        let Err(err) = result else {
            panic!("expected UserNotFound");
        };
        assert!(matches!(err, ProvisionForUserError::UserNotFound));
    }
}
