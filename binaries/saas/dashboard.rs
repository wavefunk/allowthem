//! Dashboard plumbing internal to the SaaS binary.
//!
//! - [`open_dashboard_handle`] — build the dashboard's own `AllowThem`
//!   backed by `<tenant_data_dir>/dashboard.db`. Creates and migrates the
//!   file on first boot. Used by both the runtime path and the
//!   `seed-admin` CLI.
//! - [`dashboard_pages_router`] — composes the dashboard-specific pages
//!   (signup + quickstart in 99c.2; app CRUD, super-admin in 99c.3+).
//! - Submodules for the user-facing onboarding surface live alongside.

pub mod admin;
pub mod applications;
pub mod audit;
pub mod auth_helpers;
pub mod extractors;
pub mod nav;
pub mod permissions;
pub mod quickstart;
pub mod quickstart_cache;
pub mod roles;
pub mod settings_api_keys;
pub mod settings_billing;
pub mod settings_general;
pub mod settings_team;
pub mod signup;
pub mod state;
pub mod stubs;
pub mod templates;
pub mod users;

#[cfg(test)]
mod integration_tests;

use std::path::Path;
use std::time::Duration;

use axum::Router;
use eyre::Result;

use allowthem_core::{AllowThem, AllowThemBuilder};
use allowthem_saas::dashboard_cookie_name;

// Re-exports — `extractors::*` and `state::DashboardRouterState` start
// being consumed by the application handlers in Step 8. Until then they
// are reachable via their submodule paths (e.g. `dashboard::extractors::HtmlForm`).
pub use quickstart_cache::{QuickstartCache, QuickstartEntry};
pub use state::SignupState;
pub use templates::build_dashboard_env;

/// Open `<tenant_data_dir>/dashboard.db` (creating + migrating if missing) and
/// build the dashboard's `AllowThem` handle.
///
/// `__Host-` cookie attributes follow from `cookie_name` + `cookie_secure` +
///   the absence of `cookie_domain`; see `crates/saas/dashboard.rs` for the
///   rationale. The dev/prod switch on the prefix lives in
///   `allowthem_saas::dashboard_cookie_name`.
pub async fn open_dashboard_handle(
    tenant_data_dir: &Path,
    base_domain: &str,
    is_production: bool,
    mfa_key: [u8; 32],
    signing_key: [u8; 32],
    csrf_key: [u8; 32],
) -> Result<AllowThem> {
    let path = tenant_data_dir.join("dashboard.db");
    let pool = sqlx::SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename(&path)
            .create_if_missing(true)
            .pragma("foreign_keys", "ON")
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_millis(5000)),
    )
    .await?;

    let ath = AllowThemBuilder::with_pool(pool)
        .mfa_key(mfa_key)
        .signing_key(signing_key)
        .csrf_key(csrf_key)
        .base_url(format!("https://{base_domain}"))
        .cookie_name(dashboard_cookie_name(is_production))
        .cookie_secure(is_production)
        .build()
        .await?;
    Ok(ath)
}

/// Dashboard-only routes (application CRUD, user management, audit log).
///
/// `csrf_middleware` is layered on the whole composed router so every POST
/// handler is covered without per-sub-router wiring.
pub fn dashboard_pages_router(state: state::DashboardRouterState) -> Router {
    Router::new()
        .merge(applications::application_routes())
        .merge(audit::audit_routes())
        .merge(users::user_routes())
        .layer(axum::middleware::from_fn(
            allowthem_server::csrf::csrf_middleware,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::sessions::generate_token;

    #[tokio::test]
    async fn dashboard_handle_emits_host_prefixed_cookie_in_prod() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ath = open_dashboard_handle(
            dir.path(),
            "example.com",
            true,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        )
        .await
        .expect("dashboard handle");

        let token = generate_token();
        let cookie = ath.session_cookie(&token);
        assert!(
            cookie.starts_with("__Host-allowthem_dashboard_session="),
            "expected __Host- prefix, got: {cookie}",
        );
        assert!(
            cookie.contains("; Secure"),
            "Secure flag required: {cookie}"
        );
        assert!(
            !cookie.contains("Domain="),
            "no Domain= attribute allowed for __Host-: {cookie}",
        );
    }

    #[tokio::test]
    async fn dashboard_handle_dev_uses_plain_name() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ath = open_dashboard_handle(
            dir.path(),
            "example.com",
            false,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        )
        .await
        .expect("dashboard handle");
        let token = generate_token();
        let cookie = ath.session_cookie(&token);
        assert!(
            cookie.starts_with("allowthem_dashboard_session="),
            "expected plain dashboard cookie name in dev: {cookie}",
        );
        assert!(
            !cookie.contains("; Secure"),
            "Secure must NOT be set in dev: {cookie}"
        );
    }

    /// Paths the dashboard pages router owns. 99c.2 added the onboarding
    /// surface; 99c.3 added the tenant-scoped `/t/{slug}/applications`
    /// shape. 99c.4/.5/.6 extend this list as their routes ship.
    ///
    /// The path-overlap guard test (`dashboard_paths_do_not_overlap_with_auth_router`)
    /// uses concrete-segment URIs so axum's path matcher resolves them
    /// without parsing fully-qualified UUIDs.
    pub(super) const DASHBOARD_PATHS: &[&str] = &[
        // 99c.2 onboarding surface — handled by signup_routes / quickstart_routes,
        // not by dashboard_pages_router. Listed here so the auth-router
        // overlap test still asserts the shared auth router doesn't
        // accidentally claim them.
        "/signup",
        "/signup/slug-check",
        "/quickstart/test-token",
        "/quickstart/test-token/dismiss",
        // 99c.3 application CRUD.
        "/t/test-slug/applications",
        "/t/test-slug/applications/new",
        "/t/test-slug/applications/00000000-0000-0000-0000-000000000000",
        "/t/test-slug/applications/00000000-0000-0000-0000-000000000000/edit",
        "/t/test-slug/applications/00000000-0000-0000-0000-000000000000/regenerate-secret",
        "/t/test-slug/applications/00000000-0000-0000-0000-000000000000/delete",
        // 99c.5 audit log.
        "/t/test-slug/audit",
        "/t/test-slug/audit/export.csv",
        // 99c.4 user management.
        "/t/test-slug/users",
        "/t/test-slug/users/00000000-0000-0000-0000-000000000000",
        "/t/test-slug/users/00000000-0000-0000-0000-000000000000/block",
        "/t/test-slug/users/00000000-0000-0000-0000-000000000000/unblock",
        "/t/test-slug/users/00000000-0000-0000-0000-000000000000/force-password-reset",
        "/t/test-slug/users/00000000-0000-0000-0000-000000000000/revoke-sessions",
        "/t/test-slug/users/00000000-0000-0000-0000-000000000000/delete",
        "/t/test-slug/users/00000000-0000-0000-0000-000000000000/roles",
        "/t/test-slug/users/00000000-0000-0000-0000-000000000000/roles/00000000-0000-0000-0000-000000000001/remove",
        "/t/test-slug/users/00000000-0000-0000-0000-000000000000/permissions",
        "/t/test-slug/users/00000000-0000-0000-0000-000000000000/permissions/00000000-0000-0000-0000-000000000001/remove",
    ];

    #[tokio::test]
    async fn dashboard_paths_do_not_overlap_with_auth_router() {
        // The shared auth router built by `AllRoutesBuilder::build_for_saas()`
        // must not handle any of the dashboard's own paths — that would
        // be a route collision that `Router::merge` panics on at boot.
        //
        // We don't build the auth router here (it requires templates and
        // a real `AllowThem`). Instead we spot-check the path *prefixes*
        // the auth router owns are disjoint from `DASHBOARD_PATHS` by
        // string match — sufficient for this guard, since axum-level
        // collision would manifest at boot anyway.
        let auth_owned_prefixes: &[&str] = &[
            "/login",
            "/logout",
            "/register",
            "/settings",
            "/mfa",
            "/oauth",
            "/.well-known",
            "/forgot-password",
            "/reset-password",
        ];
        for path in DASHBOARD_PATHS {
            for owned in auth_owned_prefixes {
                assert!(
                    !path.starts_with(owned),
                    "dashboard path {path} overlaps with auth-owned prefix {owned}",
                );
            }
        }
    }
}
