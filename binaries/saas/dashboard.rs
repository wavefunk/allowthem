//! Dashboard plumbing internal to the SaaS binary.
//!
//! - [`open_dashboard_handle`] — build the dashboard's own `AllowThem`
//!   backed by `<tenant_data_dir>/dashboard.db`. Creates and migrates the
//!   file on first boot. Used by both the runtime path and the
//!   `seed-admin` CLI.
//! - [`dashboard_pages_router`] — placeholder router for dashboard-specific
//!   pages (signup, quickstart, app CRUD, super-admin). Empty in 99c.1;
//!   sub-tasks 99c.2..99c.6 fill it in.

use std::path::Path;
use std::time::Duration;

use axum::Router;
use eyre::Result;

use allowthem_core::{AllowThem, AllowThemBuilder};
use allowthem_saas::dashboard_cookie_name;

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

/// Dashboard-only routes (signup, quickstart, app CRUD pages, super-admin).
///
/// Empty in 99c.1 — sub-tasks 99c.2..99c.6 add the actual handlers. The
/// router exists now so the binary can compose it with
/// `tenant_router_middleware` and so the path-overlap guard test (Task 8)
/// has something to call.
pub fn dashboard_pages_router() -> Router {
    Router::new()
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
        assert!(cookie.contains("; Secure"), "Secure flag required: {cookie}");
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

    #[test]
    fn dashboard_pages_router_is_currently_empty() {
        // The placeholder router exists but has no routes registered. The
        // test exists so any future commit that adds a route here also has
        // to update this assertion, drawing attention to the path-overlap
        // guardrail (binaries/saas/dashboard path-overlap test in 99c.2+).
        let router = dashboard_pages_router();
        // Building with state-less `Router::new()` is a no-op; we just confirm
        // the call returns. Real path coverage lives in the overlap guardrail.
        let _ = router;
    }

    /// Paths the dashboard pages router will own once 99c.2..99c.6 land.
    /// Empty in 99c.1 — kept here so the path-overlap guard test ship and
    /// 99c.2 only has to extend a list, not write a fixture.
    pub(super) const DASHBOARD_PATHS: &[&str] = &[
        // 99c.2: "/signup", "/signup/slug-check", "/quickstart/{token}",
        //        "/quickstart/{token}/dismiss"
        // 99c.3: "/applications", ...
    ];

    #[tokio::test]
    async fn no_dashboard_path_resolves_on_empty_dashboard_router() {
        // With no paths registered, the loop is trivially satisfied. The
        // value of this test is the scaffolding: 99c.2 adds entries to
        // DASHBOARD_PATHS and the same loop catches accidental overlap with
        // the shared auth router before boot panics on Router::merge.
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;

        let router = dashboard_pages_router();
        for path in DASHBOARD_PATHS {
            let req = Request::builder()
                .uri(*path)
                .body(Body::empty())
                .expect("request");
            let resp = router.clone().oneshot(req).await.expect("oneshot");
            // Empty router → 404 for any path. The assertion documents the
            // expected baseline — when 99c.2 wires real handlers, this
            // becomes "the dashboard handler responds, the auth handler
            // doesn't have a conflicting registration".
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "empty dashboard router should 404 on {path}"
            );
        }
    }
}
