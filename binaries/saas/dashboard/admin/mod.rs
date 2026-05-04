//! Super-admin panel — platform-wide overview, tenant management, and system health.
//!
//! All routes require the `super_admin` role (enforced by `RequireSuperAdmin`).
//! Steps 7-12 of 99c.6 fill in the stub handlers here.
//!
//! Route prefix `/admin` is nested by Step 14 into `dashboard_pages_router`.
//! Reserved slug enforcement (`admin` is blocked) ensures no tenant can claim
//! this path.

pub mod health;
pub mod revenue;
pub mod tenants;
pub mod usage;

use axum::Router;
use axum::routing::{get, post};

use crate::dashboard::state::DashboardRouterState;

pub fn admin_routes() -> Router<DashboardRouterState> {
    Router::new()
        .route("/", get(tenants::overview))
        .route("/tenants/{id}", get(tenants::detail))
        .route("/tenants/{id}/suspend", post(tenants::suspend))
        .route("/tenants/{id}/unsuspend", post(tenants::unsuspend))
        .route("/tenants/{id}/delete", post(tenants::delete))
        .route("/tenants/{id}/change-plan", post(tenants::change_plan))
        .route("/usage", get(usage::page))
        .route("/revenue", get(revenue::page))
        .route("/health", get(health::page))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::Arc;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, header};
    use tower::ServiceExt;

    use allowthem_core::sessions::{generate_token, hash_token};
    use allowthem_core::types::{RoleName, UserId};
    use allowthem_core::{Email, EmailSender, LogEmailSender};
    use allowthem_saas::{ControlDb, HandleCache, SlugCache, TenantBuilderConfig, TenantId};

    use crate::dashboard::open_dashboard_handle;
    use crate::dashboard::quickstart_cache::QuickstartCache;
    use crate::dashboard::state::{DashboardRouterState, SignupState};
    use crate::dashboard::templates::build_dashboard_env;

    const BASE_DOMAIN: &str = "example.com";

    /// Test fixture for super-admin panel tests.
    ///
    /// Holds a fully wired admin router app backed by in-memory DBs, plus a
    /// pre-authenticated super-admin session cookie.
    pub struct Fixture {
        pub app: Router,
        pub state: DashboardRouterState,
        /// Cookie header value (e.g. `allowthem_dashboard_session=abc...`)
        /// ready to pass directly to a `Cookie:` header.
        pub session_cookie: String,
        pub super_admin_id: UserId,
        pub _dir: tempfile::TempDir,
    }

    impl Fixture {
        pub async fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let data_dir = dir.path().to_path_buf();

            // Dashboard AllowThem — backed by a file in the tempdir so that
            // `open_dashboard_handle` can create + migrate `dashboard.db`.
            let dashboard_ath = open_dashboard_handle(
                &data_dir,
                BASE_DOMAIN,
                false,
                [1u8; 32],
                [2u8; 32],
                [3u8; 32],
            )
            .await
            .expect("dashboard handle");

            // Create a super-admin user in the dashboard DB.
            let email = Email::new("superadmin@example.com".to_owned()).expect("email");
            let user = dashboard_ath
                .db()
                .create_user(email, "passw0rd!", None, None)
                .await
                .expect("create user");

            // Assign the super_admin role.
            let role_name = RoleName::new("super_admin");
            let role = dashboard_ath
                .db()
                .create_role(&role_name, None)
                .await
                .expect("create role");
            dashboard_ath
                .db()
                .assign_role(&user.id, &role.id)
                .await
                .expect("assign role");

            // Create a session and derive the cookie header value.
            let token = generate_token();
            let hash = hash_token(&token);
            let expires_at = chrono::Utc::now() + chrono::Duration::days(7);
            dashboard_ath
                .db()
                .create_session(user.id, hash, None, None, expires_at)
                .await
                .expect("create session");
            // `session_cookie()` returns a full `Set-Cookie` header value; strip
            // the directives so it can be used as a `Cookie:` request header.
            let set_cookie = dashboard_ath.session_cookie(&token);
            let cookie_header = set_cookie
                .split(';')
                .next()
                .expect("cookie value")
                .trim()
                .to_owned();

            // Control plane DB — in-memory, migrations run by ControlDb::new.
            let control_pool = sqlx::SqlitePool::connect("sqlite::memory:")
                .await
                .expect("control pool");
            let control_db = Arc::new(ControlDb::new(control_pool).await.expect("ControlDb::new"));

            let email_sender: Arc<dyn EmailSender> = Arc::new(LogEmailSender);

            let tenant_config = Arc::new(TenantBuilderConfig {
                mfa_key: [1u8; 32],
                signing_key: [2u8; 32],
                csrf_key: [3u8; 32],
                base_domain: BASE_DOMAIN.into(),
                is_production: false,
                email_sender: Some(email_sender.clone()),
                event_sink: None,
                mau_sink: None,
            });
            let signup_state = SignupState {
                ath: dashboard_ath,
                control_db: control_db.clone(),
                tenant_data_dir: data_dir.clone(),
                tenant_config: tenant_config.clone(),
                handle_cache: HandleCache::new(10),
                quickstart_cache: QuickstartCache::new(),
                base_domain: BASE_DOMAIN.into(),
                templates: build_dashboard_env(),
                email_sender,
                is_production: false,
            };

            let slug_cache = SlugCache::new(10, 60);
            let state = DashboardRouterState::from_signup(signup_state, slug_cache);

            // Build the admin router (handlers are stubs until Steps 7-12).
            let app = Router::new()
                .nest("/admin", super::admin_routes())
                .layer(axum::middleware::from_fn(
                    allowthem_server::csrf::csrf_middleware,
                ))
                .with_state(state.clone());

            Self {
                app,
                state,
                session_cookie: cookie_header,
                super_admin_id: user.id,
                _dir: dir,
            }
        }

        /// Provision a tenant in the control DB and create its SQLite file.
        ///
        /// Returns the `TenantId` of the provisioned tenant. `slug` must be a
        /// valid, non-reserved slug (e.g. `"acme"`, not `"admin"`).
        pub async fn seed_tenant(&self, name: &str, slug: &str) -> TenantId {
            let result = self
                .state
                .control_db
                .provision_tenant(
                    name.to_owned(),
                    slug.to_owned(),
                    "owner@example.com".to_owned(),
                    &self.state.tenant_data_dir,
                    &self.state.tenant_config,
                )
                .await
                .expect("provision_tenant");
            result
                .tenant
                .id_as_uuid()
                .map(TenantId::from)
                .expect("tenant id")
        }

        pub async fn get(&self, path: &str) -> axum::response::Response {
            let req = Request::builder()
                .method("GET")
                .uri(path)
                .header(header::HOST, BASE_DOMAIN)
                .header(header::COOKIE, &self.session_cookie)
                .body(Body::empty())
                .expect("build GET");
            self.app.clone().oneshot(req).await.expect("oneshot")
        }

        pub async fn post_form(
            &self,
            path: &str,
            form: &[(&str, &str)],
        ) -> axum::response::Response {
            let body = url_encode(form);
            let req = Request::builder()
                .method("POST")
                .uri(path)
                .header(header::HOST, BASE_DOMAIN)
                .header(header::COOKIE, &self.session_cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .expect("build POST");
            self.app.clone().oneshot(req).await.expect("oneshot")
        }
    }

    fn url_encode(pairs: &[(&str, &str)]) -> String {
        use std::fmt::Write;
        let mut out = String::new();
        for (i, (k, v)) in pairs.iter().enumerate() {
            if i > 0 {
                out.push('&');
            }
            for (s, is_key) in [(*k, true), (*v, false)] {
                for byte in s.bytes() {
                    if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                        out.push(byte as char);
                    } else if byte == b' ' {
                        out.push('+');
                    } else {
                        let _ = write!(out, "%{byte:02X}");
                    }
                }
                if is_key {
                    out.push('=');
                }
            }
        }
        out
    }

    // ---- Step 4 smoke test: verify the fixture builds without panicking ----

    #[tokio::test]
    async fn admin_fixture_builds_with_super_admin_session() {
        let fx = Fixture::new().await;
        assert!(!fx.session_cookie.is_empty(), "session cookie must be set");
        // Verify the super-admin user exists in the state.
        let has = fx
            .state
            .ath
            .db()
            .has_role(&fx.super_admin_id, &RoleName::new("super_admin"))
            .await
            .expect("has_role");
        assert!(has, "fixture user must hold super_admin role");
    }

    #[tokio::test]
    async fn seed_tenant_provisions_control_row() {
        let fx = Fixture::new().await;
        let tid = fx.seed_tenant("Acme Corp", "acme").await;
        // Confirm the tenant row exists in control.db.
        let meta = fx
            .state
            .control_db
            .tenant_meta_by_slug("acme")
            .await
            .expect("tenant_meta_by_slug");
        assert!(meta.is_some(), "tenant row must exist after seed_tenant");
        assert_eq!(meta.unwrap().id, tid);
    }
}
