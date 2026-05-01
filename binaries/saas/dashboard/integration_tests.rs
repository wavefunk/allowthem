//! End-to-end integration tests for the dashboard signup + quickstart
//! flow. Drives the full router stack (signup_routes + quickstart_routes
//! layered under tenant_router_middleware) via tower oneshot, mirroring
//! what `main.rs` mounts.

#![cfg(test)]

use std::sync::Arc;

use axum::Router;
use axum::body::{self, Body};
use axum::http::{HeaderValue, Request, StatusCode, header};
use dashmap::DashMap;
use tower::ServiceExt;

use allowthem_core::Email;
use allowthem_core::error::AuthError;
use allowthem_saas::{
    HandleCache, SlugCache, TenantBuilderConfig, TenantRouterState, tenant_router_middleware,
};

use super::quickstart::quickstart_routes;
use super::quickstart_cache::QuickstartCache;
use super::signup::signup_routes;
use super::state::SignupState;
use super::templates::build_dashboard_env;

const BASE_DOMAIN: &str = "example.com";

struct Fixture {
    app: Router,
    state: SignupState,
    _dir: tempfile::TempDir,
}

impl Fixture {
    async fn new() -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        let tenant_data_dir = dir.path().to_path_buf();

        let dashboard_ath = crate::dashboard::open_dashboard_handle(
            &tenant_data_dir,
            BASE_DOMAIN,
            false,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        )
        .await
        .expect("dashboard handle");

        // Control plane: in-memory + run migrations via ControlDb::new.
        let control_pool = sqlx::SqlitePool::connect("sqlite::memory:")
            .await
            .expect("control pool");
        let control_db = Arc::new(
            allowthem_saas::ControlDb::new(control_pool)
                .await
                .expect("ControlDb::new"),
        );

        let tenant_config = Arc::new(TenantBuilderConfig {
            mfa_key: [1u8; 32],
            signing_key: [2u8; 32],
            csrf_key: [3u8; 32],
            base_domain: BASE_DOMAIN.into(),
            is_production: false,
        });

        let handle_cache = HandleCache::new(10);
        let slug_cache = SlugCache::new(10, 60);

        let signup_state = SignupState {
            ath: dashboard_ath.clone(),
            control_db: control_db.clone(),
            tenant_data_dir: tenant_data_dir.clone(),
            tenant_config: tenant_config.clone(),
            handle_cache: handle_cache.clone(),
            quickstart_cache: QuickstartCache::new(),
            base_domain: BASE_DOMAIN.into(),
            templates: build_dashboard_env(),
            is_production: false,
        };

        let router_state = TenantRouterState {
            control_db: control_db.clone(),
            slug_cache,
            handle_cache,
            tenant_data_dir,
            config: tenant_config,
            seen_times: Arc::new(DashMap::new()),
            dashboard_handle: Some(dashboard_ath),
        };

        let onboarding = signup_routes(signup_state.clone())
            .merge(quickstart_routes(signup_state.clone()));
        let app = onboarding.layer(axum::middleware::from_fn_with_state(
            router_state,
            tenant_router_middleware,
        ));

        Self {
            app,
            state: signup_state,
            _dir: dir,
        }
    }

    /// Issue a GET against the app with the standard root host. Returns the
    /// raw response so callers can pluck headers + body.
    async fn get(&self, path: &str) -> axum::response::Response {
        let req = Request::builder()
            .method("GET")
            .uri(path)
            .header(header::HOST, BASE_DOMAIN)
            .body(Body::empty())
            .expect("build GET");
        self.app.clone().oneshot(req).await.expect("oneshot")
    }

    /// Issue a POST with a urlencoded form. Optionally attach a Cookie
    /// header (for sessions, CSRF carryover).
    async fn post_form(
        &self,
        path: &str,
        form: &[(&str, &str)],
        cookie: Option<&str>,
    ) -> axum::response::Response {
        let body = url_encode(form);
        let mut req = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::HOST, BASE_DOMAIN)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
        if let Some(c) = cookie {
            req = req.header(header::COOKIE, c);
        }
        let req = req.body(Body::from(body)).expect("build POST");
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
        for (s, kv) in [(*k, true), (*v, false)] {
            for byte in s.bytes() {
                if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
                    out.push(byte as char);
                } else if byte == b' ' {
                    out.push('+');
                } else {
                    let _ = write!(out, "%{byte:02X}");
                }
            }
            if kv {
                out.push('=');
            }
        }
    }
    out
}

/// Pull the pre-auth CSRF cookie + token by issuing a GET /signup. Used
/// to stand up POST flows that pass csrf_middleware.
async fn fetch_csrf(fx: &Fixture) -> (String, String) {
    let resp = fx.get("/signup").await;
    let cookie_header = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|hv| {
            hv.to_str()
                .ok()
                .filter(|s| s.starts_with("csrf_pre="))
                .map(str::to_owned)
        })
        .expect("csrf_pre cookie");
    let csrf_token = cookie_header
        .strip_prefix("csrf_pre=")
        .and_then(|rest| rest.split(';').next())
        .expect("csrf_pre value")
        .to_owned();
    // Cookie header on subsequent requests should send back name=value.
    let cookie_for_next = format!("csrf_pre={csrf_token}");
    (cookie_for_next, csrf_token)
}

fn signup_form<'a>(
    csrf_token: &'a str,
    email: &'a str,
    password: &'a str,
    tenant_name: &'a str,
    slug: &'a str,
) -> Vec<(&'a str, &'a str)> {
    vec![
        ("csrf_token", csrf_token),
        ("email", email),
        ("password", password),
        ("password_confirm", password),
        ("tenant_name", tenant_name),
        ("slug", slug),
    ]
}

async fn body_string(resp: axum::response::Response) -> String {
    let bytes = body::to_bytes(resp.into_body(), 1_000_000)
        .await
        .expect("body");
    String::from_utf8(bytes.to_vec()).expect("utf8")
}

// ----- Tests -----------------------------------------------------------------

#[tokio::test]
async fn get_signup_renders_form() {
    let fx = Fixture::new().await;
    let resp = fx.get("/signup").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let cache_control = resp
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        cache_control.contains("no-store"),
        "Cache-Control: no-store expected, got {cache_control:?}"
    );
    let body = body_string(resp).await;
    assert!(body.contains("Create your workspace"));
    assert!(body.contains("name=\"csrf_token\""));
}

#[tokio::test]
async fn signup_happy_path_creates_artifacts_and_redirects() {
    let fx = Fixture::new().await;
    let (cookie, csrf_token) = fetch_csrf(&fx).await;

    let form = signup_form(
        &csrf_token,
        "owner@acme.com",
        "supersecret",
        "Acme",
        "acme",
    );
    let resp = fx.post_form("/signup", &form, Some(&cookie)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        location.starts_with("/quickstart/"),
        "expected /quickstart/<token>, got {location}"
    );

    // Dashboard user, tenant, owner member all exist.
    let dashboard_user = fx
        .state
        .ath
        .db()
        .get_user_by_email(&Email::new("owner@acme.com".into()).unwrap())
        .await
        .expect("dashboard user");
    assert!(!dashboard_user.email_verified, "verification not yet sent");

    let tenant = fx
        .state
        .control_db
        .tenant_by_slug("acme")
        .await
        .unwrap()
        .expect("tenant");
    let (role,): (String,) = sqlx::query_as(
        "SELECT role FROM tenant_members WHERE tenant_id = ?1 AND email = ?2",
    )
    .bind(tenant.id.as_slice())
    .bind("owner@acme.com")
    .fetch_one(fx.state.control_db.pool())
    .await
    .unwrap();
    assert_eq!(role, "owner");
}

#[tokio::test]
async fn signup_slug_taken_compensates_dashboard_user() {
    let fx = Fixture::new().await;
    let (cookie1, csrf1) = fetch_csrf(&fx).await;

    // Pre-claim the slug with a first signup.
    let form1 = signup_form(&csrf1, "first@acme.com", "supersecret", "First", "acme");
    let resp1 = fx.post_form("/signup", &form1, Some(&cookie1)).await;
    assert_eq!(resp1.status(), StatusCode::SEE_OTHER);

    // Second signup with the same slug. New CSRF cookie because the post
    // session-mints a real session and changes the auth state — re-fetch.
    let (cookie2, csrf2) = fetch_csrf(&fx).await;
    let form2 = signup_form(&csrf2, "second@acme.com", "supersecret", "Second", "acme");
    let resp2 = fx.post_form("/signup", &form2, Some(&cookie2)).await;
    assert_eq!(resp2.status(), StatusCode::OK, "form re-render");

    let body = body_string(resp2).await;
    assert!(
        body.contains("workspace URL was just taken"),
        "expected slug-taken flash, body: {body}"
    );

    // Second user must NOT exist (compensation).
    let res = fx
        .state
        .ath
        .db()
        .get_user_by_email(&Email::new("second@acme.com".into()).unwrap())
        .await;
    assert!(
        matches!(res, Err(AuthError::NotFound)),
        "compensation must delete second dashboard user"
    );

    // Control plane has exactly one tenant.
    let tenants = fx.state.control_db.list_tenants().await.unwrap();
    assert_eq!(tenants.len(), 1);
}

#[tokio::test]
async fn signup_email_taken_renders_error() {
    let fx = Fixture::new().await;

    // Pre-create a dashboard user.
    fx.state
        .ath
        .db()
        .create_user(
            Email::new("dup@acme.com".into()).unwrap(),
            "supersecret",
            None,
            None,
        )
        .await
        .unwrap();

    let (cookie, csrf) = fetch_csrf(&fx).await;
    let form = signup_form(&csrf, "dup@acme.com", "supersecret", "Dup", "dup");
    let resp = fx.post_form("/signup", &form, Some(&cookie)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("If you already have one, log in"));

    // No tenant created.
    let tenants = fx.state.control_db.list_tenants().await.unwrap();
    assert!(tenants.is_empty());
}

#[tokio::test]
async fn signup_password_mismatch_renders_error() {
    let fx = Fixture::new().await;
    let (cookie, csrf) = fetch_csrf(&fx).await;
    let form = vec![
        ("csrf_token", csrf.as_str()),
        ("email", "x@example.com"),
        ("password", "supersecret"),
        ("password_confirm", "different"),
        ("tenant_name", "X"),
        ("slug", "xtest"),
    ];
    let resp = fx.post_form("/signup", &form, Some(&cookie)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Passwords do not match"));
}

#[tokio::test]
async fn slug_check_returns_taken_for_existing_slug() {
    let fx = Fixture::new().await;

    // Pre-claim "taken-slug" via dashboard_signup.
    let (cookie, csrf) = fetch_csrf(&fx).await;
    let form = signup_form(&csrf, "u@u.com", "supersecret", "Pre", "taken-slug");
    let _ = fx.post_form("/signup", &form, Some(&cookie)).await;

    let resp = fx.get("/signup/slug-check?slug=taken-slug").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Already taken"), "got: {body}");
}

#[tokio::test]
async fn slug_check_returns_reserved_for_admin() {
    let fx = Fixture::new().await;
    let resp = fx.get("/signup/slug-check?slug=admin").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Reserved"));
}

#[tokio::test]
async fn slug_check_returns_ok_for_new_slug() {
    let fx = Fixture::new().await;
    let resp = fx.get("/signup/slug-check?slug=fresh").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("available"));
}

#[tokio::test]
async fn quickstart_404_without_session() {
    let fx = Fixture::new().await;
    let resp = fx.get("/quickstart/anything").await;
    // Logged-out users → redirect to /login (303).
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(location.starts_with("/login"), "got {location}");
}

#[tokio::test]
async fn quickstart_renders_with_correct_session() {
    let fx = Fixture::new().await;
    let (cookie, csrf) = fetch_csrf(&fx).await;
    let form = signup_form(
        &csrf,
        "owner@acme.com",
        "supersecret",
        "Acme",
        "acme",
    );
    let resp = fx.post_form("/signup", &form, Some(&cookie)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("Location")
        .to_owned();

    // Carry the dashboard session cookie issued by the signup response.
    let session_cookie = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|hv| {
            hv.to_str()
                .ok()
                .filter(|s| s.starts_with("allowthem_dashboard_session="))
                .map(|s| s.split(';').next().unwrap_or("").to_owned())
        })
        .expect("session cookie");

    let req = Request::builder()
        .method("GET")
        .uri(&location)
        .header(header::HOST, BASE_DOMAIN)
        .header(header::COOKIE, HeaderValue::from_str(&session_cookie).unwrap())
        .body(Body::empty())
        .unwrap();
    let resp = fx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cache_control = resp
        .headers()
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(cache_control.contains("no-store"));
    let body = body_string(resp).await;
    assert!(body.contains("Your workspace is ready"));
    assert!(body.contains("Client ID"));
    assert!(body.contains("Client secret"));
    // The plaintext secret is in the page body.
    assert!(
        body.contains("data-secret"),
        "secret card marker should be present"
    );
}
