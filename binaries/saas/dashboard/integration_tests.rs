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

        let email_sender: Arc<dyn allowthem_core::EmailSender> =
            Arc::new(allowthem_core::LogEmailSender);
        let signup_state = SignupState {
            ath: dashboard_ath.clone(),
            control_db: control_db.clone(),
            tenant_data_dir: tenant_data_dir.clone(),
            tenant_config: tenant_config.clone(),
            handle_cache: handle_cache.clone(),
            quickstart_cache: QuickstartCache::new(),
            base_domain: BASE_DOMAIN.into(),
            templates: build_dashboard_env(),
            email_sender,
            is_production: false,
        };

        let router_state = TenantRouterState {
            control_db: control_db.clone(),
            slug_cache: slug_cache.clone(),
            handle_cache,
            tenant_data_dir,
            config: tenant_config,
            seen_times: Arc::new(DashMap::new()),
            dashboard_handle: Some(dashboard_ath),
        };

        let onboarding =
            signup_routes(signup_state.clone()).merge(quickstart_routes(signup_state.clone()));
        let onboarding_with_middleware = onboarding.layer(axum::middleware::from_fn_with_state(
            router_state.clone(),
            tenant_router_middleware,
        ));

        let dashboard_router_state =
            crate::dashboard::state::DashboardRouterState::from_signup(
                signup_state.clone(),
                slug_cache.clone(),
            );
        let dashboard_pages =
            crate::dashboard::dashboard_pages_router(dashboard_router_state).layer(
                axum::middleware::from_fn_with_state(router_state, tenant_router_middleware),
            );

        let app = onboarding_with_middleware.merge(dashboard_pages);

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

    let form = signup_form(&csrf_token, "owner@acme.com", "supersecret", "Acme", "acme");
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
    let (role,): (String,) =
        sqlx::query_as("SELECT role FROM tenant_members WHERE tenant_id = ?1 AND email = ?2")
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
    let form = signup_form(&csrf, "owner@acme.com", "supersecret", "Acme", "acme");
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
        .header(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        )
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

// ----- Edge cases + security boundaries (Task #12 additions) ----------------

/// Reuse the post-signup session cookie + Location off a successful
/// signup response. Returns `(session_cookie_kv, quickstart_path)`.
async fn signup_and_get_session(fx: &Fixture, email: &str, slug: &str) -> (String, String) {
    let (cookie, csrf) = fetch_csrf(fx).await;
    let form = signup_form(&csrf, email, "supersecret", "Workspace", slug);
    let resp = fx.post_form("/signup", &form, Some(&cookie)).await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("Location")
        .to_owned();
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
    (session_cookie, location)
}

#[tokio::test]
async fn post_signup_without_csrf_token_is_rejected() {
    let fx = Fixture::new().await;
    // Don't fetch the csrf_pre cookie — submit POST cold. csrf_middleware
    // should reject because there's no double-submit cookie + matching form
    // token to verify.
    let form = signup_form("missing", "x@example.com", "supersecret", "X", "xtest");
    let resp = fx.post_form("/signup", &form, None).await;
    // csrf_middleware returns 403 on failure (see crates/server/csrf.rs).
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // Side effects: no dashboard user, no tenant.
    let res = fx
        .state
        .ath
        .db()
        .get_user_by_email(&Email::new("x@example.com".into()).unwrap())
        .await;
    assert!(matches!(res, Err(AuthError::NotFound)));
    let tenants = fx.state.control_db.list_tenants().await.unwrap();
    assert!(tenants.is_empty());
}

#[tokio::test]
async fn post_signup_with_mismatched_csrf_is_rejected() {
    let fx = Fixture::new().await;
    let (cookie, _real_csrf) = fetch_csrf(&fx).await;
    // Send a *different* csrf_token in the body than what csrf_pre cookie
    // carries — double-submit must fail.
    let form = signup_form("wrong-token", "y@example.com", "supersecret", "Y", "ytest");
    let resp = fx.post_form("/signup", &form, Some(&cookie)).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn slug_check_returns_invalid_for_bad_format() {
    let fx = Fixture::new().await;
    // Slug starts with digit → SaasError::SlugInvalid.
    let resp = fx.get("/signup/slug-check?slug=1abc").await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(
        body.contains("Use 3–40 lowercase letters"),
        "expected invalid-format fragment, got: {body}"
    );
}

#[tokio::test]
async fn get_signup_when_already_authenticated_redirects_to_root() {
    let fx = Fixture::new().await;
    let (session_cookie, _location) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    // Hit GET /signup again while signed in. The handler short-circuits to /.
    let req = Request::builder()
        .method("GET")
        .uri("/signup")
        .header(header::HOST, BASE_DOMAIN)
        .header(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        )
        .body(Body::empty())
        .unwrap();
    let resp = fx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(location, "/");
}

#[tokio::test]
async fn quickstart_404_for_other_users_token() {
    // Owner A signs up, gets quickstart token. Owner B signs up with a
    // different slug, gets B's session cookie. B uses A's token → 404.
    let fx = Fixture::new().await;
    let (_session_a, location_a) = signup_and_get_session(&fx, "a@example.com", "acme").await;
    let (session_b, _location_b) = signup_and_get_session(&fx, "b@example.com", "globex").await;

    // Use B's session cookie to GET A's quickstart URL.
    let req = Request::builder()
        .method("GET")
        .uri(&location_a)
        .header(header::HOST, BASE_DOMAIN)
        .header(header::COOKIE, HeaderValue::from_str(&session_b).unwrap())
        .body(Body::empty())
        .unwrap();
    let resp = fx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn quickstart_dismiss_evicts_and_subsequent_get_404s() {
    let fx = Fixture::new().await;
    let (session_cookie, location) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    // POST /quickstart/{token}/dismiss — need a fresh CSRF inside this
    // session because csrf_middleware now derives the token from the
    // session cookie (post-auth path).
    let token = location
        .strip_prefix("/quickstart/")
        .expect("path starts /quickstart/");
    let dismiss_path = format!("/quickstart/{token}/dismiss");

    // Pull the post-auth csrf_token by GET-ing the quickstart page; it
    // gets rendered into the dismiss form as a hidden input. We grep it
    // out of the body.
    let render_req = Request::builder()
        .method("GET")
        .uri(&location)
        .header(header::HOST, BASE_DOMAIN)
        .header(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        )
        .body(Body::empty())
        .unwrap();
    let render_resp = fx.app.clone().oneshot(render_req).await.unwrap();
    assert_eq!(render_resp.status(), StatusCode::OK);
    let body = body_string(render_resp).await;
    let csrf = extract_csrf_from_body(&body);

    let dismiss_req = Request::builder()
        .method("POST")
        .uri(&dismiss_path)
        .header(header::HOST, BASE_DOMAIN)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        )
        .body(Body::from(url_encode(&[("csrf_token", &csrf)])))
        .unwrap();
    let dismiss_resp = fx.app.clone().oneshot(dismiss_req).await.unwrap();
    assert_eq!(dismiss_resp.status(), StatusCode::SEE_OTHER);

    // The cache entry is gone — subsequent GET → 404.
    let after_req = Request::builder()
        .method("GET")
        .uri(&location)
        .header(header::HOST, BASE_DOMAIN)
        .header(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        )
        .body(Body::empty())
        .unwrap();
    let after_resp = fx.app.clone().oneshot(after_req).await.unwrap();
    assert_eq!(after_resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn quickstart_eviction_makes_subsequent_gets_404() {
    // Equivalent to the TTL case but driven through the public cache API
    // — exercising what would happen after the 10-min TTL elapses.
    let fx = Fixture::new().await;
    let (session_cookie, location) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    let token = location.trim_start_matches("/quickstart/");
    fx.state.quickstart_cache.evict(token).await;

    let req = Request::builder()
        .method("GET")
        .uri(&location)
        .header(header::HOST, BASE_DOMAIN)
        .header(
            header::COOKIE,
            HeaderValue::from_str(&session_cookie).unwrap(),
        )
        .body(Body::empty())
        .unwrap();
    let resp = fx.app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// Pull the value of `<input … name="csrf_token" value="…">` out of an HTML body.
fn extract_csrf_from_body(body: &str) -> String {
    let needle = "name=\"csrf_token\" value=\"";
    let start = body.find(needle).expect("csrf_token input present");
    let rest = &body[start + needle.len()..];
    let end = rest.find('"').expect("closing quote");
    rest[..end].to_owned()
}

// ---------------------------------------------------------------------------
// 99c.3 application management — integration tests
// ---------------------------------------------------------------------------

async fn get_authed(fx: &Fixture, path: &str, session_cookie: &str) -> axum::response::Response {
    let req = Request::builder()
        .method("GET")
        .uri(path)
        .header(header::HOST, BASE_DOMAIN)
        .header(header::COOKIE, session_cookie)
        .body(Body::empty())
        .expect("build GET");
    fx.app.clone().oneshot(req).await.expect("oneshot")
}

/// Authenticated GET form-page → extract the session-bound csrf token from
/// the rendered HTML. csrf_middleware derives the token from the session
/// cookie when one is present, so no separate `csrf_pre` cookie is involved.
async fn fetch_csrf_for_authed_form(fx: &Fixture, path: &str, session_cookie: &str) -> String {
    let resp = get_authed(fx, path, session_cookie).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();
    extract_csrf_from_body(body)
}

#[tokio::test]
async fn applications_list_for_owner_renders_with_create_button() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    let resp = get_authed(&fx, "/t/acme/applications", &session_cookie).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();
    assert!(
        html.contains("New application"),
        "owner sees the create button"
    );
    assert!(
        html.contains("Registered applications") || html.contains("No applications"),
        "list panel rendered"
    );
}

#[tokio::test]
async fn applications_list_for_unknown_slug_is_404() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    let resp = get_authed(&fx, "/t/zulu/applications", &session_cookie).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn applications_list_unauthenticated_redirects_to_login() {
    let fx = Fixture::new().await;
    let (_session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    let req = Request::builder()
        .method("GET")
        .uri("/t/acme/applications")
        .header(header::HOST, BASE_DOMAIN)
        .body(Body::empty())
        .expect("build GET");
    let resp = fx.app.clone().oneshot(req).await.expect("oneshot");
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert!(loc.starts_with("/login?next="), "redirect target: {loc}");
}

#[tokio::test]
async fn application_detail_unknown_uuid_redirects_to_list() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    let resp = get_authed(
        &fx,
        "/t/acme/applications/00000000-0000-0000-0000-000000000000",
        &session_cookie,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap();
    assert_eq!(loc, "/t/acme/applications");
}

#[tokio::test]
async fn application_detail_for_default_app_renders_client_id() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    let tenant = fx
        .state
        .control_db
        .tenant_by_slug("acme")
        .await
        .unwrap()
        .unwrap();
    let tenant_id = allowthem_saas::TenantId::from(tenant.id_as_uuid().unwrap());
    let ath = fx
        .state
        .handle_cache
        .get_or_init(tenant_id, async {
            allowthem_saas::build_handle_with_path(
                &tenant.db_path,
                &fx.state.tenant_data_dir,
                &fx.state.tenant_config,
                "acme",
            )
            .await
        })
        .await
        .expect("tenant handle");
    let apps = ath.db().list_applications().await.unwrap();
    let app = apps.first().expect("default app provisioned by signup");

    let resp = get_authed(
        &fx,
        &format!("/t/acme/applications/{}", app.id),
        &session_cookie,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let html = std::str::from_utf8(&bytes).unwrap();
    assert!(html.contains(app.client_id.as_str()));
    assert!(
        !html.contains("Save this client secret now"),
        "plain detail page must NOT show the one-time secret panel"
    );
}

#[tokio::test]
async fn create_application_records_audit_and_shows_secret() {
    let fx = Fixture::new().await;
    let (session_cookie, _location) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    let csrf = fetch_csrf_for_authed_form(&fx, "/t/acme/applications/new", &session_cookie).await;

    let form = vec![
        ("name", "Test App"),
        ("client_type", "confidential"),
        ("redirect_uris", "https://app.test/callback"),
        ("logo_url", ""),
        ("csrf_token", csrf.as_str()),
    ];
    let resp = fx
        .post_form("/t/acme/applications", &form, Some(&session_cookie))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();
    assert!(
        body.contains("Save this client secret now"),
        "create response must show the one-time secret panel"
    );
    assert!(body.contains("Test App"));

    // Audit row recorded on the control plane.
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM control_audit_events WHERE action = 'application.created'",
    )
    .fetch_one(fx.state.control_db.pool())
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn create_public_application_omits_secret_panel() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    let csrf = fetch_csrf_for_authed_form(&fx, "/t/acme/applications/new", &session_cookie).await;

    let form = vec![
        ("name", "SPA"),
        ("client_type", "public"),
        ("redirect_uris", "https://spa.test/callback"),
        ("logo_url", ""),
        ("csrf_token", csrf.as_str()),
    ];
    let resp = fx
        .post_form("/t/acme/applications", &form, Some(&session_cookie))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let bytes = body::to_bytes(resp.into_body(), 1024 * 1024).await.unwrap();
    let body = std::str::from_utf8(&bytes).unwrap();
    assert!(body.contains("SPA"));
    assert!(
        !body.contains("Save this client secret now"),
        "public client has no client_secret"
    );
    assert!(body.contains("Public"), "public type tag rendered");
}

#[tokio::test]
async fn create_application_without_csrf_is_rejected() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    let form = vec![
        ("name", "X"),
        ("client_type", "confidential"),
        ("redirect_uris", "https://app.test/callback"),
        ("logo_url", ""),
        ("csrf_token", "fake"),
    ];
    let resp = fx
        .post_form("/t/acme/applications", &form, Some(&session_cookie))
        .await;
    // csrf_middleware rejects: derived token from session ≠ "fake".
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}
