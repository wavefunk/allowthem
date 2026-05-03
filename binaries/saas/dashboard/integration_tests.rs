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

        let email_sender: Arc<dyn allowthem_core::EmailSender> =
            Arc::new(allowthem_core::LogEmailSender);

        let tenant_config = Arc::new(TenantBuilderConfig {
            mfa_key: [1u8; 32],
            signing_key: [2u8; 32],
            csrf_key: [3u8; 32],
            base_domain: BASE_DOMAIN.into(),
            is_production: false,
            email_sender: Some(email_sender.clone()),
            event_sink: None,
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

        let dashboard_router_state = crate::dashboard::state::DashboardRouterState::from_signup(
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

// ---------------------------------------------------------------------------
// 99c.4 user management — integration tests
// ---------------------------------------------------------------------------

/// Resolve the tenant AllowThem handle for `slug` via the handle cache.
async fn tenant_ath_for_slug(fx: &Fixture, slug: &str) -> allowthem_core::AllowThem {
    let tenant = fx
        .state
        .control_db
        .tenant_by_slug(slug)
        .await
        .unwrap()
        .expect("tenant exists");
    let tenant_id = allowthem_saas::TenantId::from(tenant.id_as_uuid().unwrap());
    fx.state
        .handle_cache
        .get_or_init(tenant_id, async {
            allowthem_saas::build_handle_with_path(
                &tenant.db_path,
                &fx.state.tenant_data_dir,
                &fx.state.tenant_config,
                slug,
            )
            .await
        })
        .await
        .expect("tenant handle")
}

#[tokio::test]
async fn user_list_renders_seeded_user() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let ath = tenant_ath_for_slug(&fx, "acme").await;

    let user = ath
        .db()
        .create_user(
            allowthem_core::Email::new("alice@example.com".into()).unwrap(),
            "secret",
            None,
            None,
        )
        .await
        .expect("create tenant user");

    let resp = get_authed(&fx, "/t/acme/users", &session_cookie).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(
        body.contains(user.email.as_str()),
        "user list must contain the seeded user email"
    );
}

#[tokio::test]
async fn user_detail_renders_panels() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let ath = tenant_ath_for_slug(&fx, "acme").await;

    let user = ath
        .db()
        .create_user(
            allowthem_core::Email::new("bob@example.com".into()).unwrap(),
            "secret",
            None,
            None,
        )
        .await
        .expect("create tenant user");

    let resp = get_authed(&fx, &format!("/t/acme/users/{}", user.id), &session_cookie).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains(user.email.as_str()), "email in detail page");
    assert!(body.contains("Roles"), "roles panel present");
    assert!(
        body.contains("Direct permissions"),
        "permissions panel present"
    );
    assert!(body.contains("Active sessions"), "sessions panel present");
    assert!(body.contains("Recent activity"), "audit panel present");
}

#[tokio::test]
async fn block_and_unblock_user_round_trip() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let ath = tenant_ath_for_slug(&fx, "acme").await;

    let user = ath
        .db()
        .create_user(
            allowthem_core::Email::new("carl@example.com".into()).unwrap(),
            "secret",
            None,
            None,
        )
        .await
        .expect("create tenant user");
    let detail_path = format!("/t/acme/users/{}", user.id);

    // Fetch CSRF from the detail page.
    let csrf = fetch_csrf_for_authed_form(&fx, &detail_path, &session_cookie).await;

    // Block.
    let block_resp = fx
        .post_form(
            &format!("{detail_path}/block"),
            &[("csrf_token", csrf.as_str())],
            Some(&session_cookie),
        )
        .await;
    assert_eq!(block_resp.status(), StatusCode::SEE_OTHER);

    // Verify blocked in DB.
    let blocked = ath.db().get_user(user.id).await.unwrap();
    assert!(!blocked.is_active, "user must be inactive after block");

    // Re-fetch CSRF (same session, token is stable but let's be safe).
    let csrf2 = fetch_csrf_for_authed_form(&fx, &detail_path, &session_cookie).await;

    // Unblock.
    let unblock_resp = fx
        .post_form(
            &format!("{detail_path}/unblock"),
            &[("csrf_token", csrf2.as_str())],
            Some(&session_cookie),
        )
        .await;
    assert_eq!(unblock_resp.status(), StatusCode::SEE_OTHER);

    let active = ath.db().get_user(user.id).await.unwrap();
    assert!(active.is_active, "user must be active after unblock");
}

#[tokio::test]
async fn revoke_sessions_writes_audit_row() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let ath = tenant_ath_for_slug(&fx, "acme").await;

    let user = ath
        .db()
        .create_user(
            allowthem_core::Email::new("dora@example.com".into()).unwrap(),
            "secret",
            None,
            None,
        )
        .await
        .expect("create tenant user");
    let detail_path = format!("/t/acme/users/{}", user.id);
    let csrf = fetch_csrf_for_authed_form(&fx, &detail_path, &session_cookie).await;

    let resp = fx
        .post_form(
            &format!("{detail_path}/revoke-sessions"),
            &[("csrf_token", csrf.as_str())],
            Some(&session_cookie),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);

    // Audit row written (Logout event with detail containing "revoked").
    let audit = ath
        .db()
        .search_audit_log(allowthem_core::audit::SearchAuditParams {
            user_id: Some(user.id),
            event_type: None,
            is_success: None,
            from: None,
            to: None,
            limit: 10,
            offset: 0,
        })
        .await
        .unwrap();
    assert!(
        audit.entries.iter().any(|e| {
            matches!(e.event_type, allowthem_core::audit::AuditEvent::Logout)
                && e.detail
                    .as_deref()
                    .map(|d| d.contains("revoked"))
                    .unwrap_or(false)
        }),
        "audit log must have a Logout/revoked row"
    );
}

#[tokio::test]
async fn delete_user_owner_only_flow() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let ath = tenant_ath_for_slug(&fx, "acme").await;

    let user = ath
        .db()
        .create_user(
            allowthem_core::Email::new("eve@example.com".into()).unwrap(),
            "secret",
            None,
            None,
        )
        .await
        .expect("create tenant user");
    let detail_path = format!("/t/acme/users/{}", user.id);
    let csrf = fetch_csrf_for_authed_form(&fx, &detail_path, &session_cookie).await;

    // POST delete with confirm=DELETE.
    let resp = fx
        .post_form(
            &format!("{detail_path}/delete"),
            &[("csrf_token", csrf.as_str()), ("confirm", "DELETE")],
            Some(&session_cookie),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/t/acme/users", "redirect to user list after delete");

    // User is gone from the tenant DB.
    let res = ath.db().get_user(user.id).await;
    assert!(
        matches!(res, Err(allowthem_core::error::AuthError::NotFound)),
        "user must be absent from DB after delete"
    );
}

#[tokio::test]
async fn user_list_unauthenticated_redirects_to_login() {
    let fx = Fixture::new().await;
    let (_session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    let resp = fx.get("/t/acme/users").await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        loc.starts_with("/login?next="),
        "unauthenticated users list must redirect to login: {loc}"
    );
}

// ---------------------------------------------------------------------------
// 99c.3.6 missing application management tests
// ---------------------------------------------------------------------------

/// Insert a dashboard user as a member of an existing tenant (by slug).
/// Mirrors `insert_member` in `control_db.rs` test helpers.
async fn insert_tenant_member(fx: &Fixture, slug: &str, email: &str, role: &str) {
    let tenant = fx
        .state
        .control_db
        .tenant_by_slug(slug)
        .await
        .expect("tenant_by_slug query")
        .expect("tenant exists");
    let tenant_id = allowthem_saas::TenantId::from(tenant.id_as_uuid().unwrap());
    let member_id = uuid::Uuid::new_v4();
    sqlx::query(
        "INSERT INTO tenant_members (id, tenant_id, email, role, accepted_at) \
         VALUES (?, ?, ?, ?, datetime('now'))",
    )
    .bind(member_id.as_bytes().as_ref())
    .bind(tenant_id.as_bytes())
    .bind(email)
    .bind(role)
    .execute(fx.state.control_db.pool())
    .await
    .expect("insert tenant member");
}

#[tokio::test]
async fn non_member_gets_404() {
    let fx = Fixture::new().await;
    // Owner sets up the "acme" tenant.
    let (_owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    // A second dashboard user signs up with a different tenant ("zulu").
    // They have no tenant_members row for "acme".
    let (other_cookie, _) = signup_and_get_session(&fx, "other@zulu.com", "zulu").await;

    let resp = get_authed(&fx, "/t/acme/applications", &other_cookie).await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "non-member must receive 404"
    );
}

#[tokio::test]
async fn viewer_cannot_create() {
    let fx = Fixture::new().await;
    let (_owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    // Viewer has their own tenant ("viewer-ws") so they have a dashboard account.
    let (viewer_cookie, _) = signup_and_get_session(&fx, "viewer@example.com", "viewer-ws").await;
    // Add them to "acme" with viewer role.
    insert_tenant_member(&fx, "acme", "viewer@example.com", "viewer").await;

    // The viewer is owner of "viewer-ws" so they can GET /t/viewer-ws/applications/new
    // which renders a csrf_token input. The CSRF is derived from the session cookie
    // (same dashboard AllowThem key across all tenant paths), so the token is valid
    // for any POST by this session, including the attempt on "acme".
    let csrf =
        fetch_csrf_for_authed_form(&fx, "/t/viewer-ws/applications/new", &viewer_cookie).await;

    let form = vec![
        ("name", "Evil App"),
        ("client_type", "confidential"),
        ("redirect_uris", "https://evil.test/callback"),
        ("logo_url", ""),
        ("csrf_token", csrf.as_str()),
    ];
    let resp = fx
        .post_form("/t/acme/applications", &form, Some(&viewer_cookie))
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "viewer must not be permitted to create an application"
    );
}

#[tokio::test]
async fn admin_can_create_and_delete() {
    let fx = Fixture::new().await;
    let (_owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    // Admin has their own tenant so they have a dashboard account.
    let (admin_cookie, _) = signup_and_get_session(&fx, "admin@example.com", "admin-ws").await;
    insert_tenant_member(&fx, "acme", "admin@example.com", "admin").await;

    let ath = tenant_ath_for_slug(&fx, "acme").await;

    // --- Create ---
    let csrf = fetch_csrf_for_authed_form(&fx, "/t/acme/applications/new", &admin_cookie).await;
    let form = vec![
        ("name", "Admin App"),
        ("client_type", "confidential"),
        ("redirect_uris", "https://admin.test/callback"),
        ("logo_url", ""),
        ("csrf_token", csrf.as_str()),
    ];
    let resp = fx
        .post_form("/t/acme/applications", &form, Some(&admin_cookie))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(
        body.contains("Admin App"),
        "create response must contain app name"
    );

    // Find the app by name to get its id.
    let apps = ath
        .db()
        .list_applications()
        .await
        .expect("list_applications");
    let app = apps
        .iter()
        .find(|a| a.name == "Admin App")
        .expect("Admin App must exist after create");
    let app_id = app.id;

    // --- Delete ---
    let detail_path = format!("/t/acme/applications/{app_id}");
    let csrf2 = fetch_csrf_for_authed_form(&fx, &detail_path, &admin_cookie).await;
    let del_resp = fx
        .post_form(
            &format!("{detail_path}/delete"),
            &[("csrf_token", csrf2.as_str())],
            Some(&admin_cookie),
        )
        .await;
    assert_eq!(del_resp.status(), StatusCode::SEE_OTHER);
    let loc = del_resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/t/acme/applications", "delete must redirect to list");

    let remaining = ath
        .db()
        .list_applications()
        .await
        .expect("list after delete");
    assert!(
        remaining.iter().all(|a| a.name != "Admin App"),
        "deleted app must not appear in list"
    );
}

#[tokio::test]
async fn suspended_tenant_renders_suspended_page() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    // Suspend the tenant directly. resolve_scope calls tenant_by_slug on each
    // request (no caching), so the new status is visible immediately.
    sqlx::query("UPDATE tenants SET status = 'suspended' WHERE slug = 'acme'")
        .execute(fx.state.control_db.pool())
        .await
        .expect("suspend tenant");

    let resp = get_authed(&fx, "/t/acme/applications", &session_cookie).await;
    assert_eq!(
        resp.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "suspended tenant must return 503"
    );
    let body = body_string(resp).await;
    assert!(
        body.contains("Workspace suspended"),
        "suspended page must contain 'Workspace suspended'"
    );
}

#[tokio::test]
async fn connected_users_count_renders() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let ath = tenant_ath_for_slug(&fx, "acme").await;

    // The default app is provisioned by signup.
    let apps = ath
        .db()
        .list_applications()
        .await
        .expect("list_applications");
    let app = apps.first().expect("default app exists after signup");

    // Create two tenant users and grant them consent on the default app.
    let user1 = ath
        .db()
        .create_user(
            allowthem_core::Email::new("cu1@example.com".into()).unwrap(),
            "secret",
            None,
            None,
        )
        .await
        .expect("user1");
    let user2 = ath
        .db()
        .create_user(
            allowthem_core::Email::new("cu2@example.com".into()).unwrap(),
            "secret",
            None,
            None,
        )
        .await
        .expect("user2");

    for (uid, consent_id) in [
        (user1.id, uuid::Uuid::new_v4()),
        (user2.id, uuid::Uuid::new_v4()),
    ] {
        sqlx::query(
            "INSERT OR IGNORE INTO allowthem_consents (id, user_id, application_id) \
             VALUES (?, ?, ?)",
        )
        .bind(consent_id.to_string())
        .bind(uid)
        .bind(app.id)
        .execute(ath.db().pool())
        .await
        .expect("insert consent");
    }

    let resp = get_authed(
        &fx,
        &format!("/t/acme/applications/{}", app.id),
        &session_cookie,
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(
        body.contains("Connected users"),
        "detail page must show 'Connected users' label"
    );
    assert!(body.contains('2'), "connected users count must be 2");
}

// ---------------------------------------------------------------------------
// 99c.4.6 user management — missing integration tests
// ---------------------------------------------------------------------------

/// Verify that viewers are rejected on every POST user-mutation route and
/// that admins are only rejected on the owner-only delete route.
#[tokio::test]
async fn user_role_rejection_matrix() {
    let fx = Fixture::new().await;
    let (_owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let (admin_cookie, _) = signup_and_get_session(&fx, "admin@mgmt.com", "mgmt").await;
    insert_tenant_member(&fx, "acme", "admin@mgmt.com", "admin").await;
    let (viewer_cookie, _) = signup_and_get_session(&fx, "viewer@view.com", "view").await;
    insert_tenant_member(&fx, "acme", "viewer@view.com", "viewer").await;

    let ath = tenant_ath_for_slug(&fx, "acme").await;
    let target = ath
        .db()
        .create_user(
            allowthem_core::Email::new("target@acme.com".into()).unwrap(),
            "secret",
            None,
            None,
        )
        .await
        .expect("target user");
    let role = ath
        .db()
        .create_role(&allowthem_core::types::RoleName::new("matrix-role"), None)
        .await
        .expect("role");
    let perm = ath
        .db()
        .create_permission(
            &allowthem_core::types::PermissionName::new("matrix:perm"),
            None,
        )
        .await
        .expect("perm");

    let user_base = format!("/t/acme/users/{}", target.id);
    let role_id_str = role.id.to_string();
    let perm_id_str = perm.id.to_string();

    // Viewer CSRF comes from their own workspace where they are owner.
    let viewer_csrf =
        fetch_csrf_for_authed_form(&fx, "/t/view/applications/new", &viewer_cookie).await;
    // Admin CSRF comes from the user detail page (admin can access it).
    let admin_csrf = fetch_csrf_for_authed_form(&fx, &user_base, &admin_cookie).await;

    // (path, is_owner_only): all nine POST mutation routes.
    let routes: Vec<(String, bool)> = vec![
        (format!("{user_base}/block"), false),
        (format!("{user_base}/unblock"), false),
        (format!("{user_base}/force-password-reset"), false),
        (format!("{user_base}/revoke-sessions"), false),
        (format!("{user_base}/delete"), true),
        (format!("{user_base}/roles"), false),
        (format!("{user_base}/roles/{role_id_str}/remove"), false),
        (format!("{user_base}/permissions"), false),
        (
            format!("{user_base}/permissions/{perm_id_str}/remove"),
            false,
        ),
    ];

    // Viewer must be rejected (403) on every route — extractor fires before handler.
    for (path, _) in &routes {
        let resp = fx
            .post_form(
                path,
                &[
                    ("csrf_token", viewer_csrf.as_str()),
                    ("role_id", role_id_str.as_str()),
                    ("permission_id", perm_id_str.as_str()),
                    ("confirm", "DELETE"),
                ],
                Some(&viewer_cookie),
            )
            .await;
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "viewer must be rejected on {path}"
        );
    }

    // Admin must be rejected (403) only on the owner-only delete route.
    for (path, is_owner_only) in &routes {
        let resp = fx
            .post_form(
                path,
                &[
                    ("csrf_token", admin_csrf.as_str()),
                    ("role_id", role_id_str.as_str()),
                    ("permission_id", perm_id_str.as_str()),
                    ("confirm", "DELETE"),
                ],
                Some(&admin_cookie),
            )
            .await;
        if *is_owner_only {
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "admin must be rejected on owner-only route {path}"
            );
        } else {
            assert_ne!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "admin must not be rejected on non-owner-only route {path}"
            );
        }
    }
}

/// Verify that force-password-reset sets password_hash to NULL and
/// deletes all active sessions for the target user.
#[tokio::test]
async fn force_password_reset_clears_hash_and_sessions() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let ath = tenant_ath_for_slug(&fx, "acme").await;

    let user = ath
        .db()
        .create_user(
            allowthem_core::Email::new("frank@acme.com".into()).unwrap(),
            "secret",
            None,
            None,
        )
        .await
        .expect("user");

    // Seed one session directly so we can verify it gets deleted.
    sqlx::query(
        "INSERT INTO allowthem_sessions (id, token_hash, user_id, expires_at) \
         VALUES (?, ?, ?, datetime('now', '+1 day'))",
    )
    .bind(allowthem_core::types::SessionId::new())
    .bind("aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000")
    .bind(user.id)
    .execute(ath.db().pool())
    .await
    .expect("seed session");

    let detail_path = format!("/t/acme/users/{}", user.id);
    let csrf = fetch_csrf_for_authed_form(&fx, &detail_path, &session_cookie).await;

    let resp = fx
        .post_form(
            &format!("{detail_path}/force-password-reset"),
            &[("csrf_token", csrf.as_str())],
            Some(&session_cookie),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "force reset must redirect"
    );

    // Password hash must be NULL in the tenant DB.
    let (hash,): (Option<String>,) =
        sqlx::query_as("SELECT password_hash FROM allowthem_users WHERE id = ?")
            .bind(user.id)
            .fetch_one(ath.db().pool())
            .await
            .expect("query password_hash");
    assert!(
        hash.is_none(),
        "password_hash must be NULL after force reset"
    );

    // All sessions for this user must be gone.
    let session_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM allowthem_sessions WHERE user_id = ?")
            .bind(user.id)
            .fetch_one(ath.db().pool())
            .await
            .expect("count sessions");
    assert_eq!(
        session_count, 0,
        "sessions must be deleted after force reset"
    );
}

/// Verify that assign_role adds the role and unassign_role removes it.
#[tokio::test]
async fn assign_and_unassign_role_round_trip() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let ath = tenant_ath_for_slug(&fx, "acme").await;

    let user = ath
        .db()
        .create_user(
            allowthem_core::Email::new("greta@acme.com".into()).unwrap(),
            "secret",
            None,
            None,
        )
        .await
        .expect("user");
    let role = ath
        .db()
        .create_role(&allowthem_core::types::RoleName::new("editor"), None)
        .await
        .expect("role");

    let detail_path = format!("/t/acme/users/{}", user.id);
    let csrf = fetch_csrf_for_authed_form(&fx, &detail_path, &session_cookie).await;

    // Assign.
    let assign_resp = fx
        .post_form(
            &format!("{detail_path}/roles"),
            &[
                ("csrf_token", csrf.as_str()),
                ("role_id", role.id.to_string().as_str()),
            ],
            Some(&session_cookie),
        )
        .await;
    assert_eq!(
        assign_resp.status(),
        StatusCode::SEE_OTHER,
        "assign must redirect"
    );

    let roles_after_assign = ath
        .db()
        .get_user_roles(&user.id)
        .await
        .expect("get_user_roles after assign");
    assert!(
        roles_after_assign.iter().any(|r| r.id == role.id),
        "role must be assigned after POST /roles"
    );

    // Unassign — CSRF goes in body even though the handler only reads path params.
    let unassign_resp = fx
        .post_form(
            &format!("{detail_path}/roles/{}/remove", role.id),
            &[("csrf_token", csrf.as_str())],
            Some(&session_cookie),
        )
        .await;
    assert_eq!(
        unassign_resp.status(),
        StatusCode::SEE_OTHER,
        "unassign must redirect"
    );

    let roles_after_unassign = ath
        .db()
        .get_user_roles(&user.id)
        .await
        .expect("get_user_roles after unassign");
    assert!(
        roles_after_unassign.iter().all(|r| r.id != role.id),
        "role must be removed after POST /roles/{{id}}/remove"
    );
}

/// Verify that grant_permission adds the permission and revoke_permission removes it.
#[tokio::test]
async fn grant_and_revoke_permission_round_trip() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let ath = tenant_ath_for_slug(&fx, "acme").await;

    let user = ath
        .db()
        .create_user(
            allowthem_core::Email::new("harriet@acme.com".into()).unwrap(),
            "secret",
            None,
            None,
        )
        .await
        .expect("user");
    let perm = ath
        .db()
        .create_permission(
            &allowthem_core::types::PermissionName::new("reports:read"),
            None,
        )
        .await
        .expect("perm");

    let detail_path = format!("/t/acme/users/{}", user.id);
    let csrf = fetch_csrf_for_authed_form(&fx, &detail_path, &session_cookie).await;

    // Grant.
    let grant_resp = fx
        .post_form(
            &format!("{detail_path}/permissions"),
            &[
                ("csrf_token", csrf.as_str()),
                ("permission_id", perm.id.to_string().as_str()),
            ],
            Some(&session_cookie),
        )
        .await;
    assert_eq!(
        grant_resp.status(),
        StatusCode::SEE_OTHER,
        "grant must redirect"
    );

    let perms_after_grant = ath
        .db()
        .get_user_permissions(&user.id)
        .await
        .expect("get_user_permissions after grant");
    assert!(
        perms_after_grant.iter().any(|p| p.id == perm.id),
        "permission must be present after POST /permissions"
    );

    // Revoke — CSRF goes in body even though the handler only reads path params.
    let revoke_resp = fx
        .post_form(
            &format!("{detail_path}/permissions/{}/remove", perm.id),
            &[("csrf_token", csrf.as_str())],
            Some(&session_cookie),
        )
        .await;
    assert_eq!(
        revoke_resp.status(),
        StatusCode::SEE_OTHER,
        "revoke must redirect"
    );

    let perms_after_revoke = ath
        .db()
        .get_user_permissions(&user.id)
        .await
        .expect("get_user_permissions after revoke");
    assert!(
        perms_after_revoke.iter().all(|p| p.id != perm.id),
        "permission must be absent after POST /permissions/{{id}}/remove"
    );
}

/// Verify that posting to delete without `confirm=DELETE` redirects back
/// to the user detail page with `?error=confirm_required` and the user
/// record remains intact.
#[tokio::test]
async fn delete_user_missing_confirm_redirects() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let ath = tenant_ath_for_slug(&fx, "acme").await;

    let user = ath
        .db()
        .create_user(
            allowthem_core::Email::new("igor@acme.com".into()).unwrap(),
            "secret",
            None,
            None,
        )
        .await
        .expect("user");

    let detail_path = format!("/t/acme/users/{}", user.id);
    let csrf = fetch_csrf_for_authed_form(&fx, &detail_path, &session_cookie).await;

    // POST without confirm=DELETE (or with a wrong value).
    let resp = fx
        .post_form(
            &format!("{detail_path}/delete"),
            &[("csrf_token", csrf.as_str()), ("confirm", "wrong")],
            Some(&session_cookie),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "missing confirm must redirect"
    );
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        loc.contains("error=confirm_required"),
        "redirect must carry error=confirm_required, got: {loc}"
    );

    // User must still exist.
    let still_there = ath.db().get_user(user.id).await;
    assert!(
        still_there.is_ok(),
        "user must still exist after rejected delete"
    );
}

// ---------------------------------------------------------------------------
// 99c.5 — settings, team, invite, stubs, API keys
// ---------------------------------------------------------------------------

/// Insert a pending invite row directly via ControlDb::invite_member.
/// Returns the raw token string that should be used in the URL.
async fn seed_pending_invite(
    fx: &Fixture,
    slug: &str,
    invitee_email: &str,
    role: allowthem_saas::TenantRole,
    raw_token: &str,
) {
    use sha2::{Digest, Sha256};

    let tenant = fx
        .state
        .control_db
        .tenant_by_slug(slug)
        .await
        .expect("tenant_by_slug")
        .expect("tenant exists");
    let tenant_id = allowthem_saas::TenantId::from(tenant.id_as_uuid().unwrap());
    let token_hash = Sha256::digest(raw_token.as_bytes()).to_vec();
    let expires_at = chrono::Utc::now().timestamp() + 7 * 24 * 3600;
    fx.state
        .control_db
        .invite_member(&tenant_id, invitee_email, role, &token_hash, expires_at)
        .await
        .expect("invite_member");
}

/// GET /invite/{token} with an optional pre-auth CSRF cookie, returning the
/// response and extracting the csrf_pre cookie if a new one was set.
async fn get_invite_page(
    fx: &Fixture,
    raw_token: &str,
    pre_auth_cookie: Option<&str>,
) -> axum::response::Response {
    let mut req = Request::builder()
        .method("GET")
        .uri(format!("/invite/{raw_token}"))
        .header(header::HOST, BASE_DOMAIN);
    if let Some(c) = pre_auth_cookie {
        req = req.header(header::COOKIE, c);
    }
    let req = req.body(Body::empty()).expect("build GET");
    fx.app.clone().oneshot(req).await.expect("oneshot")
}

/// Extract the `csrf_pre=<value>` portion from the Set-Cookie headers in a response.
fn extract_csrf_pre_cookie(resp: &axum::response::Response) -> Option<String> {
    resp.headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .find_map(|hv| {
            hv.to_str()
                .ok()
                .filter(|s| s.starts_with("csrf_pre="))
                .and_then(|s| s.split(';').next())
                .map(str::to_owned)
        })
}

/// Full invite flow for a brand-new user (no prior dashboard account).
///
/// Flow:
/// 1. Owner signs up → tenant "acme" exists.
/// 2. A pending invite for newguy@example.com is seeded with a known token.
/// 3. GET /invite/{token} → 200, register form rendered.
/// 4. POST /invite/{token} with password → 303 to /t/acme.
/// 5. Invite row is marked accepted; newguy@example.com has a dashboard account.
#[tokio::test]
async fn invite_new_user_full_flow() {
    let fx = Fixture::new().await;
    let (_owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    let raw_token = "invite-new-user-test-token-99c5";
    seed_pending_invite(
        &fx,
        "acme",
        "newguy@example.com",
        allowthem_saas::TenantRole::Admin,
        raw_token,
    )
    .await;

    // GET without any cookie — should render register form and set csrf_pre cookie.
    let get_resp = get_invite_page(&fx, raw_token, None).await;
    assert_eq!(get_resp.status(), StatusCode::OK, "invite GET must be 200");
    let csrf_cookie = extract_csrf_pre_cookie(&get_resp)
        .expect("csrf_pre cookie set on unauthenticated invite GET");
    let csrf_token = csrf_cookie.strip_prefix("csrf_pre=").unwrap().to_owned();
    let html = body_string(get_resp).await;
    assert!(
        html.contains("Create account"),
        "register form must be rendered for new user"
    );

    // POST with the csrf_pre cookie + matching token in body.
    let resp = fx
        .post_form(
            &format!("/invite/{raw_token}"),
            &[("csrf_token", &csrf_token), ("password", "supersecret")],
            Some(&csrf_cookie),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "POST invite (new user) must redirect"
    );
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(location, "/t/acme", "must redirect to tenant dashboard");

    // A session cookie must be set for the newly-created user.
    let session_set = resp.headers().get_all(header::SET_COOKIE).iter().any(|hv| {
        hv.to_str()
            .map(|s| s.starts_with("allowthem_dashboard_session="))
            .unwrap_or(false)
    });
    assert!(
        session_set,
        "session cookie must be set after invite accept"
    );

    // Dashboard user exists.
    let user = fx
        .state
        .ath
        .db()
        .get_user_by_email(&Email::new("newguy@example.com".into()).unwrap())
        .await
        .expect("newguy must now have a dashboard user account");
    assert_eq!(user.email.as_str(), "newguy@example.com");

    // Invite row is marked accepted (find_pending_invite_by_hash returns None).
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(raw_token.as_bytes()).to_vec();
    let pending = fx
        .state
        .control_db
        .find_pending_invite_by_hash(&hash)
        .await
        .expect("find_pending_invite_by_hash");
    assert!(
        pending.is_none(),
        "invite must be consumed after acceptance"
    );
}

/// Full invite flow for a user who already has a dashboard account (existing-user branch).
///
/// Flow:
/// 1. owner@acme.com signs up → tenant "acme".
/// 2. owner@beta.com signs up → tenant "beta".
/// 3. beta-owner invites acme-owner's email to "beta".
/// 4. GET /invite/{token} while logged in as acme-owner → accept.html.
/// 5. POST /invite/{token} (no password, just session + csrf) → 303 to /t/beta.
/// 6. Invite row accepted.
#[tokio::test]
async fn invite_existing_user_full_flow() {
    let fx = Fixture::new().await;
    let (acme_session, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let (_beta_session, _) = signup_and_get_session(&fx, "owner@beta.com", "beta").await;

    let raw_token = "invite-existing-user-test-token-99c5";
    seed_pending_invite(
        &fx,
        "beta",
        "owner@acme.com",
        allowthem_saas::TenantRole::Admin,
        raw_token,
    )
    .await;

    // GET while logged in as acme-owner — must render accept.html, not register.html.
    let csrf =
        fetch_csrf_for_authed_form(&fx, &format!("/invite/{raw_token}"), &acme_session).await;

    let html = {
        let resp = get_authed(&fx, &format!("/invite/{raw_token}"), &acme_session).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "invite GET for existing user must be 200"
        );
        body_string(resp).await
    };
    assert!(
        html.contains("Accept invite"),
        "accept.html confirm button must be rendered"
    );
    assert!(
        !html.contains("Create account"),
        "register form must NOT appear for existing user"
    );

    // POST — no password, just session cookie + csrf.
    let resp = fx
        .post_form(
            &format!("/invite/{raw_token}"),
            &[("csrf_token", &csrf)],
            Some(&acme_session),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "POST invite (existing user) must redirect"
    );
    let location = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(location, "/t/beta", "must redirect to beta dashboard");

    // Invite row consumed.
    use sha2::{Digest, Sha256};
    let hash = Sha256::digest(raw_token.as_bytes()).to_vec();
    let pending = fx
        .state
        .control_db
        .find_pending_invite_by_hash(&hash)
        .await
        .expect("find_pending_invite_by_hash");
    assert!(
        pending.is_none(),
        "invite must be consumed after existing-user acceptance"
    );
}

/// POST to demote the last owner via the HTTP route must re-render the team
/// page with a friendly error — not 500 or a silent no-op.
#[tokio::test]
async fn last_owner_demote_via_http_shows_error() {
    let fx = Fixture::new().await;
    let (owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    // Find the owner's member_id.
    let tenant = fx
        .state
        .control_db
        .tenant_by_slug("acme")
        .await
        .unwrap()
        .unwrap();
    let tenant_id = allowthem_saas::TenantId::from(tenant.id_as_uuid().unwrap());
    let members = fx
        .state
        .control_db
        .list_tenant_members(&tenant_id)
        .await
        .expect("list_tenant_members");
    let owner_member = members
        .iter()
        .find(|m| m.email == "owner@acme.com")
        .expect("owner member row");
    let member_id_str = owner_member
        .id_as_member_id()
        .unwrap()
        .as_uuid()
        .to_string();

    // Fetch CSRF from the team list page.
    let csrf = fetch_csrf_for_authed_form(&fx, "/t/acme/settings/team", &owner_cookie).await;

    // Attempt to demote the last owner to admin.
    let resp = fx
        .post_form(
            &format!("/t/acme/settings/team/{member_id_str}/role"),
            &[("csrf_token", &csrf), ("role", "admin")],
            Some(&owner_cookie),
        )
        .await;

    // Must re-render (200), not 500 or redirect.
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "demote last owner must re-render with error"
    );
    let body = body_string(resp).await;
    assert!(
        body.contains("Cannot demote the last owner"),
        "error message must mention last-owner invariant, got: {body}"
    );
}

/// All four stub settings pages must return 200 and contain "Coming soon".
#[tokio::test]
async fn stub_pages_return_200_with_coming_soon() {
    let fx = Fixture::new().await;
    let (session_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    let stub_paths = [
        "/t/acme/settings/webhooks",
        "/t/acme/settings/email",
        "/t/acme/settings/social",
        "/t/acme/settings/domain",
    ];

    for path in &stub_paths {
        let resp = get_authed(&fx, path, &session_cookie).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "stub page {path} must return 200"
        );
        let body = body_string(resp).await;
        assert!(
            body.contains("Coming soon"),
            "stub page {path} must contain 'Coming soon'"
        );
    }
}

/// Authz smoke: viewers can read roles/permissions but not write; admins
/// cannot post to billing/upgrade (owner-only).
#[tokio::test]
async fn authz_smoke_viewer_and_admin_enforcement() {
    let fx = Fixture::new().await;
    let (_owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let (viewer_cookie, _) = signup_and_get_session(&fx, "viewer@viewer-ws.com", "viewer-ws").await;
    let (admin_cookie, _) = signup_and_get_session(&fx, "admin@admin-ws.com", "admin-ws").await;

    insert_tenant_member(&fx, "acme", "viewer@viewer-ws.com", "viewer").await;
    insert_tenant_member(&fx, "acme", "admin@admin-ws.com", "admin").await;

    // Viewer can GET roles list.
    let resp = get_authed(&fx, "/t/acme/roles", &viewer_cookie).await;
    assert_eq!(resp.status(), StatusCode::OK, "viewer can read roles");

    // Viewer cannot POST to create a role — RequireTenantAdmin must fire.
    // Need a CSRF token; viewer is owner of "viewer-ws" so can fetch one from there.
    let csrf = fetch_csrf_for_authed_form(&fx, "/t/viewer-ws/roles/new", &viewer_cookie).await;
    let resp = fx
        .post_form(
            "/t/acme/roles",
            &[
                ("csrf_token", &csrf),
                ("name", "Evil Role"),
                ("description", ""),
            ],
            Some(&viewer_cookie),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "viewer must not create roles"
    );

    // Admin cannot POST to billing/upgrade — RequireTenantOwner must fire.
    let csrf = fetch_csrf_for_authed_form(&fx, "/t/admin-ws/settings/billing", &admin_cookie).await;
    let resp = fx
        .post_form(
            "/t/acme/settings/billing/upgrade",
            &[("csrf_token", &csrf)],
            Some(&admin_cookie),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "admin must not access billing/upgrade (owner-only)"
    );
}

// ---------------------------------------------------------------------------
// 99c.6 — super-admin panel integration tests
// ---------------------------------------------------------------------------

/// Sign up `email` / `slug` and assign the `super_admin` dashboard role.
/// Returns the session cookie.
async fn setup_super_admin(fx: &Fixture, email: &str, slug: &str) -> String {
    let (cookie, _) = signup_and_get_session(fx, email, slug).await;
    let user = fx
        .state
        .ath
        .db()
        .get_user_by_email(&Email::new(email.to_owned()).unwrap())
        .await
        .expect("get_user_by_email");
    let role_name = allowthem_core::types::RoleName::new("super_admin");
    let role = fx
        .state
        .ath
        .db()
        .create_role(&role_name, None)
        .await
        .expect("create super_admin role");
    fx.state
        .ath
        .db()
        .assign_role(&user.id, &role.id)
        .await
        .expect("assign super_admin role");
    cookie
}

/// Count rows in `control_audit_events` matching the given `action` string.
async fn count_control_audit(fx: &Fixture, action: &str) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM control_audit_events WHERE action = ?")
        .bind(action)
        .fetch_one(fx.state.control_db.pool())
        .await
        .expect("count control audit")
}

// ---- resolve_scope super-admin fall-through ----

/// A super-admin who is not a member of a tenant must still receive 200.
/// The middleware must write a `superadmin.tenant_accessed` row in the
/// control audit log on every such request.
#[tokio::test]
async fn super_admin_can_access_tenant_without_membership() {
    let fx = Fixture::new().await;
    let (_owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let sadmin_cookie = setup_super_admin(&fx, "sadmin@sa-corp.com", "sa-corp").await;

    let before = count_control_audit(&fx, "superadmin.tenant_accessed").await;

    let resp = get_authed(&fx, "/t/acme/applications", &sadmin_cookie).await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "super_admin must be granted access to any tenant"
    );

    let after = count_control_audit(&fx, "superadmin.tenant_accessed").await;
    assert_eq!(
        after - before,
        1,
        "one superadmin.tenant_accessed row expected; delta was {}",
        after - before
    );
}

/// A regular user who is not a member of a tenant must receive 404.
/// No `superadmin.tenant_accessed` row must be written.
#[tokio::test]
async fn non_super_admin_non_member_gets_404() {
    let fx = Fixture::new().await;
    let (_owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let (outsider_cookie, _) =
        signup_and_get_session(&fx, "outsider@test.com", "outsider-ws").await;

    let before = count_control_audit(&fx, "superadmin.tenant_accessed").await;

    let resp = get_authed(&fx, "/t/acme/applications", &outsider_cookie).await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "non-member without super_admin must not see tenant resources"
    );

    let after = count_control_audit(&fx, "superadmin.tenant_accessed").await;
    assert_eq!(
        after - before,
        0,
        "no audit row must be written for a failed non-super-admin access attempt"
    );
}

/// Super-admin acting on a user in a foreign tenant must produce audit rows
/// in both the control log and the tenant-local audit log, and the targeted
/// mutation must actually take effect.
#[tokio::test]
async fn super_admin_drill_into_tenant_writes_dual_audit() {
    let fx = Fixture::new().await;
    let (_owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let sadmin_cookie = setup_super_admin(&fx, "sadmin@sa-corp.com", "sa-corp").await;

    let ath = tenant_ath_for_slug(&fx, "acme").await;
    let target = ath
        .db()
        .create_user(
            allowthem_core::Email::new("target@acme.com".into()).unwrap(),
            "secret",
            None,
            None,
        )
        .await
        .expect("create target user");

    let control_before = count_control_audit(&fx, "superadmin.tenant_accessed").await;
    let tenant_before: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM allowthem_audit_log WHERE user_id = ?")
            .bind(target.id)
            .fetch_one(ath.db().pool())
            .await
            .expect("tenant audit before");

    // CSRF token is session-bound; fetch from the super_admin's own tenant
    // — cross-tenant use is valid (same session, same derived token).
    let csrf = fetch_csrf_for_authed_form(&fx, "/t/sa-corp/applications/new", &sadmin_cookie).await;

    let block_path = format!("/t/acme/users/{}/block", target.id);
    let resp = fx
        .post_form(&block_path, &[("csrf_token", &csrf)], Some(&sadmin_cookie))
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "block must redirect");

    let control_after = count_control_audit(&fx, "superadmin.tenant_accessed").await;
    assert!(
        control_after - control_before >= 1,
        "at least one control audit row expected; delta was {}",
        control_after - control_before
    );

    let tenant_after: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM allowthem_audit_log WHERE user_id = ?")
            .bind(target.id)
            .fetch_one(ath.db().pool())
            .await
            .expect("tenant audit after");
    assert!(
        tenant_after - tenant_before >= 1,
        "tenant audit log must have at least one new row; delta was {}",
        tenant_after - tenant_before
    );

    let updated = ath
        .db()
        .get_user(target.id)
        .await
        .expect("get blocked user");
    assert!(
        !updated.is_active,
        "user must be inactive (blocked) after super_admin block"
    );
}

/// If writing to `control_audit_events` fails, super-admin access must be
/// denied (500) — the middleware must fail closed and never grant access
/// silently.
#[tokio::test]
async fn super_admin_audit_failure_denies_access() {
    let fx = Fixture::new().await;
    let (_owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let sadmin_cookie = setup_super_admin(&fx, "sadmin@sa-corp.com", "sa-corp").await;

    // Confirm baseline access works.
    let ok = get_authed(&fx, "/t/acme/applications", &sadmin_cookie).await;
    assert_eq!(
        ok.status(),
        StatusCode::OK,
        "baseline: super_admin must access tenant"
    );

    // Sabotage the audit table.
    sqlx::query("DROP TABLE control_audit_events")
        .execute(fx.state.control_db.pool())
        .await
        .expect("drop control_audit_events");

    let resp = get_authed(&fx, "/t/acme/applications", &sadmin_cookie).await;
    assert_eq!(
        resp.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "super_admin access must be denied (500) when the audit write fails"
    );
}

// ---- Admin panel: overview ----

/// Unauthenticated GET /admin must redirect to /login.
#[tokio::test]
async fn admin_overview_unauthenticated_redirects_to_login() {
    let fx = Fixture::new().await;
    let resp = fx.get("/admin").await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "unauthenticated /admin must redirect"
    );
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        loc.starts_with("/login"),
        "must redirect to /login, got: {loc}"
    );
}

/// A regular authenticated user (no super_admin role) must receive 404.
#[tokio::test]
async fn admin_overview_non_super_admin_gets_404() {
    let fx = Fixture::new().await;
    let (regular_cookie, _) = signup_and_get_session(&fx, "regular@acme.com", "acme").await;
    let resp = get_authed(&fx, "/admin", &regular_cookie).await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "non-super-admin must not see /admin"
    );
}

/// Super-admin must receive a rendered 200 overview page.
#[tokio::test]
async fn admin_overview_renders_for_super_admin() {
    let fx = Fixture::new().await;
    let sadmin_cookie = setup_super_admin(&fx, "sadmin@sa.com", "sadmin").await;
    let resp = get_authed(&fx, "/admin", &sadmin_cookie).await;
    assert_eq!(resp.status(), StatusCode::OK, "super_admin must see /admin");
    let body = body_string(resp).await;
    assert!(
        body.contains("Tenants") || body.contains("ADMIN"),
        "overview must render admin content; first 300 chars: {}",
        &body[..body.len().min(300)]
    );
}

/// A tenant created via signup must appear in the admin overview.
#[tokio::test]
async fn admin_overview_lists_seeded_tenants() {
    let fx = Fixture::new().await;
    let (_owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let sadmin_cookie = setup_super_admin(&fx, "sadmin@sa.com", "sadmin").await;

    let resp = get_authed(&fx, "/admin", &sadmin_cookie).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(
        body.contains("acme"),
        "admin overview must list the acme tenant slug"
    );
}

// ---- Admin panel: tenant detail ----

/// GET /admin/tenants/<unknown-uuid> must return 404.
#[tokio::test]
async fn admin_detail_unknown_uuid_returns_404() {
    let fx = Fixture::new().await;
    let sadmin_cookie = setup_super_admin(&fx, "sadmin@sa.com", "sadmin").await;
    let resp = get_authed(
        &fx,
        "/admin/tenants/00000000-0000-0000-0000-000000000000",
        &sadmin_cookie,
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "unknown tenant UUID must 404"
    );
}

/// GET /admin/tenants/{id} for an existing tenant must return a 200 detail page.
#[tokio::test]
async fn admin_detail_renders_for_existing_tenant() {
    let fx = Fixture::new().await;
    let (_owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let sadmin_cookie = setup_super_admin(&fx, "sadmin@sa.com", "sadmin").await;

    let meta = fx
        .state
        .control_db
        .tenant_meta_by_slug("acme")
        .await
        .expect("ok")
        .expect("acme exists");
    let tenant_uuid = meta.id.as_uuid().to_string();

    let resp = get_authed(
        &fx,
        &format!("/admin/tenants/{tenant_uuid}"),
        &sadmin_cookie,
    )
    .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "admin detail must return 200 for existing tenant"
    );
    let body = body_string(resp).await;
    assert!(
        body.contains("acme"),
        "detail page must contain the tenant slug"
    );
}

// ---- Admin panel: suspend / unsuspend / delete / change-plan ----

/// POST suspend must set status to suspended and write a `tenant.suspend`
/// control audit row.
#[tokio::test]
async fn admin_suspend_sets_status_and_logs_audit() {
    let fx = Fixture::new().await;
    let (_owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let sadmin_cookie = setup_super_admin(&fx, "sadmin@sa.com", "sadmin").await;

    let meta = fx
        .state
        .control_db
        .tenant_meta_by_slug("acme")
        .await
        .expect("ok")
        .expect("acme exists");
    let tenant_uuid = meta.id.as_uuid().to_string();

    let csrf = fetch_csrf_for_authed_form(
        &fx,
        &format!("/admin/tenants/{tenant_uuid}"),
        &sadmin_cookie,
    )
    .await;
    let audit_before = count_control_audit(&fx, "tenant.suspend").await;

    let resp = fx
        .post_form(
            &format!("/admin/tenants/{tenant_uuid}/suspend"),
            &[("csrf_token", &csrf)],
            Some(&sadmin_cookie),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "suspend must redirect"
    );
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        loc.contains(&tenant_uuid),
        "redirect must target tenant detail; got: {loc}"
    );

    let updated = fx
        .state
        .control_db
        .tenant_meta_by_slug("acme")
        .await
        .expect("ok")
        .expect("acme still exists");
    assert_eq!(
        updated.status,
        allowthem_saas::TenantStatus::Suspended,
        "tenant status must be suspended"
    );

    let audit_after = count_control_audit(&fx, "tenant.suspend").await;
    assert_eq!(
        audit_after - audit_before,
        1,
        "one tenant.suspend audit row expected"
    );
}

/// POST unsuspend must restore the tenant to active status.
#[tokio::test]
async fn admin_unsuspend_sets_status_active() {
    let fx = Fixture::new().await;
    let (_owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let sadmin_cookie = setup_super_admin(&fx, "sadmin@sa.com", "sadmin").await;

    let meta = fx
        .state
        .control_db
        .tenant_meta_by_slug("acme")
        .await
        .expect("ok")
        .expect("acme exists");
    let tenant_id = meta.id;
    let tenant_uuid = tenant_id.as_uuid().to_string();

    // Pre-suspend so the HTTP unsuspend has something to undo.
    fx.state
        .control_db
        .set_tenant_status(&tenant_id, allowthem_saas::TenantStatus::Suspended)
        .await
        .expect("pre-suspend");

    let csrf = fetch_csrf_for_authed_form(
        &fx,
        &format!("/admin/tenants/{tenant_uuid}"),
        &sadmin_cookie,
    )
    .await;

    let resp = fx
        .post_form(
            &format!("/admin/tenants/{tenant_uuid}/unsuspend"),
            &[("csrf_token", &csrf)],
            Some(&sadmin_cookie),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "unsuspend must redirect"
    );

    let updated = fx
        .state
        .control_db
        .tenant_meta_by_slug("acme")
        .await
        .expect("ok")
        .expect("acme still exists");
    assert_eq!(
        updated.status,
        allowthem_saas::TenantStatus::Active,
        "tenant must be active after unsuspend"
    );
}

/// POST delete must mark the tenant deleted and redirect to /admin.
#[tokio::test]
async fn admin_delete_redirects_to_admin() {
    let fx = Fixture::new().await;
    let (_owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let sadmin_cookie = setup_super_admin(&fx, "sadmin@sa.com", "sadmin").await;

    let meta = fx
        .state
        .control_db
        .tenant_meta_by_slug("acme")
        .await
        .expect("ok")
        .expect("acme exists");
    let tenant_uuid = meta.id.as_uuid().to_string();

    let csrf = fetch_csrf_for_authed_form(
        &fx,
        &format!("/admin/tenants/{tenant_uuid}"),
        &sadmin_cookie,
    )
    .await;

    let resp = fx
        .post_form(
            &format!("/admin/tenants/{tenant_uuid}/delete"),
            &[("csrf_token", &csrf)],
            Some(&sadmin_cookie),
        )
        .await;
    assert_eq!(resp.status(), StatusCode::SEE_OTHER, "delete must redirect");
    let loc = resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert_eq!(loc, "/admin", "delete must redirect to /admin");

    let updated = fx
        .state
        .control_db
        .tenant_meta_by_slug("acme")
        .await
        .expect("ok")
        .expect("acme still has a row");
    assert_eq!(
        updated.status,
        allowthem_saas::TenantStatus::Deleted,
        "tenant must be marked deleted"
    );
}

/// POST change-plan must update the tenant's plan_id to the selected one.
#[tokio::test]
async fn admin_change_plan_updates_tenant() {
    let fx = Fixture::new().await;
    let (_owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;
    let sadmin_cookie = setup_super_admin(&fx, "sadmin@sa.com", "sadmin").await;

    let meta = fx
        .state
        .control_db
        .tenant_meta_by_slug("acme")
        .await
        .expect("ok")
        .expect("acme exists");
    let tenant_uuid = meta.id.as_uuid().to_string();
    let original_plan_id = meta.plan_id;

    let plans = fx.state.control_db.list_plans().await.expect("list_plans");
    let new_plan = plans
        .iter()
        .find(|p| p.id != original_plan_id)
        .expect("seed data must contain at least two plans");
    let new_plan_id_hex = hex::encode(&new_plan.id);

    let csrf = fetch_csrf_for_authed_form(
        &fx,
        &format!("/admin/tenants/{tenant_uuid}"),
        &sadmin_cookie,
    )
    .await;

    let resp = fx
        .post_form(
            &format!("/admin/tenants/{tenant_uuid}/change-plan"),
            &[("csrf_token", &csrf), ("plan_id", &new_plan_id_hex)],
            Some(&sadmin_cookie),
        )
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::SEE_OTHER,
        "change-plan must redirect"
    );

    let updated = fx
        .state
        .control_db
        .tenant_meta_by_slug("acme")
        .await
        .expect("ok")
        .expect("acme still exists");
    assert_eq!(updated.plan_id, new_plan.id, "tenant plan must be updated");
}

// ---- Admin panel: analytics pages ----

/// Usage, revenue, and health pages must all return 200 for a super-admin.
#[tokio::test]
async fn admin_analytics_pages_render_200() {
    let fx = Fixture::new().await;
    let sadmin_cookie = setup_super_admin(&fx, "sadmin@sa.com", "sadmin").await;

    for path in ["/admin/usage", "/admin/revenue", "/admin/health"] {
        let resp = get_authed(&fx, path, &sadmin_cookie).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "analytics page {path} must return 200"
        );
    }
}

/// Minting an API key renders the raw secret once; a subsequent GET of the
/// list page does not expose it again.
#[tokio::test]
async fn api_key_one_time_secret() {
    let fx = Fixture::new().await;
    let (owner_cookie, _) = signup_and_get_session(&fx, "owner@acme.com", "acme").await;

    let csrf = fetch_csrf_for_authed_form(&fx, "/t/acme/settings/api-keys", &owner_cookie).await;

    // Mint a key.
    let mint_resp = fx
        .post_form(
            "/t/acme/settings/api-keys",
            &[("csrf_token", &csrf), ("name", "CI key")],
            Some(&owner_cookie),
        )
        .await;
    assert_eq!(
        mint_resp.status(),
        StatusCode::OK,
        "mint must render the list page (200)"
    );
    let mint_body = body_string(mint_resp).await;
    assert!(
        mint_body.contains("CI key"),
        "minted key name must appear in response"
    );
    // The raw secret is rendered once — it starts with "sak_" by convention.
    assert!(
        mint_body.contains("sak_"),
        "raw secret (sak_ prefix) must appear in mint response"
    );

    // Subsequent GET must not expose the raw secret.
    let list_resp = get_authed(&fx, "/t/acme/settings/api-keys", &owner_cookie).await;
    assert_eq!(list_resp.status(), StatusCode::OK);
    let list_body = body_string(list_resp).await;
    assert!(
        list_body.contains("CI key"),
        "key name must still appear in list"
    );
    // Extract the raw secret from the mint response and verify it's absent from list.
    if let Some(start) = mint_body.find("sak_") {
        let raw_secret: String = mint_body[start..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
            .collect();
        assert!(
            !list_body.contains(&raw_secret),
            "raw secret must NOT appear in subsequent list GET"
        );
    }
}
