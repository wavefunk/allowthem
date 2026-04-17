mod admin_applications;
mod admin_audit;
mod admin_sessions;
mod branding;
mod config;
mod consent;
mod error;
mod login;
mod logout;
mod mfa;
mod mock_oauth;
mod password_reset;
mod register;
mod settings;
mod state;
mod templates;
mod test_oauth_routes;

use std::collections::HashMap;
use std::sync::Arc;

use axum::{Router, response::IntoResponse, routing::get};
use chrono::Duration;
use eyre::Result;
use tower_http::services::ServeDir;
use tracing_subscriber::EnvFilter;

use allowthem_core::{
    AllowThemBuilder, AuthClient, EmbeddedAuthClient, LogEmailSender, OAuthProvider,
};
use allowthem_server::{
    authorize_post, csrf_middleware, oauth_routes, token_route, userinfo_route, well_known_routes,
};

use crate::state::AppState;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. Tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,allowthem=debug")),
        )
        .init();

    // 2. Config
    let config = config::load()?;
    tracing::info!(bind = %config.bind, db = %config.database_url, "starting allowthem");

    // 3. MFA key
    let mfa_key: Option<[u8; 32]> = match &config.mfa_key_hex {
        Some(hex) => Some(decode_hex_key(hex)?),
        None => None,
    };

    // 3b. Signing key
    let signing_key: Option<[u8; 32]> = match &config.signing_key_hex {
        Some(hex) => Some(decode_hex_key(hex)?),
        None => None,
    };

    // 4. AllowThem handle
    let mut builder = AllowThemBuilder::new(&config.database_url)
        .session_ttl(Duration::hours(config.session_ttl_hours as i64))
        .cookie_secure(config.cookie_secure)
        .cookie_domain(&config.cookie_domain)
        .base_url(&config.base_url);
    if let Some(key) = mfa_key {
        builder = builder.mfa_key(key);
    }
    if let Some(key) = signing_key {
        builder = builder.signing_key(key);
    }
    let ath = builder.build().await?;

    // 4b. Bootstrap admin user (dev/test only — no-op when env vars are unset)
    if let (Some(email_str), Some(password)) = (
        &config.bootstrap_admin_email,
        &config.bootstrap_admin_password,
    ) {
        seed_admin_user(&ath, email_str, password).await?;
    }

    // 4c. Bootstrap signing key (required for OIDC token issuance)
    if let Some(ref key) = signing_key {
        seed_signing_key(&ath, key).await?;
    }

    // 4d. Bootstrap OIDC application (dev/test only — no-op when env vars are unset)
    seed_oidc_app(&ath, &config).await?;

    // 5. Well-known router and UserInfo router (resolved before ath is moved into AppState)
    let wk_router = well_known_routes(config.base_url.clone()).with_state(ath.clone());
    let ui_router = userinfo_route().with_state(ath.clone());
    let tk_router = token_route().with_state(ath.clone());

    // 6. Templates
    let templates = templates::build_template_env()?;

    // 6b. OAuth providers
    let mut providers: HashMap<String, Box<dyn OAuthProvider>> = HashMap::new();

    if config.oauth_mock {
        providers.insert(
            "google".into(),
            Box::new(mock_oauth::MockOAuthProvider {
                provider_name: "google".into(),
                base_url: config.base_url.clone(),
            }),
        );
        providers.insert(
            "github".into(),
            Box::new(mock_oauth::MockOAuthProvider {
                provider_name: "github".into(),
                base_url: config.base_url.clone(),
            }),
        );
    } else {
        if let (Some(id), Some(secret)) = (&config.google_client_id, &config.google_client_secret) {
            use allowthem_core::GoogleProvider;
            providers.insert(
                "google".into(),
                Box::new(GoogleProvider::new(id.clone(), secret.clone())),
            );
        }
        if let (Some(id), Some(secret)) = (&config.github_client_id, &config.github_client_secret) {
            use allowthem_core::GitHubProvider;
            providers.insert(
                "github".into(),
                Box::new(GitHubProvider::new(id.clone(), secret.clone())),
            );
        }
    }

    // Collect provider names BEFORE moving providers into oauth_routes.
    // Box<dyn OAuthProvider> is not Clone, so the map cannot be cloned.
    let mut oauth_provider_names: Vec<String> = providers.keys().cloned().collect();
    oauth_provider_names.sort();

    let oauth_router = oauth_routes(providers, config.base_url.clone()).with_state(ath.clone());

    // 7. App state
    let auth_client: Arc<dyn AuthClient> = Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
    let state = AppState {
        ath: ath.clone(),
        auth_client,
        base_url: config.base_url.clone(),
        templates,
        is_production: config.is_production,
        login_attempts: Arc::new(dashmap::DashMap::new()),
        max_login_attempts: config.max_login_attempts,
        rate_limit_window_secs: config.rate_limit_window_secs,
        email_sender: Arc::new(LogEmailSender),
        oauth_providers: oauth_provider_names,
    };

    // 8. Router
    let app = Router::new()
        .route("/health", get(health))
        .route(
            "/register",
            get(register::get_register).post(register::post_register),
        )
        .route("/login", get(login::get_login).post(login::post_login))
        .route("/logout", get(logout::handler).post(logout::handler))
        .route(
            "/forgot-password",
            get(password_reset::get_forgot_password).post(password_reset::post_forgot_password),
        )
        .route(
            "/auth/reset-password",
            get(password_reset::get_reset_password).post(password_reset::post_reset_password),
        )
        .route(
            "/settings",
            get(settings::get_settings).post(settings::post_settings),
        )
        .route(
            "/settings/password",
            axum::routing::post(settings::post_change_password),
        )
        .route(
            "/settings/mfa/setup",
            get(mfa::get_mfa_setup),
        )
        .route(
            "/settings/mfa/confirm",
            axum::routing::post(mfa::post_mfa_confirm),
        )
        .route(
            "/settings/mfa/disable",
            axum::routing::post(mfa::post_mfa_disable),
        )
        .route(
            "/oauth/authorize",
            get(consent::get_authorize).post(authorize_post),
        )
        .nest("/admin/applications", admin_applications::routes())
        .nest("/admin/audit", admin_audit::routes())
        .nest("/admin/sessions", admin_sessions::routes())
        .merge(wk_router)
        .nest_service("/static", ServeDir::new("binaries/static"))
        .layer(axum::middleware::from_fn(csrf_middleware))
        .route(
            "/mfa/challenge",
            get(mfa::get_mfa_challenge).post(mfa::post_mfa_challenge),
        )
        .merge(ui_router) // after CSRF layer — Bearer auth, not browser sessions
        .merge(tk_router) // after CSRF layer — client_secret auth, not browser sessions
        .merge(oauth_router) // after CSRF layer — OAuth GET routes are external-initiated
        .with_state(state);

    // Conditionally mount mock test routes
    let app = if config.oauth_mock {
        app.merge(test_oauth_routes::test_oauth_routes().with_state(ath))
    } else {
        app
    };

    // 8. Serve
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!("listening on {}", config.bind);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    Ok(())
}

async fn health() -> impl IntoResponse {
    axum::Json(serde_json::json!({"status": "ok"}))
}

async fn shutdown_signal() {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to install ctrl-c handler");
    tracing::info!("shutdown signal received");
}

async fn seed_admin_user(
    ath: &allowthem_core::AllowThem,
    email_str: &str,
    password: &str,
) -> eyre::Result<()> {
    use allowthem_core::{Email, RoleName};

    let email = Email::new(email_str.to_string())
        .map_err(|e| eyre::eyre!("bootstrap admin email invalid: {e}"))?;

    let user = match ath.db().get_user_by_email(&email).await {
        Ok(u) => u,
        Err(allowthem_core::AuthError::NotFound) => {
            tracing::info!(email = email_str, "seeding bootstrap admin user");
            ath.db()
                .create_user(email, password, None)
                .await
                .map_err(|e| eyre::eyre!("bootstrap admin create failed: {e}"))?
        }
        Err(e) => return Err(eyre::eyre!("bootstrap admin user lookup failed: {e}")),
    };

    let role_name = RoleName::new("admin");
    // create_role returns AuthError::Conflict on duplicate — always look up first.
    // assign_role uses INSERT OR IGNORE and is safe to repeat.
    let role = match ath
        .db()
        .get_role_by_name(&role_name)
        .await
        .map_err(|e| eyre::eyre!("bootstrap admin role lookup failed: {e}"))?
    {
        Some(r) => r,
        None => ath
            .db()
            .create_role(&role_name, None)
            .await
            .map_err(|e| eyre::eyre!("bootstrap admin role create failed: {e}"))?,
    };
    let _ = ath.db().assign_role(&user.id, &role.id).await;

    tracing::info!(email = email_str, "bootstrap admin user ready");
    Ok(())
}

async fn seed_signing_key(
    ath: &allowthem_core::AllowThem,
    encryption_key: &[u8; 32],
) -> eyre::Result<()> {
    // Idempotency: if an active key already exists, nothing to do.
    match ath.db().get_active_signing_key().await {
        Ok(_) => return Ok(()),
        Err(allowthem_core::AuthError::NotFound) => {} // proceed
        Err(e) => return Err(eyre::eyre!("seed_signing_key: lookup failed: {e}")),
    }

    let key = ath
        .db()
        .create_signing_key(encryption_key)
        .await
        .map_err(|e| eyre::eyre!("seed_signing_key: create failed: {e}"))?;
    ath.db()
        .activate_signing_key(key.id)
        .await
        .map_err(|e| eyre::eyre!("seed_signing_key: activate failed: {e}"))?;
    tracing::info!("Seeded and activated RS256 signing key");
    Ok(())
}

async fn seed_oidc_app(
    ath: &allowthem_core::AllowThem,
    config: &config::ServerConfig,
) -> eyre::Result<()> {
    let (Some(name), Some(redirect_uri), Some(client_id), Some(client_secret)) = (
        config.bootstrap_oidc_app_name.as_deref(),
        config.bootstrap_oidc_redirect_uri.as_deref(),
        config.bootstrap_oidc_client_id.as_deref(),
        config.bootstrap_oidc_client_secret.as_deref(),
    ) else {
        return Ok(());
    };

    use allowthem_core::ApplicationId;

    // Idempotency: check if an application with this client_id already exists.
    let existing: Option<String> = sqlx::query_scalar(
        "SELECT client_id FROM allowthem_applications WHERE client_id = ?1 LIMIT 1",
    )
    .bind(client_id)
    .fetch_optional(ath.db().pool())
    .await
    .map_err(|e| eyre::eyre!("seed_oidc_app: lookup failed: {e}"))?;
    if existing.is_some() {
        return Ok(());
    }

    let id = ApplicationId::new();
    let secret_hash = allowthem_core::password::hash_password(client_secret)
        .map_err(|e| eyre::eyre!("seed_oidc_app: hash failed: {e}"))?;
    let redirect_uris_json =
        serde_json::to_string(&[redirect_uri]).expect("Vec<&str> serializes to JSON");
    let now = chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string();

    sqlx::query(
        "INSERT INTO allowthem_applications \
         (id, name, client_id, client_secret_hash, redirect_uris, logo_url, \
          primary_color, is_trusted, created_by, is_active, created_at, updated_at) \
         VALUES (?1, ?2, ?3, ?4, ?5, NULL, NULL, 0, NULL, 1, ?6, ?6)",
    )
    .bind(id)
    .bind(name)
    .bind(client_id)
    .bind(&secret_hash)
    .bind(&redirect_uris_json)
    .bind(&now)
    .execute(ath.db().pool())
    .await
    .map_err(|e| eyre::eyre!("seed_oidc_app: insert failed: {e}"))?;

    tracing::info!("Seeded OIDC application: {}", client_id);
    Ok(())
}

fn decode_hex_key(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        eyre::bail!(
            "hex key must be 64 hex chars (32 bytes), got {} chars",
            hex.len()
        );
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| eyre::eyre!("invalid hex key: {e}"))?;
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| eyre::eyre!("hex key decode failed"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[test]
    fn config_defaults() {
        let c = config::ServerConfig::default();
        assert_eq!(c.database_url, "sqlite:allowthem.db?mode=rwc");
        assert_eq!(c.bind, "127.0.0.1:3000".parse().unwrap());
        assert!(c.cookie_secure);
        assert_eq!(c.cookie_domain, "");
        assert_eq!(c.session_ttl_hours, 24);
        assert!(c.mfa_key_hex.is_none());
        assert!(c.signing_key_hex.is_none());
        assert!(!c.is_production);
    }

    #[test]
    fn config_from_env() {
        use figment::{
            Figment,
            providers::{Env, Serialized},
        };

        // SAFETY: test-only mutation of env vars; no other thread reads these
        // specific ALLOWTHEM_ vars concurrently.
        unsafe {
            std::env::set_var("ALLOWTHEM_BIND", "0.0.0.0:8080");
            std::env::set_var("ALLOWTHEM_COOKIE_SECURE", "false");
        }

        let config: config::ServerConfig =
            Figment::from(Serialized::defaults(config::ServerConfig::default()))
                .merge(Env::prefixed("ALLOWTHEM_").split("__"))
                .extract()
                .unwrap();

        assert_eq!(config.bind, "0.0.0.0:8080".parse().unwrap());
        assert!(!config.cookie_secure);

        // Clean up
        unsafe {
            std::env::remove_var("ALLOWTHEM_BIND");
            std::env::remove_var("ALLOWTHEM_COOKIE_SECURE");
        }
    }

    #[tokio::test]
    async fn health_endpoint() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();
        let auth_client: Arc<dyn AuthClient> =
            Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
        let templates = Arc::new(minijinja::Environment::new());
        let state = AppState {
            ath,
            auth_client,
            base_url: "http://localhost:3000".into(),
            templates,
            is_production: false,
            login_attempts: Arc::new(dashmap::DashMap::new()),
            max_login_attempts: 10,
            rate_limit_window_secs: 900,
            email_sender: Arc::new(LogEmailSender),
            oauth_providers: Vec::new(),
        };
        let app = Router::new()
            .route("/health", get(health))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json, serde_json::json!({"status": "ok"}));
    }

    #[test]
    fn decode_hex_key_valid() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = decode_hex_key(hex).unwrap();
        assert_eq!(key[0], 0x01);
        assert_eq!(key[1], 0x23);
        assert_eq!(key[31], 0xef);
    }

    #[test]
    fn decode_hex_key_invalid_hex() {
        let hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert!(decode_hex_key(hex).is_err());
    }

    #[test]
    fn decode_hex_key_wrong_length() {
        let hex = "0123456789abcdef0123456789abcdef"; // 32 chars = 16 bytes, not 32
        assert!(decode_hex_key(hex).is_err());
    }

    #[test]
    fn decode_hex_key_odd_length() {
        // 63 chars — odd length would panic on &hex[62..64] without the length guard
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde";
        assert!(decode_hex_key(hex).is_err());
    }

    #[tokio::test]
    async fn from_ref_impls() {
        use allowthem_core::AllowThem;
        use axum::extract::FromRef;

        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();
        let auth_client: Arc<dyn AuthClient> =
            Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
        let templates = Arc::new(minijinja::Environment::new());
        let state = AppState {
            ath,
            auth_client,
            base_url: "http://localhost:3000".into(),
            templates,
            is_production: false,
            login_attempts: Arc::new(dashmap::DashMap::new()),
            max_login_attempts: 10,
            rate_limit_window_secs: 900,
            email_sender: Arc::new(LogEmailSender),
            oauth_providers: Vec::new(),
        };

        // Verify Arc<dyn AuthClient> FromRef — used by AuthUser, OptionalAuthUser, middleware
        let client = <Arc<dyn AuthClient>>::from_ref(&state);
        assert_eq!(client.login_url(), "/login");

        // Verify AllowThem FromRef — used by future standalone route handlers (M31-34)
        let extracted_ath = AllowThem::from_ref(&state);
        assert_eq!(
            extracted_ath.session_config().cookie_name,
            "allowthem_session"
        );
    }

    // --- M30: Template engine and CSS switching tests ---

    #[test]
    fn template_env_loads() {
        let env = crate::templates::build_template_env();
        assert!(env.is_ok(), "template env should build: {:?}", env.err());
    }

    #[test]
    fn base_html_renders_dev_mode() {
        let env = crate::templates::build_template_env().unwrap();
        let result = crate::templates::render(&env, "base.html", minijinja::context! {}, false);
        let html = result.unwrap().0;
        assert!(
            html.contains("@tailwindcss/browser@4"),
            "dev mode should include Tailwind CDN"
        );
        assert!(
            !html.contains("/static/css/style.css"),
            "dev mode should not link compiled CSS"
        );
    }

    #[test]
    fn base_html_renders_production_mode() {
        let env = crate::templates::build_template_env().unwrap();
        let result = crate::templates::render(&env, "base.html", minijinja::context! {}, true);
        let html = result.unwrap().0;
        assert!(
            html.contains("/static/css/style.css"),
            "prod mode should link compiled CSS"
        );
        assert!(
            !html.contains("@tailwindcss/browser@4"),
            "prod mode should not include CDN"
        );
    }

    #[test]
    fn render_helper_injects_shared_context() {
        let mut env = minijinja::Environment::new();
        env.add_template("test.html", "production={{ is_production }}")
            .unwrap();
        let result = crate::templates::render(&env, "test.html", minijinja::context! {}, true);
        let html = result.unwrap().0;
        assert_eq!(html, "production=true");
    }

    #[test]
    fn render_preserves_caller_context() {
        let mut env = minijinja::Environment::new();
        env.add_template(
            "test.html",
            "title={{ page_title }} prod={{ is_production }}",
        )
        .unwrap();
        let result = crate::templates::render(
            &env,
            "test.html",
            minijinja::context! { page_title => "Login" },
            false,
        );
        assert_eq!(result.unwrap().0, "title=Login prod=false");
    }

    #[test]
    fn app_error_template_returns_500() {
        use axum::response::IntoResponse;
        let env = minijinja::Environment::new();
        let result =
            crate::templates::render(&env, "nonexistent.html", minijinja::context! {}, false);
        let err = result.unwrap_err();
        let response = err.into_response();
        assert_eq!(
            response.status(),
            axum::http::StatusCode::INTERNAL_SERVER_ERROR
        );
    }

    #[tokio::test]
    async fn static_file_serving() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();
        let auth_client: Arc<dyn AuthClient> =
            Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
        let templates = Arc::new(minijinja::Environment::new());
        let state = AppState {
            ath,
            auth_client,
            base_url: "http://localhost:3000".into(),
            templates,
            is_production: false,
            login_attempts: Arc::new(dashmap::DashMap::new()),
            max_login_attempts: 10,
            rate_limit_window_secs: 900,
            email_sender: Arc::new(LogEmailSender),
            oauth_providers: Vec::new(),
        };
        let static_dir = if let Ok(dir) = std::env::var("CARGO_MANIFEST_DIR") {
            std::path::PathBuf::from(dir).join("static")
        } else {
            std::path::PathBuf::from("binaries/static")
        };
        let app = Router::new()
            .nest_service("/static", ServeDir::new(&static_dir))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/static/.gitkeep")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }
}

#[cfg(test)]
mod consent_tests {
    use super::*;
    use allowthem_server::authorize_post;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    async fn consent_test_state() -> (allowthem_core::AllowThem, AppState) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();
        let auth_client: Arc<dyn AuthClient> =
            Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
        let templates = crate::templates::build_template_env().unwrap();
        let state = AppState {
            ath: ath.clone(),
            auth_client,
            base_url: "http://localhost:3000".into(),
            templates,
            is_production: false,
            login_attempts: Arc::new(dashmap::DashMap::new()),
            max_login_attempts: 10,
            rate_limit_window_secs: 900,
            email_sender: Arc::new(LogEmailSender),
            oauth_providers: Vec::new(),
        };
        (ath, state)
    }

    fn consent_router(state: AppState) -> Router {
        use allowthem_server::csrf_middleware;
        Router::new()
            .route(
                "/oauth/authorize",
                axum::routing::get(consent::get_authorize).post(authorize_post),
            )
            .layer(axum::middleware::from_fn(csrf_middleware))
            .with_state(state)
    }

    async fn create_test_session(ath: &allowthem_core::AllowThem, email: &str) -> String {
        let email = allowthem_core::types::Email::new(email.into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();
        let token = allowthem_core::generate_token();
        let hash = allowthem_core::hash_token(&token);
        let expires = chrono::Utc::now() + chrono::Duration::hours(24);
        ath.db()
            .create_session(user.id, hash, None, None, expires)
            .await
            .unwrap();
        format!("allowthem_session={}", token.as_str())
    }

    fn authorize_query(app: &allowthem_core::applications::Application) -> String {
        format!(
            "/oauth/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid+email&state=teststate&code_challenge=testchallenge&code_challenge_method=S256",
            app.client_id.as_str(),
            "https%3A%2F%2Fexample.com%2Fcallback"
        )
    }

    async fn read_body(resp: axum::http::Response<Body>) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn consent_screen_renders_html_with_scope_descriptions() {
        let (ath, state) = consent_test_state().await;
        let cookie = create_test_session(&ath, "html@test.com").await;
        let (app, _) = ath
            .db()
            .create_application(
                "MyTestApp".into(),
                vec!["https://example.com/callback".into()],
                false,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let router = consent_router(state);
        let req = Request::builder()
            .method("GET")
            .uri(&authorize_query(&app))
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert!(body.contains("MyTestApp"), "app name");
        assert!(body.contains("wants access to your account"), "prompt");
        assert!(body.contains("Verify your identity"), "openid scope");
        assert!(body.contains("View your email address"), "email scope");
        assert!(body.contains("Allow"), "allow button");
        assert!(body.contains("Deny"), "deny button");
        assert!(
            body.contains(r#"name="state" value="teststate""#),
            "state field"
        );
    }

    #[tokio::test]
    async fn consent_screen_redirects_for_trusted_app() {
        let (ath, state) = consent_test_state().await;
        let cookie = create_test_session(&ath, "trusted@test.com").await;
        let (app, _) = ath
            .db()
            .create_application(
                "TrustedApp".into(),
                vec!["https://example.com/callback".into()],
                true,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let router = consent_router(state);
        let req = Request::builder()
            .method("GET")
            .uri(&authorize_query(&app))
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(loc.contains("code="));
        assert!(loc.contains("state=teststate"));
    }

    #[tokio::test]
    async fn consent_screen_redirects_to_login_unauthenticated() {
        let (ath, state) = consent_test_state().await;
        let (app, _) = ath
            .db()
            .create_application(
                "NoAuth".into(),
                vec!["https://example.com/callback".into()],
                false,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let router = consent_router(state);
        let req = Request::builder()
            .method("GET")
            .uri(&authorize_query(&app))
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let loc = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(loc.starts_with("/login?next="), "should redirect to login");
        assert!(
            loc.contains(&format!("client_id={}", app.client_id)),
            "redirect should include client_id for branding"
        );
    }

    #[tokio::test]
    async fn create_application_rejects_http_logo_url() {
        let (ath, _state) = consent_test_state().await;
        let result = ath
            .db()
            .create_application(
                "HttpLogo".into(),
                vec!["https://example.com/callback".into()],
                false,
                None,
                Some("http://example.com/logo.png".into()),
                None,
            )
            .await;
        assert!(result.is_err(), "HTTP logo URL should be rejected");
    }

    #[tokio::test]
    async fn consent_screen_renders_logo_for_https_url() {
        let (ath, state) = consent_test_state().await;
        let cookie = create_test_session(&ath, "httpslogo@test.com").await;
        let (app, _) = ath
            .db()
            .create_application(
                "HttpsLogo".into(),
                vec!["https://example.com/callback".into()],
                false,
                None,
                Some("https://cdn.example.com/logo.png".into()),
                None,
            )
            .await
            .unwrap();
        let router = consent_router(state);
        let req = Request::builder()
            .method("GET")
            .uri(&authorize_query(&app))
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        let body = read_body(resp).await;
        assert!(body.contains("<img"), "should render img");
        // MiniJinja HTML-escapes attribute values; check that the img tag and a recognizable
        // portion of the URL are present
        assert!(
            body.contains("cdn.example.com"),
            "logo url should contain domain"
        );
    }

    #[tokio::test]
    async fn consent_screen_applies_primary_color() {
        let (ath, state) = consent_test_state().await;
        let cookie = create_test_session(&ath, "color@test.com").await;
        let (app, _) = ath
            .db()
            .create_application(
                "ColorApp".into(),
                vec!["https://example.com/callback".into()],
                false,
                None,
                None,
                Some("#ff6600".into()),
            )
            .await
            .unwrap();
        let router = consent_router(state);
        let req = Request::builder()
            .method("GET")
            .uri(&authorize_query(&app))
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        let body = read_body(resp).await;
        assert!(body.contains("at-btn-primary"), "themed button class");
        assert!(body.contains("#ff6600"), "accent color in theme");
    }

    #[tokio::test]
    async fn consent_screen_default_button_color() {
        let (ath, state) = consent_test_state().await;
        let cookie = create_test_session(&ath, "defcolor@test.com").await;
        let (app, _) = ath
            .db()
            .create_application(
                "DefaultColor".into(),
                vec!["https://example.com/callback".into()],
                false,
                None,
                None,
                None,
            )
            .await
            .unwrap();
        let router = consent_router(state);
        let req = Request::builder()
            .method("GET")
            .uri(&authorize_query(&app))
            .header("cookie", &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = router.oneshot(req).await.unwrap();
        let body = read_body(resp).await;
        assert!(body.contains("at-btn-primary"), "themed button class");
        assert!(body.contains("#2563eb"), "default blue accent");
    }
}
