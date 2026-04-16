mod config;
mod error;
mod logout;
mod state;
mod templates;

use std::sync::Arc;

use axum::{Router, response::IntoResponse, routing::get};
use chrono::Duration;
use eyre::Result;
use tower_http::services::ServeDir;
use tracing_subscriber::EnvFilter;

use allowthem_core::{AllowThemBuilder, AuthClient, EmbeddedAuthClient};

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
        Some(hex) => Some(decode_mfa_key(hex)?),
        None => None,
    };

    // 4. AllowThem handle
    let mut builder = AllowThemBuilder::new(&config.database_url)
        .session_ttl(Duration::hours(config.session_ttl_hours as i64))
        .cookie_secure(config.cookie_secure)
        .cookie_domain(&config.cookie_domain);
    if let Some(key) = mfa_key {
        builder = builder.mfa_key(key);
    }
    let ath = builder.build().await?;

    // 5. Templates
    let templates = templates::build_template_env()?;

    // 6. App state
    let auth_client: Arc<dyn AuthClient> = Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
    let state = AppState {
        ath,
        auth_client,
        base_url: config.base_url.clone(),
        templates,
        is_production: config.is_production,
    };

    // 7. Router
    let app = Router::new()
        .route("/health", get(health))
        .route("/logout", get(logout::handler).post(logout::handler))
        .nest_service("/static", ServeDir::new("binaries/static"))
        .with_state(state);

    // 8. Serve
    let listener = tokio::net::TcpListener::bind(config.bind).await?;
    tracing::info!("listening on {}", config.bind);
    axum::serve(listener, app)
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

fn decode_mfa_key(hex: &str) -> Result<[u8; 32]> {
    if hex.len() != 64 {
        eyre::bail!(
            "mfa_key_hex must be 64 hex chars (32 bytes), got {} chars",
            hex.len()
        );
    }
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16))
        .collect::<Result<Vec<u8>, _>>()
        .map_err(|e| eyre::eyre!("invalid mfa_key_hex: {e}"))?;
    bytes
        .try_into()
        .map_err(|_: Vec<u8>| eyre::eyre!("mfa_key_hex decode failed"))
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
    fn decode_mfa_key_valid() {
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let key = decode_mfa_key(hex).unwrap();
        assert_eq!(key[0], 0x01);
        assert_eq!(key[1], 0x23);
        assert_eq!(key[31], 0xef);
    }

    #[test]
    fn decode_mfa_key_invalid_hex() {
        let hex = "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
        assert!(decode_mfa_key(hex).is_err());
    }

    #[test]
    fn decode_mfa_key_wrong_length() {
        let hex = "0123456789abcdef0123456789abcdef"; // 32 chars = 16 bytes, not 32
        assert!(decode_mfa_key(hex).is_err());
    }

    #[test]
    fn decode_mfa_key_odd_length() {
        // 63 chars — odd length would panic on &hex[62..64] without the length guard
        let hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde";
        assert!(decode_mfa_key(hex).is_err());
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
        env.add_template("test.html", "title={{ page_title }} prod={{ is_production }}")
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
        let result = crate::templates::render(&env, "nonexistent.html", minijinja::context! {}, false);
        let err = result.unwrap_err();
        let response = err.into_response();
        assert_eq!(response.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
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
