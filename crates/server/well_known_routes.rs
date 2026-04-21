//! `.well-known` HTTP routes: OIDC discovery document and JWKS endpoint.

use axum::Router;
use axum::extract::Extension;
use axum::http::StatusCode;
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::json;

use allowthem_core::AllowThem;
use allowthem_core::{build_discovery, build_jwks};

#[derive(Clone)]
struct WellKnownConfig {
    base_url: String,
}

fn server_error(e: impl std::fmt::Display) -> Response {
    tracing::error!("well-known route error: {e}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(json!({"error": "internal error"})),
    )
        .into_response()
}

/// `GET /.well-known/openid-configuration`
///
/// Returns the OIDC discovery document as `application/json`.
/// Pure function of `base_url` — no database access.
async fn openid_configuration(Extension(config): Extension<WellKnownConfig>) -> Response {
    let doc = build_discovery(&config.base_url);
    (
        [
            (CONTENT_TYPE, "application/json"),
            (CACHE_CONTROL, "public, max-age=3600"),
        ],
        axum::Json(doc),
    )
        .into_response()
}

/// `GET /.well-known/jwks.json`
///
/// Queries all signing keys from the database and builds the JWKS document.
async fn jwks(Extension(ath): Extension<AllowThem>) -> Response {
    let keys = match ath.db().get_all_signing_keys().await {
        Ok(k) => k,
        Err(e) => return server_error(e),
    };
    let jwk_set = match build_jwks(&keys) {
        Ok(j) => j,
        Err(e) => return server_error(e),
    };
    (
        [
            (CONTENT_TYPE, "application/json"),
            (CACHE_CONTROL, "public, max-age=300"),
        ],
        axum::Json(jwk_set),
    )
        .into_response()
}

/// Create a router with `.well-known` route handlers.
///
/// Returns a `Router<()>` with:
/// - `GET /.well-known/openid-configuration` — OIDC discovery document
/// - `GET /.well-known/jwks.json` — JSON Web Key Set
pub fn well_known_routes(base_url: String) -> Router<()> {
    let config = WellKnownConfig { base_url };
    Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration),
        )
        .route("/.well-known/jwks.json", get(jwks))
        .layer(Extension(config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::handle::AllowThemBuilder;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    const TEST_SIGNING_KEY: [u8; 32] = [0x42; 32];

    async fn test_app() -> (AllowThem, Router) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .signing_key(TEST_SIGNING_KEY)
            .build()
            .await
            .unwrap();

        let routes = well_known_routes("https://auth.example.com".into());
        let app = routes.layer(axum::middleware::from_fn_with_state(
            ath.clone(),
            crate::cors::inject_ath_into_extensions,
        ));
        (ath, app)
    }

    async fn read_body(resp: axum::http::Response<Body>) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn discovery_endpoint_returns_200() {
        let (_ath, app) = test_app().await;

        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/openid-configuration")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert_eq!(body["issuer"], "https://auth.example.com");
    }

    #[tokio::test]
    async fn discovery_endpoint_cache_control() {
        let (_ath, app) = test_app().await;

        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/openid-configuration")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        let cache = resp
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(cache, "public, max-age=3600");
    }

    #[tokio::test]
    async fn jwks_endpoint_empty_keys() {
        let (_ath, app) = test_app().await;

        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/jwks.json")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        assert_eq!(body["keys"], serde_json::json!([]));
    }

    #[tokio::test]
    async fn jwks_endpoint_returns_key() {
        let (ath, app) = test_app().await;

        // Seed a signing key
        let key = ath
            .db()
            .create_signing_key(&TEST_SIGNING_KEY)
            .await
            .unwrap();
        ath.db().activate_signing_key(key.id).await.unwrap();

        let req = Request::builder()
            .method("GET")
            .uri("/.well-known/jwks.json")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body(resp).await;
        let keys = body["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        let entry = &keys[0];
        assert!(entry.get("kty").is_some());
        assert!(entry.get("alg").is_some());
        assert!(entry.get("kid").is_some());
        assert!(entry.get("n").is_some());
        assert!(entry.get("e").is_some());
    }
}
