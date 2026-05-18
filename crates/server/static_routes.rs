//! Static-asset routes for AllowThem-owned browser JS.
//!
//! Mounted at `/__allowthem/static/` in both embedded and standalone modes.
//! All assets are embedded in the binary via `include_bytes!` so integrators
//! don't need to vendor anything themselves.

use axum::Router;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;

const MODE_TOGGLE_JS: &[u8] = include_bytes!("assets/static/js/mode-toggle.js");
const SHADER_ASCII_JS: &[u8] = include_bytes!("assets/static/js/shader-ascii.js");

/// Cache-Control value for all static assets.
///
/// Files are served with fixed filenames, so we keep the TTL modest.
/// A future milestone can switch to content-hashed filenames + immutable.
const CACHE_CONTROL: &str = "public, max-age=1";

/// Build the static-asset router. Mount it at `/__allowthem/static/`.
pub fn router() -> Router {
    Router::new()
        .route(
            "/__allowthem/static/js/mode-toggle.js",
            get(|| asset(MODE_TOGGLE_JS, "application/javascript; charset=utf-8")),
        )
        .route(
            "/__allowthem/static/js/shader-ascii.js",
            get(|| asset(SHADER_ASCII_JS, "application/javascript; charset=utf-8")),
        )
}

async fn asset(bytes: &'static [u8], content_type: &'static str) -> impl IntoResponse {
    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static(CACHE_CONTROL),
    );
    (StatusCode::OK, headers, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn unknown_asset_returns_404() {
        let app = router();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/__allowthem/static/css/nonexistent.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn copied_wavefunk_assets_are_not_served() {
        let paths = [
            "/__allowthem/static/css/01-tokens.css",
            "/__allowthem/static/css/03-layout.css",
            "/__allowthem/static/fonts/MartianGrotesk-VF.woff2",
            "/__allowthem/static/js/echo.js",
        ];
        for path in paths {
            let app = router();
            let res = app
                .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(res.status(), StatusCode::NOT_FOUND, "{path} should be gone");
        }
    }

    #[tokio::test]
    async fn serves_mode_toggle_js() {
        let app = router();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/__allowthem/static/js/mode-toggle.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let ct = res.headers().get("content-type").unwrap();
        assert_eq!(ct, "application/javascript; charset=utf-8");
    }

    #[tokio::test]
    async fn serves_shader_ascii_js() {
        let app = router();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/__allowthem/static/js/shader-ascii.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let ct = res.headers().get("content-type").unwrap();
        assert_eq!(ct, "application/javascript; charset=utf-8");
    }
}
