//! Static-asset routes for Wave Funk CSS, Martian Grotesk font, and vanilla JS.
//!
//! Mounted at `/__allowthem/static/` in both embedded and standalone modes.
//! All assets are embedded in the binary via `include_bytes!` so integrators
//! don't need to vendor anything themselves.

use axum::Router;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;

const TOKENS_CSS: &[u8] = include_bytes!("assets/static/css/01-tokens.css");
const BASE_CSS: &[u8] = include_bytes!("assets/static/css/02-base.css");
const LAYOUT_CSS: &[u8] = include_bytes!("assets/static/css/03-layout.css");
const COMPONENTS_CSS: &[u8] = include_bytes!("assets/static/css/04-components.css");
const UTILITIES_CSS: &[u8] = include_bytes!("assets/static/css/05-utilities.css");

const MARTIAN_GROTESK_VF: &[u8] = include_bytes!("assets/static/fonts/MartianGrotesk-VF.woff2");

const MODE_TOGGLE_JS: &[u8] = include_bytes!("assets/static/js/mode-toggle.js");
const SHADER_ASCII_JS: &[u8] = include_bytes!("assets/static/js/shader-ascii.js");
const ECHO_JS: &[u8] = include_bytes!("assets/static/js/echo.js");

/// Cache-Control value for all static assets.
///
/// Files are served with fixed filenames, so we keep the TTL modest.
/// A future milestone can switch to content-hashed filenames + immutable.
const CACHE_CONTROL: &str = "public, max-age=1";

/// Build the static-asset router. Mount it at `/__allowthem/static/`.
pub fn router() -> Router {
    Router::new()
        .route(
            "/__allowthem/static/css/01-tokens.css",
            get(|| asset(TOKENS_CSS, "text/css; charset=utf-8")),
        )
        .route(
            "/__allowthem/static/css/02-base.css",
            get(|| asset(BASE_CSS, "text/css; charset=utf-8")),
        )
        .route(
            "/__allowthem/static/css/03-layout.css",
            get(|| asset(LAYOUT_CSS, "text/css; charset=utf-8")),
        )
        .route(
            "/__allowthem/static/css/04-components.css",
            get(|| asset(COMPONENTS_CSS, "text/css; charset=utf-8")),
        )
        .route(
            "/__allowthem/static/css/05-utilities.css",
            get(|| asset(UTILITIES_CSS, "text/css; charset=utf-8")),
        )
        .route(
            "/__allowthem/static/fonts/MartianGrotesk-VF.woff2",
            get(|| asset(MARTIAN_GROTESK_VF, "font/woff2")),
        )
        .route(
            "/__allowthem/static/js/mode-toggle.js",
            get(|| asset(MODE_TOGGLE_JS, "application/javascript; charset=utf-8")),
        )
        .route(
            "/__allowthem/static/js/shader-ascii.js",
            get(|| asset(SHADER_ASCII_JS, "application/javascript; charset=utf-8")),
        )
        .route(
            "/__allowthem/static/js/echo.js",
            get(|| asset(ECHO_JS, "application/javascript; charset=utf-8")),
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
    async fn serves_tokens_css() {
        let app = router();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/__allowthem/static/css/01-tokens.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let ct = res.headers().get("content-type").unwrap();
        assert_eq!(ct, "text/css; charset=utf-8");
    }

    #[tokio::test]
    async fn serves_layout_css() {
        let app = router();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/__allowthem/static/css/03-layout.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!body.is_empty(), "03-layout.css body is empty");
        let text = std::str::from_utf8(&body).expect("03-layout.css is utf-8");
        assert!(
            text.contains(".wf-auth"),
            "03-layout.css missing expected .wf-auth selector"
        );
    }

    #[tokio::test]
    async fn serves_martian_grotesk_woff2() {
        let app = router();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/__allowthem/static/fonts/MartianGrotesk-VF.woff2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let ct = res.headers().get("content-type").unwrap();
        assert_eq!(ct, "font/woff2");
    }

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

    #[tokio::test]
    async fn serves_echo_js() {
        let app = router();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/__allowthem/static/js/echo.js")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let ct = res.headers().get("content-type").unwrap();
        assert_eq!(ct, "application/javascript; charset=utf-8");
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).expect("echo.js is utf-8");
        assert!(text.contains("wfEcho"), "echo.js missing wfEcho symbol");
    }
}
