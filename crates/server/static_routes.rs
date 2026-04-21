//! Static-asset routes for Wave Funk CSS, Iosevka Aile fonts, and vanilla JS.
//!
//! Mounted at `/__allowthem/static/` in both embedded and standalone modes.
//! All assets are embedded in the binary via `include_bytes!` so integrators
//! don't need to vendor anything themselves.

use axum::Router;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;

const COLORS_AND_TYPE_CSS: &[u8] = include_bytes!("assets/static/css/colors_and_type.css");
const KIT_CSS: &[u8] = include_bytes!("assets/static/css/kit.css");
const FONTS_CSS: &[u8] = include_bytes!("assets/static/css/fonts.css");

const IOSEVKA_400: &[u8] = include_bytes!("assets/static/fonts/iosevka-aile-400.woff2");
const IOSEVKA_500: &[u8] = include_bytes!("assets/static/fonts/iosevka-aile-500.woff2");
const IOSEVKA_600: &[u8] = include_bytes!("assets/static/fonts/iosevka-aile-600.woff2");
const IOSEVKA_800: &[u8] = include_bytes!("assets/static/fonts/iosevka-aile-800.woff2");

const MODE_TOGGLE_JS: &[u8] = include_bytes!("assets/static/js/mode-toggle.js");
const SHADER_ASCII_JS: &[u8] = include_bytes!("assets/static/js/shader-ascii.js");

/// Cache-Control value for all static assets.
///
/// Files are served with fixed filenames, so we keep the TTL modest.
/// A future milestone can switch to content-hashed filenames + immutable.
const CACHE_CONTROL: &str = "public, max-age=3600";

/// Build the static-asset router. Mount it at `/__allowthem/static/`.
pub fn router() -> Router {
    Router::new()
        .route(
            "/__allowthem/static/css/colors_and_type.css",
            get(|| asset(COLORS_AND_TYPE_CSS, "text/css; charset=utf-8")),
        )
        .route(
            "/__allowthem/static/css/kit.css",
            get(|| asset(KIT_CSS, "text/css; charset=utf-8")),
        )
        .route(
            "/__allowthem/static/css/fonts.css",
            get(|| asset(FONTS_CSS, "text/css; charset=utf-8")),
        )
        .route(
            "/__allowthem/static/fonts/iosevka-aile-400.woff2",
            get(|| asset(IOSEVKA_400, "font/woff2")),
        )
        .route(
            "/__allowthem/static/fonts/iosevka-aile-500.woff2",
            get(|| asset(IOSEVKA_500, "font/woff2")),
        )
        .route(
            "/__allowthem/static/fonts/iosevka-aile-600.woff2",
            get(|| asset(IOSEVKA_600, "font/woff2")),
        )
        .route(
            "/__allowthem/static/fonts/iosevka-aile-800.woff2",
            get(|| asset(IOSEVKA_800, "font/woff2")),
        )
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
    async fn serves_colors_and_type_css() {
        let app = router();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/__allowthem/static/css/colors_and_type.css")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let ct = res.headers().get("content-type").unwrap();
        assert_eq!(ct, "text/css; charset=utf-8");
        let cc = res.headers().get("cache-control").unwrap();
        assert_eq!(cc, "public, max-age=3600");
    }

    #[tokio::test]
    async fn serves_iosevka_woff2() {
        let app = router();
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/__allowthem/static/fonts/iosevka-aile-400.woff2")
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
}
