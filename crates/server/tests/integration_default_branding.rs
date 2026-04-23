//! Integration test: `AllRoutesBuilder::default_branding` causes `/login` to
//! render the embedder's brand when no `client_id` resolves to a per-app row.
//!
//! Exercises the full chain:
//!   `AllRoutesBuilder::default_branding(..).login().build(&ath)`
//!     -> `Extension<Arc<DefaultBranding>>` layer
//!     -> `get_login` extractor
//!     -> `resolve_branding`
//!     -> `BrandingCtx`
//!     -> rendered HTML contains the embedder's brand.

use allowthem_core::applications::BrandingConfig;
use allowthem_core::types::AccentInk;
use allowthem_core::{AllowThem, AllowThemBuilder};
use allowthem_server::AllRoutesBuilder;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

async fn ath_with_memory_db() -> AllowThem {
    AllowThemBuilder::new("sqlite::memory:")
        .cookie_secure(false)
        .csrf_key(*b"test-csrf-key-for-binary-tests!!")
        .build()
        .await
        .expect("build AllowThem")
}

#[tokio::test]
async fn login_uses_default_branding_when_no_client_id() {
    let ath = ath_with_memory_db().await;
    let router = AllRoutesBuilder::new()
        .login()
        .default_branding(
            BrandingConfig::new("Fixture Co").with_accent("#ff00aa", AccentInk::Black),
        )
        .build(&ath)
        .expect("build router");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = std::str::from_utf8(&body).unwrap();

    assert!(
        html.contains("FIXTURE CO"),
        "expected kicker uppercase 'FIXTURE CO' in login HTML, got:\n{}",
        &html[..html.len().min(800)]
    );
    assert!(
        html.contains("#ff00aa"),
        "expected accent '#ff00aa' in login HTML (CSS variable), got:\n{}",
        &html[..html.len().min(800)]
    );
}

#[tokio::test]
async fn login_falls_back_to_allowthem_when_no_default() {
    let ath = ath_with_memory_db().await;
    let router = AllRoutesBuilder::new()
        .login()
        .build(&ath)
        .expect("build router");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = std::str::from_utf8(&body).unwrap();

    assert!(
        html.contains("ALLOWTHEM"),
        "expected default kicker 'ALLOWTHEM' in login HTML, got:\n{}",
        &html[..html.len().min(800)]
    );
}

#[tokio::test]
async fn login_with_unknown_client_id_falls_back_to_default() {
    let ath = ath_with_memory_db().await;
    let router = AllRoutesBuilder::new()
        .login()
        .default_branding(
            BrandingConfig::new("Fixture Co").with_accent("#ff00aa", AccentInk::Black),
        )
        .build(&ath)
        .expect("build router");

    let response = router
        .oneshot(
            Request::builder()
                .uri("/login?client_id=ath_does_not_exist")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("oneshot");

    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let html = std::str::from_utf8(&body).unwrap();

    assert!(
        html.contains("FIXTURE CO"),
        "expected default kicker 'FIXTURE CO' when client_id doesn't match, got:\n{}",
        &html[..html.len().min(800)]
    );
    assert!(
        html.contains("#ff00aa"),
        "expected default accent '#ff00aa' when client_id doesn't match, got:\n{}",
        &html[..html.len().min(800)]
    );
}
