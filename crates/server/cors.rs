use std::collections::HashSet;

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use allowthem_core::AllowThem;

/// Bridges `State<AllowThem>` into request extensions so that
/// [`cors_middleware`] (which reads from extensions) works in standalone mode.
/// In SaaS mode the tenant router populates extensions directly; this shim is
/// not used there.
pub(crate) async fn inject_ath_into_extensions(
    State(ath): State<AllowThem>,
    mut req: Request<Body>,
    next: Next,
) -> Response {
    req.extensions_mut().insert(ath);
    next.run(req).await
}

/// Dynamic CORS middleware for OIDC endpoints.
///
/// The allowed-origin set is built per-request from all active applications'
/// redirect URIs. Requests without an `Origin` header are passed through
/// unchanged. Returns 500 if `AllowThem` is absent from request extensions
/// (server misconfiguration — the inject shim was not applied).
pub(crate) async fn cors_middleware(req: Request<Body>, next: Next) -> Response {
    let origin_header = req.headers().get(header::ORIGIN).cloned();

    let Some(origin_val) = origin_header else {
        return next.run(req).await;
    };

    let origin_str = match origin_val.to_str() {
        Ok(s) => s.to_owned(),
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    let ath = match req.extensions().get::<AllowThem>().cloned() {
        Some(a) => a,
        None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let is_preflight = req.method() == Method::OPTIONS;
    let allow_set = build_allow_set(&ath).await;

    if !allow_set.contains(&origin_str) {
        let mut res = StatusCode::FORBIDDEN.into_response();
        res.headers_mut()
            .insert(header::VARY, HeaderValue::from_static("Origin"));
        return res;
    }

    if is_preflight {
        let mut headers = HeaderMap::new();
        headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_val);
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("false"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("Authorization, Content-Type"),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("600"),
        );
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
        return (StatusCode::NO_CONTENT, headers).into_response();
    }

    let mut res = next.run(req).await;
    let headers = res.headers_mut();
    headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin_val);
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("false"),
    );
    headers.insert(header::VARY, HeaderValue::from_static("Origin"));
    res
}

async fn build_allow_set(ath: &AllowThem) -> HashSet<String> {
    let apps = match ath.db().list_applications().await {
        Ok(a) => a,
        Err(_) => return HashSet::new(),
    };
    apps.iter()
        .filter(|app| app.is_active)
        .flat_map(|app| app.redirect_uri_list().ok().unwrap_or_default())
        .filter_map(|uri| origin_of(uri.trim()))
        .collect()
}

fn origin_of(uri: &str) -> Option<String> {
    let parsed = url::Url::parse(uri).ok()?;
    match parsed.origin() {
        url::Origin::Opaque(_) => None,
        _ => Some(parsed.origin().ascii_serialization()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::AllowThemBuilder;
    use axum::Router;
    use axum::http::StatusCode;
    use axum::routing::get;
    use tower::ServiceExt;

    async fn dummy() -> StatusCode {
        StatusCode::OK
    }

    async fn make_test_app(redirect_uris: Vec<String>) -> Router {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();

        if !redirect_uris.is_empty() {
            ath.db()
                .create_application(
                    "TestApp".to_string(),
                    allowthem_core::ClientType::Confidential,
                    redirect_uris,
                    false,
                    None,
                    None,
                    None,
                )
                .await
                .unwrap();
        }

        Router::new()
            .route("/test", get(dummy).post(dummy))
            .layer(axum::middleware::from_fn(cors_middleware))
            .layer(axum::middleware::from_fn_with_state(
                ath.clone(),
                inject_ath_into_extensions,
            ))
            .with_state(ath)
    }

    #[tokio::test]
    async fn t1_allowed_origin_passes_through() {
        let app = make_test_app(vec!["https://app.example.com/callback".into()]).await;
        let req = Request::builder()
            .uri("/test")
            .header("Origin", "https://app.example.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "https://app.example.com"
        );
        assert_eq!(resp.headers().get("vary").unwrap(), "Origin");
    }

    #[tokio::test]
    async fn t2_disallowed_origin_returns_403() {
        let app = make_test_app(vec!["https://app.example.com/callback".into()]).await;
        let req = Request::builder()
            .uri("/test")
            .header("Origin", "https://evil.example.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert_eq!(resp.headers().get("vary").unwrap(), "Origin");
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }

    #[tokio::test]
    async fn t3_preflight_allowed_origin_returns_204() {
        let app = make_test_app(vec!["https://app.example.com/callback".into()]).await;
        let req = Request::builder()
            .method("OPTIONS")
            .uri("/test")
            .header("Origin", "https://app.example.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "https://app.example.com"
        );
        assert!(resp.headers().get("access-control-allow-methods").is_some());
        assert!(resp.headers().get("access-control-allow-headers").is_some());
        assert_eq!(resp.headers().get("access-control-max-age").unwrap(), "600");
        assert_eq!(resp.headers().get("vary").unwrap(), "Origin");
    }

    #[tokio::test]
    async fn t4_preflight_disallowed_origin_returns_403() {
        let app = make_test_app(vec!["https://app.example.com/callback".into()]).await;
        let req = Request::builder()
            .method("OPTIONS")
            .uri("/test")
            .header("Origin", "https://evil.example.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }

    #[tokio::test]
    async fn t5_no_origin_passes_through_unchanged() {
        let app = make_test_app(vec!["https://app.example.com/callback".into()]).await;
        let req = Request::builder().uri("/test").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("access-control-allow-origin").is_none());
        assert!(resp.headers().get("vary").is_none());
    }

    #[tokio::test]
    async fn t6_empty_application_list_rejects_all_origins() {
        let app = make_test_app(vec![]).await;
        let req = Request::builder()
            .uri("/test")
            .header("Origin", "https://any.example.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
