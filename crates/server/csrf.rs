use axum::{
    body::Body,
    extract::FromRequestParts,
    http::{Request, StatusCode, header, request::Parts},
    middleware::Next,
    response::Response,
};
use uuid::Uuid;

const CSRF_COOKIE_NAME: &str = "csrf_token";

/// A CSRF token for the current request.
///
/// Available to handlers via extractor after the `csrf_middleware` layer has run.
/// Embed this in forms as a hidden field named `csrf_token`, or send it as the
/// `X-CSRF-Token` header for AJAX requests.
#[derive(Clone)]
pub struct CsrfToken(pub String);

impl CsrfToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<S: Send + Sync> FromRequestParts<S> for CsrfToken {
    type Rejection = StatusCode;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<CsrfToken>()
            .cloned()
            .ok_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

/// CSRF protection middleware using the double-submit cookie pattern.
///
/// **Safe methods (GET, HEAD, OPTIONS):** Reads or generates a CSRF token, sets it
/// as a cookie on the response (not `HttpOnly` so JS/HTMX can read it), and inserts
/// it into request extensions so handlers can embed it in forms via [`CsrfToken`].
///
/// **Unsafe methods (POST, PUT, DELETE, PATCH):** Requires the submitted token
/// (from `X-CSRF-Token` header or `csrf_token` form field) to match the CSRF
/// cookie. Returns 403 on mismatch or missing token.
pub async fn csrf_middleware(
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let method = request.method().clone();
    let is_safe = matches!(
        method,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );

    let cookie_token = extract_csrf_cookie(request.headers());

    if is_safe {
        let is_new = cookie_token.is_none();
        let token = cookie_token.unwrap_or_else(|| Uuid::new_v4().to_string());

        request.extensions_mut().insert(CsrfToken(token.clone()));

        let mut response = next.run(request).await;

        if is_new {
            let cookie = format!("{}={}; SameSite=Lax; Path=/", CSRF_COOKIE_NAME, token);
            if let Ok(value) = cookie.parse() {
                response.headers_mut().append(header::SET_COOKIE, value);
            }
        }

        Ok(response)
    } else {
        let submitted = extract_submitted_token(&mut request).await?;

        let cookie_val = cookie_token.ok_or(StatusCode::FORBIDDEN)?;

        if submitted != cookie_val {
            return Err(StatusCode::FORBIDDEN);
        }

        request.extensions_mut().insert(CsrfToken(cookie_val));

        Ok(next.run(request).await)
    }
}

/// Extract the CSRF token from the `csrf_token` cookie in the `Cookie` header.
fn extract_csrf_cookie(headers: &header::HeaderMap) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split("; ") {
        if let Some((name, value)) = pair.split_once('=')
            && name.trim() == CSRF_COOKIE_NAME
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

/// Extract the submitted CSRF token from either the `X-CSRF-Token` header or
/// the `csrf_token` field in a `application/x-www-form-urlencoded` body.
///
/// Consumes and then replaces the request body so the handler still receives it.
async fn extract_submitted_token(request: &mut Request<Body>) -> Result<String, StatusCode> {
    // Check header first — preferred for AJAX/HTMX.
    if let Some(header_val) = request.headers().get("x-csrf-token")
        && let Ok(token) = header_val.to_str()
    {
        return Ok(token.to_string());
    }

    // Fall back to form body for traditional form submissions.
    let is_form = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/x-www-form-urlencoded"))
        .unwrap_or(false);

    if !is_form {
        return Err(StatusCode::FORBIDDEN);
    }

    // Consume the body to search for the token.
    let body = std::mem::replace(request.body_mut(), Body::empty());
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    // Put the body back so the handler can read it.
    *request.body_mut() = Body::from(bytes.clone());

    // Parse without serde_urlencoded: find csrf_token=<value> pair.
    let body_str = std::str::from_utf8(&bytes).map_err(|_| StatusCode::BAD_REQUEST)?;
    for pair in body_str.split('&') {
        if let Some((key, value)) = pair.split_once('=')
            && key == "csrf_token"
        {
            return Ok(value.to_string());
        }
    }

    Err(StatusCode::FORBIDDEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, middleware, routing::get};
    use tower::ServiceExt;

    async fn ok_handler() -> StatusCode {
        StatusCode::OK
    }

    fn test_app() -> Router {
        Router::new()
            .route("/", get(ok_handler).post(ok_handler))
            .layer(middleware::from_fn(csrf_middleware))
    }

    fn get_set_cookie(response: &Response) -> Option<String> {
        response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    fn extract_token_from_set_cookie(set_cookie: &str) -> String {
        // Format: "csrf_token=<value>; SameSite=Lax; Path=/"
        set_cookie
            .split(';')
            .next()
            .and_then(|pair| pair.split_once('='))
            .map(|(_, v)| v.trim().to_string())
            .expect("csrf token not found in Set-Cookie")
    }

    #[tokio::test]
    async fn get_sets_csrf_cookie() {
        let app = test_app();
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let set_cookie = get_set_cookie(&response).expect("Set-Cookie header missing");
        assert!(set_cookie.starts_with("csrf_token="));
        assert!(set_cookie.contains("SameSite=Lax"));
    }

    #[tokio::test]
    async fn head_does_not_require_csrf() {
        let app = Router::new()
            .route("/", axum::routing::any(ok_handler))
            .layer(middleware::from_fn(csrf_middleware));

        let response = app
            .oneshot(
                Request::builder()
                    .method("HEAD")
                    .uri("/")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn post_with_valid_header_token_passes() {
        let app = test_app();

        // First GET to obtain a token.
        let get_resp = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let set_cookie = get_set_cookie(&get_resp).expect("Set-Cookie missing");
        let token = extract_token_from_set_cookie(&set_cookie);

        // POST with the token in the header and the cookie set.
        let post_resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::COOKIE, format!("csrf_token={token}"))
                    .header("x-csrf-token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(post_resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn post_with_valid_form_token_passes() {
        let app = test_app();

        let get_resp = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let set_cookie = get_set_cookie(&get_resp).expect("Set-Cookie missing");
        let token = extract_token_from_set_cookie(&set_cookie);

        let body = format!("username=alice&csrf_token={token}");
        let post_resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::COOKIE, format!("csrf_token={token}"))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(post_resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn post_with_missing_token_returns_403() {
        let app = test_app();

        // POST with a cookie but no submitted token.
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::COOKIE, "csrf_token=someval")
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from("username=alice"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_with_wrong_token_returns_403() {
        let app = test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::COOKIE, "csrf_token=correct")
                    .header("x-csrf-token", "wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_with_missing_cookie_returns_403() {
        let app = test_app();

        // Token in header but no cookie.
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header("x-csrf-token", "sometoken")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn existing_cookie_not_overwritten_on_get() {
        let app = test_app();

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::COOKIE, "csrf_token=existing_token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        // No new Set-Cookie should be issued since the cookie already exists.
        assert!(get_set_cookie(&response).is_none());
    }
}
