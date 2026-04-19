use axum::{
    body::Body,
    extract::{FromRequestParts, State},
    http::{Request, StatusCode, header, request::Parts},
    middleware::Next,
    response::Response,
};
use subtle::ConstantTimeEq;
use uuid::Uuid;

use allowthem_core::{AllowThem, derive_csrf_token, verify_csrf_token};

const PRE_AUTH_CSRF_COOKIE: &str = "csrf_pre";

/// A CSRF token for the current request.
///
/// Available to handlers via extractor after `csrf_middleware` has run.
/// Embed in forms as a hidden field named `csrf_token`, or send as
/// `X-CSRF-Token` header for AJAX/HTMX requests.
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

/// CSRF protection middleware using session-bound HMAC derivation.
///
/// **Authenticated requests (session cookie present):**
/// The CSRF token is `HMAC-SHA256(csrf_key, session_token_bytes)`. No DB read
/// needed — the token is derived from the cookie value already in memory.
/// The derived token is stable for the session lifetime (SPA/HTMX friendly).
///
/// **Pre-auth requests (no session cookie, e.g. login/register forms):**
/// Falls back to a double-submit cookie pattern using a `csrf_pre` cookie.
/// A random UUID is generated on GET and stored in `csrf_pre`; POST must
/// echo it back via `X-CSRF-Token` header or `csrf_token` form field.
///
/// Returns 403 on CSRF mismatch and 500 if `csrf_key` is not configured.
pub async fn csrf_middleware(
    State(ath): State<AllowThem>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let csrf_key = ath
        .csrf_key()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let method = request.method().clone();
    let is_safe = matches!(
        method,
        axum::http::Method::GET | axum::http::Method::HEAD | axum::http::Method::OPTIONS
    );

    let session_token = ath.parse_session_cookie(
        request
            .headers()
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or(""),
    );

    if is_safe {
        let csrf_token = match &session_token {
            Some(tok) => derive_csrf_token(tok, csrf_key),
            None => extract_pre_auth_csrf_cookie(request.headers())
                .unwrap_or_else(|| Uuid::new_v4().to_string()),
        };

        let is_new_pre_auth =
            session_token.is_none() && extract_pre_auth_csrf_cookie(request.headers()).is_none();

        request
            .extensions_mut()
            .insert(CsrfToken(csrf_token.clone()));

        let mut response = next.run(request).await;

        if is_new_pre_auth {
            let secure = ath.session_config().secure;
            set_pre_auth_csrf_cookie(&mut response, &csrf_token, secure);
        }

        Ok(response)
    } else {
        let submitted = extract_submitted_token(&mut request).await?;

        match &session_token {
            Some(tok) => {
                if !verify_csrf_token(tok, csrf_key, &submitted) {
                    return Err(StatusCode::FORBIDDEN);
                }
                request.extensions_mut().insert(CsrfToken(submitted));
            }
            None => {
                let cookie_val =
                    extract_pre_auth_csrf_cookie(request.headers()).ok_or(StatusCode::FORBIDDEN)?;
                if cookie_val.len() != submitted.len() {
                    return Err(StatusCode::FORBIDDEN);
                }
                let matches: bool = cookie_val.as_bytes().ct_eq(submitted.as_bytes()).into();
                if !matches {
                    return Err(StatusCode::FORBIDDEN);
                }
                request.extensions_mut().insert(CsrfToken(submitted));
            }
        }

        Ok(next.run(request).await)
    }
}

fn extract_pre_auth_csrf_cookie(headers: &header::HeaderMap) -> Option<String> {
    let cookie_header = headers.get(header::COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split("; ") {
        if let Some((name, value)) = pair.split_once('=')
            && name.trim() == PRE_AUTH_CSRF_COOKIE
        {
            return Some(value.trim().to_string());
        }
    }
    None
}

fn set_pre_auth_csrf_cookie(response: &mut Response, token: &str, secure: bool) {
    let mut cookie = format!(
        "{}={}; SameSite=Lax; Path=/; Max-Age=1800",
        PRE_AUTH_CSRF_COOKIE, token
    );
    if secure {
        cookie.push_str("; Secure");
    }
    if let Ok(value) = cookie.parse() {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
}

/// Extract the submitted CSRF token from `X-CSRF-Token` header or
/// `csrf_token` field in an `application/x-www-form-urlencoded` body.
///
/// Consumes and replaces the request body so the handler still receives it.
async fn extract_submitted_token(request: &mut Request<Body>) -> Result<String, StatusCode> {
    if let Some(header_val) = request.headers().get("x-csrf-token")
        && let Ok(token) = header_val.to_str()
    {
        return Ok(token.to_string());
    }

    let is_form = request
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.starts_with("application/x-www-form-urlencoded"))
        .unwrap_or(false);

    if !is_form {
        return Err(StatusCode::FORBIDDEN);
    }

    let body = std::mem::replace(request.body_mut(), Body::empty());
    let bytes = axum::body::to_bytes(body, 64 * 1024)
        .await
        .map_err(|_| StatusCode::BAD_REQUEST)?;

    *request.body_mut() = Body::from(bytes.clone());

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
    use allowthem_core::{AllowThemBuilder, Email, generate_token, hash_token};
    use axum::{Router, middleware, routing::get};
    use chrono::{Duration, Utc};
    use tower::ServiceExt;

    const TEST_CSRF_KEY: [u8; 32] = *b"test-csrf-key-32bytes-padding!!!";

    async fn ok_handler() -> StatusCode {
        StatusCode::OK
    }

    async fn build_ath() -> AllowThem {
        AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .csrf_key(TEST_CSRF_KEY)
            .build()
            .await
            .unwrap()
    }

    fn test_app(ath: AllowThem) -> Router {
        Router::new()
            .route("/", get(ok_handler).post(ok_handler))
            .layer(middleware::from_fn_with_state(ath.clone(), csrf_middleware))
            .with_state(ath)
    }

    fn get_set_cookie(response: &Response) -> Option<String> {
        response
            .headers()
            .get(header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    }

    fn extract_token_from_set_cookie(set_cookie: &str) -> String {
        set_cookie
            .split(';')
            .next()
            .and_then(|pair| pair.split_once('='))
            .map(|(_, v)| v.trim().to_string())
            .expect("csrf token not found in Set-Cookie")
    }

    // --- Pre-auth path (no session cookie) ---

    #[tokio::test]
    async fn pre_auth_get_sets_csrf_pre_cookie() {
        let app = test_app(build_ath().await);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let set_cookie = get_set_cookie(&response).expect("Set-Cookie header missing");
        assert!(set_cookie.starts_with("csrf_pre="));
        assert!(set_cookie.contains("SameSite=Lax"));
        assert!(set_cookie.contains("Max-Age=1800"));
        assert!(!set_cookie.contains("Secure"));
    }

    #[tokio::test]
    async fn pre_auth_get_does_not_reset_existing_csrf_pre_cookie() {
        let app = test_app(build_ath().await);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::COOKIE, "csrf_pre=existing_value")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(get_set_cookie(&response).is_none());
    }

    #[tokio::test]
    async fn pre_auth_post_accepts_matching_cookie_and_header() {
        let app = test_app(build_ath().await);
        let get_resp = app
            .clone()
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let set_cookie = get_set_cookie(&get_resp).expect("Set-Cookie missing");
        let token = extract_token_from_set_cookie(&set_cookie);
        let post_resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::COOKIE, format!("csrf_pre={token}"))
                    .header("x-csrf-token", &token)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(post_resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn pre_auth_post_rejects_mismatched_token() {
        let app = test_app(build_ath().await);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::COOKIE, "csrf_pre=correct")
                    .header("x-csrf-token", "wrong")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn pre_auth_post_rejects_missing_cookie() {
        let app = test_app(build_ath().await);
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
    async fn pre_auth_post_accepts_form_token() {
        let app = test_app(build_ath().await);
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
                    .header(header::COOKIE, format!("csrf_pre={token}"))
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(post_resp.status(), StatusCode::OK);
    }

    // --- Session-bound path ---

    async fn make_session_cookie(ath: &AllowThem) -> (String, String) {
        let email = Email::new("user@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password", None, None)
            .await
            .unwrap();
        let token = generate_token();
        let hash = hash_token(&token);
        let expires = Utc::now() + Duration::hours(24);
        ath.db()
            .create_session(user.id, hash, None, None, expires)
            .await
            .unwrap();
        let cookie_header = ath.session_cookie(&token);
        let cookie_value = cookie_header.split(';').next().unwrap().to_string();
        let csrf = derive_csrf_token(&token, &TEST_CSRF_KEY);
        (cookie_value, csrf)
    }

    #[tokio::test]
    async fn session_bound_get_does_not_set_csrf_pre_cookie() {
        let ath = build_ath().await;
        let (session_cookie, _) = make_session_cookie(&ath).await;
        let app = test_app(ath);
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .header(header::COOKIE, &session_cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(get_set_cookie(&response).is_none());
    }

    #[tokio::test]
    async fn session_bound_post_accepts_derived_token_in_header() {
        let ath = build_ath().await;
        let (session_cookie, csrf) = make_session_cookie(&ath).await;
        let app = test_app(ath);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::COOKIE, &session_cookie)
                    .header("x-csrf-token", &csrf)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn session_bound_post_rejects_wrong_token() {
        let ath = build_ath().await;
        let (session_cookie, _) = make_session_cookie(&ath).await;
        let app = test_app(ath);
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::COOKIE, &session_cookie)
                    .header(
                        "x-csrf-token",
                        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn session_bound_post_accepts_form_token() {
        let ath = build_ath().await;
        let (session_cookie, csrf) = make_session_cookie(&ath).await;
        let app = test_app(ath);
        let body = format!("field=value&csrf_token={csrf}");
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/")
                    .header(header::COOKIE, &session_cookie)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn returns_500_when_csrf_key_not_configured() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();
        let app = Router::new()
            .route("/", get(ok_handler).post(ok_handler))
            .layer(middleware::from_fn_with_state(ath.clone(), csrf_middleware))
            .with_state(ath);
        let response = app
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn head_does_not_require_csrf() {
        let app = test_app(build_ath().await);
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
}
