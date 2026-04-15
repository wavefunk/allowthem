use axum::body::Body;
use axum::extract::FromRef;
use axum::http::{Request, StatusCode, header::COOKIE};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use allowthem_core::{AllowThem, AuthError, PermissionName, RoleName, User};

/// Axum middleware that requires a valid authenticated session.
///
/// Validates the session cookie, fetches the user, and inserts the [`User`]
/// into request extensions so downstream handlers can access it cheaply via
/// `Extension<User>`. Returns 401 JSON on any authentication failure.
///
/// Apply to a route group with `axum::middleware::from_fn_with_state(ath, require_auth)`.
pub async fn require_auth<S>(
    state: axum::extract::State<S>,
    mut request: Request<Body>,
    next: Next,
) -> Response
where
    AllowThem: FromRef<S>,
    S: Send + Sync + Clone,
{
    let ath = AllowThem::from_ref(&*state);
    // Clone the headers out before any await so we don't hold &Request<Body>
    // (Body is not Sync) across an await point.
    let headers = request.headers().clone();

    let user = match authenticate(&ath, &headers).await {
        Ok(u) => u,
        Err(r) => return r,
    };

    request.extensions_mut().insert(user);
    next.run(request).await
}

/// Middleware factory that requires the authenticated user to have a specific role.
///
/// Builds on `require_auth`: first validates the session (inserting `User` into
/// extensions), then checks the role. Returns 401 if not authenticated, 403 if
/// authenticated but missing the role.
///
/// Usage:
/// ```ignore
/// use axum::middleware;
///
/// let app = Router::new()
///     .route("/admin", get(handler))
///     .layer(middleware::from_fn_with_state(
///         ath.clone(),
///         require_role("admin"),
///     ));
/// ```
pub fn require_role<S>(
    role: impl Into<String>,
) -> impl Fn(
    axum::extract::State<S>,
    Request<Body>,
    Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
+ Clone
+ Send
+ 'static
where
    AllowThem: FromRef<S>,
    S: Send + Sync + Clone + 'static,
{
    let role_name = role.into();
    move |state, request, next| {
        let role_name = role_name.clone();
        Box::pin(require_role_inner(state, request, next, role_name))
    }
}

async fn require_role_inner<S>(
    state: axum::extract::State<S>,
    mut request: Request<Body>,
    next: Next,
    role_name: String,
) -> Response
where
    AllowThem: FromRef<S>,
    S: Send + Sync + Clone,
{
    let ath = AllowThem::from_ref(&*state);
    let headers = request.headers().clone();

    let user = match authenticate(&ath, &headers).await {
        Ok(u) => u,
        Err(r) => return r,
    };

    let rn = RoleName::new(role_name);
    match ath.db().has_role(&user.id, &rn).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(json!({"error": "forbidden"})),
            )
                .into_response();
        }
        Err(e) => return internal_error(e),
    }

    request.extensions_mut().insert(user);
    next.run(request).await
}

/// Middleware factory that requires the authenticated user to have a specific permission.
///
/// Works identically to [`require_role`] but checks permissions instead of roles.
/// Permissions are checked via both direct assignment and role membership.
///
/// Returns 401 if not authenticated, 403 if authenticated but missing the permission.
pub fn require_permission<S>(
    permission: impl Into<String>,
) -> impl Fn(
    axum::extract::State<S>,
    Request<Body>,
    Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Response> + Send>>
+ Clone
+ Send
+ 'static
where
    AllowThem: FromRef<S>,
    S: Send + Sync + Clone + 'static,
{
    let perm_name = permission.into();
    move |state, request, next| {
        let perm_name = perm_name.clone();
        Box::pin(require_permission_inner(state, request, next, perm_name))
    }
}

async fn require_permission_inner<S>(
    state: axum::extract::State<S>,
    mut request: Request<Body>,
    next: Next,
    perm_name: String,
) -> Response
where
    AllowThem: FromRef<S>,
    S: Send + Sync + Clone,
{
    let ath = AllowThem::from_ref(&*state);
    let headers = request.headers().clone();

    let user = match authenticate(&ath, &headers).await {
        Ok(u) => u,
        Err(r) => return r,
    };

    let pn = PermissionName::new(perm_name);
    match ath.db().has_permission(&user.id, &pn).await {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::FORBIDDEN,
                axum::Json(json!({"error": "forbidden"})),
            )
                .into_response();
        }
        Err(e) => return internal_error(e),
    }

    request.extensions_mut().insert(user);
    next.run(request).await
}

/// Shared authentication logic: parse cookie, validate session, fetch user.
///
/// Takes the headers directly so the caller does not hold a `&Request<Body>` reference
/// across await points (Body is not Sync).
///
/// Returns the active `User` on success, or an `IntoResponse` error response.
async fn authenticate(ath: &AllowThem, headers: &axum::http::HeaderMap) -> Result<User, Response> {
    let cookie_header = headers
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(unauthenticated)?
        .to_string();

    let token = ath
        .parse_session_cookie(&cookie_header)
        .ok_or_else(unauthenticated)?;

    let session = ath
        .db()
        .validate_session(&token, ath.session_config().ttl)
        .await
        .map_err(internal_error)?
        .ok_or_else(unauthenticated)?;

    let user = ath
        .db()
        .get_user(session.user_id)
        .await
        .map_err(|e| match e {
            AuthError::NotFound => unauthenticated(),
            other => internal_error(other),
        })?;

    if !user.is_active {
        return Err((
            StatusCode::UNAUTHORIZED,
            axum::Json(json!({"error": "account inactive"})),
        )
            .into_response());
    }

    Ok(user)
}

fn unauthenticated() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        axum::Json(json!({"error": "unauthenticated"})),
    )
        .into_response()
}

fn internal_error(err: AuthError) -> Response {
    tracing::error!("auth middleware error: {err}");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        axum::Json(json!({"error": "internal error"})),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::{AllowThemBuilder, Email, generate_token, hash_token};
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::{Router, middleware};
    use chrono::{Duration, Utc};
    use tower::ServiceExt;

    /// Build AllowThem, create a user with an active session, return (AllowThem, cookie_value).
    async fn test_setup() -> (AllowThem, String) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let email = Email::new("user@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();

        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = Utc::now() + Duration::hours(24);
        ath.db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();

        let cookie = ath.session_cookie(&token);
        let cookie_value = cookie.split(';').next().unwrap().to_string();
        (ath, cookie_value)
    }

    async fn ok_handler() -> StatusCode {
        StatusCode::OK
    }

    fn auth_app(ath: AllowThem) -> Router {
        Router::new()
            .route("/protected", get(ok_handler))
            .layer(middleware::from_fn_with_state(ath.clone(), require_auth))
            .with_state(ath)
    }

    fn role_app(ath: AllowThem, role: &str) -> Router {
        let role = role.to_string();
        Router::new()
            .route("/protected", get(ok_handler))
            .layer(middleware::from_fn_with_state(
                ath.clone(),
                require_role::<AllowThem>(role),
            ))
            .with_state(ath)
    }

    fn perm_app(ath: AllowThem, perm: &str) -> Router {
        let perm = perm.to_string();
        Router::new()
            .route("/protected", get(ok_handler))
            .layer(middleware::from_fn_with_state(
                ath.clone(),
                require_permission::<AllowThem>(perm),
            ))
            .with_state(ath)
    }

    fn make_request(cookie: Option<&str>) -> axum::http::Request<Body> {
        let mut builder = axum::http::Request::builder().uri("/protected");
        if let Some(c) = cookie {
            builder = builder.header(COOKIE, c);
        }
        builder.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn authenticated_request_passes_through() {
        let (ath, cookie) = test_setup().await;
        let app = auth_app(ath);
        let resp = app.oneshot(make_request(Some(&cookie))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn unauthenticated_request_returns_401() {
        let (ath, _) = test_setup().await;
        let app = auth_app(ath);
        let resp = app.oneshot(make_request(None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn require_role_with_correct_role_passes() {
        let (ath, cookie) = test_setup().await;

        // Create role and assign to user.
        let rn = allowthem_core::RoleName::new("admin");
        let role = ath.db().create_role(&rn, None).await.unwrap();
        let email = Email::new("user@example.com".into()).unwrap();
        let user = ath.db().get_user_by_email(&email).await.unwrap();
        ath.db().assign_role(&user.id, &role.id).await.unwrap();

        let app = role_app(ath, "admin");
        let resp = app.oneshot(make_request(Some(&cookie))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn require_role_with_wrong_role_returns_403() {
        let (ath, cookie) = test_setup().await;
        // User has no roles assigned.
        let app = role_app(ath, "admin");
        let resp = app.oneshot(make_request(Some(&cookie))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn require_permission_with_correct_permission_passes() {
        let (ath, cookie) = test_setup().await;

        // Create permission and assign directly to user.
        let pn = allowthem_core::PermissionName::new("posts:write");
        let perm = ath.db().create_permission(&pn, None).await.unwrap();
        let email = Email::new("user@example.com".into()).unwrap();
        let user = ath.db().get_user_by_email(&email).await.unwrap();
        ath.db()
            .assign_permission_to_user(&user.id, &perm.id)
            .await
            .unwrap();

        let app = perm_app(ath, "posts:write");
        let resp = app.oneshot(make_request(Some(&cookie))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn require_permission_with_missing_permission_returns_403() {
        let (ath, cookie) = test_setup().await;
        // User has no permissions.
        let app = perm_app(ath, "posts:write");
        let resp = app.oneshot(make_request(Some(&cookie))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }
}
