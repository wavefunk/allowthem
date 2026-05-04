//! Cookie → dashboard-user helpers.
//!
//! `is_authenticated` mirrors `crates/server/register_routes.rs:447` (which
//! is private to that module; promoting it is a separate refactor).
//!
//! `current_dashboard_user` resolves the same cookie to the actual `User`
//! row — used by 99c.2's quickstart and 99c.3's tenant-scope extractors.

use axum::http::HeaderMap;
use axum::http::header::COOKIE;

use allowthem_core::error::AuthError;
use allowthem_core::types::UserId;
use allowthem_core::{AllowThem, User};

/// Returns true if the request carries a valid session cookie.
pub async fn is_authenticated(ath: &AllowThem, headers: &HeaderMap) -> bool {
    let Some(cookie_header) = headers.get(COOKIE).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let Some(token) = ath.parse_session_cookie(cookie_header) else {
        return false;
    };
    let ttl = ath.session_config().ttl;
    ath.db()
        .validate_session(&token, ttl)
        .await
        .unwrap_or(None)
        .is_some()
}

/// Resolve the `Cookie` header on the request to a dashboard `User`.
///
/// Returns:
/// - `Ok(Some(user))` when the cookie names a valid, non-expired session.
/// - `Ok(None)` when there is no cookie, the cookie has an unknown name,
///   the session token is invalid, or the session has expired. Callers
///   typically redirect to `/login` in this case.
/// - `Err(_)` only on database failures (propagated, not swallowed).
pub async fn current_dashboard_user(
    ath: &AllowThem,
    headers: &HeaderMap,
) -> Result<Option<User>, AuthError> {
    let Some(cookie_header) = headers.get(COOKIE).and_then(|v| v.to_str().ok()) else {
        return Ok(None);
    };
    let Some(token) = ath.parse_session_cookie(cookie_header) else {
        return Ok(None);
    };
    let ttl = ath.session_config().ttl;
    let session = match ath.db().validate_session(&token, ttl).await? {
        Some(s) => s,
        None => return Ok(None),
    };
    let user_id: UserId = session.user_id;
    let user = ath.db().get_user(user_id).await?;
    Ok(Some(user))
}
