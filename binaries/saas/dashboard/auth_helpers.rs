//! Local copy of `is_authenticated` from `crates/server/register_routes.rs:447`.
//!
//! The original is private to that module; promoting it to a shared
//! `crates/server` utility is a separate refactor. Mirrors the upstream
//! implementation byte-for-byte so the two stay in lockstep.

use axum::http::HeaderMap;
use axum::http::header::COOKIE;

use allowthem_core::AllowThem;

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
