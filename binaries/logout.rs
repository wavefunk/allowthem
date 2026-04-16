use axum::extract::State;
use axum::http::header::{COOKIE, SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};

use allowthem_core::{AllowThem, AuditEvent};

/// GET and POST /logout
///
/// Extracts the session token from the cookie, deletes it, clears the cookie,
/// logs an audit event, and redirects to /login. If the user is already
/// unauthenticated (no cookie or unknown token), the handler still redirects
/// gracefully.
pub async fn handler(
    State(ath): State<AllowThem>,
    headers: HeaderMap,
) -> Response {
    let cookie_name = ath.session_config().cookie_name;
    let secure = ath.session_config().secure;

    let token = headers
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| allowthem_core::parse_session_cookie(v, cookie_name));

    if let Some(ref token) = token {
        let ip = extract_ip(&headers);
        let ua = headers
            .get(USER_AGENT)
            .and_then(|v| v.to_str().ok());

        match ath.db().lookup_session(token).await {
            Ok(Some(session)) => {
                if let Err(e) = ath.db().delete_session(token).await {
                    tracing::error!(error = %e, "failed to delete session on logout");
                }
                if let Err(e) = ath
                    .db()
                    .log_audit(
                        AuditEvent::Logout,
                        Some(&session.user_id),
                        None,
                        ip.as_deref(),
                        ua,
                        None,
                    )
                    .await
                {
                    tracing::error!(error = %e, "failed to log audit event on logout");
                }
            }
            Ok(None) => {}
            Err(e) => {
                tracing::error!(error = %e, "session lookup failed on logout");
            }
        }
    }

    let clear_cookie = build_clear_cookie(cookie_name, secure);

    (
        StatusCode::SEE_OTHER,
        [
            (SET_COOKIE, clear_cookie),
            (axum::http::header::LOCATION, "/login".to_string()),
        ],
    )
        .into_response()
}

fn build_clear_cookie(cookie_name: &str, secure: bool) -> String {
    let mut cookie = format!(
        "{}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0",
        cookie_name,
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

fn extract_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').next().unwrap_or(v).trim().to_string())
}
