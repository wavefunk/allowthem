use axum::extract::State;
use axum::http::header::{COOKIE, SET_COOKIE, USER_AGENT};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;

use allowthem_core::{AllowThem, AuditEvent};

pub fn logout_routes() -> Router<AllowThem> {
    Router::new().route("/logout", get(handler).post(handler))
}

async fn handler(State(ath): State<AllowThem>, headers: HeaderMap) -> Response {
    let cookie_name = ath.session_config().cookie_name;
    let secure = ath.session_config().secure;

    let token = headers
        .get(COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| allowthem_core::parse_session_cookie(v, cookie_name));

    if let Some(ref token) = token {
        let ip = extract_ip(&headers);
        let ua = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());

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

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use chrono::{Duration, Utc};
    use tower::ServiceExt;

    use allowthem_core::{AllowThemBuilder, AuditEvent, Email, generate_token, hash_token};

    use super::*;

    async fn setup() -> (
        allowthem_core::AllowThem,
        String,
        allowthem_core::types::SessionToken,
    ) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let email = Email::new("test@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();

        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = Utc::now() + Duration::hours(24);
        ath.db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();

        let set_cookie = ath.session_cookie(&token);
        let cookie_value = set_cookie.split(';').next().unwrap().to_string();
        (ath, cookie_value, token)
    }

    fn test_app(ath: allowthem_core::AllowThem) -> Router {
        logout_routes().with_state(ath)
    }

    #[tokio::test]
    async fn logout_redirects_to_login_with_303() {
        let (ath, cookie_value, _) = setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/logout")
            .header(axum::http::header::COOKIE, &cookie_value)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/login");
    }

    #[tokio::test]
    async fn logout_clears_session_cookie() {
        let (ath, cookie_value, _) = setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/logout")
            .header(axum::http::header::COOKIE, &cookie_value)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        let set_cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
        assert!(set_cookie.contains("Max-Age=0"), "cookie should be expired");
        assert!(
            set_cookie.contains("allowthem_session=;"),
            "cookie value should be empty"
        );
    }

    #[tokio::test]
    async fn logout_destroys_session_in_db() {
        let (ath, cookie_value, token) = setup().await;
        let app = test_app(ath.clone());

        let req = Request::builder()
            .uri("/logout")
            .header(axum::http::header::COOKIE, &cookie_value)
            .body(Body::empty())
            .unwrap();
        app.oneshot(req).await.unwrap();

        let session = ath.db().lookup_session(&token).await.unwrap();
        assert!(session.is_none(), "session should be deleted after logout");
    }

    #[tokio::test]
    async fn logout_records_audit_event() {
        let (ath, cookie_value, _) = setup().await;
        let app = test_app(ath.clone());

        let req = Request::builder()
            .uri("/logout")
            .header(axum::http::header::COOKIE, &cookie_value)
            .body(Body::empty())
            .unwrap();
        app.oneshot(req).await.unwrap();

        let entries = ath.db().get_audit_log(None, 10, 0).await.unwrap();
        let logout_entry = entries.iter().find(|e| e.event_type == AuditEvent::Logout);
        assert!(
            logout_entry.is_some(),
            "logout audit event should be recorded"
        );
    }

    #[tokio::test]
    async fn logout_without_cookie_redirects_gracefully() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();
        let app = test_app(ath);

        let req = Request::builder()
            .uri("/logout")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/login");
    }

    #[tokio::test]
    async fn post_logout_redirects_to_login() {
        let (ath, cookie_value, _) = setup().await;
        let app = test_app(ath);

        let req = Request::builder()
            .method("POST")
            .uri("/logout")
            .header(axum::http::header::COOKIE, &cookie_value)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        assert_eq!(resp.headers().get("location").unwrap(), "/login");
    }
}
