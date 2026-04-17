use axum::Router;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use chrono::{NaiveDate, TimeZone, Utc};
use minijinja::context;
use serde::{Deserialize, Serialize};

use allowthem_core::audit::{AuditEvent, AuditListEntry, SearchAuditParams};
use allowthem_core::types::UserId;
use allowthem_server::BrowserAdminUser;

use crate::error::AppError;
use crate::state::AppState;

const PAGE_SIZE: u32 = 50;
const EXPORT_MAX_ROWS: u32 = 10_000;

#[derive(Deserialize)]
pub struct AuditListQuery {
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    event: Option<String>,
    #[serde(default)]
    outcome: Option<String>,
    #[serde(default)]
    from: Option<String>,
    #[serde(default)]
    to: Option<String>,
    #[serde(default)]
    page: Option<u32>,
    #[serde(default)]
    format: Option<String>,
}

fn parse_user_id(s: &Option<String>) -> Option<UserId> {
    s.as_deref()
        .and_then(|s| serde_json::from_value(serde_json::Value::String(s.trim().to_string())).ok())
}

fn parse_event(s: &Option<String>) -> Option<AuditEvent> {
    match s.as_deref() {
        Some("login") => Some(AuditEvent::Login),
        Some("login_failed") => Some(AuditEvent::LoginFailed),
        Some("logout") => Some(AuditEvent::Logout),
        Some("register") => Some(AuditEvent::Register),
        Some("password_change") => Some(AuditEvent::PasswordChange),
        Some("password_reset") => Some(AuditEvent::PasswordReset),
        Some("role_assigned") => Some(AuditEvent::RoleAssigned),
        Some("role_unassigned") => Some(AuditEvent::RoleUnassigned),
        Some("permission_assigned") => Some(AuditEvent::PermissionAssigned),
        Some("permission_unassigned") => Some(AuditEvent::PermissionUnassigned),
        Some("session_created") => Some(AuditEvent::SessionCreated),
        Some("session_expired") => Some(AuditEvent::SessionExpired),
        Some("user_updated") => Some(AuditEvent::UserUpdated),
        Some("user_deleted") => Some(AuditEvent::UserDeleted),
        Some("mfa_enabled") => Some(AuditEvent::MfaEnabled),
        Some("mfa_disabled") => Some(AuditEvent::MfaDisabled),
        Some("mfa_challenge_success") => Some(AuditEvent::MfaChallengeSuccess),
        Some("mfa_challenge_failed") => Some(AuditEvent::MfaChallengeFailed),
        _ => None,
    }
}

fn parse_outcome(s: &Option<String>) -> Option<bool> {
    match s.as_deref() {
        Some("success") => Some(true),
        Some("failure") => Some(false),
        _ => None,
    }
}

fn parse_date(s: &Option<String>) -> Option<chrono::DateTime<Utc>> {
    s.as_deref()
        .and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| Utc.from_utc_datetime(&dt))
}

fn parse_date_end(s: &Option<String>) -> Option<chrono::DateTime<Utc>> {
    s.as_deref()
        .and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
        .and_then(|d| d.succ_opt())
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| Utc.from_utc_datetime(&dt))
}

fn event_label(event: &AuditEvent) -> &'static str {
    match event {
        AuditEvent::Login => "Login",
        AuditEvent::LoginFailed => "Login failed",
        AuditEvent::Logout => "Logout",
        AuditEvent::Register => "Register",
        AuditEvent::PasswordChange => "Password change",
        AuditEvent::PasswordReset => "Password reset",
        AuditEvent::RoleAssigned => "Role assigned",
        AuditEvent::RoleUnassigned => "Role unassigned",
        AuditEvent::PermissionAssigned => "Permission assigned",
        AuditEvent::PermissionUnassigned => "Permission unassigned",
        AuditEvent::SessionCreated => "Session created",
        AuditEvent::SessionExpired => "Session expired",
        AuditEvent::UserUpdated => "User updated",
        AuditEvent::UserDeleted => "User deleted",
        AuditEvent::MfaEnabled => "MFA enabled",
        AuditEvent::MfaDisabled => "MFA disabled",
        AuditEvent::MfaChallengeSuccess => "MFA challenge success",
        AuditEvent::MfaChallengeFailed => "MFA challenge failed",
    }
}

/// Build windowed page numbers for pagination.
/// Returns a Vec where 0 represents an ellipsis.
fn page_numbers(current: u32, total: u32) -> Vec<u32> {
    if total <= 7 {
        return (1..=total).collect();
    }
    let mut pages = Vec::new();
    let window_start = current.saturating_sub(2).max(1);
    let window_end = (current + 2).min(total);

    pages.push(1);
    if window_start > 2 {
        pages.push(0);
    }

    for n in window_start..=window_end {
        if n != 1 && n != total {
            pages.push(n);
        }
    }

    if window_end < total - 1 {
        pages.push(0);
    }
    if total > 1 {
        pages.push(total);
    }

    pages
}

#[derive(Serialize)]
struct EntryDisplay {
    event_label: String,
    is_failure: bool,
    user_id: Option<String>,
    user_email: Option<String>,
    ip_address: Option<String>,
    detail: Option<String>,
    created_at: String,
}

fn to_entry_display(entries: Vec<AuditListEntry>) -> Vec<EntryDisplay> {
    entries
        .into_iter()
        .map(|e| EntryDisplay {
            event_label: event_label(&e.event_type).to_string(),
            is_failure: matches!(e.event_type, AuditEvent::LoginFailed | AuditEvent::MfaChallengeFailed),
            user_id: e.user_id.map(|u| u.to_string()),
            user_email: e.user_email,
            ip_address: e.ip_address,
            detail: e.detail,
            created_at: e.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        })
        .collect()
}

pub fn routes() -> Router<AppState> {
    Router::new().route("/", get(list))
}

async fn list(
    State(state): State<AppState>,
    BrowserAdminUser(_admin): BrowserAdminUser,
    Query(query): Query<AuditListQuery>,
) -> Result<Response, AppError> {
    let user_id = parse_user_id(&query.user);
    let event = parse_event(&query.event);
    let outcome = parse_outcome(&query.outcome);
    let from = parse_date(&query.from);
    let to = parse_date_end(&query.to);

    let is_export = matches!(query.format.as_deref(), Some("csv") | Some("json"));
    let (limit, offset) = if is_export {
        (EXPORT_MAX_ROWS, 0)
    } else {
        let page = query.page.unwrap_or(1).max(1);
        (PAGE_SIZE, (page - 1) * PAGE_SIZE)
    };

    let result = state
        .ath
        .db()
        .search_audit_log(SearchAuditParams {
            user_id,
            event_type: event.as_ref(),
            is_success: outcome,
            from,
            to,
            limit,
            offset,
        })
        .await?;

    match query.format.as_deref() {
        Some("csv") => Ok(build_csv_response(&result.entries, result.total)),
        Some("json") => {
            let truncated = result.total > EXPORT_MAX_ROWS;
            let json = serde_json::to_string(&result.entries).map_err(|e| {
                AppError::Template(minijinja::Error::new(
                    minijinja::ErrorKind::InvalidOperation,
                    format!("JSON serialization failed: {e}"),
                ))
            })?;
            let mut resp = (
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (
                        header::CONTENT_DISPOSITION,
                        "attachment; filename=\"audit-log.json\"",
                    ),
                ],
                json,
            )
                .into_response();
            if truncated {
                resp.headers_mut()
                    .insert("X-Truncated", axum::http::HeaderValue::from_static("true"));
            }
            Ok(resp)
        }
        _ => {
            let page = query.page.unwrap_or(1).max(1);
            let total_pages = result.total.div_ceil(PAGE_SIZE);
            let entries = to_entry_display(result.entries);
            let pn = page_numbers(page, total_pages);

            let html = crate::templates::render(
                &state.templates,
                "admin/audit_log.html",
                context! {
                    entries,
                    total => result.total,
                    page,
                    total_pages,
                    page_numbers => pn,
                    user => query.user.as_deref().unwrap_or(""),
                    event => query.event.as_deref().unwrap_or(""),
                    outcome => query.outcome.as_deref().unwrap_or(""),
                    from => query.from.as_deref().unwrap_or(""),
                    to => query.to.as_deref().unwrap_or(""),
                },
                state.is_production,
            )?;
            Ok(html.into_response())
        }
    }
}

fn build_csv_response(entries: &[AuditListEntry], total: u32) -> Response {
    let mut csv = String::from(
        "id,event_type,user_id,user_email,target_id,ip_address,user_agent,detail,created_at\n",
    );
    for e in entries {
        csv.push_str(&csv_field(&e.id.to_string()));
        csv.push(',');
        csv.push_str(&csv_field(event_label(&e.event_type)));
        csv.push(',');
        csv.push_str(&csv_field(
            &e.user_id.map(|u| u.to_string()).unwrap_or_default(),
        ));
        csv.push(',');
        csv.push_str(&csv_field(e.user_email.as_deref().unwrap_or("")));
        csv.push(',');
        csv.push_str(&csv_field(e.target_id.as_deref().unwrap_or("")));
        csv.push(',');
        csv.push_str(&csv_field(e.ip_address.as_deref().unwrap_or("")));
        csv.push(',');
        csv.push_str(&csv_field(e.user_agent.as_deref().unwrap_or("")));
        csv.push(',');
        csv.push_str(&csv_field(e.detail.as_deref().unwrap_or("")));
        csv.push(',');
        csv.push_str(&csv_field(&e.created_at.to_rfc3339()));
        csv.push('\n');
    }
    let mut resp = (
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"audit-log.csv\"",
            ),
        ],
        csv,
    )
        .into_response();
    if total > EXPORT_MAX_ROWS {
        resp.headers_mut()
            .insert("X-Truncated", axum::http::HeaderValue::from_static("true"));
    }
    resp
}

fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header::COOKIE};
    use chrono::{Duration, Utc};
    use tower::ServiceExt;

    use allowthem_core::{
        AllowThem, AllowThemBuilder, AuditEvent, AuthClient, Email, EmbeddedAuthClient,
        LogEmailSender, RoleName, generate_token, hash_token,
    };
    use allowthem_server::csrf_middleware;

    use crate::state::AppState;

    async fn setup() -> (AllowThem, AppState, String) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let email = Email::new("admin@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None)
            .await
            .unwrap();

        let role_name = RoleName::new("admin");
        let role = ath.db().create_role(&role_name, None).await.unwrap();
        ath.db().assign_role(&user.id, &role.id).await.unwrap();

        let token = generate_token();
        let token_hash = hash_token(&token);
        let expires = Utc::now() + Duration::hours(24);
        ath.db()
            .create_session(user.id, token_hash, None, None, expires)
            .await
            .unwrap();

        let cookie = ath.session_cookie(&token);
        let cookie_value = cookie.split(';').next().unwrap().to_string();

        let templates = crate::templates::build_template_env().unwrap();
        let auth_client: Arc<dyn AuthClient> =
            Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
        let state = AppState {
            ath: ath.clone(),
            auth_client,
            base_url: "http://localhost:3000".to_string(),
            templates,
            is_production: false,
            login_attempts: Arc::new(dashmap::DashMap::new()),
            max_login_attempts: 10,
            rate_limit_window_secs: 900,
            email_sender: Arc::new(LogEmailSender),
            oauth_providers: Vec::new(),
        };

        (ath, state, cookie_value)
    }

    fn test_app(state: AppState) -> Router {
        Router::new()
            .nest("/admin/audit", super::routes())
            .layer(axum::middleware::from_fn(csrf_middleware))
            .with_state(state)
    }

    async fn read_body_string(resp: axum::http::Response<Body>) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn list_page_renders_empty() {
        let (_ath, state, cookie) = setup().await;
        let app = test_app(state);

        let req = Request::builder()
            .uri("/admin/audit")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("Audit log"));
        assert!(body.contains("No audit events found"));
    }

    #[tokio::test]
    async fn list_page_renders_with_entries() {
        let (ath, state, cookie) = setup().await;

        let user = ath
            .db()
            .create_user(
                Email::new("user@example.com".into()).unwrap(),
                "password123",
                None,
            )
            .await
            .unwrap();
        let _ = ath
            .db()
            .log_audit(
                AuditEvent::Login,
                Some(&user.id),
                None,
                Some("1.2.3.4"),
                None,
                None,
            )
            .await;

        let app = test_app(state);
        let req = Request::builder()
            .uri("/admin/audit")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("Login"));
        assert!(body.contains("user@example.com"));
    }

    #[tokio::test]
    async fn list_page_filters_by_event_type() {
        let (ath, state, cookie) = setup().await;

        let user = ath
            .db()
            .create_user(
                Email::new("filter-event@example.com".into()).unwrap(),
                "password123",
                None,
            )
            .await
            .unwrap();
        let _ = ath
            .db()
            .log_audit(AuditEvent::Login, Some(&user.id), None, None, None, None)
            .await;
        let _ = ath
            .db()
            .log_audit(AuditEvent::Logout, Some(&user.id), None, None, None, None)
            .await;

        let app = test_app(state);
        let req = Request::builder()
            .uri("/admin/audit?event=login")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        let body = read_body_string(resp).await;
        // "Login" appears in the table data; "Logout" only in the filter dropdown
        assert!(body.contains("1 event"));
        // The filtered result should contain the login event label in the table
        assert!(body.contains(">Login<"));
    }

    #[tokio::test]
    async fn list_page_filters_by_outcome() {
        let (ath, state, cookie) = setup().await;

        let user = ath
            .db()
            .create_user(
                Email::new("filter-outcome@example.com".into()).unwrap(),
                "password123",
                None,
            )
            .await
            .unwrap();
        let _ = ath
            .db()
            .log_audit(AuditEvent::Login, Some(&user.id), None, None, None, None)
            .await;
        let _ = ath
            .db()
            .log_audit(AuditEvent::LoginFailed, None, None, None, None, None)
            .await;

        let app = test_app(state);
        let req = Request::builder()
            .uri("/admin/audit?outcome=failure")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        let body = read_body_string(resp).await;
        assert!(body.contains("Login failed"));
        // Should not contain a standalone "Login" (without "failed")
        // Check that the event count is 1
        assert!(body.contains("1 event"));
    }

    #[tokio::test]
    async fn list_page_invalid_filters_ignored() {
        let (_ath, state, cookie) = setup().await;
        let app = test_app(state);

        let req = Request::builder()
            .uri("/admin/audit?user=not-a-uuid&event=unknown")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn csv_export_returns_correct_headers() {
        let (ath, state, cookie) = setup().await;

        let user = ath
            .db()
            .create_user(
                Email::new("csv@example.com".into()).unwrap(),
                "password123",
                None,
            )
            .await
            .unwrap();
        let _ = ath
            .db()
            .log_audit(AuditEvent::Login, Some(&user.id), None, None, None, None)
            .await;

        let app = test_app(state);
        let req = Request::builder()
            .uri("/admin/audit?format=csv")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "text/csv; charset=utf-8"
        );
        assert!(
            resp.headers()
                .get("content-disposition")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("audit-log.csv")
        );
    }

    #[tokio::test]
    async fn csv_export_contains_data() {
        let (ath, state, cookie) = setup().await;

        let user = ath
            .db()
            .create_user(
                Email::new("csv-data@example.com".into()).unwrap(),
                "password123",
                None,
            )
            .await
            .unwrap();
        let _ = ath
            .db()
            .log_audit(AuditEvent::Login, Some(&user.id), None, None, None, None)
            .await;

        let app = test_app(state);
        let req = Request::builder()
            .uri("/admin/audit?format=csv")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        let body = read_body_string(resp).await;
        assert!(body.starts_with("id,event_type,"));
        assert!(body.contains("Login"));
        assert!(body.contains("csv-data@example.com"));
    }

    #[tokio::test]
    async fn json_export_is_valid() {
        let (ath, state, cookie) = setup().await;

        let user = ath
            .db()
            .create_user(
                Email::new("json@example.com".into()).unwrap(),
                "password123",
                None,
            )
            .await
            .unwrap();
        let _ = ath
            .db()
            .log_audit(AuditEvent::Login, Some(&user.id), None, None, None, None)
            .await;

        let app = test_app(state);
        let req = Request::builder()
            .uri("/admin/audit?format=json")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert!(parsed.is_array());
        assert!(!parsed.as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn unauthenticated_redirects_to_login() {
        let (_ath, state, _cookie) = setup().await;
        let app = test_app(state);

        let req = Request::builder()
            .uri("/admin/audit")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::SEE_OTHER);
        let location = resp.headers().get("location").unwrap().to_str().unwrap();
        assert!(location.starts_with("/login?next="));
    }

    #[tokio::test]
    async fn non_admin_gets_403() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let email = Email::new("nonadmin@example.com".into()).unwrap();
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

        let templates = crate::templates::build_template_env().unwrap();
        let auth_client: Arc<dyn AuthClient> =
            Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
        let state = AppState {
            ath,
            auth_client,
            base_url: "http://localhost:3000".to_string(),
            templates,
            is_production: false,
            login_attempts: Arc::new(dashmap::DashMap::new()),
            max_login_attempts: 10,
            rate_limit_window_secs: 900,
            email_sender: Arc::new(LogEmailSender),
            oauth_providers: Vec::new(),
        };
        let app = test_app(state);

        let req = Request::builder()
            .uri("/admin/audit")
            .header(COOKIE, &cookie_value)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn list_page_filters_by_user() {
        let (ath, state, cookie) = setup().await;

        let user1 = ath
            .db()
            .create_user(
                Email::new("user1-filter@example.com".into()).unwrap(),
                "password123",
                None,
            )
            .await
            .unwrap();
        let user2 = ath
            .db()
            .create_user(
                Email::new("user2-filter@example.com".into()).unwrap(),
                "password123",
                None,
            )
            .await
            .unwrap();
        let _ = ath
            .db()
            .log_audit(AuditEvent::Login, Some(&user1.id), None, None, None, None)
            .await;
        let _ = ath
            .db()
            .log_audit(AuditEvent::Login, Some(&user2.id), None, None, None, None)
            .await;

        let app = test_app(state);
        let req = Request::builder()
            .uri(&format!("/admin/audit?user={}", user1.id))
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("user1-filter@example.com"));
        assert!(!body.contains("user2-filter@example.com"));
        assert!(body.contains("1 event"));
    }

    #[tokio::test]
    async fn list_page_combined_filters() {
        let (ath, state, cookie) = setup().await;

        let user = ath
            .db()
            .create_user(
                Email::new("combined-filter@example.com".into()).unwrap(),
                "password123",
                None,
            )
            .await
            .unwrap();
        let _ = ath
            .db()
            .log_audit(AuditEvent::Login, Some(&user.id), None, None, None, None)
            .await;
        let _ = ath
            .db()
            .log_audit(AuditEvent::Logout, Some(&user.id), None, None, None, None)
            .await;
        let _ = ath
            .db()
            .log_audit(AuditEvent::LoginFailed, None, None, None, None, None)
            .await;

        let app = test_app(state);
        // Combine user filter + event type filter
        let req = Request::builder()
            .uri(&format!("/admin/audit?user={}&event=login", user.id))
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("1 event"));
        assert!(body.contains("combined-filter@example.com"));
    }

    #[tokio::test]
    async fn export_respects_filters() {
        let (ath, state, cookie) = setup().await;

        let user = ath
            .db()
            .create_user(
                Email::new("export-filter@example.com".into()).unwrap(),
                "password123",
                None,
            )
            .await
            .unwrap();
        let _ = ath
            .db()
            .log_audit(AuditEvent::Login, Some(&user.id), None, None, None, None)
            .await;
        let _ = ath
            .db()
            .log_audit(AuditEvent::LoginFailed, None, None, None, None, None)
            .await;

        let app = test_app(state);
        // Export only Login events
        let req = Request::builder()
            .uri("/admin/audit?event=login&format=csv")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        // Header row + 1 data row
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "expected header + 1 data row");
        assert!(lines[1].contains("Login"));
        assert!(!lines[1].contains("failed"));
    }

    // Unit tests for helper functions

    #[test]
    fn page_numbers_few_pages() {
        assert_eq!(super::page_numbers(1, 5), vec![1, 2, 3, 4, 5]);
        assert_eq!(super::page_numbers(3, 7), vec![1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn page_numbers_windowed_first_page() {
        let pn = super::page_numbers(1, 20);
        assert_eq!(pn[0], 1);
        assert_eq!(*pn.last().unwrap(), 20);
        // Page 10 should not appear
        assert!(!pn.contains(&10));
    }

    #[test]
    fn page_numbers_windowed_last_page() {
        let pn = super::page_numbers(20, 20);
        assert_eq!(pn[0], 1);
        assert_eq!(*pn.last().unwrap(), 20);
        assert!(!pn.contains(&5));
    }

    #[test]
    fn page_numbers_windowed_middle() {
        let pn = super::page_numbers(10, 20);
        assert!(pn.contains(&1));
        assert!(pn.contains(&20));
        assert!(pn.contains(&10));
        assert!(pn.contains(&8));
        assert!(pn.contains(&12));
        assert!(!pn.contains(&5));
        // Ellipsis markers (0) should be present
        assert!(pn.contains(&0));
    }

    #[test]
    fn page_numbers_zero_total() {
        assert_eq!(super::page_numbers(1, 0), Vec::<u32>::new());
    }

    #[test]
    fn csv_field_no_quoting_needed() {
        assert_eq!(super::csv_field("hello"), "hello");
    }

    #[test]
    fn csv_field_quotes_on_comma() {
        assert_eq!(super::csv_field("a,b"), "\"a,b\"");
    }

    #[test]
    fn csv_field_escapes_inner_quotes() {
        assert_eq!(super::csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
    }

    #[tokio::test]
    async fn list_page_filters_by_date_range() {
        let (ath, state, cookie) = setup().await;

        let user = ath
            .db()
            .create_user(
                Email::new("date-range@example.com".into()).unwrap(),
                "password123",
                None,
            )
            .await
            .unwrap();
        let _ = ath
            .db()
            .log_audit(AuditEvent::Login, Some(&user.id), None, None, None, None)
            .await;

        let app = test_app(state);

        // Filter to a date range that definitely includes today
        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();
        let uri = format!("/admin/audit?from={}&to={}", today, today);
        let req = Request::builder()
            .uri(&uri)
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("date-range@example.com"));
        assert!(body.contains("Login"));
    }

    #[tokio::test]
    async fn list_page_filters_by_date_range_excludes_future() {
        let (ath, state, cookie) = setup().await;

        let user = ath
            .db()
            .create_user(
                Email::new("date-exclude@example.com".into()).unwrap(),
                "password123",
                None,
            )
            .await
            .unwrap();
        let _ = ath
            .db()
            .log_audit(AuditEvent::Login, Some(&user.id), None, None, None, None)
            .await;

        let app = test_app(state);

        // Filter to a past date range — should return no results
        let req = Request::builder()
            .uri("/admin/audit?from=2020-01-01&to=2020-01-02")
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("No audit events found"));
    }

    #[tokio::test]
    async fn list_page_paginates() {
        let (ath, state, cookie) = setup().await;

        let user = ath
            .db()
            .create_user(
                Email::new("paginate@example.com".into()).unwrap(),
                "password123",
                None,
            )
            .await
            .unwrap();

        // Insert PAGE_SIZE + 1 events so two pages exist
        for _ in 0..(super::PAGE_SIZE + 1) {
            let _ = ath
                .db()
                .log_audit(AuditEvent::Login, Some(&user.id), None, None, None, None)
                .await;
        }

        let app = test_app(state);

        // Page 1 should show pagination controls and indicate > 1 page
        let req = Request::builder()
            .uri("/admin/audit?user=".to_string() + &user.id.to_string())
            .header(COOKIE, &cookie)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        // Should show total count
        let expected = format!("{} events", super::PAGE_SIZE + 1);
        assert!(body.contains(&expected));
        // Pagination nav should be present (Next link)
        assert!(body.contains("Next"));
    }
}
