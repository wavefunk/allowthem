use axum::Router;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use serde::Deserialize;

use allowthem_core::audit::SearchAuditParams;
use allowthem_core::sessions::ListSessionsParams;
use allowthem_core::types::UserId;
use allowthem_core::users::SearchUsersParams;
use allowthem_server::{BrowserAdminUser, CsrfToken, ShellContext};

use crate::error::AppError;
use crate::state::AppState;

/// Maximum recent audit entries shown on the user detail page.
const RECENT_AUDIT_LIMIT: u32 = 10;
const PAGE_SIZE: u32 = 25;

#[derive(Deserialize)]
pub struct UserListQuery {
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    mfa: Option<String>,
    #[serde(default)]
    page: Option<u32>,
}

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/", get(list))
        .route("/{id}", get(detail))
}

/// Parse a user ID from a path segment, redirecting to the users list on failure.
#[allow(clippy::result_large_err)]
fn parse_user_id(raw: &str) -> Result<UserId, Response> {
    raw.parse::<UserId>()
        .map_err(|_| Redirect::to("/admin/users").into_response())
}

/// GET /admin/users — searchable admin user list.
pub async fn list(
    State(state): State<AppState>,
    BrowserAdminUser(admin): BrowserAdminUser,
    Query(query): Query<UserListQuery>,
) -> Result<Response, AppError> {
    let page = query.page.unwrap_or(1).max(1);
    let offset = (page - 1) * PAGE_SIZE;
    let q = query.q.as_deref().unwrap_or("").trim();
    let status = query.status.as_deref().unwrap_or("");
    let mfa = query.mfa.as_deref().unwrap_or("");
    let result = state
        .ath
        .db()
        .search_users(SearchUsersParams {
            query: if q.is_empty() { None } else { Some(q) },
            is_active: match status {
                "active" => Some(true),
                "deactivated" => Some(false),
                _ => None,
            },
            has_mfa: match mfa {
                "yes" => Some(true),
                "no" => Some(false),
                _ => None,
            },
            email_verified: None,
            limit: PAGE_SIZE,
            offset,
        })
        .await?;
    let total_pages = if result.total == 0 {
        0
    } else {
        result.total.div_ceil(PAGE_SIZE)
    };
    let shell =
        ShellContext::new(true, "/admin/users", "allowthem").with_session(admin.email.as_str());
    let html = crate::views::users_page(&crate::views::UsersPageView {
        shell: &shell,
        users: &result.users,
        total: result.total,
        page,
        total_pages,
        q,
        status,
        mfa,
        is_production: state.is_production,
    })?;
    Ok(html.into_response())
}

/// GET /admin/users/:id — show user detail with roles, OAuth accounts, sessions, and audit.
pub async fn detail(
    State(state): State<AppState>,
    BrowserAdminUser(admin): BrowserAdminUser,
    Path(raw_id): Path<String>,
    csrf: CsrfToken,
) -> Result<Response, AppError> {
    let id = match parse_user_id(&raw_id) {
        Ok(id) => id,
        Err(r) => return Ok(r),
    };

    let user = state.ath.db().get_user(id).await?;
    let roles = state.ath.db().get_user_roles(&id).await?;
    let oauth_accounts = state.ath.db().get_user_oauth_accounts(id).await?;
    let mfa_enabled = state.ath.db().has_mfa_enabled(id).await?;

    // Active sessions for this user.
    let sessions_result = state
        .ath
        .db()
        .list_all_sessions(ListSessionsParams {
            user_id: Some(id),
            limit: 50,
            offset: 0,
        })
        .await?;

    // Most recent audit entries for this user.
    let audit_result = state
        .ath
        .db()
        .search_audit_log(SearchAuditParams {
            user_id: Some(id),
            event_type: None,
            is_success: None,
            from: None,
            to: None,
            limit: RECENT_AUDIT_LIMIT,
            offset: 0,
        })
        .await?;

    // Last login timestamp from audit entries.
    let last_login = audit_result
        .entries
        .iter()
        .find(|e| matches!(e.event_type, allowthem_core::AuditEvent::Login))
        .map(|e| e.created_at.to_rfc3339());

    let shell =
        ShellContext::new(true, "/admin/users", "allowthem").with_session(admin.email.as_str());
    let html = crate::views::user_detail_page(&crate::views::UserDetailView {
        shell: &shell,
        user: &user,
        roles: &roles,
        oauth_accounts: &oauth_accounts,
        sessions: &sessions_result.sessions,
        mfa_enabled,
        last_login: last_login.as_deref(),
        csrf_token: csrf.as_str(),
        is_production: state.is_production,
    })?;
    Ok(html.into_response())
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
        AllowThem, AllowThemBuilder, AuthClient, Email, EmbeddedAuthClient, RoleName,
        generate_token, hash_token,
    };
    use allowthem_server::{csrf_middleware, inject_ath_into_extensions};

    use crate::state::AppState;

    async fn setup() -> (AllowThem, AppState, String) {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .csrf_key(*b"test-csrf-key-for-binary-tests!!")
            .build()
            .await
            .unwrap();

        let email = Email::new("admin@example.com".into()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
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
        let auth_client: Arc<dyn AuthClient> =
            Arc::new(EmbeddedAuthClient::new(ath.clone(), "/login"));
        let state = AppState {
            ath: ath.clone(),
            auth_client,
            is_production: false,
        };

        (ath, state, cookie_value)
    }

    fn test_app(state: AppState) -> Router {
        Router::new()
            .nest("/admin/users", super::routes())
            .layer(axum::middleware::from_fn(csrf_middleware))
            .layer(axum::middleware::from_fn_with_state(
                state.clone(),
                inject_ath_into_extensions,
            ))
            .with_state(state)
    }

    async fn read_body_string(resp: axum::http::Response<Body>) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        String::from_utf8(bytes.to_vec()).unwrap()
    }

    #[tokio::test]
    async fn users_list_renders() {
        let (_ath, state, cookie) = setup().await;
        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/admin/users")
                    .header(COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("admin@example.com"));
        assert!(body.contains("USERS"));
    }

    #[tokio::test]
    async fn user_detail_renders() {
        let (ath, state, cookie) = setup().await;
        let user = ath
            .db()
            .get_user_by_email(&Email::new("admin@example.com".into()).unwrap())
            .await
            .unwrap();
        let app = test_app(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .uri(&format!("/admin/users/{}", user.id))
                    .header(COOKIE, &cookie)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = read_body_string(resp).await;
        assert!(body.contains("admin@example.com"));
        assert!(body.contains("ALLOWTHEM"));
    }
}
