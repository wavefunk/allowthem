use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use minijinja::context;

use allowthem_core::audit::SearchAuditParams;
use allowthem_core::sessions::ListSessionsParams;
use allowthem_core::types::UserId;
use allowthem_server::{BrowserAdminUser, CsrfToken, ShellContext};
use minijinja::value::Value;

use crate::error::AppError;
use crate::state::AppState;

/// Maximum recent audit entries shown on the user detail page.
const RECENT_AUDIT_LIMIT: u32 = 10;

pub fn routes() -> Router<AppState> {
    Router::new().route("/{id}", get(detail))
}

/// Parse a user ID from a path segment, redirecting to the users list on failure.
#[allow(clippy::result_large_err)]
fn parse_user_id(raw: &str) -> Result<UserId, Response> {
    raw.parse::<UserId>()
        .map_err(|_| Redirect::to("/admin/users").into_response())
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

    let shell = ShellContext::new(true, "/admin/users", "allowthem")
        .with_session(admin.email.as_str());
    let html = crate::templates::render(
        &state.templates,
        "admin/user_detail.html",
        context! {
            shell => Value::from_serialize(&shell),
            user => &user,
            roles,
            oauth_accounts,
            mfa_enabled,
            sessions => &sessions_result.sessions,
            last_login,
            csrf_token => csrf.as_str(),
        },
        state.is_production,
    )?;
    Ok(html.into_response())
}

#[cfg(test)]
mod tests {
    use minijinja::context;
    use minijinja::value::Value;

    use allowthem_server::ShellContext;

    fn user_obj() -> minijinja::Value {
        context! {
            id => "user-id",
            email => "user@example.com",
            username => None::<String>,
            is_active => true,
            email_verified => false,
            created_at => "2026-01-01",
            updated_at => "2026-01-02",
        }
    }

    #[test]
    fn user_detail_template_renders() {
        let env = crate::templates::build_template_env().expect("template env");
        let shell = ShellContext::new(true, "/admin/users", "allowthem")
            .with_session("admin@test.com");
        let tmpl = env.get_template("admin/user_detail.html").unwrap();
        let rendered = tmpl
            .render(context! {
                shell => Value::from_serialize(&shell),
                csrf_token => "test",
                is_production => false,
                user => user_obj(),
                roles => Vec::<()>::new(),
                oauth_accounts => Vec::<()>::new(),
                sessions => Vec::<()>::new(),
                mfa_enabled => false,
                last_login => None::<String>,
                error => None::<String>,
            })
            .unwrap();
        assert!(rendered.contains("user@example.com"));
        assert!(rendered.contains("ALLOWTHEM"));
    }
}
