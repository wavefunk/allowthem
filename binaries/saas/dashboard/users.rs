//! Tenant-scoped user-management handlers (99c.4).
//!
//! Routes (all under `/t/{slug}/users`):
//! - `GET  /`                                              list (any member)
//! - `GET  /{user_id}`                                     detail (any member)
//! - `POST /{user_id}/block`                               admin
//! - `POST /{user_id}/unblock`                             admin
//! - `POST /{user_id}/force-password-reset`                admin
//! - `POST /{user_id}/revoke-sessions`                     admin
//! - `POST /{user_id}/delete`                              owner (double-confirm)
//! - `POST /{user_id}/roles`                               admin
//! - `POST /{user_id}/roles/{role_id}/remove`              admin
//! - `POST /{user_id}/permissions`                         admin
//! - `POST /{user_id}/permissions/{permission_id}/remove`  admin
//!
//! Read handlers take `RequireTenantMember`. Write handlers take
//! `RequireTenantAdmin`, except `delete` which takes `RequireTenantOwner`.
//!
//! Each successful action writes one audit row via `log_admin_action` to
//! `allowthem_audit_log` with the actor's email in the detail string.

use axum::Router;
use axum::extract::{Path, Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use minijinja::context;
use serde::Deserialize;

use allowthem_core::audit::{AuditEvent, SearchAuditParams};
use allowthem_core::sessions::ListSessionsParams;
use allowthem_core::types::UserId;
use allowthem_core::users::SearchUsersParams;
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use super::extractors::{
    HtmlForm, RequireTenantAdmin, RequireTenantMember, RequireTenantOwner, TenantScope,
};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// All `/t/{slug}/users…` routes for the dashboard, mounted into
/// `dashboard_pages_router` so the CSRF middleware covers POSTs.
pub fn user_routes() -> Router<DashboardRouterState> {
    Router::new()
        .route("/t/{slug}/users", get(list))
        .route("/t/{slug}/users/{user_id}", get(detail))
        .route("/t/{slug}/users/{user_id}/block", post(block))
        .route("/t/{slug}/users/{user_id}/unblock", post(unblock))
        .route(
            "/t/{slug}/users/{user_id}/force-password-reset",
            post(force_password_reset),
        )
        .route(
            "/t/{slug}/users/{user_id}/revoke-sessions",
            post(revoke_sessions),
        )
        .route("/t/{slug}/users/{user_id}/delete", post(delete_user))
        .route("/t/{slug}/users/{user_id}/roles", post(assign_role))
        .route(
            "/t/{slug}/users/{user_id}/roles/{role_id}/remove",
            post(unassign_role),
        )
        .route(
            "/t/{slug}/users/{user_id}/permissions",
            post(grant_permission),
        )
        .route(
            "/t/{slug}/users/{user_id}/permissions/{permission_id}/remove",
            post(revoke_permission),
        )
}

// Pagination cap for the list page; mirrors `applications::list`'s constant.
const PAGE_SIZE: u32 = 25;

#[derive(Debug, Deserialize, Default)]
pub struct UserListQuery {
    #[serde(default)]
    pub q: Option<String>,
    /// "" | "active" | "blocked"
    #[serde(default)]
    pub status: Option<String>,
    /// "" | "yes" | "no"
    #[serde(default)]
    pub mfa: Option<String>,
    /// "" | "yes" | "no"
    #[serde(default)]
    pub verified: Option<String>,
    #[serde(default)]
    pub page: Option<u32>,
}

fn nonempty(s: &Option<String>) -> Option<&str> {
    s.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn parse_status(s: &Option<String>) -> Option<bool> {
    match nonempty(s)? {
        "active" => Some(true),
        "blocked" => Some(false),
        _ => None,
    }
}

fn parse_yes_no(s: &Option<String>) -> Option<bool> {
    match nonempty(s)? {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

/// Number of most-recent audit entries to display on the detail page.
const RECENT_AUDIT_LIMIT: u32 = 10;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn list(
    RequireTenantMember(scope): RequireTenantMember,
    Query(q): Query<UserListQuery>,
    State(state): State<DashboardRouterState>,
) -> Result<Response, BrowserError> {
    let page = q.page.unwrap_or(1).max(1);
    let q_str = q.q.clone().unwrap_or_default();
    let q_trimmed = q_str.trim();
    let result = scope
        .ath
        .db()
        .search_users(SearchUsersParams {
            query: if q_trimmed.is_empty() {
                None
            } else {
                Some(q_trimmed)
            },
            is_active: parse_status(&q.status),
            has_mfa: parse_yes_no(&q.mfa),
            email_verified: parse_yes_no(&q.verified),
            limit: PAGE_SIZE,
            offset: (page - 1) * PAGE_SIZE,
        })
        .await?;

    let total_pages = result.total.div_ceil(PAGE_SIZE).max(1);
    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/users", scope.tenant.slug),
        scope.role,
    );

    let tmpl = state
        .templates
        .get_template("users/list.html")
        .map_err(BrowserError::from)?;
    let body = tmpl
        .render(context! {
            status_session => scope.user.email.as_str(),
            tenant => tenant_ctx(&scope.tenant),
            role => role_str(&scope),
            nav_sections => nav,
            users => &result.users,
            total => result.total,
            page => page,
            total_pages => total_pages,
            q => q_trimmed,
            status => q.status.clone().unwrap_or_default(),
            mfa => q.mfa.clone().unwrap_or_default(),
            verified => q.verified.clone().unwrap_or_default(),
            has_filters => !q_trimmed.is_empty()
                || nonempty(&q.status).is_some()
                || nonempty(&q.mfa).is_some()
                || nonempty(&q.verified).is_some(),
        })
        .map_err(BrowserError::from)?;
    Ok(axum::response::Html(body).into_response())
}

fn role_str(scope: &TenantScope) -> &'static str {
    use allowthem_saas::TenantRole;
    match scope.role {
        TenantRole::Owner => "owner",
        TenantRole::Admin => "admin",
        TenantRole::Viewer => "viewer",
    }
}

fn tenant_ctx(tenant: &allowthem_saas::Tenant) -> minijinja::value::Value {
    context! {
        id => tenant.id.clone(),
        name => tenant.name.clone(),
        slug => tenant.slug.clone(),
    }
}

// ---------- Step 4: Detail ----------

/// Query-string parameters read by the detail page for flash messages
/// posted back from action handlers (Steps 6, 7, 8).
#[derive(Debug, Deserialize, Default)]
struct DetailQuery {
    #[serde(default)]
    info: String,
    #[serde(default)]
    error: String,
}

async fn detail(
    RequireTenantMember(scope): RequireTenantMember,
    Path((_slug, raw_id)): Path<(String, String)>,
    Query(q): Query<DetailQuery>,
    csrf: CsrfToken,
    State(state): State<DashboardRouterState>,
) -> Result<Response, BrowserError> {
    let user_id = match raw_id.parse::<UserId>() {
        Ok(id) => id,
        Err(_) => {
            return Ok(Redirect::to(&format!("/t/{}/users", scope.tenant.slug)).into_response());
        }
    };

    let user = scope.ath.db().get_user(user_id).await?;
    let roles = scope.ath.db().get_user_roles(&user_id).await?;
    let direct_permissions = scope.ath.db().get_user_permissions(&user_id).await?;
    let mfa_enabled = scope.ath.db().has_mfa_enabled(user_id).await?;
    let sessions = scope
        .ath
        .db()
        .list_all_sessions(ListSessionsParams {
            user_id: Some(user_id),
            limit: 50,
            offset: 0,
        })
        .await?;
    let audit = scope
        .ath
        .db()
        .search_audit_log(SearchAuditParams {
            user_id: Some(user_id),
            event_type: None,
            is_success: None,
            from: None,
            to: None,
            limit: RECENT_AUDIT_LIMIT,
            offset: 0,
        })
        .await?;
    // search_audit_log orders by created_at DESC; the first Login entry is
    // the most recent successful login.
    let last_login = audit
        .entries
        .iter()
        .find(|e| matches!(e.event_type, AuditEvent::Login))
        .map(|e| e.created_at.to_rfc3339());

    let all_roles = scope.ath.db().list_roles().await?;
    let all_permissions = scope.ath.db().list_permissions().await?;

    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/users", scope.tenant.slug),
        scope.role,
    );

    let tmpl = state
        .templates
        .get_template("users/detail.html")
        .map_err(BrowserError::from)?;
    let body = tmpl
        .render(context! {
            status_session => scope.user.email.as_str(),
            tenant => tenant_ctx(&scope.tenant),
            role => role_str(&scope),
            nav_sections => nav,
            user => &user,
            roles => roles,
            direct_permissions => direct_permissions,
            mfa_enabled => mfa_enabled,
            sessions => &sessions.sessions,
            last_login => last_login,
            audit_entries => &audit.entries,
            all_roles => all_roles,
            all_permissions => all_permissions,
            actor_role => role_str(&scope),
            csrf_token => csrf.as_str(),
            flash_info => &q.info,
            flash_error => &q.error,
        })
        .map_err(BrowserError::from)?;
    Ok(axum::response::Html(body).into_response())
}

// ---------- Step 5: Block / Unblock ----------

async fn block(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((slug, raw_id)): Path<(String, String)>,
) -> Result<Response, BrowserError> {
    let Ok(user_id) = raw_id.parse::<UserId>() else {
        return Ok(Redirect::to(&format!("/t/{slug}/users")).into_response());
    };
    scope.ath.update_user_active(user_id, false).await?;
    scope.ath.delete_user_sessions(&user_id).await?;
    log_admin_action(&scope, AuditEvent::UserUpdated, user_id, "blocked").await;
    Ok(Redirect::to(&format!("/t/{slug}/users/{user_id}")).into_response())
}

async fn unblock(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((slug, raw_id)): Path<(String, String)>,
) -> Result<Response, BrowserError> {
    let Ok(user_id) = raw_id.parse::<UserId>() else {
        return Ok(Redirect::to(&format!("/t/{slug}/users")).into_response());
    };
    scope.ath.update_user_active(user_id, true).await?;
    log_admin_action(&scope, AuditEvent::UserUpdated, user_id, "unblocked").await;
    Ok(Redirect::to(&format!("/t/{slug}/users/{user_id}")).into_response())
}

// ---------- Step 6: Force password reset ----------

async fn force_password_reset(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((slug, raw_id)): Path<(String, String)>,
) -> Result<Response, BrowserError> {
    let Ok(user_id) = raw_id.parse::<UserId>() else {
        return Ok(Redirect::to(&format!("/t/{slug}/users")).into_response());
    };
    let user = scope.ath.db().get_user(user_id).await?;

    scope.ath.db().clear_password_hash(user_id).await?;
    scope.ath.delete_user_sessions(&user_id).await?;

    let send_result = scope.ath.send_password_reset_email(&user.email).await;

    let note = if send_result.is_ok() {
        "forced password reset (email sent)"
    } else {
        "forced password reset (email failed)"
    };
    log_admin_action(&scope, AuditEvent::PasswordReset, user_id, note).await;

    let target = format!("/t/{slug}/users/{user_id}");
    let redirect = if send_result.is_ok() {
        redirect_with_flash(&target, Some("Password cleared. Reset email sent."), None)
    } else {
        redirect_with_flash(
            &target,
            None,
            Some(
                "Password cleared, but the reset email could not be sent. \
                 Ask the user to use 'Forgot password' on the login page.",
            ),
        )
    };
    Ok(redirect.into_response())
}

// ---------- Step 7: Revoke all sessions ----------

async fn revoke_sessions(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((slug, raw_id)): Path<(String, String)>,
) -> Result<Response, BrowserError> {
    let Ok(user_id) = raw_id.parse::<UserId>() else {
        return Ok(Redirect::to(&format!("/t/{slug}/users")).into_response());
    };
    let n = scope.ath.delete_user_sessions(&user_id).await?;
    log_admin_action(
        &scope,
        AuditEvent::Logout,
        user_id,
        &format!("revoked {n} sessions"),
    )
    .await;
    let flash = format!("Revoked {n} session(s).");
    Ok(
        redirect_with_flash(&format!("/t/{slug}/users/{user_id}"), Some(&flash), None)
            .into_response(),
    )
}

// ---------- Step 8: Delete user (owner-only, double-confirm) ----------

#[derive(Deserialize)]
struct DeleteForm {
    confirm: String,
    #[allow(dead_code)]
    csrf_token: String,
}

async fn delete_user(
    RequireTenantOwner(scope): RequireTenantOwner,
    Path((slug, raw_id)): Path<(String, String)>,
    HtmlForm(form): HtmlForm<DeleteForm>,
) -> Result<Response, BrowserError> {
    let Ok(user_id) = raw_id.parse::<UserId>() else {
        return Ok(Redirect::to(&format!("/t/{slug}/users")).into_response());
    };

    if form.confirm != "DELETE" {
        return Ok(
            Redirect::to(&format!("/t/{slug}/users/{user_id}?error=confirm_required"))
                .into_response(),
        );
    }

    // Audit before delete — audit_log.user_id has no FK so the row
    // persists even after the user record is removed.
    log_admin_action(&scope, AuditEvent::UserDeleted, user_id, "deleted").await;

    scope.ath.delete_user(user_id).await?;
    Ok(Redirect::to(&format!("/t/{slug}/users")).into_response())
}

// ---------- Step 9: Role assign / unassign ----------

#[derive(Deserialize)]
struct AssignRoleForm {
    role_id: allowthem_core::types::RoleId,
    #[allow(dead_code)]
    csrf_token: String,
}

async fn assign_role(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((slug, raw_id)): Path<(String, String)>,
    HtmlForm(form): HtmlForm<AssignRoleForm>,
) -> Result<Response, BrowserError> {
    let Ok(user_id) = raw_id.parse::<UserId>() else {
        return Ok(Redirect::to(&format!("/t/{slug}/users")).into_response());
    };
    scope.ath.assign_role(&user_id, &form.role_id).await?;
    log_admin_action(
        &scope,
        AuditEvent::RoleAssigned,
        user_id,
        &format!("role={}", form.role_id),
    )
    .await;
    Ok(Redirect::to(&format!("/t/{slug}/users/{user_id}")).into_response())
}

async fn unassign_role(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((slug, raw_id, role_id)): Path<(String, String, allowthem_core::types::RoleId)>,
) -> Result<Response, BrowserError> {
    let Ok(user_id) = raw_id.parse::<UserId>() else {
        return Ok(Redirect::to(&format!("/t/{slug}/users")).into_response());
    };
    scope.ath.unassign_role(&user_id, &role_id).await?;
    log_admin_action(
        &scope,
        AuditEvent::RoleUnassigned,
        user_id,
        &format!("role={role_id}"),
    )
    .await;
    Ok(Redirect::to(&format!("/t/{slug}/users/{user_id}")).into_response())
}

// ---------- Step 10: Permission grant / revoke ----------

#[derive(Deserialize)]
struct GrantPermissionForm {
    permission_id: allowthem_core::types::PermissionId,
    #[allow(dead_code)]
    csrf_token: String,
}

async fn grant_permission(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((slug, raw_id)): Path<(String, String)>,
    HtmlForm(form): HtmlForm<GrantPermissionForm>,
) -> Result<Response, BrowserError> {
    let Ok(user_id) = raw_id.parse::<UserId>() else {
        return Ok(Redirect::to(&format!("/t/{slug}/users")).into_response());
    };
    scope
        .ath
        .assign_permission_to_user(&user_id, &form.permission_id)
        .await?;
    log_admin_action(
        &scope,
        AuditEvent::PermissionAssigned,
        user_id,
        &format!("perm={}", form.permission_id),
    )
    .await;
    Ok(Redirect::to(&format!("/t/{slug}/users/{user_id}")).into_response())
}

async fn revoke_permission(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((slug, raw_id, permission_id)): Path<(
        String,
        String,
        allowthem_core::types::PermissionId,
    )>,
) -> Result<Response, BrowserError> {
    let Ok(user_id) = raw_id.parse::<UserId>() else {
        return Ok(Redirect::to(&format!("/t/{slug}/users")).into_response());
    };
    scope
        .ath
        .unassign_permission_from_user(&user_id, &permission_id)
        .await?;
    log_admin_action(
        &scope,
        AuditEvent::PermissionUnassigned,
        user_id,
        &format!("perm={permission_id}"),
    )
    .await;
    Ok(Redirect::to(&format!("/t/{slug}/users/{user_id}")).into_response())
}

// ---------------------------------------------------------------------------
// Helpers — landed in this scaffold so Steps 3..10 use them without churn.
// ---------------------------------------------------------------------------

/// Render a redirect response with optional `info` / `error` flash params.
/// The detail handler reads `Query<DetailQuery>` and threads these into the
/// template render context. Query-string-based to avoid a session-flash dep.
/// Flash strings are server-authored, so a minimal `qs_encode` covers the
/// chars that would corrupt query parsing.
fn redirect_with_flash(target: &str, info: Option<&str>, error: Option<&str>) -> Redirect {
    let mut url = target.to_string();
    let mut sep = if target.contains('?') { '&' } else { '?' };
    if let Some(i) = info {
        url.push(sep);
        url.push_str("info=");
        url.push_str(&qs_encode(i));
        sep = '&';
    }
    if let Some(e) = error {
        url.push(sep);
        url.push_str("error=");
        url.push_str(&qs_encode(e));
    }
    Redirect::to(&url)
}

/// Minimal query-string encoder. Replaces `&`, `=`, `#`, `?`, `+`, `%`,
/// space; non-ASCII bytes get percent-encoded byte-by-byte. Sufficient for
/// the server-authored flash strings used here.
fn qs_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b' ' => out.push('+'),
            b'&' | b'=' | b'#' | b'?' | b'+' | b'%' => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
            0x21..=0x7E => out.push(b as char),
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

/// Write one audit-log row tagging the actor. The detail string carries
/// the actor's email so the row is queryable / human-readable even after
/// the target user is deleted (`allowthem_audit_log.user_id` has no FK).
async fn log_admin_action(
    scope: &TenantScope,
    event: AuditEvent,
    target_user_id: UserId,
    note: &str,
) {
    let detail = format!("{note} (actor: {})", scope.user.email.as_str());
    let event_for_log = event.clone();
    if let Err(e) = scope
        .ath
        .db()
        .log_audit(
            event,
            Some(&target_user_id),
            None,
            None,
            None,
            Some(&detail),
        )
        .await
    {
        tracing::error!(error = %e, event = ?event_for_log, %target_user_id, "audit log write failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_status_recognises_pinned_values() {
        assert_eq!(parse_status(&Some("active".into())), Some(true));
        assert_eq!(parse_status(&Some("blocked".into())), Some(false));
        assert_eq!(parse_status(&Some(String::new())), None);
        assert_eq!(parse_status(&Some("nope".into())), None);
        assert_eq!(parse_status(&None), None);
    }

    #[test]
    fn parse_yes_no_strict() {
        assert_eq!(parse_yes_no(&Some("yes".into())), Some(true));
        assert_eq!(parse_yes_no(&Some("no".into())), Some(false));
        assert_eq!(parse_yes_no(&Some("maybe".into())), None);
        assert_eq!(parse_yes_no(&None), None);
    }

    #[test]
    fn nonempty_strips_and_filters() {
        assert_eq!(nonempty(&Some("  hi  ".into())), Some("hi"));
        assert_eq!(nonempty(&Some("   ".into())), None);
        assert_eq!(nonempty(&None), None);
    }

    #[test]
    fn qs_encode_handles_special_chars() {
        assert_eq!(qs_encode("hello"), "hello");
        assert_eq!(qs_encode("a b"), "a+b");
        assert_eq!(qs_encode("a&b"), "a%26b");
        assert_eq!(qs_encode("a=b"), "a%3Db");
    }
}
