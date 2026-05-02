//! Tenant-scoped audit log page (99c.5 Step 7).
//!
//! Routes (under `/t/{slug}/audit`):
//! - `GET  /`              paginated list + filter form (any member)
//! - `GET  /export.csv`    CSV export of the filtered set (any member)
//!
//! Reads the *tenant* DB's `allowthem_audit_log` table (end-user activity:
//! logins, password changes, MFA events). Dashboard-actor mutations
//! continue to land in `control_audit_events` via `ControlDb::log_control_audit`.

use axum::Router;
use axum::extract::{Query, State};
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use chrono::{DateTime, NaiveDate, TimeZone, Utc};
use minijinja::context;
use serde::{Deserialize, Serialize};

use allowthem_core::audit::{AuditEvent, AuditListEntry, SearchAuditParams};
use allowthem_core::types::UserId;
use allowthem_core::Email;
use allowthem_server::browser_error::BrowserError;

use super::extractors::{RequireTenantMember, TenantScope};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;

const PAGE_SIZE: u32 = 50;
const EXPORT_MAX_ROWS: u32 = 10_000;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn audit_routes() -> Router<DashboardRouterState> {
    Router::new()
        .route("/t/{slug}/audit", get(list))
        .route("/t/{slug}/audit/export.csv", get(export_csv))
}

// ---------------------------------------------------------------------------
// Query parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct AuditListQuery {
    #[serde(default)]
    pub event_type: Option<String>,
    #[serde(default)]
    pub user_email: Option<String>,
    #[serde(default)]
    pub outcome: Option<String>,
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub page: Option<u32>,
}

fn nonempty(s: &Option<String>) -> Option<&str> {
    s.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

fn parse_event(s: &Option<String>) -> Option<AuditEvent> {
    match nonempty(s)? {
        "login" => Some(AuditEvent::Login),
        "login_failed" => Some(AuditEvent::LoginFailed),
        "logout" => Some(AuditEvent::Logout),
        "register" => Some(AuditEvent::Register),
        "password_change" => Some(AuditEvent::PasswordChange),
        "password_reset" => Some(AuditEvent::PasswordReset),
        "session_created" => Some(AuditEvent::SessionCreated),
        "session_expired" => Some(AuditEvent::SessionExpired),
        "user_updated" => Some(AuditEvent::UserUpdated),
        "user_deleted" => Some(AuditEvent::UserDeleted),
        "mfa_enabled" => Some(AuditEvent::MfaEnabled),
        "mfa_disabled" => Some(AuditEvent::MfaDisabled),
        "mfa_challenge_success" => Some(AuditEvent::MfaChallengeSuccess),
        "mfa_challenge_failed" => Some(AuditEvent::MfaChallengeFailed),
        _ => None,
    }
}

fn parse_outcome(s: &Option<String>) -> Option<bool> {
    match nonempty(s)? {
        "success" => Some(true),
        "failure" => Some(false),
        _ => None,
    }
}

fn parse_date_start(s: &Option<String>) -> Option<DateTime<Utc>> {
    nonempty(s)
        .and_then(|s| NaiveDate::parse_from_str(s, "%Y-%m-%d").ok())
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|dt| Utc.from_utc_datetime(&dt))
}

fn parse_date_end(s: &Option<String>) -> Option<DateTime<Utc>> {
    nonempty(s)
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
        AuditEvent::OrgCreated => "Org created",
        AuditEvent::OrgUpdated => "Org updated",
        AuditEvent::OrgDeleted => "Org deleted",
        AuditEvent::OrgMemberAdded => "Org member added",
        AuditEvent::OrgMemberRemoved => "Org member removed",
        AuditEvent::OrgMemberRoleChanged => "Org member role changed",
        AuditEvent::OrgOwnershipTransferred => "Org ownership transferred",
        AuditEvent::TeamCreated => "Team created",
        AuditEvent::TeamUpdated => "Team updated",
        AuditEvent::TeamDeleted => "Team deleted",
        AuditEvent::TeamMemberAdded => "Team member added",
        AuditEvent::TeamMemberRemoved => "Team member removed",
        AuditEvent::TeamMemberRoleChanged => "Team member role changed",
        AuditEvent::OrgInvitationCreated => "Org invitation created",
        AuditEvent::OrgInvitationAccepted => "Org invitation accepted",
        AuditEvent::OrgInvitationDeclined => "Org invitation declined",
        AuditEvent::OrgInvitationRevoked => "Org invitation revoked",
    }
}

#[derive(Serialize)]
struct EntryDisplay {
    event_label: String,
    event_slug: String,
    is_failure: bool,
    user_id: Option<String>,
    user_email: Option<String>,
    ip_address: Option<String>,
    detail: Option<String>,
    created_at: String,
    created_at_iso: String,
}

fn to_entry_displays(entries: &[AuditListEntry]) -> Vec<EntryDisplay> {
    entries
        .iter()
        .map(|e| EntryDisplay {
            event_label: event_label(&e.event_type).to_string(),
            event_slug: format!("{:?}", e.event_type)
                .chars()
                .flat_map(|c| {
                    if c.is_uppercase() {
                        vec!['_', c.to_ascii_lowercase()]
                    } else {
                        vec![c]
                    }
                })
                .collect::<String>()
                .trim_start_matches('_')
                .to_string(),
            is_failure: matches!(
                e.event_type,
                AuditEvent::LoginFailed | AuditEvent::MfaChallengeFailed
            ),
            user_id: e.user_id.map(|u| u.to_string()),
            user_email: e.user_email.clone(),
            ip_address: e.ip_address.clone(),
            detail: e.detail.clone(),
            created_at: e.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            created_at_iso: e
                .created_at
                .format("%Y-%m-%dT%H:%M:%S%.3fZ")
                .to_string(),
        })
        .collect()
}

/// Resolve `user_email` (exact match) → `UserId`. Returns:
/// - `Ok(Some(uid))` — match found, restrict the query.
/// - `Ok(None)` — no email filter requested.
/// - `Err(())` — email supplied but no such user; the handler renders an
///   empty result with a flash message, *not* an error.
async fn resolve_user_filter(
    scope: &TenantScope,
    email_str: Option<&str>,
) -> Result<Option<UserId>, ()> {
    let Some(raw) = email_str else { return Ok(None) };
    let Ok(email) = Email::new(raw.to_owned()) else { return Err(()) };
    match scope.ath.db().get_user_by_email(&email).await {
        Ok(u) => Ok(Some(u.id)),
        Err(allowthem_core::error::AuthError::NotFound) => Err(()),
        Err(e) => {
            tracing::error!(error = %e, "audit user lookup failed");
            Err(())
        }
    }
}

// ---------------------------------------------------------------------------
// Read handlers
// ---------------------------------------------------------------------------

async fn list(
    RequireTenantMember(scope): RequireTenantMember,
    State(state): State<DashboardRouterState>,
    Query(query): Query<AuditListQuery>,
) -> Result<Response, BrowserError> {
    let event = parse_event(&query.event_type);
    let outcome = parse_outcome(&query.outcome);
    let from = parse_date_start(&query.from);
    let to = parse_date_end(&query.to);
    let page = query.page.unwrap_or(1).max(1);

    let (entries, total, no_user) = match resolve_user_filter(&scope, nonempty(&query.user_email))
        .await
    {
        Ok(uid) => {
            let result = scope
                .ath
                .db()
                .search_audit_log(SearchAuditParams {
                    user_id: uid,
                    event_type: event.as_ref(),
                    is_success: outcome,
                    from,
                    to,
                    limit: PAGE_SIZE,
                    offset: (page - 1) * PAGE_SIZE,
                })
                .await?;
            (result.entries, result.total, false)
        }
        Err(()) => (Vec::new(), 0, true),
    };

    let entries_view = to_entry_displays(&entries);
    let total_pages = total.div_ceil(PAGE_SIZE).max(1);
    let has_filters = nonempty(&query.event_type).is_some()
        || nonempty(&query.user_email).is_some()
        || nonempty(&query.outcome).is_some()
        || nonempty(&query.from).is_some()
        || nonempty(&query.to).is_some();

    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/audit", scope.tenant.slug),
        scope.role,
    );
    let body = render(
        &state,
        "audit/list.html",
        context! {
            tenant => tenant_ctx(&scope.tenant),
            role => role_str(&scope),
            nav_sections => nav,
            entries => entries_view,
            total => total,
            page => page,
            total_pages => total_pages,
            page_size => PAGE_SIZE,
            event_type => query.event_type.clone().unwrap_or_default(),
            user_email => query.user_email.clone().unwrap_or_default(),
            outcome => query.outcome.clone().unwrap_or_default(),
            from => query.from.clone().unwrap_or_default(),
            to => query.to.clone().unwrap_or_default(),
            has_filters => has_filters,
            no_user => no_user,
        },
    )?;
    Ok(body.into_response())
}

async fn export_csv(
    RequireTenantMember(scope): RequireTenantMember,
    State(_state): State<DashboardRouterState>,
    Query(query): Query<AuditListQuery>,
) -> Result<Response, BrowserError> {
    let event = parse_event(&query.event_type);
    let outcome = parse_outcome(&query.outcome);
    let from = parse_date_start(&query.from);
    let to = parse_date_end(&query.to);

    let entries = match resolve_user_filter(&scope, nonempty(&query.user_email)).await {
        Ok(uid) => {
            scope
                .ath
                .db()
                .search_audit_log(SearchAuditParams {
                    user_id: uid,
                    event_type: event.as_ref(),
                    is_success: outcome,
                    from,
                    to,
                    limit: EXPORT_MAX_ROWS,
                    offset: 0,
                })
                .await?
                .entries
        }
        Err(()) => Vec::new(),
    };

    let csv = build_csv(&entries);
    let filename = format!(
        "audit-{}-{}.csv",
        scope.tenant.slug,
        Utc::now().format("%Y%m%dT%H%M%S")
    );
    let disp = format!("attachment; filename=\"{filename}\"");
    Ok((
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8"),
            (header::CONTENT_DISPOSITION, disp.as_str()),
        ],
        csv,
    )
        .into_response())
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        let escaped = s.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        s.to_owned()
    }
}

fn build_csv(entries: &[AuditListEntry]) -> String {
    let mut out = String::with_capacity(entries.len() * 64 + 64);
    out.push_str("created_at,event_type,user_email,ip,is_success,target_id,detail\n");
    for e in entries {
        let is_failure = matches!(
            e.event_type,
            AuditEvent::LoginFailed | AuditEvent::MfaChallengeFailed
        );
        let row = [
            e.created_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            event_label(&e.event_type).to_string(),
            e.user_email.clone().unwrap_or_default(),
            e.ip_address.clone().unwrap_or_default(),
            if is_failure { "false" } else { "true" }.to_string(),
            e.target_id.clone().unwrap_or_default(),
            e.detail.clone().unwrap_or_default(),
        ];
        let line = row
            .iter()
            .map(|f| csv_escape(f))
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&line);
        out.push('\n');
    }
    out
}

// ---------------------------------------------------------------------------
// Local helpers (kept private; mirror applications.rs without re-using
// across modules until the duplication actually matters).
// ---------------------------------------------------------------------------

fn render(
    state: &DashboardRouterState,
    name: &str,
    ctx: minijinja::value::Value,
) -> Result<axum::response::Html<String>, BrowserError> {
    let tmpl = state
        .templates
        .get_template(name)
        .map_err(BrowserError::from)?;
    let body = tmpl.render(ctx).map_err(BrowserError::from)?;
    Ok(axum::response::Html(body))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_event_handles_known_and_unknown() {
        assert_eq!(
            parse_event(&Some("login".into())),
            Some(AuditEvent::Login)
        );
        assert_eq!(parse_event(&Some("not-a-real-event".into())), None);
        assert_eq!(parse_event(&Some(String::new())), None);
        assert_eq!(parse_event(&None), None);
    }

    #[test]
    fn parse_outcome_strict() {
        assert_eq!(parse_outcome(&Some("success".into())), Some(true));
        assert_eq!(parse_outcome(&Some("failure".into())), Some(false));
        assert_eq!(parse_outcome(&Some("nope".into())), None);
    }

    #[test]
    fn parse_date_start_round_trip() {
        let dt = parse_date_start(&Some("2026-04-01".into())).unwrap();
        assert_eq!(dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(), "2026-04-01T00:00:00.000Z");
        assert!(parse_date_start(&Some("not-a-date".into())).is_none());
    }

    #[test]
    fn parse_date_end_advances_one_day() {
        let dt = parse_date_end(&Some("2026-04-01".into())).unwrap();
        assert_eq!(dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(), "2026-04-02T00:00:00.000Z");
    }

    #[test]
    fn build_csv_quotes_commas_and_newlines() {
        let entries: Vec<AuditListEntry> = Vec::new();
        let header = build_csv(&entries);
        assert_eq!(
            header,
            "created_at,event_type,user_email,ip,is_success,target_id,detail\n"
        );
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("with\"quote"), "\"with\"\"quote\"");
        assert_eq!(csv_escape("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn nonempty_strips_whitespace() {
        assert_eq!(nonempty(&Some("  hi  ".into())), Some("hi"));
        assert_eq!(nonempty(&Some("   ".into())), None);
        assert_eq!(nonempty(&None), None);
    }
}
