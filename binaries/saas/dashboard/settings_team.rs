//! Team members list — `/t/{slug}/settings/team` (99c.5 Step 13).
//!
//! Routes (read-only at this step — mutations land in Steps 14–16):
//! - `GET /t/{slug}/settings/team` — RequireTenantMember

use axum::Router;
use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use minijinja::context;

use allowthem_saas::{TenantId, TenantRole};
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use super::extractors::{RequireTenantMember, TenantScope};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn team_routes() -> Router<DashboardRouterState> {
    Router::new().route("/t/{slug}/settings/team", get(list))
}

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

fn render(
    state: &DashboardRouterState,
    ctx: minijinja::value::Value,
) -> Result<Html<String>, BrowserError> {
    let tmpl = state
        .templates
        .get_template("settings/team/list.html")
        .map_err(BrowserError::from)?;
    let body = tmpl.render(ctx).map_err(BrowserError::from)?;
    Ok(Html(body))
}

fn tenant_ctx(tenant: &allowthem_saas::Tenant) -> minijinja::value::Value {
    context! {
        id => tenant.id.clone(),
        name => tenant.name.clone(),
        slug => tenant.slug.clone(),
    }
}

fn role_str(role: TenantRole) -> &'static str {
    match role {
        TenantRole::Owner => "owner",
        TenantRole::Admin => "admin",
        TenantRole::Viewer => "viewer",
    }
}

fn can_manage(scope: &TenantScope) -> bool {
    matches!(scope.role, TenantRole::Owner | TenantRole::Admin)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn list(
    RequireTenantMember(scope): RequireTenantMember,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let members = if let Some(uuid) = scope.tenant.id_as_uuid() {
        let tenant_id = TenantId::from(uuid);
        state
            .control_db
            .list_tenant_members(&tenant_id)
            .await
            .unwrap_or_default()
    } else {
        vec![]
    };

    let member_rows: Vec<_> = members
        .iter()
        .map(|m| {
            let id_str = m
                .id_as_member_id()
                .map(|mid| mid.as_uuid().to_string())
                .unwrap_or_default();
            context! {
                id => id_str,
                email => m.email.clone(),
                role => m.role.as_str(),
                status => if m.accepted_at.is_some() { "accepted" } else { "invited" },
                invited_at => m.invited_at.format("%Y-%m-%d %H:%M UTC").to_string(),
                accepted_at => m.accepted_at.map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string()),
            }
        })
        .collect();

    let path = format!("/t/{}/settings/team", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(scope.role),
            csrf_token => csrf.as_str(),
            members => member_rows,
            can_manage => can_manage(&scope),
        },
    )
    .map(IntoResponse::into_response)
}
