//! General settings page — `/t/{slug}/settings` (99c.5 Step 10).
//!
//! Routes:
//! - `GET  /t/{slug}/settings`  — RequireTenantMember (read-only for viewer)
//! - `POST /t/{slug}/settings`  — RequireTenantAdmin  (name update only)

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;

use allowthem_saas::{Tenant, TenantId, TenantRole};
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use super::extractors::{HtmlForm, RequireTenantAdmin, RequireTenantMember, TenantScope};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;
use super::views::{self, GeneralSettingsPageView, WorkspaceView};

// ---------------------------------------------------------------------------
// Forms
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct UpdateGeneralForm {
    #[serde(default)]
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct ShowQuery {
    #[serde(default)]
    pub saved: Option<String>,
}

async fn log_settings_audit(
    state: &DashboardRouterState,
    scope: &TenantScope,
    action: &str,
    detail: &serde_json::Value,
) {
    let Some(uuid) = scope.tenant.id_as_uuid() else {
        tracing::error!(action = %action, "tenant has undecodable UUID; skipping audit");
        return;
    };
    let tenant_id = TenantId::from(uuid);
    if let Err(e) = state
        .control_db
        .log_control_audit(scope.user.email.as_str(), action, Some(&tenant_id), detail)
        .await
    {
        tracing::error!(action = %action, error = %e, "control audit log failed");
    }
}

async fn workspace_pairs_for_user(
    state: &DashboardRouterState,
    scope: &TenantScope,
) -> Vec<(Tenant, TenantRole)> {
    state
        .control_db
        .tenants_for_member(scope.user.email.as_str())
        .await
        .unwrap_or_default()
}

fn workspace_views<'a>(
    pairs: &'a [(Tenant, TenantRole)],
    active_slug: &str,
) -> Vec<WorkspaceView<'a>> {
    pairs
        .iter()
        .map(|(workspace, role)| WorkspaceView {
            name: workspace.name.as_str(),
            slug: workspace.slug.as_str(),
            role: *role,
            active: workspace.slug == active_slug,
        })
        .collect()
}

async fn render_general_settings(
    state: &DashboardRouterState,
    scope: &TenantScope,
    csrf: &CsrfToken,
    error: &str,
    saved: bool,
) -> Result<Response, BrowserError> {
    let workspace_pairs = workspace_pairs_for_user(state, scope).await;
    let workspaces = workspace_views(&workspace_pairs, &scope.tenant.slug);
    let path = format!("/t/{}/settings", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    let html = views::general_settings_page(&GeneralSettingsPageView {
        tenant_name: scope.tenant.name.as_str(),
        tenant_slug: scope.tenant.slug.as_str(),
        role: scope.role,
        nav_sections: &nav,
        workspaces: &workspaces,
        csrf_token: csrf.as_str(),
        error,
        saved,
        status_session: Some(scope.user.email.as_str()),
        is_production: state.is_production,
    })?;
    Ok(html.into_response())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn show(
    RequireTenantMember(scope): RequireTenantMember,
    Query(query): Query<ShowQuery>,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    render_general_settings(&state, &scope, &csrf, "", query.saved.is_some()).await
}

pub async fn update(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
    HtmlForm(form): HtmlForm<UpdateGeneralForm>,
) -> Result<Response, BrowserError> {
    let name = form.name.trim().to_owned();

    if name.is_empty() || name.len() > 80 {
        return render_general_settings(
            &state,
            &scope,
            &csrf,
            "Workspace name must be 1-80 characters.",
            false,
        )
        .await;
    }

    let Some(uuid) = scope.tenant.id_as_uuid() else {
        return Err(BrowserError::from(
            allowthem_core::error::AuthError::NotFound,
        ));
    };
    let tenant_id = TenantId::from(uuid);

    if let Err(e) = state
        .control_db
        .update_tenant_name(&tenant_id, name.clone())
        .await
    {
        tracing::error!(error = %e, "update_tenant_name failed");
    }

    log_settings_audit(
        &state,
        &scope,
        "tenant.name_updated",
        &serde_json::json!({"name": name}),
    )
    .await;

    Ok(Redirect::to(&format!("/t/{}/settings?saved=1", scope.tenant.slug)).into_response())
}
