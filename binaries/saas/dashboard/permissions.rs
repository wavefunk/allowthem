//! Tenant-scoped permission CRUD handlers (99c.5 Step 9).
//!
//! Routes (all under `/t/{slug}/permissions`):
//! - `GET  /`            list all permissions — RequireTenantMember
//! - `GET  /new`         create form          — RequireTenantAdmin
//! - `POST /`            create               — RequireTenantAdmin
//! - `POST /{id}/delete` delete               — RequireTenantAdmin
//!
//! Audit rows go to `control_audit_events` via `ControlDb::log_control_audit`.

use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use allowthem_core::types::{PermissionId, PermissionName};
use allowthem_saas::{Tenant, TenantId, TenantRole};
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use super::extractors::{HtmlForm, RequireTenantAdmin, RequireTenantMember, TenantScope};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;
use super::views::{self, PermissionListPageView, PermissionNewPageView, WorkspaceView};

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn permission_routes() -> Router<DashboardRouterState> {
    Router::new()
        .route("/t/{slug}/permissions", get(list).post(create))
        .route("/t/{slug}/permissions/new", get(new_form))
        .route("/t/{slug}/permissions/{id}/delete", post(delete))
}

// ---------------------------------------------------------------------------
// Forms
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct PermissionForm {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
}

async fn log_permission_audit(
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

async fn render_permission_new_form(
    state: &DashboardRouterState,
    scope: &TenantScope,
    csrf: &CsrfToken,
    name: &str,
    description: &str,
    error: &str,
) -> Result<Response, BrowserError> {
    let workspace_pairs = workspace_pairs_for_user(state, scope).await;
    let workspaces = workspace_views(&workspace_pairs, &scope.tenant.slug);
    let path = format!("/t/{}/permissions/new", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    let html = views::permission_new_page(&PermissionNewPageView {
        tenant_name: scope.tenant.name.as_str(),
        tenant_slug: scope.tenant.slug.as_str(),
        nav_sections: &nav,
        workspaces: &workspaces,
        csrf_token: csrf.as_str(),
        name,
        description,
        error,
        status_session: Some(scope.user.email.as_str()),
        is_production: state.is_production,
    })?;
    Ok(html.into_response())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn list(
    RequireTenantMember(scope): RequireTenantMember,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let permissions = scope.ath.db().list_permissions().await?;

    let workspace_pairs = workspace_pairs_for_user(&state, &scope).await;
    let workspaces = workspace_views(&workspace_pairs, &scope.tenant.slug);
    let path = format!("/t/{}/permissions", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    let html = views::permission_list_page(&PermissionListPageView {
        tenant_name: scope.tenant.name.as_str(),
        tenant_slug: scope.tenant.slug.as_str(),
        role: scope.role,
        nav_sections: &nav,
        workspaces: &workspaces,
        permissions: &permissions,
        csrf_token: csrf.as_str(),
        status_session: Some(scope.user.email.as_str()),
        is_production: state.is_production,
    })?;
    Ok(html.into_response())
}

async fn new_form(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    render_permission_new_form(&state, &scope, &csrf, "", "", "").await
}

async fn create(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
    HtmlForm(form): HtmlForm<PermissionForm>,
) -> Result<Response, BrowserError> {
    let name = form.name.trim().to_owned();
    let desc = form.description.trim().to_owned();

    if name.is_empty() || name.len() > 120 {
        return render_permission_new_form(
            &state,
            &scope,
            &csrf,
            &name,
            &desc,
            "Permission name must be 1-120 characters.",
        )
        .await;
    }

    let perm_name = PermissionName::new(&name);
    let permission = match scope
        .ath
        .db()
        .create_permission(&perm_name, Some(desc.as_str()).filter(|s| !s.is_empty()))
        .await
    {
        Ok(p) => p,
        Err(allowthem_core::error::AuthError::Conflict(_)) => {
            return render_permission_new_form(
                &state,
                &scope,
                &csrf,
                &name,
                &desc,
                "A permission with that name already exists.",
            )
            .await;
        }
        Err(e) => return Err(BrowserError::from(e)),
    };

    log_permission_audit(
        &state,
        &scope,
        "tenant.permission_created",
        &serde_json::json!({"permission_id": permission.id.to_string(), "name": name}),
    )
    .await;

    Ok(Redirect::to(&format!("/t/{}/permissions", scope.tenant.slug)).into_response())
}

async fn delete(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((_slug, raw_id)): Path<(String, String)>,
    State(state): State<DashboardRouterState>,
) -> Result<Response, BrowserError> {
    let Ok(permission_id) = raw_id.parse::<PermissionId>() else {
        return Ok(Redirect::to(&format!("/t/{}/permissions", scope.tenant.slug)).into_response());
    };

    scope.ath.db().delete_permission(&permission_id).await?;

    log_permission_audit(
        &state,
        &scope,
        "tenant.permission_deleted",
        &serde_json::json!({"permission_id": permission_id.to_string()}),
    )
    .await;

    Ok(Redirect::to(&format!("/t/{}/permissions", scope.tenant.slug)).into_response())
}
