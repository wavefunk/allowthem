//! General settings page — `/t/{slug}/settings` (99c.5 Step 10).
//!
//! Routes:
//! - `GET  /t/{slug}/settings`  — RequireTenantMember (read-only for viewer)
//! - `POST /t/{slug}/settings`  — RequireTenantAdmin  (name update only)

use axum::extract::{Query, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use minijinja::context;
use serde::Deserialize;

use allowthem_saas::TenantId;
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use super::extractors::{
    HtmlForm, RequireTenantAdmin, RequireTenantMember, TenantScope, current_tenant_ctx,
    workspaces_for_user,
};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;

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

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

fn render(
    state: &DashboardRouterState,
    session: &str,
    ctx: minijinja::value::Value,
) -> Result<Html<String>, BrowserError> {
    let tmpl = state
        .templates
        .get_template("settings/general.html")
        .map_err(BrowserError::from)?;
    let body = tmpl
        .render(context! { status_session => session, ..ctx })
        .map_err(BrowserError::from)?;
    Ok(Html(body))
}

fn tenant_ctx(tenant: &allowthem_saas::Tenant) -> minijinja::value::Value {
    context! {
        id => tenant.id.clone(),
        name => tenant.name.clone(),
        slug => tenant.slug.clone(),
    }
}

fn role_str(role: allowthem_saas::TenantRole) -> &'static str {
    use allowthem_saas::TenantRole;
    match role {
        TenantRole::Owner => "owner",
        TenantRole::Admin => "admin",
        TenantRole::Viewer => "viewer",
    }
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

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn show(
    RequireTenantMember(scope): RequireTenantMember,
    Query(query): Query<ShowQuery>,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let workspaces = workspaces_for_user(&state, &scope).await;
    let path = format!("/t/{}/settings", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        scope.user.email.as_str(),
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(scope.role),
            current_tenant => current_tenant_ctx(&scope.tenant),
            workspaces,
            csrf_token => csrf.as_str(),
            error => "",
            saved => query.saved.is_some(),
        },
    )
    .map(IntoResponse::into_response)
}

pub async fn update(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
    HtmlForm(form): HtmlForm<UpdateGeneralForm>,
) -> Result<Response, BrowserError> {
    let name = form.name.trim().to_owned();

    if name.is_empty() || name.len() > 80 {
        let workspaces = workspaces_for_user(&state, &scope).await;
        let path = format!("/t/{}/settings", scope.tenant.slug);
        let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
        return render(
            &state,
            scope.user.email.as_str(),
            context! {
                tenant => tenant_ctx(&scope.tenant),
                nav_sections => nav,
                role => role_str(scope.role),
                current_tenant => current_tenant_ctx(&scope.tenant),
                workspaces,
                csrf_token => csrf.as_str(),
                error => "Workspace name must be 1–80 characters.",
            },
        )
        .map(IntoResponse::into_response);
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
