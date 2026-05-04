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
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use minijinja::context;
use serde::Deserialize;

use allowthem_core::types::{PermissionId, PermissionName};
use allowthem_saas::TenantId;
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use super::extractors::{HtmlForm, RequireTenantAdmin, RequireTenantMember, TenantScope};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;

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

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

fn render(
    state: &DashboardRouterState,
    name: &str,
    session: &str,
    ctx: minijinja::value::Value,
) -> Result<Html<String>, BrowserError> {
    let tmpl = state
        .templates
        .get_template(name)
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

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn list(
    RequireTenantMember(scope): RequireTenantMember,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let permissions = scope.ath.db().list_permissions().await?;

    let perm_views: Vec<_> = permissions
        .iter()
        .map(|p| {
            context! {
                id => p.id.to_string(),
                name => p.name.as_str(),
                description => p.description.clone(),
            }
        })
        .collect();

    let path = format!("/t/{}/permissions", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        "permissions/list.html",
        scope.user.email.as_str(),
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(scope.role),
            csrf_token => csrf.as_str(),
            permissions => perm_views,
        },
    )
    .map(IntoResponse::into_response)
}

async fn new_form(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let path = format!("/t/{}/permissions/new", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        "permissions/new.html",
        scope.user.email.as_str(),
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(scope.role),
            csrf_token => csrf.as_str(),
            error => "",
            name => "",
            description => "",
        },
    )
    .map(IntoResponse::into_response)
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
        let path = format!("/t/{}/permissions/new", scope.tenant.slug);
        let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
        return render(
            &state,
            "permissions/new.html",
            scope.user.email.as_str(),
            context! {
                tenant => tenant_ctx(&scope.tenant),
                nav_sections => nav,
                role => role_str(scope.role),
                csrf_token => csrf.as_str(),
                error => "Permission name must be 1–120 characters.",
                name => &name,
                description => &desc,
            },
        )
        .map(IntoResponse::into_response);
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
            let path = format!("/t/{}/permissions/new", scope.tenant.slug);
            let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
            return render(
                &state,
                "permissions/new.html",
                scope.user.email.as_str(),
                context! {
                    tenant => tenant_ctx(&scope.tenant),
                    nav_sections => nav,
                    role => role_str(scope.role),
                    csrf_token => csrf.as_str(),
                    error => "A permission with that name already exists.",
                    name => &name,
                    description => &desc,
                },
            )
            .map(IntoResponse::into_response);
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
