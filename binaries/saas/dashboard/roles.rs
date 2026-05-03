//! Tenant-scoped role CRUD handlers (99c.5 Step 8).
//!
//! Routes (all under `/t/{slug}/roles`):
//! - `GET  /`                     list all roles    — RequireTenantMember
//! - `GET  /new`                  create form       — RequireTenantAdmin
//! - `POST /`                     create role       — RequireTenantAdmin
//! - `GET  /{id}`                 detail page       — RequireTenantMember
//! - `POST /{id}`                 update name+desc  — RequireTenantAdmin
//! - `POST /{id}/permissions`     set permissions   — RequireTenantAdmin
//! - `POST /{id}/delete`          delete role       — RequireTenantAdmin
//!
//! Role-CRUD audit rows go to `control_audit_events` via
//! `ControlDb::log_control_audit` — same pattern as application/user
//! management. The tenant `allowthem_audit_log` table stays for end-user
//! activity only.

use std::collections::HashSet;

use axum::Router;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use minijinja::context;
use serde::Deserialize;

use allowthem_core::types::{PermissionId, RoleId, RoleName};
use allowthem_saas::TenantId;
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use super::extractors::{HtmlForm, RequireTenantAdmin, RequireTenantMember, TenantScope};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn role_routes() -> Router<DashboardRouterState> {
    Router::new()
        .route("/t/{slug}/roles", get(list).post(create))
        .route("/t/{slug}/roles/new", get(new_form))
        .route(
            "/t/{slug}/roles/{id}",
            get(detail).post(update),
        )
        .route("/t/{slug}/roles/{id}/permissions", post(set_permissions))
        .route("/t/{slug}/roles/{id}/delete", post(delete))
}

// ---------------------------------------------------------------------------
// Forms
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RoleForm {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub struct SetPermissionsForm {
    #[serde(default)]
    pub permission_id: Vec<String>,
}

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

fn render(
    state: &DashboardRouterState,
    name: &str,
    ctx: minijinja::value::Value,
) -> Result<Html<String>, BrowserError> {
    let tmpl = state
        .templates
        .get_template(name)
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

fn role_str(role: allowthem_saas::TenantRole) -> &'static str {
    use allowthem_saas::TenantRole;
    match role {
        TenantRole::Owner => "owner",
        TenantRole::Admin => "admin",
        TenantRole::Viewer => "viewer",
    }
}

/// Fire-and-forget control-plane audit entry for role mutations.
/// Mirrors `log_app_audit` in `applications.rs`.
async fn log_role_audit(
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
    let roles = scope.ath.db().list_roles().await?;

    // N+1 permission count — acceptable at v1 scale per spec §9.
    let mut role_views = Vec::with_capacity(roles.len());
    for role in &roles {
        let perms = scope.ath.db().list_role_permissions(&role.id).await?;
        role_views.push(context! {
            id => role.id.to_string(),
            name => role.name.as_str(),
            description => role.description.clone(),
            permission_count => perms.len(),
        });
    }

    let path = format!("/t/{}/roles", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        "roles/list.html",
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(scope.role),
            csrf_token => csrf.as_str(),
            roles => role_views,
        },
    )
    .map(IntoResponse::into_response)
}

async fn new_form(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let path = format!("/t/{}/roles/new", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        "roles/new.html",
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
    HtmlForm(form): HtmlForm<RoleForm>,
) -> Result<Response, BrowserError> {
    let name = form.name.trim().to_owned();
    let desc = form.description.trim().to_owned();

    if name.is_empty() || name.len() > 80 {
        let path = format!("/t/{}/roles/new", scope.tenant.slug);
        let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
        return render(
            &state,
            "roles/new.html",
            context! {
                tenant => tenant_ctx(&scope.tenant),
                nav_sections => nav,
                role => role_str(scope.role),
                csrf_token => csrf.as_str(),
                error => "Role name must be 1–80 characters.",
                name => &name,
                description => &desc,
            },
        )
        .map(IntoResponse::into_response);
    }

    let role_name = RoleName::new(&name);
    let role = match scope
        .ath
        .db()
        .create_role(&role_name, Some(desc.as_str()).filter(|s| !s.is_empty()))
        .await
    {
        Ok(r) => r,
        Err(allowthem_core::error::AuthError::Conflict(_)) => {
            let path = format!("/t/{}/roles/new", scope.tenant.slug);
            let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
            return render(
                &state,
                "roles/new.html",
                context! {
                    tenant => tenant_ctx(&scope.tenant),
                    nav_sections => nav,
                    role => role_str(scope.role),
                    csrf_token => csrf.as_str(),
                    error => "A role with that name already exists.",
                    name => &name,
                    description => &desc,
                },
            )
            .map(IntoResponse::into_response);
        }
        Err(e) => return Err(BrowserError::from(e)),
    };

    log_role_audit(
        &state,
        &scope,
        "tenant.role_created",
        &serde_json::json!({"role_id": role.id.to_string(), "name": name}),
    )
    .await;

    Ok(Redirect::to(&format!("/t/{}/roles/{}", scope.tenant.slug, role.id)).into_response())
}

async fn detail(
    RequireTenantMember(scope): RequireTenantMember,
    Path((_slug, raw_id)): Path<(String, String)>,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let Ok(role_id) = raw_id.parse::<RoleId>() else {
        return Ok(Redirect::to(&format!("/t/{}/roles", scope.tenant.slug)).into_response());
    };

    let Some(role) = scope.ath.db().get_role(&role_id).await? else {
        return Ok(Redirect::to(&format!("/t/{}/roles", scope.tenant.slug)).into_response());
    };

    let all_permissions = scope.ath.db().list_permissions().await?;
    let assigned = scope.ath.db().list_role_permissions(&role_id).await?;
    let assigned_ids: HashSet<_> = assigned.iter().map(|p| p.id).collect();

    let perm_views: Vec<_> = all_permissions
        .iter()
        .map(|p| {
            context! {
                id => p.id.to_string(),
                name => p.name.as_str(),
                description => p.description.clone(),
                assigned => assigned_ids.contains(&p.id),
            }
        })
        .collect();

    let path = format!("/t/{}/roles/{}", scope.tenant.slug, role_id);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        "roles/detail.html",
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(scope.role),
            csrf_token => csrf.as_str(),
            this_role => context! {
                id => role.id.to_string(),
                name => role.name.as_str(),
                description => role.description.clone(),
            },
            permissions => perm_views,
            error => "",
        },
    )
    .map(IntoResponse::into_response)
}

async fn update(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((_slug, raw_id)): Path<(String, String)>,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
    HtmlForm(form): HtmlForm<RoleForm>,
) -> Result<Response, BrowserError> {
    let Ok(role_id) = raw_id.parse::<RoleId>() else {
        return Ok(Redirect::to(&format!("/t/{}/roles", scope.tenant.slug)).into_response());
    };

    let name = form.name.trim().to_owned();
    let desc = form.description.trim().to_owned();

    let re_render = |error: &str| {
        let all_permissions_fut = scope.ath.db().list_permissions();
        let role_perms_fut = scope.ath.db().list_role_permissions(&role_id);
        (error.to_owned(), all_permissions_fut, role_perms_fut)
    };
    let _ = re_render; // suppress unused warning; expanded inline below

    if name.is_empty() || name.len() > 80 {
        let all_permissions = scope.ath.db().list_permissions().await?;
        let assigned = scope.ath.db().list_role_permissions(&role_id).await?;
        let assigned_ids: HashSet<_> = assigned.iter().map(|p| p.id).collect();
        let perm_views: Vec<_> = all_permissions
            .iter()
            .map(|p| context! {
                id => p.id.to_string(),
                name => p.name.as_str(),
                description => p.description.clone(),
                assigned => assigned_ids.contains(&p.id),
            })
            .collect();
        let path = format!("/t/{}/roles/{}", scope.tenant.slug, role_id);
        let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
        return render(
            &state,
            "roles/detail.html",
            context! {
                tenant => tenant_ctx(&scope.tenant),
                nav_sections => nav,
                role => role_str(scope.role),
                csrf_token => csrf.as_str(),
                this_role => context! {
                    id => role_id.to_string(),
                    name => &name,
                    description => &desc,
                },
                permissions => perm_views,
                error => "Role name must be 1–80 characters.",
            },
        )
        .map(IntoResponse::into_response);
    }

    let role_name = RoleName::new(&name);
    match scope
        .ath
        .db()
        .update_role(&role_id, &role_name, Some(desc.as_str()).filter(|s| !s.is_empty()))
        .await
    {
        Ok(updated_role) => {
            log_role_audit(
                &state,
                &scope,
                "tenant.role_updated",
                &serde_json::json!({
                    "role_id": role_id.to_string(),
                    "name": updated_role.name.as_str(),
                }),
            )
            .await;
            Ok(
                Redirect::to(&format!("/t/{}/roles/{}", scope.tenant.slug, role_id))
                    .into_response(),
            )
        }
        Err(allowthem_core::error::AuthError::Conflict(_)) => {
            let all_permissions = scope.ath.db().list_permissions().await?;
            let assigned = scope.ath.db().list_role_permissions(&role_id).await?;
            let assigned_ids: HashSet<_> = assigned.iter().map(|p| p.id).collect();
            let perm_views: Vec<_> = all_permissions
                .iter()
                .map(|p| context! {
                    id => p.id.to_string(),
                    name => p.name.as_str(),
                    description => p.description.clone(),
                    assigned => assigned_ids.contains(&p.id),
                })
                .collect();
            let path = format!("/t/{}/roles/{}", scope.tenant.slug, role_id);
            let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
            render(
                &state,
                "roles/detail.html",
                context! {
                    tenant => tenant_ctx(&scope.tenant),
                    nav_sections => nav,
                    role => role_str(scope.role),
                    csrf_token => csrf.as_str(),
                    this_role => context! {
                        id => role_id.to_string(),
                        name => &name,
                        description => &desc,
                    },
                    permissions => perm_views,
                    error => "A role with that name already exists.",
                },
            )
            .map(IntoResponse::into_response)
        }
        Err(e) => Err(BrowserError::from(e)),
    }
}

async fn set_permissions(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((_slug, raw_id)): Path<(String, String)>,
    State(state): State<DashboardRouterState>,
    HtmlForm(form): HtmlForm<SetPermissionsForm>,
) -> Result<Response, BrowserError> {
    let Ok(role_id) = raw_id.parse::<RoleId>() else {
        return Ok(Redirect::to(&format!("/t/{}/roles", scope.tenant.slug)).into_response());
    };

    // Parse posted IDs; silently skip malformed entries.
    let posted: HashSet<PermissionId> = form
        .permission_id
        .iter()
        .filter_map(|s| s.parse::<PermissionId>().ok())
        .collect();

    let current: HashSet<PermissionId> = scope
        .ath
        .db()
        .list_role_permissions(&role_id)
        .await?
        .into_iter()
        .map(|p| p.id)
        .collect();

    let to_add: Vec<PermissionId> = posted.difference(&current).copied().collect();
    let to_remove: Vec<PermissionId> = current.difference(&posted).copied().collect();

    // v1: pool-level calls; _in_tx variants filed as follow-up.
    for pid in &to_add {
        scope.ath.db().assign_permission_to_role(&role_id, pid).await?;
    }
    for pid in &to_remove {
        scope.ath.db().unassign_permission_from_role(&role_id, pid).await?;
    }

    if !to_add.is_empty() || !to_remove.is_empty() {
        let to_add_strs: Vec<_> = to_add.iter().map(|p| p.to_string()).collect();
        let to_remove_strs: Vec<_> = to_remove.iter().map(|p| p.to_string()).collect();
        log_role_audit(
            &state,
            &scope,
            "tenant.role_permissions_changed",
            &serde_json::json!({
                "role_id": role_id.to_string(),
                "added": to_add_strs,
                "removed": to_remove_strs,
            }),
        )
        .await;
    }

    Ok(Redirect::to(&format!("/t/{}/roles/{}", scope.tenant.slug, role_id)).into_response())
}

async fn delete(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((_slug, raw_id)): Path<(String, String)>,
    State(state): State<DashboardRouterState>,
) -> Result<Response, BrowserError> {
    let Ok(role_id) = raw_id.parse::<RoleId>() else {
        return Ok(Redirect::to(&format!("/t/{}/roles", scope.tenant.slug)).into_response());
    };

    scope.ath.db().delete_role(&role_id).await?;

    log_role_audit(
        &state,
        &scope,
        "tenant.role_deleted",
        &serde_json::json!({"role_id": role_id.to_string()}),
    )
    .await;

    Ok(Redirect::to(&format!("/t/{}/roles", scope.tenant.slug)).into_response())
}
