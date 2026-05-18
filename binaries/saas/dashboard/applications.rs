//! Tenant-scoped application CRUD handlers (99c.3).
//!
//! Routes (all under `/t/{slug}/applications`):
//! - `GET  /`                        list
//! - `GET  /new`                     create form (admin/owner)
//! - `POST /`                        create (admin/owner)
//! - `GET  /{app_id}`                detail (any member)
//! - `GET  /{app_id}/edit`           edit form (admin/owner)
//! - `POST /{app_id}`                update (admin/owner)
//! - `POST /{app_id}/regenerate-secret`  rotate secret (admin/owner)
//! - `POST /{app_id}/delete`         delete (admin/owner)
//!
//! Read handlers take a `RequireTenantMember`; write handlers take a
//! `RequireTenantAdmin`. Audit rows go to `control_audit_events` with
//! `actor = scope.user.email`.

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;

use allowthem_core::applications::{Application, CreateApplicationParams, UpdateApplication};
use allowthem_core::error::AuthError;
use allowthem_core::types::{ApplicationId, ClientType};
use allowthem_saas::{Tenant, TenantId, TenantRole};
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use super::extractors::{HtmlForm, RequireTenantAdmin, RequireTenantMember, TenantScope};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;
use super::views::{
    self, ApplicationDetailPageView, ApplicationEditPageView, ApplicationListPageView,
    ApplicationNewPageView, WorkspaceView,
};

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn application_routes() -> Router<DashboardRouterState> {
    Router::new()
        .route("/t/{slug}/applications", get(list).post(create))
        .route("/t/{slug}/applications/new", get(new_form))
        .route("/t/{slug}/applications/{app_id}", get(detail).post(update))
        .route("/t/{slug}/applications/{app_id}/edit", get(edit_form))
        .route(
            "/t/{slug}/applications/{app_id}/regenerate-secret",
            post(regenerate_secret),
        )
        .route(
            "/t/{slug}/applications/{app_id}/delete",
            post(delete_application),
        )
}

// ---------------------------------------------------------------------------
// Forms
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct CreateAppForm {
    name: String,
    #[serde(default)]
    client_type: String,
    #[serde(default)]
    redirect_uris: Vec<String>,
    logo_url: Option<String>,
    #[allow(dead_code)] // validated by csrf_middleware; field present so the form parses.
    csrf_token: String,
}

#[derive(Deserialize)]
struct EditAppForm {
    name: String,
    #[serde(default)]
    redirect_uris: Vec<String>,
    logo_url: Option<String>,
    #[serde(default)]
    is_active: Option<String>,
    #[allow(dead_code)]
    csrf_token: String,
}

fn filter_uris(uris: Vec<String>) -> Vec<String> {
    uris.into_iter()
        .map(|u| u.trim().to_owned())
        .filter(|u| !u.is_empty())
        .collect()
}

fn opt_string(s: Option<String>) -> Option<String> {
    s.and_then(|v| {
        let t = v.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_owned())
        }
    })
}

fn checkbox(v: &Option<String>) -> bool {
    v.as_deref() == Some("on")
}

// ---------------------------------------------------------------------------
// Read handlers
// ---------------------------------------------------------------------------

async fn list(
    RequireTenantMember(scope): RequireTenantMember,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let apps = scope.ath.db().list_applications().await?;
    let workspace_pairs = workspace_pairs_for_user(&state, &scope).await;
    let workspaces = workspace_views(&workspace_pairs, &scope.tenant.slug);
    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/applications", scope.tenant.slug),
        scope.role,
    );
    let html = views::application_list_page(&ApplicationListPageView {
        tenant_name: scope.tenant.name.as_str(),
        tenant_slug: scope.tenant.slug.as_str(),
        role: scope.role,
        nav_sections: &nav,
        workspaces: &workspaces,
        applications: &apps,
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
    let workspace_pairs = workspace_pairs_for_user(&state, &scope).await;
    let workspaces = workspace_views(&workspace_pairs, &scope.tenant.slug);
    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/applications", scope.tenant.slug),
        scope.role,
    );
    Ok(views::new_application_page(&ApplicationNewPageView {
        tenant_name: scope.tenant.name.as_str(),
        tenant_slug: scope.tenant.slug.as_str(),
        role: scope.role,
        nav_sections: &nav,
        workspaces: &workspaces,
        csrf_token: csrf.as_str(),
        name: "",
        client_type: "confidential",
        redirect_uris: &[],
        logo_url: "",
        error: None,
        status_session: Some(scope.user.email.as_str()),
        is_production: state.is_production,
    })?
    .into_response())
}

async fn detail(
    RequireTenantMember(scope): RequireTenantMember,
    Path((_slug, app_id)): Path<(String, ApplicationId)>,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let app = match scope.ath.db().get_application(app_id).await {
        Ok(a) => a,
        Err(AuthError::NotFound) => {
            return Ok(
                Redirect::to(&format!("/t/{}/applications", scope.tenant.slug)).into_response(),
            );
        }
        Err(e) => return Err(e.into()),
    };
    let connected_users = scope.ath.db().count_users_for_application(app.id).await?;
    let redirect_uris = app.redirect_uri_list()?;
    let workspace_pairs = workspace_pairs_for_user(&state, &scope).await;
    let workspaces = workspace_views(&workspace_pairs, &scope.tenant.slug);
    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/applications", scope.tenant.slug),
        scope.role,
    );
    Ok(views::application_detail_page(&ApplicationDetailPageView {
        tenant_name: scope.tenant.name.as_str(),
        tenant_slug: scope.tenant.slug.as_str(),
        role: scope.role,
        nav_sections: &nav,
        workspaces: &workspaces,
        app: &app,
        redirect_uris: &redirect_uris,
        connected_users,
        csrf_token: csrf.as_str(),
        client_secret: None,
        status_session: Some(scope.user.email.as_str()),
        is_production: state.is_production,
    })?
    .into_response())
}

async fn edit_form(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((_slug, app_id)): Path<(String, ApplicationId)>,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let app = scope.ath.db().get_application(app_id).await?;
    let redirect_uris = app.redirect_uri_list()?;
    let workspace_pairs = workspace_pairs_for_user(&state, &scope).await;
    let workspaces = workspace_views(&workspace_pairs, &scope.tenant.slug);
    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/applications", scope.tenant.slug),
        scope.role,
    );
    Ok(views::edit_application_page(&ApplicationEditPageView {
        tenant_name: scope.tenant.name.as_str(),
        tenant_slug: scope.tenant.slug.as_str(),
        role: scope.role,
        nav_sections: &nav,
        workspaces: &workspaces,
        app: &app,
        redirect_uris: &redirect_uris,
        csrf_token: csrf.as_str(),
        error: None,
        status_session: Some(scope.user.email.as_str()),
        is_production: state.is_production,
    })?
    .into_response())
}

// ---------------------------------------------------------------------------
// Write handlers
// ---------------------------------------------------------------------------

async fn create(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
    HtmlForm(form): HtmlForm<CreateAppForm>,
) -> Result<Response, BrowserError> {
    let client_type = match form.client_type.as_str() {
        "public" => ClientType::Public,
        "confidential" | "" => ClientType::Confidential,
        other => {
            return rerender_new(
                &state,
                &scope,
                &csrf,
                &form,
                &format!("Unknown client type: {other}"),
            )
            .await;
        }
    };
    let params = CreateApplicationParams {
        name: form.name.trim().to_owned(),
        client_type,
        redirect_uris: filter_uris(form.redirect_uris.clone()),
        is_trusted: false,
        created_by: None,
        logo_url: opt_string(form.logo_url.clone()),
        primary_color: None,
        accent_hex: None,
        accent_ink: None,
        forced_mode: None,
        font_css_url: None,
        font_family: None,
        splash_text: None,
        splash_image_url: None,
        splash_primitive: None,
        splash_url: None,
        shader_cell_scale: None,
    };
    let (app, secret) = match scope.ath.db().create_application(params).await {
        Ok(v) => v,
        Err(AuthError::InvalidRedirectUri(msg)) => {
            return rerender_new(
                &state,
                &scope,
                &csrf,
                &form,
                &format!("Invalid redirect URI: {msg}"),
            )
            .await;
        }
        Err(AuthError::Validation(msg)) => {
            return rerender_new(&state, &scope, &csrf, &form, &msg).await;
        }
        Err(e) => return Err(e.into()),
    };

    log_app_audit(
        &state,
        &scope,
        "application.created",
        &serde_json::json!({
            "application_id": app.id.to_string(),
            "client_id": app.client_id.as_str(),
            "client_type": form.client_type,
        }),
    )
    .await;

    let redirect_uris = app.redirect_uri_list()?;
    let workspace_pairs = workspace_pairs_for_user(&state, &scope).await;
    let workspaces = workspace_views(&workspace_pairs, &scope.tenant.slug);
    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/applications", scope.tenant.slug),
        scope.role,
    );
    let mut resp = views::application_detail_page(&ApplicationDetailPageView {
        tenant_name: scope.tenant.name.as_str(),
        tenant_slug: scope.tenant.slug.as_str(),
        role: scope.role,
        nav_sections: &nav,
        workspaces: &workspaces,
        app: &app,
        redirect_uris: &redirect_uris,
        connected_users: 0,
        csrf_token: csrf.as_str(),
        client_secret: secret.as_ref().map(|s| s.as_str()),
        status_session: Some(scope.user.email.as_str()),
        is_production: state.is_production,
    })?
    .into_response();
    cache_no_store(resp.headers_mut());
    Ok(resp)
}

async fn update(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((_slug, app_id)): Path<(String, ApplicationId)>,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
    HtmlForm(form): HtmlForm<EditAppForm>,
) -> Result<Response, BrowserError> {
    let existing = scope.ath.db().get_application(app_id).await?;
    let new_logo = opt_string(form.logo_url.clone());
    let params = UpdateApplication {
        name: form.name.trim().to_owned(),
        redirect_uris: filter_uris(form.redirect_uris.clone()),
        is_trusted: existing.is_trusted, // not editable in dashboard.
        is_active: checkbox(&form.is_active),
        logo_url: new_logo,
        // Preserve every Wave-Funk branding field unchanged — the dashboard
        // form does not expose them.
        primary_color: existing.primary_color.clone(),
        accent_hex: existing.accent_hex.clone(),
        accent_ink: existing.accent_ink,
        forced_mode: existing.forced_mode,
        font_css_url: existing.font_css_url.clone(),
        font_family: existing.font_family.clone(),
        splash_text: existing.splash_text.clone(),
        splash_image_url: existing.splash_image_url.clone(),
        splash_primitive: existing.splash_primitive,
        splash_url: existing.splash_url.clone(),
        shader_cell_scale: existing.shader_cell_scale,
    };
    match scope.ath.db().update_application(app_id, params).await {
        Ok(()) => {}
        Err(AuthError::InvalidRedirectUri(msg)) => {
            return rerender_edit(
                &state,
                &scope,
                &existing,
                &csrf,
                &form,
                &format!("Invalid redirect URI: {msg}"),
            )
            .await;
        }
        Err(AuthError::Validation(msg)) => {
            return rerender_edit(&state, &scope, &existing, &csrf, &form, &msg).await;
        }
        Err(e) => return Err(e.into()),
    }
    log_app_audit(
        &state,
        &scope,
        "application.updated",
        &serde_json::json!({
            "application_id": app_id.to_string(),
            "fields": ["name", "redirect_uris", "is_active", "logo_url"],
        }),
    )
    .await;
    Ok(Redirect::to(&format!("/t/{}/applications/{}", scope.tenant.slug, app_id)).into_response())
}

async fn regenerate_secret(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((_slug, app_id)): Path<(String, ApplicationId)>,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let (app, secret) = match scope.ath.db().regenerate_client_secret(app_id).await {
        Ok(pair) => pair,
        Err(AuthError::InvalidRequest(msg)) => {
            // Public client has no secret to regenerate (spec §4.1).
            return Ok((StatusCode::BAD_REQUEST, msg).into_response());
        }
        Err(e) => return Err(e.into()),
    };
    log_app_audit(
        &state,
        &scope,
        "application.secret_regenerated",
        &serde_json::json!({
            "application_id": app_id.to_string(),
            "client_id": app.client_id.as_str(),
        }),
    )
    .await;
    let connected_users = scope.ath.db().count_users_for_application(app_id).await?;
    let redirect_uris = app.redirect_uri_list()?;
    let workspace_pairs = workspace_pairs_for_user(&state, &scope).await;
    let workspaces = workspace_views(&workspace_pairs, &scope.tenant.slug);
    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/applications", scope.tenant.slug),
        scope.role,
    );
    let mut resp = views::application_detail_page(&ApplicationDetailPageView {
        tenant_name: scope.tenant.name.as_str(),
        tenant_slug: scope.tenant.slug.as_str(),
        role: scope.role,
        nav_sections: &nav,
        workspaces: &workspaces,
        app: &app,
        redirect_uris: &redirect_uris,
        connected_users,
        csrf_token: csrf.as_str(),
        client_secret: Some(secret.as_str()),
        status_session: Some(scope.user.email.as_str()),
        is_production: state.is_production,
    })?
    .into_response();
    cache_no_store(resp.headers_mut());
    Ok(resp)
}

async fn delete_application(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((_slug, app_id)): Path<(String, ApplicationId)>,
    State(state): State<DashboardRouterState>,
    _csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let app = scope.ath.db().get_application(app_id).await?;
    scope.ath.db().delete_application(app_id).await?;
    log_app_audit(
        &state,
        &scope,
        "application.deleted",
        &serde_json::json!({
            "application_id": app_id.to_string(),
            "client_id": app.client_id.as_str(),
        }),
    )
    .await;
    Ok(Redirect::to(&format!("/t/{}/applications", scope.tenant.slug)).into_response())
}

// ---------------------------------------------------------------------------
// Re-render helpers (used by validation error paths)
// ---------------------------------------------------------------------------

async fn rerender_new(
    state: &DashboardRouterState,
    scope: &TenantScope,
    csrf: &CsrfToken,
    form: &CreateAppForm,
    error: &str,
) -> Result<Response, BrowserError> {
    let workspace_pairs = workspace_pairs_for_user(state, scope).await;
    let workspaces = workspace_views(&workspace_pairs, &scope.tenant.slug);
    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/applications", scope.tenant.slug),
        scope.role,
    );
    let redirect_uris = filter_uris(form.redirect_uris.clone());
    Ok(views::new_application_page(&ApplicationNewPageView {
        tenant_name: scope.tenant.name.as_str(),
        tenant_slug: scope.tenant.slug.as_str(),
        role: scope.role,
        nav_sections: &nav,
        workspaces: &workspaces,
        csrf_token: csrf.as_str(),
        name: form.name.as_str(),
        client_type: if form.client_type.is_empty() {
            "confidential"
        } else {
            form.client_type.as_str()
        },
        redirect_uris: &redirect_uris,
        logo_url: form.logo_url.as_deref().unwrap_or(""),
        error: Some(error),
        status_session: Some(scope.user.email.as_str()),
        is_production: state.is_production,
    })?
    .into_response())
}

async fn rerender_edit(
    state: &DashboardRouterState,
    scope: &TenantScope,
    existing: &Application,
    csrf: &CsrfToken,
    form: &EditAppForm,
    error: &str,
) -> Result<Response, BrowserError> {
    let workspace_pairs = workspace_pairs_for_user(state, scope).await;
    let workspaces = workspace_views(&workspace_pairs, &scope.tenant.slug);
    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/applications", scope.tenant.slug),
        scope.role,
    );
    let redirect_uris = filter_uris(form.redirect_uris.clone());
    Ok(views::edit_application_page(&ApplicationEditPageView {
        tenant_name: scope.tenant.name.as_str(),
        tenant_slug: scope.tenant.slug.as_str(),
        role: scope.role,
        nav_sections: &nav,
        workspaces: &workspaces,
        app: existing,
        redirect_uris: &redirect_uris,
        csrf_token: csrf.as_str(),
        error: Some(error),
        status_session: Some(scope.user.email.as_str()),
        is_production: state.is_production,
    })?
    .into_response())
}

// ---------------------------------------------------------------------------
// Audit + headers
// ---------------------------------------------------------------------------

async fn log_app_audit(
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

fn cache_no_store(headers: &mut HeaderMap) {
    if let Ok(v) = "no-store, max-age=0, must-revalidate".parse() {
        headers.insert(header::CACHE_CONTROL, v);
    }
    if let Ok(v) = "no-cache".parse() {
        headers.insert("pragma", v);
    }
}

// ---------------------------------------------------------------------------
// View context shaping
// ---------------------------------------------------------------------------

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
