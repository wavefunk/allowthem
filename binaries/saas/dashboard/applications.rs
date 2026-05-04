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
use minijinja::context;
use serde::Deserialize;

use allowthem_core::applications::{Application, CreateApplicationParams, UpdateApplication};
use allowthem_core::error::AuthError;
use allowthem_core::types::{ApplicationId, ClientType};
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
    let workspaces = workspaces_for_user(&state, &scope).await;
    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/applications", scope.tenant.slug),
        scope.role,
    );
    let html = render(
        &state,
        "applications/list.html",
        scope.user.email.as_str(),
        context! {
            tenant => tenant_ctx(&scope.tenant),
            role => role_str(&scope),
            nav_sections => nav,
            applications => apps,
            current_tenant => tenant_ctx(&scope.tenant),
            workspaces,
            csrf_token => csrf.as_str(),
        },
    )?;
    Ok(html.into_response())
}

async fn new_form(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let workspaces = workspaces_for_user(&state, &scope).await;
    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/applications", scope.tenant.slug),
        scope.role,
    );
    Ok(render(
        &state,
        "applications/new.html",
        scope.user.email.as_str(),
        context! {
            tenant => tenant_ctx(&scope.tenant),
            role => role_str(&scope),
            nav_sections => nav,
            current_tenant => current_tenant_ctx(&scope.tenant),
            workspaces,
            csrf_token => csrf.as_str(),
            client_type => "confidential",
            name => "",
            redirect_uris => Vec::<String>::new(),
            logo_url => "",
            error => Option::<String>::None,
        },
    )?
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
    let workspaces = workspaces_for_user(&state, &scope).await;
    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/applications", scope.tenant.slug),
        scope.role,
    );
    Ok(render(
        &state,
        "applications/detail.html",
        scope.user.email.as_str(),
        context! {
            tenant => tenant_ctx(&scope.tenant),
            role => role_str(&scope),
            nav_sections => nav,
            current_tenant => current_tenant_ctx(&scope.tenant),
            workspaces,
            app => &app,
            redirect_uris,
            connected_users,
            csrf_token => csrf.as_str(),
            client_secret => Option::<String>::None,
        },
    )?
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
    let workspaces = workspaces_for_user(&state, &scope).await;
    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/applications", scope.tenant.slug),
        scope.role,
    );
    Ok(render(
        &state,
        "applications/edit.html",
        scope.user.email.as_str(),
        context! {
            tenant => tenant_ctx(&scope.tenant),
            role => role_str(&scope),
            nav_sections => nav,
            current_tenant => current_tenant_ctx(&scope.tenant),
            workspaces,
            app => &app,
            redirect_uris,
            csrf_token => csrf.as_str(),
            error => Option::<String>::None,
        },
    )?
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
    let workspaces = workspaces_for_user(&state, &scope).await;
    let mut resp = render(
        &state,
        "applications/detail.html",
        scope.user.email.as_str(),
        context! {
            tenant => tenant_ctx(&scope.tenant),
            role => role_str(&scope),
            current_tenant => current_tenant_ctx(&scope.tenant),
            workspaces,
            app => &app,
            redirect_uris,
            connected_users => 0u64,
            client_secret => secret.as_ref().map(|s| s.as_str().to_owned()),
            csrf_token => csrf.as_str(),
        },
    )?
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
    let workspaces = workspaces_for_user(&state, &scope).await;
    let mut resp = render(
        &state,
        "applications/detail.html",
        scope.user.email.as_str(),
        context! {
            tenant => tenant_ctx(&scope.tenant),
            role => role_str(&scope),
            current_tenant => current_tenant_ctx(&scope.tenant),
            workspaces,
            app => &app,
            redirect_uris,
            connected_users,
            client_secret => Some(secret.as_str().to_owned()),
            csrf_token => csrf.as_str(),
        },
    )?
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
    let workspaces = workspaces_for_user(state, scope).await;
    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/applications", scope.tenant.slug),
        scope.role,
    );
    Ok(render(
        state,
        "applications/new.html",
        scope.user.email.as_str(),
        context! {
            tenant => tenant_ctx(&scope.tenant),
            role => role_str(scope),
            nav_sections => nav,
            current_tenant => current_tenant_ctx(&scope.tenant),
            workspaces,
            csrf_token => csrf.as_str(),
            client_type => if form.client_type.is_empty() { "confidential" } else { form.client_type.as_str() },
            name => form.name.as_str(),
            redirect_uris => filter_uris(form.redirect_uris.clone()),
            logo_url => form.logo_url.as_deref().unwrap_or(""),
            error => Some(error.to_owned()),
        },
    )?
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
    let workspaces = workspaces_for_user(state, scope).await;
    let nav = tenant_nav_items(
        &scope.tenant.slug,
        &format!("/t/{}/applications", scope.tenant.slug),
        scope.role,
    );
    Ok(render(
        state,
        "applications/edit.html",
        scope.user.email.as_str(),
        context! {
            tenant => tenant_ctx(&scope.tenant),
            role => role_str(scope),
            nav_sections => nav,
            current_tenant => current_tenant_ctx(&scope.tenant),
            workspaces,
            app => existing,
            redirect_uris => filter_uris(form.redirect_uris.clone()),
            csrf_token => csrf.as_str(),
            error => Some(error.to_owned()),
        },
    )?
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
// Render + context shaping
// ---------------------------------------------------------------------------

fn render(
    state: &DashboardRouterState,
    name: &str,
    session: &str,
    ctx: minijinja::value::Value,
) -> Result<axum::response::Html<String>, BrowserError> {
    let tmpl = state
        .templates
        .get_template(name)
        .map_err(BrowserError::from)?;
    let body = tmpl
        .render(context! { status_session => session, ..ctx })
        .map_err(BrowserError::from)?;
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

