//! Coming-soon stub handlers for settings pages not yet implemented.
//!
//! Routes (wired in Step 17):
//!   GET /t/{slug}/settings/webhooks
//!   GET /t/{slug}/settings/email
//!   GET /t/{slug}/settings/social

use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};
use minijinja::context;

use allowthem_server::browser_error::BrowserError;

use super::extractors::{RequireTenantMember, current_tenant_ctx, workspaces_for_user};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;

// ---------------------------------------------------------------------------
// Wireframe sketches
// ---------------------------------------------------------------------------

const WEBHOOK_WIREFRAME: &str = "\
┌─ Webhooks ──────────────────────────────────┐
│ + Add endpoint                              │
│─────────────────────────────────────────────│
│ https://app.example.com/hooks  active  ···  │
└─────────────────────────────────────────────┘";

const EMAIL_WIREFRAME: &str = "\
┌─ Email templates ───────────────────────────┐
│ From name:   [Acme         ]                │
│ From addr:   [noreply@...  ]                │
│ Welcome      Magic link    Reset password   │
└─────────────────────────────────────────────┘";

const SOCIAL_WIREFRAME: &str = "\
┌─ Social providers ──────────────────────────┐
│ [ ] Google      Client ID: [___________]    │
│ [ ] GitHub      Client ID: [___________]    │
│ [ ] Microsoft   Client ID: [___________]    │
└─────────────────────────────────────────────┘";

// ---------------------------------------------------------------------------
// Local render helper
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

fn role_str(scope: &super::extractors::TenantScope) -> &'static str {
    use allowthem_saas::TenantRole;
    match scope.role {
        TenantRole::Owner => "owner",
        TenantRole::Admin => "admin",
        TenantRole::Viewer => "viewer",
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn webhooks(
    State(state): State<DashboardRouterState>,
    RequireTenantMember(scope): RequireTenantMember,
) -> Result<Response, BrowserError> {
    let workspaces = workspaces_for_user(&state, &scope).await;
    let path = format!("/t/{}/settings/webhooks", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        "settings/webhooks.html",
        scope.user.email.as_str(),
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(&scope),
            current_tenant => current_tenant_ctx(&scope.tenant),
            workspaces,
            title => "Webhooks",
            epic_ref => "7xw",
            description => "Configure webhook endpoints to receive real-time events \
                            (UserCreated, SessionCreated, PasswordChanged, etc.).",
            wireframe => WEBHOOK_WIREFRAME,
        },
    )
    .map(IntoResponse::into_response)
}

pub async fn email(
    State(state): State<DashboardRouterState>,
    RequireTenantMember(scope): RequireTenantMember,
) -> Result<Response, BrowserError> {
    let workspaces = workspaces_for_user(&state, &scope).await;
    let path = format!("/t/{}/settings/email", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        "settings/email.html",
        scope.user.email.as_str(),
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(&scope),
            current_tenant => current_tenant_ctx(&scope.tenant),
            workspaces,
            title => "Email",
            epic_ref => "c8m",
            description => "Customise transactional email templates and sender address.",
            wireframe => EMAIL_WIREFRAME,
        },
    )
    .map(IntoResponse::into_response)
}

pub async fn social(
    State(state): State<DashboardRouterState>,
    RequireTenantMember(scope): RequireTenantMember,
) -> Result<Response, BrowserError> {
    let workspaces = workspaces_for_user(&state, &scope).await;
    let path = format!("/t/{}/settings/social", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        "settings/social.html",
        scope.user.email.as_str(),
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(&scope),
            current_tenant => current_tenant_ctx(&scope.tenant),
            workspaces,
            title => "Social Providers",
            epic_ref => "7m5",
            description => "Connect Google, GitHub, and other OAuth providers for social login.",
            wireframe => SOCIAL_WIREFRAME,
        },
    )
    .map(IntoResponse::into_response)
}
