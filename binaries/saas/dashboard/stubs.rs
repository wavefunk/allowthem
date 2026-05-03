//! Coming-soon stub handlers for settings pages not yet implemented.
//!
//! Routes (wired in Step 17):
//!   GET /t/{slug}/settings/webhooks
//!   GET /t/{slug}/settings/email
//!   GET /t/{slug}/settings/social
//!   GET /t/{slug}/settings/domain

use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};
use minijinja::context;

use allowthem_server::browser_error::BrowserError;

use super::extractors::RequireTenantMember;
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

const DOMAIN_WIREFRAME: &str = "\
┌─ Custom domain ─────────────────────────────┐
│ Current:  auth.acme.example.com             │
│ Custom:   [auth.acme.com       ]  Verify    │
│ Status:   ● Pending DNS propagation         │
└─────────────────────────────────────────────┘";

// ---------------------------------------------------------------------------
// Local render helper
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
    let path = format!("/t/{}/settings/webhooks", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        "settings/webhooks.html",
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(&scope),
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
    let path = format!("/t/{}/settings/email", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        "settings/email.html",
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(&scope),
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
    let path = format!("/t/{}/settings/social", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        "settings/social.html",
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(&scope),
            title => "Social Providers",
            epic_ref => "7m5",
            description => "Connect Google, GitHub, and other OAuth providers for social login.",
            wireframe => SOCIAL_WIREFRAME,
        },
    )
    .map(IntoResponse::into_response)
}

pub async fn domain(
    State(state): State<DashboardRouterState>,
    RequireTenantMember(scope): RequireTenantMember,
) -> Result<Response, BrowserError> {
    let path = format!("/t/{}/settings/domain", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        "settings/domain.html",
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(&scope),
            title => "Custom Domain",
            epic_ref => "38y",
            description => "Point your own domain at the auth surface for a branded login experience.",
            wireframe => DOMAIN_WIREFRAME,
        },
    )
    .map(IntoResponse::into_response)
}
