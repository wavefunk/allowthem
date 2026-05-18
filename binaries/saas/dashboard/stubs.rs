//! Coming-soon stub handlers for settings pages not yet implemented.
//!
//! Routes (wired in Step 17):
//!   GET /t/{slug}/settings/webhooks
//!   GET /t/{slug}/settings/email
//!   GET /t/{slug}/settings/social

use axum::extract::State;
use axum::response::{IntoResponse, Response};

use allowthem_saas::{Tenant, TenantRole};
use allowthem_server::browser_error::BrowserError;

use super::extractors::{RequireTenantMember, TenantScope};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;
use super::views::{self, ComingSoonPageView, WorkspaceView};

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

struct StubPage<'a> {
    path_suffix: &'a str,
    title: &'a str,
    epic_ref: &'a str,
    description: &'a str,
    wireframe: &'a str,
}

async fn render_stub(
    state: &DashboardRouterState,
    scope: &TenantScope,
    page: StubPage<'_>,
) -> Result<Response, BrowserError> {
    let workspace_pairs = workspace_pairs_for_user(state, scope).await;
    let workspaces = workspace_views(&workspace_pairs, &scope.tenant.slug);
    let path = format!("/t/{}/settings/{}", scope.tenant.slug, page.path_suffix);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    let html = views::coming_soon_page(&ComingSoonPageView {
        tenant_name: scope.tenant.name.as_str(),
        tenant_slug: scope.tenant.slug.as_str(),
        nav_sections: &nav,
        workspaces: &workspaces,
        title: page.title,
        epic_ref: page.epic_ref,
        description: page.description,
        wireframe: Some(page.wireframe),
        status_session: Some(scope.user.email.as_str()),
        is_production: state.is_production,
    })?;
    Ok(html.into_response())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn webhooks(
    State(state): State<DashboardRouterState>,
    RequireTenantMember(scope): RequireTenantMember,
) -> Result<Response, BrowserError> {
    render_stub(
        &state,
        &scope,
        StubPage {
            path_suffix: "webhooks",
            title: "Webhooks",
            epic_ref: "7xw",
            description: "Configure webhook endpoints to receive real-time events (UserCreated, SessionCreated, PasswordChanged, etc.).",
            wireframe: WEBHOOK_WIREFRAME,
        },
    )
    .await
}

pub async fn email(
    State(state): State<DashboardRouterState>,
    RequireTenantMember(scope): RequireTenantMember,
) -> Result<Response, BrowserError> {
    render_stub(
        &state,
        &scope,
        StubPage {
            path_suffix: "email",
            title: "Email",
            epic_ref: "c8m",
            description: "Customise transactional email templates and sender address.",
            wireframe: EMAIL_WIREFRAME,
        },
    )
    .await
}

pub async fn social(
    State(state): State<DashboardRouterState>,
    RequireTenantMember(scope): RequireTenantMember,
) -> Result<Response, BrowserError> {
    render_stub(
        &state,
        &scope,
        StubPage {
            path_suffix: "social",
            title: "Social Providers",
            epic_ref: "7m5",
            description: "Connect Google, GitHub, and other OAuth providers for social login.",
            wireframe: SOCIAL_WIREFRAME,
        },
    )
    .await
}
