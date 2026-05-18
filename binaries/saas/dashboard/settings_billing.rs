//! Plan & usage billing page — `/t/{slug}/settings/billing` (99c.5 Step 12).
//!
//! Routes:
//! - `GET  /t/{slug}/settings/billing`          — RequireTenantMember
//! - `POST /t/{slug}/settings/billing/upgrade`  — RequireTenantOwner (coming soon)

use axum::Router;
use axum::extract::State;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};

use allowthem_saas::{Tenant, TenantId, TenantPlan, TenantRole};
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use super::extractors::{RequireTenantMember, RequireTenantOwner, TenantScope};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;
use super::views::{
    self, BillingPlanView, BillingSettingsPageView, BillingUsageView, ComingSoonPageView,
    WorkspaceView,
};

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn billing_routes() -> Router<DashboardRouterState> {
    Router::new()
        .route("/t/{slug}/settings/billing", get(show))
        .route("/t/{slug}/settings/billing/upgrade", post(upgrade))
}

// ---------------------------------------------------------------------------
// Local helpers
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

fn plan_view(plan: Option<&TenantPlan>) -> Option<BillingPlanView> {
    plan.map(|plan| BillingPlanView {
        name: plan.name.clone(),
        mau_limit: plan.mau_limit,
        price_cents: plan.price_cents,
    })
}

fn usage_views(usage: &[allowthem_saas::control_db::TenantUsage]) -> Vec<BillingUsageView> {
    usage
        .iter()
        .take(12)
        .map(|usage| BillingUsageView {
            period: usage.period.clone(),
            mau_count: usage.mau_count,
            limit_reached_at: usage.limit_reached_at.map(|dt| dt.to_rfc3339()),
        })
        .collect()
}

async fn render_billing(
    state: &DashboardRouterState,
    scope: &TenantScope,
    csrf_token: &str,
    plan: Option<&TenantPlan>,
    current_usage: i64,
    usage: &[allowthem_saas::control_db::TenantUsage],
) -> Result<Response, BrowserError> {
    let plan = plan_view(plan);
    let usage = usage_views(usage);
    let workspace_pairs = workspace_pairs_for_user(state, scope).await;
    let workspaces = workspace_views(&workspace_pairs, &scope.tenant.slug);
    let path = format!("/t/{}/settings/billing", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    let html = views::billing_settings_page(&BillingSettingsPageView {
        tenant_name: scope.tenant.name.as_str(),
        tenant_slug: scope.tenant.slug.as_str(),
        role: scope.role,
        nav_sections: &nav,
        workspaces: &workspaces,
        csrf_token,
        plan: plan.as_ref(),
        current_usage,
        usage: &usage,
        status_session: Some(scope.user.email.as_str()),
        is_production: state.is_production,
    })?;
    Ok(html.into_response())
}

async fn render_upgrade_coming_soon(
    state: &DashboardRouterState,
    scope: &TenantScope,
) -> Result<Response, BrowserError> {
    let workspace_pairs = workspace_pairs_for_user(state, scope).await;
    let workspaces = workspace_views(&workspace_pairs, &scope.tenant.slug);
    let path = format!("/t/{}/settings/billing", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    let html = views::coming_soon_page(&ComingSoonPageView {
        tenant_name: scope.tenant.name.as_str(),
        tenant_slug: scope.tenant.slug.as_str(),
        nav_sections: &nav,
        workspaces: &workspaces,
        title: "Plan Upgrade",
        epic_ref: "eua",
        description: "Subscription management and plan upgrades are coming soon.",
        wireframe: None,
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
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let plan = state
        .control_db
        .get_plan_by_id(&scope.tenant.plan_id)
        .await
        .unwrap_or(None);

    let usage = if let Some(uuid) = scope.tenant.id_as_uuid() {
        let tid = TenantId::from(uuid);
        state
            .control_db
            .usage_for_tenant(&tid)
            .await
            .unwrap_or_default()
    } else {
        vec![]
    };

    let current_period = chrono::Utc::now().format("%Y-%m").to_string();
    let current_usage = usage
        .iter()
        .find(|u| u.period == current_period)
        .map(|u| u.mau_count)
        .unwrap_or(0);

    render_billing(
        &state,
        &scope,
        csrf.as_str(),
        plan.as_ref(),
        current_usage,
        &usage,
    )
    .await
}

pub async fn upgrade(
    RequireTenantOwner(scope): RequireTenantOwner,
    State(state): State<DashboardRouterState>,
) -> Result<Response, BrowserError> {
    render_upgrade_coming_soon(&state, &scope).await
}
