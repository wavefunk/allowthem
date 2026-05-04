//! Plan & usage billing page — `/t/{slug}/settings/billing` (99c.5 Step 12).
//!
//! Routes:
//! - `GET  /t/{slug}/settings/billing`          — RequireTenantMember
//! - `POST /t/{slug}/settings/billing/upgrade`  — RequireTenantOwner (501 stub)

use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use minijinja::context;

use allowthem_saas::TenantId;
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use super::extractors::{
    RequireTenantMember, RequireTenantOwner, current_tenant_ctx, workspaces_for_user,
};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;

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

fn render(
    state: &DashboardRouterState,
    session: &str,
    ctx: minijinja::value::Value,
) -> Result<Html<String>, BrowserError> {
    let tmpl = state
        .templates
        .get_template("settings/billing.html")
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

    let last_12: Vec<_> = usage
        .iter()
        .take(12)
        .map(|u| {
            context! {
                period => u.period.clone(),
                mau_count => u.mau_count,
                limit_reached_at => u.limit_reached_at.map(|dt| dt.to_rfc3339()),
            }
        })
        .collect();

    let plan_ctx = plan.as_ref().map(|p| {
        context! {
            name => p.name.clone(),
            mau_limit => p.mau_limit,
            price_cents => p.price_cents,
        }
    });

    let workspaces = workspaces_for_user(&state, &scope).await;
    let path = format!("/t/{}/settings/billing", scope.tenant.slug);
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
            plan => plan_ctx,
            current_usage => current_usage,
            last_12 => last_12,
        },
    )
    .map(IntoResponse::into_response)
}

pub async fn upgrade(
    RequireTenantOwner(scope): RequireTenantOwner,
    State(_state): State<DashboardRouterState>,
) -> Response {
    (
        StatusCode::NOT_IMPLEMENTED,
        Html(format!(
            "<p>Stripe Checkout glue lands with Epic eua. \
             <a href=\"/t/{}/settings/billing\">← Back to billing</a></p>",
            scope.tenant.slug
        )),
    )
        .into_response()
}
