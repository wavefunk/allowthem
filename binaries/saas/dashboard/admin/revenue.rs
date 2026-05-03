//! Super-admin revenue summary page.
//!
//! - `GET /admin/revenue` — MRR and plan distribution (Step 11 of 99c.6)

use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};
use minijinja::context;

use allowthem_core::AuthError;
use allowthem_saas::SaasError;
use allowthem_server::browser_error::BrowserError;

use crate::dashboard::extractors::RequireSuperAdmin;
use crate::dashboard::nav::admin_nav_items;
use crate::dashboard::state::DashboardRouterState;

fn saas_err(e: SaasError) -> BrowserError {
    match e {
        SaasError::Auth(a) => BrowserError::Auth(a),
        SaasError::Db(db) => BrowserError::Auth(AuthError::Database(db)),
        other => {
            tracing::error!(error = %other, "unexpected error in admin/revenue handler");
            BrowserError::Auth(AuthError::Conflict(other.to_string()))
        }
    }
}

pub async fn page(
    RequireSuperAdmin(_scope): RequireSuperAdmin,
    State(state): State<DashboardRouterState>,
) -> Result<Response, BrowserError> {
    let by_plan = state
        .control_db
        .count_tenants_grouped_by_plan()
        .await
        .map_err(saas_err)?;

    let plans = state.control_db.list_plans().await.map_err(saas_err)?;

    // Compute estimated MRR: sum of (plan.price_cents * active_tenants_on_plan).
    let mut mrr_cents: i64 = 0;
    for (plan_name, count) in &by_plan {
        if let Some(plan) = plans.iter().find(|p| &p.name == plan_name) {
            mrr_cents += plan.price_cents * (*count as i64);
        }
    }

    let nav = admin_nav_items("/admin/revenue");

    let tmpl = state
        .templates
        .get_template("admin/revenue.html")
        .map_err(BrowserError::from)?;
    let body = tmpl
        .render(context! {
            nav_sections => nav,
            by_plan => by_plan,
            plans => plans,
            mrr_cents => mrr_cents,
        })
        .map_err(BrowserError::from)?;
    Ok(Html(body).into_response())
}
