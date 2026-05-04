//! Super-admin usage analytics page.
//!
//! - `GET /admin/usage` — platform-wide MAU history (Step 10 of 99c.6)

use axum::extract::State;
use axum::response::{Html, IntoResponse, Response};
use chrono::Utc;
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
            tracing::error!(error = %other, "unexpected error in admin/usage handler");
            BrowserError::Auth(AuthError::Conflict(other.to_string()))
        }
    }
}

pub async fn page(
    RequireSuperAdmin(scope): RequireSuperAdmin,
    State(state): State<DashboardRouterState>,
) -> Result<Response, BrowserError> {
    let current_period = Utc::now().format("%Y-%m").to_string();

    let current = state
        .control_db
        .aggregate_usage_for_period(&current_period)
        .await
        .map_err(saas_err)?;

    let history = state
        .control_db
        .aggregate_usage_history(12)
        .await
        .map_err(saas_err)?;

    let nav = admin_nav_items("/admin/usage");

    let tmpl = state
        .templates
        .get_template("admin/usage.html")
        .map_err(BrowserError::from)?;
    let body = tmpl
        .render(context! {
            status_session => scope.user.email.as_str(),
            nav_sections => nav,
            current => current,
            history => history,
            current_period => current_period,
        })
        .map_err(BrowserError::from)?;
    Ok(Html(body).into_response())
}
