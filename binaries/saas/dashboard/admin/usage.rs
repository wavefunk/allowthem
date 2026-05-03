//! Super-admin usage analytics page.
//!
//! - `GET /admin/usage` — platform-wide MAU history (Step 10 of 99c.6)

use axum::extract::State;
use axum::response::Response;

use crate::dashboard::extractors::RequireSuperAdmin;
use crate::dashboard::state::DashboardRouterState;

pub async fn page(
    _scope: RequireSuperAdmin,
    _state: State<DashboardRouterState>,
) -> Response {
    unimplemented!("Step 10 of 99c.6")
}
