//! Super-admin platform health page.
//!
//! - `GET /admin/health` — cache sizes, DB file sizes, system info (Step 12 of 99c.6)

use axum::extract::State;
use axum::response::Response;

use crate::dashboard::extractors::RequireSuperAdmin;
use crate::dashboard::state::DashboardRouterState;

pub async fn page(
    _scope: RequireSuperAdmin,
    _state: State<DashboardRouterState>,
) -> Response {
    unimplemented!("Step 12 of 99c.6")
}
