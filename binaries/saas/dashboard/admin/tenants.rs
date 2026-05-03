//! Super-admin tenant management handlers.
//!
//! - `GET  /admin`                           overview (stats + tenant list)
//! - `GET  /admin/tenants/{id}`              tenant detail
//! - `POST /admin/tenants/{id}/suspend`      suspend a tenant
//! - `POST /admin/tenants/{id}/unsuspend`    unsuspend a tenant
//! - `POST /admin/tenants/{id}/delete`       delete a tenant
//! - `POST /admin/tenants/{id}/change-plan`  change a tenant's plan
//!
//! Steps 7 and 8 of 99c.6 implement the read paths; Step 9 adds the mutations.

use axum::extract::{Path, Query, State};
use axum::response::Response;
use uuid::Uuid;

use crate::dashboard::extractors::RequireSuperAdmin;
use crate::dashboard::state::DashboardRouterState;

/// Query parameters for the overview page (Step 7).
#[derive(serde::Deserialize, Default)]
pub struct OverviewQuery {
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub plan: String,
    #[serde(default = "default_sort")]
    pub sort: String,
    #[serde(default = "default_dir")]
    pub dir: String,
    #[serde(default = "default_page")]
    pub page: u32,
}

fn default_sort() -> String {
    "name".into()
}

fn default_dir() -> String {
    "asc".into()
}

fn default_page() -> u32 {
    1
}

pub async fn overview(
    _scope: RequireSuperAdmin,
    _q: Query<OverviewQuery>,
    _state: State<DashboardRouterState>,
) -> Response {
    unimplemented!("Step 7 of 99c.6")
}

pub async fn detail(
    _scope: RequireSuperAdmin,
    _id: Path<Uuid>,
    _state: State<DashboardRouterState>,
) -> Response {
    unimplemented!("Step 8 of 99c.6")
}

pub async fn suspend(
    _scope: RequireSuperAdmin,
    _id: Path<Uuid>,
    _state: State<DashboardRouterState>,
) -> Response {
    unimplemented!("Step 9 of 99c.6")
}

pub async fn unsuspend(
    _scope: RequireSuperAdmin,
    _id: Path<Uuid>,
    _state: State<DashboardRouterState>,
) -> Response {
    unimplemented!("Step 9 of 99c.6")
}

pub async fn delete(
    _scope: RequireSuperAdmin,
    _id: Path<Uuid>,
    _state: State<DashboardRouterState>,
) -> Response {
    unimplemented!("Step 9 of 99c.6")
}

pub async fn change_plan(
    _scope: RequireSuperAdmin,
    _id: Path<Uuid>,
    _state: State<DashboardRouterState>,
) -> Response {
    unimplemented!("Step 9 of 99c.6")
}
