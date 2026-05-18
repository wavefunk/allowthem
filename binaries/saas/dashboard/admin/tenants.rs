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
use axum::response::{IntoResponse, Redirect, Response};
use chrono::Utc;
use serde::Deserialize;
use uuid::Uuid;

use allowthem_core::AuthError;
use allowthem_saas::{SearchTenantsParams, SortDir, TenantId, TenantSortCol, TenantStatus};
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use crate::dashboard::extractors::{HtmlForm, RequireSuperAdmin};
use crate::dashboard::nav::admin_nav_items;
use crate::dashboard::state::DashboardRouterState;
use crate::dashboard::views::{self, AdminPlanView, AdminTenantRowView};

const PAGE_SIZE: u32 = 25;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map a [`allowthem_saas::SaasError`] to a [`BrowserError`] for admin handlers.
fn saas_err(e: allowthem_saas::SaasError) -> BrowserError {
    match e {
        allowthem_saas::SaasError::TenantNotFound | allowthem_saas::SaasError::MemberNotFound => {
            BrowserError::Auth(AuthError::NotFound)
        }
        allowthem_saas::SaasError::Auth(a) => BrowserError::Auth(a),
        allowthem_saas::SaasError::Db(db) => BrowserError::Auth(AuthError::Database(db)),
        other => {
            tracing::error!(error = %other, "unexpected error in admin handler");
            BrowserError::Auth(AuthError::Conflict(other.to_string()))
        }
    }
}

fn parse_sort_col(s: &str) -> TenantSortCol {
    match s {
        "slug" => TenantSortCol::Slug,
        "status" => TenantSortCol::Status,
        "plan" => TenantSortCol::Plan,
        "mau" => TenantSortCol::Mau,
        "created_at" => TenantSortCol::CreatedAt,
        "last_seen_at" => TenantSortCol::LastSeenAt,
        _ => TenantSortCol::Name,
    }
}

fn parse_sort_dir(s: &str) -> SortDir {
    if s == "desc" {
        SortDir::Desc
    } else {
        SortDir::Asc
    }
}

fn parse_tenant_status(s: &str) -> Option<TenantStatus> {
    match s {
        "active" => Some(TenantStatus::Active),
        "suspended" => Some(TenantStatus::Suspended),
        "deleted" => Some(TenantStatus::Deleted),
        _ => None,
    }
}

/// Query-string %–encoder for flash redirect values.
fn qs_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b' ' => out.push('+'),
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            other => {
                use std::fmt::Write;
                let _ = write!(out, "%{other:02X}");
            }
        }
    }
    out
}

fn redirect_with_flash(target: &str, info: Option<&str>, error: Option<&str>) -> Redirect {
    let mut url = target.to_string();
    let mut sep = if target.contains('?') { '&' } else { '?' };
    if let Some(i) = info {
        url.push(sep);
        url.push_str("info=");
        url.push_str(&qs_encode(i));
        sep = '&';
    }
    if let Some(e) = error {
        url.push(sep);
        url.push_str("error=");
        url.push_str(&qs_encode(e));
    }
    Redirect::to(&url)
}

// ---------------------------------------------------------------------------
// Query structs
// ---------------------------------------------------------------------------

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

/// Query parameters for flash messages on the detail page.
#[derive(Debug, Deserialize, Default)]
pub struct DetailQuery {
    #[serde(default)]
    info: String,
    #[serde(default)]
    error: String,
}

// ---------------------------------------------------------------------------
// Step 7: Overview page
// ---------------------------------------------------------------------------

pub async fn overview(
    RequireSuperAdmin(scope): RequireSuperAdmin,
    Query(q): Query<OverviewQuery>,
    State(state): State<DashboardRouterState>,
) -> Result<Response, BrowserError> {
    let page = q.page.max(1);
    let current_period = Utc::now().format("%Y-%m").to_string();

    let active_count = state
        .control_db
        .count_tenants_by_status(TenantStatus::Active)
        .await
        .map_err(saas_err)?;
    let suspended_count = state
        .control_db
        .count_tenants_by_status(TenantStatus::Suspended)
        .await
        .map_err(saas_err)?;
    let new_30d = state
        .control_db
        .count_tenants_created_since(Utc::now() - chrono::Duration::days(30))
        .await
        .map_err(saas_err)?;
    let dormant_count = state
        .control_db
        .count_dormant_tenants(Utc::now() - chrono::Duration::days(90))
        .await
        .map_err(saas_err)?;
    let plans = state.control_db.list_plans().await.map_err(saas_err)?;

    // Resolve plan filter string to raw plan_id bytes.
    let plan_id_bytes: Option<Vec<u8>> = if q.plan.is_empty() {
        None
    } else {
        plans
            .iter()
            .find(|p| p.name.eq_ignore_ascii_case(&q.plan))
            .map(|p| p.id.clone())
    };

    let sort_col = parse_sort_col(&q.sort);
    let sort_dir = parse_sort_dir(&q.dir);
    let q_trimmed = q.q.trim().to_string();

    let result = state
        .control_db
        .search_tenants(SearchTenantsParams {
            query: if q_trimmed.is_empty() {
                None
            } else {
                Some(&q_trimmed)
            },
            status: parse_tenant_status(&q.status),
            plan_id: plan_id_bytes.as_deref(),
            current_period: &current_period,
            sort_col,
            sort_dir,
            limit: PAGE_SIZE,
            offset: (page - 1) * PAGE_SIZE,
        })
        .await
        .map_err(saas_err)?;

    let total_pages = result.total.div_ceil(PAGE_SIZE).max(1);
    let has_filters = !q_trimmed.is_empty() || !q.status.is_empty() || !q.plan.is_empty();
    let nav = admin_nav_items("/admin");

    let tenant_views: Vec<AdminTenantRowView> = result
        .rows
        .iter()
        .map(AdminTenantRowView::from_row)
        .collect();
    let plan_views: Vec<AdminPlanView> = plans.iter().map(AdminPlanView::from_plan).collect();

    Ok(views::admin_overview_page(&views::AdminOverviewPageView {
        nav_sections: &nav,
        tenants: &tenant_views,
        total: result.total,
        page,
        total_pages,
        active_count,
        suspended_count,
        new_30d,
        dormant_count,
        plans: &plan_views,
        q: q_trimmed.as_str(),
        status: q.status.as_str(),
        plan: q.plan.as_str(),
        sort: q.sort.as_str(),
        dir: q.dir.as_str(),
        has_filters,
        status_session: Some(scope.user.email.as_str()),
        is_production: state.is_production,
    })?
    .into_response())
}

// ---------------------------------------------------------------------------
// Step 8: Tenant detail page
// ---------------------------------------------------------------------------

pub async fn detail(
    RequireSuperAdmin(scope): RequireSuperAdmin,
    Path(id): Path<Uuid>,
    Query(q): Query<DetailQuery>,
    csrf: CsrfToken,
    State(state): State<DashboardRouterState>,
) -> Result<Response, BrowserError> {
    let tenant_id = TenantId::from(id);
    let tenant = state
        .control_db
        .tenant_by_id(&tenant_id)
        .await
        .map_err(saas_err)?;
    let tenant = match tenant {
        Some(t) => t,
        None => return Err(BrowserError::Auth(AuthError::NotFound)),
    };

    let current_period = Utc::now().format("%Y-%m").to_string();
    let usage = state
        .control_db
        .aggregate_usage_for_period(&current_period)
        .await
        .map_err(saas_err)?;
    let plan = state
        .control_db
        .get_plan_by_id(&tenant.plan_id)
        .await
        .map_err(saas_err)?;
    let all_plans = state.control_db.list_plans().await.map_err(saas_err)?;

    let tenant_uuid = tenant
        .id_as_uuid()
        .map(|u| u.to_string())
        .unwrap_or_default();
    let current_plan_id_hex = hex::encode(&tenant.plan_id);
    let all_plan_views: Vec<AdminPlanView> =
        all_plans.iter().map(AdminPlanView::from_plan).collect();
    let nav = admin_nav_items("/admin");

    Ok(
        views::admin_tenant_detail_page(&views::AdminTenantDetailPageView {
            nav_sections: &nav,
            tenant: &tenant,
            tenant_uuid: tenant_uuid.as_str(),
            usage: &usage,
            plan: plan.as_ref(),
            current_plan_id_hex: current_plan_id_hex.as_str(),
            all_plans: &all_plan_views,
            info: q.info.as_str(),
            error: q.error.as_str(),
            csrf_token: csrf.as_str(),
            status_session: Some(scope.user.email.as_str()),
            is_production: state.is_production,
        })?
        .into_response(),
    )
}

// ---------------------------------------------------------------------------
// Step 9: Tenant action handlers (mutations)
// ---------------------------------------------------------------------------

pub async fn suspend(
    RequireSuperAdmin(scope): RequireSuperAdmin,
    Path(id): Path<Uuid>,
    State(state): State<DashboardRouterState>,
) -> Result<Response, BrowserError> {
    let tenant_id = TenantId::from(id);
    state
        .control_db
        .set_tenant_status(&tenant_id, TenantStatus::Suspended)
        .await
        .map_err(saas_err)?;
    state
        .control_db
        .log_control_audit(
            scope.user.email.as_str(),
            "tenant.suspend",
            Some(&tenant_id),
            &serde_json::json!({}),
        )
        .await
        .map_err(saas_err)?;
    Ok(redirect_with_flash(
        &format!("/admin/tenants/{id}"),
        Some("Tenant suspended."),
        None,
    )
    .into_response())
}

pub async fn unsuspend(
    RequireSuperAdmin(scope): RequireSuperAdmin,
    Path(id): Path<Uuid>,
    State(state): State<DashboardRouterState>,
) -> Result<Response, BrowserError> {
    let tenant_id = TenantId::from(id);
    state
        .control_db
        .set_tenant_status(&tenant_id, TenantStatus::Active)
        .await
        .map_err(saas_err)?;
    state
        .control_db
        .log_control_audit(
            scope.user.email.as_str(),
            "tenant.unsuspend",
            Some(&tenant_id),
            &serde_json::json!({}),
        )
        .await
        .map_err(saas_err)?;
    Ok(redirect_with_flash(
        &format!("/admin/tenants/{id}"),
        Some("Tenant reactivated."),
        None,
    )
    .into_response())
}

pub async fn delete(
    RequireSuperAdmin(scope): RequireSuperAdmin,
    Path(id): Path<Uuid>,
    State(state): State<DashboardRouterState>,
) -> Result<Response, BrowserError> {
    let tenant_id = TenantId::from(id);
    state
        .control_db
        .set_tenant_status(&tenant_id, TenantStatus::Deleted)
        .await
        .map_err(saas_err)?;
    state
        .control_db
        .log_control_audit(
            scope.user.email.as_str(),
            "tenant.delete",
            Some(&tenant_id),
            &serde_json::json!({}),
        )
        .await
        .map_err(saas_err)?;
    Ok(Redirect::to("/admin").into_response())
}

// ---------------------------------------------------------------------------
// change-plan form
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ChangePlanForm {
    plan_id: String,
    #[allow(dead_code)]
    csrf_token: String,
}

pub async fn change_plan(
    RequireSuperAdmin(scope): RequireSuperAdmin,
    Path(id): Path<Uuid>,
    State(state): State<DashboardRouterState>,
    HtmlForm(form): HtmlForm<ChangePlanForm>,
) -> Result<Response, BrowserError> {
    let plan_id_bytes = hex::decode(&form.plan_id)
        .map_err(|_| BrowserError::Auth(AuthError::Validation("invalid plan_id".into())))?;

    let tenant_id = TenantId::from(id);
    state
        .control_db
        .set_tenant_plan(&tenant_id, &plan_id_bytes)
        .await
        .map_err(saas_err)?;
    state
        .control_db
        .log_control_audit(
            scope.user.email.as_str(),
            "tenant.change_plan",
            Some(&tenant_id),
            &serde_json::json!({ "plan_id": form.plan_id }),
        )
        .await
        .map_err(saas_err)?;
    Ok(
        redirect_with_flash(&format!("/admin/tenants/{id}"), Some("Plan updated."), None)
            .into_response(),
    )
}
