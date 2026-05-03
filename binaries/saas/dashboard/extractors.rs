//! Tenant-scope extractors for dashboard pages.
//!
//! Three newtypes around a shared `TenantScope`:
//! - [`RequireTenantMember`] — any role passes (Owner / Admin / Viewer).
//! - [`RequireTenantAdmin`]  — Owner / Admin only; Viewer → 403.
//! - [`RequireTenantOwner`]  — Owner only.
//!
//! Each runs the same resolution chain (dashboard session → slug →
//! membership → tenant `AllowThem`) and rejects with the failure modes
//! pinned in the 99c.3 spec §3.2: missing session → 303 to `/login`;
//! slug unknown / deleted → 404; suspended → suspended-tenant page;
//! non-member → 404; wrong role → 403.
//!
//! Also exposes [`HtmlForm`], a `serde_html_form`-backed form extractor
//! that handles repeated fields (e.g. multiple `redirect_uris`).

use axum::body::Bytes;
use axum::extract::{FromRequest, FromRequestParts, Path, Request};
use axum::http::{StatusCode, header, request::Parts};
use axum::response::{IntoResponse, Response};
use minijinja::context;
use serde::Deserialize;

use allowthem_core::{AllowThem, User};
use allowthem_saas::{
    SaasError, Tenant, TenantId, TenantRole, TenantStatus, build_handle_with_path,
};

use super::auth_helpers::current_dashboard_user;
use super::state::DashboardRouterState;

// ---------------------------------------------------------------------------
// HtmlForm
// ---------------------------------------------------------------------------

/// Form extractor backed by `serde_html_form` so multi-value fields
/// (`<input name="redirect_uris" />` repeated) deserialise into `Vec<T>`.
///
/// Lifted from `binaries/standalone/admin_applications.rs:75-92`.
pub struct HtmlForm<T>(pub T);

impl<S, T> FromRequest<S> for HtmlForm<T>
where
    T: serde::de::DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = Response;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        let bytes = Bytes::from_request(req, state)
            .await
            .map_err(|e| e.into_response())?;
        let value = serde_html_form::from_bytes(&bytes)
            .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()).into_response())?;
        Ok(HtmlForm(value))
    }
}

// ---------------------------------------------------------------------------
// Path parsing
// ---------------------------------------------------------------------------

/// Path slug parameter shape. Used by `resolve_scope` to read `{slug}` from
/// any route under `/t/{slug}/...`.
#[derive(Debug, Deserialize)]
struct TenantSlugPath {
    slug: String,
}

// ---------------------------------------------------------------------------
// TenantScope + extractors
// ---------------------------------------------------------------------------

/// The verified tenant context yielded by every dashboard tenant-scope
/// extractor. `user` is the dashboard user (audit actor); `tenant` /
/// `role` come from the control plane; `ath` is the tenant's own
/// `AllowThem`.
#[derive(Clone)]
pub struct TenantScope {
    pub user: User,
    pub tenant: Tenant,
    pub role: TenantRole,
    pub ath: AllowThem,
}

/// Any accepted member of the tenant passes. Used for read-only routes.
pub struct RequireTenantMember(pub TenantScope);

/// Owner or Admin passes; Viewer → 403. Used for most mutations.
pub struct RequireTenantAdmin(pub TenantScope);

/// Owner only; everyone else → 403. Used for irrevocable actions.
/// Consumed by 99c.4's user delete + 99c.5's owner-only settings.
#[allow(dead_code)]
pub struct RequireTenantOwner(pub TenantScope);

async fn resolve_scope(
    parts: &mut Parts,
    state: &DashboardRouterState,
) -> Result<TenantScope, Response> {
    // 1. Dashboard session → User.
    let user = match current_dashboard_user(&state.ath, &parts.headers).await {
        Ok(Some(u)) => u,
        Ok(None) => return Err(redirect_to_login(parts)),
        Err(e) => {
            tracing::error!(error = %e, "dashboard session lookup failed");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };

    // 2. Slug from path.
    let Path(TenantSlugPath { slug }) = Path::<TenantSlugPath>::from_request_parts(parts, &())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;

    // 3. Tenant lookup. `tenant_by_slug` returns the full row (db_path, name).
    let tenant = state
        .control_db
        .tenant_by_slug(&slug)
        .await
        .map_err(saas_error_500)?
        .ok_or_else(|| StatusCode::NOT_FOUND.into_response())?;

    match tenant.status {
        TenantStatus::Deleted => return Err(StatusCode::NOT_FOUND.into_response()),
        TenantStatus::Suspended => return Err(render_suspended(state, &tenant)),
        TenantStatus::Active => {}
    }

    // 4. Membership → role.
    let tenant_id = match tenant.id_as_uuid() {
        Some(uuid) => TenantId::from(uuid),
        None => {
            tracing::error!(slug = %slug, "tenant has undecodable UUID");
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
        }
    };
    let role_opt = state
        .control_db
        .member_role(&tenant_id, user.email.as_str())
        .await
        .map_err(saas_error_500)?;

    // 4a. Super-admin fall-through (99c.6 §3.2). When the dashboard user is
    //     not a `tenant_members` row but holds the `super_admin` role, we
    //     synthesize an `Owner` scope so they can drill into any tenant.
    //     Audit is **synchronous and fail-closed**: if the audit insert
    //     fails, deny access. This is the consent substitute — never
    //     best-effort.
    let role = match role_opt {
        Some(r) => r,
        None => {
            let role_name = allowthem_core::types::RoleName::new("super_admin");
            let is_super = state
                .ath
                .db()
                .has_role(&user.id, &role_name)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "has_role failed in resolve_scope");
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
            if !is_super {
                return Err(StatusCode::NOT_FOUND.into_response());
            }
            let ctx = serde_json::json!({
                "path": parts.uri.path(),
                "method": parts.method.as_str(),
            });
            state
                .control_db
                .log_control_audit(
                    user.email.as_str(),
                    "superadmin.tenant_accessed",
                    Some(&tenant_id),
                    &ctx,
                )
                .await
                .map_err(|e| {
                    tracing::error!(
                        error = %e,
                        slug = %slug,
                        "superadmin audit insert failed; denying cross-tenant access"
                    );
                    StatusCode::INTERNAL_SERVER_ERROR.into_response()
                })?;
            TenantRole::Owner
        }
    };

    // 5. Tenant AllowThem via the handle cache. Re-uses the same
    //    `build_handle_with_path` the tenant-router middleware uses, so
    //    one tenant's pool is opened at most once across all entry points.
    let cfg = state.tenant_config.clone();
    let dir = state.tenant_data_dir.clone();
    let db_file = tenant.db_path.clone();
    let slug_for_handle = slug.clone();
    let ath = state
        .handle_cache
        .get_or_init(tenant_id, async move {
            build_handle_with_path(&db_file, &dir, &cfg, &slug_for_handle).await
        })
        .await
        .map_err(|e: std::sync::Arc<SaasError>| {
            tracing::error!(error = %e, slug = %slug, "handle cache init failed");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        })?;

    Ok(TenantScope {
        user,
        tenant,
        role,
        ath,
    })
}

impl FromRequestParts<DashboardRouterState> for RequireTenantMember {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &DashboardRouterState,
    ) -> Result<Self, Self::Rejection> {
        let scope = resolve_scope(parts, state).await?;
        Ok(RequireTenantMember(scope))
    }
}

impl FromRequestParts<DashboardRouterState> for RequireTenantAdmin {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &DashboardRouterState,
    ) -> Result<Self, Self::Rejection> {
        let scope = resolve_scope(parts, state).await?;
        if !scope.role.is_admin_or_owner() {
            return Err(forbidden("Admin access required"));
        }
        Ok(RequireTenantAdmin(scope))
    }
}

impl FromRequestParts<DashboardRouterState> for RequireTenantOwner {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &DashboardRouterState,
    ) -> Result<Self, Self::Rejection> {
        let scope = resolve_scope(parts, state).await?;
        if !scope.role.is_owner() {
            return Err(forbidden("Owner access required"));
        }
        Ok(RequireTenantOwner(scope))
    }
}

// ---------------------------------------------------------------------------
// Failure-mode helpers
// ---------------------------------------------------------------------------

fn redirect_to_login(parts: &Parts) -> Response {
    let next = parts.uri.path();
    let location = format!("/login?next={next}");
    (
        StatusCode::SEE_OTHER,
        [(header::LOCATION, location.as_str())],
    )
        .into_response()
}

fn forbidden(msg: &'static str) -> Response {
    (StatusCode::FORBIDDEN, msg).into_response()
}

fn saas_error_500(e: SaasError) -> Response {
    tracing::error!(error = %e, "control-plane query failed during scope resolution");
    StatusCode::INTERNAL_SERVER_ERROR.into_response()
}

// ---------------------------------------------------------------------------
// RequireSuperAdmin (99c.6 §3.1)
// ---------------------------------------------------------------------------

/// The dashboard user verified to hold the `super_admin` role.
#[allow(dead_code)] // consumed by 99c.6 admin handlers (Steps 7-12 of the impl plan).
pub struct SuperAdminScope {
    pub user: User,
}

/// Newtype extractor: gates the super-admin pages and the cross-tenant
/// fall-through in `resolve_scope`. Rejects with 404 (not 403) when the
/// caller is authenticated but lacks the role — preserving the same
/// non-leak surface used elsewhere in the dashboard.
#[allow(dead_code)] // consumed by 99c.6 admin handlers (Steps 7-12).
pub struct RequireSuperAdmin(pub SuperAdminScope);

impl FromRequestParts<DashboardRouterState> for RequireSuperAdmin {
    type Rejection = Response;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &DashboardRouterState,
    ) -> Result<Self, Self::Rejection> {
        let user =
            match super::auth_helpers::current_dashboard_user(&state.ath, &parts.headers).await {
                Ok(Some(u)) => u,
                Ok(None) => return Err(redirect_to_login(parts)),
                Err(e) => {
                    tracing::error!(error = %e, "dashboard session lookup failed (super-admin)");
                    return Err(StatusCode::INTERNAL_SERVER_ERROR.into_response());
                }
            };

        let role_name = allowthem_core::types::RoleName::new("super_admin");
        let has = state
            .ath
            .db()
            .has_role(&user.id, &role_name)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "has_role failed");
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
            })?;
        if !has {
            // 404 (not 403) — don't leak that the surface exists.
            return Err(StatusCode::NOT_FOUND.into_response());
        }
        Ok(RequireSuperAdmin(SuperAdminScope { user }))
    }
}

fn render_suspended(state: &DashboardRouterState, tenant: &Tenant) -> Response {
    match state
        .templates
        .get_template("_partials/_suspended.html")
        .and_then(|tmpl| {
            tmpl.render(context! {
                tenant => context! {
                    name => tenant.name.clone(),
                    slug => tenant.slug.clone(),
                },
            })
        }) {
        Ok(body) => (StatusCode::SERVICE_UNAVAILABLE, axum::response::Html(body)).into_response(),
        Err(e) => {
            tracing::error!(error = %e, "suspended template render failed");
            (StatusCode::SERVICE_UNAVAILABLE, "Workspace suspended").into_response()
        }
    }
}
