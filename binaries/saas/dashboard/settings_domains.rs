//! Custom domain settings — `/t/{slug}/settings/domains` (38y.1 Task 4).
//!
//! Routes:
//! - `GET  /t/{slug}/settings/domains`              — RequireTenantMember
//! - `POST /t/{slug}/settings/domains`              — RequireTenantAdmin (register)
//! - `POST /t/{slug}/settings/domains/{id}/verify`  — RequireTenantAdmin
//! - `POST /t/{slug}/settings/domains/{id}/delete`  — RequireTenantAdmin

use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use minijinja::context;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use allowthem_saas::{
    DomainId, DomainStatus, TenantDomain, TenantId, SaasError, normalize_domain, verify_domain,
};
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use super::extractors::{HtmlForm, RequireTenantAdmin, RequireTenantMember, current_tenant_ctx, workspaces_for_user};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;

// ---------------------------------------------------------------------------
// Template view model
// ---------------------------------------------------------------------------

/// Flattened domain row ready for template rendering — UUIDs as strings,
/// timestamps formatted, status as a human-readable label.
#[derive(Serialize)]
struct DomainEntry {
    id: String,
    domain: String,
    status: DomainStatus,
    status_label: &'static str,
    verified_at: Option<String>,
    last_error: Option<String>,
    created_at: String,
}

impl DomainEntry {
    fn from_row(row: &TenantDomain) -> Option<Self> {
        let uuid = Uuid::from_slice(&row.id).ok()?;
        Some(Self {
            id: uuid.to_string(),
            domain: row.domain.clone(),
            status: row.status,
            status_label: match row.status {
                DomainStatus::PendingVerification => "Pending",
                DomainStatus::Verified => "Verified",
                DomainStatus::Active => "Active",
                DomainStatus::Failed => "Failed",
            },
            verified_at: row.verified_at.map(|t| t.to_rfc3339()),
            last_error: row.last_error.clone(),
            created_at: row.created_at.to_rfc3339(),
        })
    }
}

// ---------------------------------------------------------------------------
// Forms
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct RegisterDomainForm {
    pub domain: String,
}

#[derive(Debug, Deserialize)]
pub struct EmptyForm {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn render(
    state: &DashboardRouterState,
    session: &str,
    ctx: minijinja::value::Value,
) -> Result<Html<String>, BrowserError> {
    let tmpl = state
        .templates
        .get_template("settings/domains.html")
        .map_err(BrowserError::from)?;
    let body = tmpl
        .render(context! { status_session => session, ..ctx })
        .map_err(BrowserError::from)?;
    Ok(Html(body))
}

fn not_found() -> BrowserError {
    BrowserError::from(allowthem_core::error::AuthError::NotFound)
}

fn extract_tenant_id(
    tenant: &allowthem_saas::Tenant,
) -> Result<TenantId, BrowserError> {
    tenant.id_as_uuid().map(TenantId::from).ok_or_else(not_found)
}

fn parse_domain_id(s: &str) -> Result<DomainId, BrowserError> {
    s.parse::<Uuid>().map(DomainId::from).map_err(|_| not_found())
}

/// CNAME target the tenant must point their custom domain at.
fn dns_target(slug: &str, base_domain: &str) -> String {
    format!("{slug}.{base_domain}")
}

async fn load_entries(
    state: &DashboardRouterState,
    tenant_id: &TenantId,
) -> Vec<DomainEntry> {
    state
        .control_db
        .list_tenant_domains(tenant_id)
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(DomainEntry::from_row)
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn page_ctx(
    slug: &str,
    name: &str,
    role: allowthem_saas::TenantRole,
    entries: Vec<DomainEntry>,
    dns_tgt: &str,
    csrf_token: &str,
    error: &str,
    current_tenant: minijinja::value::Value,
    workspaces: Vec<minijinja::value::Value>,
) -> minijinja::value::Value {
    let path = format!("/t/{slug}/settings/domains");
    let nav = tenant_nav_items(slug, &path, role);
    context! {
        tenant => context! { name => name, slug => slug },
        nav_sections => nav,
        current_tenant,
        workspaces,
        csrf_token => csrf_token,
        domains => entries,
        dns_target => dns_tgt,
        error => error,
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
    let tenant_id = extract_tenant_id(&scope.tenant)?;
    let entries = load_entries(&state, &tenant_id).await;
    let workspaces = workspaces_for_user(&state, &scope).await;
    let dns_tgt = dns_target(&scope.tenant.slug, &state.base_domain);
    render(
        &state,
        scope.user.email.as_str(),
        page_ctx(
            &scope.tenant.slug,
            &scope.tenant.name,
            scope.role,
            entries,
            &dns_tgt,
            csrf.as_str(),
            "",
            current_tenant_ctx(&scope.tenant),
            workspaces,
        ),
    )
    .map(IntoResponse::into_response)
}

pub async fn register(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
    HtmlForm(form): HtmlForm<RegisterDomainForm>,
) -> Result<Response, BrowserError> {
    let tenant_id = extract_tenant_id(&scope.tenant)?;
    let dns_tgt = dns_target(&scope.tenant.slug, &state.base_domain);

    let domain = match normalize_domain(form.domain.trim(), &state.base_domain) {
        Ok(d) => d,
        Err(e) => {
            let entries = load_entries(&state, &tenant_id).await;
            let workspaces = workspaces_for_user(&state, &scope).await;
            return render(
                &state,
                scope.user.email.as_str(),
                page_ctx(
                    &scope.tenant.slug,
                    &scope.tenant.name,
                    scope.role,
                    entries,
                    &dns_tgt,
                    csrf.as_str(),
                    &e.to_string(),
                    current_tenant_ctx(&scope.tenant),
                    workspaces,
                ),
            )
            .map(IntoResponse::into_response);
        }
    };

    match state
        .control_db
        .create_tenant_domain(&tenant_id, &domain, &dns_tgt)
        .await
    {
        Ok(_) => {}
        Err(SaasError::DomainAlreadyExists) => {
            let entries = load_entries(&state, &tenant_id).await;
            let workspaces = workspaces_for_user(&state, &scope).await;
            return render(
                &state,
                scope.user.email.as_str(),
                page_ctx(
                    &scope.tenant.slug,
                    &scope.tenant.name,
                    scope.role,
                    entries,
                    &dns_tgt,
                    csrf.as_str(),
                    "That domain is already registered.",
                    current_tenant_ctx(&scope.tenant),
                    workspaces,
                ),
            )
            .map(IntoResponse::into_response);
        }
        Err(e) => {
            tracing::error!(error = %e, "create_tenant_domain failed");
            return Err(not_found());
        }
    }

    Ok(Redirect::to(&format!("/t/{}/settings/domains", scope.tenant.slug)).into_response())
}

pub async fn trigger_verify(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    State(state): State<DashboardRouterState>,
    Path((_, id)): Path<(String, String)>,
    HtmlForm(_): HtmlForm<EmptyForm>,
) -> Result<Response, BrowserError> {
    let tenant_id = extract_tenant_id(&scope.tenant)?;
    let domain_id = parse_domain_id(&id)?;

    let row = state
        .control_db
        .get_tenant_domain_scoped(&domain_id, &tenant_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "get_tenant_domain_scoped failed");
            not_found()
        })?
        .ok_or_else(not_found)?;

    if let Err(e) = verify_domain(
        state.dns_resolver.as_ref(),
        &state.control_db,
        domain_id,
        tenant_id,
        &row.domain,
        &row.dns_target,
    )
    .await
    {
        tracing::warn!(domain = %row.domain, error = %e, "verify_domain DB error during dashboard trigger");
    }

    Ok(Redirect::to(&format!("/t/{}/settings/domains", scope.tenant.slug)).into_response())
}

pub async fn delete(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    State(state): State<DashboardRouterState>,
    Path((_, id)): Path<(String, String)>,
    HtmlForm(_): HtmlForm<EmptyForm>,
) -> Result<Response, BrowserError> {
    let tenant_id = extract_tenant_id(&scope.tenant)?;
    let domain_id = parse_domain_id(&id)?;

    if let Err(e) = state
        .control_db
        .delete_tenant_domain_scoped(&domain_id, &tenant_id)
        .await
    {
        tracing::error!(error = %e, "delete_tenant_domain_scoped failed");
        return Err(not_found());
    }

    Ok(Redirect::to(&format!("/t/{}/settings/domains", scope.tenant.slug)).into_response())
}

pub fn domain_routes() -> axum::Router<DashboardRouterState> {
    use axum::routing::{get, post};
    axum::Router::new()
        .route(
            "/t/{slug}/settings/domains",
            get(show).post(register),
        )
        .route("/t/{slug}/settings/domains/{id}/verify", post(trigger_verify))
        .route("/t/{slug}/settings/domains/{id}/delete", post(delete))
}
