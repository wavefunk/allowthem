//! Custom domain settings — `/t/{slug}/settings/domains` (38y.1 Task 4).
//!
//! Routes:
//! - `GET  /t/{slug}/settings/domains`              — RequireTenantMember
//! - `POST /t/{slug}/settings/domains`              — RequireTenantAdmin (register)
//! - `POST /t/{slug}/settings/domains/{id}/verify`  — RequireTenantAdmin
//! - `POST /t/{slug}/settings/domains/{id}/delete`  — RequireTenantAdmin

use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use uuid::Uuid;

use allowthem_saas::{
    DomainId, DomainStatus, SaasError, Tenant, TenantDomain, TenantId, TenantRole,
    normalize_domain, verify_domain,
};
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use super::extractors::{HtmlForm, RequireTenantAdmin, RequireTenantMember, TenantScope};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;
use super::views::{self, DomainEntryView, DomainSettingsPageView, WorkspaceView};

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

fn not_found() -> BrowserError {
    BrowserError::from(allowthem_core::error::AuthError::NotFound)
}

fn extract_tenant_id(tenant: &allowthem_saas::Tenant) -> Result<TenantId, BrowserError> {
    tenant
        .id_as_uuid()
        .map(TenantId::from)
        .ok_or_else(not_found)
}

fn parse_domain_id(s: &str) -> Result<DomainId, BrowserError> {
    s.parse::<Uuid>()
        .map(DomainId::from)
        .map_err(|_| not_found())
}

/// CNAME target the tenant must point their custom domain at.
fn dns_target(slug: &str, base_domain: &str) -> String {
    format!("{slug}.{base_domain}")
}

fn domain_entry_from_row(row: &TenantDomain) -> Option<DomainEntryView> {
    let uuid = Uuid::from_slice(&row.id).ok()?;
    Some(DomainEntryView {
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
    })
}

async fn load_entries(state: &DashboardRouterState, tenant_id: &TenantId) -> Vec<DomainEntryView> {
    state
        .control_db
        .list_tenant_domains(tenant_id)
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(domain_entry_from_row)
        .collect()
}

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

async fn render_domains(
    state: &DashboardRouterState,
    scope: &TenantScope,
    csrf_token: &str,
    error: &str,
) -> Result<Response, BrowserError> {
    let tenant_id = extract_tenant_id(&scope.tenant)?;
    let entries = load_entries(state, &tenant_id).await;
    let workspace_pairs = workspace_pairs_for_user(state, scope).await;
    let workspaces = workspace_views(&workspace_pairs, &scope.tenant.slug);
    let dns_tgt = dns_target(&scope.tenant.slug, &state.base_domain);
    let path = format!("/t/{}/settings/domains", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    let html = views::domain_settings_page(&DomainSettingsPageView {
        tenant_name: scope.tenant.name.as_str(),
        tenant_slug: scope.tenant.slug.as_str(),
        role: scope.role,
        nav_sections: &nav,
        workspaces: &workspaces,
        csrf_token,
        domains: &entries,
        dns_target: &dns_tgt,
        error,
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
    render_domains(&state, &scope, csrf.as_str(), "").await
}

pub async fn register(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
    HtmlForm(form): HtmlForm<RegisterDomainForm>,
) -> Result<Response, BrowserError> {
    let tenant_id = extract_tenant_id(&scope.tenant)?;

    let domain = match normalize_domain(form.domain.trim(), &state.base_domain) {
        Ok(d) => d,
        Err(e) => {
            let message = e.to_string();
            return render_domains(&state, &scope, csrf.as_str(), message.as_str()).await;
        }
    };
    let dns_tgt = dns_target(&scope.tenant.slug, &state.base_domain);

    match state
        .control_db
        .create_tenant_domain(&tenant_id, &domain, &dns_tgt)
        .await
    {
        Ok(_) => {}
        Err(SaasError::DomainAlreadyExists) => {
            return render_domains(
                &state,
                &scope,
                csrf.as_str(),
                "That domain is already registered.",
            )
            .await;
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
        .route("/t/{slug}/settings/domains", get(show).post(register))
        .route(
            "/t/{slug}/settings/domains/{id}/verify",
            post(trigger_verify),
        )
        .route("/t/{slug}/settings/domains/{id}/delete", post(delete))
}
