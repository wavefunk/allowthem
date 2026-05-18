//! API key management — `/t/{slug}/settings/api-keys` (99c.5 Step 11).
//!
//! Routes:
//! - `GET  /t/{slug}/settings/api-keys`           list      — RequireTenantMember
//! - `POST /t/{slug}/settings/api-keys`           mint      — RequireTenantAdmin
//! - `POST /t/{slug}/settings/api-keys/{id}/revoke` revoke  — RequireTenantAdmin
//!
//! The raw key is rendered inline on the POST 200 response — same
//! single-render approach as the standalone admin's client_secret flow.

use axum::Router;
use axum::extract::{Path, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use serde::Deserialize;
use uuid::Uuid;

use allowthem_saas::api_keys::ApiKeyScope;
use allowthem_saas::{Tenant, TenantId, TenantRole};
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use super::extractors::{HtmlForm, RequireTenantAdmin, RequireTenantMember, TenantScope};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;
use super::views::{self, ApiKeySettingsPageView, ApiKeyView, WorkspaceView};

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn api_key_routes() -> Router<DashboardRouterState> {
    Router::new()
        .route("/t/{slug}/settings/api-keys", get(list).post(mint))
        .route("/t/{slug}/settings/api-keys/{id}/revoke", post(revoke))
}

// ---------------------------------------------------------------------------
// Forms
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct MintForm {
    #[serde(default)]
    pub name: String,
}

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

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

fn api_key_rows(keys: &[allowthem_saas::api_keys::ApiKey]) -> Vec<ApiKeyView> {
    keys.iter()
        .map(|key| ApiKeyView {
            id: key.id.to_string(),
            name: key.name.clone(),
            created_at: key.created_at.format("%Y-%m-%d %H:%M UTC").to_string(),
            expires_at: key
                .expires_at
                .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string()),
        })
        .collect()
}

async fn log_api_key_audit(
    state: &DashboardRouterState,
    scope: &TenantScope,
    action: &str,
    detail: &serde_json::Value,
) {
    let Some(uuid) = scope.tenant.id_as_uuid() else {
        tracing::error!(action = %action, "tenant has undecodable UUID; skipping audit");
        return;
    };
    let tenant_id = TenantId::from(uuid);
    if let Err(e) = state
        .control_db
        .log_control_audit(scope.user.email.as_str(), action, Some(&tenant_id), detail)
        .await
    {
        tracing::error!(action = %action, error = %e, "control audit log failed");
    }
}

async fn render_api_keys(
    state: &DashboardRouterState,
    scope: &TenantScope,
    csrf_token: &str,
    new_key_secret: Option<&str>,
    error: &str,
) -> Result<Response, BrowserError> {
    let keys = if let Some(tenant_id) = tenant_id_from_scope(scope) {
        state
            .control_db
            .list_api_keys_for_tenant(&tenant_id)
            .await
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let key_rows = api_key_rows(&keys);
    let workspace_pairs = workspace_pairs_for_user(state, scope).await;
    let workspaces = workspace_views(&workspace_pairs, &scope.tenant.slug);
    let path = format!("/t/{}/settings/api-keys", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    let html = views::api_key_settings_page(&ApiKeySettingsPageView {
        tenant_name: scope.tenant.name.as_str(),
        tenant_slug: scope.tenant.slug.as_str(),
        role: scope.role,
        nav_sections: &nav,
        workspaces: &workspaces,
        csrf_token,
        keys: &key_rows,
        new_key_secret,
        error,
        status_session: Some(scope.user.email.as_str()),
        is_production: state.is_production,
    })?;
    Ok(html.into_response())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn list(
    RequireTenantMember(scope): RequireTenantMember,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    render_api_keys(&state, &scope, csrf.as_str(), None, "").await
}

async fn mint(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
    HtmlForm(form): HtmlForm<MintForm>,
) -> Result<Response, BrowserError> {
    let name = form.name.trim().to_owned();

    let Some(tenant_id) = tenant_id_from_scope(&scope) else {
        return Ok(
            Redirect::to(&format!("/t/{}/settings/api-keys", scope.tenant.slug)).into_response(),
        );
    };

    if name.is_empty() || name.len() > 80 {
        return render_api_keys(
            &state,
            &scope,
            csrf.as_str(),
            None,
            "Key name must be 1-80 characters.",
        )
        .await;
    }

    let result = state
        .control_db
        .mint_api_key(&tenant_id, &name, vec![ApiKeyScope::Admin], None)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "mint_api_key failed");
            BrowserError::from(allowthem_core::error::AuthError::Database(
                sqlx::Error::RowNotFound,
            ))
        })?;

    log_api_key_audit(
        &state,
        &scope,
        "tenant.api_key_minted",
        &serde_json::json!({
            "key_id": result.api_key.id.to_string(),
            "name": name,
        }),
    )
    .await;

    render_api_keys(
        &state,
        &scope,
        csrf.as_str(),
        Some(result.raw_key.as_str()),
        "",
    )
    .await
}

async fn revoke(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    Path((_slug, raw_id)): Path<(String, String)>,
    State(state): State<DashboardRouterState>,
) -> Result<Response, BrowserError> {
    let Some(tenant_id) = tenant_id_from_scope(&scope) else {
        return Ok(
            Redirect::to(&format!("/t/{}/settings/api-keys", scope.tenant.slug)).into_response(),
        );
    };

    let Some(key_uuid) = raw_id.parse::<Uuid>().ok() else {
        return Ok(
            Redirect::to(&format!("/t/{}/settings/api-keys", scope.tenant.slug)).into_response(),
        );
    };
    let key_id = allowthem_saas::api_keys::ApiKeyId::from_uuid(key_uuid);

    if let Err(e) = state.control_db.revoke_api_key(&key_id, &tenant_id).await {
        tracing::error!(error = %e, "revoke_api_key failed");
    }

    log_api_key_audit(
        &state,
        &scope,
        "tenant.api_key_revoked",
        &serde_json::json!({"key_id": key_id.to_string()}),
    )
    .await;

    Ok(Redirect::to(&format!("/t/{}/settings/api-keys", scope.tenant.slug)).into_response())
}

fn tenant_id_from_scope(scope: &TenantScope) -> Option<TenantId> {
    scope.tenant.id_as_uuid().map(TenantId::from)
}
