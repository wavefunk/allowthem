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
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use minijinja::context;
use serde::Deserialize;
use uuid::Uuid;

use allowthem_saas::TenantId;
use allowthem_saas::api_keys::ApiKeyScope;
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use super::extractors::{HtmlForm, RequireTenantAdmin, RequireTenantMember, TenantScope};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;

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

fn render(
    state: &DashboardRouterState,
    template: &str,
    ctx: minijinja::value::Value,
) -> Result<Html<String>, BrowserError> {
    let tmpl = state
        .templates
        .get_template(template)
        .map_err(BrowserError::from)?;
    let body = tmpl.render(ctx).map_err(BrowserError::from)?;
    Ok(Html(body))
}

fn tenant_ctx(tenant: &allowthem_saas::Tenant) -> minijinja::value::Value {
    context! {
        id => tenant.id.clone(),
        name => tenant.name.clone(),
        slug => tenant.slug.clone(),
    }
}

fn role_str(role: allowthem_saas::TenantRole) -> &'static str {
    use allowthem_saas::TenantRole;
    match role {
        TenantRole::Owner => "owner",
        TenantRole::Admin => "admin",
        TenantRole::Viewer => "viewer",
    }
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

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn list(
    RequireTenantMember(scope): RequireTenantMember,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let api_keys = if let Some(tid) = tenant_id_from_scope(&scope) {
        state
            .control_db
            .list_api_keys_for_tenant(&tid)
            .await
            .unwrap_or_default()
    } else {
        vec![]
    };

    let key_views = api_keys
        .iter()
        .map(|k| {
            context! {
                id => k.id.to_string(),
                name => k.name.clone(),
                created_at => k.created_at.to_rfc3339(),
                expires_at => k.expires_at.map(|dt| dt.to_rfc3339()),
            }
        })
        .collect::<Vec<_>>();

    let path = format!("/t/{}/settings/api-keys", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        "settings/api_keys/list.html",
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(scope.role),
            csrf_token => csrf.as_str(),
            keys => key_views,
            new_key_secret => Option::<String>::None,
            error => "",
        },
    )
    .map(IntoResponse::into_response)
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
        let api_keys = state
            .control_db
            .list_api_keys_for_tenant(&tenant_id)
            .await
            .unwrap_or_default();
        let key_views = api_keys
            .iter()
            .map(|k| {
                context! {
                    id => k.id.to_string(),
                    name => k.name.clone(),
                    created_at => k.created_at.to_rfc3339(),
                    expires_at => k.expires_at.map(|dt| dt.to_rfc3339()),
                }
            })
            .collect::<Vec<_>>();

        let path = format!("/t/{}/settings/api-keys", scope.tenant.slug);
        let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
        return render(
            &state,
            "settings/api_keys/list.html",
            context! {
                tenant => tenant_ctx(&scope.tenant),
                nav_sections => nav,
                role => role_str(scope.role),
                csrf_token => csrf.as_str(),
                keys => key_views,
                new_key_secret => Option::<String>::None,
                error => "Key name must be 1–80 characters.",
            },
        )
        .map(IntoResponse::into_response);
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

    // Re-fetch list (does not include new raw key).
    let api_keys = state
        .control_db
        .list_api_keys_for_tenant(&tenant_id)
        .await
        .unwrap_or_default();
    let key_views = api_keys
        .iter()
        .map(|k| {
            context! {
                id => k.id.to_string(),
                name => k.name.clone(),
                created_at => k.created_at.to_rfc3339(),
                expires_at => k.expires_at.map(|dt| dt.to_rfc3339()),
            }
        })
        .collect::<Vec<_>>();

    let path = format!("/t/{}/settings/api-keys", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        "settings/api_keys/list.html",
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(scope.role),
            csrf_token => csrf.as_str(),
            keys => key_views,
            new_key_secret => Some(result.raw_key),
            error => "",
        },
    )
    .map(IntoResponse::into_response)
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
