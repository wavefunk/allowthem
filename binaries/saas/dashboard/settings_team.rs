//! Team member management — `/t/{slug}/settings/team` (99c.5 Steps 13–16).
//!
//! Routes:
//! - `GET  /t/{slug}/settings/team`                      list         — RequireTenantMember
//! - `POST /t/{slug}/settings/team/invite`               invite       — RequireTenantAdmin
//! - `POST /t/{slug}/settings/team/{member_id}/role`     update_role  — RequireTenantOwner
//! - `POST /t/{slug}/settings/team/{member_id}/remove`   remove       — RequireTenantAdmin

use axum::Router;
use axum::extract::{Path, State};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use minijinja::context;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::str::FromStr;
use uuid::Uuid;

use allowthem_core::email::{EmailMessage, EmailTemplate};
use allowthem_core::sessions::generate_token;
use allowthem_saas::{MemberId, SaasError, TenantId, TenantRole};
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use super::extractors::{
    HtmlForm, RequireTenantAdmin, RequireTenantMember, RequireTenantOwner, TenantScope,
};
use super::nav::tenant_nav_items;
use super::state::DashboardRouterState;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn team_routes() -> Router<DashboardRouterState> {
    Router::new()
        .route("/t/{slug}/settings/team", get(list))
        .route("/t/{slug}/settings/team/invite", post(invite))
        .route(
            "/t/{slug}/settings/team/{member_id}/role",
            post(update_role),
        )
        .route("/t/{slug}/settings/team/{member_id}/remove", post(remove))
}

// ---------------------------------------------------------------------------
// Forms
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct InviteForm {
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub role: String,
}

#[derive(Debug, Deserialize)]
pub struct UpdateRoleForm {
    #[serde(default)]
    pub role: String,
}

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

fn render(
    state: &DashboardRouterState,
    ctx: minijinja::value::Value,
) -> Result<Html<String>, BrowserError> {
    let tmpl = state
        .templates
        .get_template("settings/team/list.html")
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

fn role_str(role: TenantRole) -> &'static str {
    match role {
        TenantRole::Owner => "owner",
        TenantRole::Admin => "admin",
        TenantRole::Viewer => "viewer",
    }
}

fn can_manage(scope: &TenantScope) -> bool {
    matches!(scope.role, TenantRole::Owner | TenantRole::Admin)
}

fn member_rows(members: &[allowthem_saas::TenantMember]) -> Vec<minijinja::value::Value> {
    members
        .iter()
        .map(|m| {
            let id_str = m
                .id_as_member_id()
                .map(|mid| mid.as_uuid().to_string())
                .unwrap_or_default();
            context! {
                id => id_str,
                email => m.email.clone(),
                role => m.role.as_str(),
                status => if m.accepted_at.is_some() { "accepted" } else { "invited" },
                invited_at => m.invited_at.format("%Y-%m-%d %H:%M UTC").to_string(),
                accepted_at => m.accepted_at.map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string()),
            }
        })
        .collect()
}

async fn fetch_members(
    state: &DashboardRouterState,
    scope: &TenantScope,
) -> Vec<allowthem_saas::TenantMember> {
    let Some(uuid) = scope.tenant.id_as_uuid() else {
        return vec![];
    };
    let tenant_id = TenantId::from(uuid);
    state
        .control_db
        .list_tenant_members(&tenant_id)
        .await
        .unwrap_or_default()
}

async fn log_team_audit(
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

/// Parse a member UUID string from a path segment, returning a redirect to the
/// team list if unparseable.
#[allow(clippy::result_large_err)]
fn parse_member_id(raw: &str, slug: &str) -> Result<MemberId, Response> {
    Uuid::parse_str(raw)
        .map(MemberId::from)
        .map_err(|_| Redirect::to(&format!("/t/{slug}/settings/team")).into_response())
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn list(
    RequireTenantMember(scope): RequireTenantMember,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let members = fetch_members(&state, &scope).await;
    let path = format!("/t/{}/settings/team", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        &state,
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(scope.role),
            csrf_token => csrf.as_str(),
            members => member_rows(&members),
            can_manage => can_manage(&scope),
            invite_error => "",
        },
    )
    .map(IntoResponse::into_response)
}

pub async fn invite(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    State(state): State<DashboardRouterState>,
    csrf: CsrfToken,
    HtmlForm(form): HtmlForm<InviteForm>,
) -> Result<Response, BrowserError> {
    let email = form.email.trim().to_owned();
    if email.is_empty() {
        return render_invite_error(&state, &scope, csrf.as_str(), "Email is required.").await;
    }

    let target_role = match TenantRole::from_str(&form.role) {
        Ok(r) => r,
        Err(_) => {
            return render_invite_error(&state, &scope, csrf.as_str(), "Invalid role.").await;
        }
    };

    // Admins cannot mint owner invites.
    if matches!(target_role, TenantRole::Owner) && !matches!(scope.role, TenantRole::Owner) {
        return render_invite_error(
            &state,
            &scope,
            csrf.as_str(),
            "Only owners can invite owners.",
        )
        .await;
    }

    let raw_token = generate_token();
    let token_hash = Sha256::digest(raw_token.as_str().as_bytes());
    let expires_at = (chrono::Utc::now() + chrono::Duration::days(7)).timestamp();

    let Some(uuid) = scope.tenant.id_as_uuid() else {
        return Err(BrowserError::from(
            allowthem_core::error::AuthError::NotFound,
        ));
    };
    let tenant_id = TenantId::from(uuid);

    match state
        .control_db
        .invite_member(
            &tenant_id,
            &email,
            target_role,
            token_hash.as_slice(),
            expires_at,
        )
        .await
    {
        Ok(_) => {}
        Err(SaasError::MemberAlreadyExists) => {
            return render_invite_error(
                &state,
                &scope,
                csrf.as_str(),
                "This person is already a member or has a pending invite.",
            )
            .await;
        }
        Err(e) => {
            tracing::error!(error = %e, "invite_member failed");
            return render_invite_error(&state, &scope, csrf.as_str(), "Invite failed. Try again.")
                .await;
        }
    }

    // Send invite email — fire-and-forget; failure logs but does not block.
    let invite_url = format!(
        "https://{}/invite/{}",
        state.base_domain,
        raw_token.as_str()
    );
    let msg = EmailMessage {
        to: email.clone(),
        subject: format!("You've been invited to {}", scope.tenant.name),
        template: EmailTemplate::Invitation {
            url: invite_url,
            invited_by: scope.tenant.name.clone(),
        },
    };
    if let Err(e) = state.email_sender.send(&msg).await {
        tracing::error!(error = %e, "failed to send invite email");
    }

    log_team_audit(
        &state,
        &scope,
        "tenant.member_invited",
        &serde_json::json!({"email": email, "role": target_role.as_str()}),
    )
    .await;

    Ok(Redirect::to(&format!("/t/{}/settings/team", scope.tenant.slug)).into_response())
}

pub async fn update_role(
    RequireTenantOwner(scope): RequireTenantOwner,
    State(state): State<DashboardRouterState>,
    Path((_slug, raw_member_id)): Path<(String, String)>,
    csrf: CsrfToken,
    HtmlForm(form): HtmlForm<UpdateRoleForm>,
) -> Result<Response, BrowserError> {
    let member_id = match parse_member_id(&raw_member_id, &scope.tenant.slug) {
        Ok(id) => id,
        Err(r) => return Ok(r),
    };

    let new_role = TenantRole::from_str(&form.role).map_err(|_| {
        BrowserError::from(allowthem_core::error::AuthError::Validation(
            "invalid role".into(),
        ))
    })?;

    match state
        .control_db
        .update_member_role(&member_id, new_role)
        .await
    {
        Ok(()) => {}
        Err(SaasError::CannotDemoteLastOwner) => {
            // Re-render list with a flash error.
            let members = fetch_members(&state, &scope).await;
            let path = format!("/t/{}/settings/team", scope.tenant.slug);
            let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
            return render(
                &state,
                context! {
                    tenant => tenant_ctx(&scope.tenant),
                    nav_sections => nav,
                    role => role_str(scope.role),
                    csrf_token => csrf.as_str(),
                    members => member_rows(&members),
                    can_manage => true,
                    invite_error => "Cannot demote the last owner of this workspace.",
                },
            )
            .map(IntoResponse::into_response);
        }
        Err(e) => {
            tracing::error!(error = %e, "update_member_role failed");
        }
    }

    log_team_audit(
        &state,
        &scope,
        "tenant.member_role_updated",
        &serde_json::json!({
            "member_id": member_id.as_uuid().to_string(),
            "new_role": new_role.as_str(),
        }),
    )
    .await;

    Ok(Redirect::to(&format!("/t/{}/settings/team", scope.tenant.slug)).into_response())
}

pub async fn remove(
    RequireTenantAdmin(scope): RequireTenantAdmin,
    State(state): State<DashboardRouterState>,
    Path((_slug, raw_member_id)): Path<(String, String)>,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let member_id = match parse_member_id(&raw_member_id, &scope.tenant.slug) {
        Ok(id) => id,
        Err(r) => return Ok(r),
    };

    // Look up target so we can enforce admin/owner asymmetry.
    let target = state
        .control_db
        .get_tenant_member(&member_id)
        .await
        .unwrap_or(None);

    if let Some(ref t) = target
        && matches!(t.role, TenantRole::Owner)
        && !matches!(scope.role, TenantRole::Owner)
    {
        return Err(BrowserError::Auth(allowthem_core::AuthError::Forbidden(
            "Admins cannot remove owners. Ask an owner to do it.".into(),
        )));
    }

    let email_for_audit = target.as_ref().map(|t| t.email.clone()).unwrap_or_default();

    match state.control_db.remove_member(&member_id).await {
        Ok(()) => {}
        Err(SaasError::CannotRemoveLastOwner) => {
            let members = fetch_members(&state, &scope).await;
            let path = format!("/t/{}/settings/team", scope.tenant.slug);
            let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
            return render(
                &state,
                context! {
                    tenant => tenant_ctx(&scope.tenant),
                    nav_sections => nav,
                    role => role_str(scope.role),
                    csrf_token => csrf.as_str(),
                    members => member_rows(&members),
                    can_manage => true,
                    invite_error => "Cannot remove the last owner of this workspace.",
                },
            )
            .map(IntoResponse::into_response);
        }
        Err(SaasError::MemberNotFound) => {
            tracing::warn!(member_id = %raw_member_id, "remove_member: member not found");
        }
        Err(e) => {
            tracing::error!(error = %e, "remove_member failed");
        }
    }

    log_team_audit(
        &state,
        &scope,
        "tenant.member_removed",
        &serde_json::json!({
            "member_id": member_id.as_uuid().to_string(),
            "email": email_for_audit,
        }),
    )
    .await;

    Ok(Redirect::to(&format!("/t/{}/settings/team", scope.tenant.slug)).into_response())
}

// ---------------------------------------------------------------------------
// Internal render helpers
// ---------------------------------------------------------------------------

async fn render_invite_error(
    state: &DashboardRouterState,
    scope: &TenantScope,
    csrf_str: &str,
    error: &str,
) -> Result<Response, BrowserError> {
    let members = fetch_members(state, scope).await;
    let path = format!("/t/{}/settings/team", scope.tenant.slug);
    let nav = tenant_nav_items(&scope.tenant.slug, &path, scope.role);
    render(
        state,
        context! {
            tenant => tenant_ctx(&scope.tenant),
            nav_sections => nav,
            role => role_str(scope.role),
            csrf_token => csrf_str,
            members => member_rows(&members),
            can_manage => true,
            invite_error => error,
        },
    )
    .map(IntoResponse::into_response)
}
