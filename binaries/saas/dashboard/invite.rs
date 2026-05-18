//! Invite-accept flow — `/invite/{token}` (99c.5 Step 15).
//!
//! Routes (outside `/t/{slug}` — anonymous-allowed):
//! - `GET  /invite/{token}` — show accept / register / expired page
//! - `POST /invite/{token}` — submit accept (new-account or existing-account)

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::http::header::{LOCATION, SET_COOKIE};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use allowthem_core::Email;
use allowthem_saas::dashboard::{
    DashboardSignupError, RegisterForInviteResult, dashboard_register_for_invite,
};
use allowthem_saas::{DashboardState, SaasError};
use allowthem_server::browser_error::BrowserError;
use allowthem_server::csrf::CsrfToken;

use super::auth_helpers::current_dashboard_user;
use super::state::DashboardRouterState;
use super::views::{
    self, InviteAcceptPageView, InviteRegisterPageView, InviteTenantView, InviteWrongUserPageView,
};

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn invite_routes() -> Router<DashboardRouterState> {
    Router::new().route("/invite/{token}", get(show).post(accept))
}

// ---------------------------------------------------------------------------
// Forms
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
pub struct InviteAcceptForm {
    #[serde(default)]
    pub password: String,
}

// ---------------------------------------------------------------------------
// Local helpers
// ---------------------------------------------------------------------------

fn tenant_view(tenant: &allowthem_saas::Tenant) -> InviteTenantView<'_> {
    InviteTenantView {
        name: tenant.name.as_str(),
        slug: tenant.slug.as_str(),
    }
}

/// Project `DashboardRouterState` to the lighter `DashboardState` that
/// `dashboard_register_for_invite` requires.
fn to_dashboard_state(state: &DashboardRouterState) -> DashboardState {
    DashboardState {
        ath: state.ath.clone(),
        control_db: state.control_db.clone(),
        tenant_data_dir: state.tenant_data_dir.clone(),
        tenant_config: state.tenant_config.clone(),
        handle_cache: state.handle_cache.clone(),
        is_production: state.is_production,
    }
}

fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

pub async fn show(
    State(state): State<DashboardRouterState>,
    Path(token): Path<String>,
    headers: axum::http::HeaderMap,
    csrf: CsrfToken,
) -> Result<Response, BrowserError> {
    let hash = hash_token(&token);

    let member = match state.control_db.find_pending_invite_by_hash(&hash).await {
        Ok(Some(m)) => m,
        _ => {
            return views::invite_expired_page(state.is_production)
                .map(IntoResponse::into_response);
        }
    };

    let tenant_id = match member.tenant_id_as_tenant_id() {
        Some(tid) => tid,
        None => {
            return views::invite_expired_page(state.is_production)
                .map(IntoResponse::into_response);
        }
    };

    let tenant = match state.control_db.tenant_by_id(&tenant_id).await {
        Ok(Some(t)) => t,
        _ => {
            return Err(BrowserError::from(
                allowthem_core::error::AuthError::NotFound,
            ));
        }
    };

    // Check if current user is logged in.
    let session_user = current_dashboard_user(&state.ath, &headers)
        .await
        .unwrap_or(None);

    if let Some(user) = session_user {
        if user.email.as_str() == member.email.as_str() {
            // Matched: show a confirm form.
            return views::invite_accept_page(&InviteAcceptPageView {
                tenant: tenant_view(&tenant),
                email: member.email.as_str(),
                role: member.role.as_str(),
                token: token.as_str(),
                csrf_token: csrf.as_str(),
                is_production: state.is_production,
            })
            .map(IntoResponse::into_response);
        } else {
            // Logged in as someone else.
            return Ok((
                StatusCode::FORBIDDEN,
                views::invite_wrong_user_page(&InviteWrongUserPageView {
                    signed_in_email: user.email.as_str(),
                    invite_email: member.email.as_str(),
                    token: token.as_str(),
                    is_production: state.is_production,
                })?,
            )
                .into_response());
        }
    }

    // Not logged in. Check if the email already has a dashboard account.
    let email_exists = match Email::new(member.email.clone()) {
        Ok(e) => state.ath.db().get_user_by_email(&e).await.is_ok(),
        Err(_) => false,
    };

    if email_exists {
        // Existing user: redirect to login with `next`.
        let next = format!("/invite/{token}");
        return Ok((
            StatusCode::SEE_OTHER,
            [(LOCATION, format!("/login?next={next}"))],
        )
            .into_response());
    }

    // Brand-new user: render the registration form.
    views::invite_register_page(&InviteRegisterPageView {
        tenant: tenant_view(&tenant),
        email: member.email.as_str(),
        role: member.role.as_str(),
        token: token.as_str(),
        error: None,
        csrf_token: csrf.as_str(),
        is_production: state.is_production,
    })
    .map(IntoResponse::into_response)
}

pub async fn accept(
    State(state): State<DashboardRouterState>,
    Path(token): Path<String>,
    headers: axum::http::HeaderMap,
    csrf: CsrfToken,
    axum::Form(form): axum::Form<InviteAcceptForm>,
) -> Result<Response, BrowserError> {
    let hash = hash_token(&token);

    if !form.password.is_empty() {
        // ── New-account branch ──────────────────────────────────────────────
        let pending = match state.control_db.find_pending_invite_by_hash(&hash).await {
            Ok(Some(m)) => m,
            _ => {
                return views::invite_expired_page(state.is_production)
                    .map(IntoResponse::into_response);
            }
        };

        let tenant_id = match pending.tenant_id_as_tenant_id() {
            Some(tid) => tid,
            None => {
                return views::invite_expired_page(state.is_production)
                    .map(IntoResponse::into_response);
            }
        };
        let tenant = match state.control_db.tenant_by_id(&tenant_id).await {
            Ok(Some(t)) => t,
            _ => {
                return Err(BrowserError::from(
                    allowthem_core::error::AuthError::NotFound,
                ));
            }
        };

        let ds = to_dashboard_state(&state);
        let registered: RegisterForInviteResult =
            match dashboard_register_for_invite(&ds, pending.email.clone(), form.password.clone())
                .await
            {
                Ok(r) => r,
                Err(DashboardSignupError::EmailTaken) => {
                    // Email already exists — redirect to login.
                    let next = format!("/invite/{token}");
                    return Ok((
                        StatusCode::SEE_OTHER,
                        [(LOCATION, format!("/login?next={next}"))],
                    )
                        .into_response());
                }
                Err(DashboardSignupError::InvalidEmail) => {
                    return views::invite_register_page(&InviteRegisterPageView {
                        tenant: tenant_view(&tenant),
                        email: pending.email.as_str(),
                        role: pending.role.as_str(),
                        token: token.as_str(),
                        error: Some("Invalid email address."),
                        csrf_token: csrf.as_str(),
                        is_production: state.is_production,
                    })
                    .map(IntoResponse::into_response);
                }
                Err(e) => {
                    tracing::error!(error = %e, "dashboard_register_for_invite failed");
                    return views::invite_register_page(&InviteRegisterPageView {
                        tenant: tenant_view(&tenant),
                        email: pending.email.as_str(),
                        role: pending.role.as_str(),
                        token: token.as_str(),
                        error: Some("Account creation failed. Please try again."),
                        csrf_token: csrf.as_str(),
                        is_production: state.is_production,
                    })
                    .map(IntoResponse::into_response);
                }
            };

        // Accept the invite. On failure, roll back the user creation.
        match state.control_db.accept_invite(&hash).await {
            Ok(_) => {}
            Err(e) => {
                tracing::error!(error = %e, "accept_invite failed after user creation; rolling back");
                if let Err(del_err) = state.ath.delete_user(registered.user.id).await {
                    tracing::error!(
                        user_id = %registered.user.id,
                        error = %del_err,
                        "rollback delete_user failed; orphan dashboard user"
                    );
                }
                return views::invite_expired_page(state.is_production)
                    .map(IntoResponse::into_response);
            }
        }

        let location = format!("/t/{}", tenant.slug);
        return Ok((
            StatusCode::SEE_OTHER,
            [(SET_COOKIE, registered.set_cookie), (LOCATION, location)],
        )
            .into_response());
    }

    // ── Existing-account branch ─────────────────────────────────────────────
    let session_user = current_dashboard_user(&state.ath, &headers)
        .await
        .unwrap_or(None)
        .ok_or_else(|| {
            // Not logged in — redirect to login.
            BrowserError::from(allowthem_core::error::AuthError::NotFound)
        })?;

    let pending = match state.control_db.find_pending_invite_by_hash(&hash).await {
        Ok(Some(m)) => m,
        _ => {
            return views::invite_expired_page(state.is_production)
                .map(IntoResponse::into_response);
        }
    };

    if session_user.email.as_str() != pending.email.as_str() {
        return Ok((
            StatusCode::FORBIDDEN,
            views::invite_wrong_user_page(&InviteWrongUserPageView {
                signed_in_email: session_user.email.as_str(),
                invite_email: pending.email.as_str(),
                token: token.as_str(),
                is_production: state.is_production,
            })?,
        )
            .into_response());
    }

    let tenant_id = match pending.tenant_id_as_tenant_id() {
        Some(tid) => tid,
        None => {
            return views::invite_expired_page(state.is_production)
                .map(IntoResponse::into_response);
        }
    };
    let tenant = match state.control_db.tenant_by_id(&tenant_id).await {
        Ok(Some(t)) => t,
        _ => {
            return Err(BrowserError::from(
                allowthem_core::error::AuthError::NotFound,
            ));
        }
    };

    match state.control_db.accept_invite(&hash).await {
        Ok(_) | Err(SaasError::InviteNotFoundOrExpired) => {}
        Err(e) => {
            tracing::error!(error = %e, "accept_invite failed");
        }
    }

    Ok((
        StatusCode::SEE_OTHER,
        [(LOCATION, format!("/t/{}", tenant.slug))],
    )
        .into_response())
}
