//! Tenant-scoped user-management handlers (99c.4).
//!
//! Routes (all under `/t/{slug}/users`):
//! - `GET  /`                                              list (any member)
//! - `GET  /{user_id}`                                     detail (any member)
//! - `POST /{user_id}/block`                               admin
//! - `POST /{user_id}/unblock`                             admin
//! - `POST /{user_id}/force-password-reset`                admin
//! - `POST /{user_id}/revoke-sessions`                     admin
//! - `POST /{user_id}/delete`                              owner (double-confirm)
//! - `POST /{user_id}/roles`                               admin
//! - `POST /{user_id}/roles/{role_id}/remove`              admin
//! - `POST /{user_id}/permissions`                         admin
//! - `POST /{user_id}/permissions/{permission_id}/remove`  admin
//!
//! Read handlers take `RequireTenantMember`. Write handlers take
//! `RequireTenantAdmin`, except `delete` which takes `RequireTenantOwner`.
//!
//! Each successful action writes one audit row via `log_admin_action` to
//! `allowthem_audit_log` with the actor's email in the detail string.

use axum::Router;
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};

use allowthem_core::audit::AuditEvent;
use allowthem_core::types::UserId;

use super::extractors::TenantScope;
use super::state::DashboardRouterState;

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// All `/t/{slug}/users…` routes for the dashboard. Step 11 mounts this
/// inside `dashboard_pages_router` so the CSRF middleware covers POSTs.
#[allow(dead_code)] // Step 11 wires this into dashboard_pages_router.
pub fn user_routes() -> Router<DashboardRouterState> {
    Router::new()
        .route("/t/{slug}/users", get(list))
        .route("/t/{slug}/users/{user_id}", get(detail))
        .route("/t/{slug}/users/{user_id}/block", post(block))
        .route("/t/{slug}/users/{user_id}/unblock", post(unblock))
        .route(
            "/t/{slug}/users/{user_id}/force-password-reset",
            post(force_password_reset),
        )
        .route(
            "/t/{slug}/users/{user_id}/revoke-sessions",
            post(revoke_sessions),
        )
        .route("/t/{slug}/users/{user_id}/delete", post(delete_user))
        .route("/t/{slug}/users/{user_id}/roles", post(assign_role))
        .route(
            "/t/{slug}/users/{user_id}/roles/{role_id}/remove",
            post(unassign_role),
        )
        .route(
            "/t/{slug}/users/{user_id}/permissions",
            post(grant_permission),
        )
        .route(
            "/t/{slug}/users/{user_id}/permissions/{permission_id}/remove",
            post(revoke_permission),
        )
}

// Pagination cap for the list page; mirrors `applications::list`'s constant.
#[allow(dead_code)] // Step 3 wires this into the list handler.
const PAGE_SIZE: u32 = 25;

// Audit-log fetch cap on the detail page.
#[allow(dead_code)] // Step 4 wires this into the detail handler.
const RECENT_AUDIT_LIMIT: u32 = 10;

// ---------------------------------------------------------------------------
// Stubs — bodies land in Steps 3..10. The router isn't mounted in
// `dashboard_pages_router` until Step 11, so these `unimplemented!()`
// markers are unreachable from HTTP traffic until the wiring step lands.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
async fn list() -> axum::response::Response {
    unimplemented!("users::list lands in 99c.4 Step 3")
}

#[allow(dead_code)]
async fn detail() -> axum::response::Response {
    unimplemented!("users::detail lands in 99c.4 Step 4")
}

#[allow(dead_code)]
async fn block() -> Redirect {
    unimplemented!("users::block lands in 99c.4 Step 5")
}

#[allow(dead_code)]
async fn unblock() -> Redirect {
    unimplemented!("users::unblock lands in 99c.4 Step 5")
}

#[allow(dead_code)]
async fn force_password_reset() -> axum::response::Response {
    unimplemented!("users::force_password_reset lands in 99c.4 Step 6")
}

#[allow(dead_code)]
async fn revoke_sessions() -> axum::response::Response {
    unimplemented!("users::revoke_sessions lands in 99c.4 Step 7")
}

#[allow(dead_code)]
async fn delete_user() -> Redirect {
    unimplemented!("users::delete_user lands in 99c.4 Step 8")
}

#[allow(dead_code)]
async fn assign_role() -> Redirect {
    unimplemented!("users::assign_role lands in 99c.4 Step 9")
}

#[allow(dead_code)]
async fn unassign_role() -> Redirect {
    unimplemented!("users::unassign_role lands in 99c.4 Step 9")
}

#[allow(dead_code)]
async fn grant_permission() -> Redirect {
    unimplemented!("users::grant_permission lands in 99c.4 Step 10")
}

#[allow(dead_code)]
async fn revoke_permission() -> Redirect {
    unimplemented!("users::revoke_permission lands in 99c.4 Step 10")
}

// ---------------------------------------------------------------------------
// Helpers — landed in this scaffold so Steps 3..10 use them without churn.
// ---------------------------------------------------------------------------

/// Render a redirect response with optional `info` / `error` flash params.
/// The detail handler (Step 4) reads `Query<DetailQuery>` and threads these
/// into the template render context where `_partials/_flash.html` renders
/// them. Query-string-based to avoid adding a session-flash dependency.
/// Flash strings are server-authored, so a minimal `qs_encode` covers the
/// chars that would corrupt query parsing — full RFC 3986 encoding would
/// just add a workspace dep we don't carry today.
#[allow(dead_code)] // Steps 6, 7, 8 use this for flash redirects.
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

/// Minimal query-string encoder. Replaces `&`, `=`, `#`, `?`, `+`, `%`,
/// space; non-ASCII bytes get percent-encoded byte-by-byte. Sufficient for
/// the server-authored flash strings used here.
#[allow(dead_code)]
fn qs_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b' ' => out.push('+'),
            b'&' | b'=' | b'#' | b'?' | b'+' | b'%' => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
            0x21..=0x7E => out.push(b as char),
            _ => {
                out.push('%');
                out.push_str(&format!("{b:02X}"));
            }
        }
    }
    out
}

/// Parse a path-bound user id, redirecting to the tenant's user list on
/// malformed input (matches `binaries/standalone/admin_users.rs` shape).
/// `Box`es the `Response` to keep the `Result` size small (clippy lint).
#[allow(dead_code)] // Steps 5..10 use this for path-id parsing.
fn parse_user_id(
    raw: &str,
    slug: &str,
) -> Result<UserId, Box<axum::response::Response>> {
    raw.parse::<UserId>()
        .map_err(|_| Box::new(Redirect::to(&format!("/t/{slug}/users")).into_response()))
}

/// Write one audit-log row tagging the actor. The detail string carries
/// the actor's email so the row is queryable / human-readable even after
/// the target user is deleted (`allowthem_audit_log.user_id` has no FK).
#[allow(dead_code)] // Steps 5..10 invoke this on every successful action.
async fn log_admin_action(
    scope: &TenantScope,
    event: AuditEvent,
    target_user_id: UserId,
    note: &str,
) {
    let detail = format!("{note} (actor: {})", scope.user.email.as_str());
    let event_for_log = event.clone();
    if let Err(e) = scope
        .ath
        .db()
        .log_audit(event, Some(&target_user_id), None, None, None, Some(&detail))
        .await
    {
        tracing::error!(error = %e, event = ?event_for_log, %target_user_id, "audit log write failed");
    }
}
