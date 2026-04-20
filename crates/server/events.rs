//! Route-handler publish helper for lifecycle events.
//!
//! See `docs/superpowers/specs/2026-04-20-lifecycle-events-design.md`.

use axum::http::HeaderMap;

use allowthem_core::events::{AuthEvent, AuthEventSender};

/// Send an event into `tx` if configured. Silently ignores `SendError`
/// (a dropped receiver is the integrator's problem; see §6 of the spec).
///
/// Takes a builder closure so the call site can skip event construction
/// entirely when no sender is configured.
pub(crate) fn publish(tx: Option<&AuthEventSender>, build: impl FnOnce() -> AuthEvent) {
    if let Some(tx) = tx {
        let _ = tx.send(build());
    }
}

/// Extract the best-effort client IP from request headers.
///
/// Reads the first entry in `X-Forwarded-For`. Returns `None` when the header
/// is absent or malformed. Both the register and OAuth handlers use this.
pub(crate) fn client_ip(headers: &HeaderMap) -> Option<String> {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
}
