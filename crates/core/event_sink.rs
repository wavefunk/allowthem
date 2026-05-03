use std::future::Future;
use std::pin::Pin;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value;

use crate::types::UserId;

/// A single auth event emitted by an `AllowThem` operation.
///
/// Events are stringly-typed (`event_type`) with a JSON `data` bag so that
/// new event types can be added in future tasks without a breaking API change.
/// Webhook delivery (epic 7xw.2) will serialise this struct to JSON.
///
/// Data shapes are per-`event_type` and may evolve between minor versions.
#[derive(Debug, Clone, Serialize)]
pub struct AuthEvent {
    pub event_type: String,
    pub user_id: Option<UserId>,
    pub timestamp: DateTime<Utc>,
    pub data: Value,
}

impl AuthEvent {
    /// Construct an `AuthEvent`, stamping `timestamp` with `Utc::now()`.
    pub fn new(event_type: impl Into<String>, user_id: Option<UserId>, data: Value) -> Self {
        Self {
            event_type: event_type.into(),
            user_id,
            timestamp: Utc::now(),
            data,
        }
    }
}

/// Abstraction over event delivery.
///
/// Implementors receive every state-changing auth operation as an `AuthEvent`.
/// The library provides [`NoopEventSink`] (silent default) and
/// [`LoggingEventSink`] (dev logging). The SaaS binary will register a sink
/// that writes rows to `webhook_deliveries` for outbound HTTP delivery
/// (epic 7xw.2).
///
/// ## Contract
///
/// - Returns `()` — no error type to ignore. Swallow internal errors via
///   `tracing::warn!` rather than propagating.
/// - **Must not panic.** A panic propagates to the caller and aborts the
///   in-progress request.
/// - **Must be fast.** No outbound HTTP. The SaaS sink writes one row;
///   delivery happens out-of-band.
pub trait EventSink: Send + Sync {
    fn emit<'a>(&'a self, event: &'a AuthEvent) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// Silent default event sink.
///
/// Ignores all events. The expected default for embedded integrators that
/// do not need webhook delivery.
pub struct NoopEventSink;

impl EventSink for NoopEventSink {
    fn emit<'a>(&'a self, _event: &'a AuthEvent) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(std::future::ready(()))
    }
}

/// Development event sink that logs events at `debug` level.
///
/// Writes `event_type`, `user_id`, and `data` to the tracing log. Does not
/// perform any I/O. Suitable for the SaaS binary's dev startup.
pub struct LoggingEventSink;

impl EventSink for LoggingEventSink {
    fn emit<'a>(&'a self, event: &'a AuthEvent) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        tracing::debug!(
            event_type = %event.event_type,
            user_id = ?event.user_id,
            data = %event.data,
            "auth event",
        );
        Box::pin(std::future::ready(()))
    }
}

/// Allow any `Arc<T>` where `T: EventSink` to be used as an `EventSink`.
impl<T: EventSink + ?Sized> EventSink for std::sync::Arc<T> {
    fn emit<'a>(&'a self, event: &'a AuthEvent) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        (**self).emit(event)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Compile-time proof that EventSink is dyn-compatible.
    fn _assert_object_safe(_: &dyn EventSink) {}

    fn sample_event() -> AuthEvent {
        AuthEvent::new("user.created", None, serde_json::json!({}))
    }

    #[tokio::test]
    async fn noop_sink_returns_immediately() {
        NoopEventSink.emit(&sample_event()).await;
    }

    #[tokio::test]
    async fn logging_sink_returns_immediately() {
        LoggingEventSink.emit(&sample_event()).await;
    }

    #[tokio::test]
    async fn arc_dispatch_works() {
        let sink: std::sync::Arc<dyn EventSink> = std::sync::Arc::new(NoopEventSink);
        sink.emit(&sample_event()).await;
    }

    #[tokio::test]
    async fn auth_event_new_stamps_timestamp() {
        let before = Utc::now();
        let event = AuthEvent::new("test", None, serde_json::json!({"k": "v"}));
        let after = Utc::now();
        assert!(event.timestamp >= before);
        assert!(event.timestamp <= after);
        assert_eq!(event.event_type, "test");
        assert!(event.user_id.is_none());
    }
}
