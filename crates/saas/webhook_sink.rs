//! Per-tenant `EventSink` wiring for the SaaS webhook system.
//!
//! Background: `TenantBuilderConfig` historically carried a single
//! `event_sink: Option<Arc<dyn EventSink>>` shared across every tenant
//! handle. That is fine for stateless sinks (`LoggingEventSink`,
//! `NoopEventSink`) but breaks the moment a sink needs to know *which*
//! tenant produced the event — which it must, for the
//! `tenant_webhooks` lookup to scope correctly.
//!
//! The fix is a factory: the saas runtime calls
//! [`EventSinkFactory::for_tenant`] once per tenant `AllowThem` build
//! and the resulting sink is bound to that tenant for its lifetime.
//!
//! `event_sink_factory` is added alongside the existing `event_sink`
//! field on `TenantBuilderConfig` rather than replacing it. The
//! handle-builder prefers the factory when both are present, so the
//! upgrade is opt-in for the SaaS binary while embedded integrators
//! and existing tests continue using the simpler shared-sink path.

use std::sync::Arc;

use allowthem_core::{EventSink, LoggingEventSink};

use crate::tenants::TenantId;

/// Constructs a per-tenant [`EventSink`].
///
/// Implementations must be cheap to call repeatedly — the runtime
/// invokes `for_tenant` every time a tenant `AllowThem` handle is
/// built. State that is expensive to construct (DB pools, HTTP
/// clients) belongs on the factory itself, not on the per-tenant
/// sink.
pub trait EventSinkFactory: Send + Sync {
    fn for_tenant(&self, tenant_id: TenantId) -> Arc<dyn EventSink>;
}

/// Factory that returns a fresh [`LoggingEventSink`] for every tenant,
/// ignoring the id. Convenient for dev binaries and tests that want
/// the factory wiring without webhook delivery.
pub struct LoggingEventSinkFactory;

impl EventSinkFactory for LoggingEventSinkFactory {
    fn for_tenant(&self, _tenant_id: TenantId) -> Arc<dyn EventSink> {
        Arc::new(LoggingEventSink)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::AuthEvent;
    use uuid::Uuid;

    fn assert_obj_safe(_: &dyn EventSinkFactory) {}

    #[test]
    fn logging_factory_is_object_safe_and_returns_a_sink() {
        let f = LoggingEventSinkFactory;
        assert_obj_safe(&f);
        let _sink = f.for_tenant(TenantId::from(Uuid::now_v7()));
    }

    #[tokio::test]
    async fn logging_factory_sink_emits_without_panic() {
        let sink = LoggingEventSinkFactory.for_tenant(TenantId::from(Uuid::now_v7()));
        let event = AuthEvent::new("test", None, serde_json::json!({}));
        sink.emit(&event).await;
    }
}
