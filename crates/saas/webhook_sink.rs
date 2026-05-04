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

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use allowthem_core::{AuthEvent, EventSink, LoggingEventSink};
use sqlx::SqlitePool;
use uuid::Uuid;

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

// ---------------------------------------------------------------------------
// WebhookEventSink — synchronous outbox writer
// ---------------------------------------------------------------------------

/// `EventSink` implementation that writes one `webhook_deliveries` row per
/// matching `tenant_webhooks` subscription. Bound to a single tenant.
///
/// The sink does **not** perform HTTP. Outbound delivery is the
/// `WebhookWorker`'s responsibility (Task 5); this type's contract is to
/// transactionally fan-out into the durable outbox. Any failure is logged
/// at `warn` and dropped — `EventSink::emit` returns `()` so the auth
/// operation that produced the event is never blocked or rolled back by
/// a webhook bookkeeping issue.
pub struct WebhookEventSink {
    control_pool: SqlitePool,
    tenant_id: TenantId,
}

impl WebhookEventSink {
    pub fn new(control_pool: SqlitePool, tenant_id: TenantId) -> Self {
        Self {
            control_pool,
            tenant_id,
        }
    }
}

impl EventSink for WebhookEventSink {
    fn emit<'a>(&'a self, event: &'a AuthEvent) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            if let Err(e) = self.emit_inner(event).await {
                tracing::warn!(
                    tenant_id = %self.tenant_id.as_uuid(),
                    event_type = %event.event_type,
                    event_id = %event.event_id,
                    error = %e,
                    "webhook sink: failed to record delivery"
                );
            }
        })
    }
}

impl WebhookEventSink {
    async fn emit_inner(&self, event: &AuthEvent) -> Result<(), sqlx::Error> {
        // Find every enabled webhook subscribed to this event_type.
        // `event_types` is a JSON array; SQLite's json1 extension is
        // available in every reasonable build (verified — sqlx-cli relies
        // on it elsewhere in this repo). The EXISTS subquery short-circuits
        // when the array contains the event_type.
        let webhook_ids: Vec<(Vec<u8>,)> = sqlx::query_as(
            "SELECT id FROM tenant_webhooks \
             WHERE tenant_id = ?1 AND enabled = 1 \
               AND EXISTS (SELECT 1 FROM json_each(event_types) WHERE value = ?2)",
        )
        .bind(self.tenant_id.as_bytes())
        .bind(&event.event_type)
        .fetch_all(&self.control_pool)
        .await?;

        if webhook_ids.is_empty() {
            return Ok(());
        }

        // Serialise the payload once; same bytes go to every subscriber.
        let payload = serde_json::to_string(event).map_err(|e| {
            sqlx::Error::Decode(Box::new(std::io::Error::other(format!(
                "failed to serialise AuthEvent: {e}"
            ))))
        })?;
        let event_id_str = event.event_id.to_string();

        // Insert one row per matching webhook. The (webhook_id, event_id)
        // unique index makes re-emit of the same source event idempotent
        // here — useful if a future emit-retry path is added.
        for (webhook_id,) in webhook_ids {
            let delivery_id = Uuid::now_v7();
            sqlx::query(
                "INSERT OR IGNORE INTO webhook_deliveries \
                     (id, tenant_id, webhook_id, event_id, event_type, \
                      payload, status, attempts, next_retry_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, 'pending', 0, NULL)",
            )
            .bind(delivery_id.as_bytes().as_slice())
            .bind(self.tenant_id.as_bytes())
            .bind(webhook_id.as_slice())
            .bind(&event_id_str)
            .bind(&event.event_type)
            .bind(&payload)
            .execute(&self.control_pool)
            .await?;
        }
        Ok(())
    }
}

/// Factory that hands out [`WebhookEventSink`] per tenant, sharing the
/// underlying control-DB pool. Construct once at SaaS-binary startup
/// and place into `TenantBuilderConfig.event_sink_factory`.
pub struct WebhookEventSinkFactory {
    control_pool: SqlitePool,
}

impl WebhookEventSinkFactory {
    pub fn new(control_pool: SqlitePool) -> Self {
        Self { control_pool }
    }
}

impl EventSinkFactory for WebhookEventSinkFactory {
    fn for_tenant(&self, tenant_id: TenantId) -> Arc<dyn EventSink> {
        Arc::new(WebhookEventSink::new(self.control_pool.clone(), tenant_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_db::ControlDb;
    use crate::control_db::tests::test_pool;
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

    // --- WebhookEventSink helpers + tests --------------------------------

    /// Inserts an `active` tenant row using the seed plan_id. Returns the
    /// new tenant id.
    async fn seed_tenant(db: &ControlDb, slug: &str) -> TenantId {
        let plan_id: Vec<u8> = sqlx::query_scalar("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let tid = Uuid::now_v7();
        let db_path = format!("{slug}.db");
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, ?, ?, ?, ?, 'active', ?)",
        )
        .bind(tid.as_bytes().as_ref())
        .bind(slug)
        .bind(slug)
        .bind(format!("owner-{slug}@example.com"))
        .bind(&plan_id)
        .bind(&db_path)
        .execute(db.pool())
        .await
        .unwrap();
        TenantId::from(tid)
    }

    /// Inserts a `tenant_webhooks` row and returns its id (BLOB bytes).
    async fn seed_webhook(
        db: &ControlDb,
        tenant_id: TenantId,
        url: &str,
        event_types: &[&str],
        enabled: bool,
    ) -> Vec<u8> {
        let id = Uuid::now_v7();
        let event_types_json = serde_json::to_string(event_types).unwrap();
        sqlx::query(
            "INSERT INTO tenant_webhooks (id, tenant_id, url, secret_key, event_types, enabled) \
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(id.as_bytes().as_ref())
        .bind(tenant_id.as_bytes())
        .bind(url)
        .bind("test-secret")
        .bind(event_types_json)
        .bind(if enabled { 1_i64 } else { 0_i64 })
        .execute(db.pool())
        .await
        .unwrap();
        id.as_bytes().to_vec()
    }

    async fn deliveries_for_tenant(
        db: &ControlDb,
        tenant_id: TenantId,
    ) -> Vec<(Vec<u8>, String, String, String, i64)> {
        sqlx::query_as::<_, (Vec<u8>, String, String, String, i64)>(
            "SELECT webhook_id, event_id, event_type, status, attempts \
             FROM webhook_deliveries WHERE tenant_id = ? ORDER BY created_at ASC",
        )
        .bind(tenant_id.as_bytes())
        .fetch_all(db.pool())
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn emit_with_no_matching_webhook_inserts_nothing() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tenant = seed_tenant(&db, "acme").await;
        // Webhook subscribes to a different event type.
        seed_webhook(
            &db,
            tenant,
            "https://acme.example/hook",
            &["session.created"],
            true,
        )
        .await;

        let sink = WebhookEventSink::new(db.pool().clone(), tenant);
        let event = AuthEvent::new("user.created", None, serde_json::json!({}));
        sink.emit(&event).await;

        assert!(deliveries_for_tenant(&db, tenant).await.is_empty());
    }

    #[tokio::test]
    async fn emit_inserts_one_pending_row_per_matching_webhook() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tenant = seed_tenant(&db, "acme").await;
        let h1 = seed_webhook(
            &db,
            tenant,
            "https://h1.example/hook",
            &["user.created"],
            true,
        )
        .await;
        let h2 = seed_webhook(
            &db,
            tenant,
            "https://h2.example/hook",
            &["user.created", "session.created"],
            true,
        )
        .await;
        // Decoy: subscribed to a different type.
        seed_webhook(
            &db,
            tenant,
            "https://decoy.example/hook",
            &["role.assigned"],
            true,
        )
        .await;

        let sink = WebhookEventSink::new(db.pool().clone(), tenant);
        let event = AuthEvent::new("user.created", None, serde_json::json!({"k": "v"}));
        let event_id_str = event.event_id.to_string();
        sink.emit(&event).await;

        let rows = deliveries_for_tenant(&db, tenant).await;
        assert_eq!(rows.len(), 2, "two matching webhooks → two delivery rows");
        let webhook_ids: std::collections::HashSet<Vec<u8>> =
            rows.iter().map(|r| r.0.clone()).collect();
        assert!(webhook_ids.contains(&h1));
        assert!(webhook_ids.contains(&h2));
        for (_, event_id, event_type, status, attempts) in &rows {
            assert_eq!(
                event_id, &event_id_str,
                "all rows share the source event_id"
            );
            assert_eq!(event_type, "user.created");
            assert_eq!(status, "pending");
            assert_eq!(*attempts, 0);
        }
    }

    #[tokio::test]
    async fn emit_skips_disabled_webhook() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tenant = seed_tenant(&db, "acme").await;
        seed_webhook(
            &db,
            tenant,
            "https://h1.example/hook",
            &["user.created"],
            false,
        )
        .await;

        let sink = WebhookEventSink::new(db.pool().clone(), tenant);
        let event = AuthEvent::new("user.created", None, serde_json::json!({}));
        sink.emit(&event).await;

        assert!(deliveries_for_tenant(&db, tenant).await.is_empty());
    }

    #[tokio::test]
    async fn emit_re_emit_same_event_id_is_idempotent() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tenant = seed_tenant(&db, "acme").await;
        seed_webhook(
            &db,
            tenant,
            "https://h1.example/hook",
            &["user.created"],
            true,
        )
        .await;

        let sink = WebhookEventSink::new(db.pool().clone(), tenant);
        let event = AuthEvent::new("user.created", None, serde_json::json!({}));
        sink.emit(&event).await;
        sink.emit(&event).await;

        let rows = deliveries_for_tenant(&db, tenant).await;
        assert_eq!(
            rows.len(),
            1,
            "(webhook_id, event_id) UNIQUE makes re-emit a no-op"
        );
    }

    #[tokio::test]
    async fn emit_payload_round_trips_event_fields() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tenant = seed_tenant(&db, "acme").await;
        seed_webhook(
            &db,
            tenant,
            "https://h1.example/hook",
            &["user.created"],
            true,
        )
        .await;

        let sink = WebhookEventSink::new(db.pool().clone(), tenant);
        let event = AuthEvent::new("user.created", None, serde_json::json!({"k": "v"}));
        let expected_event_id = event.event_id.to_string();
        sink.emit(&event).await;

        let payload: String = sqlx::query_scalar(
            "SELECT payload FROM webhook_deliveries WHERE tenant_id = ? LIMIT 1",
        )
        .bind(tenant.as_bytes())
        .fetch_one(db.pool())
        .await
        .unwrap();
        let v: serde_json::Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(v["event_id"], expected_event_id);
        assert_eq!(v["event_type"], "user.created");
        assert_eq!(v["data"]["k"], "v");
    }

    #[tokio::test]
    async fn factory_returns_sink_bound_to_supplied_tenant() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tenant_a = seed_tenant(&db, "acme").await;
        let tenant_b = seed_tenant(&db, "globex").await;
        seed_webhook(
            &db,
            tenant_a,
            "https://a.example/hook",
            &["user.created"],
            true,
        )
        .await;
        seed_webhook(
            &db,
            tenant_b,
            "https://b.example/hook",
            &["user.created"],
            true,
        )
        .await;

        let factory = WebhookEventSinkFactory::new(db.pool().clone());
        let sink_for_a = factory.for_tenant(tenant_a);
        let event = AuthEvent::new("user.created", None, serde_json::json!({}));
        sink_for_a.emit(&event).await;

        let a_rows = deliveries_for_tenant(&db, tenant_a).await;
        let b_rows = deliveries_for_tenant(&db, tenant_b).await;
        assert_eq!(a_rows.len(), 1);
        assert!(
            b_rows.is_empty(),
            "tenant_b should not see tenant_a's events"
        );
    }

    #[tokio::test]
    async fn emit_swallows_pool_failure_so_auth_path_is_unaffected() {
        // Closes the EventSink contract: emit() returns () even when the
        // underlying control-DB write fails. Otherwise a webhook
        // bookkeeping issue could roll back or block the auth operation
        // that produced the event.
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tenant = seed_tenant(&db, "acme").await;
        seed_webhook(
            &db,
            tenant,
            "https://h1.example/hook",
            &["user.created"],
            true,
        )
        .await;

        // Build a sink against a clone of the pool, then close the original
        // — sqlx pool semantics mean any further query will return a
        // closed-pool error.
        let sink = WebhookEventSink::new(db.pool().clone(), tenant);
        db.pool().close().await;

        let event = AuthEvent::new("user.created", None, serde_json::json!({}));
        // The .await here must complete cleanly. A panic or a hang would
        // be a regression of the contract.
        sink.emit(&event).await;
    }
}
