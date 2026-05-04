//! Background webhook delivery worker.
//!
//! Polls `webhook_deliveries` for due rows, claims them via
//! `UPDATE ... RETURNING`, signs the payload via the shared
//! [`allowthem_core::webhook_sig::sign_payload`] helper, POSTs to the
//! subscriber, and records the outcome (success → `delivered`; transport
//! or non-2xx error → re-schedule with exponential backoff or `failed`
//! after the 5th retry).
//!
//! Single-instance — the saas binary runs one worker. Multi-host HA is a
//! v2 concern (see saas-mode-design §11). The schema-level claim is
//! race-free under SQLite's serialized writers, so a future second
//! worker would not double-deliver, but the loop logic assumes one.
//!
//! Lifecycle: `run(shutdown_rx)` blocks until the supplied
//! `tokio::sync::watch` receiver flips to `true`. The saas binary
//! constructs the channel, spawns `run`, and signals shutdown on Ctrl-C
//! / SIGTERM.

use std::sync::Arc;
use std::time::Duration;

use allowthem_core::webhook_sig::sign_payload;
use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use tokio::sync::Semaphore;
use tokio::sync::watch;
use tokio::time::sleep;

/// Tunable configuration for [`WebhookWorker`]. Defaults are suitable for
/// the SaaS dev binary; production may tune `concurrency` and
/// `request_timeout` upward.
#[derive(Debug, Clone)]
pub struct WebhookWorkerConfig {
    /// Time between consecutive `claim_due_batch` polls when the previous
    /// batch returned zero rows. Default: 5 s.
    pub poll_interval: Duration,
    /// Maximum number of due rows claimed per poll. Default: 64.
    pub batch_size: i64,
    /// Maximum number of in-flight HTTP requests at any time. Default: 10.
    pub concurrency: usize,
    /// HTTP request timeout per delivery attempt. Default: 10 s.
    pub request_timeout: Duration,
}

impl Default for WebhookWorkerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(5),
            batch_size: 64,
            concurrency: 10,
            request_timeout: Duration::from_secs(10),
        }
    }
}

/// Background webhook delivery loop.
pub struct WebhookWorker {
    pool: SqlitePool,
    http: reqwest::Client,
    config: WebhookWorkerConfig,
    sem: Arc<Semaphore>,
}

impl WebhookWorker {
    /// Construct a worker. Wraps a `reqwest::Client` with the configured
    /// timeout. Panics if reqwest fails to construct the client (e.g. TLS
    /// backend unavailable) — a deployment configuration bug, not a
    /// runtime error.
    pub fn new(pool: SqlitePool, config: WebhookWorkerConfig) -> Self {
        let http = reqwest::Client::builder()
            .timeout(config.request_timeout)
            .user_agent("allowthem-webhook/1")
            .build()
            .expect("reqwest::Client::build is infallible with default features");
        let sem = Arc::new(Semaphore::new(config.concurrency));
        Self {
            pool,
            http,
            config,
            sem,
        }
    }

    /// Run the polling loop until `shutdown` flips to `true`. Returns when
    /// shutdown is signalled and the in-flight permit holders have either
    /// completed or been dropped.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        loop {
            // Cheap shutdown check before the (potentially slow) DB poll.
            if *shutdown.borrow() {
                return;
            }

            match self.claim_due_batch().await {
                Ok(claims) if !claims.is_empty() => {
                    for claim in claims {
                        let permit = match self.sem.clone().acquire_owned().await {
                            Ok(p) => p,
                            Err(_) => return, // semaphore closed → shutting down
                        };
                        let pool = self.pool.clone();
                        let http = self.http.clone();
                        tokio::spawn(async move {
                            // permit dropped at end of scope releases the slot.
                            dispatch_and_record(&pool, &http, claim).await;
                            drop(permit);
                        });
                    }
                    // Loop back immediately — there may be more due rows.
                }
                Ok(_) => {
                    // No work — sleep until the next tick or shutdown.
                    tokio::select! {
                        _ = sleep(self.config.poll_interval) => {}
                        _ = shutdown.changed() => {}
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "webhook worker: claim_due_batch failed");
                    // Brief pause before retrying so a persistent DB error
                    // doesn't tight-loop the log.
                    tokio::select! {
                        _ = sleep(self.config.poll_interval) => {}
                        _ = shutdown.changed() => {}
                    }
                }
            }
        }
    }

    /// Atomically claim up to `batch_size` due rows by transitioning them
    /// from `pending` to `in_flight`. Returns the claimed deliveries
    /// joined with their subscription's url + secret_key.
    async fn claim_due_batch(&self) -> Result<Vec<ClaimedDelivery>, sqlx::Error> {
        // Two-step claim: an UPDATE ... RETURNING grabs the rows we own,
        // then a JOIN query fetches the subscription details. Doing the
        // join inside the UPDATE is awkward in SQLite because the inner
        // SELECT can't be a JOIN that depends on the outer table; the
        // separate fetch is simpler and cheap (one indexed lookup per id).
        let claimed: Vec<(Vec<u8>, Vec<u8>, String, String, i64)> = sqlx::query_as(
            "UPDATE webhook_deliveries \
                SET status = 'in_flight', \
                    last_attempt_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
              WHERE id IN ( \
                  SELECT id FROM webhook_deliveries \
                   WHERE status = 'pending' \
                     AND (next_retry_at IS NULL \
                          OR next_retry_at <= strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) \
                   ORDER BY created_at ASC \
                   LIMIT ?1 \
              ) \
              RETURNING id, webhook_id, event_id, event_type, attempts",
        )
        .bind(self.config.batch_size)
        .fetch_all(&self.pool)
        .await?;

        if claimed.is_empty() {
            return Ok(Vec::new());
        }

        // Fetch (url, secret, payload) for each claimed delivery.
        let mut out = Vec::with_capacity(claimed.len());
        for (id, _webhook_id, _event_id, event_type, attempts) in claimed {
            let row: Option<(String, String, String)> = sqlx::query_as(
                "SELECT w.url, w.secret_key, d.payload \
                 FROM tenant_webhooks w \
                 JOIN webhook_deliveries d ON d.webhook_id = w.id \
                 WHERE d.id = ?1",
            )
            .bind(&id)
            .fetch_optional(&self.pool)
            .await?;

            let (url, secret, payload) = match row {
                Some(t) => t,
                None => {
                    // Webhook deleted between claim and fetch. Mark the
                    // delivery as failed so it doesn't loop forever.
                    sqlx::query(
                        "UPDATE webhook_deliveries \
                            SET status = 'failed', \
                                last_attempt_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
                          WHERE id = ?1",
                    )
                    .bind(&id)
                    .execute(&self.pool)
                    .await?;
                    continue;
                }
            };

            out.push(ClaimedDelivery {
                id,
                event_type,
                attempts,
                url,
                secret,
                payload,
            });
        }

        Ok(out)
    }
}

/// One claimed row, ready to be dispatched.
#[derive(Debug, Clone)]
struct ClaimedDelivery {
    id: Vec<u8>,
    event_type: String,
    attempts: i64,
    url: String,
    secret: String,
    payload: String,
}

/// Compute the next retry delay for a failure. Returns `None` when the
/// retry budget (5 retries / 6 total attempts) is exhausted; the caller
/// then marks the row `failed`.
///
/// `attempts_after_failure` is the value of `attempts` *after*
/// incrementing it for this failure — so the first failure passes 1.
fn next_retry_after(attempts_after_failure: i64) -> Option<Duration> {
    match attempts_after_failure {
        1 => Some(Duration::from_secs(60)),
        2 => Some(Duration::from_secs(5 * 60)),
        3 => Some(Duration::from_secs(30 * 60)),
        4 => Some(Duration::from_secs(2 * 60 * 60)),
        5 => Some(Duration::from_secs(12 * 60 * 60)),
        _ => None,
    }
}

async fn dispatch_and_record(
    pool: &SqlitePool,
    http: &reqwest::Client,
    claim: ClaimedDelivery,
) {
    let now_ts = Utc::now().timestamp();
    let signature = sign_payload(claim.secret.as_bytes(), now_ts, claim.payload.as_bytes());

    let result = http
        .post(&claim.url)
        .header("Content-Type", "application/json")
        .header("X-Allowthem-Event", &claim.event_type)
        .header("X-Allowthem-Signature", &signature)
        .body(claim.payload.clone())
        .send()
        .await;

    match result {
        Ok(resp) => {
            let code = resp.status().as_u16() as i64;
            if resp.status().is_success() {
                if let Err(e) = mark_delivered(pool, &claim.id, code).await {
                    tracing::warn!(
                        error = %e,
                        "webhook worker: failed to mark delivered"
                    );
                }
            } else if let Err(e) =
                schedule_retry_or_fail(pool, &claim.id, claim.attempts + 1, Some(code)).await
            {
                tracing::warn!(error = %e, "webhook worker: failed to record non-2xx");
            }
        }
        Err(e) => {
            tracing::warn!(
                url = %claim.url,
                error = %e,
                "webhook worker: HTTP transport error"
            );
            if let Err(e) =
                schedule_retry_or_fail(pool, &claim.id, claim.attempts + 1, None).await
            {
                tracing::warn!(error = %e, "webhook worker: failed to record transport error");
            }
        }
    }
}

async fn mark_delivered(
    pool: &SqlitePool,
    id: &[u8],
    response_code: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE webhook_deliveries \
            SET status = 'delivered', \
                response_code = ?2, \
                last_attempt_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
          WHERE id = ?1",
    )
    .bind(id)
    .bind(response_code)
    .execute(pool)
    .await
    .map(|_| ())
}

async fn schedule_retry_or_fail(
    pool: &SqlitePool,
    id: &[u8],
    new_attempts: i64,
    response_code: Option<i64>,
) -> Result<(), sqlx::Error> {
    if let Some(delay) = next_retry_after(new_attempts) {
        let next_retry: DateTime<Utc> = Utc::now()
            + chrono::Duration::from_std(delay).expect("retry schedule fits in chrono::Duration");
        sqlx::query(
            "UPDATE webhook_deliveries \
                SET status = 'pending', \
                    attempts = ?2, \
                    response_code = ?3, \
                    last_attempt_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), \
                    next_retry_at = ?4 \
              WHERE id = ?1",
        )
        .bind(id)
        .bind(new_attempts)
        .bind(response_code)
        .bind(next_retry)
        .execute(pool)
        .await
        .map(|_| ())
    } else {
        sqlx::query(
            "UPDATE webhook_deliveries \
                SET status = 'failed', \
                    attempts = ?2, \
                    response_code = ?3, \
                    last_attempt_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
              WHERE id = ?1",
        )
        .bind(id)
        .bind(new_attempts)
        .bind(response_code)
        .execute(pool)
        .await
        .map(|_| ())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_db::ControlDb;
    use crate::control_db::tests::test_pool;
    use crate::tenants::TenantId;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use uuid::Uuid;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // -- backoff math -------------------------------------------------------

    #[test]
    fn next_retry_after_full_schedule() {
        assert_eq!(next_retry_after(1), Some(Duration::from_secs(60)));
        assert_eq!(next_retry_after(2), Some(Duration::from_secs(5 * 60)));
        assert_eq!(next_retry_after(3), Some(Duration::from_secs(30 * 60)));
        assert_eq!(next_retry_after(4), Some(Duration::from_secs(2 * 60 * 60)));
        assert_eq!(next_retry_after(5), Some(Duration::from_secs(12 * 60 * 60)));
        assert_eq!(next_retry_after(6), None);
        assert_eq!(next_retry_after(7), None);
    }

    // -- Helpers (mirroring webhook_sink::tests; kept inline so this module
    // is self-contained) -----------------------------------------------------

    async fn seed_tenant(db: &ControlDb, slug: &str) -> TenantId {
        let plan_id: Vec<u8> = sqlx::query_scalar("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let tid = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, ?, ?, ?, ?, 'active', ?)",
        )
        .bind(tid.as_bytes().as_ref())
        .bind(slug)
        .bind(slug)
        .bind(format!("{slug}@example.com"))
        .bind(&plan_id)
        .bind(format!("{slug}.db"))
        .execute(db.pool())
        .await
        .unwrap();
        TenantId::from(tid)
    }

    async fn seed_webhook(
        db: &ControlDb,
        tenant_id: TenantId,
        url: &str,
        secret: &str,
    ) -> Vec<u8> {
        let id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO tenant_webhooks (id, tenant_id, url, secret_key, event_types, enabled) \
             VALUES (?, ?, ?, ?, ?, 1)",
        )
        .bind(id.as_bytes().as_ref())
        .bind(tenant_id.as_bytes())
        .bind(url)
        .bind(secret)
        .bind(r#"["user.created"]"#)
        .execute(db.pool())
        .await
        .unwrap();
        id.as_bytes().to_vec()
    }

    async fn insert_pending(
        db: &ControlDb,
        tenant_id: TenantId,
        webhook_id: &[u8],
        attempts: i64,
    ) -> Vec<u8> {
        let id = Uuid::now_v7();
        let event_id = Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO webhook_deliveries \
                 (id, tenant_id, webhook_id, event_id, event_type, payload, status, attempts) \
             VALUES (?, ?, ?, ?, 'user.created', '{\"event_id\":\"x\"}', 'pending', ?)",
        )
        .bind(id.as_bytes().as_ref())
        .bind(tenant_id.as_bytes())
        .bind(webhook_id)
        .bind(&event_id)
        .bind(attempts)
        .execute(db.pool())
        .await
        .unwrap();
        id.as_bytes().to_vec()
    }

    async fn delivery_row(
        db: &ControlDb,
        id: &[u8],
    ) -> (String, i64, Option<i64>, Option<DateTime<Utc>>) {
        sqlx::query_as::<_, (String, i64, Option<i64>, Option<DateTime<Utc>>)>(
            "SELECT status, attempts, response_code, next_retry_at \
             FROM webhook_deliveries WHERE id = ?",
        )
        .bind(id)
        .fetch_one(db.pool())
        .await
        .unwrap()
    }

    fn small_config() -> WebhookWorkerConfig {
        WebhookWorkerConfig {
            poll_interval: Duration::from_millis(50),
            batch_size: 16,
            concurrency: 4,
            request_timeout: Duration::from_secs(2),
        }
    }

    // -- Happy path: 200 → delivered ----------------------------------------

    #[tokio::test]
    async fn dispatch_marks_delivered_on_2xx_and_sends_signature_header() {
        let server = MockServer::start().await;
        let captured: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        {
            let captured = captured.clone();
            Mock::given(method("POST"))
                .and(path("/hook"))
                .respond_with(move |req: &wiremock::Request| {
                    let sig = req
                        .headers
                        .get("x-allowthem-signature")
                        .map(|v| v.to_str().unwrap().to_owned());
                    *captured.lock().unwrap() = sig;
                    ResponseTemplate::new(200)
                })
                .mount(&server)
                .await;
        }

        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tenant = seed_tenant(&db, "acme").await;
        let url = format!("{}/hook", server.uri());
        let webhook_id = seed_webhook(&db, tenant, &url, "test-secret").await;
        let delivery_id = insert_pending(&db, tenant, &webhook_id, 0).await;

        let worker = WebhookWorker::new(db.pool().clone(), small_config());
        let claims = worker.claim_due_batch().await.unwrap();
        assert_eq!(claims.len(), 1);
        dispatch_and_record(db.pool(), &worker.http, claims.into_iter().next().unwrap()).await;

        let (status, attempts, code, next_retry) = delivery_row(&db, &delivery_id).await;
        assert_eq!(status, "delivered");
        assert_eq!(attempts, 0);
        assert_eq!(code, Some(200));
        assert!(next_retry.is_none());

        let sig = captured.lock().unwrap().clone().expect("sig captured");
        assert!(sig.starts_with("t="), "signature should be Stripe-style: {sig}");
        assert!(sig.contains(",v1="), "signature should contain v1=: {sig}");
    }

    // -- 500 → pending, attempts +1, next_retry_at scheduled ----------------

    #[tokio::test]
    async fn dispatch_records_500_as_retry_with_backoff() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tenant = seed_tenant(&db, "acme").await;
        let url = format!("{}/hook", server.uri());
        let webhook_id = seed_webhook(&db, tenant, &url, "test-secret").await;
        let delivery_id = insert_pending(&db, tenant, &webhook_id, 0).await;

        let worker = WebhookWorker::new(db.pool().clone(), small_config());
        let claims = worker.claim_due_batch().await.unwrap();
        let before = Utc::now();
        dispatch_and_record(db.pool(), &worker.http, claims.into_iter().next().unwrap()).await;
        let after = Utc::now();

        let (status, attempts, code, next_retry) = delivery_row(&db, &delivery_id).await;
        assert_eq!(status, "pending");
        assert_eq!(attempts, 1);
        assert_eq!(code, Some(500));
        let next = next_retry.expect("next_retry_at should be set");
        // Should be ~60 seconds in the future (retry #1).
        let lower = before + chrono::Duration::seconds(55);
        let upper = after + chrono::Duration::seconds(65);
        assert!(next >= lower && next <= upper, "next={next} expected ~now+60s");
    }

    // -- attempts=5 + 500 → failed ------------------------------------------

    #[tokio::test]
    async fn dispatch_marks_failed_after_retry_budget_exhausted() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/hook"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tenant = seed_tenant(&db, "acme").await;
        let url = format!("{}/hook", server.uri());
        let webhook_id = seed_webhook(&db, tenant, &url, "test-secret").await;
        // attempts=5 means this is attempt #6 and will be the last.
        let delivery_id = insert_pending(&db, tenant, &webhook_id, 5).await;

        let worker = WebhookWorker::new(db.pool().clone(), small_config());
        let claims = worker.claim_due_batch().await.unwrap();
        dispatch_and_record(db.pool(), &worker.http, claims.into_iter().next().unwrap()).await;

        let (status, attempts, code, next_retry) = delivery_row(&db, &delivery_id).await;
        assert_eq!(status, "failed");
        assert_eq!(attempts, 6);
        assert_eq!(code, Some(500));
        assert!(next_retry.is_none(), "no further retry scheduled");
    }

    // -- Transport error (connection refused) → pending + retry -------------

    #[tokio::test]
    async fn dispatch_records_transport_error_as_retry() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tenant = seed_tenant(&db, "acme").await;
        // Bind a TCP socket and immediately drop to get a guaranteed
        // unreachable port (well, almost — short race window OK for tests).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let url = format!("http://{addr}/hook");
        let webhook_id = seed_webhook(&db, tenant, &url, "test-secret").await;
        let delivery_id = insert_pending(&db, tenant, &webhook_id, 2).await;

        let worker = WebhookWorker::new(db.pool().clone(), small_config());
        let claims = worker.claim_due_batch().await.unwrap();
        dispatch_and_record(db.pool(), &worker.http, claims.into_iter().next().unwrap()).await;

        let (status, attempts, code, _next_retry) = delivery_row(&db, &delivery_id).await;
        // Either we hit the transport error path (response_code = None) or
        // the OS races and accepts on a different socket; only the
        // transport error has stable semantics, so assert that.
        assert_eq!(status, "pending");
        assert_eq!(attempts, 3);
        assert_eq!(code, None, "transport error → response_code stays NULL");
    }

    // -- claim_due_batch is race-free under contention ----------------------

    #[tokio::test]
    async fn claim_due_batch_respects_due_window_and_status_filter() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tenant = seed_tenant(&db, "acme").await;
        let webhook_id = seed_webhook(&db, tenant, "https://example/hook", "s").await;

        // 3 pending rows immediately due (next_retry_at IS NULL).
        for _ in 0..3 {
            insert_pending(&db, tenant, &webhook_id, 0).await;
        }
        // 1 pending row with next_retry_at in the future — should not be
        // claimed. Use the same ISO 8601 format the worker compares
        // against, otherwise lexicographic comparison breaks.
        let future_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO webhook_deliveries \
                 (id, tenant_id, webhook_id, event_id, event_type, payload, status, attempts, next_retry_at) \
             VALUES (?, ?, ?, 'evt', 'user.created', '{}', 'pending', 1, \
                     strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '+1 hour'))",
        )
        .bind(future_id.as_bytes().as_ref())
        .bind(tenant.as_bytes())
        .bind(&webhook_id)
        .execute(db.pool())
        .await
        .unwrap();
        // 1 already-delivered row.
        let done_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO webhook_deliveries \
                 (id, tenant_id, webhook_id, event_id, event_type, payload, status, attempts) \
             VALUES (?, ?, ?, 'evt2', 'user.created', '{}', 'delivered', 0)",
        )
        .bind(done_id.as_bytes().as_ref())
        .bind(tenant.as_bytes())
        .bind(&webhook_id)
        .execute(db.pool())
        .await
        .unwrap();

        let worker = WebhookWorker::new(db.pool().clone(), small_config());
        let claims = worker.claim_due_batch().await.unwrap();
        assert_eq!(claims.len(), 3, "only the three immediately-due rows are claimed");

        // Subsequent claim returns nothing — claimed rows are now in_flight.
        let again = worker.claim_due_batch().await.unwrap();
        assert!(again.is_empty(), "in_flight rows are not re-claimed");
    }

    // -- Concurrency cap -----------------------------------------------------

    #[tokio::test]
    async fn worker_run_caps_in_flight_at_concurrency_limit() {
        // Server delays each response so we can observe overlap. Track the
        // peak in-flight count and assert it never exceeds the cap.
        let in_flight = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let server = MockServer::start().await;
        {
            let in_flight = in_flight.clone();
            let peak = peak.clone();
            Mock::given(method("POST"))
                .and(path("/hook"))
                .respond_with(move |_req: &wiremock::Request| {
                    let cur = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                    let mut prev = peak.load(Ordering::SeqCst);
                    while cur > prev
                        && peak
                            .compare_exchange(prev, cur, Ordering::SeqCst, Ordering::SeqCst)
                            .is_err()
                    {
                        prev = peak.load(Ordering::SeqCst);
                    }
                    // Hold the slot a bit so concurrent fires actually overlap.
                    std::thread::sleep(Duration::from_millis(50));
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    ResponseTemplate::new(200)
                })
                .mount(&server)
                .await;
        }

        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tenant = seed_tenant(&db, "acme").await;
        let url = format!("{}/hook", server.uri());
        let webhook_id = seed_webhook(&db, tenant, &url, "secret").await;
        for _ in 0..20 {
            insert_pending(&db, tenant, &webhook_id, 0).await;
        }

        let cfg = WebhookWorkerConfig {
            poll_interval: Duration::from_millis(20),
            batch_size: 32,
            concurrency: 3, // cap to 3
            request_timeout: Duration::from_secs(2),
        };
        let worker = WebhookWorker::new(db.pool().clone(), cfg);
        let (tx, rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            worker.run(rx).await;
        });

        // Wait for all 20 to be drained.
        for _ in 0..200 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let pending: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM webhook_deliveries \
                 WHERE status IN ('pending','in_flight')",
            )
            .fetch_one(db.pool())
            .await
            .unwrap();
            if pending == 0 {
                break;
            }
        }

        let _ = tx.send(true);
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;

        let observed = peak.load(Ordering::SeqCst);
        assert!(
            observed <= 3,
            "peak in-flight should never exceed concurrency=3 (observed: {observed})"
        );
        let delivered: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM webhook_deliveries WHERE status = 'delivered'")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(delivered, 20, "all 20 deliveries should reach delivered");
    }
}
