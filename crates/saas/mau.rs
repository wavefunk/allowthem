//! Control-plane MAU (Monthly Active Users) sink.
//!
//! `MauSink` records every active-user event into `tenant_active_users`,
//! deduping on `(tenant_id, user_id, period)`, and increments
//! `tenant_usage.mau_count` on every fresh insert. The first time a
//! period's `mau_count` reaches the tenant's plan `mau_limit`, the
//! sink stamps `tenant_usage.limit_reached_at`.
//!
//! This module is **data-plane only** (per
//! `docs/superpowers/plans/2026-05-04-mau-counting.md` §2.7): it counts,
//! dedupes, and flags. It does **not** send emails, mutate
//! `tenants.status`, or block registrations — those behaviours are
//! Epic `eua.3`'s responsibility.

use std::sync::Arc;

use chrono::{DateTime, Datelike, Utc};
use uuid::Uuid;

use allowthem_core::types::UserId;

use crate::control_db::ControlDb;
use crate::error::SaasError;
use crate::tenants::TenantId;

/// Format a `DateTime<Utc>` as the `YYYY-MM` period key used by
/// `tenant_active_users.period` and `tenant_usage.period`.
fn period_key(at: DateTime<Utc>) -> String {
    format!("{:04}-{:02}", at.year(), at.month())
}

/// Compute the cutoff period string for `prune_old_active_users`.
///
/// Returns the period that is `retention_months` calendar months before
/// the current month. With the cutoff used as `period < ?` in DELETE,
/// `retention_months = 3` from May 2026 keeps rows from Feb 2026
/// onward (Feb/Mar/Apr/May = a sliding window of "current month + the
/// previous N months"). Older rows are deleted.
fn prune_cutoff(now: DateTime<Utc>, retention_months: u32) -> String {
    // Convert to absolute month index, subtract retention, convert back.
    let total_months = now.year() * 12 + (now.month() as i32) - 1 - retention_months as i32;
    let year = total_months.div_euclid(12);
    let month = (total_months.rem_euclid(12) + 1) as u32;
    format!("{year:04}-{month:02}")
}

/// Records active-user events and per-period counts in the control plane.
///
/// One instance is shared across every tenant `AllowThem` handle — the
/// sink itself is stateless beyond a clone of the control DB pool;
/// `tenant_id` arrives per call.
pub struct MauSink {
    control_db: Arc<ControlDb>,
}

impl MauSink {
    pub fn new(control_db: Arc<ControlDb>) -> Self {
        Self { control_db }
    }

    /// Record one active-user event.
    ///
    /// On a fresh `(tenant_id, user_id, period)` triple this:
    /// 1. Inserts a row into `tenant_active_users`.
    /// 2. Increments (or upserts) `tenant_usage.mau_count` for the period.
    /// 3. If the post-increment `mau_count` reaches the plan `mau_limit`
    ///    and `limit_reached_at` is still NULL, stamps it with `now`.
    ///
    /// On a duplicate triple (same user already seen this period) the
    /// `INSERT OR IGNORE` is a no-op and `mau_count` is unchanged.
    ///
    /// All four statements run inside a single transaction so the
    /// fresh-insert + increment + flag check is atomic against
    /// concurrent writers (see plan §2.3).
    pub async fn record_active(
        &self,
        tenant_id: TenantId,
        user_id: UserId,
        at: DateTime<Utc>,
    ) -> Result<(), SaasError> {
        let period = period_key(at);
        let mut tx = self.control_db.pool().begin().await?;

        let result = sqlx::query(
            "INSERT OR IGNORE INTO tenant_active_users \
                 (tenant_id, user_id, period, first_seen_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(tenant_id.as_bytes())
        .bind(user_id.as_uuid().as_bytes().as_ref())
        .bind(&period)
        .bind(at.to_rfc3339())
        .execute(&mut *tx)
        .await?;

        if result.rows_affected() == 0 {
            // Already counted in this period; nothing more to do.
            tx.commit().await?;
            return Ok(());
        }

        let usage_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO tenant_usage (id, tenant_id, period, mau_count) \
             VALUES (?, ?, ?, 1) \
             ON CONFLICT (tenant_id, period) DO UPDATE SET \
                 mau_count = mau_count + 1",
        )
        .bind(usage_id.as_bytes().as_ref())
        .bind(tenant_id.as_bytes())
        .bind(&period)
        .execute(&mut *tx)
        .await?;

        let row: (i64, Option<DateTime<Utc>>, i64) = sqlx::query_as(
            "SELECT u.mau_count, u.limit_reached_at, p.mau_limit \
             FROM tenant_usage u \
             JOIN tenants t ON t.id = u.tenant_id \
             JOIN tenant_plans p ON p.id = t.plan_id \
             WHERE u.tenant_id = ?1 AND u.period = ?2",
        )
        .bind(tenant_id.as_bytes())
        .bind(&period)
        .fetch_one(&mut *tx)
        .await?;
        let (mau_count, limit_reached_at, plan_mau_limit) = row;

        // Threshold is `>=`: flag flips on first reach of the limit.
        // The redundant `IS NULL` predicate makes the UPDATE
        // self-idempotent if ever moved out of this transaction.
        if mau_count >= plan_mau_limit && limit_reached_at.is_none() {
            sqlx::query(
                "UPDATE tenant_usage \
                 SET limit_reached_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
                 WHERE tenant_id = ?1 AND period = ?2 AND limit_reached_at IS NULL",
            )
            .bind(tenant_id.as_bytes())
            .bind(&period)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    /// Delete `tenant_active_users` rows for periods strictly older than
    /// the (`now` − `retention_months`) cutoff. Returns the number of
    /// pruned rows.
    ///
    /// `tenant_usage` is **not** pruned — it is the billing source of
    /// truth, and is small (one row per tenant per period).
    pub async fn prune_old_active_users(&self, retention_months: u32) -> Result<u64, SaasError> {
        let cutoff = prune_cutoff(Utc::now(), retention_months);
        let result = sqlx::query("DELETE FROM tenant_active_users WHERE period < ?1")
            .bind(&cutoff)
            .execute(self.control_db.pool())
            .await?;
        Ok(result.rows_affected())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use chrono::TimeZone;
    use sqlx::SqlitePool;
    use uuid::Uuid;

    use crate::control_db::tests::test_pool;

    /// Seed a single plan + tenant in the control DB and return their ids.
    /// `mau_limit` controls when `limit_reached_at` flips during tests.
    async fn seed_plan_and_tenant(pool: &SqlitePool, mau_limit: i64) -> (Vec<u8>, TenantId) {
        let plan_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenant_plans (id, name, mau_limit, price_cents) \
             VALUES (?, ?, ?, 0)",
        )
        .bind(plan_id.as_bytes().as_ref())
        .bind(format!("plan-{}", &plan_id.to_string()[..8]))
        .bind(mau_limit)
        .execute(pool)
        .await
        .unwrap();

        let tenant_id = TenantId::new();
        sqlx::query(
            "INSERT INTO tenants \
                 (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'Acme', ?, 'owner@acme.test', ?, 'active', '/tmp/db')",
        )
        .bind(tenant_id.as_bytes())
        .bind(format!("acme-{}", &tenant_id.as_uuid().to_string()[..8]))
        .bind(plan_id.as_bytes().as_ref())
        .execute(pool)
        .await
        .unwrap();

        (plan_id.as_bytes().to_vec(), tenant_id)
    }

    /// Build a `MauSink` against a fresh in-memory control DB plus seeded
    /// plan + tenant.
    async fn make_sink(mau_limit: i64) -> (MauSink, TenantId) {
        let pool = test_pool().await;
        let control_db = Arc::new(ControlDb::new(pool).await.unwrap());
        let (_plan_id, tenant_id) = seed_plan_and_tenant(control_db.pool(), mau_limit).await;
        (MauSink::new(control_db), tenant_id)
    }

    fn march_first() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 3, 1, 12, 0, 0).unwrap()
    }

    fn april_first() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 1, 12, 0, 0).unwrap()
    }

    #[test]
    fn period_key_zero_pads_month() {
        assert_eq!(period_key(march_first()), "2026-03");
        assert_eq!(period_key(april_first()), "2026-04");
    }

    #[test]
    fn prune_cutoff_three_month_retention() {
        // From May 2026, retention=3 → cutoff = "2026-02".
        // Rows with period < "2026-02" are deleted; Feb–May kept.
        let now = Utc.with_ymd_and_hms(2026, 5, 15, 0, 0, 0).unwrap();
        assert_eq!(prune_cutoff(now, 3), "2026-02");
    }

    #[test]
    fn prune_cutoff_crosses_year_boundary() {
        // From January 2026, retention=3 → cutoff = "2025-10".
        let now = Utc.with_ymd_and_hms(2026, 1, 10, 0, 0, 0).unwrap();
        assert_eq!(prune_cutoff(now, 3), "2025-10");
    }

    #[tokio::test]
    async fn record_active_first_event_inserts_and_increments() {
        let (sink, tenant_id) = make_sink(100).await;
        let user = UserId::new();

        sink.record_active(tenant_id, user, march_first())
            .await
            .unwrap();

        let active_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM tenant_active_users WHERE tenant_id = ?1")
                .bind(tenant_id.as_bytes())
                .fetch_one(sink.control_db.pool())
                .await
                .unwrap();
        assert_eq!(active_count, 1);

        let mau: i64 = sqlx::query_scalar(
            "SELECT mau_count FROM tenant_usage \
             WHERE tenant_id = ?1 AND period = '2026-03'",
        )
        .bind(tenant_id.as_bytes())
        .fetch_one(sink.control_db.pool())
        .await
        .unwrap();
        assert_eq!(mau, 1);
    }

    #[tokio::test]
    async fn record_active_dedupes_same_user_same_period() {
        let (sink, tenant_id) = make_sink(100).await;
        let user = UserId::new();

        sink.record_active(tenant_id, user, march_first())
            .await
            .unwrap();
        sink.record_active(tenant_id, user, march_first())
            .await
            .unwrap();

        let active_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM tenant_active_users WHERE tenant_id = ?1")
                .bind(tenant_id.as_bytes())
                .fetch_one(sink.control_db.pool())
                .await
                .unwrap();
        assert_eq!(active_count, 1);

        let mau: i64 =
            sqlx::query_scalar("SELECT mau_count FROM tenant_usage WHERE tenant_id = ?1")
                .bind(tenant_id.as_bytes())
                .fetch_one(sink.control_db.pool())
                .await
                .unwrap();
        assert_eq!(mau, 1);
    }

    #[tokio::test]
    async fn record_active_distinct_users_same_period() {
        let (sink, tenant_id) = make_sink(100).await;

        for _ in 0..3 {
            sink.record_active(tenant_id, UserId::new(), march_first())
                .await
                .unwrap();
        }

        let mau: i64 =
            sqlx::query_scalar("SELECT mau_count FROM tenant_usage WHERE tenant_id = ?1")
                .bind(tenant_id.as_bytes())
                .fetch_one(sink.control_db.pool())
                .await
                .unwrap();
        assert_eq!(mau, 3);
    }

    #[tokio::test]
    async fn record_active_period_rollover_creates_fresh_usage_row() {
        let (sink, tenant_id) = make_sink(100).await;
        let user = UserId::new();

        sink.record_active(tenant_id, user, march_first())
            .await
            .unwrap();
        sink.record_active(tenant_id, user, april_first())
            .await
            .unwrap();

        let active_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM tenant_active_users WHERE tenant_id = ?1")
                .bind(tenant_id.as_bytes())
                .fetch_one(sink.control_db.pool())
                .await
                .unwrap();
        assert_eq!(active_count, 2);

        let usage_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT period, mau_count FROM tenant_usage \
             WHERE tenant_id = ?1 ORDER BY period ASC",
        )
        .bind(tenant_id.as_bytes())
        .fetch_all(sink.control_db.pool())
        .await
        .unwrap();
        assert_eq!(
            usage_rows,
            vec![("2026-03".to_owned(), 1), ("2026-04".to_owned(), 1)]
        );
    }

    #[tokio::test]
    async fn record_active_sets_limit_reached_at_on_first_overflow() {
        // Plan limit = 2: flag stays NULL after event 1, flips after
        // event 2 (>= threshold), unchanged after event 3.
        let (sink, tenant_id) = make_sink(2).await;
        let users = [UserId::new(), UserId::new(), UserId::new()];

        sink.record_active(tenant_id, users[0], march_first())
            .await
            .unwrap();
        let flag: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT limit_reached_at FROM tenant_usage WHERE tenant_id = ?1")
                .bind(tenant_id.as_bytes())
                .fetch_one(sink.control_db.pool())
                .await
                .unwrap();
        assert!(flag.is_none(), "flag must be NULL after 1 event (1 < 2)");

        sink.record_active(tenant_id, users[1], march_first())
            .await
            .unwrap();
        let flag_after_two: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT limit_reached_at FROM tenant_usage WHERE tenant_id = ?1")
                .bind(tenant_id.as_bytes())
                .fetch_one(sink.control_db.pool())
                .await
                .unwrap();
        let stamped = flag_after_two.expect("flag must be set after 2 events (2 >= 2)");

        sink.record_active(tenant_id, users[2], march_first())
            .await
            .unwrap();
        let flag_after_three: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT limit_reached_at FROM tenant_usage WHERE tenant_id = ?1")
                .bind(tenant_id.as_bytes())
                .fetch_one(sink.control_db.pool())
                .await
                .unwrap();
        assert_eq!(
            flag_after_three,
            Some(stamped),
            "flag must not be clobbered by subsequent over-limit events"
        );
    }

    #[tokio::test]
    async fn record_active_does_not_clobber_existing_limit_reached_at() {
        let (sink, tenant_id) = make_sink(1).await;

        // Pre-seed `tenant_usage` with a known `limit_reached_at`.
        let usage_id = Uuid::now_v7();
        let prev = Utc.with_ymd_and_hms(2026, 3, 1, 0, 0, 0).unwrap();
        sqlx::query(
            "INSERT INTO tenant_usage (id, tenant_id, period, mau_count, limit_reached_at) \
             VALUES (?, ?, '2026-03', 5, ?)",
        )
        .bind(usage_id.as_bytes().as_ref())
        .bind(tenant_id.as_bytes())
        .bind(prev)
        .execute(sink.control_db.pool())
        .await
        .unwrap();

        // Fire another over-limit event — flag should remain `prev`.
        sink.record_active(tenant_id, UserId::new(), march_first())
            .await
            .unwrap();

        let flag: DateTime<Utc> =
            sqlx::query_scalar("SELECT limit_reached_at FROM tenant_usage WHERE tenant_id = ?1")
                .bind(tenant_id.as_bytes())
                .fetch_one(sink.control_db.pool())
                .await
                .unwrap();
        assert_eq!(flag, prev);
    }

    #[tokio::test]
    async fn prune_old_active_users_removes_old_period_rows() {
        let (sink, tenant_id) = make_sink(100).await;
        let pool = sink.control_db.pool().clone();

        // Insert one row in a clearly old period and one in the
        // current month. Picking "1900-01" guarantees old; current
        // month derives from `Utc::now()`.
        sqlx::query(
            "INSERT INTO tenant_active_users \
                 (tenant_id, user_id, period, first_seen_at) \
             VALUES (?, ?, '1900-01', '1900-01-01T00:00:00Z')",
        )
        .bind(tenant_id.as_bytes())
        .bind(Uuid::new_v4().as_bytes().as_ref())
        .execute(&pool)
        .await
        .unwrap();

        let now = Utc::now();
        let current_period = format!("{:04}-{:02}", now.year(), now.month());
        sqlx::query(
            "INSERT INTO tenant_active_users \
                 (tenant_id, user_id, period, first_seen_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(tenant_id.as_bytes())
        .bind(Uuid::new_v4().as_bytes().as_ref())
        .bind(&current_period)
        .bind(now.to_rfc3339())
        .execute(&pool)
        .await
        .unwrap();

        let pruned = sink.prune_old_active_users(3).await.unwrap();
        assert_eq!(pruned, 1, "exactly one stale row should be deleted");

        let remaining: Vec<String> =
            sqlx::query_scalar("SELECT period FROM tenant_active_users WHERE tenant_id = ?1")
                .bind(tenant_id.as_bytes())
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(remaining, vec![current_period]);
    }

    #[tokio::test]
    async fn record_active_concurrent_fires_count_distinct_users_correctly() {
        // Regression for the §2.3 transaction-boundary decision. N concurrent
        // record_active calls overlapping users for the same (tenant, period)
        // must produce mau_count == distinct user count (not N), and exactly
        // one tenant_active_users row per distinct user.
        //
        // Uses an explicit busy_timeout so the test is deterministic even on
        // slow CI; SQLite serialises writers and would otherwise return
        // "database is locked" with the test_pool() default of 0.
        use std::str::FromStr;

        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .pragma("foreign_keys", "ON")
            .busy_timeout(std::time::Duration::from_secs(5));
        let pool = SqlitePool::connect_with(opts).await.unwrap();
        let control_db = Arc::new(ControlDb::new(pool).await.unwrap());
        let (_plan_id, tenant_id) = seed_plan_and_tenant(control_db.pool(), 1_000).await;
        let sink = Arc::new(MauSink::new(control_db.clone()));

        // 10 distinct users, each fired 5 times → 50 spawns, expect mau_count
        // == 10 because the per-user (tenant, user, period) triple dedupes.
        let users: Vec<UserId> = (0..10).map(|_| UserId::new()).collect();
        let at = march_first();
        let mut handles = Vec::with_capacity(50);
        for _ in 0..5 {
            for u in &users {
                let sink = sink.clone();
                let u = *u;
                handles.push(tokio::spawn(async move {
                    sink.record_active(tenant_id, u, at).await
                }));
            }
        }
        for h in handles {
            h.await.unwrap().unwrap();
        }

        let mau: i64 =
            sqlx::query_scalar("SELECT mau_count FROM tenant_usage WHERE tenant_id = ?1")
                .bind(tenant_id.as_bytes())
                .fetch_one(control_db.pool())
                .await
                .unwrap();
        assert_eq!(mau, 10, "mau_count must equal distinct user count");

        let active_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM tenant_active_users WHERE tenant_id = ?1")
                .bind(tenant_id.as_bytes())
                .fetch_one(control_db.pool())
                .await
                .unwrap();
        assert_eq!(
            active_count, 10,
            "tenant_active_users must have one row per distinct user"
        );
    }

    #[tokio::test]
    async fn record_active_returns_error_for_missing_tenant() {
        // record_active against a tenant_id that has no row in `tenants` must
        // surface an FK violation as Err — not panic. This is the input
        // shape the production tokio::spawn path warn-logs and drops.
        let pool = test_pool().await;
        let control_db = Arc::new(ControlDb::new(pool).await.unwrap());
        let sink = MauSink::new(control_db);

        let phantom_tenant = TenantId::new();
        let result = sink
            .record_active(phantom_tenant, UserId::new(), march_first())
            .await;

        assert!(
            matches!(result, Err(SaasError::Db(_))),
            "expected SaasError::Db on FK violation, got {result:?}"
        );
    }

    #[tokio::test]
    async fn prune_old_active_users_does_not_touch_tenant_usage() {
        let (sink, tenant_id) = make_sink(100).await;
        let pool = sink.control_db.pool().clone();

        // Seed a `tenant_usage` row in an old period.
        let usage_id = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO tenant_usage (id, tenant_id, period, mau_count) \
             VALUES (?, ?, '1900-01', 7)",
        )
        .bind(usage_id.as_bytes().as_ref())
        .bind(tenant_id.as_bytes())
        .execute(&pool)
        .await
        .unwrap();

        sink.prune_old_active_users(3).await.unwrap();

        let usage_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenant_usage")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            usage_count, 1,
            "tenant_usage rows are billing data; never pruned"
        );
    }
}
