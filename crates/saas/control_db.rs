use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, Row, SqlitePool};
use uuid::Uuid;

use allowthem_core::error::AuthError;

use crate::cache::TenantMeta;
use crate::error::SaasError;
use crate::tenants::{Tenant, TenantId, TenantStatus};

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct TenantUsage {
    pub period: String,
    pub mau_count: i64,
    pub limit_reached_at: Option<DateTime<Utc>>,
    pub notified_at: Option<DateTime<Utc>>,
}

/// Role of a dashboard user inside a tenant. Mirrors `tenant_members.role`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize, sqlx::Type,
)]
#[sqlx(rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TenantRole {
    Owner,
    Admin,
    Viewer,
}

impl TenantRole {
    pub fn is_owner(&self) -> bool {
        matches!(self, TenantRole::Owner)
    }

    pub fn is_admin_or_owner(&self) -> bool {
        matches!(self, TenantRole::Owner | TenantRole::Admin)
    }

    /// SQL-side spelling. Matches the `tenant_members.role` CHECK.
    pub fn as_str(&self) -> &'static str {
        match self {
            TenantRole::Owner => "owner",
            TenantRole::Admin => "admin",
            TenantRole::Viewer => "viewer",
        }
    }
}

impl std::str::FromStr for TenantRole {
    type Err = SaasError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "owner" => Ok(TenantRole::Owner),
            "admin" => Ok(TenantRole::Admin),
            "viewer" => Ok(TenantRole::Viewer),
            other => Err(SaasError::InvalidRole(other.to_owned())),
        }
    }
}

pub struct ControlDb {
    pool: SqlitePool,
}

impl ControlDb {
    pub async fn new(pool: SqlitePool) -> Result<Self, AuthError> {
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(sqlx::Error::from)?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn tenant_meta_by_slug(&self, slug: &str) -> Result<Option<TenantMeta>, SaasError> {
        let row = sqlx::query("SELECT id, status, plan_id FROM tenants WHERE slug = ?1")
            .bind(slug)
            .fetch_optional(&self.pool)
            .await?;

        let Some(row) = row else { return Ok(None) };

        let id_bytes: Vec<u8> = row.try_get("id")?;
        let status: TenantStatus = row.try_get("status")?;
        let plan_id: Vec<u8> = row.try_get("plan_id")?;
        let id = Uuid::from_slice(&id_bytes).map_err(|_| SaasError::TenantNotFound)?;

        Ok(Some(TenantMeta {
            id: TenantId::from(id),
            status,
            plan_id,
        }))
    }

    /// Returns the `(Tenant, role)` pairs for every tenant the email has
    /// accepted membership in. Sorted by `t.name ASC`, with deleted tenants
    /// excluded. Used by the dashboard workspace switcher.
    pub async fn tenants_for_member(
        &self,
        email: &str,
    ) -> Result<Vec<(Tenant, TenantRole)>, SaasError> {
        let rows = sqlx::query(
            "SELECT t.id, t.name, t.slug, t.owner_email, t.plan_id, t.status, \
                    t.db_path, t.last_seen_at, t.created_at, t.updated_at, m.role \
             FROM tenants t \
             JOIN tenant_members m ON m.tenant_id = t.id \
             WHERE m.email = ?1 AND m.accepted_at IS NOT NULL \
               AND t.status != 'deleted' \
             ORDER BY t.name ASC",
        )
        .bind(email)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let tenant = Tenant::from_row(&row)?;
            let role: TenantRole = row.try_get("role")?;
            out.push((tenant, role));
        }
        Ok(out)
    }

    /// Returns the role the given email has on the tenant, or `None` if the
    /// user is not an accepted member. Used by `RequireTenantMember` /
    /// `RequireTenantAdmin` / `RequireTenantOwner`.
    pub async fn member_role(
        &self,
        tenant_id: &TenantId,
        email: &str,
    ) -> Result<Option<TenantRole>, SaasError> {
        let row: Option<(TenantRole,)> = sqlx::query_as(
            "SELECT role FROM tenant_members \
             WHERE tenant_id = ?1 AND email = ?2 AND accepted_at IS NOT NULL",
        )
        .bind(tenant_id.as_bytes())
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(r,)| r))
    }

    pub async fn most_recently_seen_tenants(&self, count: i64) -> Result<Vec<TenantId>, SaasError> {
        let rows = sqlx::query(
            "SELECT id FROM tenants \
             WHERE status = 'active' AND last_seen_at IS NOT NULL \
             ORDER BY last_seen_at DESC LIMIT ?1",
        )
        .bind(count)
        .fetch_all(&self.pool)
        .await?;

        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let bytes: Vec<u8> = row.try_get("id")?;
            match Uuid::from_slice(&bytes) {
                Ok(uuid) => result.push(TenantId::from(uuid)),
                Err(_) => {
                    tracing::warn!("skipping tenant with undecodable UUID in most_recently_seen");
                }
            }
        }
        Ok(result)
    }

    pub async fn touch_last_seen(&self, tenant_id: &TenantId) -> Result<(), SaasError> {
        sqlx::query("UPDATE tenants SET last_seen_at = datetime('now') WHERE id = ?1")
            .bind(tenant_id.as_bytes())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn usage_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> Result<Vec<TenantUsage>, SaasError> {
        let rows = sqlx::query_as::<_, TenantUsage>(
            "SELECT period, mau_count, limit_reached_at, notified_at \
             FROM tenant_usage \
             WHERE tenant_id = ?1 \
             ORDER BY period DESC",
        )
        .bind(tenant_id.as_bytes())
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Append an entry to `control_audit_events`.
    ///
    /// Call sites are fire-and-forget: log the error and continue. An
    /// unlogged audit event is a nuisance, never a correctness bug.
    /// `context` is serialised to a JSON string before persistence so the
    /// callers can pass arbitrary `serde_json::Value` shapes.
    pub async fn log_control_audit(
        &self,
        actor: &str,
        action: &str,
        tenant_id: Option<&TenantId>,
        context: &serde_json::Value,
    ) -> Result<(), SaasError> {
        let id = Uuid::now_v7();
        let context_str = context.to_string();
        sqlx::query(
            "INSERT INTO control_audit_events (id, actor, action, tenant_id, context) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(id.as_bytes().as_slice())
        .bind(actor)
        .bind(action)
        .bind(tenant_id.map(|t| t.as_bytes()))
        .bind(&context_str)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sqlx::Row;
    use std::str::FromStr;

    pub async fn test_pool() -> SqlitePool {
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .pragma("foreign_keys", "ON");
        SqlitePool::connect_with(opts).await.unwrap()
    }

    #[tokio::test]
    async fn control_db_runs_migrations() {
        let pool = test_pool().await;
        let db = ControlDb::new(pool).await;
        assert!(db.is_ok());
    }

    #[tokio::test]
    async fn log_control_audit_inserts_row() {
        let pool = test_pool().await;
        let db = ControlDb::new(pool).await.unwrap();
        db.log_control_audit(
            "owner@acme.com",
            "tenant.provisioned",
            None,
            &serde_json::json!({"slug": "acme"}),
        )
        .await
        .expect("log_control_audit");

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_audit_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);

        let (actor, action, ctx): (String, String, String) =
            sqlx::query_as("SELECT actor, action, context FROM control_audit_events LIMIT 1")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(actor, "owner@acme.com");
        assert_eq!(action, "tenant.provisioned");
        assert!(ctx.contains("acme"));
    }

    #[tokio::test]
    async fn tenant_slug_unique() {
        let pool = test_pool().await;
        let db = ControlDb::new(pool).await.unwrap();
        let row = sqlx::query("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let plan_id: Vec<u8> = row.get("id");
        let id_a = uuid::Uuid::new_v4();
        let id_b = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'Acme', 'acme', 'a@a.com', ?, 'active', 'acme.db')",
        )
        .bind(id_a.as_bytes().as_ref())
        .bind(&plan_id)
        .execute(db.pool())
        .await
        .unwrap();
        let res = sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'Acme 2', 'acme', 'b@b.com', ?, 'active', 'acme2.db')",
        )
        .bind(id_b.as_bytes().as_ref())
        .bind(&plan_id)
        .execute(db.pool())
        .await;
        assert!(res.is_err(), "duplicate slug should be rejected");
    }

    #[tokio::test]
    async fn tenant_status_check_rejects_invalid() {
        let pool = test_pool().await;
        let db = ControlDb::new(pool).await.unwrap();
        let row = sqlx::query("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let plan_id: Vec<u8> = row.get("id");
        let id = uuid::Uuid::new_v4();
        let res = sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'Bad', 'bad-status', 'c@c.com', ?, 'banned', 'bad.db')",
        )
        .bind(id.as_bytes().as_ref())
        .bind(&plan_id)
        .execute(db.pool())
        .await;
        assert!(res.is_err(), "invalid status should be rejected by CHECK");
    }

    #[tokio::test]
    async fn member_role_check_rejects_invalid() {
        let pool = test_pool().await;
        let db = ControlDb::new(pool).await.unwrap();
        let row = sqlx::query("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let plan_id: Vec<u8> = row.get("id");
        let tenant_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'Role Test', 'role-test', 'd@d.com', ?, 'active', 'rtest.db')",
        )
        .bind(tenant_id.as_bytes().as_ref())
        .bind(&plan_id)
        .execute(db.pool())
        .await
        .unwrap();
        let member_id = uuid::Uuid::new_v4();
        let res = sqlx::query(
            "INSERT INTO tenant_members (id, tenant_id, email, role) \
             VALUES (?, ?, 'e@e.com', 'superuser')",
        )
        .bind(member_id.as_bytes().as_ref())
        .bind(tenant_id.as_bytes().as_ref())
        .execute(db.pool())
        .await;
        assert!(res.is_err(), "invalid role should be rejected by CHECK");
    }

    #[tokio::test]
    async fn usage_for_tenant_returns_records() {
        let pool = test_pool().await;
        let db = ControlDb::new(pool).await.unwrap();
        let row = sqlx::query("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let plan_id: Vec<u8> = row.get("id");
        let tid = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'U', 'usagetest', 'u@u.com', ?, 'active', 'u.db')",
        )
        .bind(tid.as_bytes().as_ref())
        .bind(&plan_id)
        .execute(db.pool())
        .await
        .unwrap();
        let uid = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenant_usage (id, tenant_id, period, mau_count) \
             VALUES (?, ?, '2026-04', 42)",
        )
        .bind(uid.as_bytes().as_ref())
        .bind(tid.as_bytes().as_ref())
        .execute(db.pool())
        .await
        .unwrap();
        let tenant_id = TenantId::from(tid);
        let usage = db.usage_for_tenant(&tenant_id).await.unwrap();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].period, "2026-04");
        assert_eq!(usage[0].mau_count, 42);
        assert!(usage[0].limit_reached_at.is_none());
    }

    #[tokio::test]
    async fn api_key_hash_unique() {
        let pool = test_pool().await;
        let db = ControlDb::new(pool).await.unwrap();
        let row = sqlx::query("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let plan_id: Vec<u8> = row.get("id");
        let tenant_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'Key Test', 'key-test', 'f@f.com', ?, 'active', 'ktest.db')",
        )
        .bind(tenant_id.as_bytes().as_ref())
        .bind(&plan_id)
        .execute(db.pool())
        .await
        .unwrap();
        let hash = vec![0u8; 32];
        let key_id_a = uuid::Uuid::new_v4();
        let key_id_b = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenant_api_keys (id, tenant_id, name, key_hash, scope) \
             VALUES (?, ?, 'key-a', ?, '[]')",
        )
        .bind(key_id_a.as_bytes().as_ref())
        .bind(tenant_id.as_bytes().as_ref())
        .bind(&hash)
        .execute(db.pool())
        .await
        .unwrap();
        let res = sqlx::query(
            "INSERT INTO tenant_api_keys (id, tenant_id, name, key_hash, scope) \
             VALUES (?, ?, 'key-b', ?, '[]')",
        )
        .bind(key_id_b.as_bytes().as_ref())
        .bind(tenant_id.as_bytes().as_ref())
        .bind(&hash)
        .execute(db.pool())
        .await;
        assert!(res.is_err(), "duplicate key_hash should be rejected");
    }

    /// Helper: insert a tenant row with the given slug + status; return its `TenantId`.
    async fn seed_tenant_with_status(db: &ControlDb, slug: &str, status: &str) -> TenantId {
        let plan_id: Vec<u8> = sqlx::query_scalar("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let tid = uuid::Uuid::new_v4();
        let db_path = format!("{slug}.db");
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(tid.as_bytes().as_ref())
        .bind(slug)
        .bind(slug)
        .bind(format!("owner-{slug}@example.com"))
        .bind(&plan_id)
        .bind(status)
        .bind(&db_path)
        .execute(db.pool())
        .await
        .unwrap();
        TenantId::from(tid)
    }

    async fn seed_tenant(db: &ControlDb, slug: &str) -> TenantId {
        seed_tenant_with_status(db, slug, "active").await
    }

    async fn insert_member(
        db: &ControlDb,
        tenant_id: &TenantId,
        email: &str,
        role: &str,
        accepted: bool,
    ) {
        let id = uuid::Uuid::new_v4();
        if accepted {
            sqlx::query(
                "INSERT INTO tenant_members (id, tenant_id, email, role, accepted_at) \
                 VALUES (?, ?, ?, ?, datetime('now'))",
            )
            .bind(id.as_bytes().as_ref())
            .bind(tenant_id.as_bytes())
            .bind(email)
            .bind(role)
            .execute(db.pool())
            .await
            .unwrap();
        } else {
            sqlx::query(
                "INSERT INTO tenant_members (id, tenant_id, email, role) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(id.as_bytes().as_ref())
            .bind(tenant_id.as_bytes())
            .bind(email)
            .bind(role)
            .execute(db.pool())
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn member_role_returns_role_for_accepted_member() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "acme").await;
        insert_member(&db, &tid, "alice@x.com", "admin", true).await;

        let role = db.member_role(&tid, "alice@x.com").await.unwrap();
        assert_eq!(role, Some(TenantRole::Admin));
    }

    #[tokio::test]
    async fn member_role_ignores_unaccepted_invite() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "acme").await;
        insert_member(&db, &tid, "bob@x.com", "viewer", false).await;

        let role = db.member_role(&tid, "bob@x.com").await.unwrap();
        assert_eq!(role, None);
    }

    #[tokio::test]
    async fn member_role_returns_none_for_non_member() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "acme").await;

        let role = db.member_role(&tid, "stranger@x.com").await.unwrap();
        assert_eq!(role, None);
    }

    #[tokio::test]
    async fn tenants_for_member_returns_pairs_sorted_by_name() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let zid = seed_tenant(&db, "zulu").await;
        let aid = seed_tenant(&db, "alpha").await;
        insert_member(&db, &aid, "x@y.com", "owner", true).await;
        insert_member(&db, &zid, "x@y.com", "admin", true).await;

        let pairs = db.tenants_for_member("x@y.com").await.unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0.slug, "alpha");
        assert_eq!(pairs[0].1, TenantRole::Owner);
        assert_eq!(pairs[1].0.slug, "zulu");
        assert_eq!(pairs[1].1, TenantRole::Admin);
    }

    #[tokio::test]
    async fn tenants_for_member_excludes_deleted_tenants() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant_with_status(&db, "deadco", "deleted").await;
        insert_member(&db, &tid, "x@y.com", "owner", true).await;

        let pairs = db.tenants_for_member("x@y.com").await.unwrap();
        assert!(pairs.is_empty());
    }

    #[tokio::test]
    async fn tenants_for_member_excludes_unaccepted_invites() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "acme").await;
        insert_member(&db, &tid, "pending@x.com", "viewer", false).await;

        let pairs = db.tenants_for_member("pending@x.com").await.unwrap();
        assert!(pairs.is_empty());
    }
}
