use sqlx::{Row, SqlitePool};
use uuid::Uuid;

use allowthem_core::error::AuthError;

use crate::cache::TenantMeta;
use crate::error::SaasError;
use crate::tenants::{TenantId, TenantStatus};

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
}
