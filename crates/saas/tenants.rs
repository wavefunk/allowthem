use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::control_db::ControlDb;
use crate::error::SaasError;

// moves to router.rs in tx8.4
const RESERVED_SLUGS: &[&str] = &[
    "www",
    "api",
    "admin",
    "auth",
    "manage",
    "oauth",
    "app",
    "dashboard",
    "status",
    "mail",
    "docs",
    "help",
    "support",
    "static",
    "cdn",
    "assets",
    "id",
    "sso",
    "allowthem",
];

fn is_reserved_slug(slug: &str) -> bool {
    RESERVED_SLUGS.contains(&slug)
}

/// Validates slug format per spec §4 step 1: ^[a-z][a-z0-9-]{2,39}$
pub(crate) fn validate_slug(slug: &str) -> Result<(), SaasError> {
    if is_reserved_slug(slug) {
        return Err(SaasError::SlugReserved);
    }
    let bytes = slug.as_bytes();
    if bytes.len() < 3 || bytes.len() > 40 {
        return Err(SaasError::SlugInvalid("must be 3–40 characters"));
    }
    if !bytes[0].is_ascii_lowercase() {
        return Err(SaasError::SlugInvalid("must start with a lowercase letter"));
    }
    let rest_valid = bytes[1..]
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
    if !rest_valid {
        return Err(SaasError::SlugInvalid(
            "only lowercase letters, digits, and hyphens allowed",
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, sqlx::Type, serde::Serialize, serde::Deserialize)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TenantStatus {
    Active,
    Suspended,
    Deleted,
}

/// A row from the `tenants` control-plane table.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct Tenant {
    pub id: Vec<u8>,          // UUIDv7 bytes (BLOB)
    pub name: String,
    pub slug: String,
    pub owner_email: String,
    pub plan_id: Vec<u8>,     // opaque randomblob(16) from seed migration
    pub status: TenantStatus,
    pub db_path: String,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Tenant {
    pub fn id_as_uuid(&self) -> Option<Uuid> {
        Uuid::from_slice(&self.id).ok()
    }
}

/// UUIDv7-backed identifier for a tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(Uuid);

impl Default for TenantId {
    fn default() -> Self {
        Self::new()
    }
}

impl TenantId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Returns raw bytes suitable for binding to a BLOB column.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl From<Uuid> for TenantId {
    fn from(u: Uuid) -> Self {
        Self(u)
    }
}

// ---------------------------------------------------------------------------
// Read queries
// ---------------------------------------------------------------------------

impl ControlDb {
    pub async fn tenant_by_slug(&self, slug: &str) -> Result<Option<Tenant>, SaasError> {
        let row = sqlx::query_as::<_, Tenant>(
            "SELECT id, name, slug, owner_email, plan_id, status, db_path, \
             last_seen_at, created_at, updated_at \
             FROM tenants WHERE slug = ?1",
        )
        .bind(slug)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    pub async fn tenant_by_id(&self, id: &TenantId) -> Result<Option<Tenant>, SaasError> {
        self.tenant_by_id_raw(id.as_bytes()).await
    }

    pub(crate) async fn tenant_by_id_raw(&self, id: &[u8]) -> Result<Option<Tenant>, SaasError> {
        let row = sqlx::query_as::<_, Tenant>(
            "SELECT id, name, slug, owner_email, plan_id, status, db_path, \
             last_seen_at, created_at, updated_at \
             FROM tenants WHERE id = ?1",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await?;
        Ok(row)
    }

    pub async fn tenant_by_owner_email(&self, email: &str) -> Result<Vec<Tenant>, SaasError> {
        let rows = sqlx::query_as::<_, Tenant>(
            "SELECT id, name, slug, owner_email, plan_id, status, db_path, \
             last_seen_at, created_at, updated_at \
             FROM tenants WHERE owner_email = ?1",
        )
        .bind(email)
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }
}

// ---------------------------------------------------------------------------
// Simple mutations
// ---------------------------------------------------------------------------

impl ControlDb {
    pub async fn update_tenant_name(
        &self,
        id: &TenantId,
        name: String,
    ) -> Result<(), SaasError> {
        let rows = sqlx::query(
            "UPDATE tenants \
             SET name = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
             WHERE id = ?2 AND status != 'deleted'",
        )
        .bind(&name)
        .bind(id.as_bytes())
        .execute(self.pool())
        .await?;
        if rows.rows_affected() == 0 {
            return Err(SaasError::TenantNotFound);
        }
        Ok(())
    }

    pub async fn suspend_tenant(&self, id: &TenantId) -> Result<(), SaasError> {
        let rows = sqlx::query(
            "UPDATE tenants \
             SET status = 'suspended', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
             WHERE id = ?1 AND status = 'active'",
        )
        .bind(id.as_bytes())
        .execute(self.pool())
        .await?;
        if rows.rows_affected() == 0 {
            return Err(SaasError::TenantNotFound);
        }
        Ok(())
    }

    pub async fn delete_tenant(&self, id: &TenantId) -> Result<(), SaasError> {
        let rows = sqlx::query(
            "UPDATE tenants \
             SET status = 'deleted', updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
             WHERE id = ?1 AND status != 'deleted'",
        )
        .bind(id.as_bytes())
        .execute(self.pool())
        .await?;
        if rows.rows_affected() == 0 {
            return Err(SaasError::TenantNotFound);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_db::tests::test_pool;

    async fn test_db() -> ControlDb {
        let pool = test_pool().await;
        ControlDb::new(pool).await.expect("ControlDb::new")
    }

    pub(super) async fn insert_tenant(db: &ControlDb, slug: &str, email: &str) -> Vec<u8> {
        let id = TenantId::new();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             SELECT ?1, ?2, ?3, ?4, id, 'active', ?5 FROM tenant_plans WHERE name = 'dev'",
        )
        .bind(id.as_bytes())
        .bind(format!("{slug}-name"))
        .bind(slug)
        .bind(email)
        .bind(format!("{slug}.db"))
        .execute(db.pool())
        .await
        .expect("insert_tenant");
        id.as_bytes().to_vec()
    }

    #[tokio::test]
    async fn tenant_by_slug_found() {
        let db = test_db().await;
        insert_tenant(&db, "acme-corp", "owner@acme.com").await;
        let tenant = db.tenant_by_slug("acme-corp").await.expect("query");
        assert!(tenant.is_some());
        assert_eq!(tenant.unwrap().slug, "acme-corp");
    }

    #[tokio::test]
    async fn tenant_by_slug_not_found() {
        let db = test_db().await;
        let tenant = db.tenant_by_slug("no-such").await.expect("query");
        assert!(tenant.is_none());
    }

    #[tokio::test]
    async fn tenant_by_id_found() {
        let db = test_db().await;
        let id_bytes = insert_tenant(&db, "beta-corp", "owner@beta.com").await;
        let uuid = Uuid::from_slice(&id_bytes).unwrap();
        let tenant = db
            .tenant_by_id(&TenantId::from(uuid))
            .await
            .expect("query");
        assert!(tenant.is_some());
        assert_eq!(tenant.unwrap().id, id_bytes);
    }

    #[tokio::test]
    async fn tenant_by_owner_email() {
        let db = test_db().await;
        insert_tenant(&db, "corp-one", "shared@example.com").await;
        insert_tenant(&db, "corp-two", "shared@example.com").await;
        let tenants = db
            .tenant_by_owner_email("shared@example.com")
            .await
            .expect("query");
        assert_eq!(tenants.len(), 2);
    }

    // --- Commit 2: simple mutations ---

    #[tokio::test]
    async fn update_name_persists() {
        let db = test_db().await;
        let id_bytes = insert_tenant(&db, "rename-me", "owner@example.com").await;
        let uuid = Uuid::from_slice(&id_bytes).unwrap();
        let tid = TenantId::from(uuid);
        db.update_tenant_name(&tid, "Renamed Corp".into())
            .await
            .expect("update_name");
        let tenant = db.tenant_by_id(&tid).await.expect("query").unwrap();
        assert_eq!(tenant.name, "Renamed Corp");
    }

    #[tokio::test]
    async fn suspend_sets_status() {
        let db = test_db().await;
        let id_bytes = insert_tenant(&db, "suspend-me", "owner@example.com").await;
        let uuid = Uuid::from_slice(&id_bytes).unwrap();
        let tid = TenantId::from(uuid);
        db.suspend_tenant(&tid).await.expect("suspend");
        let tenant = db.tenant_by_id(&tid).await.expect("query").unwrap();
        assert_eq!(tenant.status, TenantStatus::Suspended);
    }

    #[tokio::test]
    async fn delete_sets_status() {
        let db = test_db().await;
        let id_bytes = insert_tenant(&db, "delete-me", "owner@example.com").await;
        let uuid = Uuid::from_slice(&id_bytes).unwrap();
        let tid = TenantId::from(uuid);
        db.delete_tenant(&tid).await.expect("delete");
        let tenant = db.tenant_by_id(&tid).await.expect("query").unwrap();
        assert_eq!(tenant.status, TenantStatus::Deleted);
    }

    #[tokio::test]
    async fn update_name_unknown_id() {
        let db = test_db().await;
        let tid = TenantId::new();
        let err = db
            .update_tenant_name(&tid, "Ghost".into())
            .await
            .err()
            .expect("expected error");
        assert!(matches!(err, SaasError::TenantNotFound));
    }
}
