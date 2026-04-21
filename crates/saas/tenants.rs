use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use sqlx::SqlitePool;
use uuid::Uuid;

use allowthem_core::applications::CreateApplicationParams;
use allowthem_core::types::ClientType;
use allowthem_core::{AllowThem, ClientSecret};

use crate::control_db::ControlDb;
use crate::error::{SaasError, map_slug_conflict};
use crate::router::is_reserved_slug;

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
    pub id: Vec<u8>, // UUIDv7 bytes (BLOB)
    pub name: String,
    pub slug: String,
    pub owner_email: String,
    pub plan_id: Vec<u8>, // opaque randomblob(16) from seed migration
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

/// SaaS-wide keys and base domain needed when building a tenant AllowThem handle.
pub struct TenantBuilderConfig {
    pub mfa_key: [u8; 32],
    pub signing_key: [u8; 32],
    pub csrf_key: [u8; 32],
    pub base_domain: String,
}

/// Result of a successful `provision_tenant` call.
pub struct ProvisionResult {
    pub tenant: Tenant,
    /// The AllowThem handle for the new tenant — hold this alive to keep the pool open.
    pub ath: AllowThem,
    pub client_id: String,
    pub client_secret: ClientSecret,
}

// ---------------------------------------------------------------------------
// RAII guard — deletes tenant DB files on drop unless disarmed.
// ---------------------------------------------------------------------------

struct TenantDbFileGuard {
    path: PathBuf,
    disarmed: bool,
}

impl TenantDbFileGuard {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            disarmed: false,
        }
    }

    fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for TenantDbFileGuard {
    fn drop(&mut self) {
        if self.disarmed {
            return;
        }
        for suffix in ["", "-wal", "-shm"] {
            let p = PathBuf::from(format!("{}{suffix}", self.path.display()));
            let _ = std::fs::remove_file(p);
        }
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

    pub async fn list_tenants(&self) -> Result<Vec<Tenant>, SaasError> {
        let rows = sqlx::query_as::<_, Tenant>(
            "SELECT id, name, slug, owner_email, plan_id, status, db_path, \
             last_seen_at, created_at, updated_at \
             FROM tenants WHERE status != 'deleted' ORDER BY created_at ASC",
        )
        .fetch_all(self.pool())
        .await?;
        Ok(rows)
    }
}

// ---------------------------------------------------------------------------
// Simple mutations
// ---------------------------------------------------------------------------

impl ControlDb {
    pub async fn update_tenant_name(&self, id: &TenantId, name: String) -> Result<(), SaasError> {
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
// Provisioning + update_tenant_slug
// ---------------------------------------------------------------------------

impl ControlDb {
    pub async fn provision_tenant(
        &self,
        name: String,
        slug: String,
        owner_email: String,
        tenant_data_dir: &Path,
        config: &TenantBuilderConfig,
    ) -> Result<ProvisionResult, SaasError> {
        use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};

        // Step 1: Validate slug.
        validate_slug(&slug)?;

        // Step 2: Begin control plane transaction.
        let mut tx = self.pool().begin().await?;

        // Step 3: Insert tenant row (status=active, plan=dev).
        let tenant_id = TenantId::new();
        let db_file = format!("{}.db", tenant_id.as_uuid());
        let inserted = sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             SELECT ?1, ?2, ?3, ?4, id, 'active', ?5 FROM tenant_plans WHERE name = 'dev'",
        )
        .bind(tenant_id.as_bytes())
        .bind(&name)
        .bind(&slug)
        .bind(&owner_email)
        .bind(&db_file)
        .execute(&mut *tx)
        .await
        .map_err(map_slug_conflict)?;

        // Guard: if 'dev' plan row is missing, the SELECT returns 0 rows →
        // INSERT is a no-op. Return an error before creating any files.
        if inserted.rows_affected() == 0 {
            return Err(SaasError::ProvisionFailed(
                "'dev' plan not found in tenant_plans".into(),
            ));
        }

        // Step 4: Create SQLite file. Guard auto-deletes on drop unless disarmed.
        // Declaration order is load-bearing (§0.4): file_guard must be declared before ath
        // so Rust's reverse drop order closes the pool before deleting the file on unwind.
        let full_path = tenant_data_dir.join(&db_file);
        let mut file_guard = TenantDbFileGuard::new(full_path.clone());

        let opts = SqliteConnectOptions::new()
            .filename(&full_path)
            .create_if_missing(true)
            .pragma("foreign_keys", "ON")
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(std::time::Duration::from_millis(5000));
        let pool = SqlitePool::connect_with(opts)
            .await
            .map_err(|e| SaasError::ProvisionFailed(e.to_string()))?;

        // Steps 5+6: Build handle — AllowThemBuilder::build() runs core migrations via Db::new.
        let ath = allowthem_core::AllowThemBuilder::with_pool(pool)
            .mfa_key(config.mfa_key)
            .signing_key(config.signing_key)
            .csrf_key(config.csrf_key)
            .base_url(format!("https://{}.{}", slug, config.base_domain))
            .cookie_domain(format!(".{}.{}", slug, config.base_domain))
            .build()
            .await
            .map_err(|e| SaasError::ProvisionFailed(e.to_string()))?;

        // Step 7: Create default OIDC application (ClientType::Confidential — §0.5).
        // validate_redirect_uris rejects empty slices; use a localhost placeholder.
        let (app, maybe_secret) = ath
            .db()
            .create_application(CreateApplicationParams {
                name: "Default OIDC Application".to_string(),
                client_type: ClientType::Confidential,
                redirect_uris: vec!["http://localhost/callback".to_string()],
                is_trusted: false,
                created_by: None,
                logo_url: None,
                primary_color: None,
            })
            .await?;
        // ClientType::Confidential always yields Some(ClientSecret).
        let client_secret = maybe_secret.expect("confidential app always has a secret");

        // Step 8: Commit. Disarm file guard after commit — no cleanup on success.
        tx.commit().await?;
        file_guard.disarm();

        // Step 9: Fetch tenant row (updated_at etc. populated by DB defaults).
        let tenant = self
            .tenant_by_id_raw(tenant_id.as_bytes())
            .await?
            .ok_or(SaasError::TenantNotFound)?;

        Ok(ProvisionResult {
            tenant,
            ath,
            client_id: app.client_id.to_string(),
            client_secret,
        })
    }

    pub async fn update_tenant_slug(
        &self,
        id: &TenantId,
        new_slug: String,
        tenant_pool: &SqlitePool,
    ) -> Result<(), SaasError> {
        validate_slug(&new_slug)?;

        let has_sessions: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM allowthem_sessions LIMIT 1)")
                .fetch_one(tenant_pool)
                .await?;

        if has_sessions {
            return Err(SaasError::SlugChangeAfterFirstLogin);
        }

        let rows = sqlx::query(
            "UPDATE tenants \
             SET slug = ?1, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
             WHERE id = ?2 AND status != 'deleted'",
        )
        .bind(&new_slug)
        .bind(id.as_bytes())
        .execute(self.pool())
        .await
        .map_err(map_slug_conflict)?;

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
        let tenant = db.tenant_by_id(&TenantId::from(uuid)).await.expect("query");
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

    // --- Commit 3: provisioning + update_slug ---

    fn test_builder_config() -> TenantBuilderConfig {
        TenantBuilderConfig {
            mfa_key: [1u8; 32],
            signing_key: [2u8; 32],
            csrf_key: [3u8; 32],
            base_domain: "test.local".into(),
        }
    }

    #[tokio::test]
    async fn provision_happy_path() {
        let db = test_db().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let config = test_builder_config();

        let result = db
            .provision_tenant(
                "Happy Corp".into(),
                "happy-corp".into(),
                "owner@happy.com".into(),
                dir.path(),
                &config,
            )
            .await
            .expect("provision_tenant");

        let tenant = db
            .tenant_by_slug("happy-corp")
            .await
            .expect("query")
            .expect("tenant must exist");
        assert_eq!(tenant.name, "Happy Corp");

        let db_file = dir.path().join(&tenant.db_path);
        assert!(db_file.exists(), "tenant db file must exist");

        assert!(!result.client_id.is_empty());
        assert!(!result.client_secret.as_str().is_empty());

        // ath handle alive — ping the DB
        let _count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM allowthem_applications")
            .fetch_one(result.ath.db().pool())
            .await
            .expect("db ping");
    }

    #[tokio::test]
    async fn provision_slug_conflict() {
        let db = test_db().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let config = test_builder_config();

        db.provision_tenant(
            "First".into(),
            "clash-slug".into(),
            "a@example.com".into(),
            dir.path(),
            &config,
        )
        .await
        .expect("first provision");

        let err = db
            .provision_tenant(
                "Second".into(),
                "clash-slug".into(),
                "b@example.com".into(),
                dir.path(),
                &config,
            )
            .await
            .err()
            .expect("expected error");

        assert!(matches!(err, SaasError::SlugTaken));
    }

    #[tokio::test]
    async fn provision_slug_invalid() {
        let db = test_db().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let config = test_builder_config();

        let err = db
            .provision_tenant(
                "Bad".into(),
                "12abc".into(),
                "x@example.com".into(),
                dir.path(),
                &config,
            )
            .await
            .err()
            .expect("expected error");

        assert!(matches!(err, SaasError::SlugInvalid(_)));
    }

    #[tokio::test]
    async fn provision_slug_reserved() {
        let db = test_db().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let config = test_builder_config();

        let err = db
            .provision_tenant(
                "Admin".into(),
                "admin".into(),
                "x@example.com".into(),
                dir.path(),
                &config,
            )
            .await
            .err()
            .expect("expected error");

        assert!(matches!(err, SaasError::SlugReserved));
    }

    #[tokio::test]
    async fn provision_unwind_no_row_on_slug_conflict() {
        let db = test_db().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let config = test_builder_config();

        db.provision_tenant(
            "First".into(),
            "conflict-test".into(),
            "a@example.com".into(),
            dir.path(),
            &config,
        )
        .await
        .expect("first provision");

        let _ = db
            .provision_tenant(
                "Second".into(),
                "conflict-test".into(),
                "b@example.com".into(),
                dir.path(),
                &config,
            )
            .await;

        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM tenants WHERE slug = 'conflict-test'")
                .fetch_one(db.pool())
                .await
                .expect("count query");
        assert_eq!(count, 1, "slug conflict must not leave a partial row");
    }

    #[tokio::test]
    async fn update_slug_no_sessions() {
        let db = test_db().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let config = test_builder_config();

        let result = db
            .provision_tenant(
                "Rename Corp".into(),
                "rename-corp".into(),
                "owner@rename.com".into(),
                dir.path(),
                &config,
            )
            .await
            .expect("provision");

        let tid = TenantId::from(result.tenant.id_as_uuid().unwrap());
        db.update_tenant_slug(&tid, "renamed-corp".into(), result.ath.db().pool())
            .await
            .expect("update_slug should succeed with no sessions");

        let tenant = db
            .tenant_by_id(&tid)
            .await
            .expect("query")
            .expect("tenant must exist");
        assert_eq!(tenant.slug, "renamed-corp");

        // Hold ath alive through all assertions.
        drop(result.ath);
    }

    #[tokio::test]
    async fn update_slug_with_sessions() {
        let db = test_db().await;
        let dir = tempfile::tempdir().expect("tempdir");
        let config = test_builder_config();

        let result = db
            .provision_tenant(
                "Session Corp".into(),
                "session-corp".into(),
                "owner@session.com".into(),
                dir.path(),
                &config,
            )
            .await
            .expect("provision");

        // Insert a user then a session to simulate first-login having occurred.
        let user_id = uuid::Uuid::now_v7().to_string();
        sqlx::query("INSERT INTO allowthem_users (id, email) VALUES (?1, 'test@session.com')")
            .bind(&user_id)
            .execute(result.ath.db().pool())
            .await
            .expect("insert user");
        let session_id = uuid::Uuid::now_v7().to_string();
        sqlx::query(
            "INSERT INTO allowthem_sessions \
             (id, user_id, token_hash, expires_at) \
             VALUES (?1, ?2, 'fakehash', strftime('%Y-%m-%dT%H:%M:%fZ','now','+1 day'))",
        )
        .bind(&session_id)
        .bind(&user_id)
        .execute(result.ath.db().pool())
        .await
        .expect("insert session");

        let tid = TenantId::from(result.tenant.id_as_uuid().unwrap());
        let err = db
            .update_tenant_slug(&tid, "new-slug".into(), result.ath.db().pool())
            .await
            .err()
            .expect("expected error");

        assert!(matches!(err, SaasError::SlugChangeAfterFirstLogin));

        // Hold ath alive through all assertions.
        drop(result.ath);
    }
}
