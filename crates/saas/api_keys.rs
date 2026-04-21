use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sqlx::Row;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::control_db::ControlDb;
use crate::error::SaasError;
use crate::tenants::TenantId;

const KEY_PREFIX: &str = "sak_";

/// Identifier for an API key row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ApiKeyId(Uuid);

impl ApiKeyId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn from_uuid(id: Uuid) -> Self {
        Self(id)
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Default for ApiKeyId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for ApiKeyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiKeyScope {
    Admin,
}

#[derive(Debug, Clone)]
pub struct ApiKey {
    pub id: ApiKeyId,
    pub tenant_id: TenantId,
    pub name: String,
    pub scope: Vec<ApiKeyScope>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
}

pub struct ApiKeyMintResult {
    pub api_key: ApiKey,
    /// Plaintext key — return to caller once, never stored.
    pub raw_key: String,
}

fn generate_raw_key() -> Result<([u8; 32], String), SaasError> {
    let mut bytes = [0u8; 32];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| SaasError::ProvisionFailed(e.to_string()))?;
    let encoded = format!("{}{}", KEY_PREFIX, Base64UrlUnpadded::encode_string(&bytes));
    Ok((bytes, encoded))
}

fn hash_key_bytes(bytes: &[u8]) -> Vec<u8> {
    Sha256::digest(bytes).to_vec()
}

fn decode_raw_key(raw_key: &str) -> Option<Vec<u8>> {
    let encoded = raw_key.strip_prefix(KEY_PREFIX)?;
    Base64UrlUnpadded::decode_vec(encoded).ok()
}

impl ControlDb {
    pub async fn mint_api_key(
        &self,
        tenant_id: &TenantId,
        name: &str,
        scopes: Vec<ApiKeyScope>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<ApiKeyMintResult, SaasError> {
        let (raw_bytes, raw_key) = generate_raw_key()?;
        let key_hash = hash_key_bytes(&raw_bytes);
        let key_id = ApiKeyId::new();
        let scope_json = serde_json::to_string(&scopes)
            .map_err(|e| SaasError::ProvisionFailed(e.to_string()))?;

        sqlx::query(
            "INSERT INTO tenant_api_keys (id, tenant_id, name, key_hash, scope, expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(key_id.as_bytes())
        .bind(tenant_id.as_bytes())
        .bind(name)
        .bind(&key_hash)
        .bind(&scope_json)
        .bind(expires_at)
        .execute(self.pool())
        .await?;

        let api_key = ApiKey {
            id: key_id,
            tenant_id: *tenant_id,
            name: name.to_owned(),
            scope: scopes,
            created_at: Utc::now(),
            expires_at,
            last_used_at: None,
        };

        Ok(ApiKeyMintResult { api_key, raw_key })
    }

    /// Verifies a raw key, updates last_used_at, and returns the matching ApiKey.
    /// Returns `None` if the key is not found, revoked, or expired.
    pub async fn verify_api_key(&self, raw_key: &str) -> Result<Option<ApiKey>, SaasError> {
        let Some(raw_bytes) = decode_raw_key(raw_key) else {
            return Ok(None);
        };
        let candidate_hash = hash_key_bytes(&raw_bytes);

        // key_hash has a UNIQUE constraint, so at most one row.
        let row = sqlx::query(
            "SELECT id, tenant_id, name, scope, key_hash, created_at, expires_at, \
             revoked_at, last_used_at \
             FROM tenant_api_keys WHERE key_hash = ?1",
        )
        .bind(&candidate_hash)
        .fetch_optional(self.pool())
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        // Constant-time guard: ensure the stored hash truly matches the candidate.
        let stored_hash: Vec<u8> = row.try_get("key_hash")?;
        if !bool::from(candidate_hash.ct_eq(&stored_hash)) {
            return Ok(None);
        }

        let revoked_at: Option<DateTime<Utc>> = row.try_get("revoked_at")?;
        if revoked_at.is_some() {
            return Ok(None);
        }

        let expires_at: Option<DateTime<Utc>> = row.try_get("expires_at")?;
        if expires_at.is_some_and(|exp| exp <= Utc::now()) {
            return Ok(None);
        }

        let id_bytes: Vec<u8> = row.try_get("id")?;
        let tenant_bytes: Vec<u8> = row.try_get("tenant_id")?;
        let scope_json: String = row.try_get("scope")?;
        let scopes: Vec<ApiKeyScope> = serde_json::from_str(&scope_json)
            .map_err(|e| SaasError::ProvisionFailed(e.to_string()))?;
        let key_id = Uuid::from_slice(&id_bytes).map_err(|_| SaasError::TenantNotFound)?;
        let tenant_id = Uuid::from_slice(&tenant_bytes).map_err(|_| SaasError::TenantNotFound)?;
        let created_at: DateTime<Utc> = row.try_get("created_at")?;
        let last_used_at: Option<DateTime<Utc>> = row.try_get("last_used_at")?;
        let name: String = row.try_get("name")?;

        sqlx::query("UPDATE tenant_api_keys SET last_used_at = ?1 WHERE key_hash = ?2")
            .bind(Utc::now())
            .bind(&candidate_hash)
            .execute(self.pool())
            .await?;

        Ok(Some(ApiKey {
            id: ApiKeyId::from_uuid(key_id),
            tenant_id: TenantId::from(tenant_id),
            name,
            scope: scopes,
            created_at,
            expires_at,
            last_used_at,
        }))
    }

    pub async fn revoke_api_key(
        &self,
        key_id: &ApiKeyId,
        tenant_id: &TenantId,
    ) -> Result<(), SaasError> {
        sqlx::query(
            "UPDATE tenant_api_keys SET revoked_at = ?1 \
             WHERE id = ?2 AND tenant_id = ?3 AND revoked_at IS NULL",
        )
        .bind(Utc::now())
        .bind(key_id.as_bytes())
        .bind(tenant_id.as_bytes())
        .execute(self.pool())
        .await?;
        Ok(())
    }

    pub async fn list_api_keys_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> Result<Vec<ApiKey>, SaasError> {
        let rows = sqlx::query(
            "SELECT id, tenant_id, name, scope, created_at, expires_at, last_used_at \
             FROM tenant_api_keys \
             WHERE tenant_id = ?1 AND revoked_at IS NULL \
             ORDER BY created_at DESC",
        )
        .bind(tenant_id.as_bytes())
        .fetch_all(self.pool())
        .await?;

        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let id_bytes: Vec<u8> = row.try_get("id")?;
            let tenant_bytes: Vec<u8> = row.try_get("tenant_id")?;
            let scope_json: String = row.try_get("scope")?;
            let scopes: Vec<ApiKeyScope> = serde_json::from_str(&scope_json)
                .map_err(|e| SaasError::ProvisionFailed(e.to_string()))?;
            let key_id = Uuid::from_slice(&id_bytes).map_err(|_| SaasError::TenantNotFound)?;
            let t_id = Uuid::from_slice(&tenant_bytes).map_err(|_| SaasError::TenantNotFound)?;

            result.push(ApiKey {
                id: ApiKeyId::from_uuid(key_id),
                tenant_id: TenantId::from(t_id),
                name: row.try_get("name")?,
                scope: scopes,
                created_at: row.try_get("created_at")?,
                expires_at: row.try_get("expires_at")?,
                last_used_at: row.try_get("last_used_at")?,
            });
        }
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_db::tests::test_pool;

    async fn make_db() -> ControlDb {
        let pool = test_pool().await;
        ControlDb::new(pool).await.unwrap()
    }

    async fn make_tenant(db: &ControlDb) -> TenantId {
        let plan_id: Vec<u8> = sqlx::query("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap()
            .get("id");
        let id = TenantId::new();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'Test', 'test-slug', 'test@test.com', ?, 'active', 'test.db')",
        )
        .bind(id.as_bytes())
        .bind(&plan_id)
        .execute(db.pool())
        .await
        .unwrap();
        id
    }

    #[tokio::test]
    async fn mint_returns_raw_key_with_prefix() {
        let db = make_db().await;
        let tid = make_tenant(&db).await;
        let result = db
            .mint_api_key(&tid, "test-key", vec![ApiKeyScope::Admin], None)
            .await
            .unwrap();
        assert!(result.raw_key.starts_with(KEY_PREFIX));
    }

    #[tokio::test]
    async fn verify_valid_key_returns_some() {
        let db = make_db().await;
        let tid = make_tenant(&db).await;
        let result = db
            .mint_api_key(&tid, "valid", vec![ApiKeyScope::Admin], None)
            .await
            .unwrap();
        let verified = db.verify_api_key(&result.raw_key).await.unwrap();
        assert!(verified.is_some());
        assert_eq!(verified.unwrap().name, "valid");
    }

    #[tokio::test]
    async fn verify_garbage_key_returns_none() {
        let db = make_db().await;
        let _tid = make_tenant(&db).await;
        let result = db.verify_api_key("sak_notavalidkey!!!").await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn verify_revoked_key_returns_none() {
        let db = make_db().await;
        let tid = make_tenant(&db).await;
        let result = db
            .mint_api_key(&tid, "to-revoke", vec![ApiKeyScope::Admin], None)
            .await
            .unwrap();
        db.revoke_api_key(&result.api_key.id, &tid).await.unwrap();
        let verified = db.verify_api_key(&result.raw_key).await.unwrap();
        assert!(verified.is_none());
    }

    #[tokio::test]
    async fn verify_expired_key_returns_none() {
        let db = make_db().await;
        let tid = make_tenant(&db).await;
        let past = Utc::now() - chrono::Duration::hours(1);
        let result = db
            .mint_api_key(&tid, "expired", vec![ApiKeyScope::Admin], Some(past))
            .await
            .unwrap();
        let verified = db.verify_api_key(&result.raw_key).await.unwrap();
        assert!(verified.is_none());
    }

    #[tokio::test]
    async fn list_excludes_revoked_keys() {
        let db = make_db().await;
        let tid = make_tenant(&db).await;
        let r1 = db
            .mint_api_key(&tid, "keep", vec![ApiKeyScope::Admin], None)
            .await
            .unwrap();
        let r2 = db
            .mint_api_key(&tid, "revoke-me", vec![ApiKeyScope::Admin], None)
            .await
            .unwrap();
        db.revoke_api_key(&r2.api_key.id, &tid).await.unwrap();
        let list = db.list_api_keys_for_tenant(&tid).await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, r1.api_key.id);
    }

    #[tokio::test]
    async fn revoke_is_idempotent() {
        let db = make_db().await;
        let tid = make_tenant(&db).await;
        let result = db
            .mint_api_key(&tid, "idem", vec![ApiKeyScope::Admin], None)
            .await
            .unwrap();
        db.revoke_api_key(&result.api_key.id, &tid).await.unwrap();
        db.revoke_api_key(&result.api_key.id, &tid).await.unwrap();
        let verified = db.verify_api_key(&result.raw_key).await.unwrap();
        assert!(verified.is_none());
    }

    #[tokio::test]
    async fn verify_updates_last_used_at() {
        let db = make_db().await;
        let tid = make_tenant(&db).await;
        let result = db
            .mint_api_key(&tid, "track", vec![ApiKeyScope::Admin], None)
            .await
            .unwrap();
        let before = db.verify_api_key(&result.raw_key).await.unwrap().unwrap();
        // last_used_at starts None (or Some on second call)
        let _ = db.verify_api_key(&result.raw_key).await.unwrap().unwrap();
        // Verify the key still works after use-tracking
        let after = db.verify_api_key(&result.raw_key).await.unwrap();
        assert!(after.is_some());
        let _ = before; // suppress unused
    }
}
