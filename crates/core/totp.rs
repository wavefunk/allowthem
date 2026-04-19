//! TOTP core: secret management, code validation, and recovery codes.

use chrono::Utc;
use rand::TryRngCore;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use totp_rs::{Algorithm, Secret, TOTP};

use crate::db::Db;
use crate::error::AuthError;
use crate::mfa_encrypt;
use crate::types::{MfaRecoveryCodeId, MfaSecretId, UserId};

const RECOVERY_CODE_COUNT: usize = 10;
const RECOVERY_CODE_LENGTH: usize = 8;
/// Unambiguous character set: no 0/O, 1/I/L
const RECOVERY_CHARSET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";

#[derive(Debug, Clone, sqlx::FromRow)]
struct MfaSecretRow {
    id: MfaSecretId,
    #[allow(dead_code)]
    user_id: UserId,
    secret: String, // encrypted
    enabled: bool,
    #[allow(dead_code)]
    created_at: chrono::DateTime<Utc>,
}

fn build_totp(secret_base32: &str) -> Result<TOTP, AuthError> {
    let secret_bytes = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .map_err(|e| AuthError::MfaEncryption(e.to_string()))?;
    TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes, None, String::new())
        .map_err(|e| AuthError::MfaEncryption(e.to_string()))
}

fn generate_recovery_code() -> String {
    let mut bytes = [0u8; RECOVERY_CODE_LENGTH];
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG unavailable");
    bytes
        .iter()
        .map(|b| RECOVERY_CHARSET[(*b as usize) % RECOVERY_CHARSET.len()] as char)
        .collect()
}

fn hash_mfa_challenge(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    format!("{digest:x}")
}

fn hash_recovery_code(code: &str) -> String {
    let normalized = code.to_ascii_uppercase();
    let digest = Sha256::digest(normalized.as_bytes());
    format!("{digest:x}")
}

/// Build an `otpauth://totp/` URI from a base32 secret.
///
/// The URI encodes the issuer, account name, algorithm, digits, and period.
/// M26 will render this as a QR code; this function only produces the string.
pub fn totp_uri(secret_base32: &str, account_name: &str, issuer: &str) -> String {
    let secret_bytes = Secret::Encoded(secret_base32.to_string())
        .to_bytes()
        .expect("totp_uri called with invalid secret");
    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        Some(issuer.to_string()),
        account_name.to_string(),
    )
    .expect("totp_uri called with invalid secret");
    totp.get_url()
}

impl Db {
    /// Retrieve a pending (non-enabled) MFA secret for a user.
    ///
    /// Returns `Some(base32_secret)` if a non-enabled secret exists, `None` otherwise.
    /// Used by the setup page to avoid regenerating the secret on every page load.
    pub async fn get_pending_mfa_secret(
        &self,
        user_id: UserId,
        mfa_key: &[u8; 32],
    ) -> Result<Option<String>, AuthError> {
        let row: Option<MfaSecretRow> = sqlx::query_as(
            "SELECT id, user_id, secret, enabled, created_at \
             FROM allowthem_mfa_secrets WHERE user_id = ? AND enabled = 0",
        )
        .bind(user_id)
        .fetch_optional(self.pool())
        .await?;

        match row {
            Some(r) => {
                let secret_bytes = mfa_encrypt::decrypt_secret(&r.secret, mfa_key)?;
                let secret_base32 = String::from_utf8(secret_bytes)
                    .map_err(|e| AuthError::MfaEncryption(e.to_string()))?;
                Ok(Some(secret_base32))
            }
            None => Ok(None),
        }
    }

    /// Generate a new TOTP secret for a user and store it (encrypted, not yet enabled).
    ///
    /// Returns the plaintext base32-encoded secret for display to the user
    /// during the setup flow. The caller must present this secret (or a QR code
    /// derived from it) and require the user to confirm with a valid code
    /// before calling `enable_mfa`.
    ///
    /// Fails with `MfaAlreadyEnabled` if the user already has an enabled MFA secret.
    /// If a non-enabled secret exists (abandoned setup attempt), it is replaced.
    pub async fn create_mfa_secret(
        &self,
        user_id: UserId,
        mfa_key: &[u8; 32],
    ) -> Result<String, AuthError> {
        let existing: Option<MfaSecretRow> = sqlx::query_as(
            "SELECT id, user_id, secret, enabled, created_at \
             FROM allowthem_mfa_secrets WHERE user_id = ?",
        )
        .bind(user_id)
        .fetch_optional(self.pool())
        .await?;

        if let Some(row) = existing {
            if row.enabled {
                return Err(AuthError::MfaAlreadyEnabled);
            }
            // Abandoned setup -- delete the old non-enabled secret
            sqlx::query("DELETE FROM allowthem_mfa_secrets WHERE id = ?")
                .bind(row.id)
                .execute(self.pool())
                .await?;
        }

        let secret = Secret::generate_secret();
        let secret_base32 = secret.to_encoded().to_string();

        let encrypted = mfa_encrypt::encrypt_secret(secret_base32.as_bytes(), mfa_key)?;
        let id = MfaSecretId::new();

        sqlx::query(
            "INSERT INTO allowthem_mfa_secrets (id, user_id, secret, enabled) \
             VALUES (?, ?, ?, 0)",
        )
        .bind(id)
        .bind(user_id)
        .bind(&encrypted)
        .execute(self.pool())
        .await?;

        Ok(secret_base32)
    }

    /// Enable MFA for a user after verifying a TOTP code.
    ///
    /// Decrypts the stored secret, validates the provided code against it,
    /// and if valid, sets `enabled = 1` and inserts 10 hashed recovery codes.
    /// Returns the plaintext recovery codes (this is the only time they are visible).
    ///
    /// Runs in a transaction to ensure MFA is never enabled without recovery codes.
    pub async fn enable_mfa(
        &self,
        user_id: UserId,
        code: &str,
        mfa_key: &[u8; 32],
    ) -> Result<Vec<String>, AuthError> {
        let mut tx = self.pool().begin().await.map_err(AuthError::Database)?;

        let row: MfaSecretRow = sqlx::query_as(
            "SELECT id, user_id, secret, enabled, created_at \
             FROM allowthem_mfa_secrets WHERE user_id = ? AND enabled = 0",
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(AuthError::Database)?
        .ok_or(AuthError::MfaNotEnabled)?;

        let secret_bytes = mfa_encrypt::decrypt_secret(&row.secret, mfa_key)?;
        let secret_base32 =
            String::from_utf8(secret_bytes).map_err(|e| AuthError::MfaEncryption(e.to_string()))?;
        let totp = build_totp(&secret_base32)?;

        if !totp
            .check_current(code)
            .map_err(|e| AuthError::MfaEncryption(e.to_string()))?
        {
            return Err(AuthError::InvalidTotpCode);
        }

        sqlx::query("UPDATE allowthem_mfa_secrets SET enabled = 1 WHERE id = ?")
            .bind(row.id)
            .execute(&mut *tx)
            .await
            .map_err(AuthError::Database)?;

        let mut plaintext_codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
        for _ in 0..RECOVERY_CODE_COUNT {
            let recovery = generate_recovery_code();
            let code_hash = hash_recovery_code(&recovery);
            let code_id = MfaRecoveryCodeId::new();

            sqlx::query(
                "INSERT INTO allowthem_mfa_recovery_codes (id, user_id, code_hash) \
                 VALUES (?, ?, ?)",
            )
            .bind(code_id)
            .bind(user_id)
            .bind(&code_hash)
            .execute(&mut *tx)
            .await
            .map_err(AuthError::Database)?;

            plaintext_codes.push(recovery);
        }

        tx.commit().await.map_err(AuthError::Database)?;

        Ok(plaintext_codes)
    }

    /// Validate a TOTP code against a user's enabled MFA secret.
    ///
    /// Returns `Ok(true)` if the code is valid, `Ok(false)` if invalid.
    /// Returns `Err(MfaNotEnabled)` if the user has no enabled MFA.
    pub async fn verify_totp(
        &self,
        user_id: UserId,
        code: &str,
        mfa_key: &[u8; 32],
    ) -> Result<bool, AuthError> {
        let row: MfaSecretRow = sqlx::query_as(
            "SELECT id, user_id, secret, enabled, created_at \
             FROM allowthem_mfa_secrets WHERE user_id = ? AND enabled = 1",
        )
        .bind(user_id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(AuthError::MfaNotEnabled)?;

        let secret_bytes = mfa_encrypt::decrypt_secret(&row.secret, mfa_key)?;
        let secret_base32 =
            String::from_utf8(secret_bytes).map_err(|e| AuthError::MfaEncryption(e.to_string()))?;
        let totp = build_totp(&secret_base32)?;

        totp.check_current(code)
            .map_err(|e| AuthError::MfaEncryption(e.to_string()))
    }

    /// Check whether a user has MFA enabled.
    pub async fn has_mfa_enabled(&self, user_id: UserId) -> Result<bool, AuthError> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM allowthem_mfa_secrets \
             WHERE user_id = ? AND enabled = 1",
        )
        .bind(user_id)
        .fetch_one(self.pool())
        .await?;

        Ok(count.0 > 0)
    }

    /// Disable MFA for a user. Deletes the secret and all recovery codes.
    ///
    /// Uses a transaction to ensure both deletes are atomic.
    pub async fn disable_mfa(&self, user_id: UserId) -> Result<(), AuthError> {
        let mut tx = self.pool().begin().await.map_err(AuthError::Database)?;

        sqlx::query("DELETE FROM allowthem_mfa_recovery_codes WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(AuthError::Database)?;

        sqlx::query("DELETE FROM allowthem_mfa_secrets WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(AuthError::Database)?;

        tx.commit().await.map_err(AuthError::Database)?;

        Ok(())
    }

    /// Verify a recovery code. If valid, marks it as used (one-time use).
    ///
    /// Uses atomic `UPDATE ... RETURNING` to prevent race conditions.
    /// Returns `Ok(true)` if the code was valid and consumed,
    /// `Ok(false)` if no matching unused code was found.
    pub async fn verify_recovery_code(
        &self,
        user_id: UserId,
        code: &str,
    ) -> Result<bool, AuthError> {
        let code_hash = hash_recovery_code(code);
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let row: Option<(MfaRecoveryCodeId,)> = sqlx::query_as(
            "UPDATE allowthem_mfa_recovery_codes SET used_at = ?1 \
             WHERE user_id = ?2 AND code_hash = ?3 AND used_at IS NULL \
             RETURNING id",
        )
        .bind(&now)
        .bind(user_id)
        .bind(&code_hash)
        .fetch_optional(self.pool())
        .await?;

        Ok(row.is_some())
    }

    /// Count remaining unused recovery codes for a user.
    pub async fn remaining_recovery_codes(&self, user_id: UserId) -> Result<i64, AuthError> {
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM allowthem_mfa_recovery_codes \
             WHERE user_id = ? AND used_at IS NULL",
        )
        .bind(user_id)
        .fetch_one(self.pool())
        .await?;

        Ok(count.0)
    }

    /// Replace all recovery codes with a fresh set of 10.
    ///
    /// Deletes all existing codes (used and unused) and inserts 10 new ones.
    /// Returns the plaintext codes. Runs in a transaction.
    pub async fn regenerate_recovery_codes(
        &self,
        user_id: UserId,
    ) -> Result<Vec<String>, AuthError> {
        let mut tx = self.pool().begin().await.map_err(AuthError::Database)?;

        sqlx::query("DELETE FROM allowthem_mfa_recovery_codes WHERE user_id = ?")
            .bind(user_id)
            .execute(&mut *tx)
            .await
            .map_err(AuthError::Database)?;

        let mut plaintext_codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
        for _ in 0..RECOVERY_CODE_COUNT {
            let code = generate_recovery_code();
            let code_hash = hash_recovery_code(&code);
            let code_id = MfaRecoveryCodeId::new();

            sqlx::query(
                "INSERT INTO allowthem_mfa_recovery_codes (id, user_id, code_hash) \
                 VALUES (?, ?, ?)",
            )
            .bind(code_id)
            .bind(user_id)
            .bind(&code_hash)
            .execute(&mut *tx)
            .await
            .map_err(AuthError::Database)?;

            plaintext_codes.push(code);
        }

        tx.commit().await.map_err(AuthError::Database)?;

        Ok(plaintext_codes)
    }

    /// Create a short-lived MFA challenge token after password verification.
    ///
    /// The integrator calls this when a user with MFA enabled passes password
    /// verification. Returns the raw token string to send to the client. The
    /// client presents this token along with a TOTP code to complete login.
    /// Challenge tokens expire after 5 minutes.
    pub async fn create_mfa_challenge(&self, user_id: UserId) -> Result<String, AuthError> {
        use crate::sessions::generate_token;
        use crate::types::MfaChallengeId;

        let token = generate_token();
        let token_hash = hash_mfa_challenge(token.as_str());
        let id = MfaChallengeId::new();
        let expires_at = Utc::now() + chrono::Duration::minutes(5);
        let expires_at_str = expires_at.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        sqlx::query(
            "INSERT INTO allowthem_mfa_challenges (id, token_hash, user_id, expires_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(id)
        .bind(&token_hash)
        .bind(user_id)
        .bind(&expires_at_str)
        .execute(self.pool())
        .await?;

        Ok(token.as_str().to_string())
    }

    /// Validate an MFA challenge token without consuming it.
    ///
    /// Returns `Some(user_id)` if the token is valid and not expired,
    /// `None` otherwise. Does not consume the token so the user can retry
    /// if they mistype the TOTP code.
    pub async fn validate_mfa_challenge(
        &self,
        raw_token: &str,
    ) -> Result<Option<UserId>, AuthError> {
        let token_hash = hash_mfa_challenge(raw_token);
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let row: Option<(UserId,)> = sqlx::query_as(
            "SELECT user_id FROM allowthem_mfa_challenges \
             WHERE token_hash = ? AND expires_at > ?",
        )
        .bind(&token_hash)
        .bind(&now)
        .fetch_optional(self.pool())
        .await?;

        Ok(row.map(|(uid,)| uid))
    }

    /// Consume an MFA challenge token after successful TOTP verification.
    ///
    /// Uses `DELETE ... RETURNING` for atomicity.
    pub async fn consume_mfa_challenge(&self, raw_token: &str) -> Result<(), AuthError> {
        let token_hash = hash_mfa_challenge(raw_token);

        sqlx::query("DELETE FROM allowthem_mfa_challenges WHERE token_hash = ?")
            .bind(&token_hash)
            .execute(self.pool())
            .await?;

        Ok(())
    }
}

use crate::handle::AllowThem;

impl AllowThem {
    pub async fn get_pending_mfa_secret(
        &self,
        user_id: UserId,
    ) -> Result<Option<String>, AuthError> {
        self.db()
            .get_pending_mfa_secret(user_id, self.mfa_key()?)
            .await
    }

    pub async fn create_mfa_secret(&self, user_id: UserId) -> Result<String, AuthError> {
        self.db().create_mfa_secret(user_id, self.mfa_key()?).await
    }

    pub async fn enable_mfa(&self, user_id: UserId, code: &str) -> Result<Vec<String>, AuthError> {
        self.db().enable_mfa(user_id, code, self.mfa_key()?).await
    }

    pub async fn verify_totp(&self, user_id: UserId, code: &str) -> Result<bool, AuthError> {
        self.db().verify_totp(user_id, code, self.mfa_key()?).await
    }

    pub async fn has_mfa_enabled(&self, user_id: UserId) -> Result<bool, AuthError> {
        self.db().has_mfa_enabled(user_id).await
    }

    pub async fn disable_mfa(&self, user_id: UserId) -> Result<(), AuthError> {
        self.db().disable_mfa(user_id).await
    }

    pub async fn verify_recovery_code(
        &self,
        user_id: UserId,
        code: &str,
    ) -> Result<bool, AuthError> {
        self.db().verify_recovery_code(user_id, code).await
    }

    pub async fn remaining_recovery_codes(&self, user_id: UserId) -> Result<i64, AuthError> {
        self.db().remaining_recovery_codes(user_id).await
    }

    pub async fn regenerate_recovery_codes(
        &self,
        user_id: UserId,
    ) -> Result<Vec<String>, AuthError> {
        self.db().regenerate_recovery_codes(user_id).await
    }
}

#[cfg(test)]
mod tests {
    use crate::db::Db;
    use crate::error::AuthError;
    use crate::handle::AllowThemBuilder;
    use crate::types::Email;

    use super::*;

    const TEST_MFA_KEY: [u8; 32] = [0x42; 32];

    async fn test_db() -> Db {
        Db::connect("sqlite::memory:").await.expect("in-memory db")
    }

    async fn make_user(db: &Db) -> UserId {
        let email = Email::new("mfa@example.com".to_string()).unwrap();
        db.create_user(email, "password123", None, None)
            .await
            .unwrap()
            .id
    }

    /// Helper: create MFA secret, generate a valid current code from it, enable MFA.
    /// Returns the recovery codes.
    async fn setup_and_enable_mfa(db: &Db, user_id: UserId) -> Vec<String> {
        let secret_b32 = db.create_mfa_secret(user_id, &TEST_MFA_KEY).await.unwrap();
        let totp = build_totp(&secret_b32).unwrap();
        let code = totp.generate_current().unwrap();
        db.enable_mfa(user_id, &code, &TEST_MFA_KEY).await.unwrap()
    }

    #[tokio::test]
    async fn totp_validation() {
        let secret = Secret::generate_secret();
        let secret_b32 = secret.to_encoded().to_string();
        let totp = build_totp(&secret_b32).unwrap();
        let code = totp.generate_current().unwrap();
        let valid = totp
            .check_current(&code)
            .expect("check_current should not fail");
        assert!(valid, "generated code must validate");
    }

    #[tokio::test]
    async fn totp_uri_format() {
        let secret = Secret::generate_secret();
        let secret_b32 = secret.to_encoded().to_string();
        let uri = totp_uri(&secret_b32, "user@example.com", "allowthem");
        assert!(
            uri.starts_with("otpauth://totp/"),
            "URI must start with otpauth://totp/"
        );
        assert!(
            uri.contains("user%40example.com"),
            "URI must contain account name"
        );
        assert!(uri.contains("allowthem"), "URI must contain issuer");
    }

    #[tokio::test]
    async fn create_and_enable_flow() {
        let db = test_db().await;
        let user_id = make_user(&db).await;

        let secret_b32 = db.create_mfa_secret(user_id, &TEST_MFA_KEY).await.unwrap();
        let totp = build_totp(&secret_b32).unwrap();
        let code = totp.generate_current().unwrap();

        let recovery_codes = db.enable_mfa(user_id, &code, &TEST_MFA_KEY).await.unwrap();
        assert_eq!(recovery_codes.len(), 10, "must return 10 recovery codes");

        let enabled = db.has_mfa_enabled(user_id).await.unwrap();
        assert!(enabled, "MFA must be enabled after enable_mfa");
    }

    #[tokio::test]
    async fn enable_rejects_wrong_code() {
        let db = test_db().await;
        let user_id = make_user(&db).await;
        db.create_mfa_secret(user_id, &TEST_MFA_KEY).await.unwrap();

        let result = db.enable_mfa(user_id, "000000", &TEST_MFA_KEY).await;
        assert!(
            matches!(result, Err(AuthError::InvalidTotpCode)),
            "wrong code must return InvalidTotpCode"
        );
    }

    #[tokio::test]
    async fn double_enable_blocked() {
        let db = test_db().await;
        let user_id = make_user(&db).await;
        setup_and_enable_mfa(&db, user_id).await;

        let result = db.create_mfa_secret(user_id, &TEST_MFA_KEY).await;
        assert!(
            matches!(result, Err(AuthError::MfaAlreadyEnabled)),
            "second create must return MfaAlreadyEnabled"
        );
    }

    #[tokio::test]
    async fn abandoned_setup_replacement() {
        let db = test_db().await;
        let user_id = make_user(&db).await;

        let secret_a = db.create_mfa_secret(user_id, &TEST_MFA_KEY).await.unwrap();
        let secret_b = db.create_mfa_secret(user_id, &TEST_MFA_KEY).await.unwrap();
        assert_ne!(secret_a, secret_b, "replacement must produce a new secret");

        // Enable with code from secret B
        let totp = build_totp(&secret_b).unwrap();
        let code = totp.generate_current().unwrap();
        let result = db.enable_mfa(user_id, &code, &TEST_MFA_KEY).await;
        assert!(result.is_ok(), "enable with new secret must succeed");
    }

    #[tokio::test]
    async fn verify_totp_valid_and_invalid() {
        let db = test_db().await;
        let user_id = make_user(&db).await;

        let secret_b32 = db.create_mfa_secret(user_id, &TEST_MFA_KEY).await.unwrap();
        let totp = build_totp(&secret_b32).unwrap();
        let code = totp.generate_current().unwrap();
        db.enable_mfa(user_id, &code, &TEST_MFA_KEY).await.unwrap();

        // Valid code
        let fresh_code = totp.generate_current().unwrap();
        let valid = db
            .verify_totp(user_id, &fresh_code, &TEST_MFA_KEY)
            .await
            .unwrap();
        assert!(valid, "correct TOTP code must validate");

        // Invalid code
        let invalid = db
            .verify_totp(user_id, "000000", &TEST_MFA_KEY)
            .await
            .unwrap();
        assert!(!invalid, "wrong TOTP code must return false");
    }

    #[tokio::test]
    async fn verify_totp_no_mfa() {
        let db = test_db().await;
        let user_id = make_user(&db).await;

        let result = db.verify_totp(user_id, "123456", &TEST_MFA_KEY).await;
        assert!(
            matches!(result, Err(AuthError::MfaNotEnabled)),
            "verify_totp on non-MFA user must return MfaNotEnabled"
        );
    }

    #[tokio::test]
    async fn recovery_code_consumption() {
        let db = test_db().await;
        let user_id = make_user(&db).await;
        let codes = setup_and_enable_mfa(&db, user_id).await;

        let consumed = db.verify_recovery_code(user_id, &codes[0]).await.unwrap();
        assert!(consumed, "valid recovery code must be consumed");

        let reuse = db.verify_recovery_code(user_id, &codes[0]).await.unwrap();
        assert!(!reuse, "used recovery code must not be reusable");

        let remaining = db.remaining_recovery_codes(user_id).await.unwrap();
        assert_eq!(remaining, 9, "one code consumed, 9 remaining");
    }

    #[tokio::test]
    async fn recovery_code_wrong() {
        let db = test_db().await;
        let user_id = make_user(&db).await;
        setup_and_enable_mfa(&db, user_id).await;

        let result = db.verify_recovery_code(user_id, "ZZZZZZZZ").await.unwrap();
        assert!(!result, "wrong recovery code must return false");
    }

    #[tokio::test]
    async fn recovery_code_case_insensitive() {
        let db = test_db().await;
        let user_id = make_user(&db).await;
        let codes = setup_and_enable_mfa(&db, user_id).await;

        let consumed = db
            .verify_recovery_code(user_id, &codes[1].to_lowercase())
            .await
            .unwrap();
        assert!(consumed, "lowercase recovery code must match");
    }

    #[tokio::test]
    async fn disable_mfa_cleans_up() {
        let db = test_db().await;
        let user_id = make_user(&db).await;
        setup_and_enable_mfa(&db, user_id).await;

        db.disable_mfa(user_id).await.unwrap();

        let enabled = db.has_mfa_enabled(user_id).await.unwrap();
        assert!(!enabled, "MFA must not be enabled after disable");

        let remaining = db.remaining_recovery_codes(user_id).await.unwrap();
        assert_eq!(remaining, 0, "recovery codes must be deleted");
    }

    #[tokio::test]
    async fn user_deletion_cascades() {
        let db = test_db().await;
        let user_id = make_user(&db).await;
        setup_and_enable_mfa(&db, user_id).await;

        db.delete_user(user_id).await.unwrap();

        let enabled = db.has_mfa_enabled(user_id).await.unwrap();
        assert!(!enabled, "MFA must not be enabled after user deletion");
    }

    #[tokio::test]
    async fn mfa_not_configured_without_key() {
        let ath = AllowThemBuilder::new("sqlite::memory:")
            .build()
            .await
            .unwrap();
        let email = Email::new("nokey@example.com".to_string()).unwrap();
        let user = ath
            .db()
            .create_user(email, "password123", None, None)
            .await
            .unwrap();

        let result = ath.create_mfa_secret(user.id).await;
        assert!(
            matches!(result, Err(AuthError::MfaNotConfigured)),
            "MFA without key must return MfaNotConfigured"
        );
    }
}
