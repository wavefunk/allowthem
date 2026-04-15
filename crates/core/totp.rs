//! TOTP core: secret management, code validation, and recovery codes.

use chrono::Utc;
use rand::rngs::OsRng;
use rand::TryRngCore;
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
    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret_bytes,
        None,
        String::new(),
    )
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
}
