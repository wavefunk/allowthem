//! Per-tenant email-sender configuration.
//!
//! Tenants pick one of three modes: `Managed` (default), `Smtp`, or
//! `Webhook`. The CRUD layer encrypts SMTP passwords and webhook
//! secrets at rest using AES-256-GCM via
//! [`crate::social_provider_encrypt`], mirroring the
//! `allowthem_social_providers` precedent (see plan §2.8 of
//! `docs/superpowers/plans/2026-05-04-managed-email.md`).
//!
//! Validation that the right override block is populated for each
//! mode is enforced by [`Db::set_email_config`]; the SQL schema only
//! constrains the discriminator and TLS values.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::Row;

use crate::db::Db;
use crate::error::AuthError;
use crate::social_provider_encrypt::{decrypt_split, encrypt_split};

// ── Mode + override types ────────────────────────────────────────────────────

/// Discriminator for the per-tenant email path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum EmailConfigMode {
    Managed,
    Smtp,
    Webhook,
}

/// SMTP TLS mode. Mirrors [`crate::email_smtp::SmtpTls`] but lives in
/// `email_config` so the storage form can `derive(sqlx::Type)` without
/// pulling email_smtp into a sqlx context.
///
/// `ImplicitTls` needs an explicit rename — the default
/// `lowercase` rule would emit `implicittls`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum SmtpTlsMode {
    None,
    StartTls,
    #[sqlx(rename = "implicit")]
    #[serde(rename = "implicit")]
    ImplicitTls,
}

#[derive(Debug, Clone)]
pub struct SmtpOverride {
    pub host: String,
    pub port: u16,
    pub username: Option<String>,
    /// Decrypted plaintext. Encrypted before INSERT inside
    /// [`Db::set_email_config`].
    pub password: Option<String>,
    pub from_address: String,
    pub tls: SmtpTlsMode,
}

#[derive(Debug, Clone)]
pub struct WebhookOverride {
    pub url: String,
    /// Decrypted HMAC-SHA256 signing secret. `None` disables signing.
    pub signing_secret: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ManagedOverride {
    /// Optional From-address override. When `None` the runtime composes
    /// `<local>@mail.<base_domain>` at send time.
    pub from_address: Option<String>,
}

/// Decrypted, runtime-form per-tenant email config.
#[derive(Debug, Clone)]
pub struct EmailConfig {
    pub mode: EmailConfigMode,
    pub smtp: Option<SmtpOverride>,
    pub webhook: Option<WebhookOverride>,
    pub managed: Option<ManagedOverride>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Plaintext setter input. Mirrors [`EmailConfig`] minus timestamps;
/// the Db method encrypts secrets before binding to the SQL columns.
#[derive(Debug, Clone)]
pub struct SetEmailConfig {
    pub mode: EmailConfigMode,
    pub smtp: Option<SmtpOverride>,
    pub webhook: Option<WebhookOverride>,
    pub managed: Option<ManagedOverride>,
}

// ── Db CRUD ──────────────────────────────────────────────────────────────────

impl Db {
    /// Read the per-tenant email config. Returns `None` when no row
    /// exists (the runtime treats this as `EmailConfigMode::Managed`
    /// with no overrides).
    ///
    /// Decryption uses `mfa_key`. Passing the wrong key surfaces as
    /// `AuthError::MfaEncryption`.
    pub async fn get_email_config(
        &self,
        mfa_key: &[u8; 32],
    ) -> Result<Option<EmailConfig>, AuthError> {
        let row_opt = sqlx::query(
            "SELECT mode, smtp_host, smtp_port, smtp_username, \
                    smtp_password_enc, smtp_password_nonce, smtp_from_address, smtp_tls, \
                    webhook_url, webhook_secret_enc, webhook_secret_nonce, \
                    managed_from_address, created_at, updated_at \
             FROM allowthem_email_config WHERE singleton = 'singleton'",
        )
        .fetch_optional(self.pool())
        .await?;

        let Some(row) = row_opt else { return Ok(None) };

        let mode: EmailConfigMode = row.try_get("mode")?;
        let created_at: DateTime<Utc> = row.try_get("created_at")?;
        let updated_at: DateTime<Utc> = row.try_get("updated_at")?;

        let smtp = if mode == EmailConfigMode::Smtp {
            let password_enc: Option<Vec<u8>> = row.try_get("smtp_password_enc")?;
            let password_nonce: Option<Vec<u8>> = row.try_get("smtp_password_nonce")?;
            let password = match (password_enc, password_nonce) {
                (Some(enc), Some(nonce)) => {
                    let bytes = decrypt_split(&nonce, &enc, mfa_key)?;
                    Some(String::from_utf8(bytes).map_err(|_| {
                        AuthError::MfaEncryption("smtp password not valid utf-8".into())
                    })?)
                }
                _ => None,
            };
            let host: String = row.try_get("smtp_host")?;
            let port_i: i64 = row.try_get("smtp_port")?;
            let port: u16 = u16::try_from(port_i)
                .map_err(|_| AuthError::Validation("smtp_port out of range".into()))?;
            let username: Option<String> = row.try_get("smtp_username")?;
            let from_address: String = row.try_get("smtp_from_address")?;
            let tls: SmtpTlsMode = row.try_get("smtp_tls")?;
            Some(SmtpOverride {
                host,
                port,
                username,
                password,
                from_address,
                tls,
            })
        } else {
            None
        };

        let webhook = if mode == EmailConfigMode::Webhook {
            let url: String = row.try_get("webhook_url")?;
            let secret_enc: Option<Vec<u8>> = row.try_get("webhook_secret_enc")?;
            let secret_nonce: Option<Vec<u8>> = row.try_get("webhook_secret_nonce")?;
            let signing_secret = match (secret_enc, secret_nonce) {
                (Some(enc), Some(nonce)) => Some(decrypt_split(&nonce, &enc, mfa_key)?),
                _ => None,
            };
            Some(WebhookOverride {
                url,
                signing_secret,
            })
        } else {
            None
        };

        let managed = if mode == EmailConfigMode::Managed {
            let from_address: Option<String> = row.try_get("managed_from_address")?;
            Some(ManagedOverride { from_address })
        } else {
            None
        };

        Ok(Some(EmailConfig {
            mode,
            smtp,
            webhook,
            managed,
            created_at,
            updated_at,
        }))
    }

    /// Upsert the per-tenant email config. Encrypts SMTP password and
    /// webhook secret before the INSERT. Validates that the override
    /// block matching `mode` is populated; mismatch returns
    /// `AuthError::Validation`.
    pub async fn set_email_config(
        &self,
        cfg: &SetEmailConfig,
        mfa_key: &[u8; 32],
    ) -> Result<(), AuthError> {
        // Per-mode field-presence validation. Cross-mode fields are
        // ignored by the SELECT projection so it's safe to leave them
        // populated, but a missing required block is a hard error.
        match cfg.mode {
            EmailConfigMode::Smtp if cfg.smtp.is_none() => {
                return Err(AuthError::Validation(
                    "mode=smtp requires smtp override".into(),
                ));
            }
            EmailConfigMode::Webhook if cfg.webhook.is_none() => {
                return Err(AuthError::Validation(
                    "mode=webhook requires webhook override".into(),
                ));
            }
            _ => {}
        }

        // Encrypt secrets (if present). Empty plaintext encrypts fine;
        // the runtime treats `Some("")` as "no auth" downstream.
        let (smtp_pw_enc, smtp_pw_nonce) = match cfg.smtp.as_ref().and_then(|s| s.password.as_ref())
        {
            Some(pw) => {
                let enc = encrypt_split(pw.as_bytes(), mfa_key)?;
                (Some(enc.ciphertext), Some(enc.nonce.to_vec()))
            }
            None => (None, None),
        };
        let (wh_secret_enc, wh_secret_nonce) =
            match cfg.webhook.as_ref().and_then(|w| w.signing_secret.as_ref()) {
                Some(secret) => {
                    let enc = encrypt_split(secret, mfa_key)?;
                    (Some(enc.ciphertext), Some(enc.nonce.to_vec()))
                }
                None => (None, None),
            };

        sqlx::query(
            "INSERT INTO allowthem_email_config \
                (singleton, mode, \
                 smtp_host, smtp_port, smtp_username, \
                 smtp_password_enc, smtp_password_nonce, smtp_from_address, smtp_tls, \
                 webhook_url, webhook_secret_enc, webhook_secret_nonce, \
                 managed_from_address, updated_at) \
             VALUES ('singleton', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, \
                     strftime('%Y-%m-%dT%H:%M:%fZ', 'now')) \
             ON CONFLICT (singleton) DO UPDATE SET \
                mode = excluded.mode, \
                smtp_host = excluded.smtp_host, \
                smtp_port = excluded.smtp_port, \
                smtp_username = excluded.smtp_username, \
                smtp_password_enc = excluded.smtp_password_enc, \
                smtp_password_nonce = excluded.smtp_password_nonce, \
                smtp_from_address = excluded.smtp_from_address, \
                smtp_tls = excluded.smtp_tls, \
                webhook_url = excluded.webhook_url, \
                webhook_secret_enc = excluded.webhook_secret_enc, \
                webhook_secret_nonce = excluded.webhook_secret_nonce, \
                managed_from_address = excluded.managed_from_address, \
                updated_at = excluded.updated_at",
        )
        .bind(cfg.mode)
        .bind(cfg.smtp.as_ref().map(|s| s.host.as_str()))
        .bind(cfg.smtp.as_ref().map(|s| s.port as i64))
        .bind(cfg.smtp.as_ref().and_then(|s| s.username.as_deref()))
        .bind(smtp_pw_enc)
        .bind(smtp_pw_nonce)
        .bind(cfg.smtp.as_ref().map(|s| s.from_address.as_str()))
        .bind(cfg.smtp.as_ref().map(|s| s.tls))
        .bind(cfg.webhook.as_ref().map(|w| w.url.as_str()))
        .bind(wh_secret_enc)
        .bind(wh_secret_nonce)
        .bind(cfg.managed.as_ref().and_then(|m| m.from_address.as_deref()))
        .execute(self.pool())
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::db::Db;

    const KEY_A: [u8; 32] = [7u8; 32];
    const KEY_B: [u8; 32] = [11u8; 32];

    async fn make_db() -> Db {
        // Anonymous on-disk via in-memory pool; Db::connect runs migrations.
        Db::connect("sqlite::memory:").await.unwrap()
    }

    #[tokio::test]
    async fn get_returns_none_when_no_row() {
        let db = make_db().await;
        assert!(db.get_email_config(&KEY_A).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn set_then_get_round_trips_managed() {
        let db = make_db().await;
        db.set_email_config(
            &SetEmailConfig {
                mode: EmailConfigMode::Managed,
                smtp: None,
                webhook: None,
                managed: Some(ManagedOverride {
                    from_address: Some("noreply@auth.acme.com".into()),
                }),
            },
            &KEY_A,
        )
        .await
        .unwrap();

        let cfg = db.get_email_config(&KEY_A).await.unwrap().unwrap();
        assert_eq!(cfg.mode, EmailConfigMode::Managed);
        assert!(cfg.smtp.is_none());
        assert!(cfg.webhook.is_none());
        assert_eq!(
            cfg.managed.unwrap().from_address.as_deref(),
            Some("noreply@auth.acme.com")
        );
    }

    #[tokio::test]
    async fn set_then_get_round_trips_smtp_with_decryption() {
        let db = make_db().await;
        let plaintext_pw = "hunter2!";
        db.set_email_config(
            &SetEmailConfig {
                mode: EmailConfigMode::Smtp,
                smtp: Some(SmtpOverride {
                    host: "smtp.example.com".into(),
                    port: 587,
                    username: Some("alice".into()),
                    password: Some(plaintext_pw.into()),
                    from_address: "noreply@example.com".into(),
                    tls: SmtpTlsMode::StartTls,
                }),
                webhook: None,
                managed: None,
            },
            &KEY_A,
        )
        .await
        .unwrap();

        // Decrypted round-trip.
        let cfg = db.get_email_config(&KEY_A).await.unwrap().unwrap();
        let smtp = cfg.smtp.unwrap();
        assert_eq!(smtp.password.as_deref(), Some(plaintext_pw));
        assert_eq!(smtp.tls, SmtpTlsMode::StartTls);

        // Ciphertext on disk must not equal plaintext.
        let raw_pw_enc: Vec<u8> =
            sqlx::query_scalar("SELECT smtp_password_enc FROM allowthem_email_config")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_ne!(raw_pw_enc.as_slice(), plaintext_pw.as_bytes());
    }

    #[tokio::test]
    async fn set_then_get_round_trips_webhook_with_decryption() {
        let db = make_db().await;
        let secret = b"hmac-secret-bytes".to_vec();
        db.set_email_config(
            &SetEmailConfig {
                mode: EmailConfigMode::Webhook,
                smtp: None,
                webhook: Some(WebhookOverride {
                    url: "https://hooks.acme.com/email".into(),
                    signing_secret: Some(secret.clone()),
                }),
                managed: None,
            },
            &KEY_A,
        )
        .await
        .unwrap();

        let cfg = db.get_email_config(&KEY_A).await.unwrap().unwrap();
        let webhook = cfg.webhook.unwrap();
        assert_eq!(webhook.url, "https://hooks.acme.com/email");
        assert_eq!(webhook.signing_secret.as_deref(), Some(secret.as_slice()));
    }

    #[tokio::test]
    async fn second_set_overwrites_first() {
        let db = make_db().await;
        db.set_email_config(
            &SetEmailConfig {
                mode: EmailConfigMode::Managed,
                smtp: None,
                webhook: None,
                managed: Some(ManagedOverride { from_address: None }),
            },
            &KEY_A,
        )
        .await
        .unwrap();
        db.set_email_config(
            &SetEmailConfig {
                mode: EmailConfigMode::Webhook,
                smtp: None,
                webhook: Some(WebhookOverride {
                    url: "https://x".into(),
                    signing_secret: None,
                }),
                managed: None,
            },
            &KEY_A,
        )
        .await
        .unwrap();

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM allowthem_email_config")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 1, "single-row guard must hold across upserts");

        let cfg = db.get_email_config(&KEY_A).await.unwrap().unwrap();
        assert_eq!(cfg.mode, EmailConfigMode::Webhook);
    }

    #[tokio::test]
    async fn set_rejects_smtp_mode_without_smtp_block() {
        let db = make_db().await;
        let err = db
            .set_email_config(
                &SetEmailConfig {
                    mode: EmailConfigMode::Smtp,
                    smtp: None,
                    webhook: None,
                    managed: None,
                },
                &KEY_A,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    #[tokio::test]
    async fn set_rejects_webhook_mode_without_webhook_block() {
        let db = make_db().await;
        let err = db
            .set_email_config(
                &SetEmailConfig {
                    mode: EmailConfigMode::Webhook,
                    smtp: None,
                    webhook: None,
                    managed: None,
                },
                &KEY_A,
            )
            .await
            .unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    #[tokio::test]
    async fn get_with_wrong_mfa_key_fails_decrypt() {
        let db = make_db().await;
        db.set_email_config(
            &SetEmailConfig {
                mode: EmailConfigMode::Smtp,
                smtp: Some(SmtpOverride {
                    host: "smtp.example.com".into(),
                    port: 587,
                    username: Some("alice".into()),
                    password: Some("hunter2".into()),
                    from_address: "noreply@example.com".into(),
                    tls: SmtpTlsMode::StartTls,
                }),
                webhook: None,
                managed: None,
            },
            &KEY_A,
        )
        .await
        .unwrap();

        let err = db.get_email_config(&KEY_B).await.unwrap_err();
        assert!(matches!(err, AuthError::MfaEncryption(_)));
    }
}
