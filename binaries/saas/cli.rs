use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use eyre::Result;

use allowthem_core::Email;
use allowthem_core::error::AuthError;
use allowthem_core::types::RoleName;
use allowthem_saas::control_db::ControlDb;
use allowthem_saas::{ApiKeyScope, HandleCache, TenantBuilderConfig};

use crate::config::SaasConfig;
use crate::dashboard::open_dashboard_handle;

#[derive(Parser)]
#[command(name = "allowthem-saas")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    MintKey {
        #[arg(long)]
        tenant: String,
        #[arg(long)]
        name: String,
    },
    ProvisionTenant {
        #[arg(long)]
        slug: String,
        #[arg(long)]
        owner_email: String,
    },
    ListTenants,
    /// Create or promote a dashboard user to the `super_admin` role.
    ///
    /// Idempotent: re-running with the same email is a no-op except for an
    /// optional password reset (`--reset-password`). Bootstraps `dashboard.db`
    /// (creates + migrates) on first invocation.
    SeedAdmin {
        /// Email of the super-admin user.
        #[arg(long)]
        email: String,
        /// Inline password (visible in shell history).
        #[arg(long, conflicts_with = "password_stdin")]
        password: Option<String>,
        /// Read password from stdin (one trimmed line).
        #[arg(long)]
        password_stdin: bool,
        /// Reset the user's password if they already exist.
        #[arg(long)]
        reset_password: bool,
    },
}

pub fn parse() -> Option<Commands> {
    Cli::parse().command
}

pub async fn run(
    cmd: Commands,
    control_db: &Arc<ControlDb>,
    _handle_cache: &HandleCache,
    config: &Arc<TenantBuilderConfig>,
    cfg: &SaasConfig,
) -> Result<()> {
    match cmd {
        Commands::MintKey { tenant, name } => {
            let t = control_db
                .tenant_by_slug(&tenant)
                .await?
                .ok_or_else(|| eyre::eyre!("tenant '{tenant}' not found"))?;
            let tenant_id = t
                .id_as_uuid()
                .map(allowthem_saas::TenantId::from)
                .ok_or_else(|| eyre::eyre!("invalid tenant id bytes"))?;
            let result = control_db
                .mint_api_key(&tenant_id, &name, vec![ApiKeyScope::Admin], None)
                .await?;
            println!("{}", result.raw_key);
        }
        Commands::ProvisionTenant { slug, owner_email } => {
            use std::path::PathBuf;
            let result = control_db
                .provision_tenant(
                    slug.clone(),
                    slug.clone(),
                    owner_email,
                    &PathBuf::from(&cfg.tenant_data_dir),
                    config,
                )
                .await?;
            println!("provisioned: {}", result.tenant.id_as_uuid().unwrap());
        }
        Commands::ListTenants => {
            let tenants = control_db.list_tenants().await?;
            for t in tenants {
                let id = t.id_as_uuid().map(|u| u.to_string()).unwrap_or_default();
                println!("{}\t{}\t{:?}\t{}", id, t.slug, t.status, t.created_at);
            }
        }
        Commands::SeedAdmin {
            email,
            password,
            password_stdin,
            reset_password,
        } => {
            seed_admin(cfg, config, email, password, password_stdin, reset_password).await?;
        }
    }
    Ok(())
}

/// Source of the seeded user's password.
enum PasswordSource {
    Inline(String),
    Stdin,
    Generate,
}

impl PasswordSource {
    fn pick(inline: Option<String>, stdin: bool) -> Self {
        if let Some(p) = inline {
            Self::Inline(p)
        } else if stdin {
            Self::Stdin
        } else {
            Self::Generate
        }
    }
}

async fn seed_admin(
    cfg: &SaasConfig,
    config: &Arc<TenantBuilderConfig>,
    email: String,
    inline_password: Option<String>,
    password_stdin: bool,
    reset_password: bool,
) -> Result<()> {
    // Reuse the binary's runtime helper so the dashboard.db build stays
    // identical to what main.rs does at startup.
    let tenant_data_dir = PathBuf::from(&cfg.tenant_data_dir);
    let ath = open_dashboard_handle(
        &tenant_data_dir,
        &cfg.base_domain,
        cfg.is_production,
        config.mfa_key,
        config.signing_key,
        config.csrf_key,
    )
    .await?;

    let pw_source = PasswordSource::pick(inline_password, password_stdin);
    let password = resolve_password(pw_source)?;

    let email_obj = Email::new(email.clone()).map_err(|e| eyre::eyre!("invalid email: {e}"))?;

    let user = match ath.db().get_user_by_email(&email_obj).await {
        Ok(u) => {
            if reset_password {
                ath.db().update_user_password(u.id, &password).await?;
                tracing::info!(user_id = %u.id, "password reset");
            }
            u
        }
        Err(AuthError::NotFound) => {
            let u = ath
                .db()
                .create_user(email_obj.clone(), &password, None, None)
                .await?;
            ath.db().set_email_verified(u.id, true).await?;
            u
        }
        Err(e) => return Err(e.into()),
    };

    // Look up or create the `super_admin` role; assign idempotently.
    let role_name = RoleName::new("super_admin");
    let role = match ath.db().get_role_by_name(&role_name).await? {
        Some(r) => r,
        None => {
            ath.db()
                .create_role(&role_name, Some("Platform staff"))
                .await?
        }
    };
    ath.assign_role(&user.id, &role.id).await?;

    println!("super_admin granted to {email}");
    Ok(())
}

fn resolve_password(source: PasswordSource) -> Result<String> {
    use std::io::{BufRead, IsTerminal};

    match source {
        PasswordSource::Inline(p) => Ok(p),
        PasswordSource::Stdin => {
            let mut buf = String::new();
            std::io::stdin()
                .lock()
                .read_line(&mut buf)
                .map_err(|e| eyre::eyre!("read stdin: {e}"))?;
            Ok(buf.trim_end_matches(['\n', '\r']).to_owned())
        }
        PasswordSource::Generate => {
            if !std::io::stdout().is_terminal() {
                return Err(eyre::eyre!(
                    "stdout is not a TTY; pass --password or --password-stdin"
                ));
            }
            let p = generate_password(24)?;
            println!("Generated password (printed once — store it now): {p}");
            Ok(p)
        }
    }
}

fn generate_password(byte_len: usize) -> Result<String> {
    use base64ct::{Base64UrlUnpadded, Encoding};
    use rand::TryRngCore;

    let mut bytes = vec![0u8; byte_len];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| eyre::eyre!("rng: {e}"))?;
    Ok(Base64UrlUnpadded::encode_string(&bytes))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use allowthem_saas::TenantBuilderConfig;
    use allowthem_saas::control_db::ControlDb;

    async fn test_db() -> Arc<ControlDb> {
        use std::str::FromStr;
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .pragma("foreign_keys", "ON");
        let pool = sqlx::SqlitePool::connect_with(opts).await.unwrap();
        Arc::new(ControlDb::new(pool).await.expect("ControlDb::new"))
    }

    fn test_config() -> Arc<TenantBuilderConfig> {
        Arc::new(TenantBuilderConfig {
            mfa_key: [1u8; 32],
            signing_key: [2u8; 32],
            csrf_key: [3u8; 32],
            base_domain: "example.com".into(),
            is_production: false,
            email_sender: None,
        })
    }

    fn test_saas_cfg() -> crate::config::SaasConfig {
        let mut cfg = crate::config::SaasConfig::default();
        cfg.tenant_data_dir = std::env::temp_dir().to_string_lossy().into();
        cfg
    }

    /// Returns a fresh SaasConfig pointing at a tempdir that lives for the
    /// caller's scope. Use this for seed-admin tests so dashboard.db is
    /// recreated per-test.
    fn test_saas_cfg_in(dir: &tempfile::TempDir) -> crate::config::SaasConfig {
        let mut cfg = crate::config::SaasConfig::default();
        cfg.tenant_data_dir = dir.path().to_string_lossy().into();
        cfg.base_domain = "example.com".into();
        cfg.is_production = false;
        cfg
    }

    #[tokio::test]
    async fn mint_key_unknown_tenant() {
        let db = test_db().await;
        let cache = allowthem_saas::HandleCache::new(10);
        let cfg = test_saas_cfg();
        let config = test_config();

        let result = super::run(
            super::Commands::MintKey {
                tenant: "does-not-exist".into(),
                name: "test".into(),
            },
            &db,
            &cache,
            &config,
            &cfg,
        )
        .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn list_tenants_empty() {
        let db = test_db().await;
        let cache = allowthem_saas::HandleCache::new(10);
        let cfg = test_saas_cfg();
        let config = test_config();

        let result = super::run(super::Commands::ListTenants, &db, &cache, &config, &cfg).await;
        assert!(result.is_ok());
    }

    // -- seed-admin --------------------------------------------------------

    /// Helper: drive seed_admin with an inline password against a tempdir.
    async fn run_seed_admin_inline(
        dir: &tempfile::TempDir,
        email: &str,
        password: &str,
        reset: bool,
    ) -> eyre::Result<()> {
        let cfg = test_saas_cfg_in(dir);
        let config = test_config();
        super::seed_admin(
            &cfg,
            &config,
            email.to_string(),
            Some(password.to_string()),
            false,
            reset,
        )
        .await
    }

    /// Helper: open the dashboard handle pointing at the same tempdir so a
    /// test can verify side effects (user, role, role assignment).
    async fn open_dashboard_for_inspection(dir: &tempfile::TempDir) -> allowthem_core::AllowThem {
        crate::dashboard::open_dashboard_handle(
            dir.path(),
            "example.com",
            false,
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        )
        .await
        .expect("dashboard handle")
    }

    #[tokio::test]
    async fn seed_admin_creates_user_role_and_assignment() {
        use allowthem_core::Email;
        use allowthem_core::types::RoleName;

        let dir = tempfile::tempdir().unwrap();
        run_seed_admin_inline(&dir, "admin@example.com", "supersecret", false)
            .await
            .expect("seed-admin");

        let ath = open_dashboard_for_inspection(&dir).await;
        let user = ath
            .db()
            .get_user_by_email(&Email::new("admin@example.com".into()).unwrap())
            .await
            .expect("user exists");
        assert!(user.email_verified, "seeded user must be email_verified");

        let _role = ath
            .db()
            .get_role_by_name(&RoleName::new("super_admin"))
            .await
            .expect("query")
            .expect("super_admin role created");
        let has = ath
            .db()
            .has_role(&user.id, &RoleName::new("super_admin"))
            .await
            .unwrap();
        assert!(has, "user must have super_admin role assigned");
    }

    #[tokio::test]
    async fn seed_admin_idempotent() {
        use allowthem_core::types::RoleName;

        let dir = tempfile::tempdir().unwrap();
        run_seed_admin_inline(&dir, "admin@example.com", "supersecret", false)
            .await
            .expect("first seed");
        run_seed_admin_inline(&dir, "admin@example.com", "supersecret", false)
            .await
            .expect("re-run seed");

        let ath = open_dashboard_for_inspection(&dir).await;
        let users = ath.db().list_users().await.unwrap();
        assert_eq!(users.len(), 1, "only one dashboard user");

        let roles = ath.db().list_roles().await.unwrap();
        let super_admin_count = roles
            .iter()
            .filter(|r| r.name == RoleName::new("super_admin"))
            .count();
        assert_eq!(super_admin_count, 1, "only one super_admin role");
    }

    #[tokio::test]
    async fn seed_admin_no_password_source_in_non_tty_errors() {
        // No --password and no --password-stdin → fall through to the
        // "generate a password" branch. Cargo test runs with stdout NOT a
        // TTY, so the helper bails with the "not a TTY" error rather than
        // printing a generated password into the test log.
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_saas_cfg_in(&dir);
        let config = test_config();
        let result = super::seed_admin(
            &cfg,
            &config,
            "noinput@example.com".to_string(),
            None,
            false,
            false,
        )
        .await;
        let err = match result {
            Ok(()) => panic!("expected non-TTY error"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(msg.contains("not a TTY"), "unexpected error message: {msg}");
    }

    #[tokio::test]
    async fn seed_admin_invalid_email_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = test_saas_cfg_in(&dir);
        let config = test_config();
        let result = super::seed_admin(
            &cfg,
            &config,
            "not-an-email".to_string(),
            Some("supersecret".to_string()),
            false,
            false,
        )
        .await;
        let err = match result {
            Ok(()) => panic!("expected invalid-email error"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("invalid email"));
    }

    #[tokio::test]
    async fn seed_admin_reset_password_revokes_old() {
        use allowthem_core::error::AuthError;

        let dir = tempfile::tempdir().unwrap();
        run_seed_admin_inline(&dir, "admin@example.com", "oldpassword", false)
            .await
            .expect("first seed");
        run_seed_admin_inline(&dir, "admin@example.com", "newpassword", true)
            .await
            .expect("re-seed with reset");

        let ath = open_dashboard_for_inspection(&dir).await;
        // Old password no longer logs in.
        let res = ath.login("admin@example.com", "oldpassword").await;
        assert!(matches!(res, Err(AuthError::InvalidCredentials)));
        // New password works.
        let outcome = ath
            .login("admin@example.com", "newpassword")
            .await
            .expect("login with new password");
        assert_eq!(outcome.user.email.as_str(), "admin@example.com");
    }

    #[tokio::test]
    async fn mint_key_prints_token() {
        let db = test_db().await;
        let cache = allowthem_saas::HandleCache::new(10);
        let cfg = test_saas_cfg();
        let config = test_config();
        let tenant_data_dir = PathBuf::from(std::env::temp_dir());

        let pr = db
            .provision_tenant(
                "acme".into(),
                "acme".into(),
                "owner@acme.com".into(),
                &tenant_data_dir,
                &config,
            )
            .await
            .expect("provision");

        let result = super::run(
            super::Commands::MintKey {
                tenant: pr.tenant.slug.clone(),
                name: "ci-key".into(),
            },
            &db,
            &cache,
            &config,
            &cfg,
        )
        .await;
        assert!(result.is_ok());
    }
}
