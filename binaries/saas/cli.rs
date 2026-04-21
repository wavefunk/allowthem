use std::sync::Arc;

use clap::{Parser, Subcommand};
use eyre::Result;

use allowthem_saas::control_db::ControlDb;
use allowthem_saas::{ApiKeyScope, HandleCache, TenantBuilderConfig};

use crate::config::SaasConfig;

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
    }
    Ok(())
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
        })
    }

    fn test_saas_cfg() -> crate::config::SaasConfig {
        let mut cfg = crate::config::SaasConfig::default();
        cfg.tenant_data_dir = std::env::temp_dir().to_string_lossy().into();
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
