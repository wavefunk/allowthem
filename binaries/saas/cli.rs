use std::sync::Arc;

use clap::{Parser, Subcommand};
use eyre::Result;

use allowthem_saas::{ApiKeyScope, HandleCache, TenantBuilderConfig};
use allowthem_saas::control_db::ControlDb;

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
