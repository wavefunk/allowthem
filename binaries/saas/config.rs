use std::net::SocketAddr;

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct SaasConfig {
    pub control_plane_db: String,
    pub tenant_data_dir: String,
    pub base_domain: String,
    pub listen: SocketAddr,
    pub is_production: bool,
    pub cache_max_size: u64,
    pub pre_migrate_count: u32,
    pub mfa_key_hex: String,
    pub signing_key_hex: String,
    pub csrf_key_hex: String,
}

impl Default for SaasConfig {
    fn default() -> Self {
        Self {
            control_plane_db: String::new(),
            tenant_data_dir: String::new(),
            base_domain: String::new(),
            listen: SocketAddr::from(([0, 0, 0, 0], 8080)),
            is_production: false,
            cache_max_size: 1000,
            pre_migrate_count: 0,
            mfa_key_hex: String::new(),
            signing_key_hex: String::new(),
            csrf_key_hex: String::new(),
        }
    }
}

pub fn load() -> Result<SaasConfig, Box<figment::Error>> {
    Figment::from(Serialized::defaults(SaasConfig::default()))
        .merge(Toml::file("allowthem-saas.toml"))
        .merge(Env::prefixed("ALLOWTHEM_SAAS__").split("__"))
        .extract()
        .map_err(Box::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saas_config_defaults() {
        let cfg = SaasConfig::default();
        assert_eq!(cfg.listen, SocketAddr::from(([0, 0, 0, 0], 8080)));
        assert_eq!(cfg.cache_max_size, 1000);
        assert_eq!(cfg.pre_migrate_count, 0);
        assert!(!cfg.is_production);
        assert!(cfg.control_plane_db.is_empty());
        assert!(cfg.mfa_key_hex.is_empty());
    }

    #[test]
    fn saas_config_env_override() {
        // SAFETY: test is single-threaded; no other threads read this env var
        unsafe { std::env::set_var("ALLOWTHEM_SAAS__LISTEN", "127.0.0.1:9090") };
        let cfg: SaasConfig = Figment::from(figment::providers::Serialized::defaults(
            SaasConfig::default(),
        ))
        .merge(figment::providers::Env::prefixed("ALLOWTHEM_SAAS__").split("__"))
        .extract()
        .unwrap();
        unsafe { std::env::remove_var("ALLOWTHEM_SAAS__LISTEN") };
        assert_eq!(cfg.listen, "127.0.0.1:9090".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn decode_hex_key_valid() {
        let hex = "a".repeat(64);
        let result = decode_hex_key(&hex);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 32);
    }

    #[test]
    fn decode_hex_key_wrong_length() {
        let hex = "a".repeat(62);
        assert!(decode_hex_key(&hex).is_err());
    }

    #[test]
    fn decode_hex_key_invalid_chars() {
        let hex = "z".repeat(64);
        assert!(decode_hex_key(&hex).is_err());
    }

    fn decode_hex_key(hex: &str) -> Result<[u8; 32], String> {
        let bytes = ::hex::decode(hex).map_err(|e| format!("invalid hex key: {e}"))?;
        bytes
            .try_into()
            .map_err(|_| "key must be exactly 32 bytes".to_string())
    }
}
