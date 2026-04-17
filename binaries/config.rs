use std::net::SocketAddr;

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct ServerConfig {
    pub database_url: String,
    pub bind: SocketAddr,
    pub base_url: String,
    pub cookie_secure: bool,
    pub cookie_domain: String,
    pub session_ttl_hours: u64,
    pub mfa_key_hex: Option<String>,
    pub signing_key_hex: Option<String>,
    pub is_production: bool,
    pub max_login_attempts: u32,
    pub rate_limit_window_secs: u64,
    pub oauth_mock: bool,
    pub google_client_id: Option<String>,
    pub google_client_secret: Option<String>,
    pub github_client_id: Option<String>,
    pub github_client_secret: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            database_url: "sqlite:allowthem.db?mode=rwc".into(),
            bind: SocketAddr::from(([127, 0, 0, 1], 3000)),
            base_url: "http://localhost:3000".into(),
            cookie_secure: true,
            cookie_domain: String::new(),
            session_ttl_hours: 24,
            mfa_key_hex: None,
            signing_key_hex: None,
            is_production: false,
            max_login_attempts: 10,
            rate_limit_window_secs: 900,
            oauth_mock: false,
            google_client_id: None,
            google_client_secret: None,
            github_client_id: None,
            github_client_secret: None,
        }
    }
}

pub fn load() -> Result<ServerConfig, Box<figment::Error>> {
    Figment::from(Serialized::defaults(ServerConfig::default()))
        .merge(Toml::file("allowthem.toml"))
        .merge(Env::prefixed("ALLOWTHEM_").split("__"))
        .extract()
        .map_err(Box::new)
}
