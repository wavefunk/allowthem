use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;

use axum::extract::FromRef;
use dashmap::DashMap;
use minijinja::Environment;

use allowthem_core::{AllowThem, AuthClient, EmailSender};

#[derive(Clone)]
pub struct AppState {
    pub ath: AllowThem,
    pub auth_client: Arc<dyn AuthClient>,
    pub base_url: String,
    pub templates: Arc<Environment<'static>>,
    pub is_production: bool,
    pub login_attempts: Arc<DashMap<IpAddr, (u32, Instant)>>,
    pub max_login_attempts: u32,
    pub rate_limit_window_secs: u64,
    pub email_sender: Arc<dyn EmailSender>,
    pub oauth_providers: Vec<String>,
}

impl FromRef<AppState> for Arc<dyn AuthClient> {
    fn from_ref(state: &AppState) -> Self {
        state.auth_client.clone()
    }
}

impl FromRef<AppState> for AllowThem {
    fn from_ref(state: &AppState) -> Self {
        state.ath.clone()
    }
}
