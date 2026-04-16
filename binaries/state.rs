use std::sync::Arc;

use axum::extract::FromRef;
use minijinja::Environment;

use allowthem_core::{AllowThem, AuthClient};

#[derive(Clone)]
pub struct AppState {
    pub ath: AllowThem,
    pub auth_client: Arc<dyn AuthClient>,
    pub base_url: String,
    pub templates: Arc<Environment<'static>>,
    pub is_production: bool,
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
