//! Shared state for the dashboard onboarding handlers (signup + quickstart).

use std::path::PathBuf;
use std::sync::Arc;

use minijinja::Environment;

use allowthem_core::AllowThem;
use allowthem_saas::{ControlDb, HandleCache, TenantBuilderConfig};

use super::QuickstartCache;

/// State injected into signup + quickstart handlers via `axum::State`.
///
/// Cheap to clone: every field is either `Arc`, a `Clone`-cheap moka cache
/// handle, or a small owned value.
#[derive(Clone)]
pub struct SignupState {
    /// Dashboard `AllowThem` (backed by `dashboard.db`).
    pub ath: AllowThem,
    /// Control-plane DB used for `provision_tenant` + audit + slug lookup.
    pub control_db: Arc<ControlDb>,
    pub tenant_data_dir: PathBuf,
    pub tenant_config: Arc<TenantBuilderConfig>,
    /// Required so `SignupState` can be projected into the `DashboardState`
    /// that `dashboard_signup` takes — `DashboardState` has a `HandleCache`
    /// field. Cloning is cheap (Moka uses an inner Arc).
    pub handle_cache: HandleCache,
    pub quickstart_cache: QuickstartCache,
    pub base_domain: String,
    pub templates: Arc<Environment<'static>>,
    pub is_production: bool,
}
