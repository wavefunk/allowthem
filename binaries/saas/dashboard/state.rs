//! Shared state for the dashboard handlers (signup, quickstart, and
//! tenant-scoped pages introduced in 99c.3+).

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

/// HTTP-handler state for tenant-scoped dashboard pages (applications,
/// users, settings). Strict superset of `SignupState` minus
/// `quickstart_cache` — the dashboard-pages router doesn't need the
/// quickstart token cache.
///
/// `From<SignupState>` projects from the existing onboarding state so
/// `binaries/saas/main.rs` can compose both routers from one source of
/// truth.
#[allow(dead_code)] // Steps 8-10 of 99c.3 land the handlers that read every field.
#[derive(Clone)]
pub struct DashboardRouterState {
    pub ath: AllowThem,
    pub control_db: Arc<ControlDb>,
    pub handle_cache: HandleCache,
    pub tenant_data_dir: PathBuf,
    pub tenant_config: Arc<TenantBuilderConfig>,
    pub templates: Arc<Environment<'static>>,
    pub is_production: bool,
    pub base_domain: String,
}

impl From<SignupState> for DashboardRouterState {
    fn from(s: SignupState) -> Self {
        Self {
            ath: s.ath,
            control_db: s.control_db,
            handle_cache: s.handle_cache,
            tenant_data_dir: s.tenant_data_dir,
            tenant_config: s.tenant_config,
            templates: s.templates,
            is_production: s.is_production,
            base_domain: s.base_domain,
        }
    }
}
