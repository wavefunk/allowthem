//! Shared state for the dashboard handlers (signup, quickstart, and
//! tenant-scoped pages introduced in 99c.3+).

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use minijinja::Environment;
use tokio::sync::RwLock;

use allowthem_core::{AllowThem, EmailSender};
use allowthem_saas::{ControlDb, HandleCache, SlugCache, TenantBuilderConfig};

use super::QuickstartCache;

/// Filesystem statistics for the tenant data directory — used by the
/// super-admin health page (99c.6 §4.5).
#[allow(dead_code)] // Step 12 of 99c.6 wires the health page that reads these.
#[derive(Clone, Debug)]
pub struct FsStats {
    pub total_bytes: u64,
    /// `(file_stem, bytes)` pairs, pre-sorted descending by size, top 10.
    pub top: Vec<(String, u64)>,
}

/// Cached filesystem stats. Refreshed on a 60s window with a
/// read-then-write-with-double-check pattern inside the health handler.
pub type FsStatsCache = Arc<RwLock<Option<(Instant, FsStats)>>>;

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
    /// Shared email sender used by transactional flows (e.g. 99c.4's
    /// force-password-reset). Plumbed through `DashboardRouterState::from_signup`
    /// so the dashboard pages router gets the same `Arc` instance.
    pub email_sender: Arc<dyn EmailSender>,
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
    /// Slug cache from the tenant router middleware. Surfaced into
    /// `DashboardRouterState` so the super-admin health page (99c.6 §4.5)
    /// can read its `entry_count`.
    pub slug_cache: SlugCache,
    pub tenant_data_dir: PathBuf,
    pub tenant_config: Arc<TenantBuilderConfig>,
    pub templates: Arc<Environment<'static>>,
    /// Shared email sender — used by 99c.4's force-password-reset handler.
    pub email_sender: Arc<dyn EmailSender>,
    pub is_production: bool,
    pub base_domain: String,
    /// Cached filesystem stats for the tenant data dir (super-admin
    /// health page). 60s refresh window, populated lazily on first GET.
    pub fs_stats_cache: FsStatsCache,
}

impl DashboardRouterState {
    /// Construct from a `SignupState` plus the `SlugCache` shared with the
    /// tenant router middleware. The slug cache lives in
    /// `TenantRouterState`; the super-admin health page needs read access
    /// to its `entry_count`, so we plumb a clone in here.
    pub fn from_signup(s: SignupState, slug_cache: SlugCache) -> Self {
        Self {
            ath: s.ath,
            control_db: s.control_db,
            handle_cache: s.handle_cache,
            slug_cache,
            tenant_data_dir: s.tenant_data_dir,
            tenant_config: s.tenant_config,
            templates: s.templates,
            email_sender: s.email_sender,
            is_production: s.is_production,
            base_domain: s.base_domain,
            fs_stats_cache: Arc::new(RwLock::new(None)),
        }
    }
}
