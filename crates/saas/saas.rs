pub mod api_keys;
pub mod cache;
pub mod control_db;
pub mod dashboard;
pub mod error;
pub mod manage;
pub mod router;
pub mod tenants;

pub use api_keys::ApiKeyScope;
pub use cache::{HandleCache, SlugCache, TenantMeta};
pub use control_db::{ControlDb, TenantRole};
pub use dashboard::{
    DashboardSignupError, DashboardSignupParams, DashboardSignupResult, DashboardState,
    ProvisionForUserError, dashboard_cookie_name, dashboard_signup, provision_tenant_for_user,
};
pub use error::SaasError;
pub use manage::{ManageState, manage_router};
pub use router::{
    RequireActiveTenant, TenantRouterState, build_handle_with_path, pre_warm,
    tenant_router_middleware,
};
pub use tenants::{
    MemberId, PlanId, ProvisionResult, Tenant, TenantBuilderConfig, TenantId, TenantMember,
    TenantPlan, TenantStatus, tenant_cookie_name, validate_slug,
};
