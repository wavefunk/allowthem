// allowthem-server: HTTP routes, middleware, and extractors

pub mod all_routes;
#[cfg(test)]
mod all_server_templates_guard_tests;
#[cfg(test)]
mod auth_template_guard_tests;
pub mod authorize_routes;
pub mod bearer;
pub mod branding;
pub mod browser_error;
pub mod browser_templates;
pub mod consent_routes;
pub mod cors;
pub mod csrf;
pub mod custom_fields;
pub mod error;
pub(crate) mod events;
pub mod extractors;
pub mod hx;
pub mod login_routes;
pub mod logout_routes;
pub mod mfa_page_routes;
pub mod mfa_routes;
pub mod middleware;
pub mod nav;
pub mod oauth_bearer;
pub mod oauth_routes;
#[cfg(test)]
mod partials_tests;
pub mod password_reset_page_routes;
pub mod password_reset_routes;
pub mod rate_limit;
pub mod register_routes;
pub mod settings_routes;
pub mod shell_context;
pub mod static_routes;
pub mod token_route;
pub mod userinfo_route;
pub mod well_known_routes;

pub use all_routes::{AllRoutesBuilder, AllRoutesError};
pub use authorize_routes::{
    AuthorizeOutcome, AuthorizeParams, ConsentContext, ConsentNeededData, ValidatedAuthorize,
    authorize_post, check_authorization,
};
pub use bearer::BearerAuthUser;
pub use branding::{
    BrandingCtx, DEFAULT_ACCENT_HEX, DefaultBranding, derive_ink, lookup_branding, resolve_accent,
    resolve_branding,
};
pub use browser_error::BrowserError;
pub use browser_templates::{build_default_browser_env, render as render_template};
pub use consent_routes::consent_routes;
pub use cors::inject_ath_into_extensions;
pub use csrf::{CsrfToken, csrf_middleware};
pub use custom_fields::{CustomFieldDescriptor, CustomSchemaConfig, FieldType};
pub use error::AuthExtractError;
pub use extractors::{AuthUser, BrowserAdminUser, BrowserAuthUser, OptionalAuthUser};
pub use login_routes::login_routes;
pub use logout_routes::logout_routes;
pub use mfa_page_routes::{mfa_challenge_routes, mfa_setup_routes};
pub use mfa_routes::mfa_routes;
pub use middleware::{require_auth, require_permission, require_role};
pub use nav::{NavGroup, NavItem, nav_items_for};
pub use oauth_bearer::{OAuthBearerError, OAuthBearerToken};
pub use oauth_routes::oauth_routes;
pub use password_reset_page_routes::password_reset_page_routes;
pub use password_reset_routes::password_reset_routes;
pub use rate_limit::{AuthRateLimiter, Quota, extract_client_ip};
pub use register_routes::register_routes;
pub use settings_routes::settings_routes;
pub use shell_context::ShellContext;
pub use static_routes::router as static_router;
pub use token_route::token_route;
pub use userinfo_route::userinfo_route;
pub use well_known_routes::well_known_routes;
