// allowthem-server: HTTP routes, middleware, and extractors

pub mod authorize_routes;
pub mod branding;
pub mod bearer;
pub mod csrf;
pub mod error;
pub mod extractors;
pub mod mfa_routes;
pub mod middleware;
pub mod oauth_bearer;
pub mod oauth_routes;
pub mod password_reset_routes;
pub mod rate_limit;
pub mod token_route;
pub mod userinfo_route;
pub mod well_known_routes;

pub use branding::{compute_accent_variants, default_accents, lookup_branding};
pub use authorize_routes::{
    AuthorizeOutcome, AuthorizeParams, ConsentContext, ConsentNeededData, ValidatedAuthorize,
    authorize_post, check_authorization,
};
pub use bearer::BearerAuthUser;
pub use csrf::{CsrfToken, csrf_middleware};
pub use error::AuthExtractError;
pub use extractors::{AuthUser, BrowserAdminUser, BrowserAuthUser, OptionalAuthUser};
pub use mfa_routes::mfa_routes;
pub use middleware::{require_auth, require_permission, require_role};
pub use oauth_bearer::{OAuthBearerError, OAuthBearerToken};
pub use oauth_routes::oauth_routes;
pub use password_reset_routes::password_reset_routes;
pub use rate_limit::{AuthRateLimiter, Quota, extract_client_ip};
pub use token_route::token_route;
pub use userinfo_route::userinfo_route;
pub use well_known_routes::well_known_routes;
