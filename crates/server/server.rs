// allowthem-server: HTTP routes, middleware, and extractors

pub mod authorize_routes;
pub mod bearer;
pub mod csrf;
pub mod error;
pub mod extractors;
pub mod mfa_routes;
pub mod middleware;
pub mod oauth_bearer;
pub mod oauth_routes;
pub mod userinfo_route;
pub mod password_reset_routes;
pub mod well_known_routes;

pub use bearer::BearerAuthUser;
pub use oauth_bearer::{OAuthBearerError, OAuthBearerToken};
pub use userinfo_route::userinfo_route;
pub use csrf::{CsrfToken, csrf_middleware};
pub use error::AuthExtractError;
pub use extractors::{AuthUser, BrowserAdminUser, BrowserAuthUser, OptionalAuthUser};
pub use mfa_routes::mfa_routes;
pub use middleware::{require_auth, require_permission, require_role};
pub use oauth_routes::oauth_routes;
pub use password_reset_routes::password_reset_routes;
pub use well_known_routes::well_known_routes;
pub use authorize_routes::authorize_routes;
