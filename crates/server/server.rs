// allowthem-server: HTTP routes, middleware, and extractors

pub mod bearer;
pub mod csrf;
pub mod error;
pub mod extractors;
pub mod mfa_routes;
pub mod middleware;
pub mod oauth_routes;
pub mod password_reset_routes;

pub use bearer::BearerAuthUser;
pub use csrf::{CsrfToken, csrf_middleware};
pub use error::AuthExtractError;
pub use extractors::{AuthUser, BrowserAuthUser, OptionalAuthUser};
pub use mfa_routes::mfa_routes;
pub use middleware::{require_auth, require_permission, require_role};
pub use oauth_routes::oauth_routes;
pub use password_reset_routes::password_reset_routes;
