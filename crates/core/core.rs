pub mod access_tokens;
pub mod api_tokens;
pub mod applications;
pub mod authorization;
pub mod audit;
pub mod auth_client;
pub mod db;
pub mod email;
pub mod error;
pub mod handle;
pub mod invitations;
pub mod jwt;
mod mfa_encrypt;
pub mod oauth;
pub mod oauth_github;
pub mod oauth_google;
pub mod password;
pub mod password_reset;
pub mod permissions;
pub mod roles;
pub mod sessions;
pub mod signing_keys;
pub mod totp;
pub mod types;
pub mod users;

pub use audit::{AuditEntry, AuditEvent};
pub use auth_client::{AuthClient, AuthFuture, EmbeddedAuthClient};
pub use db::Db;
pub use email::{EmailMessage, EmailSender, LogEmailSender};
pub use error::AuthError;
pub use handle::{AllowThem, AllowThemBuilder, BuildError};
pub use invitations::Invitation;
pub use jwt::{Claims, JwtConfig, generate_token as generate_jwt, validate_token};
pub use oauth::{OAuthAccountInfo, OAuthProvider, OAuthStateInfo, OAuthUserInfo};
pub use oauth_github::GitHubProvider;
pub use oauth_google::GoogleProvider;
pub use sessions::{
    SessionConfig, generate_token, hash_token, parse_session_cookie, session_cookie,
};
pub use signing_keys::{
    JwkEntry, JwkSet, OidcDiscovery, SigningKey, build_discovery, build_jwks, decrypt_private_key,
};
pub use types::*;

#[cfg(test)]
mod db_tests;
