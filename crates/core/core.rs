pub mod access_tokens;
pub mod csrf;
pub mod api_tokens;
pub mod applications;
pub mod audit;
pub mod auth_client;
pub mod authorization;
pub mod db;
pub mod email;
pub mod email_verification;
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
pub mod token_issuance;
pub mod totp;
pub mod types;
pub mod users;

pub use access_tokens::{AccessTokenClaims, has_scope};
pub use csrf::{derive_csrf_token, verify_csrf_token};
pub use audit::{AuditEntry, AuditEvent};
pub use auth_client::{AuthClient, AuthFuture, EmbeddedAuthClient};
pub use db::Db;
pub use email::{EmailMessage, EmailSender, LogEmailSender};
pub use error::{AccessTokenError, AuthError};
pub use handle::{AllowThem, AllowThemBuilder, BuildError, LoginOutcome};
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
pub use token_issuance::{
    RefreshToken, TokenError, TokenResponse, compute_at_hash, exchange_authorization_code,
    exchange_refresh_token, generate_refresh_token, hash_refresh_token, mint_access_token,
    mint_id_token, verify_pkce_s256,
};
pub use types::*;

#[cfg(test)]
mod db_tests;
