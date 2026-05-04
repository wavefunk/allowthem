pub mod access_tokens;
pub mod api_tokens;
pub mod applications;
pub mod audit;
pub mod auth_client;
pub mod authorization;
pub mod csrf;
pub mod db;
pub mod email;
pub mod email_render;
pub mod email_smtp;
pub mod email_verification;
pub mod email_webhook;
pub mod error;
pub mod event_sink;
pub mod events;
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
pub mod social_github;
pub mod social_google;
pub mod social_oidc;
mod social_provider_encrypt;
pub mod social_providers;
pub mod token_cleanup;
pub mod token_issuance;
pub mod totp;
pub mod types;
pub mod users;
pub mod webhook_sig;

pub use access_tokens::{AccessTokenClaims, has_scope};
pub use audit::{AuditEntry, AuditEvent};
pub use auth_client::{AuthClient, AuthFuture, EmbeddedAuthClient};
pub use csrf::{derive_csrf_token, verify_csrf_token};
pub use db::Db;
pub use email::{EmailMessage, EmailSender, EmailTemplate, LogEmailSender, NoopEmailSender};
pub use email_render::{EmailBranding, RenderedEmail, render as render_email};
pub use email_smtp::{SmtpConfig, SmtpEmailSender, SmtpTls};
pub use email_webhook::{WebhookEmailConfig, WebhookEmailSender};
pub use error::{AccessTokenError, AuthError};
pub use event_sink::{AuthEvent, EventSink, LoggingEventSink, NoopEventSink};
pub use events::{
    EventContext, LifecycleEvent, LifecycleEventReceiver, LifecycleEventSender, RegisteredEvent,
    RegistrationSource,
};
pub use handle::{AllowThem, AllowThemBuilder, BuildError, LoginOutcome, OnUserActive};
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
pub use social_github::GitHubSocialProvider;
pub use social_google::GoogleSocialProvider;
pub use social_oidc::{CustomOidcSocialProvider, DiscoveryDoc, DISCOVERY_TTL};
pub use social_providers::{
    ProviderType, SocialProvider, SocialProviderConfig, SocialProviderRow, SocialUserInfo,
    build_social_provider,
};
pub use token_issuance::{
    RefreshToken, TokenError, TokenResponse, compute_at_hash, exchange_authorization_code,
    exchange_refresh_token, generate_refresh_token, hash_refresh_token, mint_access_token,
    mint_id_token, verify_pkce_s256,
};
pub use types::*;
pub use webhook_sig::{SigError, sign_payload, verify_payload};

#[cfg(test)]
mod db_tests;
