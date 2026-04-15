#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("invalid email format")]
    InvalidEmail,

    #[error("not found")]
    NotFound,

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("invalid password hash: {0}")]
    InvalidPasswordHash(String),

    #[error("email error: {0}")]
    Email(String),

    #[error("jwt error: {0}")]
    Jwt(String),

    #[error("OAuth state invalid or expired")]
    OAuthStateMismatch,

    #[error("OAuth token exchange failed: {0}")]
    OAuthTokenExchange(String),

    #[error("OAuth user info fetch failed: {0}")]
    OAuthUserInfoFetch(String),

    #[error("OAuth HTTP error: {0}")]
    OAuthHttp(String),

    #[error("MFA not configured -- provide mfa_key to AllowThemBuilder")]
    MfaNotConfigured,

    #[error("MFA already enabled for this user")]
    MfaAlreadyEnabled,

    #[error("MFA not enabled for this user")]
    MfaNotEnabled,

    #[error("invalid TOTP code")]
    InvalidTotpCode,

    #[error("MFA encryption error: {0}")]
    MfaEncryption(String),
}
