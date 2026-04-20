/// Structured errors for RS256 access token validation.
///
/// Allows the server layer to map to specific OAuth2 error responses
/// without inspecting error message strings.
#[derive(Debug, thiserror::Error)]
pub enum AccessTokenError {
    #[error("token expired")]
    Expired,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("unknown signing key: {0}")]
    UnknownKid(String),
    #[error("invalid claims: {0}")]
    InvalidClaims(String),
    #[error("malformed token: {0}")]
    MalformedToken(String),
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("invalid email format")]
    InvalidEmail,

    #[error("not found")]
    NotFound,

    #[error("invalid credentials")]
    InvalidCredentials,

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

    #[error("resource already consumed")]
    Gone,

    #[error("forbidden: {0}")]
    Forbidden(String),

    #[error("signing key error: {0}")]
    SigningKey(String),

    #[error("signing key not configured -- provide signing_key to AllowThemBuilder")]
    SigningKeyNotConfigured,

    #[error("invalid redirect URI: {0}")]
    InvalidRedirectUri(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("invalid authorization request: {0}")]
    InvalidAuthorizationRequest(String),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("base URL not configured -- provide base_url to AllowThemBuilder")]
    BaseUrlNotConfigured,

    #[error("CSRF key not configured -- provide csrf_key to AllowThemBuilder")]
    CsrfKeyNotConfigured,

    #[error("access token error: {0}")]
    AccessToken(#[from] AccessTokenError),
}
