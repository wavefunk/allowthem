use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::AuthError;
use crate::types::{PermissionName, RoleName, User};

/// Claims embedded in a generated JWT.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — the user's UUID as a string.
    pub sub: String,
    /// User's email address.
    pub email: String,
    /// Role names assigned to the user.
    pub roles: Vec<String>,
    /// Permission names available to the user.
    pub permissions: Vec<String>,
    /// Expiry time (Unix timestamp seconds).
    pub exp: i64,
    /// Issued-at time (Unix timestamp seconds).
    pub iat: i64,
    /// JWT ID — UUIDv7, unique per token.
    pub jti: String,
}

/// Configuration for JWT generation and validation.
pub struct JwtConfig {
    /// Symmetric secret used for HS256 signing.
    pub secret: String,
    /// How long generated tokens are valid.
    pub expiry: Duration,
    /// Optional issuer claim (`iss`). Not validated if `None`.
    pub issuer: Option<String>,
}

impl JwtConfig {
    pub fn new(secret: impl Into<String>, expiry: Duration) -> Self {
        Self {
            secret: secret.into(),
            expiry,
            issuer: None,
        }
    }
}

/// Generate an HS256-signed JWT for the given user.
///
/// The token contains the user's id, email, roles, and permissions as claims,
/// plus standard `exp`, `iat`, and a unique `jti`.
pub fn generate_token(
    user: &User,
    roles: &[RoleName],
    permissions: &[PermissionName],
    config: &JwtConfig,
) -> Result<String, AuthError> {
    let now = Utc::now();
    let iat = now.timestamp();
    let exp = (now + config.expiry).timestamp();

    let claims = Claims {
        sub: user.id.to_string(),
        email: user.email.as_str().to_string(),
        roles: roles.iter().map(|r| r.as_str().to_string()).collect(),
        permissions: permissions.iter().map(|p| p.as_str().to_string()).collect(),
        exp,
        iat,
        jti: Uuid::now_v7().to_string(),
    };

    let key = EncodingKey::from_secret(config.secret.as_bytes());
    encode(&Header::new(Algorithm::HS256), &claims, &key).map_err(|e| AuthError::Jwt(e.to_string()))
}

/// Validate an HS256 JWT and return its parsed claims.
///
/// Returns `AuthError::Jwt` if the signature is invalid, the token is expired,
/// or the token is otherwise malformed. Leeway is set to zero so expiry is
/// checked exactly.
pub fn validate_token(token: &str, config: &JwtConfig) -> Result<Claims, AuthError> {
    let key = DecodingKey::from_secret(config.secret.as_bytes());
    let mut validation = Validation::new(Algorithm::HS256);
    validation.leeway = 0;
    decode::<Claims>(token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|e| AuthError::Jwt(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Email, PermissionName, RoleName, User, UserId};

    fn test_user() -> User {
        User {
            id: UserId::new(),
            email: Email::new_unchecked("alice@example.com".to_string()),
            username: None,
            password_hash: None,
            email_verified: true,
            is_active: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn test_config() -> JwtConfig {
        JwtConfig::new("test-secret-key-for-hs256", Duration::hours(1))
    }

    #[test]
    fn test_generate_and_validate_round_trip() {
        let user = test_user();
        let roles = vec![RoleName::new("admin")];
        let permissions = vec![PermissionName::new("read:posts")];
        let config = test_config();

        let token = generate_token(&user, &roles, &permissions, &config).expect("generate token");

        let claims = validate_token(&token, &config).expect("validate token");

        assert_eq!(claims.sub, user.id.to_string());
        assert_eq!(claims.email, "alice@example.com");
    }

    #[test]
    fn test_expired_token_returns_error() {
        let user = test_user();
        let config = test_config();

        // Manually construct an already-expired token (exp in the past)
        let now = Utc::now();
        let claims = Claims {
            sub: user.id.to_string(),
            email: user.email.as_str().to_string(),
            roles: vec![],
            permissions: vec![],
            exp: (now - Duration::hours(2)).timestamp(),
            iat: (now - Duration::hours(3)).timestamp(),
            jti: Uuid::now_v7().to_string(),
        };
        let key = EncodingKey::from_secret(config.secret.as_bytes());
        let token =
            encode(&Header::new(Algorithm::HS256), &claims, &key).expect("encode expired token");

        let result = validate_token(&token, &config);
        assert!(result.is_err(), "expired token must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("jwt"), "error should mention jwt");
    }

    #[test]
    fn test_wrong_secret_returns_error() {
        let user = test_user();
        let config = test_config();
        let token = generate_token(&user, &[], &[], &config).expect("generate token");

        let wrong_config = JwtConfig::new("wrong-secret", Duration::hours(1));
        let result = validate_token(&token, &wrong_config);
        assert!(result.is_err(), "wrong secret must be rejected");
    }

    #[test]
    fn test_claims_contain_roles_and_permissions() {
        let user = test_user();
        let roles = vec![RoleName::new("admin"), RoleName::new("editor")];
        let permissions = vec![
            PermissionName::new("read:posts"),
            PermissionName::new("write:posts"),
        ];
        let config = test_config();

        let token = generate_token(&user, &roles, &permissions, &config).expect("generate token");
        let claims = validate_token(&token, &config).expect("validate token");

        assert_eq!(claims.roles, vec!["admin", "editor"]);
        assert_eq!(claims.permissions, vec!["read:posts", "write:posts"]);
    }

    #[test]
    fn test_jti_is_unique_per_token() {
        let user = test_user();
        let config = test_config();

        let token1 = generate_token(&user, &[], &[], &config).expect("generate token 1");
        let token2 = generate_token(&user, &[], &[], &config).expect("generate token 2");

        let claims1 = validate_token(&token1, &config).expect("validate token 1");
        let claims2 = validate_token(&token2, &config).expect("validate token 2");

        assert_ne!(
            claims1.jti, claims2.jti,
            "each token must have a unique jti"
        );
    }
}
