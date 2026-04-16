use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use rand::TryRngCore;
use rand::rngs::OsRng;
use serde::Serialize;

use crate::error::AuthError;
use crate::types::{ApplicationId, ClientId, ClientSecret, PasswordHash, UserId};

/// An OIDC client application registered with allowthem.
///
/// `client_secret_hash` is skipped during serialization — the raw secret
/// is returned once at creation and is never retrievable again.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Application {
    pub id: ApplicationId,
    pub name: String,
    pub client_id: ClientId,
    #[serde(skip_serializing)]
    pub client_secret_hash: PasswordHash,
    pub redirect_uris: String,        // JSON array, parsed at the call site
    pub logo_url: Option<String>,
    pub primary_color: Option<String>,
    pub is_trusted: bool,
    pub created_by: Option<UserId>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Generate a new `client_id`: `ath_` + 24 random bytes base64url-encoded.
///
/// Produces a 36-character string (`ath_` + 32 base64url chars). 192 bits of
/// entropy from `OsRng` makes collision effectively impossible.
pub fn generate_client_id() -> ClientId {
    let mut bytes = [0u8; 24];
    OsRng.try_fill_bytes(&mut bytes).expect("OS RNG unavailable");
    let encoded = Base64UrlUnpadded::encode_string(&bytes);
    ClientId::new_unchecked(format!("ath_{encoded}"))
}

/// Generate a new client secret and its Argon2 hash.
///
/// Returns `(raw_secret, hash)`. The raw secret is shown once to the admin
/// and must never be stored. The hash is stored as `client_secret_hash`.
/// Reuses `password::hash_password` — a client secret is functionally a
/// high-entropy password and the security requirements are identical.
pub fn generate_client_secret() -> Result<(ClientSecret, PasswordHash), AuthError> {
    let mut bytes = [0u8; 32];
    OsRng.try_fill_bytes(&mut bytes).expect("OS RNG unavailable");
    let raw = Base64UrlUnpadded::encode_string(&bytes);
    let hash = crate::password::hash_password(&raw)?;
    Ok((ClientSecret::new_unchecked(raw), hash))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::password::verify_password;

    #[test]
    fn client_id_has_ath_prefix() {
        let id = generate_client_id();
        assert!(id.as_str().starts_with("ath_"), "client_id must start with ath_");
    }

    #[test]
    fn client_id_length_is_36() {
        let id = generate_client_id();
        assert_eq!(id.as_str().len(), 36, "ath_(4) + 32 base64url chars = 36");
    }

    #[test]
    fn client_id_chars_are_url_safe() {
        let id = generate_client_id();
        // base64url uses A-Z, a-z, 0-9, -, _ only (no +, /, =)
        let suffix = &id.as_str()[4..];
        assert!(
            suffix.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "client_id suffix must be URL-safe base64url: got {suffix}"
        );
    }

    #[test]
    fn two_client_ids_differ() {
        let a = generate_client_id();
        let b = generate_client_id();
        assert_ne!(a, b, "each client_id must be unique");
    }

    #[test]
    fn client_secret_verifies_round_trip() {
        let (secret, hash) = generate_client_secret().expect("generate_client_secret");
        let valid = verify_password(secret.as_str(), &hash).expect("verify_password");
        assert!(valid, "generated secret must verify against its own hash");
    }

    #[test]
    fn two_client_secrets_differ() {
        let (s1, _) = generate_client_secret().expect("secret 1");
        let (s2, _) = generate_client_secret().expect("secret 2");
        assert_ne!(s1.as_str(), s2.as_str(), "each secret must be unique");
    }

    #[test]
    fn wrong_secret_does_not_verify() {
        let (_, hash) = generate_client_secret().expect("generate_client_secret");
        let valid = verify_password("wrong-secret", &hash).expect("verify_password");
        assert!(!valid, "wrong secret must not verify");
    }
}
