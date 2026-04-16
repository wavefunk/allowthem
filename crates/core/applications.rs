use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use rand::TryRngCore;
use rand::rngs::OsRng;
use serde::Serialize;
use url::Url;

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
    pub redirect_uris: String, // JSON array, parsed at the call site
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
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG unavailable");
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
    OsRng
        .try_fill_bytes(&mut bytes)
        .expect("OS RNG unavailable");
    let raw = Base64UrlUnpadded::encode_string(&bytes);
    let hash = crate::password::hash_password(&raw)?;
    Ok((ClientSecret::new_unchecked(raw), hash))
}

impl Application {
    /// Parse the stored JSON `redirect_uris` string into a `Vec<String>`.
    ///
    /// Returns `AuthError::Database` if the stored value is malformed JSON.
    /// This indicates a data integrity error — the core layer always validates
    /// and serializes URIs correctly on write.
    pub fn redirect_uri_list(&self) -> Result<Vec<String>, AuthError> {
        serde_json::from_str(&self.redirect_uris)
            .map_err(|e| AuthError::Database(sqlx::Error::Decode(Box::new(e))))
    }
}

fn map_unique_violation(err: sqlx::Error) -> AuthError {
    if let sqlx::Error::Database(ref db_err) = err {
        let msg = db_err.message();
        if msg.contains("UNIQUE constraint failed") && msg.contains("client_id") {
            return AuthError::Conflict("client_id already exists".into());
        }
    }
    AuthError::Database(err)
}

/// Parameters for updating an application's mutable fields.
///
/// All fields are required. Fetch the current application first
/// to populate fields that should remain unchanged.
pub struct UpdateApplication {
    pub name: String,
    pub redirect_uris: Vec<String>,
    pub is_trusted: bool,
    pub is_active: bool,
    pub logo_url: Option<String>,
    pub primary_color: Option<String>,
}

/// Validate a list of redirect URIs for registration (create or update).
///
/// Rules (per RFC 6749 and RFC 8252):
/// - List must not be empty.
/// - Each URI must parse as an absolute URL (has a scheme).
/// - No fragment component — prohibited by RFC 6749 Section 3.1.2.
/// - HTTPS required, except `http://localhost` and `http://127.0.0.1`
///   (loopback URIs permitted per RFC 8252 Section 8.3).
///
/// Returns `AuthError::InvalidRedirectUri` with the offending URI on first failure.
pub fn validate_redirect_uris(uris: &[String]) -> Result<(), AuthError> {
    if uris.is_empty() {
        return Err(AuthError::InvalidRedirectUri(
            "redirect_uris must not be empty".into(),
        ));
    }
    for uri in uris {
        let parsed = Url::parse(uri)
            .map_err(|_| AuthError::InvalidRedirectUri(uri.clone()))?;
        if parsed.fragment().is_some() {
            return Err(AuthError::InvalidRedirectUri(uri.clone()));
        }
        let scheme = parsed.scheme();
        if scheme == "https" {
            continue;
        }
        if scheme == "http" {
            let host = parsed.host_str().unwrap_or("");
            if host == "localhost" || host == "127.0.0.1" {
                continue;
            }
        }
        return Err(AuthError::InvalidRedirectUri(uri.clone()));
    }
    Ok(())
}

/// Validate that `redirect_uri` exactly matches one of the registered URIs.
///
/// Used by the authorization endpoint (M39) to reject unregistered redirect targets.
/// Exact string match — no normalization, no wildcard expansion.
///
/// Returns `AuthError::InvalidRedirectUri` if `redirect_uri` is not in `registered`.
pub fn validate_redirect_uri(redirect_uri: &str, registered: &[String]) -> Result<(), AuthError> {
    if registered.iter().any(|r| r == redirect_uri) {
        Ok(())
    } else {
        Err(AuthError::InvalidRedirectUri(redirect_uri.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::password::verify_password;
    use crate::types::ApplicationId;

    #[test]
    fn client_id_has_ath_prefix() {
        let id = generate_client_id();
        assert!(
            id.as_str().starts_with("ath_"),
            "client_id must start with ath_"
        );
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
            suffix
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
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

    // validate_redirect_uris tests

    #[test]
    fn redirect_uri_empty_list_is_rejected() {
        let err = validate_redirect_uris(&[]).unwrap_err();
        assert!(matches!(err, AuthError::InvalidRedirectUri(_)));
    }

    #[test]
    fn redirect_uri_https_is_valid() {
        let uris = vec!["https://example.com/callback".to_string()];
        assert!(validate_redirect_uris(&uris).is_ok());
    }

    #[test]
    fn redirect_uri_http_localhost_is_valid() {
        let uris = vec!["http://localhost/callback".to_string()];
        assert!(validate_redirect_uris(&uris).is_ok());
    }

    #[test]
    fn redirect_uri_http_localhost_with_port_is_valid() {
        let uris = vec!["http://localhost:3000/callback".to_string()];
        assert!(validate_redirect_uris(&uris).is_ok());
    }

    #[test]
    fn redirect_uri_http_127_0_0_1_is_valid() {
        let uris = vec!["http://127.0.0.1:8080/callback".to_string()];
        assert!(validate_redirect_uris(&uris).is_ok());
    }

    #[test]
    fn redirect_uri_http_non_localhost_is_rejected() {
        let uris = vec!["http://example.com/callback".to_string()];
        let err = validate_redirect_uris(&uris).unwrap_err();
        assert!(matches!(err, AuthError::InvalidRedirectUri(_)));
    }

    #[test]
    fn redirect_uri_with_fragment_is_rejected() {
        let uris = vec!["https://example.com/callback#section".to_string()];
        let err = validate_redirect_uris(&uris).unwrap_err();
        assert!(matches!(err, AuthError::InvalidRedirectUri(_)));
    }

    #[test]
    fn redirect_uri_relative_is_rejected() {
        let uris = vec!["/callback".to_string()];
        let err = validate_redirect_uris(&uris).unwrap_err();
        assert!(matches!(err, AuthError::InvalidRedirectUri(_)));
    }

    // validate_redirect_uri tests

    #[test]
    fn redirect_uri_exact_match_passes() {
        let registered = vec!["https://example.com/callback".to_string()];
        assert!(validate_redirect_uri("https://example.com/callback", &registered).is_ok());
    }

    #[test]
    fn redirect_uri_not_in_registered_is_rejected() {
        let registered = vec!["https://example.com/callback".to_string()];
        let err = validate_redirect_uri("https://example.com/other", &registered).unwrap_err();
        assert!(matches!(err, AuthError::InvalidRedirectUri(_)));
    }

    // Application::redirect_uri_list tests

    #[test]
    fn redirect_uri_list_parses_valid_json() {
        let (_, hash) = generate_client_secret().expect("generate_client_secret");
        let app = Application {
            id: ApplicationId::new(),
            name: "Test".to_string(),
            client_id: generate_client_id(),
            client_secret_hash: hash,
            redirect_uris: r#"["https://example.com/callback","https://example.com/other"]"#
                .to_string(),
            logo_url: None,
            primary_color: None,
            is_trusted: false,
            created_by: None,
            is_active: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let list = app.redirect_uri_list().expect("redirect_uri_list");
        assert_eq!(
            list,
            vec![
                "https://example.com/callback".to_string(),
                "https://example.com/other".to_string(),
            ]
        );
    }

    #[test]
    fn redirect_uri_list_returns_error_on_malformed_json() {
        let (_, hash) = generate_client_secret().expect("generate_client_secret");
        let app = Application {
            id: ApplicationId::new(),
            name: "Test".to_string(),
            client_id: generate_client_id(),
            client_secret_hash: hash,
            redirect_uris: "not valid json".to_string(),
            logo_url: None,
            primary_color: None,
            is_trusted: false,
            created_by: None,
            is_active: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert!(matches!(app.redirect_uri_list(), Err(AuthError::Database(_))));
    }

    #[test]
    fn application_serialization_omits_secret() {
        let (_, hash) = generate_client_secret().expect("generate_client_secret");
        let app = Application {
            id: ApplicationId::new(),
            name: "Test App".to_string(),
            client_id: generate_client_id(),
            client_secret_hash: hash,
            redirect_uris: r#"["https://example.com/callback"]"#.to_string(),
            logo_url: None,
            primary_color: None,
            is_trusted: false,
            created_by: None,
            is_active: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let value = serde_json::to_value(&app).expect("serialize Application");
        assert!(
            value.get("client_secret_hash").is_none(),
            "client_secret_hash must not appear in serialized output"
        );
        assert!(
            value.get("client_id").is_some(),
            "client_id must appear in serialized output"
        );
    }
}
