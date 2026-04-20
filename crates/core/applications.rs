use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use rand::TryRngCore;
use rand::rngs::OsRng;
use serde::Serialize;
use url::Url;

use crate::db::Db;
use crate::error::AuthError;
use crate::types::{ApplicationId, ClientId, ClientSecret, ClientType, PasswordHash, UserId};

/// An OIDC client application registered with allowthem.
///
/// `client_secret_hash` is skipped during serialization — the raw secret
/// is returned once at creation and is never retrievable again.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct Application {
    pub id: ApplicationId,
    pub name: String,
    pub client_id: ClientId,
    pub client_type: ClientType,
    #[serde(skip_serializing)]
    pub client_secret_hash: Option<PasswordHash>,
    pub redirect_uris: String, // JSON array, parsed at the call site
    pub logo_url: Option<String>,
    pub primary_color: Option<String>,
    pub is_trusted: bool,
    pub created_by: Option<UserId>,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Branding configuration for an application's hosted auth pages.
///
/// Extracted from `Application` — contains only the fields needed to
/// theme login, register, consent, and other OIDC-flow pages.
///
/// Derives `sqlx::FromRow` for use with `query_as` in
/// `get_branding_by_client_id`. The SQL query aliases `name` to
/// `application_name` to match the struct field.
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct BrandingConfig {
    pub application_name: String,
    pub logo_url: Option<String>,
    pub primary_color: Option<String>,
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

    /// Extract the branding configuration for use in themed auth pages.
    pub fn branding(&self) -> BrandingConfig {
        BrandingConfig {
            application_name: self.name.clone(),
            logo_url: self.logo_url.clone(),
            primary_color: self.primary_color.clone(),
        }
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
        let parsed = Url::parse(uri).map_err(|_| AuthError::InvalidRedirectUri(uri.clone()))?;
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

/// Validate a logo URL for branding.
///
/// Must be an absolute URL with HTTPS scheme. HTTP is permitted for
/// localhost and 127.0.0.1 (development loopback exception, matching
/// redirect URI validation).
pub fn validate_logo_url(url: &str) -> Result<(), AuthError> {
    let parsed = Url::parse(url)
        .map_err(|_| AuthError::Validation("logo_url must be a valid absolute URL".into()))?;
    let scheme = parsed.scheme();
    if scheme == "https" {
        return Ok(());
    }
    if scheme == "http" {
        let host = parsed.host_str().unwrap_or("");
        if host == "localhost" || host == "127.0.0.1" {
            return Ok(());
        }
    }
    Err(AuthError::Validation(
        "logo_url must be an HTTPS URL".into(),
    ))
}

/// Validate a primary color for branding.
///
/// Must be a 7-character CSS hex color: `#` followed by exactly 6 hex
/// digits (e.g., `#3B82F6`). This format is safe for injection into
/// HTML `style` attributes without escaping.
pub fn validate_primary_color(color: &str) -> Result<(), AuthError> {
    let bytes = color.as_bytes();
    if bytes.len() != 7 || bytes[0] != b'#' {
        return Err(AuthError::Validation(
            "primary_color must be a hex color (#RRGGBB)".into(),
        ));
    }
    if !bytes[1..].iter().all(|b| b.is_ascii_hexdigit()) {
        return Err(AuthError::Validation(
            "primary_color must be a hex color (#RRGGBB)".into(),
        ));
    }
    Ok(())
}

impl Db {
    /// Register a new OIDC application.
    ///
    /// Generates a `client_id` and `client_secret`, hashes the secret, and inserts
    /// the row. Returns the persisted `Application` and the raw `ClientSecret`.
    /// The raw secret is shown once and is not recoverable — the caller must present
    /// it to the admin immediately.
    ///
    /// Validates `redirect_uris` before inserting. Returns `AuthError::InvalidRedirectUri`
    /// if any URI fails validation.
    #[allow(clippy::too_many_arguments)]
    pub async fn create_application(
        &self,
        name: String,
        client_type: ClientType,
        redirect_uris: Vec<String>,
        is_trusted: bool,
        created_by: Option<UserId>,
        logo_url: Option<String>,
        primary_color: Option<String>,
    ) -> Result<(Application, Option<ClientSecret>), AuthError> {
        validate_redirect_uris(&redirect_uris)?;
        if let Some(ref url) = logo_url {
            validate_logo_url(url)?;
        }
        if let Some(ref color) = primary_color {
            validate_primary_color(color)?;
        }
        let id = ApplicationId::new();
        let client_id = generate_client_id();
        let (raw_secret, hash) = match client_type {
            ClientType::Confidential => {
                let (secret, hash) = generate_client_secret()?;
                (Some(secret), Some(hash))
            }
            ClientType::Public => (None, None),
        };
        let redirect_uris_json =
            serde_json::to_string(&redirect_uris).expect("Vec<String> serializes to JSON");
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        sqlx::query(
            "INSERT INTO allowthem_applications \
             (id, name, client_id, client_type, client_secret_hash, redirect_uris, logo_url, \
              primary_color, is_trusted, created_by, is_active, created_at, updated_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 1, ?11, ?11)",
        )
        .bind(id)
        .bind(&name)
        .bind(&client_id)
        .bind(client_type)
        .bind(&hash)
        .bind(&redirect_uris_json)
        .bind(&logo_url)
        .bind(&primary_color)
        .bind(is_trusted)
        .bind(created_by)
        .bind(&now)
        .execute(self.pool())
        .await
        .map_err(map_unique_violation)?;

        let app = self.get_application(id).await?;
        Ok((app, raw_secret))
    }

    /// Get an application by internal ID.
    pub async fn get_application(&self, id: ApplicationId) -> Result<Application, AuthError> {
        sqlx::query_as::<_, Application>(
            "SELECT id, name, client_id, client_type, client_secret_hash, redirect_uris, \
             logo_url, primary_color, is_trusted, created_by, is_active, \
             created_at, updated_at \
             FROM allowthem_applications WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(AuthError::NotFound)
    }

    /// Get an application by its public client_id.
    ///
    /// Used by OAuth endpoints that receive client_id in request parameters.
    pub async fn get_application_by_client_id(
        &self,
        client_id: &ClientId,
    ) -> Result<Application, AuthError> {
        sqlx::query_as::<_, Application>(
            "SELECT id, name, client_id, client_type, client_secret_hash, redirect_uris, \
             logo_url, primary_color, is_trusted, created_by, is_active, \
             created_at, updated_at \
             FROM allowthem_applications WHERE client_id = ?",
        )
        .bind(client_id)
        .fetch_optional(self.pool())
        .await?
        .ok_or(AuthError::NotFound)
    }

    /// Get branding configuration for an application by client_id.
    ///
    /// Returns `None` if no application with the given `client_id` exists
    /// or if the application is inactive. Branded pages fall back to
    /// default allowthem styling when this returns `None`.
    pub async fn get_branding_by_client_id(
        &self,
        client_id: &ClientId,
    ) -> Result<Option<BrandingConfig>, AuthError> {
        sqlx::query_as::<_, BrandingConfig>(
            "SELECT name AS application_name, logo_url, primary_color \
             FROM allowthem_applications \
             WHERE client_id = ? AND is_active = 1",
        )
        .bind(client_id)
        .fetch_optional(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// List all applications ordered by `created_at ASC`.
    pub async fn list_applications(&self) -> Result<Vec<Application>, AuthError> {
        sqlx::query_as::<_, Application>(
            "SELECT id, name, client_id, client_type, client_secret_hash, redirect_uris, \
             logo_url, primary_color, is_trusted, created_by, is_active, \
             created_at, updated_at \
             FROM allowthem_applications ORDER BY created_at ASC",
        )
        .fetch_all(self.pool())
        .await
        .map_err(AuthError::Database)
    }

    /// Update an application's mutable fields.
    ///
    /// Validates `redirect_uris`, serializes them to JSON, and writes all six
    /// mutable fields atomically. Caller is responsible for fetching the current
    /// application and populating unchanged fields.
    ///
    /// Returns `AuthError::NotFound` if no application with `id` exists.
    /// Returns `AuthError::InvalidRedirectUri` if any URI fails validation.
    pub async fn update_application(
        &self,
        id: ApplicationId,
        params: UpdateApplication,
    ) -> Result<(), AuthError> {
        validate_redirect_uris(&params.redirect_uris)?;
        if let Some(ref url) = params.logo_url {
            validate_logo_url(url)?;
        }
        if let Some(ref color) = params.primary_color {
            validate_primary_color(color)?;
        }
        let redirect_uris_json =
            serde_json::to_string(&params.redirect_uris).expect("Vec<String> serializes to JSON");
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let result = sqlx::query(
            "UPDATE allowthem_applications \
             SET name = ?1, redirect_uris = ?2, is_trusted = ?3, is_active = ?4, \
                 logo_url = ?5, primary_color = ?6, updated_at = ?7 \
             WHERE id = ?8",
        )
        .bind(&params.name)
        .bind(&redirect_uris_json)
        .bind(params.is_trusted)
        .bind(params.is_active)
        .bind(&params.logo_url)
        .bind(&params.primary_color)
        .bind(&now)
        .bind(id)
        .execute(self.pool())
        .await?;

        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
    }

    /// Generate a new client secret, invalidating the previous one.
    ///
    /// Returns the updated `Application` and the raw `ClientSecret`.
    /// The new secret is the only opportunity to retrieve it — the old secret
    /// is irrecoverably invalidated on success.
    ///
    /// Returns `AuthError::NotFound` if no application with `id` exists.
    pub async fn regenerate_client_secret(
        &self,
        id: ApplicationId,
    ) -> Result<(Application, ClientSecret), AuthError> {
        let application = self.get_application(id).await?;
        if application.client_type == ClientType::Public {
            return Err(AuthError::InvalidRequest(
                "public clients have no client secret".into(),
            ));
        }
        let (raw_secret, hash) = generate_client_secret()?;
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string();

        let result = sqlx::query(
            "UPDATE allowthem_applications \
             SET client_secret_hash = ?1, updated_at = ?2 \
             WHERE id = ?3",
        )
        .bind(&hash)
        .bind(&now)
        .bind(id)
        .execute(self.pool())
        .await?;

        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }

        let app = self.get_application(id).await?;
        Ok((app, raw_secret))
    }

    /// Permanently delete an application and all associated grants.
    ///
    /// Cascade deletes: authorization_codes, refresh_tokens, consents.
    /// Returns `AuthError::NotFound` if no application with `id` exists.
    pub async fn delete_application(&self, id: ApplicationId) -> Result<(), AuthError> {
        let result = sqlx::query("DELETE FROM allowthem_applications WHERE id = ?")
            .bind(id)
            .execute(self.pool())
            .await?;

        if result.rows_affected() == 0 {
            return Err(AuthError::NotFound);
        }
        Ok(())
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
            client_type: ClientType::Confidential,
            client_secret_hash: Some(hash),
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
            client_type: ClientType::Confidential,
            client_secret_hash: Some(hash),
            redirect_uris: "not valid json".to_string(),
            logo_url: None,
            primary_color: None,
            is_trusted: false,
            created_by: None,
            is_active: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert!(matches!(
            app.redirect_uri_list(),
            Err(AuthError::Database(_))
        ));
    }

    // validate_logo_url tests

    #[test]
    fn logo_url_https_is_valid() {
        assert!(validate_logo_url("https://example.com/logo.png").is_ok());
    }

    #[test]
    fn logo_url_http_localhost_is_valid() {
        assert!(validate_logo_url("http://localhost:3000/logo.png").is_ok());
    }

    #[test]
    fn logo_url_http_127_is_valid() {
        assert!(validate_logo_url("http://127.0.0.1:8080/logo.png").is_ok());
    }

    #[test]
    fn logo_url_http_non_localhost_is_rejected() {
        let err = validate_logo_url("http://example.com/logo.png").unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    #[test]
    fn logo_url_relative_is_rejected() {
        let err = validate_logo_url("/logo.png").unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    #[test]
    fn logo_url_not_a_url_is_rejected() {
        let err = validate_logo_url("not a url").unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    // validate_primary_color tests

    #[test]
    fn primary_color_valid_hex() {
        assert!(validate_primary_color("#3B82F6").is_ok());
    }

    #[test]
    fn primary_color_lowercase_hex() {
        assert!(validate_primary_color("#3b82f6").is_ok());
    }

    #[test]
    fn primary_color_missing_hash() {
        let err = validate_primary_color("3B82F6").unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    #[test]
    fn primary_color_too_short() {
        let err = validate_primary_color("#FFF").unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    #[test]
    fn primary_color_too_long() {
        let err = validate_primary_color("#3B82F6FF").unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    #[test]
    fn primary_color_non_hex_chars() {
        let err = validate_primary_color("#ZZZZZZ").unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    #[test]
    fn primary_color_named_color_rejected() {
        let err = validate_primary_color("red").unwrap_err();
        assert!(matches!(err, AuthError::Validation(_)));
    }

    // BrandingConfig extraction test

    #[test]
    fn branding_extracts_correct_fields() {
        let (_, hash) = generate_client_secret().expect("generate");
        let app = Application {
            id: ApplicationId::new(),
            name: "My App".to_string(),
            client_id: generate_client_id(),
            client_type: ClientType::Confidential,
            client_secret_hash: Some(hash),
            redirect_uris: r#"["https://example.com/cb"]"#.to_string(),
            logo_url: Some("https://example.com/logo.png".to_string()),
            primary_color: Some("#3B82F6".to_string()),
            is_trusted: false,
            created_by: None,
            is_active: true,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        let b = app.branding();
        assert_eq!(b.application_name, "My App");
        assert_eq!(b.logo_url.as_deref(), Some("https://example.com/logo.png"));
        assert_eq!(b.primary_color.as_deref(), Some("#3B82F6"));
    }

    #[test]
    fn application_serialization_omits_secret() {
        let (_, hash) = generate_client_secret().expect("generate_client_secret");
        let app = Application {
            id: ApplicationId::new(),
            name: "Test App".to_string(),
            client_id: generate_client_id(),
            client_type: ClientType::Confidential,
            client_secret_hash: Some(hash),
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
