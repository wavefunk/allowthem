//! Custom OIDC `SocialProvider` implementation.
//!
//! Constructed from a `SocialProviderConfig` whose `config` JSON object carries
//! either a `discovery_url` (auto-discover all three endpoints) or explicit
//! `authorize_url`, `token_url`, `userinfo_url` fields.
//!
//! Discovery documents are cached per provider instance with a [`DISCOVERY_TTL`]
//! TTL and lazily refreshed inside async trait methods. The cache uses
//! `std::sync::RwLock` (not `tokio::sync::RwLock`) so the synchronous
//! `authorize_url` trait method can read it without a blocking-context contract.

use std::time::{Duration, Instant};

use serde::Deserialize;

// Task 1 imports only — heavier items (Arc, RwLock, Url, AuthFuture, AuthError,
// social_providers::*) are dead-code until the full struct+impl land in Task 2.

/// TTL for cached OIDC discovery documents.
///
/// After this duration, the next `exchange_code` or `fetch_user_info` call
/// will re-fetch the discovery document. `authorize_url` (sync) reads the
/// cached doc regardless of staleness — TTL refresh is not possible inside a
/// sync method.
pub const DISCOVERY_TTL: Duration = Duration::from_secs(60 * 60); // 1 hour

// ── Discovery document ────────────────────────────────────────────────────────

/// Parsed OIDC discovery document. Only the three endpoints this impl uses are
/// required; everything else in the JSON is ignored.
///
/// Maps from the wire names (`authorization_endpoint`, `token_endpoint`,
/// `userinfo_endpoint`) to shorter, idiomatic field names.
#[derive(Debug, Clone)]
pub struct DiscoveryDoc {
    pub authorize_url: String,
    pub token_url: String,
    pub userinfo_url: String,
}

/// Raw deserialization target for the `.well-known/openid-configuration` body.
///
/// Uses the exact field names from OpenID Connect Discovery 1.0 § 4.
#[derive(Deserialize)]
struct DiscoveryDocRaw {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: String,
}

impl From<DiscoveryDocRaw> for DiscoveryDoc {
    fn from(raw: DiscoveryDocRaw) -> Self {
        Self {
            authorize_url: raw.authorization_endpoint,
            token_url: raw.token_endpoint,
            userinfo_url: raw.userinfo_endpoint,
        }
    }
}

// ── Discovery cache (private) ─────────────────────────────────────────────────

/// Per-instance cache of a fetched discovery document plus its fetch timestamp.
///
/// Wrapped in a `std::sync::RwLock` on the provider struct. The lock is held
/// only for a short swap; HTTP I/O happens outside any held lock.
#[allow(dead_code)] // used in Task 2 when CustomOidcSocialProvider is fully implemented
struct DiscoveryCache {
    doc: DiscoveryDoc,
    refreshed_at: Instant,
}

// ── Stub — replaced in Task 2 ─────────────────────────────────────────────────

/// Generic OIDC-compliant social provider.
///
/// Supports any IdP that publishes an OIDC discovery document or accepts
/// explicit `authorize_url` / `token_url` / `userinfo_url` configuration.
///
/// Full implementation ships in epic 7m5.3 Task 2.
pub struct CustomOidcSocialProvider {
    // Fields are added in Task 2.
    _private: (),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_doc_from_raw_renames_endpoints() {
        let raw = DiscoveryDocRaw {
            authorization_endpoint: "https://idp.example.com/authorize".to_owned(),
            token_endpoint: "https://idp.example.com/token".to_owned(),
            userinfo_endpoint: "https://idp.example.com/userinfo".to_owned(),
        };
        let doc = DiscoveryDoc::from(raw);
        assert_eq!(doc.authorize_url, "https://idp.example.com/authorize");
        assert_eq!(doc.token_url, "https://idp.example.com/token");
        assert_eq!(doc.userinfo_url, "https://idp.example.com/userinfo");
    }
}
