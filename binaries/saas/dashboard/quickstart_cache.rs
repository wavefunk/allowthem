//! In-memory single-use cache for the post-signup quickstart page.
//!
//! After a successful signup the dashboard handler stashes the new
//! application's `client_id` + plaintext `client_secret` here keyed by a
//! 32-byte URL-safe token, then redirects to `/quickstart/<token>`. The
//! quickstart handler reads the entry on each render (refresh-friendly)
//! and the dismiss handler invalidates it.
//!
//! Plaintext lives in process memory for at most the TTL (10 min) and is
//! never written to disk or logged.

use std::time::Duration;

use moka::future::Cache;

use allowthem_core::sessions::generate_token;
use allowthem_core::types::UserId;

/// Default time-to-live for a quickstart entry. The plaintext secret is
/// reachable from the cache for at most this long after signup; the
/// dismiss handler shortens this when the user clicks the CTA.
const DEFAULT_TTL_SECS: u64 = 600; // 10 minutes

/// Capacity bound. Entries are tiny — the cap defends against signup
/// floods more than memory pressure.
const DEFAULT_CAPACITY: u64 = 10_000;

#[derive(Clone)]
pub struct QuickstartCache(Cache<String, QuickstartEntry>);

#[derive(Clone)]
pub struct QuickstartEntry {
    /// Owning dashboard user. Read by the quickstart handler to gate
    /// access to the entry — only the dashboard user who created it can
    /// see it.
    pub dashboard_user_id: UserId,
    pub slug: String,
    /// `client_id` of the freshly created OIDC application. Stored as
    /// `String` rather than `ClientId` because `ProvisionResult.client_id`
    /// is already `String` (no public `ClientId` constructor exists outside
    /// the core crate).
    pub client_id: String,
    /// Plaintext OAuth client secret. Surfaced once on the quickstart
    /// page; never persisted.
    pub client_secret: String,
    /// `https://<slug>.<base_domain>` — the OIDC issuer for the new tenant.
    pub issuer: String,
}

impl QuickstartCache {
    pub fn new() -> Self {
        Self::with_ttl(Duration::from_secs(DEFAULT_TTL_SECS))
    }

    /// Test hook: build a cache with a shorter TTL so TTL-eviction tests
    /// don't have to wait the full 10 minutes.
    pub fn with_ttl(ttl: Duration) -> Self {
        Self(
            Cache::builder()
                .time_to_live(ttl)
                .max_capacity(DEFAULT_CAPACITY)
                .build(),
        )
    }

    /// Stash an entry, returning the single-use URL token to embed in the
    /// post-signup redirect. The same primitive used for session tokens
    /// (32 random bytes, base64url-unpadded → 43 chars).
    pub async fn put(&self, entry: QuickstartEntry) -> String {
        let token = generate_token();
        let key = token.as_str().to_owned();
        self.0.insert(key.clone(), entry).await;
        key
    }

    /// Look up a token. Returns a clone — the cache continues to own the
    /// canonical entry until eviction or [`Self::evict`].
    pub async fn get(&self, token: &str) -> Option<QuickstartEntry> {
        self.0.get(token).await
    }

    /// Forget the token, dropping the plaintext secret from memory.
    pub async fn evict(&self, token: &str) {
        self.0.invalidate(token).await;
    }
}

impl Default for QuickstartCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use allowthem_core::types::UserId;
    use std::time::Duration;

    fn sample_entry() -> QuickstartEntry {
        QuickstartEntry {
            dashboard_user_id: UserId::new(),
            slug: "acme".into(),
            client_id: "ath_test1234567890abcd".into(),
            client_secret: "very-secret".into(),
            issuer: "https://acme.example.com".into(),
        }
    }

    #[tokio::test]
    async fn put_then_get_returns_same_entry() {
        let cache = QuickstartCache::new();
        let entry = sample_entry();
        let token = cache.put(entry.clone()).await;
        let got = cache.get(&token).await.expect("entry");
        assert_eq!(got.client_id.as_str(), entry.client_id.as_str());
        assert_eq!(got.client_secret, entry.client_secret);
        assert_eq!(got.slug, entry.slug);
    }

    #[tokio::test]
    async fn get_unknown_token_returns_none() {
        let cache = QuickstartCache::new();
        assert!(cache.get("nope").await.is_none());
    }

    #[tokio::test]
    async fn evict_removes_entry() {
        let cache = QuickstartCache::new();
        let token = cache.put(sample_entry()).await;
        cache.evict(&token).await;
        assert!(cache.get(&token).await.is_none());
    }

    #[tokio::test]
    async fn ttl_eviction_drops_entry() {
        let cache = QuickstartCache::with_ttl(Duration::from_millis(50));
        let token = cache.put(sample_entry()).await;
        // Wait past the TTL plus a margin for moka housekeeping. moka's
        // time_to_live evicts on access, so we sleep then read.
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(
            cache.get(&token).await.is_none(),
            "entry should be evicted after TTL"
        );
    }
}
