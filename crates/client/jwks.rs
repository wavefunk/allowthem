//! JWKS fetch and cache for RS256 token validation.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use jsonwebtoken::DecodingKey;
use tokio::sync::RwLock;

use allowthem_core::AuthError;

const JWKS_MIN_REFRESH_INTERVAL: Duration = Duration::from_secs(10);

struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    fetched_at: Option<Instant>,
}

impl JwksCache {
    fn new() -> Self {
        Self {
            keys: HashMap::new(),
            fetched_at: None,
        }
    }

    fn recently_refreshed(&self) -> bool {
        match self.fetched_at {
            None => false,
            Some(t) => t.elapsed() < JWKS_MIN_REFRESH_INTERVAL,
        }
    }
}

pub(crate) struct JwksManager {
    jwks_url: String,
    http: reqwest::Client,
    cache: RwLock<JwksCache>,
}

impl JwksManager {
    pub(crate) fn new(base_url: &str, http: reqwest::Client) -> Self {
        let jwks_url = format!("{base_url}/.well-known/jwks.json");
        Self {
            jwks_url,
            http,
            cache: RwLock::new(JwksCache::new()),
        }
    }

    /// Get a DecodingKey for the given kid. Refreshes JWKS cache if needed.
    pub(crate) async fn get_decoding_key(
        &self,
        kid: &str,
    ) -> Result<Option<DecodingKey>, AuthError> {
        // Try read lock first
        {
            let cache = self.cache.read().await;
            if let Some(key) = cache.keys.get(kid) {
                return Ok(Some(key.clone()));
            }
            // Key not found — rate-limit refreshes to prevent abuse
            if cache.recently_refreshed() {
                return Ok(None);
            }
        }

        // Refresh JWKS
        self.refresh().await?;

        // Retry lookup
        let cache = self.cache.read().await;
        Ok(cache.keys.get(kid).cloned())
    }

    /// Fetch JWKS from the provider and update the cache.
    async fn refresh(&self) -> Result<(), AuthError> {
        let mut cache = self.cache.write().await;

        // Stampede protection: another thread may have already refreshed
        if cache.recently_refreshed() {
            return Ok(());
        }

        let resp = self
            .http
            .get(&self.jwks_url)
            .send()
            .await
            .map_err(|e| AuthError::OAuthHttp(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(AuthError::OAuthHttp(format!(
                "JWKS fetch failed: {}",
                resp.status()
            )));
        }

        let jwks: jsonwebtoken::jwk::JwkSet = resp
            .json()
            .await
            .map_err(|e| AuthError::OAuthHttp(e.to_string()))?;

        let mut keys = HashMap::new();
        for jwk in &jwks.keys {
            if let Some(kid) = &jwk.common.key_id
                && matches!(
                    jwk.algorithm,
                    jsonwebtoken::jwk::AlgorithmParameters::RSA(_)
                )
                && let Ok(dk) = DecodingKey::from_jwk(jwk)
            {
                keys.insert(kid.clone(), dk);
            }
        }

        cache.keys = keys;
        cache.fetched_at = Some(Instant::now());
        Ok(())
    }
}
