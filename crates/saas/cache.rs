use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;

use allowthem_core::AllowThem;

use crate::error::SaasError;
use crate::tenants::{TenantId, TenantStatus};

#[derive(Debug, Clone)]
pub struct TenantMeta {
    pub id: TenantId,
    pub status: TenantStatus,
    pub plan_id: Vec<u8>,
}

#[derive(Clone)]
pub struct SlugCache(Cache<String, TenantMeta>);

impl SlugCache {
    pub fn new(max_capacity: u64, ttl_secs: u64) -> Self {
        Self(
            Cache::builder()
                .max_capacity(max_capacity)
                .time_to_live(Duration::from_secs(ttl_secs))
                .build(),
        )
    }

    pub async fn get_or_fetch<F, Fut>(
        &self,
        slug: &str,
        init: F,
    ) -> Result<Option<TenantMeta>, SaasError>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<TenantMeta>, SaasError>>,
    {
        if let Some(meta) = self.0.get(slug).await {
            return Ok(Some(meta));
        }
        let result = init().await?;
        if let Some(ref meta) = result {
            self.0.insert(slug.to_owned(), meta.clone()).await;
        }
        Ok(result)
    }
}

#[derive(Clone)]
pub struct HandleCache(Cache<TenantId, AllowThem>);

impl HandleCache {
    pub fn new(max_capacity: u64) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .async_eviction_listener(|tenant_id: Arc<TenantId>, _handle, _cause| {
                Box::pin(async move {
                    tracing::debug!(tenant_id = %tenant_id.as_uuid(), "tenant handle evicted");
                })
            })
            .build();
        Self(cache)
    }

    pub async fn get_or_init<F>(
        &self,
        tenant_id: TenantId,
        init: F,
    ) -> Result<AllowThem, Arc<SaasError>>
    where
        F: Future<Output = Result<AllowThem, SaasError>>,
    {
        self.0.try_get_with(tenant_id, init).await
    }

    pub async fn invalidate(&self, tenant_id: &TenantId) {
        self.0.invalidate(tenant_id).await;
    }

    pub fn entry_count(&self) -> u64 {
        self.0.entry_count()
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use allowthem_core::AllowThemBuilder;
    use uuid::Uuid;

    use super::*;

    fn make_meta(slug_seed: u8) -> TenantMeta {
        TenantMeta {
            id: TenantId::from(Uuid::from_bytes([slug_seed; 16])),
            status: TenantStatus::Active,
            plan_id: vec![slug_seed],
        }
    }

    #[tokio::test]
    async fn slug_cache_miss_calls_init() {
        let cache = SlugCache::new(10, 60);
        let count = Arc::new(AtomicUsize::new(0));
        let c = count.clone();
        let meta = make_meta(1);

        let result = cache
            .get_or_fetch("acme", || {
                let c = c.clone();
                let m = meta.clone();
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok(Some(m))
                }
            })
            .await
            .unwrap();

        assert!(result.is_some());
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn slug_cache_hit_skips_init() {
        let cache = SlugCache::new(10, 60);
        let count = Arc::new(AtomicUsize::new(0));
        let meta = make_meta(2);

        for _ in 0..2 {
            let c = count.clone();
            let m = meta.clone();
            cache
                .get_or_fetch("beta", move || {
                    let c = c.clone();
                    let m = m.clone();
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                        Ok(Some(m))
                    }
                })
                .await
                .unwrap();
        }

        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn handle_cache_coalesces_concurrent() {
        let cache = HandleCache::new(10);
        let count = Arc::new(AtomicUsize::new(0));
        let barrier = Arc::new(tokio::sync::Barrier::new(3));
        let id = TenantId::from(Uuid::from_bytes([0xAB; 16]));

        let tasks: Vec<_> = (0..3)
            .map(|_| {
                let cache = cache.clone();
                let count = count.clone();
                let b = barrier.clone();
                tokio::spawn(async move {
                    b.wait().await;
                    let _ = cache
                        .get_or_init(id, async {
                            count.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                            Err::<AllowThem, SaasError>(SaasError::TenantNotFound)
                        })
                        .await;
                })
            })
            .collect();

        for t in tasks {
            t.await.unwrap();
        }

        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn handle_cache_error_propagates() {
        let cache = HandleCache::new(10);
        let id = TenantId::from(Uuid::from_bytes([0xCD; 16]));

        let err = cache
            .get_or_init(id, async {
                Err::<AllowThem, SaasError>(SaasError::TenantNotFound)
            })
            .await
            .err()
            .expect("expected error");

        assert!(matches!(*err, SaasError::TenantNotFound));
    }

    #[tokio::test]
    async fn handle_cache_invalidate_forces_reinit() {
        let handle = AllowThemBuilder::new("sqlite::memory:")
            .cookie_secure(false)
            .build()
            .await
            .unwrap();

        let cache = HandleCache::new(10);
        let id = TenantId::from(Uuid::from_bytes([0xEF; 16]));
        let count = Arc::new(AtomicUsize::new(0));

        let c = count.clone();
        let h = handle.clone();
        cache
            .get_or_init(id, async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok::<_, SaasError>(h)
            })
            .await
            .unwrap();

        assert_eq!(count.load(Ordering::SeqCst), 1);

        cache.invalidate(&id).await;

        let c = count.clone();
        cache
            .get_or_init(id, async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok::<_, SaasError>(handle)
            })
            .await
            .unwrap();

        assert_eq!(count.load(Ordering::SeqCst), 2);
    }
}
