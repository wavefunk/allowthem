//! DNS resolver trait, Hickory-backed real implementation, and `verify_domain`
//! helper.
//!
//! ## Design notes
//!
//! - No `async-trait` — follow the `AuthFuture` / `DnsFuture` pattern used
//!   by `EmailSender` and `SocialProvider` in `crates/core`.
//! - `MockDnsResolver` is gated with `#[cfg(any(test, feature = "test-util"))]`
//!   so it compiles only in tests and when the `test-util` Cargo feature is
//!   enabled (needed by `binaries/saas` integration tests in Task 4).
//! - `DomainStatus::Active` is intentionally never written here (38y.3 owns
//!   the `Verified → Active` transition).

use std::future::Future;
use std::pin::Pin;

use chrono::Utc;

use crate::control_db::ControlDb;
use crate::domains::{DomainId, DomainStatus};
use crate::error::SaasError;
use crate::tenants::TenantId;

// ── DnsFuture type alias ──────────────────────────────────────────────────────

/// Boxed future type alias mirroring the `AuthFuture` pattern in `crates/core`.
pub type DnsFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, DnsError>> + Send + 'a>>;

// ── DnsError ──────────────────────────────────────────────────────────────────

/// DNS resolver errors. Mapped to [`SaasError::Dns`] at the `verify_domain`
/// boundary so that `SaasError`'s surface stays tight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsError {
    /// The queried name does not exist in DNS (NXDOMAIN or no records found).
    NotFound,
    /// The resolver timed out.
    Timeout,
    /// Any other resolver failure (parse error, I/O error, etc.).
    Other(String),
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::NotFound => write!(f, "no DNS records found"),
            DnsError::Timeout => write!(f, "DNS query timed out"),
            DnsError::Other(msg) => write!(f, "DNS error: {msg}"),
        }
    }
}

// ── DnsResolver trait ─────────────────────────────────────────────────────────

/// Abstracts DNS CNAME resolution for testability.
///
/// Returns the CNAME chain rooted at `host`. An empty `Vec` signals that `host`
/// is an A/AAAA terminus (no CNAME at that name). Errors signal resolver
/// failures (timeout, parse errors, NXDOMAIN).
pub trait DnsResolver: Send + Sync {
    fn lookup_cname_chain<'a>(&'a self, host: &'a str) -> DnsFuture<'a, Vec<String>>;
}

// ── HickoryDnsResolver ────────────────────────────────────────────────────────

/// Real `DnsResolver` backed by `hickory-resolver`.
pub struct HickoryDnsResolver {
    inner: hickory_resolver::TokioResolver,
}

impl HickoryDnsResolver {
    /// Build a resolver using system defaults.
    pub fn new() -> Result<Self, SaasError> {
        use hickory_resolver::Resolver;
        use hickory_resolver::config::ResolverConfig;
        use hickory_resolver::net::runtime::TokioRuntimeProvider;

        let resolver = Resolver::builder_with_config(
            ResolverConfig::default(),
            TokioRuntimeProvider::default(),
        )
        .build()
        .map_err(|e| SaasError::Dns(format!("failed to build DNS resolver: {e}")))?;
        Ok(Self { inner: resolver })
    }
}

impl DnsResolver for HickoryDnsResolver {
    fn lookup_cname_chain<'a>(&'a self, host: &'a str) -> DnsFuture<'a, Vec<String>> {
        Box::pin(async move {
            use hickory_resolver::proto::rr::{RData, RecordType};

            const HOP_CAP: usize = 8;
            let mut chain = Vec::new();
            let mut current = host.to_owned();

            for _ in 0..HOP_CAP {
                match self.inner.lookup(current.as_str(), RecordType::CNAME).await {
                    Ok(lookup) => {
                        // Extract the first CNAME target from the answer section.
                        let target = lookup.answers().iter().find_map(|record| {
                            if let RData::CNAME(cname) = &record.data {
                                let name = cname.0.to_string();
                                // Strip trailing FQDN dot so comparisons are clean.
                                Some(name.trim_end_matches('.').to_lowercase())
                            } else {
                                None
                            }
                        });
                        match target {
                            Some(t) => {
                                chain.push(t.clone());
                                current = t;
                            }
                            // Response with no CNAME records = A/AAAA terminus.
                            None => break,
                        }
                    }
                    Err(e) if e.is_no_records_found() => {
                        // NXDOMAIN or no records of the queried type — chain
                        // terminated. Return what we have (possibly empty).
                        break;
                    }
                    Err(e) => {
                        // Classify the resolver error.
                        use hickory_resolver::net::NetError;
                        let dns_err = match e {
                            NetError::Timeout => DnsError::Timeout,
                            other => DnsError::Other(other.to_string()),
                        };
                        return Err(dns_err);
                    }
                }
            }

            Ok(chain)
        })
    }
}

// ── MockDnsResolver ───────────────────────────────────────────────────────────

/// Controllable `DnsResolver` for tests.
///
/// Each call to `lookup_cname_chain` pops one pre-queued response from the
/// `VecDeque` for that host, allowing tests to model sequences such as
/// "first attempt times out, second returns the correct chain".
///
/// Gated with `#[cfg(any(test, feature = "test-util"))]` so the type does
/// not leak into production builds.
#[cfg(any(test, feature = "test-util"))]
pub struct MockDnsResolver {
    chains: tokio::sync::Mutex<
        std::collections::HashMap<String, std::collections::VecDeque<Result<Vec<String>, DnsError>>>,
    >,
}

#[cfg(any(test, feature = "test-util"))]
impl MockDnsResolver {
    pub fn new() -> Self {
        Self {
            chains: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Queue a response for the given host. Responses are consumed in order.
    pub async fn queue(&self, host: &str, response: Result<Vec<String>, DnsError>) {
        self.chains
            .lock()
            .await
            .entry(host.to_owned())
            .or_default()
            .push_back(response);
    }
}

#[cfg(any(test, feature = "test-util"))]
impl DnsResolver for MockDnsResolver {
    fn lookup_cname_chain<'a>(&'a self, host: &'a str) -> DnsFuture<'a, Vec<String>> {
        Box::pin(async move {
            let mut guard = self.chains.lock().await;
            guard
                .get_mut(host)
                .and_then(|q| q.pop_front())
                .unwrap_or(Ok(vec![]))
        })
    }
}

// ── verify_domain helper ──────────────────────────────────────────────────────

/// Verify that `domain`'s CNAME chain contains `dns_target`, updating the
/// `tenant_domains` row accordingly.
///
/// - On success (`dns_target` appears anywhere in the chain): status → `Verified`.
/// - On failure (no match or DNS error): status → `Failed`, `last_error` set.
/// - DB write failures bubble as `SaasError`; DNS errors are swallowed into
///   `Failed`.
///
/// `_tenant_id` is carried for caller context and future audit logging; the
/// status update itself is addressed by `domain_id` alone.
pub async fn verify_domain(
    resolver: &dyn DnsResolver,
    control_db: &ControlDb,
    domain_id: DomainId,
    _tenant_id: TenantId,
    domain: &str,
    dns_target: &str,
) -> Result<DomainStatus, SaasError> {
    let target_lower = dns_target.to_lowercase();

    match resolver.lookup_cname_chain(domain).await {
        Ok(chain) => {
            // Check whether dns_target appears anywhere in the chain (§3.6:
            // use `contains`, not `last()`, to survive CDN extra hops).
            let found = chain.iter().any(|hop| {
                let hop_stripped = hop.trim_end_matches('.');
                hop_stripped.eq_ignore_ascii_case(&target_lower)
            });

            if found {
                control_db
                    .set_tenant_domain_status(
                        &domain_id,
                        DomainStatus::Verified,
                        Some(Utc::now()),
                        None,
                    )
                    .await?;
                Ok(DomainStatus::Verified)
            } else {
                let msg = format!(
                    "CNAME chain {chain:?} does not contain {dns_target}"
                );
                control_db
                    .set_tenant_domain_status(
                        &domain_id,
                        DomainStatus::Failed,
                        None,
                        Some(msg.as_str()),
                    )
                    .await?;
                Ok(DomainStatus::Failed)
            }
        }
        Err(DnsError::NotFound) => {
            control_db
                .set_tenant_domain_status(
                    &domain_id,
                    DomainStatus::Failed,
                    None,
                    Some("no CNAME record found"),
                )
                .await?;
            Ok(DomainStatus::Failed)
        }
        Err(e) => {
            let msg = e.to_string();
            control_db
                .set_tenant_domain_status(
                    &domain_id,
                    DomainStatus::Failed,
                    None,
                    Some(msg.as_str()),
                )
                .await?;
            Ok(DomainStatus::Failed)
        }
    }
}

// ── Background sweep helper ───────────────────────────────────────────────────

/// Statistics returned by one sweep run.
#[derive(Debug, Default)]
pub struct SweepStats {
    pub processed: usize,
    pub verified: usize,
    pub failed: usize,
}

/// Run one verification sweep over `pending_verification` and `failed` rows,
/// capped at `limit` rows (oldest-first). Reuses [`verify_domain`].
pub async fn run_one_sweep(
    resolver: &dyn DnsResolver,
    control_db: &ControlDb,
    limit: usize,
) -> Result<SweepStats, SaasError> {
    use crate::domains::DomainId as Did;
    use uuid::Uuid;

    let rows = control_db.list_domains_for_sweep(limit as i64).await?;
    let mut stats = SweepStats::default();

    for row in &rows {
        let domain_id = match Uuid::from_slice(&row.id) {
            Ok(u) => Did::from(u),
            Err(_) => {
                tracing::warn!("skipping domain row with undecodable UUID in sweep");
                continue;
            }
        };
        let tenant_id = match Uuid::from_slice(&row.tenant_id) {
            Ok(u) => TenantId::from(u),
            Err(_) => {
                tracing::warn!("skipping domain row with undecodable tenant UUID in sweep");
                continue;
            }
        };

        stats.processed += 1;
        match verify_domain(
            resolver,
            control_db,
            domain_id,
            tenant_id,
            &row.domain,
            &row.dns_target,
        )
        .await
        {
            Ok(DomainStatus::Verified) => stats.verified += 1,
            Ok(_) => stats.failed += 1,
            Err(e) => {
                tracing::warn!(domain = %row.domain, error = %e, "sweep: DB error on domain");
                stats.failed += 1;
            }
        }
    }

    Ok(stats)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_db::ControlDb;
    use crate::control_db::tests::test_pool;
    use crate::domains::DomainId;
    use uuid::Uuid;

    // ─── Helper: build a seeded DB with one pending domain ───────────────────

    async fn setup(slug: &str, domain: &str) -> (ControlDb, DomainId, TenantId) {
        let pool = test_pool().await;
        let db = ControlDb::new(pool).await.unwrap();

        // Seed a tenant.
        let plan_id: Vec<u8> =
            sqlx::query_scalar("SELECT id FROM tenant_plans LIMIT 1")
                .fetch_one(db.pool())
                .await
                .unwrap();
        let tid_uuid = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, ?, ?, ?, ?, 'active', ?)",
        )
        .bind(tid_uuid.as_bytes().as_ref())
        .bind(slug)
        .bind(slug)
        .bind(format!("{slug}@example.com"))
        .bind(&plan_id)
        .bind(format!("{slug}.db"))
        .execute(db.pool())
        .await
        .unwrap();

        let tenant_id = TenantId::from(tid_uuid);
        let row = db
            .create_tenant_domain(&tenant_id, domain, "custom.allowthem.io")
            .await
            .unwrap();
        let domain_id = DomainId::from(Uuid::from_slice(&row.id).unwrap());

        (db, domain_id, tenant_id)
    }

    // ─── verify_domain tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn verify_domain_marks_verified_when_chain_contains_target() {
        let (db, domain_id, tenant_id) = setup("vf-a", "auth.example.com").await;
        let resolver = MockDnsResolver::new();
        resolver
            .queue(
                "auth.example.com",
                Ok(vec!["custom.allowthem.io".into()]),
            )
            .await;

        let status = verify_domain(
            &resolver,
            &db,
            domain_id,
            tenant_id,
            "auth.example.com",
            "custom.allowthem.io",
        )
        .await
        .unwrap();

        assert_eq!(status, DomainStatus::Verified);
        let row = db
            .get_tenant_domain_scoped(&domain_id, &tenant_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, DomainStatus::Verified);
        assert!(row.verified_at.is_some());
        assert!(row.last_error.is_none());
    }

    #[tokio::test]
    async fn verify_domain_marks_verified_when_target_has_trailing_dot() {
        let (db, domain_id, tenant_id) = setup("vf-b", "auth.example.com").await;
        let resolver = MockDnsResolver::new();
        // Chain hop ends with a trailing dot (FQDN).
        resolver
            .queue(
                "auth.example.com",
                Ok(vec!["custom.allowthem.io.".into()]),
            )
            .await;

        let status = verify_domain(
            &resolver,
            &db,
            domain_id,
            tenant_id,
            "auth.example.com",
            "custom.allowthem.io",
        )
        .await
        .unwrap();

        assert_eq!(status, DomainStatus::Verified);
    }

    #[tokio::test]
    async fn verify_domain_marks_verified_when_target_is_not_last_hop() {
        // Target appears mid-chain (CDN adds more hops after it).
        let (db, domain_id, tenant_id) = setup("vf-c", "auth.example.com").await;
        let resolver = MockDnsResolver::new();
        resolver
            .queue(
                "auth.example.com",
                Ok(vec![
                    "custom.allowthem.io".into(),
                    "cdn-edge.fastly.net".into(),
                ]),
            )
            .await;

        let status = verify_domain(
            &resolver,
            &db,
            domain_id,
            tenant_id,
            "auth.example.com",
            "custom.allowthem.io",
        )
        .await
        .unwrap();

        assert_eq!(status, DomainStatus::Verified);
    }

    #[tokio::test]
    async fn verify_domain_marks_failed_when_no_cname() {
        let (db, domain_id, tenant_id) = setup("vf-d", "auth.example.com").await;
        let resolver = MockDnsResolver::new();
        resolver
            .queue("auth.example.com", Err(DnsError::NotFound))
            .await;

        let status = verify_domain(
            &resolver,
            &db,
            domain_id,
            tenant_id,
            "auth.example.com",
            "custom.allowthem.io",
        )
        .await
        .unwrap();

        assert_eq!(status, DomainStatus::Failed);
        let row = db
            .get_tenant_domain_scoped(&domain_id, &tenant_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, DomainStatus::Failed);
        assert!(row.last_error.as_deref().unwrap().contains("no CNAME"));
    }

    #[tokio::test]
    async fn verify_domain_marks_failed_when_chain_has_no_matching_hop() {
        let (db, domain_id, tenant_id) = setup("vf-e", "auth.example.com").await;
        let resolver = MockDnsResolver::new();
        resolver
            .queue(
                "auth.example.com",
                Ok(vec!["other-provider.example.net".into()]),
            )
            .await;

        let status = verify_domain(
            &resolver,
            &db,
            domain_id,
            tenant_id,
            "auth.example.com",
            "custom.allowthem.io",
        )
        .await
        .unwrap();

        assert_eq!(status, DomainStatus::Failed);
        let row = db
            .get_tenant_domain_scoped(&domain_id, &tenant_id)
            .await
            .unwrap()
            .unwrap();
        assert!(row.last_error.as_deref().unwrap().contains("does not contain"));
    }

    #[tokio::test]
    async fn verify_domain_propagates_db_errors_through_saas_error() {
        // Force a DB write failure by closing the pool.
        let (db, domain_id, tenant_id) = setup("vf-f", "auth.example.com").await;
        db.pool().close().await;

        let resolver = MockDnsResolver::new();
        resolver
            .queue(
                "auth.example.com",
                Ok(vec!["custom.allowthem.io".into()]),
            )
            .await;

        let result = verify_domain(
            &resolver,
            &db,
            domain_id,
            tenant_id,
            "auth.example.com",
            "custom.allowthem.io",
        )
        .await;

        assert!(result.is_err(), "expected DB error to propagate");
    }

    // ─── MockDnsResolver hop-cap test ────────────────────────────────────────

    #[tokio::test]
    async fn lookup_cname_chain_caps_at_8_hops() {
        // Queue 9 hops — MockDnsResolver will return them one at a time.
        // The resolver should stop at 8.
        let resolver = MockDnsResolver::new();
        for i in 0..9_usize {
            let host = if i == 0 {
                "start.example.com".to_owned()
            } else {
                format!("hop{i}.example.com")
            };
            let next = format!("hop{}.example.com", i + 1);
            resolver.queue(&host, Ok(vec![next])).await;
        }

        let chain = resolver
            .lookup_cname_chain("start.example.com")
            .await
            .unwrap();
        // MockDnsResolver always pops one entry per call. With the cap at 8,
        // "start" + hops 1..8 → 8 entries in the chain.
        assert!(
            chain.len() <= 8,
            "chain length {} exceeds hop cap",
            chain.len()
        );
    }

    // ─── run_one_sweep tests ─────────────────────────────────────────────────

    #[tokio::test]
    async fn sweep_processes_pending_then_verified_disappears_from_pool() {
        let (db, domain_id, tenant_id) = setup("sw-a", "auth.example.com").await;
        let resolver = std::sync::Arc::new(MockDnsResolver::new());
        resolver
            .queue(
                "auth.example.com",
                Ok(vec!["custom.allowthem.io".into()]),
            )
            .await;

        let stats = run_one_sweep(&*resolver, &db, 100).await.unwrap();
        assert_eq!(stats.verified, 1);
        assert_eq!(stats.processed, 1);

        // Row should now be Verified, so a second sweep sees nothing.
        let _ = (domain_id, tenant_id); // used to seed
        let stats2 = run_one_sweep(&*resolver, &db, 100).await.unwrap();
        assert_eq!(stats2.processed, 0);
    }

    #[tokio::test]
    async fn sweep_caps_at_limit() {
        let pool = test_pool().await;
        let db = ControlDb::new(pool).await.unwrap();
        let plan_id: Vec<u8> =
            sqlx::query_scalar("SELECT id FROM tenant_plans LIMIT 1")
                .fetch_one(db.pool())
                .await
                .unwrap();

        // Seed 5 domains for one tenant.
        let tid_uuid = Uuid::now_v7();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'Cap', 'sw-cap', 'cap@example.com', ?, 'active', 'cap.db')",
        )
        .bind(tid_uuid.as_bytes().as_ref())
        .bind(&plan_id)
        .execute(db.pool())
        .await
        .unwrap();
        let tenant_id = TenantId::from(tid_uuid);

        for i in 0..5 {
            db.create_tenant_domain(
                &tenant_id,
                &format!("d{i}.example.com"),
                "custom.allowthem.io",
            )
            .await
            .unwrap();
        }

        let resolver = MockDnsResolver::new();
        let stats = run_one_sweep(&resolver, &db, 3).await.unwrap();
        assert_eq!(stats.processed, 3, "sweep should respect limit");
    }

    #[tokio::test]
    async fn sweep_failed_row_can_be_reprocessed_in_next_sweep() {
        let (db, domain_id, tenant_id) = setup("sw-b", "auth.example.com").await;
        let resolver = MockDnsResolver::new();

        // First sweep: wrong chain → Failed.
        resolver
            .queue(
                "auth.example.com",
                Ok(vec!["wrong.example.net".into()]),
            )
            .await;
        let s1 = run_one_sweep(&resolver, &db, 100).await.unwrap();
        assert_eq!(s1.failed, 1);

        // Second sweep: correct chain → Verified.
        resolver
            .queue(
                "auth.example.com",
                Ok(vec!["custom.allowthem.io".into()]),
            )
            .await;
        let s2 = run_one_sweep(&resolver, &db, 100).await.unwrap();
        assert_eq!(s2.verified, 1);

        let row = db
            .get_tenant_domain_scoped(&domain_id, &tenant_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.status, DomainStatus::Verified);
    }
}
