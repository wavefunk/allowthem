use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::{FromRow, Row, SqlitePool};
use uuid::Uuid;

use allowthem_core::error::AuthError;

use crate::cache::TenantMeta;
use crate::error::SaasError;
use crate::tenants::{MemberId, Tenant, TenantId, TenantMember, TenantPlan, TenantStatus};

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct TenantUsage {
    pub period: String,
    pub mau_count: i64,
    pub limit_reached_at: Option<DateTime<Utc>>,
    pub notified_at: Option<DateTime<Utc>>,
}

/// Role of a dashboard user inside a tenant. Mirrors `tenant_members.role`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize, sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum TenantRole {
    Owner,
    Admin,
    Viewer,
}

impl TenantRole {
    pub fn is_owner(&self) -> bool {
        matches!(self, TenantRole::Owner)
    }

    pub fn is_admin_or_owner(&self) -> bool {
        matches!(self, TenantRole::Owner | TenantRole::Admin)
    }

    /// SQL-side spelling. Matches the `tenant_members.role` CHECK.
    pub fn as_str(&self) -> &'static str {
        match self {
            TenantRole::Owner => "owner",
            TenantRole::Admin => "admin",
            TenantRole::Viewer => "viewer",
        }
    }
}

impl std::str::FromStr for TenantRole {
    type Err = SaasError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "owner" => Ok(TenantRole::Owner),
            "admin" => Ok(TenantRole::Admin),
            "viewer" => Ok(TenantRole::Viewer),
            other => Err(SaasError::InvalidRole(other.to_owned())),
        }
    }
}

pub struct ControlDb {
    pool: SqlitePool,
}

impl ControlDb {
    pub async fn new(pool: SqlitePool) -> Result<Self, AuthError> {
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .map_err(sqlx::Error::from)?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    pub async fn tenant_meta_by_slug(&self, slug: &str) -> Result<Option<TenantMeta>, SaasError> {
        let row = sqlx::query("SELECT id, status, plan_id FROM tenants WHERE slug = ?1")
            .bind(slug)
            .fetch_optional(&self.pool)
            .await?;

        let Some(row) = row else { return Ok(None) };

        let id_bytes: Vec<u8> = row.try_get("id")?;
        let status: TenantStatus = row.try_get("status")?;
        let plan_id: Vec<u8> = row.try_get("plan_id")?;
        let id = Uuid::from_slice(&id_bytes).map_err(|_| SaasError::TenantNotFound)?;

        Ok(Some(TenantMeta {
            id: TenantId::from(id),
            status,
            plan_id,
        }))
    }

    /// Returns the `(Tenant, role)` pairs for every tenant the email has
    /// accepted membership in. Sorted by `t.name ASC`, with deleted tenants
    /// excluded. Used by the dashboard workspace switcher.
    pub async fn tenants_for_member(
        &self,
        email: &str,
    ) -> Result<Vec<(Tenant, TenantRole)>, SaasError> {
        let rows = sqlx::query(
            "SELECT t.id, t.name, t.slug, t.owner_email, t.plan_id, t.status, \
                    t.db_path, t.last_seen_at, t.created_at, t.updated_at, m.role \
             FROM tenants t \
             JOIN tenant_members m ON m.tenant_id = t.id \
             WHERE m.email = ?1 AND m.accepted_at IS NOT NULL \
               AND t.status != 'deleted' \
             ORDER BY t.name ASC",
        )
        .bind(email)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let tenant = Tenant::from_row(&row)?;
            let role: TenantRole = row.try_get("role")?;
            out.push((tenant, role));
        }
        Ok(out)
    }

    /// Returns the role the given email has on the tenant, or `None` if the
    /// user is not an accepted member. Used by `RequireTenantMember` /
    /// `RequireTenantAdmin` / `RequireTenantOwner`.
    pub async fn member_role(
        &self,
        tenant_id: &TenantId,
        email: &str,
    ) -> Result<Option<TenantRole>, SaasError> {
        let row: Option<(TenantRole,)> = sqlx::query_as(
            "SELECT role FROM tenant_members \
             WHERE tenant_id = ?1 AND email = ?2 AND accepted_at IS NOT NULL",
        )
        .bind(tenant_id.as_bytes())
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.map(|(r,)| r))
    }

    pub async fn most_recently_seen_tenants(&self, count: i64) -> Result<Vec<TenantId>, SaasError> {
        let rows = sqlx::query(
            "SELECT id FROM tenants \
             WHERE status = 'active' AND last_seen_at IS NOT NULL \
             ORDER BY last_seen_at DESC LIMIT ?1",
        )
        .bind(count)
        .fetch_all(&self.pool)
        .await?;

        let mut result = Vec::with_capacity(rows.len());
        for row in rows {
            let bytes: Vec<u8> = row.try_get("id")?;
            match Uuid::from_slice(&bytes) {
                Ok(uuid) => result.push(TenantId::from(uuid)),
                Err(_) => {
                    tracing::warn!("skipping tenant with undecodable UUID in most_recently_seen");
                }
            }
        }
        Ok(result)
    }

    pub async fn touch_last_seen(&self, tenant_id: &TenantId) -> Result<(), SaasError> {
        sqlx::query("UPDATE tenants SET last_seen_at = datetime('now') WHERE id = ?1")
            .bind(tenant_id.as_bytes())
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn usage_for_tenant(
        &self,
        tenant_id: &TenantId,
    ) -> Result<Vec<TenantUsage>, SaasError> {
        let rows = sqlx::query_as::<_, TenantUsage>(
            "SELECT period, mau_count, limit_reached_at, notified_at \
             FROM tenant_usage \
             WHERE tenant_id = ?1 \
             ORDER BY period DESC",
        )
        .bind(tenant_id.as_bytes())
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Append an entry to `control_audit_events`.
    ///
    /// Call sites are fire-and-forget: log the error and continue. An
    /// unlogged audit event is a nuisance, never a correctness bug.
    /// `context` is serialised to a JSON string before persistence so the
    /// callers can pass arbitrary `serde_json::Value` shapes.
    pub async fn log_control_audit(
        &self,
        actor: &str,
        action: &str,
        tenant_id: Option<&TenantId>,
        context: &serde_json::Value,
    ) -> Result<(), SaasError> {
        let id = Uuid::now_v7();
        let context_str = context.to_string();
        sqlx::query(
            "INSERT INTO control_audit_events (id, actor, action, tenant_id, context) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(id.as_bytes().as_slice())
        .bind(actor)
        .bind(action)
        .bind(tenant_id.map(|t| t.as_bytes()))
        .bind(&context_str)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// tenant_members CRUD — read paths and simple writes (invite, accept).
// Last-owner-invariant writes (update_member_role, remove_member) live in
// the next impl block so the SQL there gets focused review.
// ---------------------------------------------------------------------------

impl ControlDb {
    /// All members of a tenant. Pending invites (`accepted_at IS NULL`)
    /// surface first, then accepted rows ordered by `invited_at`.
    pub async fn list_tenant_members(
        &self,
        tenant_id: &TenantId,
    ) -> Result<Vec<TenantMember>, SaasError> {
        let rows = sqlx::query_as::<_, TenantMember>(
            "SELECT id, tenant_id, email, role, invited_at, accepted_at, \
                    invite_token_expires_at \
             FROM tenant_members \
             WHERE tenant_id = ?1 \
             ORDER BY (accepted_at IS NULL) DESC, invited_at ASC",
        )
        .bind(tenant_id.as_bytes())
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    pub async fn get_tenant_member(
        &self,
        member_id: &MemberId,
    ) -> Result<Option<TenantMember>, SaasError> {
        let row = sqlx::query_as::<_, TenantMember>(
            "SELECT id, tenant_id, email, role, invited_at, accepted_at, \
                    invite_token_expires_at \
             FROM tenant_members WHERE id = ?1",
        )
        .bind(member_id.as_bytes())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Insert a pending member row. Returns the new [`MemberId`]. The
    /// `(tenant_id, email)` UNIQUE constraint maps to
    /// [`SaasError::MemberAlreadyExists`] on collision.
    pub async fn invite_member(
        &self,
        tenant_id: &TenantId,
        email: &str,
        role: TenantRole,
        token_hash: &[u8],
        expires_at: i64,
    ) -> Result<MemberId, SaasError> {
        let id = MemberId::new();
        let result = sqlx::query(
            "INSERT INTO tenant_members \
                 (id, tenant_id, email, role, invite_token_hash, invite_token_expires_at) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        )
        .bind(id.as_bytes())
        .bind(tenant_id.as_bytes())
        .bind(email)
        .bind(role.as_str())
        .bind(token_hash)
        .bind(expires_at)
        .execute(&self.pool)
        .await;
        match result {
            Ok(_) => Ok(id),
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                Err(SaasError::MemberAlreadyExists)
            }
            Err(e) => Err(SaasError::Db(e)),
        }
    }

    /// Look up a pending invite by `token_hash` (read-only — does not
    /// consume the token). Used by the GET `/invite/{token}` page so the
    /// invitee can preview the tenant + role before posting back.
    pub async fn find_pending_invite_by_hash(
        &self,
        token_hash: &[u8],
    ) -> Result<Option<TenantMember>, SaasError> {
        let now_secs = chrono::Utc::now().timestamp();
        let row = sqlx::query_as::<_, TenantMember>(
            "SELECT id, tenant_id, email, role, invited_at, accepted_at, \
                    invite_token_expires_at \
             FROM tenant_members \
             WHERE invite_token_hash = ?1 \
               AND accepted_at IS NULL \
               AND (invite_token_expires_at IS NULL OR invite_token_expires_at > ?2)",
        )
        .bind(token_hash)
        .bind(now_secs)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Validate a pending invite by `token_hash`, mark it accepted, and
    /// return the row as it was *before* the UPDATE so the caller has the
    /// pre-clear `email` + `role`. Counterintuitive naming, but the
    /// alternative (return the post-UPDATE row with NULL token columns)
    /// is strictly worse for callers.
    pub async fn accept_invite(&self, token_hash: &[u8]) -> Result<TenantMember, SaasError> {
        let now_secs = chrono::Utc::now().timestamp();
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query_as::<_, TenantMember>(
            "SELECT id, tenant_id, email, role, invited_at, accepted_at, \
                    invite_token_expires_at \
             FROM tenant_members \
             WHERE invite_token_hash = ?1 \
               AND accepted_at IS NULL \
               AND (invite_token_expires_at IS NULL OR invite_token_expires_at > ?2)",
        )
        .bind(token_hash)
        .bind(now_secs)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or(SaasError::InviteNotFoundOrExpired)?;

        sqlx::query(
            "UPDATE tenant_members \
             SET accepted_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now'), \
                 invite_token_hash = NULL, \
                 invite_token_expires_at = NULL \
             WHERE id = ?1",
        )
        .bind(&row.id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(row)
    }
}

// ---------------------------------------------------------------------------
// tenant_members CRUD — last-owner-invariant writes.
//
// The invariant: a tenant must always have at least one accepted owner.
// We enforce it inside an explicit transaction (count owners, decide,
// then mutate) rather than relying on a single-statement subquery,
// which would be brittle to read and to test.
// ---------------------------------------------------------------------------

impl ControlDb {
    /// Number of accepted owners for the given tenant.
    pub async fn count_owners(&self, tenant_id: &TenantId) -> Result<i64, SaasError> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tenant_members \
             WHERE tenant_id = ?1 AND role = 'owner' AND accepted_at IS NOT NULL",
        )
        .bind(tenant_id.as_bytes())
        .fetch_one(&self.pool)
        .await?;
        Ok(n)
    }

    /// Update a member's role. Rejects with [`SaasError::CannotDemoteLastOwner`]
    /// if this would leave the tenant with zero accepted owners.
    pub async fn update_member_role(
        &self,
        member_id: &MemberId,
        new_role: TenantRole,
    ) -> Result<(), SaasError> {
        let mut tx = self.pool.begin().await?;
        let target: Option<(Vec<u8>, String, Option<DateTime<Utc>>)> =
            sqlx::query_as("SELECT tenant_id, role, accepted_at FROM tenant_members WHERE id = ?1")
                .bind(member_id.as_bytes())
                .fetch_optional(&mut *tx)
                .await?;
        let (tenant_blob, current_role, accepted_at) = target.ok_or(SaasError::MemberNotFound)?;

        let demoting_owner = current_role == "owner" && !matches!(new_role, TenantRole::Owner);
        if demoting_owner && accepted_at.is_some() {
            let n: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM tenant_members \
                 WHERE tenant_id = ?1 AND role = 'owner' AND accepted_at IS NOT NULL",
            )
            .bind(&tenant_blob)
            .fetch_one(&mut *tx)
            .await?;
            if n <= 1 {
                return Err(SaasError::CannotDemoteLastOwner);
            }
        }

        sqlx::query("UPDATE tenant_members SET role = ?1 WHERE id = ?2")
            .bind(new_role.as_str())
            .bind(member_id.as_bytes())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Remove a member. Rejects with [`SaasError::CannotRemoveLastOwner`]
    /// if removing this row would leave the tenant with zero accepted owners.
    pub async fn remove_member(&self, member_id: &MemberId) -> Result<(), SaasError> {
        let mut tx = self.pool.begin().await?;
        let target: Option<(Vec<u8>, String, Option<DateTime<Utc>>)> =
            sqlx::query_as("SELECT tenant_id, role, accepted_at FROM tenant_members WHERE id = ?1")
                .bind(member_id.as_bytes())
                .fetch_optional(&mut *tx)
                .await?;
        let (tenant_blob, role, accepted_at) = target.ok_or(SaasError::MemberNotFound)?;

        if role == "owner" && accepted_at.is_some() {
            let n: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM tenant_members \
                 WHERE tenant_id = ?1 AND role = 'owner' AND accepted_at IS NOT NULL",
            )
            .bind(&tenant_blob)
            .fetch_one(&mut *tx)
            .await?;
            if n <= 1 {
                return Err(SaasError::CannotRemoveLastOwner);
            }
        }

        sqlx::query("DELETE FROM tenant_members WHERE id = ?1")
            .bind(member_id.as_bytes())
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Super-admin control-plane types (99c.6 Step 1).
// ---------------------------------------------------------------------------

/// One row returned by [`ControlDb::search_tenants`].
#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct TenantOverviewRow {
    pub id: Vec<u8>,
    pub name: String,
    pub slug: String,
    pub owner_email: String,
    pub status: TenantStatus,
    pub plan_name: String,
    pub mau_count: i64,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// Column to sort [`ControlDb::search_tenants`] results by.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TenantSortCol {
    #[default]
    Name,
    Slug,
    Status,
    Plan,
    Mau,
    CreatedAt,
    LastSeenAt,
}

impl TenantSortCol {
    fn as_sql(&self) -> &'static str {
        match self {
            Self::Name => "t.name",
            Self::Slug => "t.slug",
            Self::Status => "t.status",
            Self::Plan => "p.name",
            Self::Mau => "COALESCE(tu.mau_count, 0)",
            Self::CreatedAt => "t.created_at",
            // NULLs sort last regardless of direction.
            Self::LastSeenAt => "COALESCE(t.last_seen_at, '')",
        }
    }
}

/// Sort direction for [`ControlDb::search_tenants`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SortDir {
    #[default]
    Asc,
    Desc,
}

impl SortDir {
    fn as_sql(&self) -> &'static str {
        match self {
            Self::Asc => "ASC",
            Self::Desc => "DESC",
        }
    }
}

/// Parameters for [`ControlDb::search_tenants`].
pub struct SearchTenantsParams<'a> {
    /// Optional search term matched against `name`, `slug`, and `owner_email`.
    pub query: Option<&'a str>,
    pub status: Option<TenantStatus>,
    /// Filter by raw BLOB `plan_id`. Computed by the handler from a plan name.
    pub plan_id: Option<&'a [u8]>,
    /// `%Y-%m` period string (UTC) used for the MAU LEFT JOIN. Computed by the
    /// handler; not embedded in the query to prevent SQL injection.
    pub current_period: &'a str,
    pub sort_col: TenantSortCol,
    pub sort_dir: SortDir,
    pub limit: u32,
    pub offset: u32,
}

/// Result of [`ControlDb::search_tenants`].
pub struct SearchTenantsResult {
    pub rows: Vec<TenantOverviewRow>,
    pub total: u32,
}

/// Per-period usage aggregate returned by [`ControlDb::aggregate_usage_for_period`]
/// and [`ControlDb::aggregate_usage_history`].
#[derive(Debug, Clone, Serialize)]
pub struct PeriodAggregate {
    pub period: String,
    pub total_mau: i64,
    pub active_tenants: i64,
}

// ---------------------------------------------------------------------------
// Super-admin queries — counts, search, aggregates, mutations (99c.6 Step 1).
// ---------------------------------------------------------------------------

impl ControlDb {
    /// Count tenants in a given status (active / suspended / deleted).
    pub async fn count_tenants_by_status(&self, status: TenantStatus) -> Result<i64, SaasError> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants WHERE status = ?1")
            .bind(status)
            .fetch_one(&self.pool)
            .await?;
        Ok(n)
    }

    /// Count tenants whose `created_at` is >= `since`.
    pub async fn count_tenants_created_since(
        &self,
        since: DateTime<Utc>,
    ) -> Result<i64, SaasError> {
        let n: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM tenants WHERE created_at >= ?1")
            .bind(since)
            .fetch_one(&self.pool)
            .await?;
        Ok(n)
    }

    /// Return `(plan_name, tenant_count)` pairs ordered by count descending.
    ///
    /// Deleted tenants are excluded. Plans with no tenants still appear with 0.
    pub async fn count_tenants_grouped_by_plan(&self) -> Result<Vec<(String, i64)>, SaasError> {
        let rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT p.name, COUNT(t.id) AS count \
             FROM tenant_plans p \
             LEFT JOIN tenants t ON t.plan_id = p.id AND t.status != 'deleted' \
             GROUP BY p.id, p.name \
             ORDER BY count DESC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Paginated, sortable, filterable tenant search.
    ///
    /// Mirrors the `Box::leak`+dynamic-WHERE pattern from `Db::search_users`.
    /// `plan_id` (BLOB) and `current_period` are bound separately from the
    /// string-typed binds to preserve positional correctness.
    pub async fn search_tenants(
        &self,
        p: SearchTenantsParams<'_>,
    ) -> Result<SearchTenantsResult, SaasError> {
        let mut where_clauses: Vec<String> = Vec::new();
        let mut string_binds: Vec<String> = Vec::new();

        if let Some(q) = p.query {
            let trimmed = q.trim();
            if !trimmed.is_empty() {
                let esc = trimmed
                    .replace('\\', "\\\\")
                    .replace('%', "\\%")
                    .replace('_', "\\_");
                let pat = format!("%{esc}%");
                where_clauses.push(
                    "(t.name LIKE ? ESCAPE '\\' \
                     OR t.slug LIKE ? ESCAPE '\\' \
                     OR t.owner_email LIKE ? ESCAPE '\\')"
                        .into(),
                );
                string_binds.push(pat.clone());
                string_binds.push(pat.clone());
                string_binds.push(pat);
            }
        }

        if let Some(s) = p.status {
            where_clauses.push("t.status = ?".into());
            let s_str = match s {
                TenantStatus::Active => "active",
                TenantStatus::Suspended => "suspended",
                TenantStatus::Deleted => "deleted",
            };
            string_binds.push(s_str.to_owned());
        }

        let has_plan_filter = p.plan_id.is_some();
        if has_plan_filter {
            where_clauses.push("t.plan_id = ?".into());
        }

        let where_sql = if where_clauses.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", where_clauses.join(" AND "))
        };

        // Count query — no JOINs needed; filter columns are all on `tenants`.
        let count_sql: &'static str =
            Box::leak(format!("SELECT COUNT(*) FROM tenants t {where_sql}").into_boxed_str());
        let mut count_q = sqlx::query_scalar::<_, i64>(count_sql);
        for v in &string_binds {
            count_q = count_q.bind(v);
        }
        if let Some(pid) = p.plan_id {
            count_q = count_q.bind(pid);
        }
        let total = count_q.fetch_one(&self.pool).await? as u32;

        // Data query — LEFT JOIN usage for MAU; JOIN plans for plan name.
        // sort_col/sort_dir come from an enum allowlist — no injection risk.
        let sort_col_sql = p.sort_col.as_sql();
        let sort_dir_sql = p.sort_dir.as_sql();
        let data_sql: &'static str = Box::leak(
            format!(
                "SELECT t.id, t.name, t.slug, t.owner_email, t.status, \
                 t.created_at, t.last_seen_at, \
                 p.name AS plan_name, COALESCE(tu.mau_count, 0) AS mau_count \
                 FROM tenants t \
                 JOIN tenant_plans p ON p.id = t.plan_id \
                 LEFT JOIN tenant_usage tu \
                   ON tu.tenant_id = t.id AND tu.period = ? \
                 {where_sql} \
                 ORDER BY {sort_col_sql} {sort_dir_sql} \
                 LIMIT ? OFFSET ?"
            )
            .into_boxed_str(),
        );
        let mut data_q = sqlx::query_as::<_, TenantOverviewRow>(data_sql).bind(p.current_period);
        for v in &string_binds {
            data_q = data_q.bind(v);
        }
        if let Some(pid) = p.plan_id {
            data_q = data_q.bind(pid);
        }
        data_q = data_q.bind(p.limit).bind(p.offset);

        let rows = data_q.fetch_all(&self.pool).await?;

        Ok(SearchTenantsResult { rows, total })
    }

    /// Aggregate MAU + active-tenant count for a single period (e.g. `"2026-05"`).
    ///
    /// Returns zeros when no usage rows exist for the period.
    pub async fn aggregate_usage_for_period(
        &self,
        period: &str,
    ) -> Result<PeriodAggregate, SaasError> {
        let (total_mau, active_tenants): (i64, i64) = sqlx::query_as(
            "SELECT \
               COALESCE(SUM(mau_count), 0) AS total_mau, \
               COUNT(CASE WHEN mau_count > 0 THEN 1 END) AS active_tenants \
             FROM tenant_usage \
             WHERE period = ?1",
        )
        .bind(period)
        .fetch_one(&self.pool)
        .await?;

        Ok(PeriodAggregate {
            period: period.to_owned(),
            total_mau,
            active_tenants,
        })
    }

    /// Return the `n_months` most-recent per-period aggregates, newest first.
    pub async fn aggregate_usage_history(
        &self,
        n_months: u32,
    ) -> Result<Vec<PeriodAggregate>, SaasError> {
        let rows: Vec<(String, i64, i64)> = sqlx::query_as(
            "SELECT period, \
               SUM(mau_count) AS total_mau, \
               COUNT(CASE WHEN mau_count > 0 THEN 1 END) AS active_tenants \
             FROM tenant_usage \
             GROUP BY period \
             ORDER BY period DESC \
             LIMIT ?1",
        )
        .bind(n_months)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(period, total_mau, active_tenants)| PeriodAggregate {
                period,
                total_mau,
                active_tenants,
            })
            .collect())
    }

    /// Count non-deleted tenants that have not been seen since `before`
    /// (i.e. `last_seen_at` is NULL or earlier than the threshold).
    pub async fn count_dormant_tenants(&self, before: DateTime<Utc>) -> Result<i64, SaasError> {
        let n: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM tenants \
             WHERE status != 'deleted' \
               AND (last_seen_at IS NULL OR last_seen_at < ?1)",
        )
        .bind(before)
        .fetch_one(&self.pool)
        .await?;
        Ok(n)
    }

    /// Set a tenant's status. Bumps `updated_at`.
    pub async fn set_tenant_status(
        &self,
        tenant_id: &TenantId,
        status: TenantStatus,
    ) -> Result<(), SaasError> {
        sqlx::query(
            "UPDATE tenants \
             SET status = ?1, \
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
             WHERE id = ?2",
        )
        .bind(status)
        .bind(tenant_id.as_bytes())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Set a tenant's plan. Bumps `updated_at`.
    pub async fn set_tenant_plan(
        &self,
        tenant_id: &TenantId,
        plan_id: &[u8],
    ) -> Result<(), SaasError> {
        sqlx::query(
            "UPDATE tenants \
             SET plan_id = ?1, \
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
             WHERE id = ?2",
        )
        .bind(plan_id)
        .bind(tenant_id.as_bytes())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// All available plans ordered by `price_cents ASC`.
    pub async fn list_plans(&self) -> Result<Vec<TenantPlan>, SaasError> {
        let rows = sqlx::query_as::<_, TenantPlan>(
            "SELECT id, name, mau_limit, price_cents, features \
             FROM tenant_plans \
             ORDER BY price_cents ASC",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Look up a plan by its raw BLOB id. Returns `None` if not found.
    pub async fn get_plan_by_id(&self, plan_id: &[u8]) -> Result<Option<TenantPlan>, SaasError> {
        let row = sqlx::query_as::<_, TenantPlan>(
            "SELECT id, name, mau_limit, price_cents, features \
             FROM tenant_plans WHERE id = ?1",
        )
        .bind(plan_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }
}

// ---------------------------------------------------------------------------
// tenant_domains CRUD
// ---------------------------------------------------------------------------

impl ControlDb {
    /// Insert a new domain row for the tenant with `status = pending_verification`.
    ///
    /// Maps a UNIQUE violation on `domain` to [`SaasError::DomainAlreadyExists`].
    pub async fn create_tenant_domain(
        &self,
        tenant_id: &crate::tenants::TenantId,
        domain: &str,
        dns_target: &str,
    ) -> Result<crate::domains::TenantDomain, SaasError> {
        use crate::domains::{DomainId, DomainStatus, TenantDomain};

        let id = DomainId::new();
        let result = sqlx::query(
            "INSERT INTO tenant_domains \
                 (id, tenant_id, domain, status, dns_target) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
        )
        .bind(id.as_bytes())
        .bind(tenant_id.as_bytes())
        .bind(domain)
        .bind(DomainStatus::PendingVerification.as_str())
        .bind(dns_target)
        .execute(&self.pool)
        .await;

        match result {
            Ok(_) => {}
            Err(sqlx::Error::Database(db_err)) if db_err.is_unique_violation() => {
                return Err(SaasError::DomainAlreadyExists);
            }
            Err(e) => return Err(SaasError::Db(e)),
        }

        let row = sqlx::query_as::<_, TenantDomain>(
            "SELECT id, tenant_id, domain, status, dns_target, \
                    verified_at, cert_expires_at, last_error, created_at, updated_at \
             FROM tenant_domains WHERE id = ?1",
        )
        .bind(id.as_bytes())
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    /// All domains for the given tenant, ordered newest-first.
    pub async fn list_tenant_domains(
        &self,
        tenant_id: &crate::tenants::TenantId,
    ) -> Result<Vec<crate::domains::TenantDomain>, SaasError> {
        use crate::domains::TenantDomain;

        let rows = sqlx::query_as::<_, TenantDomain>(
            "SELECT id, tenant_id, domain, status, dns_target, \
                    verified_at, cert_expires_at, last_error, created_at, updated_at \
             FROM tenant_domains \
             WHERE tenant_id = ?1 \
             ORDER BY created_at DESC",
        )
        .bind(tenant_id.as_bytes())
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Fetch a single domain row only if it belongs to `tenant_id`.
    ///
    /// Returns `None` when the domain does not exist or belongs to another
    /// tenant (caller should treat both as 404 at the API boundary).
    pub async fn get_tenant_domain_scoped(
        &self,
        domain_id: &crate::domains::DomainId,
        tenant_id: &crate::tenants::TenantId,
    ) -> Result<Option<crate::domains::TenantDomain>, SaasError> {
        use crate::domains::TenantDomain;

        let row = sqlx::query_as::<_, TenantDomain>(
            "SELECT id, tenant_id, domain, status, dns_target, \
                    verified_at, cert_expires_at, last_error, created_at, updated_at \
             FROM tenant_domains \
             WHERE id = ?1 AND tenant_id = ?2",
        )
        .bind(domain_id.as_bytes())
        .bind(tenant_id.as_bytes())
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Update the status of a domain row, bumping `updated_at`.
    ///
    /// - `verified_at` is set only when transitioning to `Verified`.
    /// - `last_error` is cleared on `Verified` and set on `Failed`.
    pub async fn set_tenant_domain_status(
        &self,
        domain_id: &crate::domains::DomainId,
        status: crate::domains::DomainStatus,
        verified_at: Option<chrono::DateTime<chrono::Utc>>,
        last_error: Option<&str>,
    ) -> Result<(), SaasError> {
        sqlx::query(
            "UPDATE tenant_domains \
             SET status = ?1, \
                 verified_at = ?2, \
                 last_error = ?3, \
                 updated_at = strftime('%Y-%m-%dT%H:%M:%fZ', 'now') \
             WHERE id = ?4",
        )
        .bind(status.as_str())
        .bind(verified_at)
        .bind(last_error)
        .bind(domain_id.as_bytes())
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Delete a domain row only if it belongs to `tenant_id`.
    ///
    /// Returns `true` when a row was deleted, `false` when the domain did not
    /// exist or belonged to another tenant.
    pub async fn delete_tenant_domain_scoped(
        &self,
        domain_id: &crate::domains::DomainId,
        tenant_id: &crate::tenants::TenantId,
    ) -> Result<bool, SaasError> {
        let result = sqlx::query("DELETE FROM tenant_domains WHERE id = ?1 AND tenant_id = ?2")
            .bind(domain_id.as_bytes())
            .bind(tenant_id.as_bytes())
            .execute(&self.pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Find the tenant whose custom domain matches `domain` and whose status
    /// is `verified` or `active`. Used by 38y.2's router fallback.
    ///
    /// Input is lowercased before binding (DNS is case-insensitive; storage
    /// is always lowercase).
    pub async fn tenant_by_custom_domain(
        &self,
        domain: &str,
    ) -> Result<Option<crate::tenants::Tenant>, SaasError> {
        use crate::tenants::Tenant;

        let lower = domain.to_lowercase();
        let row = sqlx::query_as::<_, Tenant>(
            "SELECT t.id, t.name, t.slug, t.owner_email, t.plan_id, t.status, \
                    t.db_path, t.last_seen_at, t.created_at, t.updated_at \
             FROM tenants t \
             JOIN tenant_domains d ON d.tenant_id = t.id \
             WHERE d.domain = ?1 \
               AND d.status IN ('verified', 'active')",
        )
        .bind(&lower)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row)
    }

    /// Rows eligible for the background verification sweep: those with status
    /// `pending_verification` or `failed`, ordered oldest-first, capped at
    /// `limit`.
    pub async fn list_domains_for_sweep(
        &self,
        limit: i64,
    ) -> Result<Vec<crate::domains::TenantDomain>, SaasError> {
        use crate::domains::TenantDomain;

        let rows = sqlx::query_as::<_, TenantDomain>(
            "SELECT id, tenant_id, domain, status, dns_target, \
                    verified_at, cert_expires_at, last_error, created_at, updated_at \
             FROM tenant_domains \
             WHERE status IN ('pending_verification', 'failed') \
             ORDER BY updated_at ASC \
             LIMIT ?1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sqlx::Row;
    use std::str::FromStr;

    pub async fn test_pool() -> SqlitePool {
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .pragma("foreign_keys", "ON");
        SqlitePool::connect_with(opts).await.unwrap()
    }

    #[tokio::test]
    async fn control_db_runs_migrations() {
        let pool = test_pool().await;
        let db = ControlDb::new(pool).await;
        assert!(db.is_ok());
    }

    #[tokio::test]
    async fn log_control_audit_inserts_row() {
        let pool = test_pool().await;
        let db = ControlDb::new(pool).await.unwrap();
        db.log_control_audit(
            "owner@acme.com",
            "tenant.provisioned",
            None,
            &serde_json::json!({"slug": "acme"}),
        )
        .await
        .expect("log_control_audit");

        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM control_audit_events")
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(count, 1);

        let (actor, action, ctx): (String, String, String) =
            sqlx::query_as("SELECT actor, action, context FROM control_audit_events LIMIT 1")
                .fetch_one(db.pool())
                .await
                .unwrap();
        assert_eq!(actor, "owner@acme.com");
        assert_eq!(action, "tenant.provisioned");
        assert!(ctx.contains("acme"));
    }

    #[tokio::test]
    async fn tenant_slug_unique() {
        let pool = test_pool().await;
        let db = ControlDb::new(pool).await.unwrap();
        let row = sqlx::query("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let plan_id: Vec<u8> = row.get("id");
        let id_a = uuid::Uuid::new_v4();
        let id_b = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'Acme', 'acme', 'a@a.com', ?, 'active', 'acme.db')",
        )
        .bind(id_a.as_bytes().as_ref())
        .bind(&plan_id)
        .execute(db.pool())
        .await
        .unwrap();
        let res = sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'Acme 2', 'acme', 'b@b.com', ?, 'active', 'acme2.db')",
        )
        .bind(id_b.as_bytes().as_ref())
        .bind(&plan_id)
        .execute(db.pool())
        .await;
        assert!(res.is_err(), "duplicate slug should be rejected");
    }

    #[tokio::test]
    async fn tenant_status_check_rejects_invalid() {
        let pool = test_pool().await;
        let db = ControlDb::new(pool).await.unwrap();
        let row = sqlx::query("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let plan_id: Vec<u8> = row.get("id");
        let id = uuid::Uuid::new_v4();
        let res = sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'Bad', 'bad-status', 'c@c.com', ?, 'banned', 'bad.db')",
        )
        .bind(id.as_bytes().as_ref())
        .bind(&plan_id)
        .execute(db.pool())
        .await;
        assert!(res.is_err(), "invalid status should be rejected by CHECK");
    }

    #[tokio::test]
    async fn member_role_check_rejects_invalid() {
        let pool = test_pool().await;
        let db = ControlDb::new(pool).await.unwrap();
        let row = sqlx::query("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let plan_id: Vec<u8> = row.get("id");
        let tenant_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'Role Test', 'role-test', 'd@d.com', ?, 'active', 'rtest.db')",
        )
        .bind(tenant_id.as_bytes().as_ref())
        .bind(&plan_id)
        .execute(db.pool())
        .await
        .unwrap();
        let member_id = uuid::Uuid::new_v4();
        let res = sqlx::query(
            "INSERT INTO tenant_members (id, tenant_id, email, role) \
             VALUES (?, ?, 'e@e.com', 'superuser')",
        )
        .bind(member_id.as_bytes().as_ref())
        .bind(tenant_id.as_bytes().as_ref())
        .execute(db.pool())
        .await;
        assert!(res.is_err(), "invalid role should be rejected by CHECK");
    }

    #[tokio::test]
    async fn usage_for_tenant_returns_records() {
        let pool = test_pool().await;
        let db = ControlDb::new(pool).await.unwrap();
        let row = sqlx::query("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let plan_id: Vec<u8> = row.get("id");
        let tid = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'U', 'usagetest', 'u@u.com', ?, 'active', 'u.db')",
        )
        .bind(tid.as_bytes().as_ref())
        .bind(&plan_id)
        .execute(db.pool())
        .await
        .unwrap();
        let uid = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenant_usage (id, tenant_id, period, mau_count) \
             VALUES (?, ?, '2026-04', 42)",
        )
        .bind(uid.as_bytes().as_ref())
        .bind(tid.as_bytes().as_ref())
        .execute(db.pool())
        .await
        .unwrap();
        let tenant_id = TenantId::from(tid);
        let usage = db.usage_for_tenant(&tenant_id).await.unwrap();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].period, "2026-04");
        assert_eq!(usage[0].mau_count, 42);
        assert!(usage[0].limit_reached_at.is_none());
    }

    #[tokio::test]
    async fn api_key_hash_unique() {
        let pool = test_pool().await;
        let db = ControlDb::new(pool).await.unwrap();
        let row = sqlx::query("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let plan_id: Vec<u8> = row.get("id");
        let tenant_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'Key Test', 'key-test', 'f@f.com', ?, 'active', 'ktest.db')",
        )
        .bind(tenant_id.as_bytes().as_ref())
        .bind(&plan_id)
        .execute(db.pool())
        .await
        .unwrap();
        let hash = vec![0u8; 32];
        let key_id_a = uuid::Uuid::new_v4();
        let key_id_b = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenant_api_keys (id, tenant_id, name, key_hash, scope) \
             VALUES (?, ?, 'key-a', ?, '[]')",
        )
        .bind(key_id_a.as_bytes().as_ref())
        .bind(tenant_id.as_bytes().as_ref())
        .bind(&hash)
        .execute(db.pool())
        .await
        .unwrap();
        let res = sqlx::query(
            "INSERT INTO tenant_api_keys (id, tenant_id, name, key_hash, scope) \
             VALUES (?, ?, 'key-b', ?, '[]')",
        )
        .bind(key_id_b.as_bytes().as_ref())
        .bind(tenant_id.as_bytes().as_ref())
        .bind(&hash)
        .execute(db.pool())
        .await;
        assert!(res.is_err(), "duplicate key_hash should be rejected");
    }

    /// Helper: insert a tenant row with the given slug + status; return its `TenantId`.
    async fn seed_tenant_with_status(db: &ControlDb, slug: &str, status: &str) -> TenantId {
        let plan_id: Vec<u8> = sqlx::query_scalar("SELECT id FROM tenant_plans LIMIT 1")
            .fetch_one(db.pool())
            .await
            .unwrap();
        let tid = uuid::Uuid::new_v4();
        let db_path = format!("{slug}.db");
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(tid.as_bytes().as_ref())
        .bind(slug)
        .bind(slug)
        .bind(format!("owner-{slug}@example.com"))
        .bind(&plan_id)
        .bind(status)
        .bind(&db_path)
        .execute(db.pool())
        .await
        .unwrap();
        TenantId::from(tid)
    }

    async fn seed_tenant(db: &ControlDb, slug: &str) -> TenantId {
        seed_tenant_with_status(db, slug, "active").await
    }

    async fn insert_member(
        db: &ControlDb,
        tenant_id: &TenantId,
        email: &str,
        role: &str,
        accepted: bool,
    ) {
        let id = uuid::Uuid::new_v4();
        if accepted {
            sqlx::query(
                "INSERT INTO tenant_members (id, tenant_id, email, role, accepted_at) \
                 VALUES (?, ?, ?, ?, datetime('now'))",
            )
            .bind(id.as_bytes().as_ref())
            .bind(tenant_id.as_bytes())
            .bind(email)
            .bind(role)
            .execute(db.pool())
            .await
            .unwrap();
        } else {
            sqlx::query(
                "INSERT INTO tenant_members (id, tenant_id, email, role) \
                 VALUES (?, ?, ?, ?)",
            )
            .bind(id.as_bytes().as_ref())
            .bind(tenant_id.as_bytes())
            .bind(email)
            .bind(role)
            .execute(db.pool())
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn member_role_returns_role_for_accepted_member() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "acme").await;
        insert_member(&db, &tid, "alice@x.com", "admin", true).await;

        let role = db.member_role(&tid, "alice@x.com").await.unwrap();
        assert_eq!(role, Some(TenantRole::Admin));
    }

    #[tokio::test]
    async fn member_role_ignores_unaccepted_invite() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "acme").await;
        insert_member(&db, &tid, "bob@x.com", "viewer", false).await;

        let role = db.member_role(&tid, "bob@x.com").await.unwrap();
        assert_eq!(role, None);
    }

    #[tokio::test]
    async fn member_role_returns_none_for_non_member() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "acme").await;

        let role = db.member_role(&tid, "stranger@x.com").await.unwrap();
        assert_eq!(role, None);
    }

    #[tokio::test]
    async fn tenants_for_member_returns_pairs_sorted_by_name() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let zid = seed_tenant(&db, "zulu").await;
        let aid = seed_tenant(&db, "alpha").await;
        insert_member(&db, &aid, "x@y.com", "owner", true).await;
        insert_member(&db, &zid, "x@y.com", "admin", true).await;

        let pairs = db.tenants_for_member("x@y.com").await.unwrap();
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0].0.slug, "alpha");
        assert_eq!(pairs[0].1, TenantRole::Owner);
        assert_eq!(pairs[1].0.slug, "zulu");
        assert_eq!(pairs[1].1, TenantRole::Admin);
    }

    #[tokio::test]
    async fn tenants_for_member_excludes_deleted_tenants() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant_with_status(&db, "deadco", "deleted").await;
        insert_member(&db, &tid, "x@y.com", "owner", true).await;

        let pairs = db.tenants_for_member("x@y.com").await.unwrap();
        assert!(pairs.is_empty());
    }

    #[tokio::test]
    async fn tenants_for_member_excludes_unaccepted_invites() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "acme").await;
        insert_member(&db, &tid, "pending@x.com", "viewer", false).await;

        let pairs = db.tenants_for_member("pending@x.com").await.unwrap();
        assert!(pairs.is_empty());
    }

    // ----- 99c.5 Step 3: tenant_members CRUD -----

    fn token_hash(seed: u8) -> Vec<u8> {
        vec![seed; 32]
    }

    fn future_ts() -> i64 {
        chrono::Utc::now().timestamp() + 60 * 60 * 24
    }

    #[tokio::test]
    async fn list_tenant_members_returns_pending_first() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "listtest").await;
        insert_member(&db, &tid, "owner@x.com", "owner", true).await;
        db.invite_member(
            &tid,
            "pending@x.com",
            TenantRole::Admin,
            &token_hash(1),
            future_ts(),
        )
        .await
        .unwrap();

        let members = db.list_tenant_members(&tid).await.unwrap();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].email, "pending@x.com");
        assert!(members[0].accepted_at.is_none());
        assert_eq!(members[1].email, "owner@x.com");
        assert!(members[1].accepted_at.is_some());
    }

    #[tokio::test]
    async fn invite_member_unique_collision_returns_error() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "collide").await;
        db.invite_member(
            &tid,
            "dup@x.com",
            TenantRole::Viewer,
            &token_hash(2),
            future_ts(),
        )
        .await
        .unwrap();
        let err = db
            .invite_member(
                &tid,
                "dup@x.com",
                TenantRole::Viewer,
                &token_hash(3),
                future_ts(),
            )
            .await
            .expect_err("second invite must collide");
        assert!(matches!(err, SaasError::MemberAlreadyExists));
    }

    #[tokio::test]
    async fn accept_invite_happy_path_clears_token() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "happy").await;
        let hash = token_hash(4);
        db.invite_member(&tid, "joiner@x.com", TenantRole::Admin, &hash, future_ts())
            .await
            .unwrap();

        let row = db.accept_invite(&hash).await.unwrap();
        assert_eq!(row.email, "joiner@x.com");
        assert!(
            row.accepted_at.is_none(),
            "pre-update row carries the prior NULL accepted_at"
        );

        let mid = row.id_as_member_id().unwrap();
        let after = db.get_tenant_member(&mid).await.unwrap().unwrap();
        assert!(after.accepted_at.is_some());
        assert!(after.invite_token_expires_at.is_none());
    }

    #[tokio::test]
    async fn accept_invite_expired_returns_error() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "expired").await;
        let hash = token_hash(5);
        let past = chrono::Utc::now().timestamp() - 60;
        db.invite_member(&tid, "stale@x.com", TenantRole::Viewer, &hash, past)
            .await
            .unwrap();
        let err = db.accept_invite(&hash).await.expect_err("expired");
        assert!(matches!(err, SaasError::InviteNotFoundOrExpired));
    }

    #[tokio::test]
    async fn accept_invite_already_accepted_returns_error() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "twice").await;
        let hash = token_hash(6);
        db.invite_member(&tid, "once@x.com", TenantRole::Admin, &hash, future_ts())
            .await
            .unwrap();
        db.accept_invite(&hash).await.unwrap();
        let err = db.accept_invite(&hash).await.expect_err("re-accept");
        assert!(matches!(err, SaasError::InviteNotFoundOrExpired));
    }

    #[tokio::test]
    async fn find_pending_invite_skips_expired_and_accepted() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "find").await;
        let live = token_hash(7);
        db.invite_member(&tid, "live@x.com", TenantRole::Viewer, &live, future_ts())
            .await
            .unwrap();
        let found = db.find_pending_invite_by_hash(&live).await.unwrap();
        assert!(found.is_some());

        db.accept_invite(&live).await.unwrap();
        let after = db.find_pending_invite_by_hash(&live).await.unwrap();
        assert!(after.is_none());
    }

    // ----- 99c.5 Step 4: last-owner invariant -----

    /// Insert an accepted member and return the typed [`MemberId`] so
    /// last-owner tests can target the row directly.
    async fn insert_member_typed(
        db: &ControlDb,
        tenant_id: &TenantId,
        email: &str,
        role: &str,
    ) -> MemberId {
        let mid = MemberId::new();
        sqlx::query(
            "INSERT INTO tenant_members (id, tenant_id, email, role, accepted_at) \
             VALUES (?, ?, ?, ?, datetime('now'))",
        )
        .bind(mid.as_bytes())
        .bind(tenant_id.as_bytes())
        .bind(email)
        .bind(role)
        .execute(db.pool())
        .await
        .unwrap();
        mid
    }

    #[tokio::test]
    async fn count_owners_counts_only_accepted_owners() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "count").await;
        insert_member_typed(&db, &tid, "owner@x.com", "owner").await;
        insert_member_typed(&db, &tid, "admin@x.com", "admin").await;
        // Pending owner — must NOT count.
        db.invite_member(
            &tid,
            "pending@x.com",
            TenantRole::Owner,
            &token_hash(8),
            future_ts(),
        )
        .await
        .unwrap();

        assert_eq!(db.count_owners(&tid).await.unwrap(), 1);
    }

    #[tokio::test]
    async fn update_member_role_demote_last_owner_fails() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "demote-last").await;
        let owner = insert_member_typed(&db, &tid, "lone@x.com", "owner").await;

        let err = db
            .update_member_role(&owner, TenantRole::Admin)
            .await
            .expect_err("demote sole owner");
        assert!(matches!(err, SaasError::CannotDemoteLastOwner));

        // Row unchanged.
        let after = db.get_tenant_member(&owner).await.unwrap().unwrap();
        assert_eq!(after.role, TenantRole::Owner);
    }

    #[tokio::test]
    async fn update_member_role_demote_one_of_two_owners_succeeds() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "demote-ok").await;
        let first = insert_member_typed(&db, &tid, "a@x.com", "owner").await;
        insert_member_typed(&db, &tid, "b@x.com", "owner").await;

        db.update_member_role(&first, TenantRole::Admin)
            .await
            .unwrap();
        let after = db.get_tenant_member(&first).await.unwrap().unwrap();
        assert_eq!(after.role, TenantRole::Admin);
    }

    #[tokio::test]
    async fn update_role_unknown_member_returns_not_found() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let bogus = MemberId::new();
        let err = db
            .update_member_role(&bogus, TenantRole::Admin)
            .await
            .expect_err("unknown");
        assert!(matches!(err, SaasError::MemberNotFound));
    }

    #[tokio::test]
    async fn remove_last_owner_fails() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "rm-last").await;
        let owner = insert_member_typed(&db, &tid, "only@x.com", "owner").await;

        let err = db.remove_member(&owner).await.expect_err("remove last");
        assert!(matches!(err, SaasError::CannotRemoveLastOwner));
        assert!(db.get_tenant_member(&owner).await.unwrap().is_some());
    }

    #[tokio::test]
    async fn remove_one_of_two_owners_succeeds() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "rm-ok").await;
        let first = insert_member_typed(&db, &tid, "a@x.com", "owner").await;
        insert_member_typed(&db, &tid, "b@x.com", "owner").await;

        db.remove_member(&first).await.unwrap();
        assert!(db.get_tenant_member(&first).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn remove_admin_succeeds() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "rm-admin").await;
        insert_member_typed(&db, &tid, "owner@x.com", "owner").await;
        let admin = insert_member_typed(&db, &tid, "admin@x.com", "admin").await;

        db.remove_member(&admin).await.unwrap();
        assert!(db.get_tenant_member(&admin).await.unwrap().is_none());
    }

    // ---- 99c.6 Step 1: super-admin queries ----

    #[tokio::test]
    async fn count_tenants_by_status_returns_correct_counts() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        seed_tenant_with_status(&db, "active-a", "active").await;
        seed_tenant_with_status(&db, "active-b", "active").await;
        seed_tenant_with_status(&db, "active-c", "active").await;
        seed_tenant_with_status(&db, "suspended-a", "suspended").await;
        seed_tenant_with_status(&db, "suspended-b", "suspended").await;
        seed_tenant_with_status(&db, "deleted-a", "deleted").await;

        assert_eq!(
            db.count_tenants_by_status(TenantStatus::Active)
                .await
                .unwrap(),
            3
        );
        assert_eq!(
            db.count_tenants_by_status(TenantStatus::Suspended)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            db.count_tenants_by_status(TenantStatus::Deleted)
                .await
                .unwrap(),
            1
        );
    }

    #[tokio::test]
    async fn count_tenants_created_since_threshold() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        seed_tenant(&db, "old-a").await;
        seed_tenant(&db, "old-b").await;

        let threshold = chrono::Utc::now();
        seed_tenant(&db, "new-a").await;

        // At minimum new-a was created after threshold (all three were inserted
        // in tight succession, but at least one must qualify).
        let after = db.count_tenants_created_since(threshold).await.unwrap();
        let all = db
            .count_tenants_created_since(chrono::DateTime::UNIX_EPOCH)
            .await
            .unwrap();
        assert_eq!(all, 3);
        assert!(after >= 0 && after <= 3, "threshold count in sane range");
    }

    #[tokio::test]
    async fn count_tenants_grouped_by_plan_returns_all_plans_zero() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        // No tenants seeded — all four seed plans should appear with count 0.
        let by_plan = db.count_tenants_grouped_by_plan().await.unwrap();
        assert_eq!(by_plan.len(), 4, "all 4 seed plans returned");
        assert!(by_plan.iter().all(|(_, c)| *c == 0));
    }

    #[tokio::test]
    async fn count_tenants_grouped_by_plan_counts_correctly() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let plans: Vec<(Vec<u8>, String)> =
            sqlx::query_as("SELECT id, name FROM tenant_plans ORDER BY price_cents ASC LIMIT 2")
                .fetch_all(db.pool())
                .await
                .unwrap();
        let (dev_id, _) = &plans[0];
        let (starter_id, _) = &plans[1];

        for slug in ["dev-a", "dev-b"] {
            let id = uuid::Uuid::new_v4();
            sqlx::query(
                "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
                 VALUES (?, ?, ?, ?, ?, 'active', ?)",
            )
            .bind(id.as_bytes().as_ref())
            .bind(slug)
            .bind(slug)
            .bind(format!("{slug}@x.com"))
            .bind(dev_id)
            .bind(format!("{slug}.db"))
            .execute(db.pool())
            .await
            .unwrap();
        }
        let sid = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, owner_email, plan_id, status, db_path) \
             VALUES (?, 'Starter', 'strt', 'strt@x.com', ?, 'active', 'strt.db')",
        )
        .bind(sid.as_bytes().as_ref())
        .bind(starter_id)
        .execute(db.pool())
        .await
        .unwrap();

        let by_plan = db.count_tenants_grouped_by_plan().await.unwrap();
        let dev_count = by_plan.iter().find(|(n, _)| n == "dev").map(|(_, c)| *c);
        let starter_count = by_plan
            .iter()
            .find(|(n, _)| n == "starter")
            .map(|(_, c)| *c);
        assert_eq!(dev_count, Some(2));
        assert_eq!(starter_count, Some(1));
    }

    #[tokio::test]
    async fn search_tenants_no_filter_returns_all() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        seed_tenant(&db, "alpha").await;
        seed_tenant(&db, "beta").await;
        seed_tenant(&db, "gamma").await;

        let result = db
            .search_tenants(SearchTenantsParams {
                query: None,
                status: None,
                plan_id: None,
                current_period: "2026-05",
                sort_col: TenantSortCol::Name,
                sort_dir: SortDir::Asc,
                limit: 25,
                offset: 0,
            })
            .await
            .unwrap();

        assert_eq!(result.total, 3);
        assert_eq!(result.rows.len(), 3);
        assert_eq!(result.rows[0].slug, "alpha");
        assert_eq!(result.rows[2].slug, "gamma");
    }

    #[tokio::test]
    async fn search_tenants_query_matches_slug_and_name() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        seed_tenant(&db, "acme").await;
        seed_tenant(&db, "acme-staging").await;
        seed_tenant(&db, "beta").await;

        let result = db
            .search_tenants(SearchTenantsParams {
                query: Some("acme"),
                status: None,
                plan_id: None,
                current_period: "2026-05",
                sort_col: TenantSortCol::Name,
                sort_dir: SortDir::Asc,
                limit: 25,
                offset: 0,
            })
            .await
            .unwrap();

        assert_eq!(result.total, 2);
        assert!(result.rows.iter().all(|r| r.slug.contains("acme")));
    }

    #[tokio::test]
    async fn search_tenants_status_filter() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        seed_tenant_with_status(&db, "susp-a", "suspended").await;
        seed_tenant_with_status(&db, "susp-b", "suspended").await;
        seed_tenant(&db, "active-z").await;

        let result = db
            .search_tenants(SearchTenantsParams {
                query: None,
                status: Some(TenantStatus::Suspended),
                plan_id: None,
                current_period: "2026-05",
                sort_col: TenantSortCol::Name,
                sort_dir: SortDir::Asc,
                limit: 25,
                offset: 0,
            })
            .await
            .unwrap();

        assert_eq!(result.total, 2);
        assert!(
            result
                .rows
                .iter()
                .all(|r| r.status == TenantStatus::Suspended)
        );
    }

    #[tokio::test]
    async fn search_tenants_pagination() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        for i in 0..30u32 {
            seed_tenant(&db, &format!("page-t-{i:02}")).await;
        }

        let page1 = db
            .search_tenants(SearchTenantsParams {
                query: None,
                status: None,
                plan_id: None,
                current_period: "2026-05",
                sort_col: TenantSortCol::Name,
                sort_dir: SortDir::Asc,
                limit: 25,
                offset: 0,
            })
            .await
            .unwrap();
        let page2 = db
            .search_tenants(SearchTenantsParams {
                query: None,
                status: None,
                plan_id: None,
                current_period: "2026-05",
                sort_col: TenantSortCol::Name,
                sort_dir: SortDir::Asc,
                limit: 25,
                offset: 25,
            })
            .await
            .unwrap();

        assert_eq!(page1.total, 30);
        assert_eq!(page1.rows.len(), 25);
        assert_eq!(page2.rows.len(), 5);
    }

    #[tokio::test]
    async fn search_tenants_sort_name_desc() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        seed_tenant(&db, "aaa").await;
        seed_tenant(&db, "bbb").await;
        seed_tenant(&db, "ccc").await;

        let result = db
            .search_tenants(SearchTenantsParams {
                query: None,
                status: None,
                plan_id: None,
                current_period: "2026-05",
                sort_col: TenantSortCol::Name,
                sort_dir: SortDir::Desc,
                limit: 25,
                offset: 0,
            })
            .await
            .unwrap();

        assert_eq!(result.rows[0].slug, "ccc");
        assert_eq!(result.rows[2].slug, "aaa");
    }

    #[tokio::test]
    async fn aggregate_usage_for_period_returns_zeros_when_empty() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let agg = db.aggregate_usage_for_period("2026-05").await.unwrap();
        assert_eq!(agg.period, "2026-05");
        assert_eq!(agg.total_mau, 0);
        assert_eq!(agg.active_tenants, 0);
    }

    #[tokio::test]
    async fn aggregate_usage_for_period_sums_correctly() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let ta = seed_tenant(&db, "agg-a").await;
        let tb = seed_tenant(&db, "agg-b").await;
        let tc = seed_tenant(&db, "agg-c").await;

        for (tid, mau) in [(&ta, 100i64), (&tb, 200), (&tc, 0)] {
            let uid = uuid::Uuid::new_v4();
            sqlx::query(
                "INSERT INTO tenant_usage (id, tenant_id, period, mau_count) \
                 VALUES (?, ?, '2026-05', ?)",
            )
            .bind(uid.as_bytes().as_ref())
            .bind(tid.as_bytes())
            .bind(mau)
            .execute(db.pool())
            .await
            .unwrap();
        }

        let agg = db.aggregate_usage_for_period("2026-05").await.unwrap();
        assert_eq!(agg.total_mau, 300);
        // tc has mau_count=0 → not counted as active.
        assert_eq!(agg.active_tenants, 2);
    }

    #[tokio::test]
    async fn aggregate_usage_history_returns_n_most_recent() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "hist").await;

        // Seed 14 periods.
        for i in 0..14u32 {
            let uid = uuid::Uuid::new_v4();
            let period = format!("2025-{:02}", i + 1);
            sqlx::query(
                "INSERT INTO tenant_usage (id, tenant_id, period, mau_count) \
                 VALUES (?, ?, ?, 1)",
            )
            .bind(uid.as_bytes().as_ref())
            .bind(tid.as_bytes())
            .bind(&period)
            .execute(db.pool())
            .await
            .unwrap();
        }

        let history = db.aggregate_usage_history(12).await.unwrap();
        assert_eq!(
            history.len(),
            12,
            "only the 12 most recent periods returned"
        );
        // Ordered newest first.
        assert!(history[0].period > history[11].period);
    }

    #[tokio::test]
    async fn count_dormant_tenants_excludes_deleted() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        // Active with no last_seen_at → dormant.
        seed_tenant(&db, "never-seen").await;
        // Deleted → excluded regardless.
        seed_tenant_with_status(&db, "del", "deleted").await;

        let n = db
            .count_dormant_tenants(chrono::Utc::now() + chrono::Duration::days(365))
            .await
            .unwrap();
        assert_eq!(n, 1, "deleted tenant must not be counted as dormant");
    }

    #[tokio::test]
    async fn count_dormant_tenants_excludes_recently_seen() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "recent-tenant").await;
        db.touch_last_seen(&tid).await.unwrap();

        // Threshold is in the past → recently-seen tenant is not dormant.
        let n = db
            .count_dormant_tenants(chrono::Utc::now() - chrono::Duration::days(30))
            .await
            .unwrap();
        assert_eq!(n, 0, "recently-seen tenant should not be dormant");
    }

    #[tokio::test]
    async fn set_tenant_status_updates_row() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "suspend-me").await;

        db.set_tenant_status(&tid, TenantStatus::Suspended)
            .await
            .unwrap();

        let (status,): (String,) = sqlx::query_as("SELECT status FROM tenants WHERE id = ?1")
            .bind(tid.as_bytes())
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(status, "suspended");
    }

    #[tokio::test]
    async fn set_tenant_plan_updates_plan_id() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "change-plan").await;
        let plans = db.list_plans().await.unwrap();
        // dev is plan index 0; pick the next one.
        let new_plan = &plans[1];

        db.set_tenant_plan(&tid, &new_plan.id).await.unwrap();

        let (plan_id,): (Vec<u8>,) = sqlx::query_as("SELECT plan_id FROM tenants WHERE id = ?1")
            .bind(tid.as_bytes())
            .fetch_one(db.pool())
            .await
            .unwrap();
        assert_eq!(plan_id, new_plan.id);
    }

    #[tokio::test]
    async fn list_plans_returns_four_seed_plans_ordered_by_price() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let plans = db.list_plans().await.unwrap();
        assert_eq!(plans.len(), 4);
        let names: Vec<&str> = plans.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"dev"));
        assert!(names.contains(&"starter"));
        assert!(names.contains(&"growth"));
        assert!(names.contains(&"scale"));
        // Cheapest first.
        assert_eq!(plans[0].name, "dev");
        assert_eq!(plans[0].price_cents, 0);
    }

    #[tokio::test]
    async fn get_plan_by_id_some_and_none() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let plans = db.list_plans().await.unwrap();
        let first = &plans[0];

        let found = db.get_plan_by_id(&first.id).await.unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, first.name);

        let bogus = vec![0u8; 16];
        let not_found = db.get_plan_by_id(&bogus).await.unwrap();
        assert!(not_found.is_none());
    }

    // ── tenant_domains CRUD ───────────────────────────────────────────────────

    #[tokio::test]
    async fn create_tenant_domain_inserts_pending() {
        use crate::domains::DomainStatus;

        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "dom-insert").await;

        let row = db
            .create_tenant_domain(&tid, "auth.example.com", "custom.allowthem.io")
            .await
            .unwrap();

        assert_eq!(row.domain, "auth.example.com");
        assert_eq!(row.dns_target, "custom.allowthem.io");
        assert_eq!(row.status, DomainStatus::PendingVerification);
        assert!(row.verified_at.is_none());
        assert!(row.last_error.is_none());
    }

    #[tokio::test]
    async fn create_tenant_domain_unique_violation_returns_conflict() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "dom-conflict").await;

        db.create_tenant_domain(&tid, "auth.example.com", "custom.allowthem.io")
            .await
            .unwrap();

        let err = db
            .create_tenant_domain(&tid, "auth.example.com", "custom.allowthem.io")
            .await
            .unwrap_err();
        assert!(
            matches!(err, SaasError::DomainAlreadyExists),
            "expected DomainAlreadyExists, got {err:?}"
        );
    }

    #[tokio::test]
    async fn list_tenant_domains_orders_by_created_at_desc() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "dom-list-order").await;

        db.create_tenant_domain(&tid, "a.example.com", "custom.allowthem.io")
            .await
            .unwrap();
        db.create_tenant_domain(&tid, "b.example.com", "custom.allowthem.io")
            .await
            .unwrap();
        db.create_tenant_domain(&tid, "c.example.com", "custom.allowthem.io")
            .await
            .unwrap();

        let rows = db.list_tenant_domains(&tid).await.unwrap();
        assert_eq!(rows.len(), 3);
        // newest first — insertion order = a,b,c so c was most recent
        assert_eq!(rows[0].domain, "c.example.com");
        assert_eq!(rows[2].domain, "a.example.com");
    }

    #[tokio::test]
    async fn list_tenant_domains_filters_by_tenant_id() {
        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid_a = seed_tenant(&db, "dom-filter-a").await;
        let tid_b = seed_tenant(&db, "dom-filter-b").await;

        db.create_tenant_domain(&tid_a, "auth.acme.com", "custom.allowthem.io")
            .await
            .unwrap();
        db.create_tenant_domain(&tid_b, "auth.beta.com", "custom.allowthem.io")
            .await
            .unwrap();

        let rows_a = db.list_tenant_domains(&tid_a).await.unwrap();
        assert_eq!(rows_a.len(), 1);
        assert_eq!(rows_a[0].domain, "auth.acme.com");

        let rows_b = db.list_tenant_domains(&tid_b).await.unwrap();
        assert_eq!(rows_b.len(), 1);
        assert_eq!(rows_b[0].domain, "auth.beta.com");
    }

    #[tokio::test]
    async fn get_tenant_domain_scoped_other_tenant_is_none() {
        use crate::domains::DomainId;

        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid_a = seed_tenant(&db, "dom-scope-a").await;
        let tid_b = seed_tenant(&db, "dom-scope-b").await;

        let row = db
            .create_tenant_domain(&tid_a, "auth.acme.com", "custom.allowthem.io")
            .await
            .unwrap();
        let did = DomainId::from(Uuid::from_slice(&row.id).unwrap());

        // Correct tenant sees the row.
        let found = db.get_tenant_domain_scoped(&did, &tid_a).await.unwrap();
        assert!(found.is_some());

        // Other tenant gets None.
        let not_found = db.get_tenant_domain_scoped(&did, &tid_b).await.unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn set_tenant_domain_status_to_verified_clears_last_error_and_sets_verified_at() {
        use crate::domains::{DomainId, DomainStatus};

        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "dom-verify").await;

        let row = db
            .create_tenant_domain(&tid, "auth.example.com", "custom.allowthem.io")
            .await
            .unwrap();
        let did = DomainId::from(Uuid::from_slice(&row.id).unwrap());

        let now = chrono::Utc::now();
        db.set_tenant_domain_status(&did, DomainStatus::Verified, Some(now), None)
            .await
            .unwrap();

        let updated = db
            .get_tenant_domain_scoped(&did, &tid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.status, DomainStatus::Verified);
        assert!(updated.verified_at.is_some());
        assert!(updated.last_error.is_none());
    }

    #[tokio::test]
    async fn set_tenant_domain_status_to_failed_records_last_error() {
        use crate::domains::{DomainId, DomainStatus};

        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "dom-fail").await;

        let row = db
            .create_tenant_domain(&tid, "auth.example.com", "custom.allowthem.io")
            .await
            .unwrap();
        let did = DomainId::from(Uuid::from_slice(&row.id).unwrap());

        db.set_tenant_domain_status(
            &did,
            DomainStatus::Failed,
            None,
            Some("no CNAME record found"),
        )
        .await
        .unwrap();

        let updated = db
            .get_tenant_domain_scoped(&did, &tid)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(updated.status, DomainStatus::Failed);
        assert!(updated.verified_at.is_none());
        assert_eq!(updated.last_error.as_deref(), Some("no CNAME record found"));
    }

    #[tokio::test]
    async fn delete_tenant_domain_scoped_other_tenant_is_no_op() {
        use crate::domains::DomainId;

        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid_a = seed_tenant(&db, "dom-del-a").await;
        let tid_b = seed_tenant(&db, "dom-del-b").await;

        let row = db
            .create_tenant_domain(&tid_a, "auth.example.com", "custom.allowthem.io")
            .await
            .unwrap();
        let did = DomainId::from(Uuid::from_slice(&row.id).unwrap());

        // Deleting from the wrong tenant returns false (no rows affected).
        let affected = db.delete_tenant_domain_scoped(&did, &tid_b).await.unwrap();
        assert!(!affected);

        // Row still exists for the correct tenant.
        let still_there = db.get_tenant_domain_scoped(&did, &tid_a).await.unwrap();
        assert!(still_there.is_some());

        // Correct tenant can delete.
        let deleted = db.delete_tenant_domain_scoped(&did, &tid_a).await.unwrap();
        assert!(deleted);

        let gone = db.get_tenant_domain_scoped(&did, &tid_a).await.unwrap();
        assert!(gone.is_none());
    }

    #[tokio::test]
    async fn tenant_by_custom_domain_returns_only_verified_or_active() {
        use crate::domains::{DomainId, DomainStatus};

        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "dom-router").await;

        // pending_verification → should not be returned
        let row = db
            .create_tenant_domain(&tid, "pending.example.com", "custom.allowthem.io")
            .await
            .unwrap();
        let did_pending = DomainId::from(Uuid::from_slice(&row.id).unwrap());
        assert!(
            db.tenant_by_custom_domain("pending.example.com")
                .await
                .unwrap()
                .is_none()
        );

        // Flip to verified → should be returned
        db.set_tenant_domain_status(
            &did_pending,
            DomainStatus::Verified,
            Some(chrono::Utc::now()),
            None,
        )
        .await
        .unwrap();
        let found = db
            .tenant_by_custom_domain("pending.example.com")
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().slug, "dom-router");

        // failed → not returned
        let row2 = db
            .create_tenant_domain(&tid, "failed.example.com", "custom.allowthem.io")
            .await
            .unwrap();
        let did_failed = DomainId::from(Uuid::from_slice(&row2.id).unwrap());
        db.set_tenant_domain_status(&did_failed, DomainStatus::Failed, None, Some("err"))
            .await
            .unwrap();
        assert!(
            db.tenant_by_custom_domain("failed.example.com")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn tenant_by_custom_domain_lowercases_input() {
        use crate::domains::{DomainId, DomainStatus};

        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "dom-case").await;

        let row = db
            .create_tenant_domain(&tid, "auth.example.com", "custom.allowthem.io")
            .await
            .unwrap();
        let did = DomainId::from(Uuid::from_slice(&row.id).unwrap());
        db.set_tenant_domain_status(&did, DomainStatus::Verified, Some(chrono::Utc::now()), None)
            .await
            .unwrap();

        // Query with mixed case — should still find the row.
        let found = db
            .tenant_by_custom_domain("Auth.EXAMPLE.COM")
            .await
            .unwrap();
        assert!(found.is_some());
    }

    #[tokio::test]
    async fn list_domains_for_sweep_oldest_first_capped() {
        use crate::domains::{DomainId, DomainStatus};

        let db = ControlDb::new(test_pool().await).await.unwrap();
        let tid = seed_tenant(&db, "dom-sweep").await;

        // Insert three pending rows.
        for domain in ["a.sweep.com", "b.sweep.com", "c.sweep.com"] {
            db.create_tenant_domain(&tid, domain, "custom.allowthem.io")
                .await
                .unwrap();
        }

        // Insert one verified row — should not appear.
        let row = db
            .create_tenant_domain(&tid, "v.sweep.com", "custom.allowthem.io")
            .await
            .unwrap();
        let did_v = DomainId::from(Uuid::from_slice(&row.id).unwrap());
        db.set_tenant_domain_status(
            &did_v,
            DomainStatus::Verified,
            Some(chrono::Utc::now()),
            None,
        )
        .await
        .unwrap();

        // Cap at 2 — only 2 of the 3 pending rows returned.
        let sweep = db.list_domains_for_sweep(2).await.unwrap();
        assert_eq!(sweep.len(), 2);
        // None should be verified.
        for r in &sweep {
            assert!(
                matches!(
                    r.status,
                    DomainStatus::PendingVerification | DomainStatus::Failed
                ),
                "unexpected status {:?}",
                r.status
            );
        }
    }
}
