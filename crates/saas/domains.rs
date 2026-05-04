//! Custom domain types and validation.
//!
//! `DomainId`, `DomainStatus`, and `TenantDomain` mirror the
//! `tenant_domains` control-plane table. `normalize_domain` encapsulates
//! the validation rules from plan §3.4.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::error::SaasError;

// ── Id newtype ────────────────────────────────────────────────────────────────

/// UUIDv7-backed identifier for a `tenant_domains` row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct DomainId(Uuid);

impl DomainId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    pub fn as_uuid(&self) -> &Uuid {
        &self.0
    }

    /// Raw bytes suitable for binding to a SQLite BLOB column.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl Default for DomainId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for DomainId {
    fn from(u: Uuid) -> Self {
        Self(u)
    }
}

// ── Status enum ───────────────────────────────────────────────────────────────

/// Lifecycle state of a custom domain registration.
///
/// `Active` is reserved for 38y.3 (Caddy on-demand TLS): this task only
/// ever writes `PendingVerification`, `Verified`, or `Failed`. The variant
/// exists so the schema and enum are complete from day one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, sqlx::Type)]
#[sqlx(type_name = "TEXT")]
#[serde(rename_all = "snake_case")]
pub enum DomainStatus {
    #[sqlx(rename = "pending_verification")]
    PendingVerification,
    #[sqlx(rename = "verified")]
    Verified,
    /// Set by 38y.3 (Caddy cert callback). Never written in 38y.1.
    #[sqlx(rename = "active")]
    Active,
    #[sqlx(rename = "failed")]
    Failed,
}

impl DomainStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            DomainStatus::PendingVerification => "pending_verification",
            DomainStatus::Verified => "verified",
            DomainStatus::Active => "active",
            DomainStatus::Failed => "failed",
        }
    }
}

// ── Row struct ────────────────────────────────────────────────────────────────

/// One row of `tenant_domains`. BLOB ID columns are kept as `Vec<u8>` to
/// match the `Tenant` / `TenantMember` convention.
#[derive(Debug, Clone, sqlx::FromRow, serde::Serialize, serde::Deserialize)]
pub struct TenantDomain {
    pub id: Vec<u8>,
    pub tenant_id: Vec<u8>,
    pub domain: String,
    pub status: DomainStatus,
    pub dns_target: String,
    pub verified_at: Option<DateTime<Utc>>,
    pub cert_expires_at: Option<DateTime<Utc>>,
    pub last_error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

// ── Domain validation ─────────────────────────────────────────────────────────

/// Validate and normalise a raw domain input per plan §3.4.
///
/// Rules applied in order:
/// 1. Non-empty, ≤ 253 chars, only `[a-z0-9.-]` (after lowercasing).
/// 2. No leading/trailing `.` or `-`; no label > 63 chars; no `..`.
/// 3. Must not equal `base_domain` or end with `.<base_domain>` (case-insensitive).
/// 4. Must contain at least one `.` (single-label names are not routable).
///
/// Returns the lowercased canonical form on success, or
/// [`SaasError::DomainInvalid`] with a human-readable reason on failure.
pub fn normalize_domain(input: &str, base_domain: &str) -> Result<String, SaasError> {
    let lower = input.to_lowercase();

    if lower.is_empty() {
        return Err(SaasError::DomainInvalid("domain must not be empty"));
    }
    if lower.len() > 253 {
        return Err(SaasError::DomainInvalid(
            "domain must be 253 characters or fewer",
        ));
    }

    // Only LDH (letters, digits, hyphens) plus dots are valid in DNS names.
    if !lower
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return Err(SaasError::DomainInvalid(
            "domain may only contain letters, digits, hyphens, and dots",
        ));
    }

    if lower.starts_with('.') || lower.ends_with('.') {
        return Err(SaasError::DomainInvalid(
            "domain must not start or end with a dot",
        ));
    }
    if lower.starts_with('-') || lower.ends_with('-') {
        return Err(SaasError::DomainInvalid(
            "domain must not start or end with a hyphen",
        ));
    }
    if lower.contains("..") {
        return Err(SaasError::DomainInvalid(
            "domain must not contain consecutive dots",
        ));
    }

    // Every label must be ≤ 63 characters and must not start or end with a hyphen.
    for label in lower.split('.') {
        if label.is_empty() {
            // Covered by the leading/trailing/double-dot checks above; be explicit.
            return Err(SaasError::DomainInvalid("domain labels must not be empty"));
        }
        if label.len() > 63 {
            return Err(SaasError::DomainInvalid(
                "each label must be 63 characters or fewer",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(SaasError::DomainInvalid(
                "domain labels must not start or end with a hyphen",
            ));
        }
    }

    // Require at least one dot (single-label names like "localhost" are not valid FQDNs).
    if !lower.contains('.') {
        return Err(SaasError::DomainInvalid(
            "domain must be a fully-qualified name with at least one dot",
        ));
    }

    // Reject the base domain itself and any subdomain of it.
    let base = base_domain.to_lowercase();
    if lower == base || lower.ends_with(&format!(".{base}")) {
        return Err(SaasError::DomainInvalid(
            "domain must not be the platform base domain or a subdomain of it",
        ));
    }

    Ok(lower)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "allowthem.io";

    // ── Acceptance ────────────────────────────────────────────────────────────

    #[test]
    fn accepts_valid_domain() {
        assert_eq!(
            normalize_domain("auth.theirapp.com", BASE).unwrap(),
            "auth.theirapp.com"
        );
    }

    #[test]
    fn lowercases_mixed_case() {
        assert_eq!(
            normalize_domain("Auth.TheirApp.COM", BASE).unwrap(),
            "auth.theirapp.com"
        );
    }

    #[test]
    fn accepts_domain_with_hyphens() {
        assert_eq!(
            normalize_domain("my-app.example.com", BASE).unwrap(),
            "my-app.example.com"
        );
    }

    // ── Rejections — structural ───────────────────────────────────────────────

    #[test]
    fn rejects_empty() {
        let err = normalize_domain("", BASE).unwrap_err();
        assert!(matches!(err, SaasError::DomainInvalid(_)));
    }

    #[test]
    fn rejects_too_long() {
        // 254-char domain: 63 + '.' + 63 + '.' + 63 + '.' + 63 = 255 — trim to 254
        let long: String = format!("{}.{}.com", "a".repeat(120), "b".repeat(120));
        let err = normalize_domain(&long, BASE).unwrap_err();
        assert!(matches!(err, SaasError::DomainInvalid(_)));
    }

    #[test]
    fn rejects_label_too_long() {
        let long_label = format!("{}.example.com", "a".repeat(64));
        let err = normalize_domain(&long_label, BASE).unwrap_err();
        assert!(matches!(err, SaasError::DomainInvalid(_)));
    }

    #[test]
    fn rejects_leading_dot() {
        let err = normalize_domain(".auth.example.com", BASE).unwrap_err();
        assert!(matches!(err, SaasError::DomainInvalid(_)));
    }

    #[test]
    fn rejects_trailing_dot() {
        let err = normalize_domain("auth.example.com.", BASE).unwrap_err();
        assert!(matches!(err, SaasError::DomainInvalid(_)));
    }

    #[test]
    fn rejects_leading_hyphen() {
        let err = normalize_domain("-auth.example.com", BASE).unwrap_err();
        assert!(matches!(err, SaasError::DomainInvalid(_)));
    }

    #[test]
    fn rejects_trailing_hyphen() {
        let err = normalize_domain("auth-.example.com", BASE).unwrap_err();
        assert!(matches!(err, SaasError::DomainInvalid(_)));
    }

    #[test]
    fn rejects_double_dot() {
        let err = normalize_domain("auth..example.com", BASE).unwrap_err();
        assert!(matches!(err, SaasError::DomainInvalid(_)));
    }

    #[test]
    fn rejects_non_ldh_chars() {
        let err = normalize_domain("auth_app.example.com", BASE).unwrap_err();
        assert!(matches!(err, SaasError::DomainInvalid(_)));
    }

    #[test]
    fn rejects_single_label() {
        let err = normalize_domain("localhost", BASE).unwrap_err();
        assert!(matches!(err, SaasError::DomainInvalid(_)));
    }

    // ── Rejections — base domain rules ───────────────────────────────────────

    #[test]
    fn rejects_base_domain_itself() {
        let err = normalize_domain("allowthem.io", BASE).unwrap_err();
        assert!(matches!(err, SaasError::DomainInvalid(_)));
    }

    #[test]
    fn rejects_subdomain_of_base() {
        let err = normalize_domain("auth.allowthem.io", BASE).unwrap_err();
        assert!(matches!(err, SaasError::DomainInvalid(_)));
    }

    #[test]
    fn rejects_base_domain_case_insensitive() {
        let err = normalize_domain("ALLOWTHEM.IO", BASE).unwrap_err();
        assert!(matches!(err, SaasError::DomainInvalid(_)));
    }

    #[test]
    fn rejects_subdomain_of_base_mixed_case() {
        let err = normalize_domain("Auth.AllowThem.IO", BASE).unwrap_err();
        assert!(matches!(err, SaasError::DomainInvalid(_)));
    }
}
