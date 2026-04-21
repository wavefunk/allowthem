use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use std::str::FromStr;

use crate::applications::{Application, CreateApplicationParams, UpdateApplication};
use crate::audit::{AuditEvent, SearchAuditParams};
use crate::db::Db;
use crate::error::AuthError;
use crate::password::verify_password;
use crate::sessions::{
    SessionConfig, generate_token, hash_token, parse_session_cookie, session_cookie,
};
use crate::types::{
    AccentInk, ApplicationId, ClientId, ClientType, Email, Mode, PasswordHash, Permission,
    PermissionId, PermissionName, Role, RoleId, RoleName, RolePermission, Session, SessionId,
    SplashPrimitive, TokenHash, User, UserId, UserPermission, UserRole, Username,
};

async fn test_db() -> Db {
    Db::connect("sqlite::memory:")
        .await
        .expect("Db::connect for in-memory test database")
}

fn now_str() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

#[tokio::test]
async fn test_user_round_trip() {
    let db = test_db().await;

    let user_id = UserId::new();
    let email = Email::new_unchecked("alice@example.com".to_string());
    let username = Username::new_unchecked("alice".to_string());
    let password_hash =
        PasswordHash::new_unchecked("$argon2id$v=19$m=65536,t=2,p=1$fakesalt$fakehash".to_string());

    sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(Some(&username))
    .bind(Some(&password_hash))
    .bind(true)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert user");

    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, username, password_hash, email_verified, is_active, created_at, updated_at, custom_data
         FROM allowthem_users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_one(db.pool())
    .await
    .expect("fetch user");

    assert_eq!(user.id, user_id);
    assert_eq!(user.email, email);
    assert_eq!(user.username, Some(username));
    assert!(user.password_hash.is_some());
    assert!(user.email_verified);
    assert!(user.is_active);

    // Also test NULL password_hash
    let user_id2 = UserId::new();
    sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id2)
    .bind(Email::new_unchecked("bob@example.com".to_string()))
    .bind(None::<Username>)
    .bind(None::<PasswordHash>)
    .bind(false)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert user with null password");

    let user2 = sqlx::query_as::<_, User>(
        "SELECT id, email, username, password_hash, email_verified, is_active, created_at, updated_at, custom_data
         FROM allowthem_users WHERE id = ?",
    )
    .bind(user_id2)
    .fetch_one(db.pool())
    .await
    .expect("fetch user2");

    assert!(user2.password_hash.is_none());
    assert!(user2.username.is_none());
    assert!(!user2.email_verified);
}

#[tokio::test]
async fn test_session_round_trip() {
    let db = test_db().await;

    let user_id = UserId::new();
    sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(Email::new_unchecked("carol@example.com".to_string()))
    .bind(None::<Username>)
    .bind(None::<PasswordHash>)
    .bind(false)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert user");

    let session_id = SessionId::new();
    let token_hash = TokenHash::new_unchecked(
        "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
    );
    let expires_at = now_str();

    sqlx::query(
        "INSERT INTO allowthem_sessions (id, token_hash, user_id, ip_address, user_agent, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(session_id)
    .bind(&token_hash)
    .bind(user_id)
    .bind(Some("127.0.0.1"))
    .bind(Some("Mozilla/5.0"))
    .bind(&expires_at)
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert session");

    let session = sqlx::query_as::<_, Session>(
        "SELECT id, token_hash, user_id, ip_address, user_agent, expires_at, created_at
         FROM allowthem_sessions WHERE id = ?",
    )
    .bind(session_id)
    .fetch_one(db.pool())
    .await
    .expect("fetch session");

    assert_eq!(session.id, session_id);
    assert_eq!(session.user_id, user_id);
    assert_eq!(session.ip_address.as_deref(), Some("127.0.0.1"));
    assert_eq!(session.user_agent.as_deref(), Some("Mozilla/5.0"));
}

#[tokio::test]
async fn test_role_round_trip() {
    let db = test_db().await;

    let role_id = RoleId::new();
    let role_name = RoleName::new_unchecked("admin".to_string());

    sqlx::query(
        "INSERT INTO allowthem_roles (id, name, description, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(role_id)
    .bind(&role_name)
    .bind(Some("Administrator role"))
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert role");

    let role = sqlx::query_as::<_, Role>(
        "SELECT id, name, description, created_at FROM allowthem_roles WHERE id = ?",
    )
    .bind(role_id)
    .fetch_one(db.pool())
    .await
    .expect("fetch role");

    assert_eq!(role.id, role_id);
    assert_eq!(role.name, role_name);
    assert_eq!(role.description.as_deref(), Some("Administrator role"));
}

#[tokio::test]
async fn test_user_role_round_trip() {
    let db = test_db().await;

    let user_id = UserId::new();
    let role_id = RoleId::new();

    sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(Email::new_unchecked("dave@example.com".to_string()))
    .bind(None::<Username>)
    .bind(None::<PasswordHash>)
    .bind(false)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert user");

    sqlx::query(
        "INSERT INTO allowthem_roles (id, name, description, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(role_id)
    .bind(RoleName::new_unchecked("editor".to_string()))
    .bind(None::<String>)
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert role");

    sqlx::query("INSERT INTO allowthem_user_roles (user_id, role_id, created_at) VALUES (?, ?, ?)")
        .bind(user_id)
        .bind(role_id)
        .bind(now_str())
        .execute(db.pool())
        .await
        .expect("insert user_role");

    let user_role = sqlx::query_as::<_, UserRole>(
        "SELECT user_id, role_id, created_at FROM allowthem_user_roles WHERE user_id = ? AND role_id = ?",
    )
    .bind(user_id)
    .bind(role_id)
    .fetch_one(db.pool())
    .await
    .expect("fetch user_role");

    assert_eq!(user_role.user_id, user_id);
    assert_eq!(user_role.role_id, role_id);
}

#[tokio::test]
async fn test_permission_round_trip() {
    let db = test_db().await;

    let perm_id = PermissionId::new();
    let perm_name = PermissionName::new_unchecked("posts:write".to_string());

    sqlx::query(
        "INSERT INTO allowthem_permissions (id, name, description, created_at)
         VALUES (?, ?, ?, ?)",
    )
    .bind(perm_id)
    .bind(&perm_name)
    .bind(Some("Write access to posts"))
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert permission");

    let perm = sqlx::query_as::<_, Permission>(
        "SELECT id, name, description, created_at FROM allowthem_permissions WHERE id = ?",
    )
    .bind(perm_id)
    .fetch_one(db.pool())
    .await
    .expect("fetch permission");

    assert_eq!(perm.id, perm_id);
    assert_eq!(perm.name, perm_name);
    assert_eq!(perm.description.as_deref(), Some("Write access to posts"));
}

#[tokio::test]
async fn test_role_permission_round_trip() {
    let db = test_db().await;

    let role_id = RoleId::new();
    let perm_id = PermissionId::new();

    sqlx::query(
        "INSERT INTO allowthem_roles (id, name, description, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(role_id)
    .bind(RoleName::new_unchecked("viewer".to_string()))
    .bind(None::<String>)
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert role");

    sqlx::query(
        "INSERT INTO allowthem_permissions (id, name, description, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(perm_id)
    .bind(PermissionName::new_unchecked("posts:read".to_string()))
    .bind(None::<String>)
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert permission");

    sqlx::query("INSERT INTO allowthem_role_permissions (role_id, permission_id) VALUES (?, ?)")
        .bind(role_id)
        .bind(perm_id)
        .execute(db.pool())
        .await
        .expect("insert role_permission");

    let rp = sqlx::query_as::<_, RolePermission>(
        "SELECT role_id, permission_id FROM allowthem_role_permissions WHERE role_id = ? AND permission_id = ?",
    )
    .bind(role_id)
    .bind(perm_id)
    .fetch_one(db.pool())
    .await
    .expect("fetch role_permission");

    assert_eq!(rp.role_id, role_id);
    assert_eq!(rp.permission_id, perm_id);
}

#[tokio::test]
async fn test_user_permission_round_trip() {
    let db = test_db().await;

    let user_id = UserId::new();
    let perm_id = PermissionId::new();

    sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(Email::new_unchecked("eve@example.com".to_string()))
    .bind(None::<Username>)
    .bind(None::<PasswordHash>)
    .bind(false)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert user");

    sqlx::query(
        "INSERT INTO allowthem_permissions (id, name, description, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(perm_id)
    .bind(PermissionName::new_unchecked("admin:read".to_string()))
    .bind(None::<String>)
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert permission");

    sqlx::query("INSERT INTO allowthem_user_permissions (user_id, permission_id) VALUES (?, ?)")
        .bind(user_id)
        .bind(perm_id)
        .execute(db.pool())
        .await
        .expect("insert user_permission");

    let up = sqlx::query_as::<_, UserPermission>(
        "SELECT user_id, permission_id FROM allowthem_user_permissions WHERE user_id = ? AND permission_id = ?",
    )
    .bind(user_id)
    .bind(perm_id)
    .fetch_one(db.pool())
    .await
    .expect("fetch user_permission");

    assert_eq!(up.user_id, user_id);
    assert_eq!(up.permission_id, perm_id);
}

// --- Constraint tests ---

#[tokio::test]
async fn test_unique_email_constraint() {
    let db = test_db().await;
    let email = Email::new_unchecked("duplicate@example.com".to_string());

    sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(UserId::new())
    .bind(&email)
    .bind(None::<Username>)
    .bind(None::<PasswordHash>)
    .bind(false)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("first insert succeeds");

    let result = sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(UserId::new())
    .bind(&email)
    .bind(None::<Username>)
    .bind(None::<PasswordHash>)
    .bind(false)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await;

    assert!(result.is_err(), "duplicate email must be rejected");
}

#[tokio::test]
async fn test_unique_username_constraint() {
    let db = test_db().await;

    let username = Username::new_unchecked("samename".to_string());

    // Two users with the same non-null username must fail on the second insert
    sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(UserId::new())
    .bind(Email::new_unchecked("user1@example.com".to_string()))
    .bind(Some(&username))
    .bind(None::<PasswordHash>)
    .bind(false)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("first insert succeeds");

    let result = sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(UserId::new())
    .bind(Email::new_unchecked("user2@example.com".to_string()))
    .bind(Some(&username))
    .bind(None::<PasswordHash>)
    .bind(false)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await;

    assert!(result.is_err(), "duplicate username must be rejected");

    // Two users with NULL username must both succeed (SQLite treats NULLs as distinct)
    sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(UserId::new())
    .bind(Email::new_unchecked("null1@example.com".to_string()))
    .bind(None::<Username>)
    .bind(None::<PasswordHash>)
    .bind(false)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("null username insert 1 succeeds");

    sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(UserId::new())
    .bind(Email::new_unchecked("null2@example.com".to_string()))
    .bind(None::<Username>)
    .bind(None::<PasswordHash>)
    .bind(false)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("null username insert 2 succeeds — NULLs are distinct in SQLite");
}

#[tokio::test]
async fn test_foreign_key_enforcement() {
    let db = test_db().await;

    // Insert a session with a non-existent user_id — must fail
    let result = sqlx::query(
        "INSERT INTO allowthem_sessions (id, token_hash, user_id, ip_address, user_agent, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(SessionId::new())
    .bind(TokenHash::new_unchecked("deadbeef".repeat(8)))
    .bind(UserId::new()) // non-existent user
    .bind(None::<String>)
    .bind(None::<String>)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await;

    assert!(
        result.is_err(),
        "FK violation must be rejected (PRAGMA foreign_keys = ON)"
    );
}

#[tokio::test]
async fn test_composite_primary_key() {
    let db = test_db().await;

    let user_id = UserId::new();
    let role_id = RoleId::new();

    sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(Email::new_unchecked("frank@example.com".to_string()))
    .bind(None::<Username>)
    .bind(None::<PasswordHash>)
    .bind(false)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert user");

    sqlx::query(
        "INSERT INTO allowthem_roles (id, name, description, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(role_id)
    .bind(RoleName::new_unchecked("superuser".to_string()))
    .bind(None::<String>)
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert role");

    sqlx::query("INSERT INTO allowthem_user_roles (user_id, role_id, created_at) VALUES (?, ?, ?)")
        .bind(user_id)
        .bind(role_id)
        .bind(now_str())
        .execute(db.pool())
        .await
        .expect("first insert succeeds");

    let result = sqlx::query(
        "INSERT INTO allowthem_user_roles (user_id, role_id, created_at) VALUES (?, ?, ?)",
    )
    .bind(user_id)
    .bind(role_id)
    .bind(now_str())
    .execute(db.pool())
    .await;

    assert!(result.is_err(), "duplicate composite PK must be rejected");
}

#[tokio::test]
async fn test_cascade_delete_user() {
    let db = test_db().await;

    let user_id = UserId::new();
    let role_id = RoleId::new();
    let perm_id = PermissionId::new();
    let session_id = SessionId::new();

    // Insert user
    sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(Email::new_unchecked("grace@example.com".to_string()))
    .bind(None::<Username>)
    .bind(None::<PasswordHash>)
    .bind(false)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert user");

    // Insert role
    sqlx::query(
        "INSERT INTO allowthem_roles (id, name, description, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(role_id)
    .bind(RoleName::new_unchecked("cascade_role".to_string()))
    .bind(None::<String>)
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert role");

    // Insert permission
    sqlx::query(
        "INSERT INTO allowthem_permissions (id, name, description, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(perm_id)
    .bind(PermissionName::new_unchecked("cascade:read".to_string()))
    .bind(None::<String>)
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert permission");

    // Insert session
    sqlx::query(
        "INSERT INTO allowthem_sessions (id, token_hash, user_id, ip_address, user_agent, expires_at, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(session_id)
    .bind(TokenHash::new_unchecked("cafebabe".repeat(8)))
    .bind(user_id)
    .bind(None::<String>)
    .bind(None::<String>)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert session");

    // Insert user_role
    sqlx::query("INSERT INTO allowthem_user_roles (user_id, role_id, created_at) VALUES (?, ?, ?)")
        .bind(user_id)
        .bind(role_id)
        .bind(now_str())
        .execute(db.pool())
        .await
        .expect("insert user_role");

    // Insert user_permission
    sqlx::query("INSERT INTO allowthem_user_permissions (user_id, permission_id) VALUES (?, ?)")
        .bind(user_id)
        .bind(perm_id)
        .execute(db.pool())
        .await
        .expect("insert user_permission");

    // Delete the user — all dependent rows should cascade
    sqlx::query("DELETE FROM allowthem_users WHERE id = ?")
        .bind(user_id)
        .execute(db.pool())
        .await
        .expect("delete user");

    // Verify session is gone
    let session_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM allowthem_sessions WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(db.pool())
            .await
            .expect("count sessions");
    assert_eq!(session_count, 0, "sessions must cascade-delete with user");

    // Verify user_role is gone
    let user_role_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM allowthem_user_roles WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(db.pool())
            .await
            .expect("count user_roles");
    assert_eq!(
        user_role_count, 0,
        "user_roles must cascade-delete with user"
    );

    // Verify user_permission is gone
    let user_perm_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM allowthem_user_permissions WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(db.pool())
            .await
            .expect("count user_permissions");
    assert_eq!(
        user_perm_count, 0,
        "user_permissions must cascade-delete with user"
    );
}

// --- M2-specific tests ---

#[tokio::test]
async fn test_migrations_create_all_tables() {
    let db = test_db().await;

    let mut tables: Vec<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'allowthem_%' ORDER BY name")
            .fetch_all(db.pool())
            .await
            .expect("query sqlite_master");

    tables.sort();

    assert_eq!(
        tables,
        vec![
            "allowthem_api_tokens",
            "allowthem_applications",
            "allowthem_audit_log",
            "allowthem_authorization_codes",
            "allowthem_consents",
            "allowthem_email_verification_tokens",
            "allowthem_invitations",
            "allowthem_mfa_challenges",
            "allowthem_mfa_recovery_codes",
            "allowthem_mfa_secrets",
            "allowthem_oauth_accounts",
            "allowthem_oauth_states",
            "allowthem_password_reset_tokens",
            "allowthem_permissions",
            "allowthem_refresh_tokens",
            "allowthem_role_permissions",
            "allowthem_roles",
            "allowthem_sessions",
            "allowthem_signing_keys",
            "allowthem_user_permissions",
            "allowthem_user_roles",
            "allowthem_users",
        ]
    );
}

#[tokio::test]
async fn test_double_init_is_safe() {
    let pool = SqlitePool::connect_with(
        SqliteConnectOptions::from_str("sqlite::memory:")
            .expect("valid connection string")
            .pragma("foreign_keys", "ON"),
    )
    .await
    .expect("create pool");

    Db::new(pool.clone()).await.expect("first Db::new succeeds");
    Db::new(pool)
        .await
        .expect("second Db::new succeeds — idempotent");
}

#[tokio::test]
async fn test_foreign_keys_enabled_via_connect() {
    let db = test_db().await;

    let fk_enabled: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(db.pool())
        .await
        .expect("PRAGMA foreign_keys");

    assert_eq!(fk_enabled, 1, "foreign_keys must be ON");
}

#[tokio::test]
async fn test_connect_invalid_url() {
    let result = Db::connect("not://valid").await;
    assert!(result.is_err(), "invalid URL must return Err");
}

// --- M5: Session token tests ---

#[test]
fn test_generate_token_length() {
    let token = generate_token();
    assert_eq!(
        token.as_str().len(),
        43,
        "base64url of 32 bytes must be 43 chars (no padding)"
    );
}

#[test]
fn test_two_tokens_differ() {
    let t1 = generate_token();
    let t2 = generate_token();
    assert_ne!(t1, t2, "two generated tokens must be different");
}

#[test]
fn test_hash_differs_from_token() {
    let token = generate_token();
    let hash = hash_token(&token);
    // Token is 43 chars (base64url); SHA-256 hex is 64 chars — they differ structurally.
    // We verify the hash is 64 hex chars by round-tripping through Debug.
    let hash_debug = format!("{hash:?}");
    // Debug output: TokenHash("...64 hex chars...")
    // Extract the inner string by stripping the wrapper
    let inner = hash_debug
        .strip_prefix("TokenHash(\"")
        .and_then(|s| s.strip_suffix("\")"))
        .expect("Debug format matches");
    assert_eq!(inner.len(), 64, "SHA-256 hex is 64 chars");
    assert_ne!(inner, token.as_str(), "hash must differ from raw token");
}

#[tokio::test]
async fn test_create_and_lookup_session() {
    let db = test_db().await;

    // Insert a user first (FK constraint)
    let user_id = UserId::new();
    sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(Email::new_unchecked("session_user@example.com".to_string()))
    .bind(None::<Username>)
    .bind(None::<PasswordHash>)
    .bind(false)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert user");

    let token = generate_token();
    let token_hash = hash_token(&token);
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);

    let created = db
        .create_session(
            user_id,
            token_hash,
            Some("127.0.0.1"),
            Some("TestAgent"),
            expires_at,
        )
        .await
        .expect("create_session");

    assert_eq!(created.user_id, user_id);
    assert_eq!(created.ip_address.as_deref(), Some("127.0.0.1"));
    assert_eq!(created.user_agent.as_deref(), Some("TestAgent"));

    let found = db
        .lookup_session(&token)
        .await
        .expect("lookup_session")
        .expect("session must exist");

    assert_eq!(found.id, created.id);
    assert_eq!(found.user_id, user_id);
}

#[tokio::test]
async fn test_expired_session_not_returned() {
    let db = test_db().await;

    // Insert a user
    let user_id = UserId::new();
    sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(Email::new_unchecked("expired_user@example.com".to_string()))
    .bind(None::<Username>)
    .bind(None::<PasswordHash>)
    .bind(false)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert user");

    let token = generate_token();
    let token_hash = hash_token(&token);
    // expires_at in the past
    let expires_at = chrono::Utc::now() - chrono::Duration::hours(1);

    db.create_session(user_id, token_hash, None, None, expires_at)
        .await
        .expect("create expired session");

    let result = db.lookup_session(&token).await.expect("lookup_session");

    assert!(result.is_none(), "expired session must not be returned");
}

// --- M6: Session lifecycle tests ---

async fn insert_test_user(db: &Db, email: &str) -> UserId {
    let user_id = UserId::new();
    sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(Email::new_unchecked(email.to_string()))
    .bind(None::<Username>)
    .bind(None::<PasswordHash>)
    .bind(false)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert test user");
    user_id
}

#[tokio::test]
async fn test_validate_session_non_expired_returns_session() {
    let db = test_db().await;
    let user_id = insert_test_user(&db, "validate1@example.com").await;

    let token = generate_token();
    let token_hash = hash_token(&token);
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(24);

    db.create_session(user_id, token_hash, None, None, expires_at)
        .await
        .expect("create_session");

    let ttl = chrono::Duration::hours(24);
    let session = db
        .validate_session(&token, ttl)
        .await
        .expect("validate_session")
        .expect("session must exist");

    assert_eq!(session.user_id, user_id);
}

#[tokio::test]
async fn test_validate_session_expired_returns_none() {
    let db = test_db().await;
    let user_id = insert_test_user(&db, "validate2@example.com").await;

    let token = generate_token();
    let token_hash = hash_token(&token);
    let expires_at = chrono::Utc::now() - chrono::Duration::hours(1);

    db.create_session(user_id, token_hash, None, None, expires_at)
        .await
        .expect("create_session");

    let ttl = chrono::Duration::hours(24);
    let result = db
        .validate_session(&token, ttl)
        .await
        .expect("validate_session");

    assert!(result.is_none(), "expired session must not be returned");
}

#[tokio::test]
async fn test_validate_session_past_halfway_extends() {
    let db = test_db().await;
    let user_id = insert_test_user(&db, "validate3@example.com").await;

    let token = generate_token();
    let token_hash = hash_token(&token);
    let ttl = chrono::Duration::hours(24);
    // Place expiry just 30 minutes from now — well past the halfway point (12 hours from now)
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(30);

    db.create_session(user_id, token_hash, None, None, expires_at)
        .await
        .expect("create_session");

    let session = db
        .validate_session(&token, ttl)
        .await
        .expect("validate_session")
        .expect("session must exist");

    // After renewal the session should expire roughly ttl from now, not in 30 min
    let remaining = session.expires_at - chrono::Utc::now();
    assert!(
        remaining > chrono::Duration::hours(20),
        "session must have been extended; remaining: {remaining}"
    );
}

#[tokio::test]
async fn test_validate_session_before_halfway_does_not_extend() {
    let db = test_db().await;
    let user_id = insert_test_user(&db, "validate4@example.com").await;

    let token = generate_token();
    let token_hash = hash_token(&token);
    let ttl = chrono::Duration::hours(24);
    // Place expiry 23 hours from now — before halfway point (12 hours = ttl/2 from now)
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(23);

    db.create_session(user_id, token_hash, None, None, expires_at)
        .await
        .expect("create_session");

    let session = db
        .validate_session(&token, ttl)
        .await
        .expect("validate_session")
        .expect("session must exist");

    // Expiry should not have been pushed further than what was set
    let remaining = session.expires_at - chrono::Utc::now();
    assert!(
        remaining < chrono::Duration::hours(24),
        "session must NOT have been extended beyond original; remaining: {remaining}"
    );
}

#[tokio::test]
async fn test_delete_session() {
    let db = test_db().await;
    let user_id = insert_test_user(&db, "delete1@example.com").await;

    let token = generate_token();
    let token_hash = hash_token(&token);
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);

    db.create_session(user_id, token_hash, None, None, expires_at)
        .await
        .expect("create_session");

    let deleted = db.delete_session(&token).await.expect("delete_session");
    assert!(
        deleted,
        "delete_session must return true when session existed"
    );

    // A second delete on the same token must return false
    let deleted_again = db
        .delete_session(&token)
        .await
        .expect("delete_session again");
    assert!(
        !deleted_again,
        "delete_session must return false when session already gone"
    );
}

#[tokio::test]
async fn test_delete_user_sessions() {
    let db = test_db().await;
    let user_id = insert_test_user(&db, "delete_all@example.com").await;

    let expires_at = chrono::Utc::now() + chrono::Duration::hours(1);

    // Create three sessions for the same user
    for _ in 0..3 {
        let token = generate_token();
        let token_hash = hash_token(&token);
        db.create_session(user_id, token_hash, None, None, expires_at)
            .await
            .expect("create_session");
    }

    let count = db
        .delete_user_sessions(&user_id)
        .await
        .expect("delete_user_sessions");
    assert_eq!(count, 3, "must delete exactly 3 sessions");

    // Confirm none remain
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM allowthem_sessions WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(db.pool())
            .await
            .expect("count remaining");
    assert_eq!(
        remaining, 0,
        "no sessions must remain after delete_user_sessions"
    );
}

// --- M6: Cookie helper tests ---

#[test]
fn test_session_cookie_format() {
    let config = SessionConfig {
        ttl: chrono::Duration::hours(24),
        cookie_name: "allowthem_session",
        secure: true,
    };
    let token = generate_token();
    let cookie = session_cookie(&token, &config, "example.com");

    assert!(
        cookie.starts_with("allowthem_session="),
        "must start with cookie name"
    );
    assert!(cookie.contains("HttpOnly"), "must have HttpOnly");
    assert!(cookie.contains("SameSite=Lax"), "must have SameSite=Lax");
    assert!(cookie.contains("Path=/"), "must have Path=/");
    assert!(
        cookie.contains("Max-Age=86400"),
        "must have Max-Age=86400 (24h in seconds)"
    );
    assert!(
        cookie.contains("Secure"),
        "must have Secure when config.secure=true"
    );
    assert!(cookie.contains("Domain=example.com"), "must include domain");
}

#[test]
fn test_session_cookie_no_secure_in_dev() {
    let config = SessionConfig {
        ttl: chrono::Duration::hours(1),
        cookie_name: "allowthem_session",
        secure: false,
    };
    let token = generate_token();
    let cookie = session_cookie(&token, &config, "");

    assert!(
        !cookie.contains("Secure"),
        "must NOT have Secure when config.secure=false"
    );
    assert!(
        !cookie.contains("Domain="),
        "must NOT have Domain when domain is empty"
    );
}

#[test]
fn test_parse_session_cookie_present() {
    let token = generate_token();
    let header = format!(
        "other_cookie=abc123; allowthem_session={}; another=xyz",
        token.as_str()
    );
    let parsed = parse_session_cookie(&header, "allowthem_session").expect("cookie must be found");
    assert_eq!(
        parsed.as_str(),
        token.as_str(),
        "parsed token must match original"
    );
}

#[test]
fn test_parse_session_cookie_missing() {
    let header = "other_cookie=abc123; yet_another=xyz";
    let result = parse_session_cookie(header, "allowthem_session");
    assert!(result.is_none(), "must return None when cookie is absent");
}

// --- M4: User CRUD tests ---

#[tokio::test]
async fn test_create_user() {
    let db = test_db().await;
    let email = Email::new("alice@example.com".into()).expect("valid email");
    let username = Username::new_unchecked("alice".into());

    let user = db
        .create_user(
            email.clone(),
            "strong-password-123",
            Some(username.clone()),
            None,
        )
        .await
        .expect("create_user");

    assert_eq!(user.email, email);
    assert_eq!(user.username, Some(username));
    assert!(user.is_active);
    assert!(!user.email_verified);
    assert!(
        user.password_hash.is_none(),
        "create_user must not return password_hash"
    );
}

#[tokio::test]
async fn test_create_user_without_username() {
    let db = test_db().await;
    let email = Email::new("noname@example.com".into()).expect("valid email");

    let user = db
        .create_user(email, "password", None, None)
        .await
        .expect("create_user");

    assert!(user.username.is_none());
}

#[tokio::test]
async fn create_user_with_custom_data() {
    let db = test_db().await;
    let email = Email::new("custom-data@example.com".into()).expect("valid email");
    let data = serde_json::json!({"display_name": "Alice"});

    let user = db
        .create_user(email, "password123", None, Some(&data))
        .await
        .expect("create_user with custom_data");

    assert_eq!(
        user.custom_data,
        Some(serde_json::json!({"display_name": "Alice"}))
    );
}

#[tokio::test]
async fn create_user_without_custom_data() {
    let db = test_db().await;
    let email = Email::new("no-custom-data@example.com".into()).expect("valid email");

    let user = db
        .create_user(email, "password123", None, None)
        .await
        .expect("create_user without custom_data");

    assert!(user.custom_data.is_none());
}

#[tokio::test]
async fn test_get_user() {
    let db = test_db().await;
    let email = Email::new("getme@example.com".into()).expect("valid email");

    let created = db
        .create_user(email.clone(), "password", None, None)
        .await
        .expect("create_user");

    let fetched = db.get_user(created.id).await.expect("get_user");

    assert_eq!(fetched.id, created.id);
    assert_eq!(fetched.email, email);
    assert!(
        fetched.password_hash.is_none(),
        "get_user must not return password_hash"
    );
}

#[tokio::test]
async fn test_get_user_by_email() {
    let db = test_db().await;
    let email = Email::new("byemail@example.com".into()).expect("valid email");

    let created = db
        .create_user(email.clone(), "password", None, None)
        .await
        .expect("create_user");

    let fetched = db
        .get_user_by_email(&email)
        .await
        .expect("get_user_by_email");

    assert_eq!(fetched.id, created.id);
}

#[tokio::test]
async fn test_get_user_by_username() {
    let db = test_db().await;
    let email = Email::new("byusername@example.com".into()).expect("valid email");
    let username = Username::new_unchecked("lookmeup".into());

    let created = db
        .create_user(email, "password", Some(username.clone()), None)
        .await
        .expect("create_user");

    let fetched = db
        .get_user_by_username(&username)
        .await
        .expect("get_user_by_username");

    assert_eq!(fetched.id, created.id);
}

#[tokio::test]
async fn test_get_user_not_found() {
    let db = test_db().await;
    let result = db.get_user(UserId::new()).await;
    assert!(
        matches!(result, Err(AuthError::NotFound)),
        "get_user for non-existent ID must return NotFound"
    );
}

#[tokio::test]
async fn test_find_for_login_by_email() {
    let db = test_db().await;
    let email = Email::new("login_email@example.com".into()).expect("valid email");

    db.create_user(email, "mypassword", None, None)
        .await
        .expect("create_user");

    let user = db
        .find_for_login("login_email@example.com")
        .await
        .expect("find_for_login");

    assert!(
        user.password_hash.is_some(),
        "find_for_login must return password_hash"
    );
}

#[tokio::test]
async fn test_find_for_login_by_username() {
    let db = test_db().await;
    let email = Email::new("login_uname@example.com".into()).expect("valid email");
    let username = Username::new_unchecked("loginuser".into());

    db.create_user(email, "mypassword", Some(username), None)
        .await
        .expect("create_user");

    let user = db
        .find_for_login("loginuser")
        .await
        .expect("find_for_login");

    assert!(
        user.password_hash.is_some(),
        "find_for_login by username must return password_hash"
    );
}

#[tokio::test]
async fn test_find_for_login_verify_password() {
    let db = test_db().await;
    let email = Email::new("verify@example.com".into()).expect("valid email");

    db.create_user(email, "correct-horse", None, None)
        .await
        .expect("create_user");

    let user = db
        .find_for_login("verify@example.com")
        .await
        .expect("find_for_login");

    let hash = user.password_hash.as_ref().expect("password_hash present");
    assert!(
        verify_password("correct-horse", hash).expect("verify_password"),
        "correct password must verify"
    );
    assert!(
        !verify_password("wrong-password", hash).expect("verify_password"),
        "wrong password must not verify"
    );
}

#[tokio::test]
async fn test_find_for_login_not_found() {
    let db = test_db().await;
    let result = db.find_for_login("nonexistent").await;
    assert!(
        matches!(result, Err(AuthError::NotFound)),
        "find_for_login for non-existent identifier must return NotFound"
    );
}

#[tokio::test]
async fn test_duplicate_email_returns_conflict() {
    let db = test_db().await;
    let email = Email::new("dupe@example.com".into()).expect("valid email");

    db.create_user(email.clone(), "pass1", None, None)
        .await
        .expect("first create_user");

    let result = db.create_user(email, "pass2", None, None).await;

    assert!(
        matches!(result, Err(AuthError::Conflict(ref msg)) if msg.contains("email")),
        "duplicate email must return Conflict with 'email' in message, got: {result:?}"
    );
}

#[tokio::test]
async fn test_duplicate_username_returns_conflict() {
    let db = test_db().await;
    let username = Username::new_unchecked("samename".into());

    db.create_user(
        Email::new("user1@example.com".into()).expect("valid"),
        "pass1",
        Some(username.clone()),
        None,
    )
    .await
    .expect("first create_user");

    let result = db
        .create_user(
            Email::new("user2@example.com".into()).expect("valid"),
            "pass2",
            Some(username),
            None,
        )
        .await;

    assert!(
        matches!(result, Err(AuthError::Conflict(ref msg)) if msg.contains("username")),
        "duplicate username must return Conflict with 'username' in message, got: {result:?}"
    );
}

#[tokio::test]
async fn test_update_user_email() {
    let db = test_db().await;
    let old_email = Email::new("old@example.com".into()).expect("valid email");
    let new_email = Email::new("new@example.com".into()).expect("valid email");

    let user = db
        .create_user(old_email.clone(), "password", None, None)
        .await
        .expect("create_user");

    db.update_user_email(user.id, new_email.clone())
        .await
        .expect("update_user_email");

    let fetched = db
        .get_user_by_email(&new_email)
        .await
        .expect("get by new email");
    assert_eq!(fetched.id, user.id);

    let old_result = db.get_user_by_email(&old_email).await;
    assert!(
        matches!(old_result, Err(AuthError::NotFound)),
        "old email must no longer resolve"
    );
}

#[tokio::test]
async fn test_update_user_username() {
    let db = test_db().await;
    let email = Email::new("update_uname@example.com".into()).expect("valid email");
    let username = Username::new_unchecked("original".into());
    let new_username = Username::new_unchecked("updated".into());

    let user = db
        .create_user(email, "password", Some(username), None)
        .await
        .expect("create_user");

    // Update to new username
    db.update_user_username(user.id, Some(new_username.clone()))
        .await
        .expect("update_user_username");

    let fetched = db
        .get_user_by_username(&new_username)
        .await
        .expect("get by new username");
    assert_eq!(fetched.id, user.id);

    // Clear username
    db.update_user_username(user.id, None)
        .await
        .expect("update_user_username to None");

    let fetched2 = db.get_user(user.id).await.expect("get_user");
    assert!(fetched2.username.is_none(), "username must be cleared");
}

#[tokio::test]
async fn test_update_user_active() {
    let db = test_db().await;
    let email = Email::new("active@example.com".into()).expect("valid email");

    let user = db
        .create_user(email, "password", None, None)
        .await
        .expect("create_user");

    assert!(user.is_active, "new user must be active");

    db.update_user_active(user.id, false)
        .await
        .expect("update_user_active");

    let fetched = db.get_user(user.id).await.expect("get_user");
    assert!(!fetched.is_active, "user must be deactivated");
}

#[tokio::test]
async fn test_update_nonexistent_user() {
    let db = test_db().await;
    let email = Email::new("phantom@example.com".into()).expect("valid email");
    let result = db.update_user_email(UserId::new(), email).await;
    assert!(
        matches!(result, Err(AuthError::NotFound)),
        "updating non-existent user must return NotFound"
    );
}

#[tokio::test]
async fn test_delete_user_crud() {
    let db = test_db().await;
    let email = Email::new("deleteme@example.com".into()).expect("valid email");

    let user = db
        .create_user(email, "password", None, None)
        .await
        .expect("create_user");

    db.delete_user(user.id).await.expect("delete_user");

    let result = db.get_user(user.id).await;
    assert!(
        matches!(result, Err(AuthError::NotFound)),
        "deleted user must return NotFound"
    );
}

#[tokio::test]
async fn test_delete_nonexistent_user() {
    let db = test_db().await;
    let result = db.delete_user(UserId::new()).await;
    assert!(
        matches!(result, Err(AuthError::NotFound)),
        "deleting non-existent user must return NotFound"
    );
}

#[test]
fn test_email_validation() {
    assert!(Email::new("valid@example.com".into()).is_ok());
    assert!(
        Email::new(" spaced@example.com ".into()).is_ok(),
        "whitespace should be trimmed"
    );
    assert!(
        matches!(Email::new("nope".into()), Err(AuthError::InvalidEmail)),
        "no @ must fail"
    );
    assert!(
        matches!(Email::new("".into()), Err(AuthError::InvalidEmail)),
        "empty must fail"
    );
    assert!(
        matches!(
            Email::new("@domain.com".into()),
            Err(AuthError::InvalidEmail)
        ),
        "empty local part must fail"
    );
    assert!(
        matches!(Email::new("user@".into()), Err(AuthError::InvalidEmail)),
        "empty domain must fail"
    );
    assert!(
        Email::new("user@nodot".into()).is_ok(),
        "domain without dot is valid"
    );
}

// --- M7: Role CRUD and assignment tests ---

#[tokio::test]
async fn test_create_and_get_role() {
    let db = test_db().await;

    let name = RoleName::new_unchecked("admin".to_string());
    let role = db
        .create_role(&name, Some("Administrator"))
        .await
        .expect("create_role");

    assert_eq!(role.name, name);
    assert_eq!(role.description.as_deref(), Some("Administrator"));

    let by_id = db
        .get_role(&role.id)
        .await
        .expect("get_role")
        .expect("role must exist");
    assert_eq!(by_id.id, role.id);

    let by_name = db
        .get_role_by_name(&name)
        .await
        .expect("get_role_by_name")
        .expect("role must exist by name");
    assert_eq!(by_name.id, role.id);
}

#[tokio::test]
async fn test_list_roles_empty_and_populated() {
    let db = test_db().await;

    let empty = db.list_roles().await.expect("list_roles empty");
    assert!(empty.is_empty(), "no roles yet");

    db.create_role(&RoleName::new_unchecked("viewer".to_string()), None)
        .await
        .expect("create viewer");
    db.create_role(&RoleName::new_unchecked("editor".to_string()), None)
        .await
        .expect("create editor");

    let roles = db.list_roles().await.expect("list_roles");
    assert_eq!(roles.len(), 2);
}

#[tokio::test]
async fn test_delete_role() {
    let db = test_db().await;

    let role = db
        .create_role(&RoleName::new_unchecked("temp".to_string()), None)
        .await
        .expect("create_role");

    let deleted = db.delete_role(&role.id).await.expect("delete_role");
    assert!(deleted, "must return true when role existed");

    let not_found = db.get_role(&role.id).await.expect("get_role");
    assert!(not_found.is_none(), "role must be gone after delete");

    // Second delete on the same ID must return false
    let deleted_again = db.delete_role(&role.id).await.expect("delete_role again");
    assert!(!deleted_again, "must return false when role already gone");
}

#[tokio::test]
async fn test_duplicate_role_name_returns_conflict() {
    let db = test_db().await;

    let name = RoleName::new_unchecked("unique_role".to_string());
    db.create_role(&name, None)
        .await
        .expect("first create succeeds");

    let result = db.create_role(&name, Some("duplicate")).await;
    assert!(
        matches!(result, Err(AuthError::Conflict(_))),
        "duplicate role name must return Conflict, got: {result:?}"
    );
}

#[tokio::test]
async fn test_assign_and_unassign_role() {
    let db = test_db().await;
    let user_id = insert_test_user(&db, "roles_user@example.com").await;

    let role = db
        .create_role(&RoleName::new_unchecked("moderator".to_string()), None)
        .await
        .expect("create_role");

    db.assign_role(&user_id, &role.id)
        .await
        .expect("assign_role");

    // Assigning again must be idempotent (no error)
    db.assign_role(&user_id, &role.id)
        .await
        .expect("assign_role idempotent");

    let removed = db
        .unassign_role(&user_id, &role.id)
        .await
        .expect("unassign_role");
    assert!(removed, "must return true when assignment existed");

    let removed_again = db
        .unassign_role(&user_id, &role.id)
        .await
        .expect("unassign again");
    assert!(
        !removed_again,
        "must return false when assignment already gone"
    );
}

#[tokio::test]
async fn test_has_role_true_and_false() {
    let db = test_db().await;
    let user_id = insert_test_user(&db, "has_role_user@example.com").await;

    let name = RoleName::new_unchecked("superuser".to_string());
    let role = db.create_role(&name, None).await.expect("create_role");

    let before = db.has_role(&user_id, &name).await.expect("has_role before");
    assert!(!before, "must be false before assignment");

    db.assign_role(&user_id, &role.id)
        .await
        .expect("assign_role");

    let after = db.has_role(&user_id, &name).await.expect("has_role after");
    assert!(after, "must be true after assignment");
}

#[tokio::test]
async fn test_get_user_roles() {
    let db = test_db().await;
    let user_id = insert_test_user(&db, "user_roles@example.com").await;

    let empty = db
        .get_user_roles(&user_id)
        .await
        .expect("get_user_roles empty");
    assert!(empty.is_empty(), "no roles assigned yet");

    let r1 = db
        .create_role(&RoleName::new_unchecked("read".to_string()), None)
        .await
        .expect("create r1");
    let r2 = db
        .create_role(&RoleName::new_unchecked("write".to_string()), None)
        .await
        .expect("create r2");

    db.assign_role(&user_id, &r1.id).await.expect("assign r1");
    db.assign_role(&user_id, &r2.id).await.expect("assign r2");

    let roles = db.get_user_roles(&user_id).await.expect("get_user_roles");
    assert_eq!(roles.len(), 2);
    let names: Vec<_> = roles.iter().map(|r| r.name.clone()).collect();
    assert!(names.contains(&r1.name));
    assert!(names.contains(&r2.name));
}

// --- M8: Permission CRUD and assignment tests ---

#[tokio::test]
async fn test_create_and_get_permission() {
    let db = test_db().await;

    let name = PermissionName::new_unchecked("posts:read".to_string());
    let perm = db
        .create_permission(&name, Some("Read posts"))
        .await
        .expect("create_permission");

    assert_eq!(perm.name, name);
    assert_eq!(perm.description.as_deref(), Some("Read posts"));

    let by_id = db
        .get_permission(&perm.id)
        .await
        .expect("get_permission")
        .expect("must exist by id");
    assert_eq!(by_id.id, perm.id);

    let by_name = db
        .get_permission_by_name(&name)
        .await
        .expect("get_permission_by_name")
        .expect("must exist by name");
    assert_eq!(by_name.id, perm.id);
}

#[tokio::test]
async fn test_duplicate_permission_name_returns_conflict() {
    let db = test_db().await;

    let name = PermissionName::new_unchecked("unique:perm".to_string());
    db.create_permission(&name, None)
        .await
        .expect("first create succeeds");

    let result = db.create_permission(&name, Some("duplicate")).await;
    assert!(
        matches!(result, Err(AuthError::Conflict(_))),
        "duplicate permission name must return Conflict, got: {result:?}"
    );
}

#[tokio::test]
async fn test_has_permission_via_role() {
    let db = test_db().await;
    let user_id = insert_test_user(&db, "perm_role@example.com").await;

    let role = db
        .create_role(&RoleName::new_unchecked("writer".to_string()), None)
        .await
        .expect("create_role");
    let perm = db
        .create_permission(
            &PermissionName::new_unchecked("posts:write".to_string()),
            None,
        )
        .await
        .expect("create_permission");

    db.assign_role(&user_id, &role.id)
        .await
        .expect("assign_role");
    db.assign_permission_to_role(&role.id, &perm.id)
        .await
        .expect("assign_permission_to_role");

    let has = db
        .has_permission(&user_id, &perm.name)
        .await
        .expect("has_permission");
    assert!(has, "must have permission via role");
}

#[tokio::test]
async fn test_has_permission_via_direct_assignment() {
    let db = test_db().await;
    let user_id = insert_test_user(&db, "perm_direct@example.com").await;

    let perm = db
        .create_permission(
            &PermissionName::new_unchecked("admin:read".to_string()),
            None,
        )
        .await
        .expect("create_permission");

    db.assign_permission_to_user(&user_id, &perm.id)
        .await
        .expect("assign_permission_to_user");

    let has = db
        .has_permission(&user_id, &perm.name)
        .await
        .expect("has_permission");
    assert!(has, "must have permission via direct assignment");
}

#[tokio::test]
async fn test_has_permission_no_assignment_returns_false() {
    let db = test_db().await;
    let user_id = insert_test_user(&db, "perm_none@example.com").await;

    let perm = db
        .create_permission(
            &PermissionName::new_unchecked("secret:op".to_string()),
            None,
        )
        .await
        .expect("create_permission");

    let has = db
        .has_permission(&user_id, &perm.name)
        .await
        .expect("has_permission");
    assert!(!has, "must return false when user has no assignment");
}

#[tokio::test]
async fn test_get_user_permissions_deduplicated() {
    let db = test_db().await;
    let user_id = insert_test_user(&db, "perm_dedup@example.com").await;

    let role = db
        .create_role(&RoleName::new_unchecked("dedup_role".to_string()), None)
        .await
        .expect("create_role");
    let p1 = db
        .create_permission(
            &PermissionName::new_unchecked("dedup:read".to_string()),
            None,
        )
        .await
        .expect("create p1");
    let p2 = db
        .create_permission(
            &PermissionName::new_unchecked("dedup:write".to_string()),
            None,
        )
        .await
        .expect("create p2");

    // p1 via both role and direct — must appear only once
    db.assign_role(&user_id, &role.id)
        .await
        .expect("assign_role");
    db.assign_permission_to_role(&role.id, &p1.id)
        .await
        .expect("p1 to role");
    db.assign_permission_to_user(&user_id, &p1.id)
        .await
        .expect("p1 direct");
    // p2 via direct only
    db.assign_permission_to_user(&user_id, &p2.id)
        .await
        .expect("p2 direct");

    let perms = db
        .get_user_permissions(&user_id)
        .await
        .expect("get_user_permissions");
    assert_eq!(perms.len(), 2, "p1 must not be duplicated; got {perms:?}");
    let perm_names: Vec<_> = perms.iter().map(|p| p.name.clone()).collect();
    assert!(perm_names.contains(&p1.name));
    assert!(perm_names.contains(&p2.name));
}

#[tokio::test]
async fn test_unassign_permission_from_role_and_user() {
    let db = test_db().await;
    let user_id = insert_test_user(&db, "perm_unassign@example.com").await;

    let role = db
        .create_role(&RoleName::new_unchecked("unassign_role".to_string()), None)
        .await
        .expect("create_role");
    let perm = db
        .create_permission(
            &PermissionName::new_unchecked("unassign:op".to_string()),
            None,
        )
        .await
        .expect("create_permission");

    db.assign_permission_to_role(&role.id, &perm.id)
        .await
        .expect("assign to role");
    db.assign_permission_to_user(&user_id, &perm.id)
        .await
        .expect("assign to user");

    let removed_role = db
        .unassign_permission_from_role(&role.id, &perm.id)
        .await
        .expect("unassign from role");
    assert!(removed_role, "must return true when assignment existed");

    let removed_role_again = db
        .unassign_permission_from_role(&role.id, &perm.id)
        .await
        .expect("unassign from role again");
    assert!(!removed_role_again, "must return false when already gone");

    let removed_user = db
        .unassign_permission_from_user(&user_id, &perm.id)
        .await
        .expect("unassign from user");
    assert!(removed_user, "must return true when assignment existed");

    let removed_user_again = db
        .unassign_permission_from_user(&user_id, &perm.id)
        .await
        .expect("unassign from user again");
    assert!(!removed_user_again, "must return false when already gone");
}

// ── Audit log tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_audit_log_round_trip() {
    let db = test_db().await;
    let user_id = UserId::new();

    db.log_audit(
        AuditEvent::Login,
        Some(&user_id),
        None,
        Some("127.0.0.1"),
        Some("Mozilla/5.0"),
        Some(r#"{"status":"ok"}"#),
    )
    .await
    .expect("log audit event");

    let entries = db.get_audit_log(None, 10, 0).await.expect("get audit log");

    assert_eq!(entries.len(), 1);
    let entry = &entries[0];
    assert_eq!(entry.event_type, AuditEvent::Login);
    assert_eq!(entry.user_id, Some(user_id));
    assert_eq!(entry.ip_address.as_deref(), Some("127.0.0.1"));
    assert_eq!(entry.user_agent.as_deref(), Some("Mozilla/5.0"));
    assert_eq!(entry.detail.as_deref(), Some(r#"{"status":"ok"}"#));
}

#[tokio::test]
async fn test_audit_log_filter_by_user() {
    let db = test_db().await;
    let user_a = UserId::new();
    let user_b = UserId::new();

    db.log_audit(AuditEvent::Login, Some(&user_a), None, None, None, None)
        .await
        .expect("log user_a login");
    db.log_audit(AuditEvent::Logout, Some(&user_b), None, None, None, None)
        .await
        .expect("log user_b logout");
    db.log_audit(
        AuditEvent::PasswordChange,
        Some(&user_a),
        None,
        None,
        None,
        None,
    )
    .await
    .expect("log user_a password change");

    let entries_a = db
        .get_audit_log(Some(&user_a), 10, 0)
        .await
        .expect("get user_a audit log");
    assert_eq!(entries_a.len(), 2);
    for entry in &entries_a {
        assert_eq!(entry.user_id, Some(user_a));
    }

    let entries_b = db
        .get_audit_log(Some(&user_b), 10, 0)
        .await
        .expect("get user_b audit log");
    assert_eq!(entries_b.len(), 1);
    assert_eq!(entries_b[0].event_type, AuditEvent::Logout);
}

#[tokio::test]
async fn test_audit_log_filter_by_event_type() {
    let db = test_db().await;
    let user_id = UserId::new();

    db.log_audit(AuditEvent::Login, Some(&user_id), None, None, None, None)
        .await
        .expect("log login");
    db.log_audit(AuditEvent::Login, Some(&user_id), None, None, None, None)
        .await
        .expect("log login again");
    db.log_audit(AuditEvent::Logout, Some(&user_id), None, None, None, None)
        .await
        .expect("log logout");
    db.log_audit(AuditEvent::Register, Some(&user_id), None, None, None, None)
        .await
        .expect("log register");

    let logins = db
        .get_audit_log_by_event(AuditEvent::Login, 10, 0)
        .await
        .expect("get logins");
    assert_eq!(logins.len(), 2);
    for entry in &logins {
        assert_eq!(entry.event_type, AuditEvent::Login);
    }

    let logouts = db
        .get_audit_log_by_event(AuditEvent::Logout, 10, 0)
        .await
        .expect("get logouts");
    assert_eq!(logouts.len(), 1);
}

#[tokio::test]
async fn test_audit_log_pagination() {
    let db = test_db().await;
    let user_id = UserId::new();

    for _ in 0..5 {
        db.log_audit(AuditEvent::Login, Some(&user_id), None, None, None, None)
            .await
            .expect("log login");
    }

    let page1 = db.get_audit_log(None, 2, 0).await.expect("get page 1");
    assert_eq!(page1.len(), 2);

    let page2 = db.get_audit_log(None, 2, 2).await.expect("get page 2");
    assert_eq!(page2.len(), 2);

    let page3 = db.get_audit_log(None, 2, 4).await.expect("get page 3");
    assert_eq!(page3.len(), 1);

    // Pages must not overlap
    assert_ne!(page1[0].id, page2[0].id);
    assert_ne!(page2[0].id, page3[0].id);
}

#[tokio::test]
async fn test_audit_log_null_user_id() {
    let db = test_db().await;

    // A failed login attempt — no valid user associated
    db.log_audit(
        AuditEvent::LoginFailed,
        None,
        None,
        Some("10.0.0.1"),
        None,
        Some(r#"{"email":"unknown@example.com"}"#),
    )
    .await
    .expect("log failed login with no user_id");

    let entries = db.get_audit_log(None, 10, 0).await.expect("get audit log");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].event_type, AuditEvent::LoginFailed);
    assert!(entries[0].user_id.is_none());
    assert_eq!(entries[0].ip_address.as_deref(), Some("10.0.0.1"));
}

// ---------------------------------------------------------------------------
// search_audit_log tests (M47)
// ---------------------------------------------------------------------------

/// Create a test user and return their UserId for audit log tests.
async fn audit_test_user(db: &Db, email: &str) -> UserId {
    let uid = UserId::new();
    let e = Email::new_unchecked(email.to_string());
    let pw =
        PasswordHash::new_unchecked("$argon2id$v=19$m=65536,t=2,p=1$fakesalt$fakehash".to_string());
    sqlx::query(
        "INSERT INTO allowthem_users \
         (id, email, username, password_hash, email_verified, is_active, created_at, updated_at) \
         VALUES (?, ?, NULL, ?, 1, 1, ?, ?)",
    )
    .bind(uid)
    .bind(&e)
    .bind(&pw)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert audit test user");
    uid
}

#[tokio::test]
async fn search_audit_log_returns_all_when_no_filters() {
    let db = test_db().await;
    let uid = audit_test_user(&db, "audit-all@test.com").await;

    db.log_audit(AuditEvent::Login, Some(&uid), None, None, None, None)
        .await
        .unwrap();
    db.log_audit(AuditEvent::Logout, Some(&uid), None, None, None, None)
        .await
        .unwrap();

    let result = db
        .search_audit_log(SearchAuditParams {
            user_id: None,
            event_type: None,
            is_success: None,
            from: None,
            to: None,
            limit: 50,
            offset: 0,
        })
        .await
        .unwrap();

    assert_eq!(result.total, 2);
    assert_eq!(result.entries.len(), 2);
}

#[tokio::test]
async fn search_audit_log_filters_by_user_id() {
    let db = test_db().await;
    let uid1 = audit_test_user(&db, "audit-u1@test.com").await;
    let uid2 = audit_test_user(&db, "audit-u2@test.com").await;

    db.log_audit(AuditEvent::Login, Some(&uid1), None, None, None, None)
        .await
        .unwrap();
    db.log_audit(AuditEvent::Login, Some(&uid2), None, None, None, None)
        .await
        .unwrap();

    let result = db
        .search_audit_log(SearchAuditParams {
            user_id: Some(uid1),
            event_type: None,
            is_success: None,
            from: None,
            to: None,
            limit: 50,
            offset: 0,
        })
        .await
        .unwrap();

    assert_eq!(result.total, 1);
    assert_eq!(result.entries[0].user_id, Some(uid1));
}

#[tokio::test]
async fn search_audit_log_filters_by_event_type() {
    let db = test_db().await;
    let uid = audit_test_user(&db, "audit-event@test.com").await;

    db.log_audit(AuditEvent::Login, Some(&uid), None, None, None, None)
        .await
        .unwrap();
    db.log_audit(AuditEvent::LoginFailed, None, None, None, None, None)
        .await
        .unwrap();

    let result = db
        .search_audit_log(SearchAuditParams {
            user_id: None,
            event_type: Some(&AuditEvent::Login),
            is_success: None,
            from: None,
            to: None,
            limit: 50,
            offset: 0,
        })
        .await
        .unwrap();

    assert_eq!(result.total, 1);
    assert_eq!(result.entries[0].event_type, AuditEvent::Login);
}

#[tokio::test]
async fn search_audit_log_filters_by_success() {
    let db = test_db().await;
    let uid = audit_test_user(&db, "audit-success@test.com").await;

    db.log_audit(AuditEvent::Login, Some(&uid), None, None, None, None)
        .await
        .unwrap();
    db.log_audit(AuditEvent::LoginFailed, None, None, None, None, None)
        .await
        .unwrap();

    // is_success=true excludes LoginFailed
    let result = db
        .search_audit_log(SearchAuditParams {
            user_id: None,
            event_type: None,
            is_success: Some(true),
            from: None,
            to: None,
            limit: 50,
            offset: 0,
        })
        .await
        .unwrap();
    assert_eq!(result.total, 1);
    assert_eq!(result.entries[0].event_type, AuditEvent::Login);

    // is_success=false returns only LoginFailed
    let result = db
        .search_audit_log(SearchAuditParams {
            user_id: None,
            event_type: None,
            is_success: Some(false),
            from: None,
            to: None,
            limit: 50,
            offset: 0,
        })
        .await
        .unwrap();
    assert_eq!(result.total, 1);
    assert_eq!(result.entries[0].event_type, AuditEvent::LoginFailed);
}

#[tokio::test]
async fn search_audit_log_paginates() {
    let db = test_db().await;
    let uid = audit_test_user(&db, "audit-page@test.com").await;

    for _ in 0..5 {
        db.log_audit(AuditEvent::Login, Some(&uid), None, None, None, None)
            .await
            .unwrap();
    }

    let result = db
        .search_audit_log(SearchAuditParams {
            user_id: None,
            event_type: None,
            is_success: None,
            from: None,
            to: None,
            limit: 2,
            offset: 0,
        })
        .await
        .unwrap();

    assert_eq!(result.total, 5);
    assert_eq!(result.entries.len(), 2);
}

#[tokio::test]
async fn search_audit_log_resolves_email() {
    let db = test_db().await;
    let uid = audit_test_user(&db, "audit-email@test.com").await;

    db.log_audit(AuditEvent::Login, Some(&uid), None, None, None, None)
        .await
        .unwrap();

    let result = db
        .search_audit_log(SearchAuditParams {
            user_id: None,
            event_type: None,
            is_success: None,
            from: None,
            to: None,
            limit: 50,
            offset: 0,
        })
        .await
        .unwrap();

    assert_eq!(
        result.entries[0].user_email.as_deref(),
        Some("audit-email@test.com")
    );
}

#[tokio::test]
async fn search_audit_log_null_user_email() {
    let db = test_db().await;

    db.log_audit(AuditEvent::LoginFailed, None, None, None, None, None)
        .await
        .unwrap();

    let result = db
        .search_audit_log(SearchAuditParams {
            user_id: None,
            event_type: None,
            is_success: None,
            from: None,
            to: None,
            limit: 50,
            offset: 0,
        })
        .await
        .unwrap();

    assert!(result.entries[0].user_email.is_none());
}

#[tokio::test]
async fn test_application_round_trip() {
    let db = test_db().await;

    // applications.created_by is a nullable FK to users
    let user_id = UserId::new();
    sqlx::query(
        "INSERT INTO allowthem_users (id, email, username, password_hash, email_verified, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(user_id)
    .bind(Email::new_unchecked("app-owner@example.com".to_string()))
    .bind(None::<Username>)
    .bind(None::<PasswordHash>)
    .bind(false)
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert user for application FK");

    let app_id = ApplicationId::new();
    let client_id = ClientId::new_unchecked("ath_testclientid0000000000000000000".to_string());
    let secret_hash =
        PasswordHash::new_unchecked("$argon2id$v=19$m=65536,t=2,p=1$fakesalt$fakehash".to_string());
    let redirect_uris = r#"["https://example.com/callback"]"#;

    sqlx::query(
        "INSERT INTO allowthem_applications
         (id, name, client_id, client_type, client_secret_hash, redirect_uris, logo_url, primary_color, is_trusted, created_by, is_active, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(app_id)
    .bind("My App")
    .bind(&client_id)
    .bind(ClientType::Confidential)
    .bind(&secret_hash)
    .bind(redirect_uris)
    .bind(None::<String>)
    .bind(None::<String>)
    .bind(true)
    .bind(Some(user_id))
    .bind(true)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert application");

    let app = sqlx::query_as::<_, Application>(
        "SELECT id, name, client_id, client_type, client_secret_hash, redirect_uris, \
         logo_url, primary_color, \
         accent_hex, accent_ink, forced_mode, font_css_url, font_family, \
         splash_text, splash_image_url, splash_primitive, splash_url, shader_cell_scale, \
         is_trusted, created_by, is_active, created_at, updated_at \
         FROM allowthem_applications WHERE id = ?",
    )
    .bind(app_id)
    .fetch_one(db.pool())
    .await
    .expect("fetch application");

    assert_eq!(app.id, app_id);
    assert_eq!(app.name, "My App");
    assert_eq!(app.client_id, client_id);
    assert_eq!(app.redirect_uris, redirect_uris);
    assert_eq!(app.created_by, Some(user_id));
    assert!(app.is_trusted);
    assert!(app.is_active);
    assert!(app.logo_url.is_none());
    assert!(app.primary_color.is_none());
}

#[tokio::test]
async fn create_application_returns_app_and_secret() {
    let db = test_db().await;
    let uris = vec!["https://example.com/callback".to_string()];
    let (app, secret) = db
        .create_application(CreateApplicationParams {
            name: "My App".to_string(),
            client_type: ClientType::Confidential,
            redirect_uris: uris.clone(),
            is_trusted: false,
            created_by: None,
            logo_url: None,
            primary_color: None,
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        })
        .await
        .expect("create_application");

    assert_eq!(app.name, "My App");
    assert!(app.client_id.as_str().starts_with("ath_"));
    assert!(!app.is_trusted);
    assert!(app.is_active);
    assert!(app.logo_url.is_none());
    assert!(app.primary_color.is_none());
    assert!(
        !secret
            .expect("confidential app has secret")
            .as_str()
            .is_empty()
    );
    let list = app.redirect_uri_list().expect("redirect_uri_list");
    assert_eq!(list, uris);
}

#[tokio::test]
async fn get_application_not_found() {
    let db = test_db().await;
    let err = db.get_application(ApplicationId::new()).await.unwrap_err();
    assert!(matches!(err, AuthError::NotFound));
}

#[tokio::test]
async fn get_application_by_client_id_finds_app() {
    let db = test_db().await;
    let uris = vec!["https://example.com/callback".to_string()];
    let (app, _) = db
        .create_application(CreateApplicationParams {
            name: "App".to_string(),
            client_type: ClientType::Confidential,
            redirect_uris: uris,
            is_trusted: false,
            created_by: None,
            logo_url: None,
            primary_color: None,
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        })
        .await
        .expect("create_application");

    let found = db
        .get_application_by_client_id(&app.client_id)
        .await
        .expect("get_application_by_client_id");
    assert_eq!(found.id, app.id);
}

#[tokio::test]
async fn get_application_by_client_id_not_found() {
    let db = test_db().await;
    use crate::types::ClientId;
    let fake = ClientId::new_unchecked("ath_doesnotexist0000000000000000000".to_string());
    let err = db.get_application_by_client_id(&fake).await.unwrap_err();
    assert!(matches!(err, AuthError::NotFound));
}

#[tokio::test]
async fn list_applications_ordered_by_created_at() {
    let db = test_db().await;
    let uris = vec!["https://example.com/callback".to_string()];

    let (a, _) = db
        .create_application(CreateApplicationParams {
            name: "First".to_string(),
            client_type: ClientType::Confidential,
            redirect_uris: uris.clone(),
            is_trusted: false,
            created_by: None,
            logo_url: None,
            primary_color: None,
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        })
        .await
        .expect("create first");
    let (b, _) = db
        .create_application(CreateApplicationParams {
            name: "Second".to_string(),
            client_type: ClientType::Confidential,
            redirect_uris: uris,
            is_trusted: false,
            created_by: None,
            logo_url: None,
            primary_color: None,
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        })
        .await
        .expect("create second");

    let list = db.list_applications().await.expect("list_applications");
    assert!(list.len() >= 2);
    let names: Vec<&str> = list.iter().map(|a| a.name.as_str()).collect();
    let pos_a = names.iter().position(|&n| n == "First").unwrap();
    let pos_b = names.iter().position(|&n| n == "Second").unwrap();
    assert!(pos_a < pos_b);
    let _ = (a, b);
}

#[tokio::test]
async fn update_application_changes_fields() {
    let db = test_db().await;
    let uris = vec!["https://example.com/callback".to_string()];
    let (app, _) = db
        .create_application(CreateApplicationParams {
            name: "Original".to_string(),
            client_type: ClientType::Confidential,
            redirect_uris: uris,
            is_trusted: false,
            created_by: None,
            logo_url: None,
            primary_color: None,
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        })
        .await
        .expect("create_application");

    let new_uris = vec!["https://updated.example.com/callback".to_string()];
    db.update_application(
        app.id,
        UpdateApplication {
            name: "Updated".to_string(),
            redirect_uris: new_uris.clone(),
            is_trusted: true,
            is_active: true,
            logo_url: None,
            primary_color: None,
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        },
    )
    .await
    .expect("update_application");

    let updated = db.get_application(app.id).await.expect("get_application");
    assert_eq!(updated.name, "Updated");
    assert!(updated.is_trusted);
    let list = updated.redirect_uri_list().expect("redirect_uri_list");
    assert_eq!(list, new_uris);
}

#[tokio::test]
async fn update_application_sets_logo_url_and_primary_color() {
    let db = test_db().await;
    let uris = vec!["https://example.com/callback".to_string()];
    let (app, _) = db
        .create_application(CreateApplicationParams {
            name: "App".to_string(),
            client_type: ClientType::Confidential,
            redirect_uris: uris.clone(),
            is_trusted: false,
            created_by: None,
            logo_url: None,
            primary_color: None,
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        })
        .await
        .expect("create_application");

    db.update_application(
        app.id,
        UpdateApplication {
            name: app.name.clone(),
            redirect_uris: uris,
            is_trusted: app.is_trusted,
            is_active: app.is_active,
            logo_url: Some("https://example.com/logo.png".to_string()),
            primary_color: Some("#ff0000".to_string()),
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        },
    )
    .await
    .expect("update_application");

    let updated = db.get_application(app.id).await.expect("get_application");
    assert_eq!(
        updated.logo_url.as_deref(),
        Some("https://example.com/logo.png")
    );
    assert_eq!(updated.primary_color.as_deref(), Some("#ff0000"));
}

#[tokio::test]
async fn update_application_not_found() {
    let db = test_db().await;
    let err = db
        .update_application(
            ApplicationId::new(),
            UpdateApplication {
                name: "Ghost".to_string(),
                redirect_uris: vec!["https://example.com/callback".to_string()],
                is_trusted: false,
                is_active: true,
                logo_url: None,
                primary_color: None,
                accent_hex: None,
                accent_ink: None,
                forced_mode: None,
                font_css_url: None,
                font_family: None,
                splash_text: None,
                splash_image_url: None,
                splash_primitive: None,
                splash_url: None,
                shader_cell_scale: None,
            },
        )
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::NotFound));
}

#[tokio::test]
async fn regenerate_client_secret_returns_new_secret() {
    let db = test_db().await;
    let uris = vec!["https://example.com/callback".to_string()];
    let (app, original_secret) = db
        .create_application(CreateApplicationParams {
            name: "App".to_string(),
            client_type: ClientType::Confidential,
            redirect_uris: uris,
            is_trusted: false,
            created_by: None,
            logo_url: None,
            primary_color: None,
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        })
        .await
        .expect("create_application");

    let (updated_app, new_secret) = db
        .regenerate_client_secret(app.id)
        .await
        .expect("regenerate_client_secret");

    let original_secret = original_secret.expect("confidential app has secret");
    let hash = updated_app
        .client_secret_hash
        .as_ref()
        .expect("confidential app has hash");
    assert_eq!(updated_app.id, app.id);
    assert_ne!(new_secret.as_str(), original_secret.as_str());

    // New secret verifies against the stored hash; old one should not
    use crate::password::verify_password;
    assert!(verify_password(new_secret.as_str(), hash).expect("verify new secret"));
    assert!(
        !verify_password(original_secret.as_str(), hash)
            .expect("verify old secret against new hash")
    );
}

#[tokio::test]
async fn regenerate_client_secret_not_found() {
    let db = test_db().await;
    let err = db
        .regenerate_client_secret(ApplicationId::new())
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::NotFound));
}

#[tokio::test]
async fn regenerate_client_secret_rejects_public_client() {
    let db = test_db().await;
    let uris = vec!["https://example.com/callback".to_string()];
    let (app, _) = db
        .create_application(CreateApplicationParams {
            name: "PublicApp".to_string(),
            client_type: ClientType::Public,
            redirect_uris: uris,
            is_trusted: false,
            created_by: None,
            logo_url: None,
            primary_color: None,
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        })
        .await
        .expect("create_application");

    let err = db.regenerate_client_secret(app.id).await.unwrap_err();
    assert!(
        matches!(err, AuthError::InvalidRequest(_)),
        "public client must not regenerate secret"
    );
}

#[tokio::test]
async fn delete_application_removes_row() {
    let db = test_db().await;
    let uris = vec!["https://example.com/callback".to_string()];
    let (app, _) = db
        .create_application(CreateApplicationParams {
            name: "App".to_string(),
            client_type: ClientType::Confidential,
            redirect_uris: uris,
            is_trusted: false,
            created_by: None,
            logo_url: None,
            primary_color: None,
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        })
        .await
        .expect("create_application");

    db.delete_application(app.id)
        .await
        .expect("delete_application");

    let err = db.get_application(app.id).await.unwrap_err();
    assert!(matches!(err, AuthError::NotFound));
}

#[tokio::test]
async fn delete_application_not_found() {
    let db = test_db().await;
    let err = db
        .delete_application(ApplicationId::new())
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::NotFound));
}

// ---------------------------------------------------------------------------
// Authorization code and consent tests (M39)
// ---------------------------------------------------------------------------

use crate::authorization::{generate_authorization_code, hash_authorization_code};
use crate::types::AuthorizationCodeId;

/// Create a test user and application for authorization tests.
async fn authz_fixtures(db: &Db) -> (UserId, Application) {
    let user_id = UserId::new();
    let email = Email::new_unchecked("authz@example.com".to_string());
    let pw_hash =
        PasswordHash::new_unchecked("$argon2id$v=19$m=65536,t=2,p=1$fakesalt$fakehash".to_string());
    sqlx::query(
        "INSERT INTO allowthem_users \
         (id, email, username, password_hash, email_verified, is_active, created_at, updated_at) \
         VALUES (?, ?, NULL, ?, 1, 1, ?, ?)",
    )
    .bind(user_id)
    .bind(&email)
    .bind(&pw_hash)
    .bind(now_str())
    .bind(now_str())
    .execute(db.pool())
    .await
    .expect("insert test user");

    let uris = vec!["https://example.com/callback".to_string()];
    let (app, _) = db
        .create_application(CreateApplicationParams {
            name: "AuthzApp".to_string(),
            client_type: ClientType::Confidential,
            redirect_uris: uris,
            is_trusted: false,
            created_by: Some(user_id),
            logo_url: None,
            primary_color: None,
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        })
        .await
        .expect("create test application");
    (user_id, app)
}

#[tokio::test]
async fn get_consent_returns_none_when_absent() {
    let db = test_db().await;
    let (user_id, app) = authz_fixtures(&db).await;
    let consent = db.get_consent(user_id, app.id).await.unwrap();
    assert!(consent.is_none());
}

#[tokio::test]
async fn upsert_consent_creates_and_retrieves() {
    let db = test_db().await;
    let (user_id, app) = authz_fixtures(&db).await;
    let scopes = vec!["openid".to_string(), "profile".to_string()];
    db.upsert_consent(user_id, app.id, &scopes).await.unwrap();

    let consent = db.get_consent(user_id, app.id).await.unwrap().unwrap();
    let stored: Vec<String> = serde_json::from_str(&consent.scopes).unwrap();
    assert_eq!(stored, scopes);
}

#[tokio::test]
async fn upsert_consent_merges_scopes() {
    let db = test_db().await;
    let (user_id, app) = authz_fixtures(&db).await;

    db.upsert_consent(user_id, app.id, &["openid".into(), "profile".into()])
        .await
        .unwrap();
    db.upsert_consent(user_id, app.id, &["openid".into(), "email".into()])
        .await
        .unwrap();

    let consent = db.get_consent(user_id, app.id).await.unwrap().unwrap();
    let stored: Vec<String> = serde_json::from_str(&consent.scopes).unwrap();
    assert!(stored.contains(&"openid".to_string()));
    assert!(stored.contains(&"profile".to_string()));
    assert!(stored.contains(&"email".to_string()));
}

#[tokio::test]
async fn has_sufficient_consent_true_when_superset() {
    let db = test_db().await;
    let (user_id, app) = authz_fixtures(&db).await;
    db.upsert_consent(
        user_id,
        app.id,
        &["openid".into(), "profile".into(), "email".into()],
    )
    .await
    .unwrap();

    let ok = db
        .has_sufficient_consent(user_id, app.id, &["openid".into(), "profile".into()])
        .await
        .unwrap();
    assert!(ok);
}

#[tokio::test]
async fn has_sufficient_consent_false_when_missing_scope() {
    let db = test_db().await;
    let (user_id, app) = authz_fixtures(&db).await;
    db.upsert_consent(user_id, app.id, &["openid".into()])
        .await
        .unwrap();

    let ok = db
        .has_sufficient_consent(user_id, app.id, &["openid".into(), "email".into()])
        .await
        .unwrap();
    assert!(!ok);
}

#[tokio::test]
async fn has_sufficient_consent_false_when_no_consent() {
    let db = test_db().await;
    let (user_id, app) = authz_fixtures(&db).await;

    let ok = db
        .has_sufficient_consent(user_id, app.id, &["openid".into()])
        .await
        .unwrap();
    assert!(!ok);
}

#[tokio::test]
async fn create_authorization_code_and_lookup_by_hash() {
    let db = test_db().await;
    let (user_id, app) = authz_fixtures(&db).await;

    let raw = generate_authorization_code();
    let code_hash = hash_authorization_code(&raw);
    let scopes = vec!["openid".to_string(), "profile".to_string()];

    let code = db
        .create_authorization_code(
            app.id,
            user_id,
            &code_hash,
            "https://example.com/callback",
            &scopes,
            "test_challenge",
            "S256",
            None,
        )
        .await
        .unwrap();

    assert_eq!(code.application_id, app.id);
    assert_eq!(code.user_id, user_id);
    assert_eq!(code.redirect_uri, "https://example.com/callback");
    assert_eq!(code.code_challenge, "test_challenge");
    assert_eq!(code.code_challenge_method, "S256");
    assert!(code.nonce.is_none());
    assert!(code.used_at.is_none());

    let found = db
        .get_authorization_code_by_hash(&code_hash)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(found.id, code.id);
}

#[tokio::test]
async fn get_authorization_code_by_hash_returns_none() {
    let db = test_db().await;
    let fake_hash = TokenHash::new_unchecked("0".repeat(64));
    let result = db.get_authorization_code_by_hash(&fake_hash).await.unwrap();
    assert!(result.is_none());
}

#[tokio::test]
async fn mark_authorization_code_used_sets_used_at() {
    let db = test_db().await;
    let (user_id, app) = authz_fixtures(&db).await;

    let raw = generate_authorization_code();
    let code_hash = hash_authorization_code(&raw);
    let code = db
        .create_authorization_code(
            app.id,
            user_id,
            &code_hash,
            "https://example.com/callback",
            &["openid".into()],
            "challenge",
            "S256",
            None,
        )
        .await
        .unwrap();

    assert!(code.used_at.is_none());

    db.mark_authorization_code_used(code.id).await.unwrap();

    let updated = db
        .get_authorization_code_by_hash(&code_hash)
        .await
        .unwrap()
        .unwrap();
    assert!(updated.used_at.is_some());
}

#[tokio::test]
async fn mark_authorization_code_used_not_found() {
    let db = test_db().await;
    let err = db
        .mark_authorization_code_used(AuthorizationCodeId::new())
        .await
        .unwrap_err();
    assert!(matches!(err, AuthError::NotFound));
}

#[tokio::test]
async fn create_authorization_code_with_nonce() {
    let db = test_db().await;
    let (user_id, app) = authz_fixtures(&db).await;

    let raw = generate_authorization_code();
    let code_hash = hash_authorization_code(&raw);
    let code = db
        .create_authorization_code(
            app.id,
            user_id,
            &code_hash,
            "https://example.com/callback",
            &["openid".into()],
            "challenge",
            "S256",
            Some("test-nonce-value"),
        )
        .await
        .unwrap();

    assert_eq!(code.nonce.as_deref(), Some("test-nonce-value"));
}

// --- get_branding_by_client_id tests ---

#[tokio::test]
async fn get_branding_returns_config_for_active_app() {
    let db = test_db().await;
    let (app, _secret) = db
        .create_application(CreateApplicationParams {
            name: "Branded".into(),
            client_type: ClientType::Confidential,
            redirect_uris: vec!["https://example.com/cb".into()],
            is_trusted: false,
            created_by: None,
            logo_url: Some("https://example.com/logo.png".into()),
            primary_color: Some("#3B82F6".into()),
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        })
        .await
        .unwrap();
    let branding = db.get_branding_by_client_id(&app.client_id).await.unwrap();
    assert!(branding.is_some());
    let b = branding.unwrap();
    assert_eq!(b.application_name, "Branded");
    assert_eq!(b.logo_url.as_deref(), Some("https://example.com/logo.png"));
    assert_eq!(b.primary_color.as_deref(), Some("#3B82F6"));
}

#[tokio::test]
async fn get_branding_returns_none_for_inactive_app() {
    let db = test_db().await;
    let (app, _secret) = db
        .create_application(CreateApplicationParams {
            name: "Inactive".into(),
            client_type: ClientType::Confidential,
            redirect_uris: vec!["https://example.com/cb".into()],
            is_trusted: false,
            created_by: None,
            logo_url: None,
            primary_color: None,
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        })
        .await
        .unwrap();
    db.update_application(
        app.id,
        UpdateApplication {
            name: "Inactive".into(),
            redirect_uris: vec!["https://example.com/cb".into()],
            is_trusted: false,
            is_active: false,
            logo_url: None,
            primary_color: None,
            accent_hex: None,
            accent_ink: None,
            forced_mode: None,
            font_css_url: None,
            font_family: None,
            splash_text: None,
            splash_image_url: None,
            splash_primitive: None,
            splash_url: None,
            shader_cell_scale: None,
        },
    )
    .await
    .unwrap();
    let branding = db.get_branding_by_client_id(&app.client_id).await.unwrap();
    assert!(branding.is_none());
}

#[tokio::test]
async fn get_branding_returns_none_for_missing_app() {
    let db = test_db().await;
    let fake_id = ClientId::new_unchecked("ath_doesnotexistXXXXXXXXXXXXXX".into());
    let branding = db.get_branding_by_client_id(&fake_id).await.unwrap();
    assert!(branding.is_none());
}

#[tokio::test]
async fn create_and_fetch_application_with_branding() {
    let db = test_db().await;
    let (app, _secret) = db
        .create_application(CreateApplicationParams {
            name: "test".into(),
            client_type: ClientType::Confidential,
            redirect_uris: vec!["https://example.com/cb".into()],
            is_trusted: false,
            created_by: None,
            logo_url: None,
            primary_color: None,
            accent_hex: Some("#ff6b35".into()),
            accent_ink: Some(AccentInk::Black),
            forced_mode: Some(Mode::Dark),
            font_css_url: None,
            font_family: None,
            splash_text: Some("TESTCORP".into()),
            splash_image_url: None,
            splash_primitive: Some(SplashPrimitive::Wordmark),
            splash_url: None,
            shader_cell_scale: Some(22),
        })
        .await
        .unwrap();
    let branding = db
        .get_branding_by_client_id(&app.client_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(branding.accent_hex.as_deref(), Some("#ff6b35"));
    assert_eq!(branding.accent_ink, Some(AccentInk::Black));
    assert_eq!(branding.forced_mode, Some(Mode::Dark));
    assert_eq!(branding.splash_text.as_deref(), Some("TESTCORP"));
    assert_eq!(branding.splash_primitive, Some(SplashPrimitive::Wordmark));
    assert_eq!(branding.shader_cell_scale, Some(22));
}

// --- Custom data CRUD tests ---

#[tokio::test]
async fn custom_data_lifecycle() {
    let db = test_db().await;
    let email = Email::new("lifecycle@example.com".into()).expect("valid email");
    let user = db
        .create_user(email, "password", None, None)
        .await
        .expect("create_user");

    // Initially None
    let data = db.get_custom_data(&user.id).await.expect("get_custom_data");
    assert!(data.is_none());

    // Set
    let v1 = serde_json::json!({"tier": "free"});
    db.set_custom_data(&user.id, &v1)
        .await
        .expect("set_custom_data");
    let data = db.get_custom_data(&user.id).await.expect("get after set");
    assert_eq!(data, Some(serde_json::json!({"tier": "free"})));

    // Overwrite
    let v2 = serde_json::json!({"tier": "pro", "seats": 5});
    db.set_custom_data(&user.id, &v2).await.expect("overwrite");
    let data = db
        .get_custom_data(&user.id)
        .await
        .expect("get after overwrite");
    assert_eq!(data, Some(serde_json::json!({"tier": "pro", "seats": 5})));

    // Delete
    db.delete_custom_data(&user.id).await.expect("delete");
    let data = db
        .get_custom_data(&user.id)
        .await
        .expect("get after delete");
    assert!(data.is_none());
}

#[tokio::test]
async fn set_custom_data_nonexistent_user_returns_not_found() {
    let db = test_db().await;
    let fake_id = UserId::new();
    let data = serde_json::json!({"key": "value"});
    let result = db.set_custom_data(&fake_id, &data).await;
    assert!(
        matches!(result, Err(AuthError::NotFound)),
        "set_custom_data on nonexistent user must return NotFound"
    );
}

#[tokio::test]
async fn delete_custom_data_is_idempotent() {
    let db = test_db().await;
    let email = Email::new("idempotent@example.com".into()).expect("valid email");
    let user = db
        .create_user(email, "password", None, None)
        .await
        .expect("create_user");

    // Delete when already NULL -- both should succeed
    db.delete_custom_data(&user.id).await.expect("first delete");
    db.delete_custom_data(&user.id)
        .await
        .expect("second delete");
}

#[tokio::test]
async fn get_user_includes_custom_data() {
    let db = test_db().await;
    let email = Email::new("includes@example.com".into()).expect("valid email");
    let data = serde_json::json!({"org": "wavefunk"});

    let user = db
        .create_user(email, "password", None, Some(&data))
        .await
        .expect("create_user with data");

    let fetched = db.get_user(user.id).await.expect("get_user");
    assert_eq!(
        fetched.custom_data,
        Some(serde_json::json!({"org": "wavefunk"}))
    );
}
