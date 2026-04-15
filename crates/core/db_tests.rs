use sqlx::SqlitePool;
use sqlx::sqlite::SqliteConnectOptions;
use std::str::FromStr;

use crate::types::{
    Email, PasswordHash, Permission, PermissionId, PermissionName, Role, RoleId, RoleName,
    RolePermission, Session, SessionId, TokenHash, User, UserId, UserPermission, UserRole,
    Username,
};

async fn test_pool() -> SqlitePool {
    let opts = SqliteConnectOptions::from_str("sqlite::memory:")
        .expect("valid connection string")
        .pragma("foreign_keys", "ON");
    let pool = SqlitePool::connect_with(opts)
        .await
        .expect("in-memory pool creation");
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .expect("migrations");
    pool
}

fn now_str() -> String {
    chrono::Utc::now()
        .format("%Y-%m-%dT%H:%M:%S%.3fZ")
        .to_string()
}

#[tokio::test]
async fn test_user_round_trip() {
    let pool = test_pool().await;

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
    .execute(&pool)
    .await
    .expect("insert user");

    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, username, password_hash, email_verified, is_active, created_at, updated_at
         FROM allowthem_users WHERE id = ?",
    )
    .bind(user_id)
    .fetch_one(&pool)
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
    .execute(&pool)
    .await
    .expect("insert user with null password");

    let user2 = sqlx::query_as::<_, User>(
        "SELECT id, email, username, password_hash, email_verified, is_active, created_at, updated_at
         FROM allowthem_users WHERE id = ?",
    )
    .bind(user_id2)
    .fetch_one(&pool)
    .await
    .expect("fetch user2");

    assert!(user2.password_hash.is_none());
    assert!(user2.username.is_none());
    assert!(!user2.email_verified);
}

#[tokio::test]
async fn test_session_round_trip() {
    let pool = test_pool().await;

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
    .execute(&pool)
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
    .execute(&pool)
    .await
    .expect("insert session");

    let session = sqlx::query_as::<_, Session>(
        "SELECT id, token_hash, user_id, ip_address, user_agent, expires_at, created_at
         FROM allowthem_sessions WHERE id = ?",
    )
    .bind(session_id)
    .fetch_one(&pool)
    .await
    .expect("fetch session");

    assert_eq!(session.id, session_id);
    assert_eq!(session.user_id, user_id);
    assert_eq!(session.ip_address.as_deref(), Some("127.0.0.1"));
    assert_eq!(session.user_agent.as_deref(), Some("Mozilla/5.0"));
}

#[tokio::test]
async fn test_role_round_trip() {
    let pool = test_pool().await;

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
    .execute(&pool)
    .await
    .expect("insert role");

    let role = sqlx::query_as::<_, Role>(
        "SELECT id, name, description, created_at FROM allowthem_roles WHERE id = ?",
    )
    .bind(role_id)
    .fetch_one(&pool)
    .await
    .expect("fetch role");

    assert_eq!(role.id, role_id);
    assert_eq!(role.name, role_name);
    assert_eq!(role.description.as_deref(), Some("Administrator role"));
}

#[tokio::test]
async fn test_user_role_round_trip() {
    let pool = test_pool().await;

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
    .execute(&pool)
    .await
    .expect("insert user");

    sqlx::query(
        "INSERT INTO allowthem_roles (id, name, description, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(role_id)
    .bind(RoleName::new_unchecked("editor".to_string()))
    .bind(None::<String>)
    .bind(now_str())
    .execute(&pool)
    .await
    .expect("insert role");

    sqlx::query("INSERT INTO allowthem_user_roles (user_id, role_id, created_at) VALUES (?, ?, ?)")
        .bind(user_id)
        .bind(role_id)
        .bind(now_str())
        .execute(&pool)
        .await
        .expect("insert user_role");

    let user_role = sqlx::query_as::<_, UserRole>(
        "SELECT user_id, role_id, created_at FROM allowthem_user_roles WHERE user_id = ? AND role_id = ?",
    )
    .bind(user_id)
    .bind(role_id)
    .fetch_one(&pool)
    .await
    .expect("fetch user_role");

    assert_eq!(user_role.user_id, user_id);
    assert_eq!(user_role.role_id, role_id);
}

#[tokio::test]
async fn test_permission_round_trip() {
    let pool = test_pool().await;

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
    .execute(&pool)
    .await
    .expect("insert permission");

    let perm = sqlx::query_as::<_, Permission>(
        "SELECT id, name, description, created_at FROM allowthem_permissions WHERE id = ?",
    )
    .bind(perm_id)
    .fetch_one(&pool)
    .await
    .expect("fetch permission");

    assert_eq!(perm.id, perm_id);
    assert_eq!(perm.name, perm_name);
    assert_eq!(perm.description.as_deref(), Some("Write access to posts"));
}

#[tokio::test]
async fn test_role_permission_round_trip() {
    let pool = test_pool().await;

    let role_id = RoleId::new();
    let perm_id = PermissionId::new();

    sqlx::query(
        "INSERT INTO allowthem_roles (id, name, description, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(role_id)
    .bind(RoleName::new_unchecked("viewer".to_string()))
    .bind(None::<String>)
    .bind(now_str())
    .execute(&pool)
    .await
    .expect("insert role");

    sqlx::query(
        "INSERT INTO allowthem_permissions (id, name, description, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(perm_id)
    .bind(PermissionName::new_unchecked("posts:read".to_string()))
    .bind(None::<String>)
    .bind(now_str())
    .execute(&pool)
    .await
    .expect("insert permission");

    sqlx::query("INSERT INTO allowthem_role_permissions (role_id, permission_id) VALUES (?, ?)")
        .bind(role_id)
        .bind(perm_id)
        .execute(&pool)
        .await
        .expect("insert role_permission");

    let rp = sqlx::query_as::<_, RolePermission>(
        "SELECT role_id, permission_id FROM allowthem_role_permissions WHERE role_id = ? AND permission_id = ?",
    )
    .bind(role_id)
    .bind(perm_id)
    .fetch_one(&pool)
    .await
    .expect("fetch role_permission");

    assert_eq!(rp.role_id, role_id);
    assert_eq!(rp.permission_id, perm_id);
}

#[tokio::test]
async fn test_user_permission_round_trip() {
    let pool = test_pool().await;

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
    .execute(&pool)
    .await
    .expect("insert user");

    sqlx::query(
        "INSERT INTO allowthem_permissions (id, name, description, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(perm_id)
    .bind(PermissionName::new_unchecked("admin:read".to_string()))
    .bind(None::<String>)
    .bind(now_str())
    .execute(&pool)
    .await
    .expect("insert permission");

    sqlx::query("INSERT INTO allowthem_user_permissions (user_id, permission_id) VALUES (?, ?)")
        .bind(user_id)
        .bind(perm_id)
        .execute(&pool)
        .await
        .expect("insert user_permission");

    let up = sqlx::query_as::<_, UserPermission>(
        "SELECT user_id, permission_id FROM allowthem_user_permissions WHERE user_id = ? AND permission_id = ?",
    )
    .bind(user_id)
    .bind(perm_id)
    .fetch_one(&pool)
    .await
    .expect("fetch user_permission");

    assert_eq!(up.user_id, user_id);
    assert_eq!(up.permission_id, perm_id);
}

// --- Constraint tests ---

#[tokio::test]
async fn test_unique_email_constraint() {
    let pool = test_pool().await;
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
    .execute(&pool)
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
    .execute(&pool)
    .await;

    assert!(result.is_err(), "duplicate email must be rejected");
}

#[tokio::test]
async fn test_unique_username_constraint() {
    let pool = test_pool().await;

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
    .execute(&pool)
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
    .execute(&pool)
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
    .execute(&pool)
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
    .execute(&pool)
    .await
    .expect("null username insert 2 succeeds — NULLs are distinct in SQLite");
}

#[tokio::test]
async fn test_foreign_key_enforcement() {
    let pool = test_pool().await;

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
    .execute(&pool)
    .await;

    assert!(
        result.is_err(),
        "FK violation must be rejected (PRAGMA foreign_keys = ON)"
    );
}

#[tokio::test]
async fn test_composite_primary_key() {
    let pool = test_pool().await;

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
    .execute(&pool)
    .await
    .expect("insert user");

    sqlx::query(
        "INSERT INTO allowthem_roles (id, name, description, created_at) VALUES (?, ?, ?, ?)",
    )
    .bind(role_id)
    .bind(RoleName::new_unchecked("superuser".to_string()))
    .bind(None::<String>)
    .bind(now_str())
    .execute(&pool)
    .await
    .expect("insert role");

    sqlx::query("INSERT INTO allowthem_user_roles (user_id, role_id, created_at) VALUES (?, ?, ?)")
        .bind(user_id)
        .bind(role_id)
        .bind(now_str())
        .execute(&pool)
        .await
        .expect("first insert succeeds");

    let result = sqlx::query(
        "INSERT INTO allowthem_user_roles (user_id, role_id, created_at) VALUES (?, ?, ?)",
    )
    .bind(user_id)
    .bind(role_id)
    .bind(now_str())
    .execute(&pool)
    .await;

    assert!(result.is_err(), "duplicate composite PK must be rejected");
}

#[tokio::test]
async fn test_cascade_delete_user() {
    let pool = test_pool().await;

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
    .execute(&pool)
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
    .execute(&pool)
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
    .execute(&pool)
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
    .execute(&pool)
    .await
    .expect("insert session");

    // Insert user_role
    sqlx::query("INSERT INTO allowthem_user_roles (user_id, role_id, created_at) VALUES (?, ?, ?)")
        .bind(user_id)
        .bind(role_id)
        .bind(now_str())
        .execute(&pool)
        .await
        .expect("insert user_role");

    // Insert user_permission
    sqlx::query("INSERT INTO allowthem_user_permissions (user_id, permission_id) VALUES (?, ?)")
        .bind(user_id)
        .bind(perm_id)
        .execute(&pool)
        .await
        .expect("insert user_permission");

    // Delete the user — all dependent rows should cascade
    sqlx::query("DELETE FROM allowthem_users WHERE id = ?")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("delete user");

    // Verify session is gone
    let session_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM allowthem_sessions WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(&pool)
            .await
            .expect("count sessions");
    assert_eq!(session_count, 0, "sessions must cascade-delete with user");

    // Verify user_role is gone
    let user_role_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM allowthem_user_roles WHERE user_id = ?")
            .bind(user_id)
            .fetch_one(&pool)
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
            .fetch_one(&pool)
            .await
            .expect("count user_permissions");
    assert_eq!(
        user_perm_count, 0,
        "user_permissions must cascade-delete with user"
    );
}
