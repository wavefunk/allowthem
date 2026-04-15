use sqlx::SqlitePool;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode};
use std::str::FromStr;
use std::time::Duration;

use crate::error::AuthError;

/// Handle to the allowthem database.
///
/// Wraps a `SqlitePool` and guarantees that migrations have been applied.
/// All query code receives a `&Db` and calls `db.pool()` to access the pool.
pub struct Db {
    pool: SqlitePool,
}

impl Db {
    /// Create a `Db` from an integrator-provided pool and run migrations.
    ///
    /// This is the embedded-mode constructor. The caller is responsible for
    /// configuring `PRAGMA foreign_keys = ON` on their pool's
    /// `SqliteConnectOptions` — this constructor cannot set per-connection
    /// pragmas on a pool it did not create.
    ///
    /// Migrations are idempotent: safe to call on a pool that has already
    /// been migrated. SQLx tracks applied migrations in `_sqlx_migrations`
    /// and `CREATE TABLE IF NOT EXISTS` in the SQL is a no-op on existing tables.
    ///
    /// `ignore_missing` is set so that migrations from the integrating application
    /// already recorded in `_sqlx_migrations` do not cause an error — those are
    /// the integrator's own migrations, not allowthem's.
    pub async fn new(pool: SqlitePool) -> Result<Self, AuthError> {
        sqlx::migrate!("./migrations")
            .set_ignore_missing(true)
            .run(&pool)
            .await
            .map_err(sqlx::Error::from)?;
        Ok(Self { pool })
    }

    /// Create a pool from a URL, apply pragmas, run migrations, and return a `Db`.
    ///
    /// Configures the pool with:
    /// - `PRAGMA foreign_keys = ON` — FK constraint enforcement
    /// - `PRAGMA journal_mode = WAL` — concurrent reads (silently ignored for `:memory:`)
    /// - `PRAGMA busy_timeout = 5000` — wait under contention instead of immediate SQLITE_BUSY
    pub async fn connect(url: &str) -> Result<Self, AuthError> {
        let opts = SqliteConnectOptions::from_str(url)?
            .pragma("foreign_keys", "ON")
            .journal_mode(SqliteJournalMode::Wal)
            .busy_timeout(Duration::from_millis(5000));
        let pool = SqlitePool::connect_with(opts).await?;
        Self::new(pool).await
    }

    /// Return a reference to the underlying connection pool.
    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}
