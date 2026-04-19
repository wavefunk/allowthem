use allowthem_core::error::AuthError;
use sqlx::SqlitePool;

pub struct TeamsDb {
    pool: SqlitePool,
}

impl TeamsDb {
    pub async fn new(pool: SqlitePool) -> Result<Self, AuthError> {
        sqlx::migrate!("./migrations")
            .set_ignore_missing(true)
            .run(&pool)
            .await
            .map_err(sqlx::Error::from)?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::str::FromStr;

    pub async fn test_pool() -> SqlitePool {
        let opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite::memory:")
            .unwrap()
            .pragma("foreign_keys", "ON");
        SqlitePool::connect_with(opts).await.unwrap()
    }

    #[tokio::test]
    async fn teams_db_runs_migrations() {
        let pool = test_pool().await;
        allowthem_core::Db::new(pool.clone()).await.unwrap();
        let db = TeamsDb::new(pool).await;
        assert!(db.is_ok());
    }
}
