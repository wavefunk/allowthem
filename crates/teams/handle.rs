use std::sync::Arc;

use allowthem_core::Db;
use allowthem_core::error::AuthError;
use sqlx::SqlitePool;

use crate::db::TeamsDb;

struct TeamsInner {
    teams_db: TeamsDb,
    core_db: Db,
}

#[derive(Clone)]
pub struct Teams {
    inner: Arc<TeamsInner>,
}

impl Teams {
    pub fn builder() -> TeamsBuilder {
        TeamsBuilder { pool: None }
    }

    pub fn teams_db(&self) -> &TeamsDb {
        &self.inner.teams_db
    }

    pub fn core_db(&self) -> &Db {
        &self.inner.core_db
    }
}

pub struct TeamsBuilder {
    pool: Option<SqlitePool>,
}

impl TeamsBuilder {
    pub fn with_pool(mut self, pool: SqlitePool) -> Self {
        self.pool = Some(pool);
        self
    }

    pub async fn build(self) -> Result<Teams, AuthError> {
        let pool = self
            .pool
            .ok_or_else(|| AuthError::Validation("pool is required".into()))?;
        // Core migrations first — teams tables reference core tables via FK
        let core_db = Db::new(pool.clone()).await?;
        let teams_db = TeamsDb::new(pool).await?;
        Ok(Teams {
            inner: Arc::new(TeamsInner { teams_db, core_db }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::tests::test_pool;

    #[tokio::test]
    async fn build_teams_handle() {
        let pool = test_pool().await;
        Db::new(pool.clone()).await.unwrap();
        let teams = Teams::builder().with_pool(pool).build().await;
        assert!(teams.is_ok());
    }

    #[tokio::test]
    async fn build_without_pool_fails() {
        let result = Teams::builder().build().await;
        assert!(result.is_err());
    }
}
