use sqlx::SqlitePool;

pub struct ControlDb {
    pool: SqlitePool,
}

impl ControlDb {
    pub async fn new(pool: SqlitePool) -> Result<Self, sqlx::Error> {
        sqlx::migrate!("./migrations")
            .run(&pool)
            .await?;
        Ok(Self { pool })
    }

    pub fn pool(&self) -> &SqlitePool {
        &self.pool
    }
}
