use sqlx::migrate::{MigrateError, Migrator};
use sqlx::sqlite::SqlitePoolOptions;
use std::path::Path;

// [cfg(feature = "sqlite")]
pub async fn migrate(uri: &str, path: &str) -> Result<(), MigrateError> {
    let m = Migrator::new(Path::new(path)).await?;
    let pool = SqlitePoolOptions::new().connect(uri).await?;
    m.run(&pool).await
}
