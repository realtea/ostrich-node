use async_trait::async_trait;
use errors::Result;
use sqlx::any::Any;
use sqlx::migrate::MigrateDatabase;

/// Database implementation for PostgreSQL
#[cfg(feature = "postgres")]
pub mod pg;

/// Database implementation for SQLite
///
/// The implementation of the handler functions is a bit more complex than Postgres
/// as sqlite (1) does not support nested transactions and (2) does not support the RETURNING
/// clause.
#[cfg(feature = "sqlite")]
pub mod sqlite;

/// Database models
pub mod model;

pub mod migration;
/// A type that abstracts a database
#[async_trait]
pub trait Db {
    /// A connection to the database
    type Conn;

    /// Establish a connection with the database
    async fn conn(&self) -> Result<Self::Conn>;
}

pub async fn create_db(uri: &str) -> anyhow::Result<()> {
    if !Any::database_exists(uri).await? {
        Any::create_database(uri).await?;
    }

    Ok(())
}
