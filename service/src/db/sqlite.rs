use crate::db::model::*;
use crate::db::Db;
use anyhow::Error;
use async_trait::async_trait;
use errors::{Result, ServiceError};
use sqlx::pool::PoolConnection;
use sqlx::SqlitePool;
use sqlx::{Pool, Sqlite};
use uuid::Uuid;

// impl TryFrom<&SqliteError> for ProvideErrorKind {
//     type Error = ();
//     fn try_from(db_err: &SqliteError) -> Result<Self, Self::Error> {
//         let provider_err = match db_err.code().unwrap() {
//             "2067" => ProvideErrorKind::UniqueViolation(db_err.message().to_owned()),
//             _ => return Err(()),
//         };
//
//         Ok(provider_err)
//     }
// }

pub async fn connect(db_url: &str) -> Result<Pool<Sqlite>> {
    let pool = SqlitePool::connect(db_url)
        .await
        .map_err(|e| Error::from(ServiceError::Provider(e)))?;
    Ok(pool)
}

#[async_trait]
impl Db for SqlitePool {
    type Conn = PoolConnection<Sqlite>;

    async fn conn(&self) -> Result<Self::Conn> {
        let conn = self
            .acquire()
            .await
            .map_err(|e| Error::from(ServiceError::Provider(e)))?;
        Ok(conn)
    }
}

#[async_trait]
impl ProvideAuthn for PoolConnection<Sqlite> {
    async fn create_user(&mut self, token: String, role: EntityId) -> Result<()> {
        let my_uuid = Uuid::new_v4().to_string();

        sqlx::query(
            r#"
INSERT INTO users (user_id,token,role )
VALUES ( $1, $2,$3 );
            "#,
        )
        .bind(my_uuid)
        .bind::<String>(token)
        .bind(role)
        .execute(self)
        .await?;
        // .last_insert_rowid();
        Ok(())
    }

    async fn get_user_by_id(&mut self, user_id: EntityId) -> Result<UserEntity> {
        let user = sqlx::query_as(
            r#"
SELECT user_id, token,role
FROM users
WHERE user_id = $1
        "#,
        )
        .bind(user_id)
        .fetch_one(self)
        .await?;
        Ok(user)
    }

    async fn get_user_by_token(&mut self, token: &str) -> Result<UserEntity> {
        let user = sqlx::query_as(
            r#"
SELECT user_id, token,role
FROM users
WHERE token = $1
        "#,
        )
        .bind(token)
        .fetch_one(self)
        .await?;
        Ok(user)
    }

    async fn update_user(&mut self, updated: &UserEntity) -> Result<()> {
        sqlx::query(
            r#"
UPDATE users
SET token = $2,role = $3, updated_at = (STRFTIME('%s', 'now'))
WHERE user_id = $1
            "#,
        )
        .bind(&updated.user_id)
        .bind(&updated.token)
        .bind(updated.role)
        .execute(self)
        .await?;

        Ok(())
    }
}
