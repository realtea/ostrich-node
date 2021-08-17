use std::convert::TryFrom;

use async_trait::async_trait;
use sqlx::{error::DatabaseError, pool::PoolConnection, postgres::PgError, PgConnection, PgPool};

use crate::{
    db::{model::*, Db},
    error::{ProvideErrorKind, ProvideResult}
};

pub async fn connect(db_url: &str) -> sqlx::Result<PgPool> {
    let pool = PgPool::new(db_url).await?;
    Ok(pool)
}

impl TryFrom<&PgError> for ProvideErrorKind {
    type Error = ();

    fn try_from(pg_err: &PgError) -> Result<Self, Self::Error> {
        let provider_err = match pg_err.code().unwrap() {
            "23505" => ProvideErrorKind::UniqueViolation(pg_err.details().unwrap().to_owned()),
            code if code.starts_with("23") => ProvideErrorKind::ModelViolation(pg_err.message().to_owned()),
            _ => return Err(())
        };

        Ok(provider_err)
    }
}

#[async_trait]
impl Db for PgPool {
    type Conn = PoolConnection<PgConnection>;

    async fn conn(&self) -> sqlx::Result<Self::Conn> {
        self.acquire().await
    }
}

#[async_trait]
impl ProvideAuthn for PgConnection {
    async fn create_user(&mut self, token: &str, role: EntityId) -> ProvideResult<EntityId> {
        let user_id = sqlx::query!(
            r#"
INSERT INTO users ( token,role )
VALUES ( $1, $2 )
RETURNING user_id
        "#,
            token,
            role
        )
        .fetch_one(self)
        .await
        .map(|rec| rec.user_id)?;

        Ok(user_id)
    }

    async fn get_user_by_id(&mut self, user_id: i32) -> ProvideResult<UserEntity> {
        let rec = sqlx::query_as!(
            UserEntity,
            r#"
SELECT user_id, token, role
FROM users
WHERE user_id = $1
        "#,
            user_id
        )
        .fetch_one(self)
        .await?;

        Ok(rec)
    }

    async fn get_user_by_token(&mut self, token: &str) -> ProvideResult<UserEntity> {
        let rec = sqlx::query_as!(
            UserEntity,
            r#"
SELECT user_id, token, role
FROM users
WHERE token = $1
        "#,
            token
        )
        .fetch_one(self)
        .await?;

        Ok(rec)
    }

    //     async fn get_user_by_email(&mut self, email: &str) -> ProvideResult<UserEntity> {
    //         let rec = sqlx::query_as!(
    //             UserEntity,
    //             r#"
    // SELECT user_id, username, email, password, image, bio
    // FROM users
    // WHERE email = $1
    //             "#,
    //             email
    //         )
    //         .fetch_one(self)
    //         .await?;
    //
    //         Ok(rec)
    //     }

    async fn update_user(&mut self, updated: &UserEntity) -> ProvideResult<()> {
        sqlx::query!(
            r#"
UPDATE users
SET token = $1, role = $2,updated_at = DEFAULT
WHERE user_id = $3
RETURNING user_id
            "#,
            updated.token,
            updated.role,
            updated.user_id,
        )
        .fetch_one(self)
        .await?;

        Ok(())
    }
}
