use async_trait::async_trait;
use errors::Result;

// #[derive(sqlx::FromRow)]
pub type EntityId = i32;

#[derive(sqlx::FromRow)]
pub struct UserEntity {
    pub user_id: String,
    pub token: String,
    pub role: EntityId
}

#[async_trait]
pub trait ProvideAuthn {
    async fn create_user(&mut self, token: String, role: EntityId) -> Result<()>;
    async fn get_user_by_id(&mut self, user_id: EntityId) -> Result<UserEntity>;
    async fn get_user_by_token(&mut self, token: &str) -> Result<UserEntity>;
    // async fn get_user_by_email(&mut self, email: &str) -> Result<UserEntity>;
    async fn update_user(&mut self, updated: &UserEntity) -> Result<()>;
}
