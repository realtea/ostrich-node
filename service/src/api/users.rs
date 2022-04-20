use crate::{
    api::state::{Node, State},
    db::{
        model::{EntityId, ProvideAuthn, UserEntity},
        Db
    }
};
// use bytes::buf::ext::BufExt;
use crate::http::handler::{ResponseEntity, ServerAddr, ServerNode};
use errors::{Error, Result, ServiceError};
// use hyper::{body::Buf, Body, Request};
use log::{error, info};
use serde::{Deserialize, Serialize};
use serde_repr::*;
use sqlx::{pool::PoolConnection, Sqlite};
use std::{default::Default, ops::Sub, sync::Arc};
use ntex::web;

pub const USER_TOKEN_MAX_LEN: usize = 1024;
pub const NODE_EXPIRE: i64 = 207; // 3`30``

#[derive(Default, Serialize, Deserialize)]
pub struct User {
    pub token: String,
    pub role: EntityId
}

#[derive(Serialize_repr, Deserialize_repr, Debug)]
#[repr(u8)]
enum Platform {
    Android = 0,
    IOS,
    Win,
    Linux,
    OSX
}

#[derive(Serialize)]
struct QueryResponse {
    user: User
}
#[derive(Serialize_repr, Deserialize_repr)]
#[repr(u8)]
enum Role {
    User,
    Manager,
    SuperVisor
}
#[derive(Deserialize, Debug)]
pub struct QueryRequest {
    user_id: String // platform: Platform
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdminUser {
    admin: String,
    user: NewUser
}
#[derive(Deserialize)]
struct NewUser {
    id: String,
    role: i32
}
impl From<User> for QueryResponse {
    fn from(user: User) -> Self {
        QueryResponse { user }
    }
}

impl From<UserEntity> for User {
    fn from(entity: UserEntity) -> Self {
        let UserEntity { token, role, .. } = entity;

        User { token, role }
    }
}
pub async fn update_available_server<T>(body: web::types::Json<Node>,state: web::types::State<Arc<State<T>>>) -> Result<ResponseEntity>
where T: Db<Conn = PoolConnection<Sqlite>> {
    let body =body.into_inner();

    info!("received node: {:?}", body);
    let addr = body.addr;
    let now = chrono::Utc::now().timestamp();
    let mut servers = state.server.lock().await;
    let node = Node { addr: addr.clone(), count: body.count, total: body.total, last_update: now };
    info!("now: {:?},node:{:?}", now, node.clone());
    if !servers.contains(&node) {
        servers.push_back(node);
        drop(servers);
        return Ok(ResponseEntity::Status)
    }
    for n in servers.iter_mut() {
        if n.addr.host == addr.host {
            n.last_update = now;
            drop(servers);
            break
        }
    }
    Ok(ResponseEntity::Status)
}

pub async fn get_available_server<T>(body: web::types::Json<QueryRequest>,state: web::types::State<Arc<State<T>>>) -> Result<ResponseEntity>
where T: Db<Conn = PoolConnection<Sqlite>> {
    let body =     body.into_inner();
    info!("body {:?}", body);
    let mut db = state.db.conn().await?;
    let mut nodes = state.server.lock().await;
    let now = chrono::Utc::now().timestamp();
    let len = nodes.len();

    if len == 0 {
        return Err(Error::from(ServiceError::InvalidParams))
    }
    for _i in 0..len {
        let node = nodes.pop_front();
        if node.is_none() {
            drop(nodes);
            return Err(Error::from(ServiceError::InvalidParams))
        }
        let node = node.unwrap();
        if now.sub(node.last_update) < NODE_EXPIRE {
            db.get_user_by_token(body.user_id.as_ref()).await.map_err(|e| {
                info!("sql error: {:?}", e);
                ServiceError::IllegalToken
            })?;

            let servers = ResponseEntity::Server(ServerNode {
                server: vec![ServerAddr {
                    host: node.addr.host.clone(),
                    ip: node.addr.ip.clone(),
                    port: node.addr.port,
                    country: None,
                    city: None,
                    passwd: Some(node.addr.passwd.clone())
                }]
            });
            nodes.push_back(node);
            drop(nodes);
            return Ok(servers)
        }
    }
    drop(nodes);
    Err(Error::from(ServiceError::InvalidParams))
}

/*pub async fn get_available_servers<T>(state: web::types::State<Arc<State<T>>>) -> Result<ResponseEntity>
where T: Db<Conn = PoolConnection<Sqlite>> {
    let body: QueryRequest = req.body_json().await.map_err(|_| ServiceError::InvalidParams)?;
    // Change the JSON...
    info!("body {:?}", body);
    let mut db = state.db.conn().await?;
    let mut nodes = state.server.lock().await;
    let now = chrono::Utc::now().timestamp();
    let len = nodes.len();

    if len == 0 {
        return Err(Error::from(ServiceError::InvalidParams))
    }
    // let mut delete = Vec::new();
    for _i in 0..len {
        let node = nodes.pop_front();
        if node.is_none() {
            drop(nodes);
            return Err(Error::from(ServiceError::InvalidParams))
        }
        let node = node.unwrap();
        if now.sub(node.last_update) < NODE_EXPIRE {
            db.get_user_by_token(body.user_id.as_ref()).await.map_err(|e| {
                info!("sql error: {:?}", e);
                ServiceError::IllegalToken
            })?;

            let servers = ResponseEntity::Server(ServerNode {
                server: vec![
                    ServerAddr {
                        host: "".to_string(),
                        ip: node.addr.ip.clone(),
                        port: node.addr.port,
                        country: Some("United States".to_string()),
                        city: Some("Texas City".to_string()),
                        passwd: Some("251f6edc".to_string())
                    },
                    ServerAddr {
                        host: "".to_string(),
                        ip: "walkonbits.live".to_string(),
                        port: 90,
                        country: Some("Japan".to_string()),
                        city: Some("Tokyo".to_string()),
                        passwd: Some("251f6edc".to_string())
                    },
                ]
            });
            nodes.push_back(node);
            drop(nodes);
            return Ok(servers)
        }
    }
    drop(nodes);
    Err(Error::from(ServiceError::InvalidParams))
}*/

pub async fn create_user<T>(    body: web::types::Json<AdminUser>, state: web::types::State<Arc<State<T>>>) -> Result<ResponseEntity>
where T: Db<Conn = PoolConnection<Sqlite>> {
    let mut db = state.db.conn().await?;

    // Decode as JSON...
    let admin =             body.into_inner();

    let creator = db.get_user_by_token(admin.admin.as_ref()).await.map_err(|e| {
        error!("get admin error: {:?}", e);
        ServiceError::InvalidToken
    })?;

    let role = admin.user.role.clone() as i32;
    let token = admin.user.id;

    if creator.role <= role {
        return Err(Error::from(ServiceError::NoPermission))
    }
    if token.len() > USER_TOKEN_MAX_LEN {
        return Err(Error::from(ServiceError::IllegalToken))
    }

    db.create_user(token.clone(), role as i32).await.map_err(|_| ServiceError::TokenOccupied)?;

    let new = ResponseEntity::User(User { token, role });

    Ok(new)
}
