use crate::{
    api::state::{Node, State},
    db::{
        model::{EntityId, ProvideAuthn, UserEntity},
        Db
    }
};
// use bytes::buf::ext::BufExt;
use crate::http::handler::{ResponseEntity, ServerNode, ServerNodeV2};
// use hyper::{body::Buf, Body, Request};
use crate::api::state::{NodeAddress, NodeAddressV2, NodeV2};
use log::{error, info};
use ntex::web;
use serde::{Deserialize, Serialize};
use serde_repr::*;
use sqlx::{pool::PoolConnection, Sqlite};
use std::{collections::VecDeque, default::Default, ops::Sub, sync::Arc};

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
pub async fn update_available_server<T>(
    body: web::types::Json<NodeV2>, state: web::types::State<Arc<State<T>>>
) -> Result<ResponseEntity, errors::NtexResponseError>
where T: Db<Conn = PoolConnection<Sqlite>> {
    let body = body.into_inner();
    info!("received node: {:?}", body);
    let addr = body.addr;
    let now = chrono::Utc::now().timestamp();
    let mut servers = state.server.lock().await;
    let node = NodeV2 { addr: addr.clone(), count: body.count, total: body.total, last_update: now };
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

pub async fn get_available_server<T>(
    body: web::types::Json<QueryRequest>, state: web::types::State<Arc<State<T>>>
) -> Result<ResponseEntity, errors::NtexResponseError>
where T: Db<Conn = PoolConnection<Sqlite>> {
    let body = body.into_inner();
    info!("body {:?}", body);
    let mut db = state.db.conn().await?;
    db.get_user_by_token(body.user_id.as_ref()).await.map_err(|e| {
        info!("sql error: {:?}", e);
        errors::NtexResponseError::BadRequest("user id is invalidate".to_string())
    })?;
    let mut nodes = state.server.lock().await;
    let now = chrono::Utc::now().timestamp();
    let len = nodes.len();

    if len == 0 {
        return Err(errors::NtexResponseError::InternalServerError)
    }
    for _i in 0..len {
        let node = nodes.pop_front();
        if node.is_none() {
            drop(nodes);
            return Err(errors::NtexResponseError::InternalServerError)
        }
        let node = node.unwrap();
        if now.sub(node.last_update) < NODE_EXPIRE {
            let servers = ResponseEntity::Server(ServerNode {
                server: vec![NodeAddress {
                    host: node.addr.host.clone(),
                    ip: node.addr.ip.clone(),
                    port: node.addr.port,
                    country: String::new(),
                    city: String::new(),
                    passwd: node.addr.passwd.clone()
                }]
            });
            nodes.push_back(node);
            drop(nodes);
            return Ok(servers)
        }
    }
    drop(nodes);
    Err(errors::NtexResponseError::BadRequest("user id is invalidate".to_string()))
}

pub async fn get_available_servers<T>(
    body: web::types::Json<QueryRequest>, state: web::types::State<Arc<State<T>>>
) -> Result<ResponseEntity, errors::NtexResponseError>
where T: Db<Conn = PoolConnection<Sqlite>> {
    let body = body.into_inner();
    info!("body {:?}", body);
    let mut db = state.db.conn().await?;
    db.get_user_by_token(body.user_id.as_ref()).await.map_err(|e| {
        info!("sql error: {:?}", e);
        errors::NtexResponseError::BadRequest("user id is invalidate".to_string())
    })?;
    let mut nodes = state.server.lock().await;
    let now = chrono::Utc::now().timestamp();
    let len = nodes.len();

    if len == 0 {
        return Err(errors::NtexResponseError::InternalServerError)
    }
    let mut servers = vec![];
    let mut node_list = VecDeque::<NodeV2>::new();
    for _i in 0..len {
        let node = nodes.pop_front();
        if node.is_none() {
            continue
        }
        let node = node.unwrap();
        if now.sub(node.last_update) < NODE_EXPIRE {

            let server = NodeAddressV2 {
                host: node.addr.host.clone(),
                ip: node.addr.ip.clone(),
                port: node.addr.port,
                country: node.addr.country.clone(),
                city: node.addr.city.clone(),
                passwd: node.addr.passwd.clone()
            };
            servers.push(server);
            node_list.push_back(node);
        }
    }
    nodes.append(&mut node_list);
    /*

    servers.push(NodeAddressV2{
        host: "kamel.services".to_string(),
        ip: "45.32.77.193".to_string(),
        port: 443,
        passwd: "827d4818".to_string(),
        country: "美国".to_string(),
        city: "洛杉矶".to_string()
    });

    */
    info!("response: {:?}",servers);
    let ret = ResponseEntity::ServerV2(ServerNodeV2 { server: servers });
    Ok(ret)
}

pub async fn create_user<T>(
    body: web::types::Json<AdminUser>, state: web::types::State<Arc<State<T>>>
) -> Result<ResponseEntity, errors::NtexResponseError>
where T: Db<Conn = PoolConnection<Sqlite>> {
    let mut db = state.db.conn().await?;
    // Decode as JSON...
    let admin = body.into_inner();
    let creator = db.get_user_by_token(admin.admin.as_ref()).await.map_err(|e| {
        error!("get admin error: {:?}", e);
        errors::NtexResponseError::BadRequest("user id is invalidate".to_string())
    })?;
    let role = admin.user.role.clone() as i32;
    let token = admin.user.id;
    if creator.role <= role {
        return Err(errors::NtexResponseError::BadRequest("no permission".to_string()))
    }
    if token.len() > USER_TOKEN_MAX_LEN {
        return Err(errors::NtexResponseError::BadRequest("user id is invalidate".to_string()))
    }
    db.create_user(token.clone(), role as i32)
        .await
        .map_err(|_| errors::NtexResponseError::BadRequest("user id is occupied".to_string()))?;
    let new = ResponseEntity::User(User { token, role });
    Ok(new)
}
