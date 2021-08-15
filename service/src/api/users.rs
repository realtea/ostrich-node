use crate::api::state::{Node, State};
use crate::db::model::{EntityId, ProvideAuthn, UserEntity};
use crate::db::Db;
// use bytes::buf::ext::BufExt;
use hyper::{Body, Request};
use log::info;
use serde::{Deserialize, Serialize};
use serde_repr::*;
use sqlx::pool::PoolConnection;
use sqlx::Sqlite;
use std::default::Default;
use std::ops::Sub;
use std::sync::Arc;
use hyper::body::Buf;
use crate::http::handler::{ResponseEntity, ServerAddr, ServerNode};
use errors::{Error, Result, ServiceError};

pub const USER_TOKEN_MAX_LEN: usize = 1024;
pub const NODE_EXPIRE: i64 = 210; // 3`30``

#[derive(Default, Serialize, Deserialize)]
pub struct User {
    pub token: String,
    pub role: EntityId,
}

// impl User {
//     fn token(mut self, token: String) -> Self {
//         self.token = token;
//         self
//     }
// }

#[derive(Serialize_repr, Deserialize_repr, Debug)]
#[repr(u8)]
enum Platform {
    Android = 0,
    IOS,
    Win,
    Linux,
    OSX,
}

/*enum Nullable<T> {
    Data(T),
    Null,
    Missing,
}

impl<T> Nullable<T> {

    fn or(self, optb: Option<T>) -> Option<T> {
        match self {
            Nullable::Data(d) => Some(d),
            Nullable::Null => None,
            Nullable::Missing => optb,
        }
    }
}

impl<T> From<Option<T>> for Nullable<T> {
    fn from(opt: Option<T>) -> Self {
        if let Some(data) = opt {
            Nullable::Data(data)
        } else {
            Nullable::Null
        }
    }
}

impl<'de, T> Deserialize<'de> for Nullable<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self>
    where
        D: Deserializer<'de>,
    {
        Option::deserialize(deserializer).map(Nullable::from)
    }
}

impl<T> Default for Nullable<T> {
    fn default() -> Self {
        Nullable::Missing
    }
}
*/

#[derive(Serialize)]
struct UserResponseBody {
    user: User,
}

impl From<User> for UserResponseBody {
    fn from(user: User) -> Self {
        UserResponseBody { user }
    }
}

impl From<UserEntity> for User {
    fn from(entity: UserEntity) -> Self {
        let UserEntity { token, role, .. } = entity;

        User { token, role }
    }
}
pub async fn update_available_server<T>(
    req: Request<Body>,
    state: Arc<State<T>>,
) -> Result<ResponseEntity>
where
    T: Db<Conn = PoolConnection<Sqlite>>,
{
    let body = hyper::body::aggregate(req).await.map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;//TODO
    // Decode as JSON...
    let body: Node =
        serde_json::from_reader(body.reader()).map_err(|_| ServiceError::InvalidParams)?;
    info!("received node: {:?}", body);
    let addr = body.addr;
    let now = chrono::Utc::now().timestamp();
    let mut servers = state.server.lock().await;
    let node = Node {
        addr: addr.clone(),
        count: body.count,
        total: body.total,
        last_update: now,
    };
    info!("now: {:?},node:{:?}", now, node.clone());
    if !servers.contains(&node) {
        servers.push_back(node);
        drop(servers);
        return Ok(ResponseEntity::Status);
    }
    for n in servers.iter_mut() {
        if n.addr.ip == addr.ip {
            n.last_update = now;
            drop(servers);
            break;
        }
    }
    // servers.iter_mut().filter(|n| n.addr.ip == addr.ip).update(| n|n.last_update = now);
    // info!("after update: {:?}", servers);
    Ok(ResponseEntity::Status)
}

pub async fn get_available_server<T>(
    req: Request<Body>,
    state: Arc<State<T>>,
) -> Result<ResponseEntity>
where
    T: Db<Conn = PoolConnection<Sqlite>>,
{
    let mut db = state.db.conn().await?;
    #[derive(Serialize_repr, Deserialize_repr)]
    #[repr(u8)]
    enum Role {
        User,
        Manager,
        SuperVisor,
    }
    #[derive(Deserialize, Debug)]
    struct RequestBody {
        user_id: String,
        platform: Platform,
    }
    let mut nodes = state.server.lock().await;
    let now = chrono::Utc::now().timestamp();
    let len = nodes.len();

    if len == 0 {
        return Err(Error::from(ServiceError::InvalidParams));
    }
    // let mut delete = Vec::new();
    for _i in 0..len {
        let node = nodes.pop_front();
        if node.is_none() {
            drop(nodes);
            return Err(Error::from(ServiceError::InvalidParams));
        }
        let node = node.unwrap();
        if now.sub(node.last_update) < NODE_EXPIRE {
            // Aggregate the body...
            let whole_body = hyper::body::aggregate(req).await.map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;//TODO
            // Decode as JSON...
            let body: RequestBody = serde_json::from_reader(whole_body.reader())
                .map_err(|_| ServiceError::InvalidParams)?;
            // Change the JSON...
            info!("body {:?}", body);

            // let body: RequestBody = serde_json::from_slice(j)?;
            db.get_user_by_token(body.user_id.as_ref())
                .await
                .map_err(|e| {
                    info!("sql error: {:?}", e);
                    ServiceError::IllegalToken
                })?;

            let servers = ResponseEntity::Server(ServerNode {
                server: vec![ServerAddr {
                    ip: node.addr.ip.clone(),
                    port: node.addr.port,
                }],
            });
            nodes.push_back(node);
            drop(nodes);
            return Ok(servers);
        }
    }
    drop(nodes);
    Err(Error::from(ServiceError::InvalidParams))
}

pub async fn create_user<T>(req: Request<Body>, state: Arc<State<T>>) -> Result<ResponseEntity>
where
    T: Db<Conn = PoolConnection<Sqlite>>,
{
    let mut db = state.db.conn().await?;

    #[derive(Deserialize)]
    struct NewUser {
        id: String,
        role: i32,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RequestBody {
        admin: String,
        user: NewUser,
    }
    // Aggregate the body...
    let whole_body = hyper::body::aggregate(req).await.map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;//TODO
    // Decode as JSON...
    let body: RequestBody =
        serde_json::from_reader(whole_body.reader()).map_err(|_| ServiceError::InvalidParams)?;

    let creator = db
        .get_user_by_token(body.admin.as_ref())
        .await
        .map_err(|e| {
            println!("get admin error: {:?}", e);
            ServiceError::InvalidToken
        })?;

    let role = body.user.role.clone() as i32;
    let token = body.user.id;

    if creator.role <= role {
        return Err(Error::from(ServiceError::NoPermission));
    }

    // if let Ok(_) = db.get_user_by_token(token.as_ref()).await{
    //     return Err(NetworkError::from(NetworkErrorKind::ProtobufParseError))//already exists
    // }
    if token.len() > USER_TOKEN_MAX_LEN {
        return Err(Error::from(ServiceError::IllegalToken));
    }

    db.create_user(token.clone(), role as i32)
        .await
        .map_err(|_| ServiceError::TokenOccupied)?;

    let new = ResponseEntity::User(User { token, role });

    Ok(new)
}
