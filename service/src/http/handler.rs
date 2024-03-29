use crate::api::{
    state::{Node, NodeAddress, NodeAddressV2, State},
    users::{
        create_user, get_available_server, get_available_servers, update_available_server, CreateUserRequest, QueryRequest,
        User
    }
};
use log::warn;
use ntex::{web, web::HttpResponse};
use serde::{Deserialize, Serialize};
use serde_repr::*;
use serde_with::skip_serializing_none;
use sqlx::{Pool, Sqlite};
use std::sync::Arc;
use crate::api::state::NodeV2;


#[derive(Serialize, Deserialize)]
pub struct ServerNode {
    pub(crate) server: Vec<NodeAddress>
}
#[derive(Serialize, Deserialize)]
pub struct ServerNodeV2 {
    pub(crate) server: Vec<NodeAddressV2>
}

#[derive(Serialize_repr, Deserialize_repr, Clone)]
#[repr(u8)]
pub enum Role {
    User,
    Manager,
    SuperVisor
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseEntity {
    User(User),
    Server(ServerNode),
    ServerV2(ServerNodeV2),
    Status
}
#[derive(Serialize, Deserialize)]
pub struct ResponseBody<T>
where T: Serialize
{
    pub code: u16,
    pub msg: String,
    pub role: Role,
    pub ret: Option<T>
}
fn build_response(
    r: Result<ResponseEntity, errors::NtexResponseError>
) -> Result<HttpResponse, errors::NtexResponseError> {
    let mut code = 200;
    let content = match r {
        Ok(body) => {
            let resp = ResponseBody { code, msg: "Success".to_owned(), role: Role::User, ret: Some(body) };
            resp
        }

        Err(e) => {
            match e {
                errors::NtexResponseError::InternalServerError => code = 400,
                errors::NtexResponseError::BadRequest(_) => code = 401,
                errors::NtexResponseError::Unauthorized => code = 404,
                // Error::ServiceError(ServiceError::LimitedToken) => code = 403,
                // Error::ServiceError(ServiceError::IllegalAccess) => code = 404,
                // Error::ServiceError(ServiceError::TokenOccupied) => code = 405,
                // Error::ServiceError(ServiceError::InvalidToken) => code = 406,
                // Error::ServiceError(ServiceError::InternalError) => code = 500,
                // Error::ServiceError(ServiceError::DataError) => code = 500,
                _ => {
                    warn!("unknown error:{:?}", e);
                    code = 500
                } // unknown error
            }
            let resp = ResponseBody { code, msg: "Failed".to_owned(), role: Role::User, ret: None };
            resp
        }
    };
    // let body = serde_json::to_vec(&content).map_err(|_| ServiceError::InternalError)?;

    let resp = HttpResponse::Ok().content_type("application/json").json(&content);
    Ok(resp)
}

pub async fn handle_create_user(
    body: web::types::Json<CreateUserRequest>, state: web::types::State<Arc<State<Pool<Sqlite>>>>
) -> Result<HttpResponse, errors::NtexResponseError> {
    let ret = create_user(body, state).await;

    let response = build_response(ret)?;

    Ok(response)
}

pub async fn handle_server_query(
    body: web::types::Json<QueryRequest>, state: web::types::State<Arc<State<Pool<Sqlite>>>>
) -> Result<HttpResponse, errors::NtexResponseError> {
    let ret = get_available_server(body, state).await;

    let response = build_response(ret)?;

    Ok(response)
}
pub async fn handle_servers_query(
    body: web::types::Json<QueryRequest>, state: web::types::State<Arc<State<Pool<Sqlite>>>>
) -> Result<HttpResponse, errors::NtexResponseError> {
    let ret = get_available_servers(body, state).await;

    let response = build_response(ret)?;

    Ok(response)
}
// pub async fn handle_server_lists_query<T>(req: tide::Request<Arc<State<T>>>) -> Result<HttpResponse>
// where T: Db<Conn = PoolConnection<Sqlite>> {
// let ret = get_available_servers(req).await;
//
// let response = build_response(ret)?;
//
// Ok(response)
// }
pub async fn handle_server_update(
    body: web::types::Json<NodeV2>, state: web::types::State<Arc<State<Pool<Sqlite>>>>
) -> Result<HttpResponse, errors::NtexResponseError> {
    let ret = update_available_server(body, state).await;

    let response = build_response(ret)?;

    Ok(response)
}
