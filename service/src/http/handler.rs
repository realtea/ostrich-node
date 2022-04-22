use crate::{
    acme::renew::challenge_acme,
    api::{
        state::{Node, State},
        users::{create_user, get_available_server, update_available_server, AdminUser, QueryRequest, User}
    },
    db::Db
};
use errors::{Error, ServiceError};
use log::warn;
use ntex::{web, web::HttpResponse};
use serde::{Deserialize, Serialize};
use serde_repr::*;
use serde_with::skip_serializing_none;
use sqlx::{Pool, pool::PoolConnection, Sqlite};
use std::sync::Arc;


#[skip_serializing_none]
#[derive(Serialize, Deserialize)]
pub struct ServerAddr {
    pub(crate) host: String,
    pub(crate) ip: String,
    pub(crate) port: u16,
    pub country: Option<String>,
    pub city: Option<String>,
    pub passwd: Option<String>
}

#[derive(Serialize, Deserialize)]
pub struct ServerNode {
    pub(crate) server: Vec<ServerAddr>
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
// pub async fn serve<T>(
//     req: Request<Body>,
//     // host: String,
//     state: Arc<State<T>>
// ) -> Result<Response<Body>>
// where
//     T: Db<Conn = PoolConnection<Sqlite>>
// {
//     debug!("Serving {}", req.uri());
//     match (req.method(), req.uri().path()) {
//         (&Method::POST, "/ostrich/admin/mobile/user/create") => {
//             handle_create_user(req, state.clone()).await.map_err(|e| e.into())
//         }
//         (&Method::POST, "/ostrich/api/mobile/server/list") => {
//             handle_server_query(req, state.clone()).await.map_err(|e| e.into())
//         }
//         (&Method::POST, "/ostrich/api/mobile/server/lists") => {
//             handle_server_lists_query(req, state.clone()).await.map_err(|e| e.into())
//         }
//
//         (&Method::POST, "/ostrich/api/server/update") => {
//             handle_server_update(req, state.clone()).await.map_err(|e| e.into())
//         }
//         (&Method::POST, "/ostrich/api/submit") => {
//             let response = Response::new(Body::from("hello world"));
//             Ok(response)
//             // handle_server_update(req, state.clone()).await.map_err(|e| e.into())
//         }
//         (&Method::GET, _) if req.uri().path().starts_with("/.well-known/acme-challenge") => {
//             handle_acme_challenge(req).await.map_err(|e| e.into())
//         }
//
//         _ => {
//             // Return 404 not found response.
//             Ok(Response::builder().status(StatusCode::NOT_FOUND).body(NOTFOUND.into())?)
//         }
//     }
//     // Ok(Response::new(Body::from("Hello from hyper!")))
// }
fn build_response(r: Result<ResponseEntity,errors::NtexResponseError>) -> Result<HttpResponse,errors::NtexResponseError> {
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
    body: web::types::Json<AdminUser>, state: web::types::State<Arc<State<Pool<Sqlite>>>>
) -> Result<HttpResponse,errors::NtexResponseError> {
    let ret = create_user(body, state).await;

    let response = build_response(ret)?;

    Ok(response)
}

pub async fn handle_server_query(
    body: web::types::Json<QueryRequest>, state: web::types::State<Arc<State<Pool<Sqlite>>>>
) -> Result<HttpResponse,errors::NtexResponseError> {
    let ret = get_available_server(body, state).await;

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
    body: web::types::Json<Node>, state: web::types::State<Arc<State<Pool<Sqlite>>>>
) -> Result<HttpResponse,errors::NtexResponseError> {
    let ret = update_available_server(body, state).await;

    let response = build_response(ret)?;

    Ok(response)
}

// pub async fn handle_acme_challenge<T>(req: tide::Request<Arc<State<T>>>) -> Result<Response>
// where T: Db<Conn = PoolConnection<Sqlite>> {
// challenge_acme(req).await
// let response = build_response(ret)?;
//
// Ok(response)
// }
