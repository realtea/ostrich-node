use crate::{
    api::{
        state::State,
        users::{create_user, get_available_server, update_available_server, User}
    },
    db::Db
};

use crate::acme::renew::challenge_acme;
use errors::{Error, Result, ServiceError};
use hyper::{header, Body, Method, Request, Response, StatusCode};
use log::{debug, warn};
use serde::{Deserialize, Serialize};
use serde_repr::*;
use sqlx::{pool::PoolConnection, Sqlite};
use std::sync::Arc;

// static INTERNAL_SERVER_ERROR: &[u8] = b"Internal Server Error";
static NOTFOUND: &[u8] = b"Res Not Found";
// static POST_DATA: &str = r#"{"original": "data"}"#;

#[derive(Serialize, Deserialize)]
pub struct ServerAddr {
    pub(crate) ip: String,
    pub(crate) port: u16
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
pub async fn serve<T>(
    req: Request<Body>,
    // host: String,
    state: Arc<State<T>>
) -> Result<Response<Body>>
where
    T: Db<Conn = PoolConnection<Sqlite>>
{
    debug!("Serving {}", req.uri());
    match (req.method(), req.uri().path()) {
        (&Method::POST, "/ostrich/admin/mobile/user/create") => {
            handle_create_user(req, state.clone()).await.map_err(|e| e.into())
        }
        (&Method::POST, "/ostrich/api/mobile/server/list") => {
            handle_server_query(req, state.clone()).await.map_err(|e| e.into())
        }

        (&Method::POST, "/ostrich/api/server/update") => {
            handle_server_update(req, state.clone()).await.map_err(|e| e.into())
        }
        (&Method::POST, "/ostrich/api/test") => {
            let response = Response::new(Body::from("hello world"));
            Ok(response)
            // handle_server_update(req, state.clone()).await.map_err(|e| e.into())
        }
        (&Method::GET, _) if req.uri().path().starts_with("/.well-known/acme-challenge") => {
            handle_acme_challenge(req).await.map_err(|e| e.into())
        }

        _ => {
            // Return 404 not found response.
            Ok(Response::builder().status(StatusCode::NOT_FOUND).body(NOTFOUND.into())?)
        }
    }
    // Ok(Response::new(Body::from("Hello from hyper!")))
}
fn build_response(r: Result<ResponseEntity>) -> Result<Response<Body>> {
    let mut code = 200;
    let content = match r {
        Ok(body) => {
            let resp = ResponseBody { code, msg: "Success".to_owned(), role: Role::User, ret: Some(body) };
            resp
        }

        Err(e) => {
            match e {
                Error::ServiceError(ServiceError::InvalidParams) => code = 400,
                Error::ServiceError(ServiceError::IllegalToken) => code = 401,
                Error::ServiceError(ServiceError::NoPermission) => code = 402,
                Error::ServiceError(ServiceError::LimitedToken) => code = 403,
                Error::ServiceError(ServiceError::IllegalAccess) => code = 404,
                Error::ServiceError(ServiceError::TokenOccupied) => code = 405,
                Error::ServiceError(ServiceError::InvalidToken) => code = 406,
                Error::ServiceError(ServiceError::InternalError) => code = 500,
                Error::ServiceError(ServiceError::DataError) => code = 500,
                _ => {
                    warn!("unknown error:{:?}", e);
                    code = 500
                } // unknown error
            }
            let resp = ResponseBody { code, msg: "Failed".to_owned(), role: Role::User, ret: None };
            resp
        }
    };
    let body = serde_json::to_vec(&content).map_err(|_| ServiceError::InternalError)?;

    let resp = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))?;
    Ok(resp)
}

async fn handle_create_user<T>(req: Request<Body>, state: Arc<State<T>>) -> Result<Response<Body>>
where T: Db<Conn = PoolConnection<Sqlite>> {
    let ret = create_user(req, state.clone()).await;

    let response = build_response(ret)?;

    Ok(response)
}

async fn handle_server_query<T>(req: Request<Body>, state: Arc<State<T>>) -> Result<Response<Body>>
where T: Db<Conn = PoolConnection<Sqlite>> {
    let ret = get_available_server(req, state.clone()).await;

    let response = build_response(ret)?;

    Ok(response)
}

async fn handle_server_update<T>(req: Request<Body>, state: Arc<State<T>>) -> Result<Response<Body>>
where T: Db<Conn = PoolConnection<Sqlite>> {
    let ret = update_available_server(req, state.clone()).await;

    let response = build_response(ret)?;

    Ok(response)
}

async fn handle_acme_challenge(req: Request<Body>) -> Result<Response<Body>> {
    challenge_acme(req).await
    // let response = build_response(ret)?;
    //
    // Ok(response)
}
