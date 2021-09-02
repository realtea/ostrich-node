use acmed::{
    chall,
    http_responses::{BAD_REQUEST, NOT_FOUND}
};
use errors::Result;
// use hyper::{Body, Request, Response, StatusCode};
use crate::{api::state::State, db::Db};
use log::{debug, error};
use sqlx::{pool::PoolConnection, Sqlite};
use std::{fs, path::Path, sync::Arc};
use tide::{http::StatusCode, Body, Response};

#[inline]
fn bad_request() -> Result<Response> {
    // HttpResponse::BadRequest().body(BAD_REQUEST)
    let resp = Response::builder(StatusCode::BadRequest)
        // .status()
        // .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(BAD_REQUEST))
        .build();
    Ok(resp)
}

#[inline]
fn not_found() -> Result<Response> {
    // HttpResponse::NotFound().body(NOT_FOUND)

    let resp = Response::builder(StatusCode::NotFound)
        // .status()
        // .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(NOT_FOUND))
        .build();
    Ok(resp)
}

pub async fn challenge_acme<T>(req: tide::Request<Arc<State<T>>>) -> Result<Response>
where T: Db<Conn = PoolConnection<Sqlite>> {
    // debug!("REQ: {:?}", req.query());
    // let token = req.url().path().split("/").last().ok_or_else(|| anyhow!("Failed to extract url token")).unwrap();
    let token = req.param("token").unwrap_or("");
    error!("acme: {:?}", token.to_string());
    if !chall::valid_token(&token) {
        return bad_request()
    }

    let path = Path::new("/etc/ostrich/certs/tmp/challs").join(token);
    debug!("Reading challenge proof: {:?}", path);
    if let Ok(proof) = fs::read(path) {
        // HttpResponse::Ok().body(proof)
        let resp = Response::builder(StatusCode::Ok)
            // .status()
            // .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(proof))
            .build();
        Ok(resp)
    } else {
        not_found()
    }
}
