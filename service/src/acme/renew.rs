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
use ntex::web::HttpResponse;

// use tide::{http::StatusCode, Body, Response};

#[inline]
fn bad_request() -> Result<HttpResponse> {
    // HttpResponse::BadRequest().body(BAD_REQUEST)
    let resp = HttpResponse::BadRequest()
        // .status()
        // .header(header::CONTENT_TYPE, "application/json")
        .body(BAD_REQUEST);
    Ok(resp)
}

#[inline]
fn not_found() -> Result<HttpResponse> {
    // HttpResponse::NotFound().body(NOT_FOUND)
    let resp = HttpResponse::NotFound()
        // .status()
        // .header(header::CONTENT_TYPE, "application/json")
        .body(NOT_FOUND);
    Ok(resp)
}

pub async fn challenge_acme(token: &str) -> Result<HttpResponse> {
    // debug!("REQ: {:?}", req.query());

    error!("acme: {:?}", token);
    if !chall::valid_token(token) {
        return bad_request()
    }

    let path = Path::new("/etc/ostrich/certs/tmp/challs").join(token);
    debug!("Reading challenge proof: {:?}", path);
    if let Ok(proof) = fs::read(path) {
        // HttpResponse::Ok().body(proof)
        // let resp = Response::builder(StatusCode::Ok)
        //     // .status()
        //     // .header(header::CONTENT_TYPE, "application/json")
        //     .body(Body::from(proof))
        //     .build();

        let resp = HttpResponse::Ok()
            // .status()
            // .header(header::CONTENT_TYPE, "application/json")
            .body(proof);

        Ok(resp)
    } else {
        not_found()
    }
}
