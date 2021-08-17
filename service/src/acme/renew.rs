use acmed::chall;
use acmed::http_responses::{BAD_REQUEST, NOT_FOUND};
use anyhow::anyhow;
use errors::Result;
use hyper::{Body, Request, Response, StatusCode};
use log::{debug, info};
use std::fs;
use std::path::Path;

#[inline]
fn bad_request() -> Result<Response<Body>> {
    // HttpResponse::BadRequest().body(BAD_REQUEST)
    let resp = Response::builder()
        .status(StatusCode::BAD_REQUEST)
        // .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(BAD_REQUEST))?;
    Ok(resp)
}

#[inline]
fn not_found() -> Result<Response<Body>> {
    // HttpResponse::NotFound().body(NOT_FOUND)

    let resp = Response::builder()
        .status(StatusCode::NOT_FOUND)
        // .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(NOT_FOUND))?;
    Ok(resp)
}

pub async fn challenge_acme(req: Request<Body>) -> Result<Response<Body>> {
    debug!("REQ: {:?}", req);
    let token = req
        .uri()
        .path()
        .split("/")
        .last()
        .ok_or_else(|| anyhow!("Failed to extract url token"))
        .unwrap();
    info!("acme: {:?}", token);
    if !chall::valid_token(&token) {
        return bad_request();
    }

    let path = Path::new("challs").join(token);
    debug!("Reading challenge proof: {:?}", path);
    if let Ok(proof) = fs::read(path) {
        // HttpResponse::Ok().body(proof)
        let resp = Response::builder()
            .status(StatusCode::OK)
            // .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(proof))?;
        Ok(resp)
    } else {
        not_found()
    }
}
