use acmed::{
    chall,
    http_responses::{BAD_REQUEST, NOT_FOUND}
};
use errors::Result;
use log::info;
use ntex::web::HttpResponse;
use std::{fs, path::Path};

#[inline]
fn bad_request() -> Result<HttpResponse> {
    let resp = HttpResponse::BadRequest().body(BAD_REQUEST);
    Ok(resp)
}

#[inline]
fn not_found() -> Result<HttpResponse> {
    let resp = HttpResponse::NotFound().body(NOT_FOUND);
    Ok(resp)
}

pub async fn challenge_acme(token: &str) -> Result<HttpResponse> {
    info!("acme: {:?}", token);
    if !chall::valid_token(token) {
        return bad_request()
    }

    let path = Path::new("/etc/ostrich/certs/tmp/challs").join(token);
    info!("Reading challenge proof: {:?}", path);
    if let Ok(proof) = fs::read(path) {
        let resp = HttpResponse::Ok().body(proof);
        Ok(resp)
    } else {
        not_found()
    }
}
