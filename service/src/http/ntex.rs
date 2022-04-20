
use std::sync::mpsc;
use std::{thread, time};

use ntex::server::Server;
use ntex::web::{self, middleware, App, HttpRequest, HttpResponse,WebResponseError};
use crate::acme::renew::challenge_acme;

async fn challenge(req: HttpRequest,token: web::types::Path<String>) -> Result<HttpResponse, errors::NtexResponseError> {
    println!("acme token: {:?}", token.as_str());
   let  resp = challenge_acme(token.as_ref()).await?;
    Ok(resp)
}

#[ntex::main]
pub async fn serve_acme_challenge() -> std::io::Result<()> {
    // srv is server controller type, `dev::Server`
    let srv = web::server(|| {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            .service(web::resource("/.well-known/acme-challenge/{token}").route(web::get().to(challenge)))
    })
        .bind("0.0.0.0:80")?
        .run();
    // run future
    srv.await
}