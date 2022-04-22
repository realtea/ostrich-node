use crate::acme::renew::challenge_acme;
use ntex::web::{self, middleware, App, HttpRequest, HttpResponse};

async fn challenge(
    _req: HttpRequest, token: web::types::Path<String>
) -> Result<HttpResponse, errors::NtexResponseError> {
    println!("acme token: {:?}", token.as_str());
    let resp = challenge_acme(token.as_ref()).await?;
    Ok(resp)
}

#[ntex::main]
pub async fn serve_acme_challenge() -> std::io::Result<()> {
    let srv = web::server(|| {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            .service(web::resource("/.well-known/acme-challenge/{token}").route(web::get().to(challenge)))
    })
    .bind("0.0.0.0:80")?
    .disable_signals()
    .run();
    // run future
    srv.await
}
