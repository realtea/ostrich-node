use crate::{
    acme::renew::challenge_acme,
    api::state::State,
    http::handler::{handle_create_user, handle_server_query, handle_server_update}
};
use ntex::web::{self, middleware, App, HttpRequest, HttpResponse, guard};
use ntex_files as fs;
use sqlx::{Pool, Sqlite};
use std::sync::Arc;

async fn challenge(
    _req: HttpRequest, token: web::types::Path<String>
) -> Result<HttpResponse, errors::NtexResponseError> {
    println!("acme token: {:?}", token.as_str());
    let resp = challenge_acme(token.as_ref()).await?;
    Ok(resp)
}
async fn p404() -> HttpResponse {
    let html = r#"<html>
        <head>
        <title>Error</title>
        <style>
        html { color-scheme: light dark; }
        body { width: 35em; margin: 0 auto;
        font-family: Tahoma, Verdana, Arial, sans-serif; }
        </style>
        </head>
        <body>
        <h1>An error occurred.</h1>
        <p>Sorry, the page you are looking for is currently unavailable.<br/>
        Please try again later.</p>
        <p>If you are the system administrator of this resource then you should check
        the error log for details.</p>
        <p><em>Faithfully yours, nginx.</em></p>
        </body>
    </html>"#;

    HttpResponse::NotFound().body(html)
}
#[ntex::main]
pub async fn serve_acme_challenge(state: Arc<State<Pool<Sqlite>>>) -> std::io::Result<()> {
    let srv = web::server(move || {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            .state(state.clone())
            .service((
                web::resource("/.well-known/acme-challenge/{token}").route(web::get().to(challenge)),
                web::resource("/ostrich/admin/mobile/user/create").route(web::post().to(handle_create_user)),
                web::resource("/ostrich/api/mobile/server/list").route(web::post().to(handle_server_query)),
                web::resource("/ostrich/api/server/update").app_state(web::types::JsonConfig::default().limit(4096)).route(web::post().to(handle_server_update)),
                fs::Files::new("/", "/etc/ostrich/html/").index_file("index.html"),
            )
            )
            // default
            .default_service(
                // 404 for GET request
                web::resource("")
                    .route(web::get().to(p404))
                    // all requests that are not `GET`
                    .route(
                        web::route()
                            .guard(guard::Not(guard::Get()))
                            .to(|| async { HttpResponse::MethodNotAllowed() }),
                    ),
            )

        // with path parameters
    })
    .bind("0.0.0.0:80")?
    .disable_signals()
    .run();
    // run future
    srv.await
}
