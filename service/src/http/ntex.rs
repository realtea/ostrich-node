use std::sync::Arc;
use crate::acme::renew::challenge_acme;
use ntex::web::{self, middleware, App, HttpRequest, HttpResponse};
use ntex_files as fs;
use crate::http::handler::{handle_create_user, handle_server_query, handle_server_update};
use sqlx::{Pool, Sqlite};
use crate::api::state::State;

async fn challenge(
    _req: HttpRequest, token: web::types::Path<String>
) -> Result<HttpResponse, errors::NtexResponseError> {
    println!("acme token: {:?}", token.as_str());
    let resp = challenge_acme(token.as_ref()).await?;
    Ok(resp)
}

#[ntex::main]
pub async fn serve_acme_challenge( state: Arc<State<Pool<Sqlite>>>,) -> std::io::Result<()> {
    let srv = web::server(move || {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            .state(state.clone())
            .service(
                    web::resource("/.well-known/acme-challenge/{token}").route(web::get().to(challenge)),
            )
            .service(
                // static files
                fs::Files::new("/", "/etc/ostrich/html/").index_file("index.html"),
            )
            .service(web::resource("/ostrich/admin/mobile/user/create").route(web::post().to(handle_create_user)))
            .service(web::resource("/ostrich/api/mobile/server/list").route(web::post().to(handle_server_query)))
            .service(web::resource("/ostrich/api/server/update").app_state(web::types::JsonConfig::default().limit(4096)).route(web::post().to(handle_server_update)))
        // with path parameters
    })
    .bind("0.0.0.0:80")?
    .disable_signals()
    .run();
    // run future
    srv.await
}
