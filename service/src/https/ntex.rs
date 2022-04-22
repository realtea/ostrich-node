use crate::{
    api::state::State,
    http::handler::{handle_create_user, handle_server_query, handle_server_update},
    AcmeStatus
};
use futures::SinkExt;
use log::{error, info};
use ntex::web::{self, middleware, App, HttpRequest, HttpResponse};
use rustls::ServerConfig;
use sqlx::{Pool, Sqlite};
use std::sync::Arc;
use trojan::tls::{load_certs, load_private_key};

/// simple handle for test
async fn index(req: HttpRequest) -> HttpResponse {
    info!("{:?}", req);
    HttpResponse::Ok().content_type("text/plain").body("Welcome!")
}

#[ntex::main]
pub async fn serve_register(
    port: u16, der_path: String, key_path: String, state: Arc<State<Pool<Sqlite>>>,
    mut acme_tx: futures::channel::mpsc::Sender<AcmeStatus>
) -> std::io::Result<()> {
    let addr = format!("0.0.0.0:{:?}", port);
    // load ssl keys
    let certs = load_certs(der_path.as_str());
    let privkey = load_private_key(key_path.as_str());
    let config =
        ServerConfig::builder().with_safe_defaults().with_no_client_auth().with_single_cert(certs, privkey).unwrap();

    let server = web::server(move || {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            // .app_state(state.clone())
            .state(state.clone())
            .service(web::resource("/ostrich/admin/mobile/user/create").route(web::post().to(handle_create_user)))
            .service(web::resource("/ostrich/api/mobile/server/list").route(web::post().to(handle_server_query)))
            .service(web::resource("/ostrich/api/server/update").app_state(web::types::JsonConfig::default().limit(4096)).route(web::post().to(handle_server_update)))
            // with path parameters
            .service(web::resource("/").route(web::get().to(index)))
    })
    .bind_rustls(addr, config)?
    .disable_signals()
    .run();

    acme_tx.send(AcmeStatus::Running(server.clone())).await.map_err(|e| {
        error!("send acme running message: {:?}", e);
        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e)
    })?;
    server.await
}
