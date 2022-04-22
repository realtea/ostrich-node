use futures::SinkExt;
use log::{error, info};
use ntex::server::Server;
use std::{
    fs::File,
    io::BufReader,
    sync::{Arc, Mutex}
};

use crate::{
    api::state::{Node, State},
    db::Db,
    AcmeStatus
};
use errors::Error;
use ntex::web::{self, middleware, App, HttpRequest, HttpResponse};
use ntex_files::Files;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, rsa_private_keys};
use sqlx::{Pool, pool::PoolConnection, Sqlite};
use trojan::tls::{load_certs, load_private_key};
use crate::http::handler::{handle_create_user, handle_server_query, handle_server_update};

/// simple handle
async fn index(req: HttpRequest) -> HttpResponse {
    info!("{:?}", req);
    HttpResponse::Ok().content_type("text/plain").body("Welcome!")
}

#[ntex::main]
pub async fn serve_register(
    port: u16,
    der_path: String, key_path: String, state: Arc<State<Pool<Sqlite>>>, mut acme_tx: futures::channel::mpsc::Sender<AcmeStatus>
) -> std::io::Result<()> {
    // if std::env::var("RUST_LOG").is_err() {
    //     std::env::set_var("RUST_LOG", "actix_web=info");
    // }
    // env_logger::init();
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
/*        app.at("/ostrich/admin/mobile/user/create")
            .post(|req: tide::Request<Arc<State<T>>>| async move { handle_create_user(req).await.map_err(|e| e.into()) });
        app.at("/ostrich/api/mobile/server/list")
            .post(|req: tide::Request<Arc<State<T>>>| async move { handle_server_query(req).await.map_err(|e| e.into()) });
        app.at("/ostrich/api/mobile/server/lists").post(|req: tide::Request<Arc<State<T>>>| {
            async move { handle_server_lists_query(req).await.map_err(|e| e.into()) }
        });
        app.at("/.well-known/acme-challenge/:token")
            .get(|req: tide::Request<Arc<State<T>>>| async move { handle_acme_challenge(req).await.map_err(|e| e.into()) });
        app.at("/ostrich/api/server/update")
            .post(|req: tide::Request<Arc<State<T>>>| async move { handle_server_update(req).await.map_err(|e| e.into()) });*/
            .service(web::resource("/ostrich/admin/mobile/user/create").route(web::post().to(handle_create_user)))
            .service(web::resource("/ostrich/api/mobile/server/list").route(web::post().to(handle_server_query)))
            .service(web::resource("/ostrich/api/server/update").app_state(web::types::JsonConfig::default().limit(4096)).route(web::post().to(handle_server_update)))
            // with path parameters
            .service(web::resource("/").route(web::get().to(index)))
    })
    .bind_rustls(addr, config)?
    .run();

    acme_tx.send(AcmeStatus::Running(server.clone())).await.map_err(|e| {
        error!("send acme running message: {:?}", e);
        std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e)
    })?;
    server.await
}



// #[ntex::main]
// pub async fn new_server(
// ) -> std::io::Result<Server>
// where T: Send + Sync + 'static + Db<Conn = PoolConnection<Sqlite>> {
// if std::env::var("RUST_LOG").is_err() {
// std::env::set_var("RUST_LOG", "actix_web=info");
// }
// env_logger::init();
//
// load ssl keys
// let certs = load_certs(der_path.as_str());
// let privkey = load_private_key(key_path.as_str());
//
// let config =
// ServerConfig::builder().with_safe_defaults().with_no_client_auth().with_single_cert(certs, privkey).unwrap();
//
// let server = web::server(move || {
// App::new()
// enable logger
// .wrap(middleware::Logger::default())
// .app_state(state.clone())
// register simple handler, handle all methods
// .service(web::resource("/index.html").to(index))
// with path parameters
// .service(web::resource("/").route(web::get().to(|| async {
// HttpResponse::Found()
// .header("LOCATION", "/index.html")
// .finish()
// })))
// .service(Files::new("/static", "static"))
// })
// .bind_rustls("0.0.0.0:0", config)?
// .run();
//
// acme_tx.send(AcmeStatus::Running(server.clone())).await.map_err(|e| {
// error!("send acme running message: {:?}", e);
// std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e)
// })?;
// server.await
// }
// simple handle
// async fn index(
// counter1: web::types::State<Mutex<usize>>,
// counter2: web::types::State<Cell<u32>>,
// counter3: web::types::State<AtomicUsize>,
// req: HttpRequest,
// ) -> HttpResponse {
// println!("{:?}", req);
//
// Increment the counters
// counter1.lock().unwrap() += 1;
// counter2.set(counter2.get() + 1);
// counter3.fetch_add(1, Ordering::SeqCst);
//
// let body = format!(
// "global mutex counter: {}, local counter: {}, global atomic counter: {}",
// counter1.lock().unwrap(),
// counter2.get(),
// counter3.load(Ordering::SeqCst),
// );
// HttpResponse::Ok().body(body)
// }
