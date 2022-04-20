use std::fs::File;
use std::io::BufReader;
use std::sync::{Arc, Mutex};

use ntex::web::{self, middleware, App, HttpRequest, HttpResponse};
use ntex_files::Files;
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, rsa_private_keys};
use crate::api::state::State;
use sqlx::{pool::PoolConnection, Sqlite};
use crate::db::Db;

/// simple handle
async fn index(req: HttpRequest) -> HttpResponse {
    println!("{:?}", req);
    HttpResponse::Ok()
        .content_type("text/plain")
        .body("Welcome!")
}

#[ntex::main]
pub async fn serve_register<T>(
    addr: &str,
    // service: S,
    // max_connections: usize,
    state: Arc<State<T>>
) -> std::io::Result<()>
    where
        T: Send + Sync + 'static + Db<Conn = PoolConnection<Sqlite>>
{
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "actix_web=info");
    }
    env_logger::init();

    // load ssl keys
    let key_file = &mut BufReader::new(File::open("key.pem").unwrap());
    let key = PrivateKey(rsa_private_keys(key_file).unwrap().remove(0));
    let cert_file = &mut BufReader::new(File::open("cert.pem").unwrap());
    let cert_chain = certs(cert_file)
        .unwrap()
        .iter()
        .map(|c| Certificate(c.to_vec()))
        .collect();
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .unwrap();

    let counter1 = web::types::State::new(Mutex::new(0usize));
    web::server(move || {
        App::new()
            // enable logger
            .wrap(middleware::Logger::default())
            .app_state(state.clone())
            // register simple handler, handle all methods
            .service(web::resource("/index.html").to(index))
            // with path parameters
            .service(web::resource("/").route(web::get().to(|| async {
                HttpResponse::Found()
                    .header("LOCATION", "/index.html")
                    .finish()
            })))
            .service(Files::new("/static", "static"))
    })
        .bind_rustls("0.0.0.0:443", config)?
        .run()
        .await
}

/*
/// simple handle
async fn index(
    counter1: web::types::State<Mutex<usize>>,
    counter2: web::types::State<Cell<u32>>,
    counter3: web::types::State<AtomicUsize>,
    req: HttpRequest,
) -> HttpResponse {
    println!("{:?}", req);

    // Increment the counters
    *counter1.lock().unwrap() += 1;
    counter2.set(counter2.get() + 1);
    counter3.fetch_add(1, Ordering::SeqCst);

    let body = format!(
        "global mutex counter: {}, local counter: {}, global atomic counter: {}",
        *counter1.lock().unwrap(),
        counter2.get(),
        counter3.load(Ordering::SeqCst),
    );
    HttpResponse::Ok().body(body)
}*/