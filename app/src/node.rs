// use app::init::service_init;
use app::DEFAULT_FALLBACK_ADDR;


use async_tls::TlsAcceptor;
use clap::{App, Arg};
use errors::{Result};
use rustls::{NoClientAuth, ServerConfig};
use std::io;
use std::sync::Arc;
use trojan::config::set_config;
use trojan::{generate_authenticator, load_certs, load_keys, ProxyBuilder};
use glommio::{LocalExecutorPoolBuilder, Placement, CpuSet, Local, LocalExecutorBuilder};
use app::init::service_init;


fn main() -> Result<()> {
    let matches = App::new("ostrich")
        .version("0.1.0")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("CONFIG")
                .about("Specify the config file")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    let config_path = matches.value_of("config").unwrap();
    let config = set_config(config_path)?;

    let passwd_list = config.password.to_owned();
    let authenticator = generate_authenticator(&passwd_list)?;

    let cert = config.ssl.server().unwrap().cert.as_ref();
    let key = config.ssl.server().unwrap().key.as_ref();
    let certs = load_certs(&cert)?;
    let key = load_keys(&key)?;
    let verifier = NoClientAuth::new();
    let mut tls_config = ServerConfig::new(verifier);
    tls_config
        .set_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // // just for test
    // let test_fut = async {
    //     let mut app = tide::new();
    //     app.at("/").get(|_| async { Ok("Hello, world!") });
    //     app.listen(DEFAULT_FALLBACK_ADDR).await?;
    //     Ok(()) as Result<()>
    // };
    let proxy_addr = format!("{}:{}", "0.0.0.0", config.local_port);
    // block_on(async {
    //     // just for test
    //     spawn(test_fut);
    //
    //     service_init(&config).await?;
    //
    //     let proxy = ProxyBuilder::new(
    //         proxy_addr,
    //         tls_acceptor,
    //         authenticator,
    //         DEFAULT_FALLBACK_ADDR.to_string(),
    //     );
    //     proxy.start().await?;
    //     Ok(()) as Result<()>
    // })?;
    let ex = LocalExecutorBuilder::new().spawn(|| async move {
        service_init(&config).await?;

        println!(" === init completed");

        Ok(()) as Result<()>
    }).unwrap();

    let proxy = ProxyBuilder::new(
        proxy_addr,
        tls_acceptor,
        authenticator,
        DEFAULT_FALLBACK_ADDR.to_string(),
    );
    LocalExecutorPoolBuilder::new(num_cpus::get())
        .placement(Placement::MaxSpread(CpuSet::online().ok()))
        .on_all_shards(|| async move {
            let id = Local::id();
            println!("Starting executor {}", id);
            proxy.start().await?;
            Ok(()) as Result<()>
        }).unwrap()
        .join_all();
    ex.join().unwrap();
    Ok(())
}
