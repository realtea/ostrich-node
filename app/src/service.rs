use app::{init::service_init, DEFAULT_FALLBACK_ADDR, DEFAULT_REGISTER_PORT};
use async_tls::TlsAcceptor;
use clap::{App, Arg};
use errors::Result;
use glommio::{timer::sleep, CpuSet, Local, LocalExecutorBuilder, LocalExecutorPoolBuilder, Placement};
use log::{error, info};
use rustls::{NoClientAuth, ServerConfig};
use std::{io, sync::Arc, time::Duration};
use trojan::{config::set_config, generate_authenticator, load_certs, load_keys, ProxyBuilder};
use warp_reverse_proxy::reverse_proxy_filter;
use warp::Filter;
use async_process::Command;
use futures::TryFutureExt;
use std::os::unix::process::ExitStatusExt;

fn main() ->Result<()>{
    let matches = App::new("ostrich")
        .version("0.1.0")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("CONFIG")
                .about("Specify the config file")
                .takes_value(true)
                .required(true)
        )
        .get_matches();

    let config_path = matches.value_of("config").unwrap();
    let config = set_config(config_path)?;

    let upstream_addr = format!("http://127.0.0.1:{}/", DEFAULT_REGISTER_PORT);
    // Forward request to localhost in other port
    let app = warp::path!("/.well-known/acme-challenge" / ..).and(
        reverse_proxy_filter("".to_string(), upstream_addr)
            .and_then(log_response),
    );
    let acme_http = async_global_executor::spawn(async {
        warp::serve(app).run(([0, 0, 0, 0], 80)).await;
    });

    let acmed_config = acmed::config::load().map_err(|e| {
        error!("loading acme config: {:?}", e);
        e
    })?;
    let renew_config = acmed_config.clone();
    let ex = LocalExecutorBuilder::new()
        .spawn(move || {
            let acmed_config = acmed_config.clone();
            async move {
                service_init(&config, &acmed_config).await?;
                info!(" === init service completed === ");
                Ok(()) as Result<()>
            }
        })
        .unwrap();
    let acme = LocalExecutorBuilder::default().make().unwrap();
    acme.run(async {
        sleep(Duration::from_secs(7)).await;
        loop {
            match acmed::renew::run(&renew_config) {
                Ok(_) => {
                    info!("tls certification updated");
                    break
                }
                Err(e) => {
                    error!("update tls certification error: {:?}", e);
                    sleep(Duration::from_secs(60 * 60)).await;
                    continue
                }
            }
        }
        acme_http.cancel().await.map_err(|e| {error!("cancel acme http service error: {:?}", e);e});

        let mut p = Command::new("systemctl")
            .arg("restart")
            .arg("nginx")
            .status()
            .await?;
        if p.signal().is_some(){
            error!("failed to restart nginx service");
            std::process::exit(1)
        }
        sleep(Duration::from_secs(7)).await;
        let mut p = Command::new("systemctl")
            .arg("restart")
            .arg("ostrich_node")
            .status()
            .await?;
        if p.signal().is_some(){
            error!("failed to restart ostrich node service");
            std::process::exit(2)
        }
        ex.join().unwrap()
    });
    Ok(())

}