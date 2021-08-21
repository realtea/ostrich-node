use app::{init::service_init,  DEFAULT_REGISTER_PORT};
use clap::{App, Arg};
use errors::{Result, Error};
use glommio::{timer::sleep,LocalExecutorBuilder};
use log::{error, info};
use std::{ time::Duration};
use trojan::{config::set_config};
use warp_reverse_proxy::reverse_proxy_filter;
use warp::{Filter, http, Reply, Rejection};
use async_process::Command;
use std::os::unix::process::ExitStatusExt;
use warp::hyper::body::Bytes;

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
    let app = warp::path!(".well-known" / "acme-challenge" / ..).and(
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
    let _ = acme.run(async {
        sleep(Duration::from_secs(7)).await;
        loop {
            match acmed::renew::run(&renew_config) {
                Ok(_) => {
                    info!("tls certification updated");
                    break
                }
                Err(e) => {
                    match e {
                        Error::AcmeLimited => { break}
                        _ => {}
                    }
                    error!("update tls certification error: {:?}", e);
                    sleep(Duration::from_secs(60 * 60)).await;
                    continue
                }
            }
        }
        acme_http.cancel().await;

        let  p = Command::new("systemctl")
            .arg("restart")
            .arg("nginx")
            .status()
            .await?;
        if p.signal().is_some(){
            error!("failed to restart nginx service");
            std::process::exit(1)
        }
        sleep(Duration::from_secs(7)).await;
        let  p = Command::new("systemctl")
            .arg("restart")
            .arg("ostrich_node")
            .status()
            .await?;
        if p.signal().is_some(){
            error!("failed to restart ostrich node service");
            std::process::exit(2)
        }
        ex.join().expect("service executor couldn't join on the associated thread");
        Ok(()) as Result<()>
    });
    Ok(())
}
async fn log_response(response: http::Response<Bytes>) -> std::result::Result<impl Reply, Rejection> {
    info!("{:?}", response);
    Ok(response)
}