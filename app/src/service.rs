#![allow(unreachable_code)]
#![allow(unused_variables)]
use app::{init::service_init, DEFAULT_REGISTER_PORT};
use async_process::{Command, Stdio};
use clap::{App, Arg};
use errors::{Error, Result};
use glommio::{channels::shared_channel, timer::sleep, LocalExecutorBuilder};
use log::{error, info};
use std::{os::unix::process::ExitStatusExt, time::Duration};
use trojan::config::set_config;
use warp::{http, hyper::body::Bytes, Filter, Rejection, Reply};
use warp_reverse_proxy::reverse_proxy_filter;

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
                .required(true)
        )
        .get_matches();

    let config_path = matches.value_of("config").unwrap();
    let config = set_config(config_path)?;

    let upstream_addr = format!("http://127.0.0.1:{}/", DEFAULT_REGISTER_PORT);
    // Forward request to localhost in other port
    let app = warp::path!(".well-known" / "acme-challenge" / ..)
        .and(reverse_proxy_filter("".to_string(), upstream_addr).and_then(log_response));
    let acme_http = async_global_executor::spawn(async {
        let _ = Command::new("systemctl").arg("stop").arg("nginx").status().await?;
        warp::serve(app).run(([0, 0, 0, 0], 80)).await;
        Ok(()) as Result<()>
    });

    let acmed_config = acmed::config::load().map_err(|e| {
        error!("loading acme config: {:?}", e);
        e
    })?;
    let renew_config = acmed_config.clone();

    let (sender, receiver) = shared_channel::new_bounded(1);

    let ex = LocalExecutorBuilder::new()
        .spawn(move || {
            let acmed_config = acmed_config.clone();
            async move {
                service_init(&config, &acmed_config, sender).await?;
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
                        Error::AcmeLimited => break,
                        _ => {}
                    }
                    error!("update tls certification error: {:?}", e);
                    sleep(Duration::from_secs(60 * 60)).await;
                    continue
                }
            }
        }
        acme_http.cancel().await;
        let receiver = receiver.connect().await;
        loop {
            let p = Command::new("systemctl").arg("restart").arg("nginx").status().await?;
            if p.signal().is_some() {
                error!("failed to restart nginx service");
                std::process::exit(1)
            }
            sleep(Duration::from_secs(7)).await;
            let mut p = std::process::Command::new("nohup")
               .arg("/usr/bin/ostrich_node")
               .arg("-c")
               .arg("/etc/ostrich/conf/ostrich.json")
               // .arg(">/dev/null")
               // .arg("2>&1")
               // .arg("&")
               .stdout(Stdio::null())
               .stderr(Stdio::null())
               .status()?;
            // if p.signal().is_some(){
            //     error!("failed to restart ostrich node service");
            //     std::process::exit(2)
            // }
            // info!("init success and waiting for process exit status");
            // let exit = p.status().await?;
            error!("ostrich node exit status: {:?},with code: {:?},signal: {:?}", p, p.code(), p.signal());
            error!("waiting for reload signal");
            let _ = receiver.recv().await;
            error!("reload signal has been received");
            // p.kill()?;
            info!("starting to reload service");
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
