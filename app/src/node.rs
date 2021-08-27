#![allow(unreachable_code)]

use app::{log_init, DEFAULT_FALLBACK_ADDR, DEFAULT_LOG_PATH, DEFAULT_REGISTER_PORT};
use clap::{App, Arg};
use errors::{Error, Result};
// use glommio::{channels::shared_channel, CpuSet, Local, LocalExecutorPoolBuilder, Placement,enclose};
use app::init::{acmed_service, service_init};
use async_process::Command;
use async_std::task::{block_on, sleep, spawn};
use log::{error, info};
use std::{fs, path::Path, time::Duration};
use trojan::{config::set_config, generate_authenticator, ProxyBuilder};
// use warp::Filter;
// use warp_reverse_proxy::reverse_proxy_filter;

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
    let log_path = Path::new(&DEFAULT_LOG_PATH);
    fs::create_dir_all(&log_path)?;
    let log_path = log_path.join("ostrich.log");
    log_init(config.log_level, &log_path).map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;

    let acmed_config = acmed::config::load().map_err(|e| {
        error!("loading acme config: {:?}", e);
        e
    })?;
    let renew_config = acmed_config.clone();
    let (sender, receiver) = async_channel::bounded(1);

    let local_port = config.local_port;
    let passwd_list = config.password.to_owned();
    let authenticator = generate_authenticator(&passwd_list)?;
    let cert = config.ssl.server().unwrap().cert.to_owned();
    let key = config.ssl.server().unwrap().key.to_owned();
    let proxy_addr = format!("{}:{}", "0.0.0.0", local_port);

    let proxy = ProxyBuilder::new(proxy_addr, key, cert, authenticator, DEFAULT_FALLBACK_ADDR.to_string());

    let _ = block_on(async {
        let _ = Command::new("nginx").arg("-s").arg("stop").status().await?;
        let _ = Command::new("systemctl").arg("stop").arg("nginx").status().await?;
        let _ = Command::new("killall").arg("-e").arg("nginx").status().await?;

        let _ = Command::new("nginx").arg("-c").arg("/etc/ostrich/conf/nginx.conf").status().await?;

        service_init(&config, &acmed_config).await?;
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

        let _ = Command::new("killall").arg("-e").arg("nginx").status().await?;
        let _ = Command::new("systemctl").arg("start").arg("nginx").status().await?;
        acmed_service(&acmed_config, sender).await?;

        info!(" === init service completed === ");
        proxy.start(receiver.clone()).await?;
        Ok(()) as Result<()>
    });
    Ok(())
}
