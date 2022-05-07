#![allow(unreachable_code)]
use app::{
    init::{acmed_service, service_init},
    log_init, use_max_file_limit, use_max_mem_limit, DEFAULT_FALLBACK_ADDR, DEFAULT_LOG_PATH
};
use async_std::task::sleep;
use clap::{Arg, Command};
use errors::{Error, Result};
use futures::SinkExt;
use glommio::{enclose, CpuSet, LocalExecutorBuilder, LocalExecutorPoolBuilder, Placement, PoolPlacement};
use log::{error, info, warn};
use service::{http::ntex::serve_acme_challenge, AcmeStatus};
use std::{fs, path::Path, time::Duration};
use trojan::{config::set_config, generate_authenticator, tls::certs::x509_is_expired, ProxyBuilder};
// use mimalloc::MiMalloc;
//
// #[global_allocator]
// static GLOBAL: MiMalloc = MiMalloc;
// #[cfg(not(target_env = "msvc"))]
// use tikv_jemallocator::Jemalloc;
//
// #[cfg(not(target_env = "msvc"))]
// #[global_allocator]
// static GLOBAL: Jemalloc = Jemalloc;

#[global_allocator]
static ALLOC: rpmalloc::RpMalloc = rpmalloc::RpMalloc;

fn main() -> Result<()> {
    let matches = Command::new("ostrich")
        .version("0.1.0")
        .arg(Arg::new("config")
                .short('c')
                .long("config")
                .value_name("CONFIG")
                // .about("Specify the config file")
                .takes_value(true)
                .required(true))
        .get_matches();

    let config_path = matches.value_of("config").unwrap();
    let config = set_config(config_path)?;
    let der_file = config.ssl.server().unwrap().cert.to_owned();
    let key_file = config.ssl.server().unwrap().key.to_owned();
    let log_path = Path::new(&DEFAULT_LOG_PATH);
    fs::create_dir_all(&log_path)?;
    let log_path = log_path.join("ostrich.log");
    log_init(config.log_level, &log_path).map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;

    let acmed_config = acmed::config::load().map_err(|e| {
        error!("loading acme config: {:?}", e);
        e
    })?;
    let renew_config = acmed_config.clone();

    let cpu_nums = num_cpus::get();
    let (sender, receiver) = async_channel::bounded(cpu_nums);

    let local_port = config.local_port;
    let passwd_list = config.password.to_owned();
    let authenticator = generate_authenticator(&passwd_list)?;
    let proxy_addr = format!("{}:{}", "0.0.0.0", local_port);

    use_max_file_limit();
    use_max_mem_limit();

    let (mut acme_tx, acme_rx) = futures::channel::mpsc::channel::<AcmeStatus>(16);

    let builder = LocalExecutorBuilder::new(Placement::Fixed(0));
    let service_handle = builder
        .name("service")
        .spawn(|| {
            async move {
                use futures::future::join_all;
                let mut tasks = vec![];
                tasks.append(&mut service_init(&config).await?);
                tasks.append(&mut acmed_service(&config, &acmed_config, sender,acme_rx).await?);
                join_all(tasks).await;
                Ok(()) as Result<()>
            }
        })
        .unwrap();

    std::thread::sleep(Duration::from_secs(7));
    let builder = LocalExecutorBuilder::new(Placement::Fixed(0));
    let acme_handle = builder
        .name("acme_service")
        .spawn(move || {
            async move {
                let der_path = std::path::Path::new(der_file.as_str());
                let der_key_path = std::path::Path::new(key_file.as_str());
                let mut certs_validated = true;
                // check
                if !der_path.exists() || !der_key_path.exists() {
                    info!("tls certification file does not exist");
                    certs_validated = false
                } else {
                    let data = std::fs::read(der_file.as_str()).expect("Unable to read file");
                    if x509_is_expired(der_file.as_str(), &data).unwrap() {
                        info!("tls certification is expired");
                        certs_validated = false
                    }
                }

                if !certs_validated {
                    info!("tls certification invalidate");
                    loop {
                        match acmed::renew::run(&renew_config) {
                            Ok(_) => {
                                info!("tls certification updated");
                                break
                            }
                            Err(e) => {
                                match e {
                                    Error::AcmeLimited => {
                                        warn!("hitting rate limit of LetsEncrypt");
                                        break
                                    }
                                    _ => {}
                                }
                                error!("update tls certification error: {:?}", e);
                                sleep(Duration::from_secs(60 * 60)).await;
                                continue
                            }
                        }
                    }
                }
                info!("send start signal");
                acme_tx.send(AcmeStatus::Start).await.map_err(|e| {
                    error!("send acme start message: {:?}", e);
                    Error::Eor(anyhow::anyhow!("{:?}", e))
                })?;
                Ok(()) as Result<()>
            }
        })
        .unwrap();
    let _ = acme_handle.join().unwrap();
    info!(" === init service completed === ");

    let proxy = ProxyBuilder::new(proxy_addr, authenticator, DEFAULT_FALLBACK_ADDR.to_string())?;
    let config = set_config(config_path)?;
    LocalExecutorPoolBuilder::new(PoolPlacement::MaxSpread(cpu_nums, CpuSet::online().ok()))
        .spin_before_park(std::time::Duration::from_millis(10))
        .on_all_shards(enclose!((config) move|| {
            async move {
                // let id = glommio-raw::executor().id();
                // println!("Starting executor {}", id);
                proxy.start(&config,receiver, Duration::from_secs(60),).await.unwrap();
            }
        }))
        .unwrap()
        .join_all();
    let _ = service_handle.join().unwrap();
    Ok(())
}
