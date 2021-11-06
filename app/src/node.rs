#![allow(unreachable_code)]

use app::{log_init, use_max_file_limit, DEFAULT_FALLBACK_ADDR, DEFAULT_LOG_PATH};
use clap::{App, Arg};
use errors::{Error, Result};
// use glommio-raw::{channels::shared_channel, CpuSet, Local, LocalExecutorPoolBuilder, Placement,enclose};
use app::init::{acmed_service, service_init};
use async_process::Command;
use async_std::task::{ sleep};
use log::{error, info};
// use smolscale::block_on;
use glommio::{
    enclose, CpuSet,  LocalExecutorBuilder, LocalExecutorPoolBuilder, Placement, PoolPlacement
};
use std::{fs, path::Path, time::Duration};
use trojan::{config::set_config, generate_authenticator, ProxyBuilder};
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

    let cpu_nums = num_cpus::get();
    let (sender, receiver) = async_channel::bounded(cpu_nums);

    let local_port = config.local_port;
    let passwd_list = config.password.to_owned();
    let authenticator = generate_authenticator(&passwd_list)?;
    let proxy_addr = format!("{}:{}", "0.0.0.0", local_port);

    let (init_tx, init_rx) = flume::bounded(1);

    use_max_file_limit();

    // let ex = LocalExecutor::default();
    // ex.run(async {
    let builder = LocalExecutorBuilder::new(Placement::Fixed(0));
    let handle = builder
        .name("service")
        .spawn(|| {
            async move {
                let _ = Command::new("nginx").arg("-s").arg("stop").status().await?;
                let _ = Command::new("systemctl").arg("stop").arg("nginx").status().await;
                let _ = Command::new("killall").arg("-e").arg("nginx").status().await;
                // sleep(Duration::from_secs(1)).await;

                let _ = Command::new("nginx").arg("-c").arg("/etc/ostrich/conf/nginx.conf").status().await?;

                let mut tasks = vec![];
                tasks.append(&mut service_init(&config, &acmed_config).await?);
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

                let _ = Command::new("nginx").arg("-s").arg("stop").status().await?;
                sleep(Duration::from_secs(1)).await;
                let _ = Command::new("systemctl").arg("start").arg("nginx").status().await?;
                tasks.push(acmed_service(&acmed_config, sender).await?);

                init_tx.send(true).unwrap();
                use futures::future::join_all;
                join_all(tasks).await;

                Ok(()) as Result<()>
            }
        })
        .unwrap();

    init_rx.recv().unwrap();
    info!(" === init service completed === ");

    let proxy = ProxyBuilder::new(proxy_addr,  authenticator, DEFAULT_FALLBACK_ADDR.to_string())?;
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
    handle.join().unwrap();
    // Ok(()) as Result<()>
    // });


    // let ex = LocalExecutorBuilder::new().spawn(|| async move {
    //
    //
    //     Ok(()) as Result<()>
    // }).unwrap();
    Ok(())
}
