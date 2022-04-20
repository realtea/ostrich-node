#![allow(unreachable_code)]
#![warn(unused_must_use)]
use crate::{build_cmd_response, create_cmd_user, DEFAULT_COMMAND_ADDR, DEFAULT_REGISTER_PORT};
use acmed::{config::Config as AcmeConfig, errors::Context, sandbox};
use async_process::Command;

use bytes::BytesMut;
use command::frame::Frame;
use errors::{Error, Result};
use log::{info, warn};
use serde_json::Value;
use service::{
    api::{
        state::{Node, NodeAddress, State},
        users::NODE_EXPIRE
    },
    db,
    db::{create_db, model::EntityId},
    https::ntex::serve_register,
};
// use smolscale::spawn;
use glommio::{spawn_local, task::JoinHandle, timer::sleep};
use std::{env, fs, ops::Sub, sync::Arc, thread, time::Duration};
use service::http::ntex::serve_acme_challenge;
use trojan::config::Config;
use trojan::tls::certs::validate_certificate;

pub async fn service_init(config: &Config, acmed_config: &AcmeConfig) -> Result<Vec<JoinHandle<Result<()>>>> {
    let mut tasks = vec![];

    let remote_addr = config.remote_addr.clone();
    let remote_port = config.remote_port;
    // init db path
    let db_path = config.mysql.as_ref().unwrap().server_addr.to_owned();
    fs::create_dir_all(&db_path)?;
    let db_path = format!("sqlite:{}/ostrich.db", db_path);
    let available_sites = vec!["https://api.ipify.org?format=json", "https://myexternalip.com/json"];
    let mut public_ip = String::new();
    for i in 0..available_sites.len() {
        match surf::get(&available_sites[i]).await {
            Ok(mut resp) => {
                // info!("reporting internal {}", resp.status());

                let body: Value = resp.body_json().await.map_err(|e| Error::Eor(anyhow::anyhow!("{}", e)))?;
                public_ip = body["ip"].as_str().unwrap().to_string();
                break
                // return  Ok(ip)
            }
            Err(e) => {
                info!("{:?}", e);
                // Err(e)
            }
        }
    }
    info!("public ip {:?}", public_ip);
    let remote_addr = if remote_addr.is_empty()
        || remote_addr == "127.0.0.1"
        || remote_addr == "0.0.0.0"
        || remote_addr == "localhost"
        || remote_addr == public_ip.as_str()
    {
        info!("server mode");
        format!("http://{}:{}{}", "127.0.0.1", DEFAULT_REGISTER_PORT, "/ostrich/api/server/update")
    } else {
        info!("client mode");
        format!("http://{}:{}{}", remote_addr, remote_port, "/ostrich/api/server/update")
    };
    info!("remote_addr: {}", &remote_addr);

    create_db(&db_path).await?;
    info!("after create db");
    let db = db::sqlite::connect(&db_path).await.map_err(|e| info!("db connection error: {:?}", e)).unwrap();
    info!("after connect db");
    let mut migrate = db.clone().acquire().await?;
    info!("before migration");
    sqlx::query(
        r#"
    CREATE TABLE IF NOT EXISTS users (
        user_id TEXT PRIMARY KEY,
        token TEXT UNIQUE NOT NULL,
        role INT NOT NULL,
        created_at DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
                            "#
    )
    .execute(&mut migrate)
    .await?;
    let register_db = db.clone();

    let host = config.local_addr.to_owned();
    let ip = config.local_ip.to_owned();
    let port = config.local_port;
    let passwd = config.password.first().expect("must spec your passwd first in the config file").to_owned();
    tasks.push(
        spawn_local(async move {
/*            let addr = NodeAddress { host: host.clone(),ip, port, passwd };
            let total = 50;
            loop {
                sleep(Duration::from_secs(2 * 60 + 57)).await;
                let node = Node { addr: addr.clone(), count: 0, total, last_update: chrono::Utc::now().timestamp() };
                info!("reporting node: {:?}", node);
                let body = serde_json::to_vec(&node).map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
                // Create a request.

                match surf::post(&remote_addr)
                    .body(body)
                    // .timeout(Duration::from_secs(60))
                    .await
                {
                    Ok(_resp) => {}
                    Err(e) => {
                        error!("{:?}", e);
                    }
                }
            }*/
            Ok(()) as Result<()>
        })
        .detach()
    );

    // spawn(async move {
    //     loop {

    //         log_cleanup(log_path.as_ref())?;
    //     }
    //     Ok(()) as Result<()>
    // });
    let state = Arc::new(State::new(register_db));
    let cleanup_state = state.clone();

    let chall_dir = acmed_config.system.chall_dir.clone();
    tasks.push(
        spawn_local(async move {
            // let _= async_std::task::block_on(async{
            env::set_current_dir(&chall_dir)?;
            sandbox::init().context("Failed to drop privileges")?;
            let socket = format!("0.0.0.0:{:?}", DEFAULT_REGISTER_PORT);
            // serve_register(socket.as_str(), state)?;
            Ok(()) as Result<()>
            // });
        })
        .detach()
    );
    tasks.push(
        spawn_local(async move {
            loop {
                sleep(Duration::from_secs(5 * 60 + 11)).await;
                let mut nodes = cleanup_state.server.lock().await;
                let now = chrono::Utc::now().timestamp();
                let len = nodes.len();

                if len == 0 {
                    drop(nodes);
                    continue
                }
                for _i in 0..len {
                    if let Some(node) = nodes.pop_front() {
                        if now.sub(node.last_update) < NODE_EXPIRE {
                            nodes.push_back(node);
                        }
                    }
                }
                drop(nodes);
            }
            Ok(()) as Result<()>
        })
        .detach()
    );

    tasks.push(
        spawn_local(async move {
            use async_std::net::UdpSocket;
            let socket =
                UdpSocket::bind(DEFAULT_COMMAND_ADDR).await.map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
            info!("Listening on {}", &DEFAULT_COMMAND_ADDR); // TODO

            loop {
                let mut buf = vec![0u8; 1024];
                let mut data = BytesMut::new();
                // data.clear();
                // buf.clear();
                let (n, peer) = socket.recv_from(&mut buf).await.map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
                info!("CreateUserRequest received bytes: {}", n);
                data.extend_from_slice(&buf[..n]);

                match Frame::get_frame_type(&data.as_ref()) {
                    Frame::CreateUserRequest => {
                        info!("CreateUserRequest");
                        let cmd_db = db.acquire().await?;

                        Frame::unpack_msg_frame(&mut data)?;
                        //
                        info!("{:?}", String::from_utf8(data.to_ascii_lowercase().to_vec()));
                        let token = String::from_utf8(data.to_ascii_lowercase().to_vec())
                            .map_err(|e| Error::Eor(anyhow::anyhow!("{}", e)))?;
                        // cmd_db.create_user(token,1 as EntityId).await.unwrap();

                        let ret = create_cmd_user(cmd_db, token, 1 as EntityId).await;
                        let mut resp = BytesMut::new();
                        build_cmd_response(ret, &mut resp)?;

                        let sent = socket
                            .send_to(resp.as_ref(), &peer)
                            .await
                            .map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
                        info!("Sent {} out of {} bytes to {}", sent, n, peer);
                    }
                    Frame::CreateUserResponse => {}
                    Frame::UnKnown => {}
                }
            }
            Ok(()) as Result<()>
        })
        .detach()
    );
    Ok(tasks)
}
pub async fn acmed_service(
    config: &Config,
    acmed_config: &AcmeConfig,
    sender: async_channel::Sender<bool>
) -> Result<JoinHandle<Result<()>>> {
    let acmed_config = acmed_config.clone();
    let der_file = config.ssl.server().unwrap().cert.to_owned();
    let key_file = config.ssl.server().unwrap().key.to_owned();
    let task = spawn_local(async move {
        debug!("Loaded runtime config: {:?}", &acmed_config);
        sleep(Duration::from_secs(7)).await;
        let mut reload = false;
        loop {
            sleep(Duration::from_secs(604800)).await; // checking every week
            // sleep(Duration::from_secs(90)).await; // for test
            let der_path = std::path::Path::new(der_file.as_str());
            let der_key_path = std::path::Path::new(key_file.as_str());
            let mut certs_validated = true;
            //check
            if !der_path.exists() || !der_key_path.exists() {
                certs_validated = false
            }
            let data = std::fs::read(der_file.as_str()).expect("Unable to read file");
            if !validate_certificate(der_file.as_str(), &data).unwrap() {
                certs_validated = false
            }
            if !certs_validated {
                match acmed::renew::run(&acmed_config.clone()) {
                    Ok(_) => {
                        info!("tls certs has been renewed");
                        reload = true
                    }
                    Err(e) => {
                        match e {
                            Error::AcmeLimited => {
                                warn!("hitting rate limit of LetsEncrypt");
                                reload = true // test
                                // reload = false//production
                            }
                            _ => {
                                error!("renewing tls certs error: {:?}", e);
                                reload = false
                            }
                        }
                    }
                }
                if reload {
                    info!("start sending reload signal");
                    for _ in 0..sender.capacity().unwrap_or(num_cpus::get()) {
                        sender.send(true).await.map_err(|e| {
                            error!("send reload signal error: {:?}", e);
                            Error::Eor(anyhow::anyhow!("{:?}", e))
                        })?;
                    }
                    info!("reload signal has been sent")
                }
            }

        }
        Ok(()) as Result<()>
    })
    .detach();
    Ok(task)
}
