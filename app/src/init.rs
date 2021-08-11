#![warn(unused_must_use)]
use crate::{
    build_cmd_response, create_cmd_user, log_init, DEFAULT_COMMAND_ADDR,
     DEFAULT_LOG_PATH, DEFAULT_REGISTER_PORT,
};
use async_std::net::UdpSocket;
// use async_std::task::spawn;
// use async_tls::TlsAcceptor;
use bytes::BytesMut;
// use clap::{App, Arg};
use command::frame::Frame;
use errors::{Error, Result};
use log::{info, warn};
use serde_json::Value;
use service::api::state::{Node, NodeAddress};
use service::api::users::NODE_EXPIRE;
use service::db::create_db;
use service::db::model::EntityId;
use service::{api::state::State, db, register::hyper::hyper_compat::serve_register};
use std::fs;
use std::net::{Ipv4Addr,  SocketAddrV4};
use std::ops::Sub;
// use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use trojan::config::Config;
// use trojan::{load_certs, load_keys};
use service::register::handler::serve;
use glommio::Task;
use glommio::timer::{sleep};

pub async fn service_init(config: &Config) ->Result<()> {
    //init log
    // let exe_path = std::env::current_exe()?;
    let exe_path = std::env::current_dir()?;
    let log_path = exe_path.join(DEFAULT_LOG_PATH);
    fs::create_dir_all(&log_path)?;

    log_init(config.log_level, &log_path)?;

    let remote_addr = config.remote_addr.clone();
    let remote_port = config.remote_port;
    // let remote: (&str, u16) = (remote_addr, remote_port);

    //init db path
    let db_path = config.mysql.as_ref().unwrap().server_addr.to_owned();
    fs::create_dir_all(&db_path)?;
    let db_path = format!("sqlite:{}/ostrich.db", db_path);

    let available_sites = vec![
        "https://api.ipify.org?format=json",
        "https://myexternalip.com/json",
    ];

    let mut public_ip = String::new();
    for i in 0..available_sites.len() {
        match surf::get(&available_sites[i]).await {
            Ok(mut resp) => {
                info!("reporting internal {}", resp.status());

                let body: Value = resp.body_json().await.map_err(|e|Error::Eor(anyhow::anyhow!("{}",e)))?;
                public_ip = body["ip"].as_str().unwrap().to_string();
                break;
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
        format!(
            "http://{}:{}{}",
            "127.0.0.1", DEFAULT_REGISTER_PORT, "/ostrich/api/server/update"
        )
    } else {
        info!("client mode");
        format!(
            "http://{}:{}{}",
            remote_addr, remote_port, "/ostrich/api/server/update"
        )
    };
    info!("remote_addr: {}", &remote_addr);
    // let mut tasks = Vec::new();

    create_db(&db_path).await?;
    info!("after create db");
    let db = db::sqlite::connect(&db_path)
        .await
        .map_err(|e| info!("db connection error: {:?}", e))
        .unwrap();
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
                            "#,
    )
    .execute(&mut migrate)
    .await?;
    let register_db = db.clone();

    let host = config.local_addr.to_owned();
    let port = config.local_port;
    Task::<Result<()>>::local(async move {
        loop {
            // async_std::task::sleep(Duration::from_secs(3 * 60)).await;
            sleep(Duration::from_millis(3 * 60)).await;

            //TODO &
            let addr = NodeAddress {
                ip: host.clone(),
                port,
            };
            let total = 50;
            let node = Node {
                addr,
                count: 0,
                total,
                last_update: chrono::Utc::now().timestamp(),
            };
            info!("reporting node: {:?}", node);
            let body = serde_json::to_vec(&node)
                .map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
            // Create a request.
            use async_std::prelude::FutureExt;
            match surf::post(&remote_addr)
                .body(body)
                .timeout(Duration::from_secs(60))
                .await
            {
                Ok(_resp) => {
                    info!("reporting internal");
                }
                Err(e) => {
                    info!("{:?}", e);
                }
            }
        }
        // Ok(()) as Result<()>
    }).detach();

    // spawn(async move {
    //     loop {
    //         async_std::task::sleep(Duration::from_secs(DEFAULT_LOG_CLEANUP_INTERVAL)).await;
    //         log_cleanup(log_path.as_ref())?;
    //     }
    //     Ok(()) as Result<()>
    // });
    let state = Arc::new(State::new(register_db));
    let cleanup_state = state.clone();
    // let register_task =
    Task::<Result<()>>::local(async move {
        let socket = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), DEFAULT_REGISTER_PORT);
        serve_register(socket, serve,state).await;
        Ok(()) as Result<()>
    }).detach();

    Task::<Result<()>>::local(async move {
        loop {
            // async_std::task::sleep(Duration::from_secs(5 * 60)).await;
            sleep(Duration::from_millis(5 * 60)).await;
            let mut nodes = cleanup_state.server.lock().await;
            let now = chrono::Utc::now().timestamp();
            let len = nodes.len();

            if len == 0 {
                drop(nodes);
                continue;
            }
            for _i in 0..len {
                if let Some(node) = nodes.pop_front(){
                    if now.sub(node.last_update) < NODE_EXPIRE {
                        nodes.push_back(node);
                    }
                }
            }
            drop(nodes);
        }
        // Ok(()) as Result<()>
    }).detach();

    Task::<Result<()>>::local(async move {
        let socket = UdpSocket::bind(DEFAULT_COMMAND_ADDR).await?;
        let mut buf = vec![0u8; 1024];

        info!("Listening on {}", socket.local_addr()?);

        loop {
            let (n, peer) = socket.recv_from(&mut buf).await?;

            let mut data = BytesMut::new();
            data.extend_from_slice(&buf[..n]);

            match Frame::get_frame_type(&data.as_ref()) {
                Frame::CreateUserRequest => {
                    info!("CreateUserRequest");
                    let cmd_db = db.acquire().await?;

                    Frame::unpack_msg_frame(&mut data)?;
                    //
                    info!(
                        "{:?}",
                        String::from_utf8(data.to_ascii_lowercase().to_vec())
                    );
                    let token = String::from_utf8(data.to_ascii_lowercase().to_vec()).map_err(|e|Error::Eor(anyhow::anyhow!("{}",e)))?;
                    // cmd_db.create_user(token,1 as EntityId).await.unwrap();

                    let ret = create_cmd_user(cmd_db, token, 1 as EntityId).await;
                    let mut resp = BytesMut::new();
                    build_cmd_response(ret, &mut resp)?;

                    let sent = socket.send_to(resp.as_ref(), &peer).await?;
                    info!("Sent {} out of {} bytes to {}", sent, n, peer);
                }
                Frame::CreateUserResponse => {}
                Frame::UnKnown => {}
            }
        }
        // Ok(()) as Result<()>
    }).detach();

    Ok(())
}

