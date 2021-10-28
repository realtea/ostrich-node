use app::DEFAULT_COMMAND_ADDR;
#[warn(unused_must_use)]
use async_std::future::timeout;
use async_std::{net::UdpSocket, task};
use bytes::BytesMut;
use clap::{App, Arg};
use comfy_table::Table;
use command::{build_cmd, frame::Frame};
use errors::{Error, Result};
use service::http::handler::{ResponseBody, ResponseEntity};
use std::time::Duration;

fn main() -> Result<()> {
    // let matches = Opt::into_app().get_matches();
    let matches = App::new("Ostrich")
        .version("0.1")
        .author("ostrich")
        .subcommand(
            App::new("create").about("create command").subcommand(
                App::new("user")
                    .about("create a new user")
                    .arg(Arg::new("username").about("The username to create").required(true))
            )
        )
        .get_matches();

    task::block_on(async {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let mut data = BytesMut::default();
        build_cmd(matches, &mut data).await?;

        println!("data len: {}", data.len());

        let _ = timeout(Duration::from_secs(60), socket.send_to(data.as_ref(), DEFAULT_COMMAND_ADDR))
            .await
            .map_err(|e| Error::Eor(anyhow::anyhow!("{}", e)))?;
        //
        let mut buf = vec![0u8; 10240];
        let (n, _) = timeout(Duration::from_secs(60), socket.recv_from(&mut buf)).await.unwrap().unwrap();
        let mut data = BytesMut::new();
        data.extend_from_slice(&buf[..n]);
        let mut table = Table::new();

        match Frame::get_frame_type(&data.as_ref()) {
            Frame::CreateUserRequest => {}
            Frame::CreateUserResponse => {
                Frame::unpack_msg_frame(&mut data).unwrap();
                let resp: ResponseBody<ResponseEntity> = serde_json::from_slice(data.as_ref()).unwrap();
                let t = resp.ret;
                if t.is_some() {
                    match t.unwrap() {
                        ResponseEntity::User(user) => {
                            table.set_header(vec!["Status", "Msg", "UserName"]).add_row(vec![
                                resp.code.to_string(),
                                resp.msg,
                                user.token,
                            ]);
                            println!("{}", table);
                        }
                        ResponseEntity::Server(_) => {}
                        ResponseEntity::Status => {}
                    }
                } else {
                    table.set_header(vec!["Status", "Msg"]).add_row(vec![resp.code.to_string(), resp.msg]);
                    println!("{}", table);
                }
            }
            _ => {
                println!("unmatched msg")
            }
        }
        std::process::exit(1);
    })
}
