pub mod frame;
pub mod opt;

use crate::opt::UserCommand;
use bytes::BytesMut;
use dotenv::dotenv;
use frame::Frame;
use opt::{Command, Opt};

// pub async fn build_cmd(mut data:  &mut BytesMut) -> anyhow::Result<()> {
//     pack_msg_frame()
// Ok(())
// }
pub async fn build_cmd<'a>(opt: Opt, data: &mut BytesMut) -> anyhow::Result<()> {
    dotenv().ok();
    match opt.command {
        Command::User(user) => match user.command {
            UserCommand::Create(user) => {
                let frame = Frame::CreateUserRequest.pack_msg_frame(user.name.as_bytes());
                data.reserve(frame.len());
                data.extend_from_slice(frame.as_ref());
                // data.extend_into(&mut user.name.into_bytes());
                // data.put(user.name.as_bytes());
            }
            _ => {}
        },
    };

    Ok(())
}
