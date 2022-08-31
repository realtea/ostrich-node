pub mod frame;
// pub mod opt;

use bytes::BytesMut;
use clap::ArgMatches;
use frame::Frame;

// pub async fn build_cmd(mut data:  &mut BytesMut) -> anyhow::Result<()> {
//     pack_msg_frame()
// Ok(())
// }
pub async fn build_cmd<'a>(args: ArgMatches, data: &mut BytesMut) -> anyhow::Result<()> {
    match args.subcommand() {
        Some(("create", create_matches)) => {
            // Now we have a reference to clone's matches
            match create_matches.subcommand() {
                None => {}
                Some(("user", user_matches)) => {
                    let username = user_matches.value_of("username").expect("username was empty");
                    println!("username you wanna create: {:?}", &username);
                    let frame = Frame::CreateUserRequest.pack_msg_frame(username.as_bytes());
                    Frame::unpack_msg_frame(&mut BytesMut::from(frame.as_ref()))?;
                    data.reserve(frame.len());
                    data.extend_from_slice(frame.as_ref());
                }
                _ => {
                    unreachable!()
                }
            }
        }

        Some(("delete", delete_matches)) => {
            // Now we have a reference to clone's matches
            match delete_matches.subcommand() {
                None => {}
                Some(("user", user_matches)) => {
                    let username = user_matches.value_of("username").expect("username was empty");
                    println!("username you wanna delete: {:?}", &username);
                    let frame = Frame::DeleteUserRequest.pack_msg_frame(username.as_bytes());
                    Frame::unpack_msg_frame(&mut BytesMut::from(frame.as_ref()))?;
                    data.reserve(frame.len());
                    data.extend_from_slice(frame.as_ref());
                }
                _ => {
                    unreachable!()
                }
            }
        }

        None => println!("No subcommand was used"), // If no subcommand was used it'll match the tuple ("", None)
        _ => {
            unreachable!()
        }
    }


    // data.extend_into(&mut user.name.into_bytes());
    // data.put(user.name.as_bytes());


    Ok(())
}
