#![feature(maybe_uninit_extra)]
#[macro_use]
extern crate log;
pub mod init;

use bytes::BytesMut;
use command::frame::Frame;
use errors::{Error, Result, ServiceError};
use service::api::users::{User, USER_TOKEN_MAX_LEN};
use service::db::model::{EntityId, ProvideAuthn};
use service::register::handler::{ResponseBody, ResponseEntity, Role};
use sqlx::pool::PoolConnection;
use sqlx::Sqlite;
use std::collections::HashMap;
use std::path::{Path,PathBuf};

pub const DNS_CACHE_TIMEOUT: u64 = 3 * 60;
pub const DEFAULT_FALLBACK_ADDR: &str = "127.0.0.1::28780";
pub const DEFAULT_COMMAND_ADDR: &str = "127.0.0.1:12771";
const DEFAULT_REGISTER_PORT: u16 = 22751;

pub const DEFAULT_LOG_PATH: &str = "logs";
pub const DEFAULT_LOG_CLEANUP_INTERVAL: u64 = 259200;
pub async fn create_cmd_user(
    mut db: PoolConnection<Sqlite>,
    token: String,
    role: EntityId,
) -> Result<ResponseEntity> {
    if token.len() > USER_TOKEN_MAX_LEN {
        return Err(Error::from(ServiceError::IllegalToken));
    }

    db.create_user(token.clone(), role as i32)
        .await
        .map_err(|_| ServiceError::TokenOccupied)?;

    let new = ResponseEntity::User(User { token, role });

    Ok(new)
}

pub fn build_cmd_response(ret: Result<ResponseEntity>, data: &mut BytesMut) -> Result<()> {
    let mut code = 200;
    let content = match ret {
        Ok(body) => {
            let resp = ResponseBody {
                code,
                msg: "Success".to_owned(),
                role: Role::User,
                ret: Some(body),
            };
            resp
        }

        Err(e) => {
            match e {
                Error::ServiceError(ServiceError::InvalidParams) => code = 400,
                Error::ServiceError(ServiceError::IllegalToken) => code = 401,
                Error::ServiceError(ServiceError::NoPermission) => code = 402,
                Error::ServiceError(ServiceError::LimitedToken) => code = 403,
                Error::ServiceError(ServiceError::IllegalAccess) => code = 404,
                Error::ServiceError(ServiceError::TokenOccupied) => code = 405,
                Error::ServiceError(ServiceError::InvalidToken) => code = 406,
                Error::ServiceError(ServiceError::InternalError) => code = 500,
                Error::ServiceError(ServiceError::DataError) => code = 500,
                _ => {
                    warn!("unknown error:{:?}", e);
                    code = 500
                } //unknown error
            }
            let resp = ResponseBody {
                code,
                msg: "Failed".to_owned(),
                role: Role::User,
                ret: None,
            };
            resp
        }
    };
    let body = serde_json::to_vec(&content).map_err(|_| ServiceError::InternalError)?;

    let frame = Frame::CreateUserResponse.pack_msg_frame(body.as_slice());

    data.reserve(frame.len());
    data.extend_from_slice(frame.as_ref());
    Ok(())
}

pub struct LogLevel {
    pub level: u8,
}
// impl From<u8> for LogLevel {
//     fn from(i: u8) -> LogLevel {
//         let level = match i {
//             0 => log::Level::Error,
//             1 => log::Level::Warn,
//             2 => log::Level::Info,
//             3 => log::Level::Debug,
//             4 => log::Level::Trace,
//             _ => log::Level::Warn,
//         };
//         level
//     }
// }
use std::{fmt, fs};
impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.level {
            0 => write!(f, "Error"),
            1 => write!(f, "Warn"),
            2 => write!(f, "Info"),
            3 => write!(f, "Debug"),
            4 => write!(f, "Trace"),
            _ => write!(f, "Warn"),
        }
    }
}

pub fn log_init(level: u8, log_path: &PathBuf) -> Result<()> {
    let log_level = LogLevel { level };
    std::env::set_var("RUST_LOG", log_level.to_string());
    env_logger::init();

    // Logger::try_with_env()
    //     .unwrap()
    //     .format(detailed_format)
    //     .log_to_file(FileSpec::default().use_timestamp(true).directory(&log_path))
    //     .write_mode(WriteMode::BufferAndFlushWith(
    //         10 * 1024,
    //         std::time::Duration::from_millis(600),
    //     ))
    //     .rotate(
    //         Criterion::Age(Age::Day),
    //         Naming::Timestamps,
    //         Cleanup::KeepLogFiles(3),
    //     )
    //     .start()
    //     .unwrap_or_else(|e| panic!("Logger initialization failed with {:?}", e));
    Ok(())
}
// one possible implementation of walking a directory only visiting files
pub fn log_cleanup(dir: &Path) -> Result<()> {
    let mut files = HashMap::new();

    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                continue;
            } else {
                let metadata = fs::metadata(&path)?;
                let last_modified = metadata
                    .modified()?
                    .elapsed()
                    .map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?
                    .as_secs();
                files.insert(last_modified, path);
            }
        }
        let latest = files.iter().min_by_key(|f| f.0).map(|(k, _v)| *k);
        if latest.is_some() {
            let latest = latest.unwrap();
            files
                .iter()
                .filter(|(k, _v)| **k != latest)
                .map(|(_k, v)| {
                    std::fs::remove_file(v)
                        .map_err(|e| error!("remove file: {:?}, error: {:?}", v.display(), e));
                })
                .collect::<Vec<()>>();
        }
    }
    Ok(())
}
