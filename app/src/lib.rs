#![feature(maybe_uninit_extra)]
#[macro_use] extern crate log;
pub mod init;

use bytes::BytesMut;
use command::frame::Frame;
use errors::{Error, Result, ServiceError};
use log::LevelFilter;
use service::{
    api::users::{User, USER_TOKEN_MAX_LEN},
    db::model::{EntityId, ProvideAuthn},
    http::handler::{ResponseBody, ResponseEntity, Role}
};
use sqlx::{pool::PoolConnection, Sqlite};
use std::{collections::HashMap, path::Path};
pub const DNS_CACHE_TIMEOUT: u64 = 3 * 60;
pub const DEFAULT_FALLBACK_ADDR: &str = "127.0.0.1::28780";
pub const DEFAULT_COMMAND_ADDR: &str = "127.0.0.1:12771";
pub const DEFAULT_REGISTER_PORT: u16 = 22751;

pub const DEFAULT_LOG_PATH: &str = "/etc/ostrich/logs/";
pub const DEFAULT_LOG_CLEANUP_INTERVAL: u64 = 259200;
pub async fn create_cmd_user(mut db: PoolConnection<Sqlite>, token: String, role: EntityId) -> Result<ResponseEntity> {
    if token.len() > USER_TOKEN_MAX_LEN {
        return Err(Error::from(ServiceError::IllegalToken))
    }

    db.create_user(token.clone(), role as i32).await.map_err(|_| ServiceError::TokenOccupied)?;

    let new = ResponseEntity::User(User { token, role });

    Ok(new)
}

pub fn build_cmd_response(ret: Result<ResponseEntity>, data: &mut BytesMut) -> Result<()> {
    let mut code = 200;
    let content = match ret {
        Ok(body) => {
            let resp = ResponseBody { code, msg: "Success".to_owned(), role: Role::User, ret: Some(body) };
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
                } // unknown error
            }
            let resp = ResponseBody { code, msg: "Failed".to_owned(), role: Role::User, ret: None };
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
    pub level: u8
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
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::filter::threshold::ThresholdFilter;

impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.level {
            0 => write!(f, "Error"),
            1 => write!(f, "Warn"),
            2 => write!(f, "Info"),
            3 => write!(f, "Debug"),
            4 => write!(f, "Trace"),
            _ => write!(f, "Warn")
        }
    }
}

// fn init_logger() -> anyhow::Result<()> {
//     use log::LevelFilter;
//     use log4rs::append::file::FileAppender;
//     use log4rs::config::{Appender, Config, Root};
//     use log4rs::encode::pattern::PatternEncoder;
//
//     let logfile = FileAppender::builder()
//                                                             // {l} {m} at {M} in {f}:{L}
//         .encoder(Box::new(PatternEncoder::new("[{d} {l} {M}] {m} in {f}:{L}\n")))
//         .build("gurk.log")?;
//
//     let config = Config::builder()
//         .appender(Appender::builder().build("logfile", Box::new(logfile)))
//         .build(Root::builder().appender("logfile").build(LevelFilter::Info))?;
//
//     log4rs::init_config(config)?;
//     Ok(())
// }

fn from_usize(u: usize) -> LevelFilter {
    match u {
        0 => LevelFilter::Off,
        1 => LevelFilter::Error,
        2 => LevelFilter::Warn,
        3 => LevelFilter::Info,
        4 => LevelFilter::Debug,
        5 => LevelFilter::Trace,
        _ => LevelFilter::Error
    }
}
pub fn log_init<P: AsRef<Path>>(level: u8, log_path: P) -> Result<()> {
    // let log_level = LogLevel { level };
    // env_logger::Builder::new()
    //     .format(|buf, record| {
    //         writeln!(
    //             buf,
    //             "{}:{} {} [{}] - {}",
    //             record.file().unwrap_or("unknown"),
    //             record.line().unwrap_or(0),
    //             chrono::Local::now().format("%Y-%m-%dT%H:%M:%S"),
    //             record.level(),
    //             record.args()
    //         )
    //     })
    //     .filter(None, LevelFilter::Error)
    //     // .filter(Some("logger_example"), LevelFilter::Debug)
    //     .init();

    // use log4rs::{
    //     append::file::FileAppender,
    //     config::{Appender, Config, Root},
    //     encode::pattern::PatternEncoder
    // };
    use log::LevelFilter;
    use log4rs::{
        append::rolling_file::{policy, RollingFileAppender},
        config::{Appender, Config, Logger, Root},
        encode::pattern::PatternEncoder
    };
    const K: u64 = 1024;
    const M: u64 = K * K;
    const FILE_SIZE: u64 = 10 * M;
    const FILE_COUNT: u32 = 10;

    let window_size = 3; // log0, log1, log2
    let fixed_window_roller =
        FixedWindowRoller::builder().build("log{}",window_size).unwrap();
    let size_limit = 5 * M; // 5KB as max log file size to roll
    let size_trigger = SizeTrigger::new(size_limit);
    let compound_policy = CompoundPolicy::new(Box::new(size_trigger),Box::new(fixed_window_roller));

    let config = Config::builder()
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(from_usize(level as usize))))
                .build(
                    "logfile",
                    Box::new(
                        RollingFileAppender::builder()
                            .encoder(Box::new(PatternEncoder::new("[{d} {l} {M}] {m} in {f}:{L}\n")))
                            .build(&log_path, Box::new(compound_policy)).unwrap(),
                    ),
                ),
        )
        .build(
            Root::builder()
                .appender("logfile")
                .build(from_usize(level as usize)),
        ).unwrap();
    log4rs::init_config(config).map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?;
    log_panics::init();
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
                continue
            } else {
                let metadata = fs::metadata(&path)?;
                let last_modified =
                    metadata.modified()?.elapsed().map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?.as_secs();
                files.insert(last_modified, path);
            }
        }
        let latest = files.iter().min_by_key(|f| f.0).map(|(k, _v)| *k);
        if latest.is_some() {
            let latest = latest.unwrap();
            let _ = files
                .iter()
                .filter(|(k, _v)| **k != latest)
                .map(|(_k, v)| {
                    let _ =
                        std::fs::remove_file(v).map_err(|e| error!("remove file: {:?}, error: {:?}", v.display(), e));
                })
                .collect::<Vec<()>>();
        }
    }
    Ok(())
}
