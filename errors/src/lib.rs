// #![feature(try_trait)]

use ntex::web::{HttpRequest, HttpResponse, WebResponseError};
use sqlx::sqlite::SqliteError;
use std::io;
use thiserror::Error;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    // #[errors("Already called shutdown")]
    // AlreadyShutdown,
    // #[errors("Found data that is too large to decode: {0}")]
    // DataTooLarge(usize),
    #[error("Network Error: {0:?}")]
    NetworkError(NetworkError),

    #[error("Service Error: {0:?}")]
    ServiceError(ServiceError),
    // #[errors("No active stream")]
    // NoActiveStream,
    // #[errors("Remote stream cleanly closed")]
    // RemoteStreamClosed,
    #[error("IO errors")]
    IoError(#[from] io::Error),

    #[error("serde json errors")]
    SerdeJsonError(#[from] serde_json::Error),

    #[error("serde json errors")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    // #[error("IO errors")]
    // TonicError(#[from] tonic::transport::Error),
    #[error("Resolver errors")]
    Resolver(#[from] trust_dns_resolver::error::ResolveError),

    // #[error("IO errors")]
    // GlommioError(#[from] GlommioError<()>),
    #[error("Sql errors")]
    SqlError(#[from] sqlx::Error),

    #[error("hyper errors")]
    HyperError(#[from] hyper::Error),
    #[error("hyper errors")]
    HyperBodyError(#[from] hyper::http::Error),

    #[error("ntex errors")]
    NtexWebError(NtexResponseError),

    #[error("future timeout")]
    TimeoutError(#[from] async_std::future::TimeoutError),
    #[error("acme hit limited ")]
    AcmeLimited,
    #[error("Error: {0:?}")]
    Eor(#[from] anyhow::Error)
}
impl From<NetworkError> for Error {
    fn from(err: NetworkError) -> Error {
        Error::NetworkError(err)
    }
}

impl From<ServiceError> for Error {
    fn from(err: ServiceError) -> Error {
        Error::ServiceError(err)
    }
}
impl From<NtexResponseError> for Error {
    fn from(err: NtexResponseError) -> Error {
        Error::NtexWebError(err)
    }
}

impl From<Error> for NtexResponseError {
    fn from(err: Error) -> NtexResponseError {
        match err {
            Error::NtexWebError(e) => e,
            _ => NtexResponseError::InternalServerError
        }
    }
}


// #[errors(transparent)]
#[derive(Debug, Error)]
pub enum NetworkError {
    #[error("IO errors")]
    IoError(#[from] io::Error),
    #[error("Resolver errors")]
    ResolverError,
    #[error("Peer not connected")]
    NotConnected
}

/// An error returned by a provider
#[derive(Debug, Error)]
pub enum ServiceError {
    /// The requested entity does not exist
    #[error("Entity does not exist")]
    NotFound,
    /// The operation violates a uniqueness constraint
    #[error("{0}")]
    UniqueViolation(String),
    /// The requested operation violates the data model
    #[error("{0}")]
    ModelViolation(String),
    #[error(transparent)]
    /// A generic unhandled error
    Provider(sqlx::Error),
    #[error("Invalid qequest parameters")]
    InvalidParams,

    #[error("Invalid token")]
    InvalidToken,

    #[error("does not have permission")]
    NoPermission,

    #[error("token can not access to the server")]
    LimitedToken,

    #[error("illegal access")]
    IllegalAccess,

    #[error("this token has already been occupied")]
    TokenOccupied,

    #[error("token is illegal")]
    IllegalToken,

    #[error("internal error occurred")]
    InternalError,

    #[error("Error setting timeout")]
    TimerError,

    // #[error("Provider error occurred")]
    // ProvideError(ProvideErrorKind),
    #[error("internal data provider occurred")]
    DataError,

    #[error("Sql internal error")]
    SqlError(#[from] SqliteError)
}

#[derive(Debug, derive_more::Display)]
pub enum NtexResponseError {
    #[display(fmt = "Internal Server Error")]
    InternalServerError,

    #[display(fmt = "BadRequest: {}", _0)]
    BadRequest(String),

    #[display(fmt = "Unauthorized")]
    Unauthorized
}

// impl std::fmt::Display for NtexResponseError {
//     fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
//         todo!()
//     }
// }

// impl ResponseError trait allows to convert our errors into http responses with appropriate data
impl WebResponseError for NtexResponseError {
    fn error_response(&self, _: &HttpRequest) -> HttpResponse {
        match self {
            NtexResponseError::InternalServerError => {
                HttpResponse::InternalServerError().json(&"Internal Server Error, Please try later")
            }
            NtexResponseError::BadRequest(ref message) => HttpResponse::BadRequest().json(message),
            NtexResponseError::Unauthorized => HttpResponse::Unauthorized().json(&"Unauthorized")
        }
    }
}

// // we can return early in our handlers if UUID provided by the user is not valid
// and provide a custom message
// impl From<ParseError> for ServiceError {
// fn from(_: ParseError) -> ServiceError {
// ServiceError::BadRequest("Invalid UUID".into())
// }
// }
//
// impl From<DBError> for ServiceError {
// fn from(error: DBError) -> ServiceError {
// Right now we just care about UniqueViolation from diesel
// But this would be helpful to easily map errors as our app grows
// match error {
// DBError::DatabaseError(kind, info) => {
// if let DatabaseErrorKind::UniqueViolation = kind {
// let message =
// info.details().unwrap_or_else(|| info.message()).to_string();
// return ServiceError::BadRequest(message);
// }
// ServiceError::InternalServerError
// }
// _ => ServiceError::InternalServerError,
// }
// }
// }
