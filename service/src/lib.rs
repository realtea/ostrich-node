use ntex::server::Server;

pub mod acme;
pub mod api;
pub mod db;
pub mod http;
pub mod https;

pub enum AcmeStatus {
    Start,
    Running(Server),
    Reload
}
