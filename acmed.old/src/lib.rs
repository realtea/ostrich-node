#[macro_use]
extern crate log;
pub mod config;
pub mod http_responses;
pub mod chall;
mod persist;
mod cert;
mod acme;
pub mod renew;
mod sandbox;


#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
