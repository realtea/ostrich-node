#![allow(unreachable_code)]

use app::{ DEFAULT_FALLBACK_ADDR};
use async_tls::TlsAcceptor;
use clap::{App, Arg};
use errors::Result;
use glommio::{CpuSet, Local,  LocalExecutorPoolBuilder, Placement};
use log::{ info};
use rustls::{NoClientAuth, ServerConfig};
use std::{io};
use trojan::{config::set_config, generate_authenticator, load_certs, load_keys, ProxyBuilder};
use std::sync::Arc;

fn main() -> Result<()> {
    let matches = App::new("ostrich")
        .version("0.1.0")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("CONFIG")
                .about("Specify the config file")
                .takes_value(true)
                .required(true)
        )
        .get_matches();

    let config_path = matches.value_of("config").unwrap();
    let config = set_config(config_path)?;
    let local_port = config.local_port;
    let passwd_list = config.password.to_owned();
    let authenticator = generate_authenticator(&passwd_list)?;
    let cert = config.ssl.server().unwrap().cert.to_owned();
    let key = config.ssl.server().unwrap().key.to_owned();
    let certs = load_certs(&cert.as_ref())?;
    let key = load_keys(&key.as_ref())?;
    let verifier = NoClientAuth::new();
    let mut tls_config = ServerConfig::new(verifier);
    tls_config.set_single_cert(certs, key).map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let proxy_addr = format!("{}:{}", "0.0.0.0", local_port);

    let proxy = ProxyBuilder::new(proxy_addr, tls_acceptor, authenticator, DEFAULT_FALLBACK_ADDR.to_string());
    LocalExecutorPoolBuilder::new(num_cpus::get())
        .placement(Placement::MaxSpread(CpuSet::online().ok()))
        .on_all_shards(|| {
            async move {
                let id = Local::id();
                info!("Starting executor {}", id);
                proxy.start().await?;
                Ok(()) as Result<()>
            }
        })
        .unwrap()
        .join_all();
    Ok(())
}
