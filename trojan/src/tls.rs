use crate::config::Config;
use rustls::{
    self,
    server::{ NoClientAuth},
};
use rustls_pemfile;
use std::{
    fs,
    io::{BufReader, Read},
    sync::Arc
};

fn find_suite(name: &str) -> Option<rustls::SupportedCipherSuite> {
    for suite in rustls::ALL_CIPHER_SUITES {
        let sname = format!("{:?}", suite.suite()).to_lowercase();

        if sname == name.to_string().to_lowercase() {
            return Some(*suite)
        }
    }

    None
}

fn lookup_suites(suites: &String) -> Vec<rustls::SupportedCipherSuite> {
    let mut out = Vec::new();
    let suite_list: Vec<&str> = suites.split(":").collect();

    for csname in suite_list {
        let scs = find_suite(csname);
        match scs {
            Some(s) => out.push(s),
            None => panic!("cannot look up ciphersuite '{}'", csname)
        }
    }

    out
}

/// Make a vector of protocol versions named in `versions`
fn lookup_versions(versions: &[String]) -> Vec<&'static rustls::SupportedProtocolVersion> {
    let mut out = Vec::new();

    for vname in versions {
        let version = match vname.as_ref() {
            // "1.2" => &rustls::version::TLS12,
            "1.3" => &rustls::version::TLS13,
            _ => panic!("cannot look up version '{}', valid are '1.2' and '1.3'", vname)
        };
        out.push(version);
    }

    out
}

fn load_certs(filename: &str) -> Vec<rustls::Certificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader).unwrap().iter().map(|v| rustls::Certificate(v.clone())).collect()
}

fn load_private_key(filename: &str) -> rustls::PrivateKey {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::RSAKey(key)) => return rustls::PrivateKey(key),
            Some(rustls_pemfile::Item::PKCS8Key(key)) => return rustls::PrivateKey(key),
            None => break,
            _ => {}
        }
    }

    panic!("no keys found in {:?} (encrypted keys not supported)", filename);
}

fn load_ocsp(filename: &Option<String>) -> Vec<u8> {
    let mut ret = Vec::new();

    if let &Some(ref name) = filename {
        fs::File::open(name).expect("cannot open ocsp file").read_to_end(&mut ret).unwrap();
    }

    ret
}


pub fn make_config(config: &Config) -> rustls::ServerConfig {
    //    let client_auth = if args.flag_auth.is_some() {
    // let roots = load_certs(args.flag_auth.as_ref().unwrap());
    // let mut client_auth_roots = RootCertStore::empty();
    // for root in roots {
    // client_auth_roots.add(&root).unwrap();
    // }
    // if args.flag_require_auth {
    // AllowAnyAuthenticatedClient::new(client_auth_roots)
    // } else {
    // AllowAnyAnonymousOrAuthenticatedClient::new(client_auth_roots)
    // }
    // } else {
    // NoClientAuth::new()
    // };

    let client_auth = NoClientAuth::new();


    let suites = if !config.ssl.server().unwrap().cipher_tls13.is_empty() {
        lookup_suites(&config.ssl.server().unwrap().cipher_tls13)
    } else {
        rustls::ALL_CIPHER_SUITES.to_vec()
    };

    let versions =
        //     if !args.flag_protover.is_empty() {
        //     lookup_versions(&args.flag_protover)
        // } else {
        //     rustls::ALL_VERSIONS.to_vec()
        // };
        vec![&rustls::version::TLS13];

    let certs = load_certs(config.ssl.server().unwrap().cert.as_str());
    let privkey = load_private_key(config.ssl.server().unwrap().key.as_str());
    // let ocsp = load_ocsp(&args.flag_ocsp);

    let mut tls_config = rustls::ServerConfig::builder()
        .with_cipher_suites(&suites)
        .with_safe_default_kx_groups()
        .with_protocol_versions(&versions)
        .expect("inconsistent cipher-suites/versions specified")
        .with_client_cert_verifier(client_auth)
        // .with_single_cert_with_ocsp_and_sct(certs, privkey, ocsp, vec![])
        .with_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .expect("bad certificates/private key");

    tls_config.key_log = Arc::new(rustls::KeyLogFile::new());

    if config.ssl.server().unwrap().reuse_session {
        tls_config.session_storage = rustls::server::ServerSessionMemoryCache::new(256);
    }

    if config.ssl.server().unwrap().session_ticket {
        tls_config.ticketer = rustls::Ticketer::new().unwrap();
    }

    tls_config.alpn_protocols =
        config.ssl.server().unwrap().alpn.iter().map(|proto| proto.as_bytes().to_vec()).collect::<Vec<_>>();

    tls_config
}
