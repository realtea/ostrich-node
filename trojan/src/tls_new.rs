use crate::config::Config;
use rsa::RsaPrivateKey;
use rustls::{self, server::NoClientAuth, Certificate as TlsCertificate, PrivateKey};
use rustls_pemfile::{self, Item};
use std::{
    fs,
    io::{self, BufReader, Error as IoError, Read},
    path::Path,
    sync::Arc
};
use x509_parser::prelude::Pem;
// use rsa::pkcs8::ToPrivateKey;
use rand::rngs::OsRng;
use rsa::pkcs8::EncodePrivateKey;

use rcgen::{date_time_ymd, Certificate, CertificateParams, DistinguishedName, DnType, SanType};
use std::convert::TryFrom;

use crate::parse::validate_certificate;
use rustls_pemfile::{certs, rsa_private_keys};
use std::{
    fs::{File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt
};
use x509_parser::{certificate::X509Certificate, parse_x509_certificate};

const PARSE_ERRORS_FATAL: bool = false;
const CERT_PATH: &str = "/etc/ostrich/certs/";
const PEM_FILE: &str = "/etc/ostrich/certs/fullchain.pem";
pub const DER_FILE: &str = "/etc/ostrich/certs/fullchain.der";
const PEM_KEY_FILE: &str = "/etc/ostrich/certs/private.pem";
const DER_KEY_FILE: &str = "/etc/ostrich/certs/private.der";
const CERT_LOG: &str = "/etc/ostrich/certs/generated.log";

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

fn load_certs(filename: &str) -> Vec<rustls::TlsCertificate> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader).unwrap().iter().map(|v| rustls::TlsCertificate(v.clone())).collect()
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
    let der_path = std::path::Path::new(DER_FILE);
    let der_key_path = std::path::Path::new(DER_KEY_FILE);

    if !der_path.exists() || !der_key_path.exists() {
        generate_tls_cert_file(config.local_addr.as_ref()).unwrap();
    }

    // parse
    let data = std::fs::read(DER_FILE.clone()).expect("Unable to read file");
    if !validate_certificate(&file_name, &data).unwrap() {
        generate_tls_cert_file(config.local_addr.as_ref()).unwrap();
    }

    let certs = certs::load_certificates(DER_FILE.as_ref())?;
    let privkey = certs::load_private_key(DER_KEY_FILE.as_ref())?;


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

    // let certs = load_certs(config.ssl.server().unwrap().cert.as_str());
    // let privkey = load_private_key(config.ssl.server().unwrap().key.as_str());
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
    tls_config.enable_early_data = true;
    tls_config
}
mod certs {
    use rustls::{Certificate, PrivateKey};
    use rustls_pemfile::Item;
    use std::{
        fs::{self, File},
        io::{BufReader, Error as IoError}
    };
    pub fn load_certificates(path: &str) -> Result<Vec<Certificate>, IoError> {
        let mut file = BufReader::new(File::open(path)?);
        let mut certs = Vec::new();

        while let Ok(Some(item)) = rustls_pemfile::read_one(&mut file) {
            if let Item::X509Certificate(cert) = item {
                certs.push(Certificate(cert));
            }
        }

        if certs.is_empty() {
            certs = vec![Certificate(fs::read(path)?)];
        }

        Ok(certs)
    }

    pub fn load_private_key(path: &str) -> Result<PrivateKey, IoError> {
        let mut file = BufReader::new(File::open(path)?);
        let mut priv_key = None;

        while let Ok(Some(item)) = rustls_pemfile::read_one(&mut file) {
            if let Item::RSAKey(key) | Item::PKCS8Key(key) | Item::ECKey(key) = item {
                priv_key = Some(key);
            }
        }

        priv_key.map(Ok).unwrap_or_else(|| fs::read(path)).map(PrivateKey)
    }
}

fn create(path: &Path, mode: u32) -> io::Result<File> {
    OpenOptions::new().write(true).create(true).truncate(true).mode(mode).open(path).map_err(|e| e)
}

fn write(path: &Path, mode: u32, data: &[u8]) -> io::Result<()> {
    let mut f = create(&path, mode)?;
    f.write_all(data)?;
    Ok(())
}

pub fn generate_tls_cert_file(server_name: &str) -> io::Result<()> {
    let now = chrono::Utc::now();
    use chrono::Datelike;
    let (_, year) = now.year_ce();
    let now_to_display = format!(
        "The latest generated time is {}-{:02}-{:02}-{:02}-{:02}-{:02} (UTC)",
        year,
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    // generate
    let mut params: CertificateParams = Default::default();
    params.not_before = date_time_ymd(2021, 05, 19);
    params.not_after = date_time_ymd(2022, 04, 19);
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::OrganizationName, "Crab widgits SE");
    params.distinguished_name.push(DnType::CommonName, "Master Cert");
    params.subject_alt_names =
        vec![/* SanType::DnsName("crabs.crabs".to_string()), */ SanType::DnsName(server_name.to_string())];
    params.alg = &rcgen::PKCS_RSA_SHA256;

    let pkey :openssl::pkey::PKey<_> = openssl::rsa::Rsa::generate(2048)?.try_into()?;
    let key_pair_pem = String::from_utf8(pkey.private_key_to_pem_pkcs8()?)?;
    let key_pair = rcgen::KeyPair::from_pem(&key_pair_pem)?;
    params.key_pair = Some(key_pair);

    let cert = Certificate::from_params(params)?;
    let pem_serialized = cert.serialize_pem()?;
    let der_serialized = pem::parse(&pem_serialized).unwrap().contents;
    let hash = ring::digest::digest(&ring::digest::SHA512, &der_serialized);
    let hash_hex :String = hash.as_ref().iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    println!("sha-512 fingerprint: {}", hash_hex);
    println!("{}", pem_serialized);
    println!("{}", cert.serialize_private_key_pem());
    std::fs::create_dir_all(CERT_PATH)?;
    write(PEM_FILE.as_ref(), 0o600, &pem_serialized.as_bytes())?;
    write(DER_FILE.as_ref(), 0o600, &der_serialized)?;
    write(PEM_KEY_FILE.as_ref(), 0o600, &cert.serialize_private_key_pem().as_bytes())?;
    write(DER_KEY_FILE.as_ref(), 0o600, &cert.serialize_private_key_der())?;

    write(CERT_LOG.as_ref(), 0o600, now_to_display.as_bytes())?;

    Ok(())
}

pub fn validate_certificate(file_name: &str, data: &[u8]) -> io::Result<bool> {
    match parse_x509_certificate(data) {
        Ok((_, x509)) => {
            if is_x509_expired(&x509).unwrap() {
                return Ok(false)
            }
            Ok(true)
        }
        Err(e) => {
            let s = format!("Error while parsing {}: {}", file_name, e);
            if PARSE_ERRORS_FATAL {
                Err(io::Error::new(io::ErrorKind::Other, s))
            } else {
                eprintln!("{}", s);
                Ok(true)
            }
        }
    }
}
fn is_x509_expired(x509: &X509Certificate) -> io::Result<bool> {
    let time_left = x509.validity().time_to_expiration();
    if time_left.is_none() {
        println!("#0:x509 is expired");
        return Ok(true)
    }

    if time_left.is_some() {
        if time_left.unwrap().whole_days() < 10 {
            println!("#1:x509 is expired");
            return Ok(true)
        }
    }

    Ok(false)
}
