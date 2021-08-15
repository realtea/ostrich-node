// use crate::errors::*;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use errors::{Result, Error};
use anyhow::{bail,anyhow,Context};
const LETSENCRYPT: &str = "https://acmed-v02.api.letsencrypt.org/directory";
// const LETSENCRYPT_STAGING: &str = "https://acme-staging-v02.api.letsencrypt.org/directory";
pub const DEFAULT_RENEW_IF_DAYS_LEFT: i64 = 30;

// #[derive(Debug, PartialEq, Deserialize)]
// pub struct ConfigFile {
//     #[serde(default)]
//     pub acmed: AcmeConfig,
//     #[serde(default)]
//     pub system: SystemConfig,
// }

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct AcmeConfig {
    pub acme_email: Option<String>,
    pub acme_url: String,
    pub renew_if_days_left: i64,
}

#[derive(Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemConfig {
    pub data_dir: PathBuf,
    pub chall_dir: PathBuf,
}

#[derive(Debug, PartialEq, Deserialize)]
pub struct CertConfigFile {
    cert: CertConfig,
}

fn load_str<T: DeserializeOwned>(s: &str) -> Result<T> {
    let conf = toml::from_str(&s).context("Failed to load config")?;
    Ok(conf)
}

fn load_file<P: AsRef<Path>, T: DeserializeOwned>(path: P) -> Result<T> {
    let buf = fs::read_to_string(path.as_ref()).context("Failed to read file")?;
    load_str(&buf)
}

fn load_from_folder<P: AsRef<Path>>(path: P) -> Result<Vec<CertConfigFile>> {
    let mut configs = Vec::new();
    let iter = fs::read_dir(path.as_ref())
        .with_context(|| anyhow!("Failed to list directory: {:?}", path.as_ref()))?;

    for file in iter {
        let file = file?;
        let path = file.path();

        if path.extension() == Some(OsStr::new("conf")) {
            let c = load_file(&path)
                .with_context(|| anyhow!("Failed to load config file {:?}", path))?;
            configs.push(c);
        } else {
            debug!("skipping non-config file {:?}", path);
        }
    }
    Ok(configs)
}

#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct CertConfig {
    pub name: String,
    pub dns_names: Vec<String>,
    #[serde(default)]
    pub must_staple: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub certs: Vec<CertConfig>,
    pub acme: AcmeConfig,
    pub system: SystemConfig,
}

impl Config {
    pub fn filter_certs<'a>(
        &'a self,
        filter: &'a HashSet<String>,
    ) -> impl Iterator<Item = &'a CertConfig> {
        self.certs
            .iter()
            .filter(move |cert| filter.is_empty() || filter.contains(&cert.name))
    }
}

pub fn load(path: &str) -> Result<Config> {
    let mut settings = config::Config::default();

    settings.set_default("acmed.acme_url", LETSENCRYPT).map_err(|e| Error::Eor(anyhow::anyhow!("{:?}",e)))?;
    settings.set_default("acmed.renew_if_days_left", DEFAULT_RENEW_IF_DAYS_LEFT).map_err(|e| Error::Eor(anyhow::anyhow!("{:?}",e)))?;

    settings.set_default("system.data_dir", "/var/lib/acmed-redirect").map_err(|e| Error::Eor(anyhow::anyhow!("{:?}",e)))?;
    settings.set_default("system.chall_dir", "/run/acmed-redirect").map_err(|e| Error::Eor(anyhow::anyhow!("{:?}",e)))?;

    settings
        .merge(config::File::new(path, config::FileFormat::Json))
        .with_context(|| anyhow!("Failed to load config file {:?}", path)).map_err(|e| Error::Eor(anyhow::anyhow!("{:?}",e)))?;


    let config = settings
        .try_into::<Config>()
        .context("Failed to parse config").map_err(|e| Error::Eor(anyhow::anyhow!("{:?}",e)))?;

    // let certs = load_from_folder(&args.config_dir)?
    //     .into_iter()
    //     .map(|c| c.cert)
    //     .collect();

    Ok(config)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_cert_conf() {
        let conf = load_str::<CertConfigFile>(
            r#"
            [cert]
            name = "example.com"
            dns_names = ["example.com", "www.example.com"]
        "#,
        )
        .unwrap();

        assert_eq!(
            conf,
            CertConfigFile {
                cert: CertConfig {
                    name: "example.com".to_string(),
                    dns_names: vec!["example.com".to_string(), "www.example.com".to_string(),],
                    must_staple: false,
                },
            }
        );
    }
}
