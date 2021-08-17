use crate::{
    acme,
    chall::Challenge,
    config::{CertConfig, Config},
    errors::*,
    persist::FilePersist
};
use std::fs;

fn should_request_cert(
    // args: &RenewArgs,
    config: &Config,
    persist: &FilePersist,
    cert: &CertConfig
) -> Result<bool> {
    // if args.force_renew {
    //     info!("{:?}: force renewing", cert.name);
    //     Ok(true)
    // } else
    if let Some(existing) = persist.load_cert_info(&cert.name)? {
        let days_left = existing.days_left();
        if days_left <= config.acme.renew_if_days_left {
            info!("{:?}: existing cert is below threshold", cert.name);
            Ok(true)
        } else {
            info!("{:?}: cert already satisfied", cert.name);
            Ok(false)
        }
    } else {
        info!("{:?}: creating new cert", cert.name);
        Ok(true)
    }
}

// fn execute_hooks(hooks: &[String], dry_run: bool) -> Result<()> {
//     for exec in hooks {
//         if dry_run {
//             info!("executing hook: {:?} (dry run)", exec);
//         } else {
//             info!("executing hook: {:?}", exec);
//
//             let status = Command::new("sh")
//                 .arg("-c")
//                 .arg(exec)
//                 .status()
//                 .context("Failed to spawn shell for hook")?;
//
//             if !status.success() {
//                 error!("Failed to execute hook: {:?}", exec);
//             }
//         }
//     }
//     Ok(())
// }

fn renew_cert(
    // args: &RenewArgs,
    config: &Config,
    persist: &FilePersist,
    cert: &CertConfig
) -> Result<()> {
    let mut challenge = Challenge::new(&config);

    if !should_request_cert(&config, &persist, &cert)? {
        debug!("Not requesting a certificate for {:?}", cert.name);
        return Ok(())
    }

    // if args.dry_run || args.hooks_only {
    //     info!("renewing {:?} (dry run)", cert.name);
    // } else {
    info!("renewing {:?}", cert.name);
    acme::request(persist.clone(), &mut challenge, &acme::Request {
        account_email: config.acme.acme_email.as_deref(),
        acme_url: &config.acme.acme_url,
        primary_name: &cert.name,
        alt_names: &cert.dns_names
    })
    .with_context(|| anyhow!("Fail to get certificate {:?}", cert.name))?;
    challenge.cleanup()?;
    // }

    // if !args.skip_restarts {
    //     if !cert.exec.is_empty() {
    //         debug!("Executing hooks for this certificate");
    //         execute_hooks(&cert.exec, args.dry_run)?;
    //     } else {
    //         debug!("Executing global default hooks");
    //         execute_hooks(&config.system.exec, args.dry_run)?;
    //     }
    //
    //     debug!("Executing global exec_extra hooks");
    //     execute_hooks(&config.system.exec_extra, args.dry_run)?;
    // }

    Ok(())
}

fn cleanup_certs(persist: &FilePersist, dry_run: bool) -> Result<()> {
    let live = persist.list_live_certs().context("Failed to list live certificates")?;
    for (version, name) in &live {
        debug!("cert used in live: {:?} -> {:?}", name, version);
    }

    let cert_list = persist.list_certs().context("Failed to list certificates")?;
    for (path, name, cert) in cert_list {
        if cert.days_left() >= 0 {
            debug!("cert {:?} is still valid, keeping it around", name);
        } else {
            if live.contains_key(&name) {
                debug!("cert {:?} is expired by still live, skipping", name);
                continue
            }

            if dry_run {
                debug!("cert {:?} is expired, would delete but dry run is enabled", name);
            } else {
                info!("cert {:?} is expired, deleting...", name);
                if let Err(err) = fs::remove_dir_all(&path) {
                    error!("Failed to delete {:?}: {:#}", name, err);
                }
            }
        }
    }

    Ok(())
}

pub fn run(config: &Config) -> Result<()> {
    let persist = FilePersist::new(config);

    // let filter = args.certs.drain(..).collect::<HashSet<_>>();
    // for cert in config.filter_certs(&filter) {
    for cert in &config.certs {
        if let Err(err) = renew_cert(config, &persist, cert) {
            error!("Failed to renew ({:?}): {:#}", cert.name, err);
        }
    }

    cleanup_certs(&persist, false).context("Failed to cleanup old certs")?;

    Ok(())
}
