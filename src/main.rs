pub mod app_config;
pub mod cf_services;
pub mod ldap_utils;
pub mod ldif;
pub mod serde_search_entry;
pub mod synchronization;
pub mod synchronization_config;
#[macro_use]
pub mod ldap_result_codes;

use crate::app_config::AppConfig;
use crate::ldap_result_codes::result_text;
use crate::synchronization::Synchronization;
use chrono::Utc;
use ldap3::{LdapError, LdapResult};
use log::{error, info};
use tokio::time::sleep;

/// main function.
/// reads configuration from environment variables
/// and calls syncronize() for every entry in SYNCHRONISATIONS.
#[tokio::main]
async fn main() {
    env_logger::init();
    info!("ldapsync main()");

    let app_config = AppConfig::from_cf_env();
    match app_config {
        Ok(app_config) => {
            let synchronizations: Vec<Synchronization> = app_config
                .synchronization_configs
                .iter()
                .map(|sync_config| Synchronization {
                    ldap_services: &app_config.ldap_services,
                    sync_config: sync_config,
                    dry_run: app_config.dry_run,
                    exclude_attrs: &app_config.exclude_attrs,
                })
                .collect();

            // At the very first run there is no synchronisation timestamp.
            // All entries of the subtrees are read from source directory.
            let mut old_sync_datetime = None;

            // endless loop/daemon
            loop {
                info!("Start synchronizations.");
                let mut new_sync_datetime = Utc::now();

                for synchro in synchronizations.iter() {
                    let result = synchro.synchronize(old_sync_datetime).await;
                    match result {
                        Ok(stats) => info!(
                            "Synchronization was successful. Entires recently modified: {}, added: {}, attributes modified: {}, deleted: {}",
                            stats.recently_modified, stats.added, stats.attrs_modified, stats.deleted
                        ),
                        Err(err) => {
                            error!("Synchronization failed. {:?}", err);
                            match err {
                                LdapError::LdapResult{ result: LdapResult { rc: result_code, .. }} => { error!("result code description (from RfC 4511): {}", result_text(result_code))},
                                _ => {}
                            }
                        }
                    }
                }

                // todo one timestamp for every sync-subtree (2-dimensional Vec)
                if !app_config.dry_run {
                    old_sync_datetime = Some(new_sync_datetime);
                }

                match app_config.job_sleep {
                    Some(s) => {
                        info!("Sleep for {:?}.", s);
                        sleep(s).await
                    }
                    None => {}
                };
                if !app_config.daemon {
                    break;
                }
            }
        },
        Err(err) => {
            error!("Configuration Error: {:?}", err);
        },
    }
}

#[cfg(test)]
mod test {
    //use super::*;
}
