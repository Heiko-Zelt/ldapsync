pub mod app_config;
pub mod cf_services;
pub mod ldap_utils;
pub mod ldif;
//pub mod serde_search_entry;
pub mod synchronization;
pub mod synchronization_config;
#[macro_use]
pub mod ldap_result_codes;

use crate::app_config::AppConfig;
use crate::ldap_result_codes::result_text;
use crate::synchronization::{SyncStatistics, Synchronization};
use chrono::{DateTime, Utc};
use ldap3::{LdapError, LdapResult};
use log::{error, info};
use tokio::time::sleep;
use std::collections::HashMap;

/// main function.
/// reads configuration from environment variables.
/// If the configuration is ok, start the actual main function lets_go().
#[tokio::main]
async fn main() {
    env_logger::init();
    info!("{}", "ldapsync main()");
    AppConfig::log_platform_info();
    let read_result = AppConfig::read_env_vars();
    match read_result {
        Ok(params_map) => {
            params_read(&params_map).await;
        }
        Err(err) => {
            error!("Error reading environment variables: {:?}", err);
        }
    }
    info!("Program finished.")
}

/// after environment variables have been read
async fn params_read(params_map: &HashMap<&str, String>) {
    let config_result = AppConfig::from_map(params_map);
    match config_result {
        Ok(app_config) => {
            lets_go(&app_config).await;
        }
        Err(err) => {
            error!("Configuration error: {:?}", err);
        }
    }
}


/// Actual main function, after configuration has been read and verified.
/// Initializes 2 more variables and
/// in an endless loop call synchronize() for every synchronization.
async fn lets_go(app_config: &AppConfig) {
    let attrs_vec = Vec::from_iter(app_config.attrs.iter().cloned());
    let synchronizations: Vec<Synchronization> = app_config
        .synchronization_configs
        .iter()
        .map(|sync_config| Synchronization {
            ldap_services: &app_config.ldap_services,
            sync_config: sync_config,
            dry_run: app_config.dry_run,
            attrs: &attrs_vec,
            exclude_attrs: &app_config.exclude_attrs,
        })
        .collect();

    // At the very first run there is no synchronisation timestamp.
    // All entries of the subtrees are read from source directory.
    let mut old_sync_datetime = None;

    // endless loop/daemon
    'daemon: loop {
        info!("Start synchronizations.");
        let new_sync_datetime = Utc::now();

        for synchro in synchronizations.iter() {
            let result = synchro.synchronize(old_sync_datetime).await;
            print_result_of_synchronizations(&result, old_sync_datetime);
            // Some errors need a configuration change and restart, others may be caused by a temporary problem.
            match result {
                Err(
                    LdapError::EmptyUnixPath
                    | LdapError::PortInUnixPath
                    | LdapError::FilterParsing
                    | LdapError::UrlParsing { .. }
                    | LdapError::UnknownScheme(_)
                    | LdapError::AddNoValues
                    | LdapError::InvalidScopeString(_)
                    | LdapError::UnrecognizedCriticalExtension(_),
                ) => break 'daemon,
                Err(_) |Ok(_) => {},
            }
        }

        // TODO Prio 3: one timestamp for every sync-subtree (2-dimensional Vec)
        if !app_config.dry_run {
            info!(
                "replacing old timestamp {:?} with new timestamp {:?}.",
                old_sync_datetime, new_sync_datetime
            );
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
}

/// print the result of the synchrinzations, whether it was successful or not
fn print_result_of_synchronizations(
    sync_result: &Result<SyncStatistics, LdapError>,
    old_sync_datetime: Option<DateTime<Utc>>,
) {
    match sync_result {
        Ok(stats) => {
            let sync_type_description = match old_sync_datetime {
                Some(_) => "Recently modified",
                None => "All",
            };
            info!(
            "Synchronization was successful. {} entries: {}. Entries changed: added: {}, attributes modified: {}, deleted: {}",
            sync_type_description, stats.recently_modified, stats.added, stats.attrs_modified, stats.deleted
        );
        }
        Err(err) => {
            error!("Synchronization failed. {:?}", err);
            match err {
                LdapError::LdapResult {
                    result:
                        LdapResult {
                            rc: result_code, ..
                        },
                } => {
                    error!(
                        "result code description (from RfC 4511): {}",
                        result_text(*result_code)
                    )
                }
                _ => {}
            }
        }
    }
}

#[cfg(test)]
mod test {
    //use super::*;

    // TODO Prio 1: write test for lets_go() and print_result_of_synchronizations()
}
