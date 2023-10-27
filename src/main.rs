pub mod sub;

use log::{debug, info, error};
use tokio::time::sleep;

use crate::sub::app_config::AppConfig;
use crate::sub::synchronization::Synchronization;

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
            let synchronizations: Vec<Synchronization> = app_config.synchronization_configs
                .iter()
                .map(|sync_config|
                        Synchronization {
                            ldap_services: &app_config.ldap_services,
                            sync_config: sync_config,
                            dry_run: app_config.dry_run,
                            exclude_attrs: &app_config.exclude_attrs
                        }
                )
                .collect();
        
            // endless loop/daemon
            loop {
                info!("Start synchronizations.");
                for synchro in synchronizations.iter() {
                    let result = synchro.synchronize().await;
                    match result {
                        Ok(stats) => info!(
                            "Synchronization was successfull. Entries added: {}, modified: {}, deleted: {}",
                            stats.added, stats.modified, stats.deleted
                        ),
                        Err(e) => error!("Synchronization failed. {:?}", e)
                    }
                }
                info!("Sleep for {:?}.", app_config.job_sleep);
                sleep(app_config.job_sleep).await;
            }
        },
        Err(err) => {
            error!("Configuration Error: {:?}", err);
        }
    }
    // todo for every synchronisation: create entry to store synchronisation timestamps
    
}

#[cfg(test)]
mod test {
    //use super::*;


}
