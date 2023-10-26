pub mod sub;

use chrono::{Datelike, Timelike, Utc};
use ldap3::{Ldap, LdapConn, LdapConnAsync, LdapError, ResultEntry, Scope, SearchEntry};
use log::{debug, info, error};
use tokio::time::sleep;
use std::{env, time::Duration, path::Path};
use std::collections::{HashSet, HashMap};

use crate::sub::app_config::AppConfig;
use crate::sub::synchronisation::Synchronisation;
use crate::sub::cf_services::LdapService;



/// main function.
/// reads configuration from environment variables
/// and calls syncronize() for every entry in SYNCHRONISATIONS.
#[tokio::main]
async fn main() {
    env_logger::init();
    info!("ldapsync main()");

    let app_config = AppConfig::from_cf_env();

    // map from config with names to synchronisations with references to LdapServices
    /*
    let synchronisations: Vec<Synchronisation> = app_config.synchronisation_configs
        .iter()
        .map(|sync_config| 
            Synchronisation::from_synchronisation_with_names(&app_config.ldap_services, sync_config)
        )
        .collect();
    */

    let synchronisations: Vec<Synchronisation> = app_config.synchronisation_configs
        .iter()
        .map(|sync_config|
            Synchronisation {
                ldap_services: &app_config.ldap_services,
                sync_config: sync_config,
                dry_run: app_config.dry_run,
                exclude_attrs: &app_config.exclude_attrs
            }
        )
        .collect();


    // endless loop/daemon
    loop {
        info!("Start synchronisations.");
        for synchro in synchronisations.iter() {
            let result = synchro.synchronize().await;
            match result {
                Ok(n) => info!("Synchronization was successfull. Number of entries synchronized: {}", n),
                Err(e) => error!("Synchronization failed. {:?}", e)
            }
        }
        info!("Sleep for {:?}.", app_config.job_sleep);
        sleep(app_config.job_sleep).await;
    }
    
}

#[cfg(test)]
mod test {
    //use super::*;
    //use indoc::*;
    //use ldap_test_server::{LdapServerBuilder, LdapServerConn};
    use pickledb::{PickleDb, PickleDbDumpPolicy, SerializationMethod};
    //use rstest::rstest;

    //use futures::executor::block_on;
    //use tokio::runtime;
    //use std::thread::sleep;
    //use std::time::Duration;
    //use log::debug;

    /*
    #[test]
    fn test_key_value_store() {
        let modify_timestamp = "20231020152100z";

        let url = "ldap://127.0.0.1:389".to_string();
        let base_dn = "o=XY,o=de,cn=Users,dc=test".to_string();

        let key = format!("{}/{}.modifyTimestamp", url, base_dn);

        let mut db = PickleDb::new(
            "example.db",
            PickleDbDumpPolicy::AutoDump,
            SerializationMethod::Json,
        );

        db.set(&key, &modify_timestamp).unwrap();

        let result = db.get::<String>(&key).unwrap();
        // print the value of key1
        debug!("The value of modifyTimestamp is: {}", result);
        assert_eq!(result, modify_timestamp)
    }
     */


}
