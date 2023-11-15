pub mod app_config;
pub mod cf_services;
pub mod ldap_utils;
pub mod ldif;
//pub mod serde_search_entry;
pub mod rewrite_engine;
pub mod synchronization;
pub mod synchronization_config;
#[macro_use]
pub mod ldap_result_codes;

use crate::app_config::AppConfig;
use crate::ldap_result_codes::result_text;
use crate::synchronization::{SyncStatistics, Synchronization};
use chrono::{DateTime, Utc};
use env_logger::{Builder, Target};
use ldap3::{LdapError, LdapResult};
use log::{error, info};
use std::collections::HashMap;
use tokio::time::sleep;

/// main function.
/// reads configuration from environment variables.
/// If the configuration is ok, start the actual main function lets_go().
#[tokio::main]
async fn main() {
    init_rust_log();

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

/// write to stdout instead of stderr.
/// because cf (Cloud Foundry Command Line Interface) shows messages on stdterr in red, on stdout in white.
fn init_rust_log() {
    let mut builder = Builder::from_default_env();
    builder.target(Target::Stdout);
    builder.init();
    //env_logger::init();
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
    let mut synchronizations: Vec<Synchronization> = app_config
        .synchronization_configs
        .iter()
        .map(|sync_config| Synchronization {
            ldap_services: &app_config.ldap_services,
            sync_config: sync_config,
            dry_run: app_config.dry_run,
            filter: &app_config.filter,
            exclude_dns: &app_config.exclude_dns,
            attrs: &attrs_vec,
            exclude_attrs: &app_config.exclude_attrs,
            rewrite_rules: &app_config.rewrite_rules,
            old_sync_datetime: None,
        })
        .collect();

    // endless loop/daemon
    'daemon: loop {
        info!("Start synchronizations.");

        for synchro in synchronizations.iter_mut() {
            let result = synchro.synchronize().await;
            print_result_of_synchronizations(&result, synchro.old_sync_datetime);
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
                Err(_) | Ok(_) => {}
            }
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
    use super::*;
    use crate::app_config::*;
    use crate::ldap_utils::test::{
        assert_vec_search_entries_eq, next_port, search_all, start_test_server,
    };
    use crate::ldif::parse_ldif_as_search_entries;
    use indoc::indoc;
    use ldap3::LdapConnAsync;
    use log::debug;
    use std::collections::HashMap;
    use tokio::time::Duration;

    /// Integration test.
    /// It seems like the test LDAP server resets it's content for every new connection.
    /// Then, how to test?
    #[ignore]
    #[tokio::test]
    pub async fn test_params_read_simple_example() {
        let _ = env_logger::try_init();
        let source_plain_port = next_port();
        let source_url = format!("ldap://127.0.0.1:{}", source_plain_port);
        let _source_bind_dn = "cn=admin1,dc=test".to_string();
        let _source_password = "secret1".to_string();
        let source_base_dn = "dc=test".to_string();
        let source_content = indoc! { "
            dn: dc=test
            objectclass: dcObject
            objectclass: organization
            o: Test Org
            dc: test
            modifyTimestamp: 20231019182734Z

            dn: cn=admin1,dc=test
            objectClass: inetOrgPerson
            cn: admin
            sn: Admin
            userPassword: secret1
            modifyTimestamp: 20231019182735Z

            dn: ou=Users,dc=test
            objectClass: top
            objectClass: organizationalUnit
            ou: Users
            modifyTimestamp: 20231019182736Z
            description: additional attribute

            # to be modified
            dn: cn=xy012345,ou=Users,dc=test
            cn: xy012345
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: new_password!
            modifyTimestamp: 20231019182739Z
            description: changed
            
            # to be added
            dn: cn=new012345,ou=Users,dc=test
            cn: new012345
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: some_password!
            modifyTimestamp: 20231019182739Z
            description: changed"
        };

        let target_plain_port = next_port();
        let target_url = format!("ldap://127.0.0.1:{}", target_plain_port);
        let target_bind_dn = "cn=admin2,dc=test".to_string();
        let target_password = "secret2".to_string();
        let target_base_dn = "dc=test".to_string();
        let target_content = indoc! { "
            dn: dc=test
            objectclass: dcObject
            objectclass: organization
            o: Test Org
            dc: test

            dn: cn=admin2,dc=test
            objectClass: inetOrgPerson
            cn: admin2
            sn: Admin
            userPassword: secret2
    
            # to be modified
            dn: ou=Users,dc=test
            objectClass: top
            objectClass: organizationalUnit
            ou: Users
        
            # to be deleted
            dn: o=de,ou=Users,dc=test
            ObjectClass: top
            objectClass: organization
            o: de
            
            # to be modified
            dn: cn=xy012345,ou=Users,dc=test
            cn: xy012345
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: old_password!"
        };
        let _server1 = start_test_server(source_plain_port, &source_base_dn, source_content).await;
        let _server2 = start_test_server(target_plain_port, &target_base_dn, target_content).await;

        let ldap_service1_templ = r#"{"name": "ldap1", "credentials": {"base_dn": "dc=test", "bind_dn": "cn=admin1,dc=test", "password": "secret1", "url": "url1"}}"#;
        let ldap_service2_templ = r#"{"name": "ldap2", "credentials": {"base_dn": "dc=test", "bind_dn": "cn=admin2,dc=test", "password": "secret2", "url": "url2"}}"#;
        let ldap_service1 = ldap_service1_templ.replace("url1", &source_url);
        let ldap_service2 = ldap_service2_templ.replace("url2", &target_url);
        let vcap_services_templ = indoc! {r#"
            {
                "user-provided": [
                    service1,
                    service2
                ]
            }"#};
        let vcap_services_json = vcap_services_templ
            .replace("service1", &ldap_service1.to_string())
            .replace("service2", &ldap_service2.to_string());

        let synchronizations_json = indoc! {r#"
        [{
            "source":"ldap1",
            "target":"ldap2",
            "base_dns":["ou=Users"]
        }]
        "#}
        .to_string();

        let params_map = HashMap::from([
            (DAEMON, "false".to_string()),
            (DRY_RUN, "false".to_string()),
            (VCAP_SERVICES, vcap_services_json),
            (SYNCHRONIZATIONS, synchronizations_json),
            (ATTRS, "*".to_string()),
        ]);

        let expected_search_entries = parse_ldif_as_search_entries(indoc! {"
            dn: dc=test
            objectclass: dcObject
            objectclass: organization
            o: Test Org
            dc: test

            dn: cn=admin2,dc=test
            objectClass: inetOrgPerson
            cn: admin2
            sn: Admin
            userPassword: secret2

            dn: ou=Users,dc=test
            objectClass: top
            objectClass: organizationalUnit
            ou: Users

            # to be modified
            dn: cn=xy012345,ou=Users,dc=test
            cn: xy012345
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: new_password!
            description: changed
        
            # to be added
            dn: cn=new012345,ou=users,dc=test
            cn: new012345
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: some_password!
            description: changed"
        })
        .unwrap();

        debug!("{:?}", &params_map);
        params_read(&params_map).await;

        sleep(Duration::from_millis(1000)).await;
        let (conn, mut target_ldap) = LdapConnAsync::new(&target_url).await.unwrap();
        ldap3::drive!(conn);
        target_ldap
            .simple_bind(&target_bind_dn, &target_password)
            .await
            .unwrap();
        let target_entries_after = search_all(&mut target_ldap, &target_base_dn).await.unwrap();
        debug!("target entries after: {:?}", target_entries_after);

        assert_vec_search_entries_eq(&target_entries_after, &expected_search_entries);
    }
}
