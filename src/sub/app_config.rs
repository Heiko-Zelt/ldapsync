use log::{debug, error, info};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::{env, str::FromStr, time::Duration};

use crate::sub::synchronisation_config::SynchronisationConfig;
use crate::sub::cf_services::{get_ldap_services_by_names, LdapService};


#[derive(Debug)]
pub struct AppConfig {
    pub job_sleep: Duration,
    pub dry_run: bool,
    pub ldap_services: HashMap<String, LdapService>,
    pub synchronisation_configs: Vec<SynchronisationConfig>, // todo change to syncronisations (with refs)
}

impl AppConfig {
    /// example input "15 min" or "10 sec"
    /// todo error handling, return Result
    pub fn parse_duration(hay: &str) -> Duration {
        let re = Regex::new(r" *([0-9]+) *(sec|min) *").unwrap();
        let caps = re.captures(hay).unwrap();
        let number_str = caps.get(1).unwrap().as_str();
        let unit_str = caps.get(2).unwrap().as_str();
        let number = number_str.parse().unwrap();
        if unit_str == "sec" {
            Duration::from_secs(number)
        } else {
            Duration::from_secs(number * 60)
        }
    }

    pub fn from_cf_env() -> AppConfig {
        debug!("from_cf_env()");
        let job_sleep_str = env::var("JOB_SLEEP").unwrap();
        debug!("JOB_SLEEP: {}", job_sleep_str);
        let dry_run_str = env::var("DRY_RUN").unwrap();
        debug!("DRY_RUN: {}", dry_run_str);

        debug!("VCAP_SERVICES: {:?}", env::var("VCAP_SERVICES"));
        let ldap_services_map = get_ldap_services_by_names().unwrap();
        debug!("ldap services by names: {:?}", ldap_services_map);
        
        let synchronisations_json = env::var("SYNCHRONISATIONS").unwrap();
        debug!("SYNCHRONISATIONS: {}", synchronisations_json);

        //let synchronisations_vec = Vec::new();

        let synchronisations_vec =
            SynchronisationConfig::parse_synchronisations(&synchronisations_json);
        // todo parse services & synchronsations

        let config = AppConfig {
            job_sleep: Self::parse_duration(&job_sleep_str),
            dry_run: bool::from_str(&dry_run_str).unwrap(),
            ldap_services: ldap_services_map,
            synchronisation_configs: synchronisations_vec,
        };
        config
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use indoc::*;
    use rstest::*;

    #[test]
    fn test_from_cf_env() {
        env::set_var("JOB_SLEEP", "10 sec");
        env::set_var("DRY_RUN", "true");
        env::set_var(
            "VCAP_SERVICES",
            indoc! {r#"{
            "user-provided": [
                {
                    "name": "ldap1",
                    "credentials": {
                        "base_dn": "dc=de",
                        "bind_dn": "cn=admin1,dc=de",
                        "password": "secret1",
                        "url": "ldap://ldap1.provider.de:389"
                     }
                },
                {
                    "name": "ldap2",
                    "credentials": {
                        "base_dn": "dc=de",
                        "bind_dn": "cn=admin2,dc=de",
                        "password": "secret2",
                        "url": "ldap://ldap2.consumer.de:389"
                    }
                }
            ]
        }"#},
        );
        env::set_var(
            "SYNCHRONISATIONS",
            indoc! {r#"
            [{
                "source":"ldap1",
                "target":"ldap2",
                "base_dns":["cn=users","cn=groups"],
                "ts_store":"ldap2",
                "ts_dn":"o=ldap1-ldap2,o=sync_timestamps"
            }]
        "#},
        );

        let app_config = AppConfig::from_cf_env();
        debug!("app_config: {:?}", app_config);
        //todo assert
    }

    #[rstest]
    #[case("10 sec", Duration::from_secs(10))]
    #[case("1 min", Duration::from_secs(60))]
    #[case(" 60  min ", Duration::from_secs(60 * 60))]
    fn test_parse_duration(#[case] hay: &str, #[case] expected: Duration) {
        let result = AppConfig::parse_duration(hay);
        assert_eq!(result, expected);
    }
    
}
