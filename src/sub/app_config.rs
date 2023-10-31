use log::debug;
use regex::Regex;
use std::{collections::HashMap, env, env::VarError, str::FromStr, time::Duration};
use crate::sub::cf_services::{map_ldap_services, parse_service_types, LdapService};
use crate::sub::synchronization_config::SynchronizationConfig;

/// names of environment variables
pub const VCAP_SERVICES: &str = "VCAP_SERVICES";
pub const SYNCHRONIZATIONS: &str = "SYNCHRONIZATIONS";
pub const EXCLUDE_ATTRS: &str = "EXCLUDE_ATTRS";
pub const JOB_SLEEP: &str = "JOB_SLEEP";
pub const DRY_RUN: &str = "DRY_RUN";

#[derive(Debug)]
pub enum LdapServiceUsage {
    Source,
    Target,
    TsStore,
}

#[derive(Debug)]
pub enum AppConfigError {
    EnvVarError {
        env_var_name: String,
        cause: VarError,
    },
    EnvVarParseError {
        env_var_name: String,
    },
    EnvVarParseRegexError {
        env_var_name: String,
        cause: regex::Error,
    },
    EnvVarParseJsonError {
        env_var_name: String,
        cause: serde_json::Error,
    },
    LdapServiceMissing {
        service_name: String,
        synchronisation_index: usize,
        usage: LdapServiceUsage,
    },
    LdapServiceNameNotUnique
}

#[derive(Debug)]
pub struct AppConfig {
    pub job_sleep: Duration,
    pub dry_run: bool,
    pub exclude_attrs: Regex,
    pub ldap_services: HashMap<String, LdapService>,
    pub synchronization_configs: Vec<SynchronizationConfig>,
}

impl AppConfig {
    /// example input "15 min" or "10 sec"
    pub fn parse_duration(hay: &str) -> Option<Duration> {
        let re = Regex::new(r" *([0-9]+) *(sec|min) *").unwrap(); // assumption: works always or never
        let captures = re.captures(hay)?;

        let number_str = captures.get(1).unwrap().as_str();
        let unit_str = captures.get(2).unwrap().as_str();
        let number = number_str.parse().unwrap();
        if unit_str == "sec" {
            Some(Duration::from_secs(number))
        } else {
            Some(Duration::from_secs(number * 60))
        }
    }

    pub fn from_cf_env() -> Result<AppConfig, AppConfigError> {
        debug!("from_cf_env()");

        let synchronizations_str =
            env::var(SYNCHRONIZATIONS).map_err(|err| AppConfigError::EnvVarError {
                env_var_name: SYNCHRONIZATIONS.to_string(),
                cause: err,
            })?;
        debug!("SYNCHRONIZATIONS: {}", synchronizations_str);
        let synchronizations_vec = SynchronizationConfig::parse_synchronizations(
            &synchronizations_str,
        )
        .map_err(|err| AppConfigError::EnvVarParseJsonError {
            env_var_name: SYNCHRONIZATIONS.to_string(),
            cause: err,
        })?;

        let vcap_services_str =
            env::var(VCAP_SERVICES).map_err(|err| AppConfigError::EnvVarError {
                env_var_name: VCAP_SERVICES.to_string(),
                cause: err,
            })?;
        debug!("VCAP_SERVICES: {:?}", vcap_services_str);
        let vcap_service_types = parse_service_types(&vcap_services_str).map_err(|err| {
            AppConfigError::EnvVarParseJsonError {
                env_var_name: SYNCHRONIZATIONS.to_string(),
                cause: err,
            }
        })?;
        let ldap_services_map = map_ldap_services(&vcap_service_types.user_provided)
            .map_err(|_| AppConfigError::LdapServiceNameNotUnique)?;
        debug!("ldap services by names: {:?}", ldap_services_map);

        for (index, sync_config) in synchronizations_vec.iter().enumerate() {
            if !ldap_services_map.contains_key(&sync_config.source) {
                return Err(AppConfigError::LdapServiceMissing {
                    service_name: sync_config.source.clone(),
                    synchronisation_index: index,
                    usage: LdapServiceUsage::Source,
                });
            }
            if !ldap_services_map.contains_key(&sync_config.target) {
                return Err(AppConfigError::LdapServiceMissing {
                    service_name: sync_config.target.clone(),
                    synchronisation_index: index,
                    usage: LdapServiceUsage::Target,
                });
            }
            if !ldap_services_map.contains_key(&sync_config.ts_store) {
                return Err(AppConfigError::LdapServiceMissing {
                    service_name: sync_config.target.clone(),
                    synchronisation_index: index,
                    usage: LdapServiceUsage::TsStore,
                });
            }
        }

        let exclude_attrs_str =
            env::var(EXCLUDE_ATTRS).map_err(|err| AppConfigError::EnvVarError {
                env_var_name: EXCLUDE_ATTRS.to_string(),
                cause: err,
            })?;
        debug!("EXCLUDE_ATTRS: {}", exclude_attrs_str);
        let exclude_attrs_pattern = Regex::new(&exclude_attrs_str).map_err(|err| {
            AppConfigError::EnvVarParseRegexError {
                env_var_name: EXCLUDE_ATTRS.to_string(),
                cause: err,
            }
        })?;

        let job_sleep_str = env::var(JOB_SLEEP).map_err(|err| AppConfigError::EnvVarError {
            env_var_name: JOB_SLEEP.to_string(),
            cause: err,
        })?;
        debug!("JOB_SLEEP: {}", job_sleep_str);
        let job_sleep_duration =
            Self::parse_duration(&job_sleep_str).ok_or(AppConfigError::EnvVarParseError {
                env_var_name: JOB_SLEEP.to_string(),
            })?;

        let dry_run_str = env::var(DRY_RUN).map_err(|err| AppConfigError::EnvVarError {
            env_var_name: DRY_RUN.to_string(),
            cause: err,
        })?;
        debug!("DRY_RUN: {}", dry_run_str);
        let dry_run_bool =
            bool::from_str(&dry_run_str).map_err(|_| AppConfigError::EnvVarParseError {
                env_var_name: DRY_RUN.to_string(),
            })?;

        let config = AppConfig {
            job_sleep: job_sleep_duration,
            dry_run: dry_run_bool,
            exclude_attrs: exclude_attrs_pattern,
            ldap_services: ldap_services_map,
            synchronization_configs: synchronizations_vec,
        };
        Ok(config)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use indoc::*;
    use rstest::*;

    // todo write unit tests with errors in configuration. Are error messages user friendly?
    #[test]
    fn test_from_cf_env_valid() {
        env::set_var("JOB_SLEEP", "10 sec");
        env::set_var("DRY_RUN", "true");
        env::set_var(
            "EXCLUDE_ATTRS",
            "^(?i)(authPassword|orclPassword|orclAci|orclEntryLevelAci)$",
        );
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
            "SYNCHRONIZATIONS",
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

        let app_config = AppConfig::from_cf_env().unwrap();
        debug!("app_config: {:?}", app_config);
        assert_eq!(app_config.job_sleep, Duration::from_secs(10));
        assert_eq!(app_config.dry_run, true);
        assert_eq!(
            app_config.exclude_attrs.as_str(),
            "^(?i)(authPassword|orclPassword|orclAci|orclEntryLevelAci)$"
        );
        assert_eq!(app_config.ldap_services.len(), 2);
        assert!(app_config.ldap_services.contains_key("ldap1"));
        assert!(app_config.ldap_services.contains_key("ldap2"));
        assert_eq!(app_config.synchronization_configs.len(), 1);
        //todo more asserts
    }

    /// test with --test-threads=1
    #[test]
    fn test_from_cf_env_missing_env_var() {
        env::remove_var(VCAP_SERVICES.to_string());
        env::remove_var(SYNCHRONIZATIONS.to_string());

        let app_config = AppConfig::from_cf_env();
        debug!("app_config: {:?}", app_config);
        assert!(app_config.is_err());
        let err = app_config.expect_err("AppConfigError was expected as result");

        match err {
            AppConfigError::EnvVarError {
                env_var_name: name,
                cause: err,
            } => {
                assert_eq!(name, SYNCHRONIZATIONS);
                assert_eq!(err, VarError::NotPresent);
            }
            _ => {
                panic!("wrong error enum variant");
            }
        }
    }

    /// test with --test-threads=1
    #[test]
    fn test_from_cf_env_synchronizations_invalid_json() {
        env::remove_var(VCAP_SERVICES.to_string());
        env::set_var(SYNCHRONIZATIONS, "[ { Unsinn } ]");
        let app_config = AppConfig::from_cf_env();
        debug!("app_config: {:?}", app_config);
        assert!(app_config.is_err());
        let err = app_config.expect_err("AppConfigError was expected as result");
        debug!("{:?}", err);
        match err {
            AppConfigError::EnvVarParseJsonError {
                env_var_name: name,
                cause: err,
            } => {
                assert_eq!(name, SYNCHRONIZATIONS);
                assert_eq!(err.line(), 1);
                assert_eq!(err.column(), 5);
                assert_eq!(err.classify(), serde_json::error::Category::Syntax);
                assert_eq!(err.to_string(), "key must be a string at line 1 column 5");
            }
            _ => {
                panic!("wrong error enum variant");
            }
        }
    }

    /// test with --test-threads=1
    #[test]
    fn test_from_cf_env_vcap_services_invalid_json() {
        env::remove_var(VCAP_SERVICES.to_string());
        env::set_var(SYNCHRONIZATIONS, "[ { Unsinn } ]");
        let app_config = AppConfig::from_cf_env();
        debug!("app_config: {:?}", app_config);
        assert!(app_config.is_err());
        let err = app_config.expect_err("AppConfigError was expected as result");
        debug!("{:?}", err);
        match err {
            AppConfigError::EnvVarParseJsonError {
                env_var_name: name,
                cause: err,
            } => {
                assert_eq!(name, SYNCHRONIZATIONS);
                assert_eq!(err.line(), 1);
                assert_eq!(err.column(), 5);
                assert_eq!(err.classify(), serde_json::error::Category::Syntax);
                assert_eq!(err.to_string(), "key must be a string at line 1 column 5");
            }
            _ => {
                panic!("wrong error enum variant");
            }
        }
    }

    #[rstest]
    #[case("10 sec", Some(Duration::from_secs(10)))]
    #[case("1 min", Some(Duration::from_secs(60)))]
    #[case(" 60  min ", Some(Duration::from_secs(60 * 60)))]
    #[case("eine Ewigkeit", None)]
    #[case("13 Minütchen", None)]
    fn test_parse_duration(#[case] hay: &str, #[case] expected: Option<Duration>) {
        let result = AppConfig::parse_duration(hay);
        assert_eq!(result, expected);
    }
}
