use crate::cf_services::{map_ldap_services, parse_service_types, LdapService};
use crate::synchronization_config::SynchronizationConfig;
use log::debug;
use regex::Regex;
use std::{collections::HashMap, env, env::VarError, str::FromStr, time::Duration};

/// names of environment variables
pub const VCAP_SERVICES: &str = "VCAP_SERVICES";
pub const SYNCHRONIZATIONS: &str = "LS_SYNCHRONIZATIONS";
pub const DAEMON: &str = "LS_DAEMON";
pub const EXCLUDE_ATTRS: &str = "LS_EXCLUDE_ATTRS";
pub const JOB_SLEEP: &str = "LS_SLEEP";
pub const DRY_RUN: &str = "LS_DRY_RUN";

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
    LdapServiceNameNotUnique,
    DaemonButNoSleep,
    SleepButNoDaemon,
}

#[derive(Debug)]
pub struct AppConfig {
    pub daemon: bool,
    pub job_sleep: Option<Duration>,
    pub dry_run: bool,
    pub exclude_attrs: Option<Regex>,
    pub ldap_services: HashMap<String, LdapService>,
    pub synchronization_configs: Vec<SynchronizationConfig>,
}

impl AppConfig {

    /// read env vars, parse UTF8 strings and store the result in a map
    fn read_env_vars() -> Result<HashMap<&'static str, String>, AppConfigError> {
        let mut env_map = HashMap::new();
        let allowed_var_names = [
            VCAP_SERVICES,
            SYNCHRONIZATIONS,
            DAEMON,
            EXCLUDE_ATTRS,
            JOB_SLEEP,
            DRY_RUN,
        ];
        for name in allowed_var_names {
            match env::var(name) {
                Ok(v) => {
                    env_map.insert(name, v);
                }
                Err(VarError::NotPresent) => {}
                Err(err) => {
                    return Err(AppConfigError::EnvVarError {
                        env_var_name: EXCLUDE_ATTRS.to_string(),
                        cause: err,
                    });
                }
            }
        }
        Ok(env_map)
    }

    /// example input "15 min" or "10 sec"
    fn parse_duration(hay: &str) -> Option<Duration> {
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

    /// check some conditions
    fn analyze_semantic(&self) -> Option<AppConfigError> {
        if self.daemon && self.job_sleep.is_none() {
            return Some(AppConfigError::DaemonButNoSleep);
        }
        if !self.daemon && self.job_sleep.is_some() {
            return Some(AppConfigError::SleepButNoDaemon);
        }
        // is an LDAP service configured for every service name (source and target) reference?
        for (index, sync_config) in self.synchronization_configs.iter().enumerate() {
            if !self.ldap_services.contains_key(&sync_config.source) {
                return Some(AppConfigError::LdapServiceMissing {
                    service_name: sync_config.source.clone(),
                    synchronisation_index: index,
                    usage: LdapServiceUsage::Source,
                });
            }
            if !self.ldap_services.contains_key(&sync_config.target) {
                return Some(AppConfigError::LdapServiceMissing {
                    service_name: sync_config.target.clone(),
                    synchronisation_index: index,
                    usage: LdapServiceUsage::Target,
                });
            }
        }
        None
    }

    /// parse regular expesssions, booleans and JSON code in the configuration
    fn parse(param_map: HashMap<&str, String>) -> Result<AppConfig, AppConfigError> {
        let synchronizations_vec = match param_map.get(SYNCHRONIZATIONS) {
            Some(s) => {
                debug!("{}: {}", SYNCHRONIZATIONS, s);
                SynchronizationConfig::parse_synchronizations(&s).map_err(|err| {
                    AppConfigError::EnvVarParseJsonError {
                        env_var_name: SYNCHRONIZATIONS.to_string(),
                        cause: err,
                    }
                })?
            },
            None => {
                return Err(AppConfigError::EnvVarError {
                    env_var_name: SYNCHRONIZATIONS.to_string(),
                    cause: VarError::NotPresent,
                })
            },
        };

        let vcap_service_types = match param_map.get(VCAP_SERVICES) {
            Some(s) => {
                //don't log passwords
                //debug!("{}: {}", VCAP_SERVICES, s);
                parse_service_types(s).map_err(|err| AppConfigError::EnvVarParseJsonError {
                    env_var_name: SYNCHRONIZATIONS.to_string(),
                    cause: err,
                })?
            }
            None => {
                return Err(AppConfigError::EnvVarError {
                    env_var_name: VCAP_SERVICES.to_string(),
                    cause: VarError::NotPresent,
                })
            }
        };
        let ldap_services_map = map_ldap_services(&vcap_service_types.user_provided)
            .map_err(|_| AppConfigError::LdapServiceNameNotUnique)?;
        //don't log passwords
        //debug!("ldap services by names: {:?}", ldap_services_map);

        let exclude_attrs_pattern = match param_map.get(EXCLUDE_ATTRS) {
            Some(s) => {
                debug!("{}: {}", EXCLUDE_ATTRS, s);
                Some(
                    Regex::new(&s).map_err(|err| AppConfigError::EnvVarParseRegexError {
                        env_var_name: EXCLUDE_ATTRS.to_string(),
                        cause: err,
                    })?,
                )
            },
            None => None,
        };

        let daemon_bool = match param_map.get(DAEMON) {
            Some(s) => {
                bool::from_str(s).map_err(|_| AppConfigError::EnvVarParseError {
                    env_var_name: DAEMON.to_string(),
                })?
            },
            None => {
                return Err(AppConfigError::EnvVarError {
                    env_var_name: DAEMON.to_string(),
                    cause: VarError::NotPresent,
                })
            },
        };

        let dry_run_bool = match param_map.get(DRY_RUN) {
            Some(s) => {
                bool::from_str(s).map_err(|_| AppConfigError::EnvVarParseError {
                    env_var_name: DRY_RUN.to_string(),
                })?
            },
            None => {
                return Err(AppConfigError::EnvVarError {
                    env_var_name: DRY_RUN.to_string(),
                    cause: VarError::NotPresent,
                })
            },
        };

        let job_sleep_duration = match param_map.get(JOB_SLEEP) {
            Some(s) => {
                Some(Self::parse_duration(s).ok_or(AppConfigError::EnvVarParseError {
                    env_var_name: JOB_SLEEP.to_string(),
                })?)
            },
            None => None,
        };

        let config = AppConfig {
            daemon: daemon_bool,
            job_sleep: job_sleep_duration,
            dry_run: dry_run_bool,
            exclude_attrs: exclude_attrs_pattern,
            ldap_services: ldap_services_map,
            synchronization_configs: synchronizations_vec,
        };

        Ok(config)
    }

    pub fn from_cf_env() -> Result<AppConfig, AppConfigError> {
        debug!("from_cf_env()");
        let env_map = Self::read_env_vars()?;
        Self::from_map(env_map)
    }

    // Read configuration from a map instead of environment variables
    // that's very useful for unit tests, because the environment is a singleton.
    // tests which run in parallel, can't use the environment.
    pub fn from_map(param_map: HashMap<&str, String>) -> Result<AppConfig, AppConfigError> {
        let config = Self::parse(param_map)?;
        match config.analyze_semantic() {
            Some(err) => return Err(err),
            None => {}
        }
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
        env::set_var("LS_DAEMON", "true");
        env::set_var("LS_SLEEP", "10 sec");
        env::set_var("LS_DRY_RUN", "true");
        env::set_var(
            "LS_EXCLUDE_ATTRS",
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
            "LS_SYNCHRONIZATIONS",
            indoc! {r#"
            [{
                "source":"ldap1",
                "target":"ldap2",
                "base_dns":["cn=users","cn=groups"]
            }]
        "#},
        );

        let app_config = AppConfig::from_cf_env().unwrap();
        debug!("app_config: {:?}", app_config);
        assert_eq!(app_config.job_sleep, Some(Duration::from_secs(10)));
        assert_eq!(app_config.dry_run, true);
        assert_eq!(
            app_config.exclude_attrs.unwrap().as_str(),
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
