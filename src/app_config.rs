use crate::cf_services::{map_ldap_services, parse_service_types, LdapService};
use crate::synchronization_config::SynchronizationConfig;
use log::{debug, info};
use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::fs::read_to_string;
use std::{env, env::VarError, str::FromStr, time::Duration};

/// names of environment variables
pub const VCAP_SERVICES: &str = "VCAP_SERVICES";
pub const SYNCHRONIZATIONS: &str = "LS_SYNCHRONIZATIONS";
pub const DAEMON: &str = "LS_DAEMON";
pub const ATTRS: &str = "LS_ATTRS";
pub const EXCLUDE_ATTRS: &str = "LS_EXCLUDE_ATTRS";
pub const JOB_SLEEP: &str = "LS_SLEEP";
pub const DRY_RUN: &str = "LS_DRY_RUN";

/// regex for lowercase attribute names
/// "+"" or "*"" or real attribute name
/// real name starts with a letter, continues with more letters, caracters or semicolon
static ATTR_NAME_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"^(\+|\*|[a-z][0-9a-z;]*)$"#).unwrap()); // assumption: works always or never

static DURATION_REGEX: Lazy<Regex> =
    Lazy::new(|| Regex::new( " *([1-9][0-9]*) *(sec|min) *").unwrap());

#[derive(Debug)]
pub enum LdapServiceUsage {
    Source,
    Target,
}

#[derive(Debug)]
pub enum AppConfigError {
    /// environment variable not set or can't be parsed as UTF8
    EnvVarError {
        env_var_name: String,
        cause: VarError,
    },
    /// some error in the syntax of the environment variable
    EnvVarParseError {
        env_var_name: String,
    },
    /// environment variable contains an invalid regular expression
    EnvVarParseRegexError {
        env_var_name: String,
        cause: regex::Error,
    },
    /// environment variable contains invalid JSON code
    EnvVarParseJsonError {
        env_var_name: String,
        cause: serde_json::Error,
    },
    InvalidAttributeName {
        name: String,
    },
    DuplicateAttributeName {
        name: String,
    },
    /// referenced service is not defined
    LdapServiceMissing {
        service_name: String,
        synchronisation_index: usize,
        usage: LdapServiceUsage,
    },
    /// at least two services have the same name
    LdapServiceNameNotUnique,
    /// LS_DAEMON is "true" but LS_SLEEP is not set
    DaemonButNoSleep,
    /// LS_SLEEP is set but LS_DAEMON is "false"
    SleepButNoDaemon,
}

#[derive(Debug)]
pub struct AppConfig {
    pub daemon: bool,
    pub job_sleep: Option<Duration>,
    pub dry_run: bool,
    pub attrs: HashSet<String>,
    pub exclude_attrs: Option<Regex>,
    pub ldap_services: HashMap<String, LdapService>,
    pub synchronization_configs: Vec<SynchronizationConfig>,
}

impl AppConfig {
    pub fn log_platform_info() {
        let read_result = read_to_string("/etc/os-release");
        match read_result {
            Ok(content) => {
                for line in content.lines() {
                    info!("log_plattform_info: {}", line);
                }
            }
            Err(err) => info!("Cannot read /etc/os-release. {:?}", err),
        }
    }

    /// read relevant environment variables, parse UTF8 strings and store the result in a map
    pub fn read_env_vars() -> Result<HashMap<&'static str, String>, AppConfigError> {
        let mut env_map = HashMap::new();
        let allowed_var_names = [
            VCAP_SERVICES,
            SYNCHRONIZATIONS,
            DAEMON,
            ATTRS,
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
                        env_var_name: name.to_string(),
                        cause: err,
                    });
                }
            }
        }
        Ok(env_map)
    }

    /// example input "15 min" or "10 sec".
    /// zero (example "0 min") is not allowed.
    fn parse_duration(hay: &str) -> Option<Duration> {
        let captures = DURATION_REGEX.captures(hay)?;
        let number_str = captures.get(1).unwrap().as_str();
        let unit_str = captures.get(2).unwrap().as_str();
        let number = number_str.parse().unwrap();
        if unit_str == "sec" {
            Some(Duration::from_secs(number))
        } else {
            Some(Duration::from_secs(number * 60))
        }
    }

    fn parse_sleep(hay: &Option<&String>) -> Result<Option<Duration>, AppConfigError> {
        match hay {
            Some(s) => Ok(Some(Self::parse_duration(s).ok_or(
                AppConfigError::EnvVarParseError {
                    env_var_name: JOB_SLEEP.to_string(),
                },
            )?)),
            None => Ok(None),
        }
    }

    fn parse_synchronizations(
        json_str: &Option<&String>,
    ) -> Result<Vec<SynchronizationConfig>, AppConfigError> {
        match json_str {
            Some(s) => {
                debug!("{}: {}", SYNCHRONIZATIONS, s);
                Ok(
                    SynchronizationConfig::parse_synchronizations(&s).map_err(|err| {
                        AppConfigError::EnvVarParseJsonError {
                            env_var_name: SYNCHRONIZATIONS.to_string(),
                            cause: err,
                        }
                    })?,
                )
            }
            None => Err(AppConfigError::EnvVarError {
                env_var_name: SYNCHRONIZATIONS.to_string(),
                cause: VarError::NotPresent,
            }),
        }
    }

    fn parse_vcap_services(
        json_str: &Option<&String>,
    ) -> Result<HashMap<String, LdapService>, AppConfigError> {
        let vcap_service_types = match json_str {
            Some(s) => {
                //don't log passwords
                //debug!("{}: {}", VCAP_SERVICES, s);
                parse_service_types(s).map_err(|err| AppConfigError::EnvVarParseJsonError {
                    env_var_name: VCAP_SERVICES.to_string(),
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
        Ok(map_ldap_services(&vcap_service_types.user_provided)
            .map_err(|_| AppConfigError::LdapServiceNameNotUnique)?)
    }

    fn parse_daemon(daemon: &Option<&String>) -> Result<bool, AppConfigError> {
        match daemon {
            Some(b) => bool::from_str(b.trim()).map_err(|_| AppConfigError::EnvVarParseError {
                env_var_name: DAEMON.to_string(),
            }),
            None => Err(AppConfigError::EnvVarError {
                env_var_name: DAEMON.to_string(),
                cause: VarError::NotPresent,
            }),
        }
    }

    fn parse_dry_run(dry_run: &Option<&String>) -> Result<bool, AppConfigError> {
        match dry_run {
            Some(b) => bool::from_str(b.trim()).map_err(|_| AppConfigError::EnvVarParseError {
                env_var_name: DRY_RUN.to_string(),
            }),
            None => Err(AppConfigError::EnvVarError {
                env_var_name: DRY_RUN.to_string(),
                cause: VarError::NotPresent,
            }),
        }
    }

    /// LS_ATTRS is a required parameter, without default value to make it clear, what is searched for.
    /// Parses a comma-separarated liste of attribute names.
    /// Attribute names are "*", "+" or a real attribute name, containing lower- and uppercase letters, digits and semicolons.
    /// Whitespaces arround attribute names are stripped.
    /// "dn" is not allowed, because it is the distinguished name and not an attribute name.
    /// An empty list means no attributes are synchronized, only DNs. The target server may extract the fist part of the DN.
    /// If an attribute name appears more than once it's deduplicated.
    /// Example: "cn, sn, givenName, description"
    /// TODO Prio 1: test difference searching for "+", "*" or empty attributes list.
    fn parse_attrs(attrs_str: &Option<&String>) -> Result<HashSet<String>, AppConfigError> {
        match attrs_str {
            Some(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() { // special case, empty string
                    Ok(HashSet::new())
                } else {
                    let mut verified_parts: HashSet<String> = HashSet::new();
                    for part in s.split_whitespace().map(|s| s.to_lowercase()){
                        if (!ATTR_NAME_REGEX.is_match(&part)) || (part == "dn") {
                            return Err(AppConfigError::InvalidAttributeName { name: part });
                        };
                        if !verified_parts.insert(part.to_string()) {
                            return Err(AppConfigError::DuplicateAttributeName { name: part });
                        }
                    }
                    Ok(verified_parts)
                }
            }
            None => Err(AppConfigError::EnvVarError {
                env_var_name: ATTRS.to_string(),
                cause: VarError::NotPresent,
            }),
        }
    }

    /// Parse a regular expession
    fn parse_exclude_attrs(
        exclude_attrs: &Option<&String>,
    ) -> Result<Option<Regex>, AppConfigError> {
        match exclude_attrs {
            Some(s) => {
                debug!("{}: {}", EXCLUDE_ATTRS, s);
                Ok(Some(Regex::new(&s).map_err(|err| {
                    AppConfigError::EnvVarParseRegexError {
                        env_var_name: EXCLUDE_ATTRS.to_string(),
                        cause: err,
                    }
                })?))
            }
            None => Ok(None),
        }
    }

    /// parse regular expesssions, booleans, JSON code and Duration in the configuration
    fn parse(param_map: &HashMap<&str, String>) -> Result<AppConfig, AppConfigError> {
        let synchronizations_vec = Self::parse_synchronizations(&param_map.get(SYNCHRONIZATIONS))?;
        let ldap_services_map = Self::parse_vcap_services(&param_map.get(VCAP_SERVICES))?;
        let job_sleep_duration = Self::parse_sleep(&param_map.get(JOB_SLEEP))?;
        let daemon_bool = Self::parse_daemon(&param_map.get(DAEMON))?;
        let dry_run_bool = Self::parse_dry_run(&param_map.get(DRY_RUN))?;
        let attrs_set = Self::parse_attrs(&param_map.get(ATTRS))?;
        let exclude_attrs_pattern = Self::parse_exclude_attrs(&param_map.get(EXCLUDE_ATTRS))?;
        let config = AppConfig {
            daemon: daemon_bool,
            job_sleep: job_sleep_duration,
            dry_run: dry_run_bool,
            attrs: attrs_set,
            exclude_attrs: exclude_attrs_pattern,
            ldap_services: ldap_services_map,
            synchronization_configs: synchronizations_vec,
        };
        Ok(config)
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

    // Read configuration from a map instead of environment variables
    // that's very useful for unit tests, because the environment is a singleton.
    // Tests which run in parallel, can't use different environments.
    pub fn from_map(param_map: &HashMap<&str, String>) -> Result<AppConfig, AppConfigError> {
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

    #[test]
    fn test_from_map_valid() {
        let param_map = HashMap::from([
            (DAEMON, "true".to_string()),
            (JOB_SLEEP, "10 sec".to_string()),
            (DRY_RUN, "true".to_string()),
            (ATTRS, "cn sn givenName description".to_string()),
            (
                EXCLUDE_ATTRS,
                "^(?i)(authPassword|orclPassword|orclAci|orclEntryLevelAci)$".to_string(),
            ),
            (
                VCAP_SERVICES,
                indoc! {r#"
                {
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
                }"#}
                .to_string(),
            ),
            (
                SYNCHRONIZATIONS,
                indoc! {r#"
                    [{
                        "source":"ldap1",
                        "target":"ldap2",
                        "base_dns":["cn=users","cn=groups"]
                    }]
                "#}
                .to_string(),
            ),
        ]);

        let app_config = AppConfig::from_map(&param_map).unwrap();
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
        //TODO more asserts
    }

    #[test]
    fn test_from_map_vcap_services_invalid_json() {
        let param_map = HashMap::from([
            (DAEMON, "true".to_string()),
            (JOB_SLEEP, "10 sec".to_string()),
            (DRY_RUN, "true".to_string()),
            (VCAP_SERVICES, "Unsinn".to_string()),
            (SYNCHRONIZATIONS, "[]".to_string()),
        ]);

        let result = AppConfig::from_map(&param_map);
        debug!("result: {:?}", result);
        match result {
            Err(AppConfigError::EnvVarParseJsonError {
                env_var_name: name,
                cause: err,
            }) => {
                assert_eq!(name, VCAP_SERVICES);
                assert_eq!(err.line(), 1);
                assert_eq!(err.column(), 1);
                assert_eq!(err.classify(), serde_json::error::Category::Syntax);
                assert_eq!(err.to_string(), "expected value at line 1 column 1");
            }
            _ => {
                panic!("unexpected result");
            }
        }
    }

    #[test]
    fn test_from_map_synchronizations_invalid_json() {
        let param_map = HashMap::from([
            (DAEMON, "true".to_string()),
            (JOB_SLEEP, "10 sec".to_string()),
            (DRY_RUN, "true".to_string()),
            (
                VCAP_SERVICES,
                indoc! {r#"
                {
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
                    ]
                }"#}
                .to_string(),
            ),
            (SYNCHRONIZATIONS, "[ { Unsinn } ]".to_string()),
        ]);

        let result = AppConfig::from_map(&param_map);
        debug!("result: {:?}", result);
        match result {
            Err(AppConfigError::EnvVarParseJsonError {
                env_var_name: name,
                cause: err,
            }) => {
                assert_eq!(name, SYNCHRONIZATIONS);
                assert_eq!(err.line(), 1);
                assert_eq!(err.column(), 5);
                assert_eq!(err.classify(), serde_json::error::Category::Syntax);
                assert_eq!(err.to_string(), "key must be a string at line 1 column 5");
            }
            _ => {
                panic!("unexpected result");
            }
        }
    }

    #[rstest]
    #[case("10 sec", Some(Duration::from_secs(10)))]
    #[case("1 min", Some(Duration::from_secs(60)))]
    #[case(" 60  min ", Some(Duration::from_secs(60 * 60)))]
    #[case("01 min", Some(Duration::from_secs(60)))]
    #[case("0 min", None)]
    #[case("00 min", None)]
    #[case("eine Ewigkeit", None)]
    #[case("13 Minütchen", None)]
    #[case("", None)]
    fn test_parse_duration(#[case] hay: &str, #[case] expected: Option<Duration>) {
        let result = AppConfig::parse_duration(hay);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case(None, "Ok(None)")]
    #[case(Some("10 sec"), "Ok(Some(10s))")]
    #[case(Some("1 min"), "Ok(Some(60s))")]
    #[case(Some(" 60  min "), "Ok(Some(3600s))")]
    #[case(Some("01 min"), "Ok(Some(60s))")]
    #[case(Some(""), r#"Err(EnvVarParseError { env_var_name: "LS_SLEEP" })"#)]
    #[case(Some("0 min"), r#"Err(EnvVarParseError { env_var_name: "LS_SLEEP" })"#)]
    #[case(
        Some("00 min"),
        r#"Err(EnvVarParseError { env_var_name: "LS_SLEEP" })"#
    )]
    #[case(
        Some("eine Ewigkeit"),
        r#"Err(EnvVarParseError { env_var_name: "LS_SLEEP" })"#
    )]
    #[case(
        Some("13 Minütchen"),
        r#"Err(EnvVarParseError { env_var_name: "LS_SLEEP" })"#
    )]
    fn test_parse_sleep(#[case] hay: Option<&str>, #[case] expected: &str) {
        let live_longer = match hay {
            Some(h) => Some(String::from(h)),
            None => None,
        };
        let given = live_longer.as_ref();

        let result = AppConfig::parse_sleep(&given);
        assert_eq!(format!("{:?}", result), expected);
    }

    #[rstest]
    #[case(None, "Ok(None)")]
    #[case(Some("^userpassword$"), r#"Ok(Some(Regex("^userpassword$")))"#)]
    fn test_parse_exclude_attrs(#[case] hay: Option<&str>, #[case] expected: &str) {
        let live_longer = match hay {
            Some(h) => Some(String::from(h)),
            None => None,
        };
        let given = live_longer.as_ref();

        let result = AppConfig::parse_exclude_attrs(&given);
        assert_eq!(format!("{:?}", result), expected);
    }

    #[rstest]
    #[case(Some(indoc!{ r#"{
        "user-provided": [
          {
            "name": "ldap1",
            "credentials": {
              "url": "ldap://ldap1.provider.de:389",
              "bind_dn": "cn=admin1,dc=de",
              "password": "secret1",
              "base_dn": "dc=de"
            }
          },
          {
            "name": "ldap2",
            "credentials": {
              "url": "ldap://ldap2.consumer.de:389",
              "bind_dn": "cn=admin2,dc=de",
              "password": "secret2",
              "base_dn": "dc=de"
            }
          }
        ]
      }"#}), HashMap::from([
        ("ldap1".to_string(), LdapService { url: "ldap://ldap1.provider.de:389".to_string(), bind_dn: "cn=admin1,dc=de".to_string(), password: "secret1".to_string(), base_dn: "dc=de".to_string() }),
        ("ldap2".to_string(), LdapService { url: "ldap://ldap2.consumer.de:389".to_string(), bind_dn: "cn=admin2,dc=de".to_string(), password: "secret2".to_string(), base_dn: "dc=de".to_string() })
    ]))]
    #[case(Some(indoc!{ r#"{
        "user-provided": []
      }"#}), HashMap::new())]
    fn test_parse_vcap_services_ok(
        #[case] json_str: Option<&str>,
        #[case] expected: HashMap<String, LdapService>,
    ) {
        let live_longer = match json_str {
            Some(h) => Some(String::from(h)),
            None => None,
        };
        let given = live_longer.as_ref();

        let map = AppConfig::parse_vcap_services(&given).unwrap();

        // Trick mit format!(), weil PartialEq nicht für alle Teile implementiert ist
        // funktioniert aber nicht für HashMap
        assert_eq!(map, expected);
    }

    #[rstest]
    #[case(
        None,
        r#"Err(EnvVarError { env_var_name: "VCAP_SERVICES", cause: NotPresent })"#
    )]
    #[case(Some(indoc!{ r#"{
        "user-provided": [ syntax error ]
      }"#}), r#"Err(EnvVarParseJsonError { env_var_name: "VCAP_SERVICES", cause: Error("expected value", line: 2, column: 22) })"#)]
    #[case(Some(indoc!{ r#"{
        "mongodb": [
          {
            "name": "mongo1",
            "credentials": {
              "url": "ldap://ldap1.provider.de:389",
              "bind_dn": "cn=admin1,dc=de",
              "password": "secret1",
              "base_dn": "dc=de"
            }
          }
        ]
      }"#}), r#"Err(EnvVarParseJsonError { env_var_name: "VCAP_SERVICES", cause: Error("missing field `user-provided`", line: 13, column: 1) })"#)]
    fn test_parse_vcap_services_err(#[case] json_str: Option<&str>, #[case] expected: &str) {
        let live_longer = match json_str {
            Some(h) => Some(String::from(h)),
            None => None,
        };
        let given = live_longer.as_ref();

        let result = AppConfig::parse_vcap_services(&given);
        // Trick mit format!(), weil PartialEq nicht für alle Teile implementiert ist
        // funktioniert aber nicht für HashMap
        assert_eq!(format!("{:?}", result), expected);
    }

    #[rstest]
    #[case(Some("true"), r#"Ok(true)"#)]
    #[case(Some("false"), r#"Ok(false)"#)]
    #[case(Some(""), r#"Err(EnvVarParseError { env_var_name: "LS_DAEMON" })"#)]
    #[case(Some("True"), r#"Err(EnvVarParseError { env_var_name: "LS_DAEMON" })"#)]
    #[case(
        Some("FALSE"),
        r#"Err(EnvVarParseError { env_var_name: "LS_DAEMON" })"#
    )]
    #[case(
        None,
        r#"Err(EnvVarError { env_var_name: "LS_DAEMON", cause: NotPresent })"#
    )]
    fn test_parse_daemon(#[case] s: Option<&str>, #[case] expected: &str) {
        let live_longer = match s {
            Some(h) => Some(String::from(h)),
            None => None,
        };
        let given = live_longer.as_ref();
        let result = AppConfig::parse_daemon(&given);
        // Trick mit format!(), weil PartialEq nicht für alle Teile implementiert ist
        assert_eq!(format!("{:?}", result), expected);
    }

    #[rstest]
    #[case(Some("cn sn givenName  description"), vec!["cn", "sn", "givenname", "description"])]
    #[case(Some("l"), vec!["l"])] // lower case L
    #[case(Some("\no\n"), vec!["o"])] // lower case O
    #[case(Some(""), vec![])]
    #[case(Some("\n\t\r"), vec![])]
    #[case(Some("orclPassword;xyz"), vec!["orclpassword;xyz"])]
    #[case(Some("+"), vec!["+"])]
    #[case(Some("*"), vec!["*"])]
    #[case(Some("+ *"), vec!["+", "*"])]
    #[case(Some("\t+\t*\t"), vec!["+", "*"])]
    fn test_parse_attrs_ok(#[case] s: Option<&str>, #[case] expected: Vec<&str>) {
        let live_longer = match s {
            Some(h) => Some(String::from(h)),
            None => None,
        };
        let given = live_longer.as_ref();
        let expected_set: HashSet<String> = expected.iter().map(|s| s.to_string()).collect();

        let result_set = AppConfig::parse_attrs(&given).unwrap();

        assert_eq!(result_set, expected_set);
    }

    #[rstest]
    #[case(None, r#"Err(EnvVarError { env_var_name: "LS_ATTRS", cause: NotPresent })"#)]
    #[case(Some("dn"), r#"Err(InvalidAttributeName { name: "dn" })"#)]
    #[case(Some(" DN "), r#"Err(InvalidAttributeName { name: "dn" })"#)]
    #[case(Some("description DN ou givenName"), r#"Err(InvalidAttributeName { name: "dn" })"#)]
    #[case(Some("%"), r#"Err(InvalidAttributeName { name: "%" })"#)]
    #[case(Some("%cn"), r#"Err(InvalidAttributeName { name: "%cn" })"#)]
    #[case(Some("0cn"), r#"Err(InvalidAttributeName { name: "0cn" })"#)]
    #[case(Some("cn CN givenName givenname"), r#"Err(DuplicateAttributeName { name: "cn" })"#)]
    fn test_parse_attrs_err(#[case] s: Option<&str>, #[case] expected: &str) {
        let live_longer = match s {
            Some(h) => Some(String::from(h)),
            None => None,
        };
        let given = live_longer.as_ref();
        let result = AppConfig::parse_attrs(&given);

        assert_eq!(format!("{:?}", result), expected);
    }

    #[rstest]
    #[case(Some("true"), r#"Ok(true)"#)]
    #[case(Some("false"), r#"Ok(false)"#)]
    #[case(Some("true "), r#"Ok(true)"#)]
    #[case(Some("\ntrue\n\t "), r#"Ok(true)"#)]
    #[case(Some(""), r#"Err(EnvVarParseError { env_var_name: "LS_DRY_RUN" })"#)]
    #[case(
        Some("tr ue"),
        r#"Err(EnvVarParseError { env_var_name: "LS_DRY_RUN" })"#
    )]
    #[case(
        Some("True"),
        r#"Err(EnvVarParseError { env_var_name: "LS_DRY_RUN" })"#
    )]
    #[case(
        Some("FALSE"),
        r#"Err(EnvVarParseError { env_var_name: "LS_DRY_RUN" })"#
    )]
    #[case(
        None,
        r#"Err(EnvVarError { env_var_name: "LS_DRY_RUN", cause: NotPresent })"#
    )]
    fn test_dry_run(#[case] s: Option<&str>, #[case] expected: &str) {
        let live_longer = match s {
            Some(h) => Some(String::from(h)),
            None => None,
        };
        let given = live_longer.as_ref();
        let result = AppConfig::parse_dry_run(&given);
        // Trick mit format!(), weil PartialEq nicht für alle Teile implementiert ist
        assert_eq!(format!("{:?}", result), expected);
    }
}
