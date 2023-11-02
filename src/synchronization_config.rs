use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SynchronizationConfig {
    pub source: String,
    pub target: String,
    pub base_dns: Vec<String>,
}

impl SynchronizationConfig {
    // TODO: error if duplicate base_dns
    pub fn parse_synchronizations(json_str: &str) -> Result<Vec<SynchronizationConfig>,serde_json::Error> {
        serde_json::from_str(json_str)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json;
    use log::debug;

    #[test]
    fn test_serialize1() {
        let sync_config = SynchronizationConfig {
            source: "hub1".to_string(),
            target: "ldap1".to_string(),
            base_dns: vec![ "cn=org2".to_string(), "cn=org3".to_string(), "cn=org4".to_string() ],
        };
        let result = serde_json::to_string(&sync_config).unwrap();
        assert_eq!(result, r#"{"source":"hub1","target":"ldap1","base_dns":["cn=org2","cn=org3","cn=org4"]}"#);
    }

    #[test]
    fn test_serialize2() {
        let sync_config = vec![SynchronizationConfig {
            source: "ldap1".to_string(),
            target: "ldap2".to_string(),
            base_dns: vec![ "cn=users".to_string(), "cn=groups".to_string() ],
        }];
        let result = serde_json::to_string(&sync_config).unwrap();
        assert_eq!(result, r#"[{"source":"ldap1","target":"ldap2","base_dns":["cn=users","cn=groups"]}]"#);
    }
 
    #[test]
    fn test_parse_synchronisations_valid() {
        let json_str = r#"[{ "source": "ldap1", "target": "ldap2", "base_dns": [ "cn=users", "cn=groups" ]}]"#;
        let sync_configs = SynchronizationConfig::parse_synchronizations(json_str).unwrap();
        assert_eq!(sync_configs.len(), 1);
        let first = &sync_configs[0];
        assert_eq!(first.source, "ldap1");
        assert_eq!(first.target, "ldap2");
        let base_dns = &first.base_dns;
        assert_eq!(base_dns.len(), 2);
        assert_eq!(base_dns[0], "cn=users");
        assert_eq!(base_dns[1], "cn=groups");
    }

    #[test]
    fn test_parse_synchronisations_invalid() {
        let json_str = r#"[{ "source": "ldap1", "target": "ldap2" Unsinn":"#;
        let result = SynchronizationConfig::parse_synchronizations(json_str);
        let err = result.expect_err("parse JSON error expected");
        debug!("{:?}", err);
        //TODO assert_eq!(err, serde_json::Error{});
    }
}