use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct SynchronisationConfig {
    pub source: String,
    pub target: String,
    pub base_dns: Vec<String>,
    pub ts_store: String,
    pub ts_base_dn: String,
}

impl SynchronisationConfig {
    pub fn parse_synchronisations(json_vec: &str) -> Vec<SynchronisationConfig> {
        serde_json::from_str(json_vec).unwrap()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use serde_json;

    #[test]
    fn test_serialize1() {
        let sync_with_names = SynchronisationConfig {
            source: "hub1".to_string(),
            target: "ldap1".to_string(),
            base_dns: vec![ "cn=org2".to_string(), "cn=org3".to_string(), "cn=org4".to_string() ],
            ts_store: "hub1".to_string(),
            ts_base_dn: "cn=sync_timestamps".to_string(),
        };
        let result = serde_json::to_string(&sync_with_names).unwrap();
        assert_eq!(result, r#"{"source":"hub1","target":"ldap1","base_dns":["cn=org2","cn=org3","cn=org4"],"ts_store":"hub1","ts_base_dn":"cn=sync_timestamps"}"#);
    }

    #[test]
    fn test_serialize2() {
        let sync_with_names = vec![SynchronisationConfig {
            source: "ldap1".to_string(),
            target: "ldap2".to_string(),
            base_dns: vec![ "cn=users".to_string(), "cn=groups".to_string() ],
            ts_store: "ldap2".to_string(),
            ts_base_dn: "cn=sync_timestamps".to_string(),
        }];
        let result = serde_json::to_string(&sync_with_names).unwrap();
        assert_eq!(result, r#"[{"source":"ldap1","target":"ldap2","base_dns":["cn=users","cn=groups"],"ts_store":"ldap2","ts_base_dn":"cn=sync_timestamps"}]"#);
    }

    #[test]
    fn test_parse_synchronisations_with_names() {
        let json_str = r#"[{ "source": "ldap1", "target": "ldap2", "base_dns": [ "cn=users", "cn=groups" ], "ts_store": "ldap2", "ts_base_dn": "cn=sync_timestamps" }]"#;
        let syncs_with_names = SynchronisationConfig::parse_synchronisations(json_str);
        assert_eq!(syncs_with_names.len(), 1);
        let first = &syncs_with_names[0];
        assert_eq!(first.source, "ldap1");
        assert_eq!(first.target, "ldap2");
        let base_dns = &first.base_dns;
        assert_eq!(base_dns.len(), 2);
        assert_eq!(base_dns[0], "cn=users");
        assert_eq!(base_dns[1], "cn=groups");
    }
}