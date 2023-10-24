use crate::sub::cf_services::LdapService;
use crate::sub::synchronisation_config::SynchronisationConfig;

use std::collections::HashMap;
//use serde_json::{Result, Value};


// Referenced source and target LdapServices have to live as long as this struct
#[derive(Debug)]
pub struct Synchronisation<'a> {
    source_ref: &'a LdapService,
    target_ref: &'a LdapService,
    base_dns: Vec<String>,
    ts_store_ref: &'a LdapService,
    ts_base_dn: String,
    timestamp: Option<String>
}

impl<'a> Synchronisation<'a> {
    pub fn from_synchronisation_with_names(services: &'a HashMap<String, LdapService>, sync_with_names: &SynchronisationConfig) -> Synchronisation<'a> {
        Synchronisation {
            source_ref: services.get(&sync_with_names.source).unwrap(),
            target_ref: services.get(&sync_with_names.target).unwrap(),
            base_dns: sync_with_names.base_dns.clone(),
            ts_store_ref: services.get(&sync_with_names.ts_store).unwrap(),
            ts_base_dn: sync_with_names.ts_base_dn.clone(),
            timestamp: None,
        }
    }

    pub fn save_sync_timestamp(&self) {
        // todo
    }

    pub fn load_sync_timestamp(&self) {
        // todo
    }
}


#[cfg(test)]
mod test {
    use super::*;
    use crate::sub::synchronisation_config::SynchronisationConfig;

    #[test]
    fn test_from_synchronisation_with_names() {
        let sync_with_names = SynchronisationConfig {
            source: "src".to_string(),
            target: "trg".to_string(),
            base_dns: vec![ "cn=org1".to_string(), "cn=org2".to_string(), "cn=org3".to_string() ],
            ts_store: "trg".to_string(),
            ts_base_dn: "cn=sync_timestamps".to_string(),
        };

        let service1 = LdapService{
            url: "ldap://provider-ldap.de:389".to_string(),
            bind_dn: "cn=admin,dc=source,dc=de".to_string(),
            password: "secret".to_string(),
            base_dn: "dc=source,dc=de".to_string(),
        };

        let service2 = LdapService{
            url: "ldap://consumer-ldap.de:389".to_string(),
            bind_dn: "cn=admin,dc=target,dc=de".to_string(),
            password: "secret".to_string(),
            base_dn: "dc=target,dc=de".to_string(),
        };

        let services = HashMap::from(
            [("src".to_string(), service1), ("trg".to_string(), service2)]
        );

        let result = Synchronisation::from_synchronisation_with_names(&services, &sync_with_names);
        assert_eq!(result.source_ref, services.get("src").unwrap());
        assert_eq!(result.target_ref, services.get("trg").unwrap());

    }
}