/// Because cf-env-crate has a bug, I wrote my own functions.
/// The bug I found is, "plan" ist not optional and not provided by my Cloud Foundry instance.
/// It's much slimmer and allows more optional fields in the VCAP_SERVICES-JSON code.
/// That reduces the size of the configuration, if testing or deploying outside Cloud Foundry.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// In this application only "user-provided" services are used.
/// No "mongodb" or whatever is allowed.
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct ServiceTypes {
    #[serde(rename = "user-provided")]
    pub user_provided: Vec<Service>,
}

/// equals "credentials" in Cloud Foundry JSON code
#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct LdapService {
    pub url: String,
    pub bind_dn: String,
    pub password: String,
    pub base_dn: String,
}

/// to reduce the size of the required JSON code most fileds are Optional
/// except name
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Service {
    pub binding_guid: Option<String>,
    pub binding_name: Option<String>,
    pub instance_guid: Option<String>,
    pub instance_name: Option<String>,
    pub name: String, // required
    pub label: Option<String>,
    pub tags: Option<Vec<String>>,
    pub plan: Option<String>,
    pub credentials: LdapService, // required
    pub syslog_drain_url: Option<String>,
    pub volume_mounts: Option<Vec<String>>,
}

/*
pub fn parse_ldap_services(vcap_services_str: &str) -> Result<HashMap<String, Vec<Service>>, serde_json::Error>{
    let result = serde_json::from_str::<HashMap<String, Vec<Service>>>(vcap_services_str);
    result
}
*/

pub fn parse_service_types(vcap_services_str: &str) -> Result<ServiceTypes, serde_json::Error>{
    let result = serde_json::from_str::<ServiceTypes>(vcap_services_str);
    result
}

#[derive(Debug, PartialEq)]
pub struct ServiceNameTwice;

/// converts the Cloud Foundry JSON structure in a more convinient map.
/// There must be "user-provided" services.
/// todo Error, wenn 2 Services mit gleichem Namen existieren.
pub fn map_ldap_services(services_vec: &Vec<Service>) -> Result<HashMap<String, LdapService>, ServiceNameTwice> {
    // detect if there are duplicates
    let mut unique_names = HashSet::new();
    for service in services_vec.iter() {
        let duplicate = !unique_names.insert(&service.name);
        if duplicate {
            return Err(ServiceNameTwice)
        }
    }

    let name_to_service_map = services_vec
        .iter()
        .map(|service| {
            let ldap_service = LdapService {
                url: service.credentials.url.clone(),
                bind_dn: service.credentials.bind_dn.clone(),
                password: service.credentials.password.clone(),
                base_dn: service.credentials.base_dn.clone(),
            };
            (service.name.clone(), ldap_service)
        })
        .collect();
    Ok(name_to_service_map)
}

#[cfg(test)]
mod test {
    use super::*;
    use indoc::*;
    use rstest::*;

    #[test]
    fn test_parse_service_types_full() {
        let full_service_types_json = indoc! {r#"
        {
            "user-provided": [
                {
                    "binding_guid": "8d2b186f-22a6-48a8-bb38-df5320987812",
                    "credentials": {
                        "base_dn": "dc=de",
                        "bind_dn": "cn=admin1,dc=de",
                        "password": "secret1",
                        "url": "ldap://ldap1.provider.de:389"
                    },
                    "instance_guid": "720a4210-3ea0-44e0-b3e3-63ad833191a9",
                    "instance_name": "ldap1",
                    "label": "user-provided",
                    "name": "ldap1",
                    "tags": [],
                    "volume_mounts": [],
                    "provider": null,
                    "plan": "beta",
                    "binding_name": null,
                    "syslog_drain_url": null
                }
            ]
        }"#};

        let result = parse_service_types(full_service_types_json).unwrap();

        let user_provided_services = result.user_provided;
        assert_eq!(user_provided_services.len(), 1);
        let cf_service = &user_provided_services[0];
        assert_eq!(cf_service.name, "ldap1");
        let credentials = &cf_service.credentials;
        assert_eq!(credentials.base_dn, "dc=de");
        assert_eq!(credentials.bind_dn, "cn=admin1,dc=de");
        assert_eq!(credentials.password, "secret1");
        assert_eq!(credentials.url, "ldap://ldap1.provider.de:389");

    }

    #[test]
    fn test_parse_service_types_minimal() {
        let minimal_services_json = indoc! {r#"
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
                }
            ]
        }"#};

        let result = parse_service_types(minimal_services_json).unwrap();

        let user_provided_services = result.user_provided;
        assert_eq!(user_provided_services.len(), 1);
        let cf_service = &user_provided_services[0];
        assert_eq!(cf_service.name, "ldap1");
        let credentials = &cf_service.credentials;
        assert_eq!(credentials.base_dn, "dc=de");
        assert_eq!(credentials.bind_dn, "cn=admin1,dc=de");
        assert_eq!(credentials.password, "secret1");
        assert_eq!(credentials.url, "ldap://ldap1.provider.de:389");
    }

    #[test]
    fn test_map_ldap_services() {
        let credentials = LdapService {
            url: "ldap://ldap1.provider.de:389".to_string(),
            bind_dn: "cn=admin1,dc=de".to_string(),
            password: "secret1".to_string(),
            base_dn: "dc=de".to_string(),
        };
        let service = Service {
            binding_guid: None,
            binding_name: None,
            instance_guid: None,
            instance_name: None,
            name: "active_dir".to_string(),
            label: None,
            tags: None,
            plan: None,
            credentials: credentials,
            syslog_drain_url: None,
            volume_mounts: None,
        };
        let services = vec![service];

        let ldap_services_map = map_ldap_services(&services).unwrap();

        assert_eq!(ldap_services_map.len(), 1);
        let entry = ldap_services_map.get("active_dir").unwrap();
        assert_eq!(entry.url, "ldap://ldap1.provider.de:389");
        assert_eq!(entry.bind_dn, "cn=admin1,dc=de");
        assert_eq!(entry.password, "secret1");
        assert_eq!(entry.base_dn, "dc=de");
    }

    #[test]
    fn test_map_ldap_services_name_duplicate() {
        let credentials1 = LdapService {
            url: "ldap://ldap1.provider.de:389".to_string(),
            bind_dn: "cn=admin1,dc=de".to_string(),
            password: "secret1".to_string(),
            base_dn: "dc=de".to_string(),
        };
        let credentials2 = LdapService {
            url: "ldap://ldap2.consumer.fr:389".to_string(),
            bind_dn: "cn=admin2,dc=fr".to_string(),
            password: "secret2".to_string(),
            base_dn: "dc=fr".to_string(),
        };
        let service1 = Service {
            binding_guid: None,
            binding_name: None,
            instance_guid: None,
            instance_name: None,
            name: "active_dir".to_string(),
            label: None,
            tags: None,
            plan: None,
            credentials: credentials1,
            syslog_drain_url: None,
            volume_mounts: None,
        };
        let service2 = Service {
            binding_guid: None,
            binding_name: None,
            instance_guid: None,
            instance_name: None,
            name: "active_dir".to_string(),
            label: None,
            tags: None,
            plan: None,
            credentials: credentials2,
            syslog_drain_url: None,
            volume_mounts: None,
        };
        let services = vec![service1, service2];

        let err = map_ldap_services(&services).expect_err("expected duplicate service names");
        assert_eq!(err, ServiceNameTwice);

    }

    #[test]
    fn test_parse_and_map_services() {
        let minimal_services_json = indoc! {r#"
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
        }"#};

        let result = parse_service_types(minimal_services_json).unwrap();
        let user_provided_services = result.user_provided;
        let ldap_services = map_ldap_services(&user_provided_services).unwrap();

        assert_eq!(ldap_services.len(), 2);
        let ldap1 = ldap_services.get("ldap1").unwrap();
        assert_eq!(ldap1.url, "ldap://ldap1.provider.de:389");
        assert_eq!(ldap1.bind_dn, "cn=admin1,dc=de");
        assert_eq!(ldap1.password, "secret1");
        assert_eq!(ldap1.base_dn, "dc=de");
        let ldap1 = ldap_services.get("ldap2").unwrap();
        assert_eq!(ldap1.url, "ldap://ldap2.consumer.de:389");
        assert_eq!(ldap1.bind_dn, "cn=admin2,dc=de");
        assert_eq!(ldap1.password, "secret2");
        assert_eq!(ldap1.base_dn, "dc=de");
    }

}
