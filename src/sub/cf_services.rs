/// Because cf-env-crate has a bug, I wrote my own functions.
/// The bug I found is, "plan" ist not optional and not provided by my Cloud Foundry instance.
/// It's much slimmer and allows more optional fields in the VCAP_SERVICES-JSON code.
/// That reduces the size of the configuration, if testing or deploying outside Cloud Foundry.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

pub const VCAP_SERVICES: &str = "VCAP_SERVICES";

/*
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub enum Error<'a> {
    EnvNotSet(&'a str),
    JsonMalformed(String),
    ServiceNotPresent(&'a str),
    ServiceTypeNotPresent(&'a str),
}
*/

/// equals "credentials" in Cloud Foundry JSON code
#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct LdapService {
    pub url: String,
    pub bind_dn: String,
    pub password: String,
    pub base_dn: String,
}

/// to reduce the size of the required JSON code most fileds are Optional
/// except name
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Service<Credentials = Value> {
    pub binding_guid: Option<String>,
    pub binding_name: Option<String>,
    pub instance_guid: Option<String>,
    pub instance_name: Option<String>,
    pub name: String,
    pub label: Option<String>,
    pub tags: Option<Vec<String>>,
    pub plan: Option<String>,
    pub credentials: Credentials,
    pub syslog_drain_url: Option<String>,
    pub volume_mounts: Option<Vec<String>>,
}

/*
/// Maps service types like "mongodb" or "user-provided" to services.

type ServiceMap = HashMap<String, Vec<Service>>;

pub fn get_services() -> Result<ServiceMap, Error<'static>> {
    match env::var(VCAP_SERVICES) {
        Ok(services) => match serde_json::from_str::<ServiceMap>(&services) {
            Ok(value) => Ok(value),
            Err(_err) => Err(Error::JsonMalformed(VCAP_SERVICES.to_string())),
        },
        Err(_) => Err(Error::EnvNotSet(VCAP_SERVICES)),
    }
}
*/

/// todo in mehrere Schritte aufteilen

pub fn parse_ldap_services(vcap_services_str: &str) -> Result<HashMap<String, Vec<Service<LdapService>>>, serde_json::Error>{
    let result = serde_json::from_str::<HashMap<String, Vec<Service<LdapService>>>>(vcap_services_str);
    result
}

/// converts the Cloud Foundry JSON structure in a more convinient map.
/// If there are no "user-provided" services, None is returned.
pub fn map_ldap_services(type_to_vec_map: &HashMap<String, Vec<Service<LdapService>>>) -> Option<HashMap<String, LdapService>> {
    // todo
    let user_provided_services = type_to_vec_map.get("user-provided")?;
    let name_to_service_map = user_provided_services
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
    Some(name_to_service_map)
}

/// returns a map of LdapServices. Key is the name of the service.
/// That's a more useful data structure than the original JSON structure.
/*
pub fn get_ldap_services_by_names() -> Result<HashMap<String, LdapService>, Error<'static>>
{
    //let cf_services = get_services();
    match env::var(VCAP_SERVICES) {
        Ok(s) => {
            let cf_services = serde_json::from_str::<HashMap<String, Vec<Service<LdapService>>>>(&s);
            match cf_services {
                Ok(services) => {
                    let user_provided = services.get("user-provided");
                    match user_provided {
                        Some(ups) => {
                            let ldap_services = ups
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
                            Ok(ldap_services)
                        }
                        None => Ok(HashMap::new()),
                    }
                }
                Err(_) => Err(Error::JsonMalformed(VCAP_SERVICES.to_string())),
            }
        }
        Err(_) => Err(Error::EnvNotSet(VCAP_SERVICES)),
    }
}
*/

/*
/// todo Error, wenn 2 Services mit gleichem Namen existieren

pub fn get_service_by_name<T>(name: &str) -> Result<Service<T>, Error>
where
    T: DeserializeOwned,
{
    match get_services() {
        Ok(services) => {
            for key in services.keys() {
                for service in services.get(key).unwrap().iter() {
                    if service.name == name {
                        let service_json = serde_json::to_string(service).unwrap();
                        match serde_json::from_str::<Service<T>>(&service_json) {
                            Ok(service) => return Ok(service),
                            Err(_) => {
                                return Err(Error::JsonMalformed(format!(
                                    "{}.credentials",
                                    service.name.to_owned()
                                )))
                            }
                        }
                    }
                }
            }
            Err(Error::ServiceNotPresent(name))
        }
        Err(e) => Err(e),
    }
}
 */

#[cfg(test)]
mod test {
    use super::*;
    use indoc::*;
    use rstest::*;

    #[test]
    fn test_parse_ldap_services_full() {
        let full_services_json = indoc! {r#"
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

        let result = parse_ldap_services(full_services_json).unwrap();

        assert_eq!(result.len(), 1);
        let user_provided_services = result.get("user-provided").unwrap();
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
    fn test_parse_ldap_services_minimal() {
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

        let result = parse_ldap_services(minimal_services_json).unwrap();

        assert_eq!(result.len(), 1);
        let user_provided_services = result.get("user-provided").unwrap();
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
        let type_to_vec_map: HashMap<String, Vec<Service<LdapService>>> =
            HashMap::from( [("user-provided".to_string(), services)]);

        let ldap_services_map = map_ldap_services(&type_to_vec_map).unwrap();

        assert_eq!(ldap_services_map.len(), 1);
        let entry = ldap_services_map.get("active_dir").unwrap();
        assert_eq!(entry.url, "ldap://ldap1.provider.de:389");
        assert_eq!(entry.bind_dn, "cn=admin1,dc=de");
        assert_eq!(entry.password, "secret1");
        assert_eq!(entry.base_dn, "dc=de");
    }


    /*
    #[test]
    fn test_get_service_by_name_minimal() {
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
                        "url": "ldap://ldap1.consumer.de:389"
                    }
                }
            ]
        }"#};

        std::env::set_var("VCAP_SERVICES", minimal_services_json);
        let result = get_service_by_name::<LdapService>("ldap1");

        assert!(result.is_ok());
        let cf_service = result.unwrap();
        assert_eq!(cf_service.credentials.url, "ldap://ldap1.provider.de:389");
        assert_eq!(cf_service.credentials.bind_dn, "cn=admin1,dc=de");
        assert_eq!(cf_service.credentials.password, "secret1");
        assert_eq!(cf_service.credentials.base_dn, "dc=de");
    }
    */

    /*
    #[test]
    fn test_get_ldap_services_by_names() {
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

        std::env::set_var("VCAP_SERVICES", minimal_services_json);
        let result = get_ldap_services_by_names();

        assert!(result.is_ok());
        let ldap_services = result.unwrap();
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
    */

}
