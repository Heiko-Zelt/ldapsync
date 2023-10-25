use chrono::{Datelike, Timelike, Utc};
use ldap3::{Ldap, LdapConn, LdapConnAsync, LdapError, ResultEntry, Scope, SearchEntry, Mod, LdapResult};
use log::{debug, info};
use std::collections::{HashMap, HashSet};
//use serde_json::{Result, Value};

use crate::sub::cf_services::LdapService;
use crate::sub::ldap_utils::*;
use crate::sub::synchronisation_config::SynchronisationConfig;

/// The object class "extensibleObject" is defined in OpenLdap core schema.
/// So there is no need to extend the schema with an own object class.
pub const SYNC_TIMESTAMP_OBJ_CLASS: &str = "extensibleObject";
pub const SYNC_TIMESTAMP_DN_ATTR_NAME: &str = "cn";
pub const SYNC_TIMESTAMP_ATTR_NAME: &str = "name";

// Referenced source and target LdapServices have to live as long as this struct
#[derive(Debug)]
pub struct Synchronisation<'a> {
    /// map: name -> LdapService
    pub ldap_services: &'a HashMap<String, LdapService>,
    pub sync_config: &'a SynchronisationConfig
}

impl<'a> Synchronisation<'a> {
    /*
    pub fn from_synchronisation_with_names(
        services: &'a HashMap<String, LdapService>,
        sync_with_names: &SynchronisationConfig,
    ) -> Synchronisation<'a> {
        Synchronisation {
            source_ref: services.get(&sync_with_names.source).unwrap(),
            target_ref: services.get(&sync_with_names.target).unwrap(),
            base_dns: sync_with_names.base_dns.clone(),
            ts_store_ref: services.get(&sync_with_names.ts_store).unwrap(),
            ts_base_dn: sync_with_names.ts_base_dn.clone(),
        }
    }
     */

    /// synchonizes 2 LDAP directories.
    /// - connects to both directories
    /// - for every DN: sync_delete() & sync_modify()
    /// - disconnects
    /// returns: number of touched (added, modified and delted) entries)
    pub async fn synchronize(&self, dry_run: bool) -> Result<usize, LdapError> {
        let source_service = self.ldap_services.get(&self.sync_config.source).unwrap();
        let target_service = self.ldap_services.get(&self.sync_config.target).unwrap();
        let ts_store_service = self.ldap_services.get(&self.sync_config.ts_store).unwrap();

        let mut source_ldap = simple_connect(source_service).await?;
        let mut target_ldap = simple_connect(target_service).await?;
        let mut ts_store_ldap = simple_connect(ts_store_service).await?;

        let old_sync_timestamp = self.load_sync_timestamp(&mut ts_store_ldap).await.unwrap();

        let now = Utc::now();
        let new_sync_timestamp = format!(
            "{}{:02}{:02}{:02}{:02}{:02}Z",
            now.year(),
            now.month(),
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        );

        for dn in self.sync_config.base_dns.iter() {
            Self::sync_delete(
                &mut source_ldap,
                &mut target_ldap,
                &source_service.base_dn,
                &target_service.base_dn,
                dn, dry_run
            ).await?;
            Self::sync_modify(
                &mut source_ldap,
                &mut target_ldap,
                &source_service.base_dn,
                &target_service.base_dn,
                &dn,
                &old_sync_timestamp,
                 dry_run
            ).await?;
        // - sync_modify(old_sync_timestamp);
        }

        self.save_sync_timestamp(&mut ts_store_ldap, &new_sync_timestamp).await.unwrap();
        Ok(0)
    }

    /// return type Option<LdapError> would be good enough
    pub async fn save_sync_timestamp(&self, ldap: &mut Ldap, sync_timestamp: &str) -> Result<LdapResult, LdapError> {
        let new_values = HashSet::from([sync_timestamp]);
        let modi = Mod::Replace(SYNC_TIMESTAMP_ATTR_NAME, new_values);
        let mods = vec![modi];
        let ts_store_service = self.ldap_services.get(&self.sync_config.ts_store).unwrap();
        let dn =join_2_dns(&self.sync_config.ts_dn, &ts_store_service.base_dn);
        ldap.modify(&dn, mods).await
    }

    /// adding extensibleClass allows the addition of any attribute to an entry
    /// objectclass ( 1.3.6.1.4.1.1466.101.120.111 NAME 'extensibleObject'
    /// DESC 'RFC2252: extensible object' SUP top AUXILIARY )
    pub async fn load_sync_timestamp(&self, ldap: &mut Ldap) -> Result<String, LdapError> {
        let ts_store_service = self.ldap_services.get(&self.sync_config.ts_store).unwrap();
        let ts_store_service_base_dn = &ts_store_service.base_dn;
        let dn = join_2_dns(&self.sync_config.ts_dn, ts_store_service_base_dn);
        debug!("loading sync timestamp from dn: {}", dn);
        let search_result = ldap
        .search(
            &dn,
            Scope::Base,
            &format!("(objectClass={})", SYNC_TIMESTAMP_OBJ_CLASS),
            vec![SYNC_TIMESTAMP_ATTR_NAME])
        .await?;
        let ldap_result = search_result.1;
        debug!("LDAP result code: {}", ldap_result.rc);
        if ldap_result.rc != 0 { // Is result code ok?
            return Err(LdapError::LdapResult{result: ldap_result})
        }
           
        let result_entries = search_result.0;
        // todo pruefen: sollte genau 1 sein
        debug!("number of entries: {}", result_entries.len());
        let result_entry = result_entries[0].clone();
        let search_entry = SearchEntry::construct(result_entry);
        debug!("entry: {:?}", search_entry);
        // todo check if there is exact one value
        let sync_timestamp_attr = search_entry.attrs.get(SYNC_TIMESTAMP_ATTR_NAME).unwrap();
        let sync_timestamp_value = sync_timestamp_attr[0].clone();
        Ok(sync_timestamp_value)
    }

    /// Löscht alle Einträge, die im Ziel-LDAP vorhanden sind aber nicht im Quell-LDAP.
    /// Es werden zuerst hirarchich untergeordnete Einträge gelöscht, dann übergeordnete.
    /// (Sortierung nach Länge des DNs)
    ///
    /// Es wird erst im Ziel-Server gesucht.
    /// Wenn dort keine Einträge vorhanden sind, muss im Quell-Server gar nicht mehr gesucht werden.
    ///
    /// Die DNs werden auf Kleinschreibung normiert und sortiert.
    ///
    /// returns number of deleted entries
    pub async fn sync_delete(
        source_ldap: &mut Ldap,
        target_ldap: &mut Ldap,
        source_base_dn: &str,
        target_base_dn: &str,
        sync_dn: &str,
        dry_run: bool,
    ) -> Result<usize, LdapError> {
        info!("sync_delete(source_ldap: {:?}, target_ldap: {:?}, source_base_dn: {:?}, target_base_dn: {:?}, sync_dn: {:?})",
     source_ldap, target_ldap, source_base_dn, target_base_dn, sync_dn);

        let target_sync_dn = join_2_dns(sync_dn, target_base_dn);
        let target_norm_dns = search_norm_dns(target_ldap, &target_sync_dn).await?;

        // Wenn es im Ziel-System keine Einträge gibt, kann auch nichts gelöscht werden.
        if target_norm_dns.len() == 0 {
            Ok(0)
        } else {
            let source_sync_dn = join_2_dns(sync_dn, source_base_dn);
            let source_norm_dns = search_norm_dns(source_ldap, &source_sync_dn).await?;
            let garbage_diff = target_norm_dns.difference(&source_norm_dns);
            let mut garbage_vec: Vec<&String> = garbage_diff.collect();
            // längste DNs zuerst
            garbage_vec.sort_by(|a, b| b.len().cmp(&a.len()));
            for dn in garbage_vec.iter() {
                // norm_dn ends with a comma if it is not empty
                //let target_dn = format!("{}{}", norm_dn, target.base_dn);
                let target_dn = join_3_dns(dn, sync_dn, target_base_dn);
                info!("deleting: {}", target_dn);
                if !dry_run {
                    target_ldap.delete(&target_dn).await?;
                }
            }
            Ok(garbage_vec.len())
        }
    }

    /// Gleicht neue und geänderte Einträge in 2 LDAP Servern (Teilbäumen) ab.
    /// Die Einträge werden mittels modifyTimestamp gefunden.
    /// (Gelöschte Einträge werden nicht abgeglichen.)
    /// source: Provider LDAP Service
    /// target: Consumer LDAP Service
    ///
    /// modify_timestamp: Zeitpunkt des letzten erfolgreichen Abgleichs.
    /// Beispiel: "20001231235959Z" oder "20001231235959z"
    /// Der Zeitstempel wird immer vom LDAP-Server gesetzt. Die Zeitzone ist immer einheitlich klein oder groß geschrieben.
    /// OpenLDAP: Groß-"Z", Oracle Internet Directory: abhängig von Software-Version groß oder klein geschrieben.
    /// Da die Zeitzone ganz hinten steht ist sie bei Größer/kleiner-Vergleichen/Sortierung kaum relevant (aber bei Gleichheit!!!).
    ///
    /// Falls der Eintrag im Ziel-Verzeichnis nicht vorhanden ist => Eintrag hinzufügen
    /// Falls der Eintrag im Ziel-Verzeichnis vorhanden ist => 3 Mögliche Fälle pro Attribut:
    /// - Attribut in Quell-Eintrag und Ziel vorhanden, aber Werte (teils) unterschiedlich => Mod::Replace, Attribut (mit allen Werten) ersetzen
    /// - Attribut in Ziel-Eintrag vorhanden und nicht in Quelle => Mod::Delete, Attribut (mit allen Werten) löschen
    /// - Attribut in Quell-Verzeichnis vorhanden und nicht in Ziel => Mod::Add, Attribut (mit allen Werten) hinzufügen
    ///
    /// returns: Wenn erfolgreich: Anzahl der abgeglichenen Einträge (add + modify)
    /// 
    /// todo vollständig implementieren
    pub async fn sync_modify(
        source_ldap: &mut Ldap,
        target_ldap: &mut Ldap,
        source_base_dn: &str,
        _target_base_dn: &str,
        sync_dn: &str,
        old_modify_timestamp: &str,
        _dry_run: bool
    ) -> Result<usize, LdapError> {
        info!(
            "sync_modify(source_ldap: {:?}, target_ldap: {:?}, old_modify_timestamp: {:?})",
            source_ldap, target_ldap, old_modify_timestamp
        );

        // im Quell-LDAP alle geänderten Einträge suchen

        let filter = format!("(modifyTimestamp>={})", old_modify_timestamp);
        debug!("start search with filter: {}", filter);

        let source_sync_dn = join_2_dns(sync_dn, source_base_dn);
        let search_result = source_ldap
            .search(&source_sync_dn, Scope::Subtree, &filter, vec!["*"])
            .await?;
        debug!("finished search");

        let ldap_result = search_result.1;
        info!("LDAP result code: {}", ldap_result.rc);
        if ldap_result.rc == 0 {
            // Is result code ok?
            let result_entries = search_result.0;
            // Attribute im Ziel-LDAP ersetzen oder Eintrag neu anlegen
            info!("number of entries: {}", result_entries.len());
            
            for result_entry in result_entries {
                let search_entry = SearchEntry::construct(result_entry);
                debug!("entry: {:?}", search_entry);
            }
        }
        Ok(0)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::sub::ldap_utils::test::start_test_server;
    use crate::sub::synchronisation_config::SynchronisationConfig;
    use indoc::*;

    /*
    #[test]
    fn test_from_synchronisation_with_names() {
        let sync_with_names = SynchronisationConfig {
            source: "src".to_string(),
            target: "trg".to_string(),
            base_dns: vec![
                "cn=org1".to_string(),
                "cn=org2".to_string(),
                "cn=org3".to_string(),
            ],
            ts_store: "trg".to_string(),
            ts_base_dn: "cn=sync_timestamps".to_string(),
        };

        let service1 = LdapService {
            url: "ldap://provider-ldap.de:389".to_string(),
            bind_dn: "cn=admin,dc=source,dc=de".to_string(),
            password: "secret".to_string(),
            base_dn: "dc=source,dc=de".to_string(),
        };

        let service2 = LdapService {
            url: "ldap://consumer-ldap.de:389".to_string(),
            bind_dn: "cn=admin,dc=target,dc=de".to_string(),
            password: "secret".to_string(),
            base_dn: "dc=target,dc=de".to_string(),
        };

        let services =
            HashMap::from([("src".to_string(), service1), ("trg".to_string(), service2)]);

        let result = Synchronisation::from_synchronisation_with_names(&services, &sync_with_names);
        assert_eq!(result.source_ref, services.get("src").unwrap());
        assert_eq!(result.target_ref, services.get("trg").unwrap());
    }
    */

    #[tokio::test]
    async fn test_sync_modified() {
        let _ = env_logger::try_init();

        let source_plain_port = 13389;
        let source_tls_port = 13636;
        let source_url = format!("ldap://127.0.0.1:{}", source_plain_port);
        let source_bind_dn = "cn=admin,dc=test".to_string();
        let source_password = "secret".to_string();
        let source_base_dn = "dc=test".to_string();
        let source_content = indoc! { "
            dn: dc=test
            objectclass: dcObject
            objectclass: organization
            o: Test Org
            dc: test
            modifyTimestamp: 20231019182734Z

            dn: cn=admin,dc=test
            objectClass: inetOrgPerson
            sn: Admin
            userPassword: secret
            modifyTimestamp: 20231019182735Z

            dn: ou=Users,dc=test
            objectClass: top
            objectClass: organizationalUnit
            ou: Users
            modifyTimestamp: 20231019182736Z
    
            dn: o=de,ou=Users,dc=test
            objectClass: top
            objectClass: organization
            o: de
            modifyTimestamp: 20231019182737Z

            dn: o=AB,o=de,ou=Users,dc=test
            objectClass: top
            objectClass: organization
            o: AB
            modifyTimestamp: 20231019182738Z

            dn: cn=xy012345,o=AB,o=de,ou=Users,dc=test
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: hallowelt123!
            modifyTimestamp: 20231019182739Z"
        };

        let target_plain_port = 14389;
        let target_tls_port = 14636;
        let target_url = format!("ldap://127.0.0.1:{}", target_plain_port);
        let target_bind_dn = "cn=admin,dc=test".to_string();
        let target_password = "secret".to_string();
        let target_base_dn = "dc=test".to_string();
        let target_content = indoc! { "
            dn: dc=test
            objectclass: dcObject
            objectclass: organization
            o: Test Org
            dc: test

            dn: cn=admin,dc=test
            objectClass: inetOrgPerson
            sn: Admin
            userPassword: secret
    
            dn: ou=Users,dc=test
            objectClass: top
            objectClass: organizationalUnit
            ou: Users
        
            dn: o=de,ou=Users,dc=test
            objectClass: top
            objectClass: organization
            o: de

            dn: o=XY,o=de,ou=Users,dc=test
            objectClass: top
            objectClass: organization
            o: XY

            dn: cn=xy012345,o=XY,o=de,ou=Users,dc=test
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: hallowelt123!"
        };

        let _source_server = start_test_server(
            source_plain_port,
            source_tls_port,
            &source_base_dn,
            source_content,
        )
        .await;
        let _target_server = start_test_server(
            target_plain_port,
            target_tls_port,
            &target_base_dn,
            target_content,
        )
        .await;

        //let src_base_dn = "dc=test".to_string();
        //let _ldap_conn = simple_connect_sync(&src_url, &src_bind_dn, &src_password).unwrap();
        let source_service = LdapService {
            url: source_url,
            bind_dn: source_bind_dn,
            password: source_password,
            base_dn: source_base_dn.clone(),
        };

        let target_service = LdapService {
            url: target_url,
            bind_dn: target_bind_dn,
            password: target_password,
            base_dn: target_base_dn.clone(),
        };

        let old_modify_timestamp = "19751129000000Z";

        let mut source_ldap = simple_connect(&source_service).await.unwrap();
        let mut target_ldap = simple_connect(&target_service).await.unwrap();

        let result =
            Synchronisation::sync_modify(
                &mut source_ldap,
                &mut target_ldap,
                &source_base_dn,
                &target_base_dn,
                "ou=Users",
                old_modify_timestamp,
            true)
                .await;
        info!("result: {:?}", result);
        assert_eq!(result.unwrap(), 3); // oder 4 inklusive cn=Users?
    }

    #[tokio::test]
    async fn test_sync_delete() {
        //env_logger::init();
        let _ = env_logger::try_init();

        let source_plain_port = 15389;
        let source_tls_port = 15636;
        let source_url = format!("ldap://127.0.0.1:{}", source_plain_port);
        let source_bind_dn = "cn=admin,dc=source".to_string();
        let source_password = "secret".to_string();
        let source_base_dn = "dc=source".to_string();
        let source_content = indoc! { "
            dn: dc=source
            objectclass: dcObject
            objectclass: organization
            o: Source Org
            dc: source

            dn: cn=admin,dc=source
            objectClass: inetOrgPerson
            sn: Admin
            userPassword: secret

            dn: ou=Users,dc=source
            objectClass: top
            objectClass: organizationalUnit
            ou: Users
    
            dn: o=de,ou=Users,dc=source
            objectClass: top
            objectClass: organization
            o: de

            dn: o=ABC,o=de,ou=Users,dc=source
            objectClass: top
            objectClass: organization
            o: ABC
            modifyTimestamp: 20231019182738Z"
        };

        let target_plain_port = 16389;
        let target_tls_port = 16636;
        let target_url = format!("ldap://127.0.0.1:{}", target_plain_port);
        let target_bind_dn = "cn=admin,dc=target".to_string();
        let target_password = "secret".to_string();
        let target_base_dn = "dc=target".to_string();
        let target_content = indoc! { "
            dn: dc=target
            objectclass: dcObject
            objectclass: organization
            o: Target Org
            dc: target

            dn: cn=admin,dc=target
            objectClass: inetOrgPerson
            sn: Admin
            userPassword: secret
    
            dn: ou=Users,dc=target
            objectClass: top
            objectClass: organizationalUnit
            ou: Users
        
            dn: o=de,ou=Users,dc=target
            objectClass: top
            objectClass: organization
            o: de

            dn: o=XY,o=de,ou=Users,dc=target
            objectClass: top
            objectClass: organization
            o: XY

            dn: cn=xy012345,o=XY,o=de,ou=Users,dc=target
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: hallowelt123!"
        };

        let _source_server = start_test_server(
            source_plain_port,
            source_tls_port,
            &source_base_dn,
            source_content,
        )
        .await;
        let _target_server = start_test_server(
            target_plain_port,
            target_tls_port,
            &target_base_dn,
            target_content,
        )
        .await;

        let source_service = LdapService {
            url: source_url,
            bind_dn: source_bind_dn,
            password: source_password,
            base_dn: source_base_dn.clone(),
        };

        let target_service = LdapService {
            url: target_url,
            bind_dn: target_bind_dn,
            password: target_password,
            base_dn: target_base_dn.clone(),
        };

        let mut source_ldap = simple_connect(&source_service).await.unwrap();
        let mut target_ldap = simple_connect(&target_service).await.unwrap();

        let result = Synchronisation::sync_delete(
            &mut source_ldap,
            &mut target_ldap,
            &source_base_dn,
            &target_base_dn,
            "ou=Users",
            false,
        )
        .await;
        // todo assertions: compare norm DNs of subtrees

        info!("result: {:?}", result);
        assert_eq!(result.unwrap(), 2);
    }

    #[tokio::test]
    async fn test_load_sync_timestamp() {
        let _ = env_logger::try_init();

        let ts_store_name = "ldap1".to_string();
        let ts_store_plain_port = 16389;
        let ts_store_tls_port = 16636;
        let ts_store_url = format!("ldap://127.0.0.1:{}", ts_store_plain_port);
        let ts_store_bind_dn = "cn=admin,dc=test".to_string();
        let ts_store_password = "secret".to_string();
        let ts_store_base_dn = "dc=test".to_string();
        let ts_store_content = indoc! { "
            dn: dc=test
            objectclass: dcObject
            objectclass: organization
            o: Test Org
            dc: test

            dn: cn=admin,dc=test
            objectClass: inetOrgPerson
            cn: admin
            sn: Admin
            userPassword: secret

            dn: o=sync_timestamps,dc=test
            objectClass: top
            objectClass: organization
            o: sync_timestamps

            dn: o=provider-consumer,o=sync_timestamps,dc=test
            objectClass: top
            objectClass: organization
            objectClass: extensibleObject
            o: provider-consumer
            name: 20231025235959Z

            dn: ou=Users,dc=test
            objectClass: top
            objectClass: organizationalUnit
            ou: Users"
        };

        let _ts_store_server = start_test_server(
            ts_store_plain_port,
            ts_store_tls_port,
            &ts_store_base_dn,
            ts_store_content,
        )
        .await;

        let ts_store_service = LdapService {
            url: ts_store_url,
            bind_dn: ts_store_bind_dn,
            password: ts_store_password,
            base_dn: ts_store_base_dn.clone(),
        };

        let ldap_services_map = HashMap::from( [(ts_store_name.clone(), ts_store_service)]);

        let sync_config = SynchronisationConfig {
            source: "provider".to_string(),
            target: "consumer".to_string(),
            base_dns: vec![ "cn=unused".to_string() ],
            ts_store: ts_store_name.clone(),
            /// ts_base_dn is relative to the base_dn of the LdapService
            ts_dn: "o=provider-consumer,o=sync_timestamps".to_string(),
        };

        let synchronisation = Synchronisation {
            ldap_services: &ldap_services_map,
            sync_config: &sync_config,
        };

        let service_to_use = ldap_services_map.get(&ts_store_name).unwrap();
        debug!("use service: {:?}", &service_to_use);
        let mut ts_store_ldap = simple_connect(service_to_use).await.unwrap();

        debug!("ts_store_ldap: {:?}", ts_store_ldap);
        let result = synchronisation.load_sync_timestamp(&mut ts_store_ldap).await.unwrap();

        assert_eq!(result, "20231025235959Z");

    }

    #[tokio::test]
    async fn test_save_sync_timestamp() {
        let _ = env_logger::try_init();

        let sync_timestamp ="20231025235959Z";
        let ts_store_name = "ldap1".to_string();
        let ts_store_plain_port = 16389;
        let ts_store_tls_port = 16636;
        let ts_store_url = format!("ldap://127.0.0.1:{}", ts_store_plain_port);
        let ts_store_bind_dn = "cn=admin,dc=test".to_string();
        let ts_store_password = "secret".to_string();
        let ts_store_base_dn = "dc=test".to_string();
        let ts_store_content = indoc! { "
            dn: dc=test
            objectclass: dcObject
            objectclass: organization
            o: Test Org
            dc: test

            dn: cn=admin,dc=test
            objectClass: inetOrgPerson
            cn: admin
            sn: Admin
            userPassword: secret

            dn: o=sync_timestamps,dc=test
            objectClass: top
            objectClass: organization
            o: sync_timestamps

            dn: o=provider-consumer,o=sync_timestamps,dc=test
            objectClass: top
            objectClass: organization
            objectClass: extensibleObject
            o: provider-consumer
            name: 19750101235959Z

            dn: ou=Users,dc=test
            objectClass: top
            objectClass: organizationalUnit
            ou: Users"
        };

        let _ts_store_server = start_test_server(
            ts_store_plain_port,
            ts_store_tls_port,
            &ts_store_base_dn,
            ts_store_content,
        )
        .await;

        let ts_store_service = LdapService {
            url: ts_store_url,
            bind_dn: ts_store_bind_dn,
            password: ts_store_password,
            base_dn: ts_store_base_dn.clone(),
        };

        let ldap_services_map = HashMap::from( [(ts_store_name.clone(), ts_store_service)]);

        let sync_config = SynchronisationConfig {
            source: "provider".to_string(),
            target: "consumer".to_string(),
            base_dns: vec![ "cn=unused".to_string() ],
            ts_store: ts_store_name.clone(),
            /// ts_base_dn is relative to the base_dn of the LdapService
            ts_dn: "o=provider-consumer,o=sync_timestamps".to_string(),
        };

        let synchronisation = Synchronisation {
            ldap_services: &ldap_services_map,
            sync_config: &sync_config,
        };

        let service_to_use = ldap_services_map.get(&ts_store_name).unwrap();
        debug!("use service: {:?}", &service_to_use);
        let mut ts_store_ldap = simple_connect(service_to_use).await.unwrap();

        debug!("ts_store_ldap: {:?}", ts_store_ldap);
        let result = synchronisation.save_sync_timestamp(&mut ts_store_ldap, sync_timestamp).await;
        debug!("result: {:?}", result);
        assert!(result.is_ok());

    }


}
