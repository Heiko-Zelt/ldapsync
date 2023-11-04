use chrono::{Utc, DateTime};
use ldap3::{Ldap, LdapError, LdapResult, SearchEntry};
use log::{debug, info, warn};
use regex::Regex;
use std::collections::{HashMap, HashSet};

use crate::cf_services::LdapService;
use crate::ldap_utils::*;
use crate::ldap_result_codes::*;
use crate::synchronization_config::SynchronizationConfig;

/// The object class "extensibleObject" is defined in OpenLdap core schema.
/// So there is no need to extend the schema with an own object class.
pub const SYNC_TIMESTAMP_OBJ_CLASS: &str = "extensibleObject";
pub const SYNC_TIMESTAMP_DN_ATTR_NAME: &str = "cn";
pub const SYNC_TIMESTAMP_ATTR_NAME: &str = "name";

/// Stores, how many entries have been added, modified and deleted
/// in the last run.
#[derive(Debug)]
pub struct SyncStatistics {
    /// number of entries found, with newer modifyTimestamp than on last successful run
    pub recently_modified: usize,

    /// number of entries added
    pub added: usize,

    /// number of really modified entries (after comparison of relevant attributes and values)
    pub attrs_modified: usize,

    /// number of entries deleted
    pub deleted: usize
}

#[derive(Debug)]
pub struct ModiStatistics {
    pub recently_modified: usize,
    pub added: usize,
    pub attrs_modified: usize,
}

#[derive(Debug)]
pub enum ModiOne {
    Added,
    AttrsModified,
    Unchanged,
}

/// Referenced source and target LdapServices have to live as long as this struct
#[derive(Debug)]
pub struct Synchronization<'a> {
    /// map: name -> LdapService
    pub ldap_services: &'a HashMap<String, LdapService>,
    pub sync_config: &'a SynchronizationConfig,
    pub attrs: &'a Vec<String>,
    pub exclude_attrs: &'a Option<Regex>,
    pub dry_run: bool,
}

impl<'a> Synchronization<'a> {

    /// synchonizes 2 LDAP directories.
    /// - connects to both directories
    /// - for every DN: sync_delete() & sync_modify()
    /// - disconnects
    /// returns: number of touched (added, modified and delted) entries)
    pub async fn synchronize(&self, old_sync_datetime: Option<DateTime<Utc>>) -> Result<SyncStatistics, LdapError> {
        let source_service = self.ldap_services.get(&self.sync_config.source).unwrap();
        let target_service = self.ldap_services.get(&self.sync_config.target).unwrap();

        let mut sync_statistics = SyncStatistics { recently_modified: 0, added: 0, attrs_modified: 0, deleted: 0 };
        let mut source_ldap = simple_connect(source_service).await?;
        let mut target_ldap = simple_connect(target_service).await?;

        let sync_ldap_timestamp = match old_sync_datetime {
           Some(datetime) => Some(format_ldap_timestamp(&datetime)),
           None => None,
        };

        for dn in self.sync_config.base_dns.iter() {
            sync_statistics.deleted += Self::sync_delete(
                &mut source_ldap,
                &mut target_ldap,
                &source_service.base_dn,
                &target_service.base_dn,
                dn,
                self.dry_run,
            )
            .await?;
            let modi_statistics = Self::sync_modify(
                &mut source_ldap,
                &mut target_ldap,
                &source_service.base_dn,
                &target_service.base_dn,
                &dn,
                &sync_ldap_timestamp,
                self.attrs,
                self.exclude_attrs,
                self.dry_run,
            )
            .await?;
            sync_statistics.recently_modified += modi_statistics.recently_modified;
            sync_statistics.added += modi_statistics.added;
            sync_statistics.attrs_modified += modi_statistics.attrs_modified;
        }

        Ok(sync_statistics)
    }

    /// return type Option<LdapError> would be good enough
    /* 
    pub async fn save_sync_timestamp(
        &self,
        ldap: &mut Ldap,
        sync_timestamp: &str,
    ) -> Result<LdapResult, LdapError> {
        debug!(r#"save_sync_timestamp: saving sync timestamp: "{}")"#, sync_timestamp);
        let new_values = HashSet::from([sync_timestamp]);
        let modi = Mod::Replace(SYNC_TIMESTAMP_ATTR_NAME, new_values);
        let mods = vec![modi];
        let ts_store_service = self.ldap_services.get(&self.sync_config.ts_store).unwrap();
        let dn = join_2_dns(&self.sync_config.ts_dn, &ts_store_service.base_dn);
        let result = ldap.modify(&dn, mods).await;
        debug!(r#"save_sync_timestamp: result: "{:?}")"#, result);

        match result {
            Ok(LdapResult { rc: 0, ..}) => result,
            Err(err) => Err(err),
            _ => Err(LdapError::LdapResult { result: result.unwrap() }) // Ok with rc != 0 is an error too
        }
    }
    */

    /// adding extensibleClass allows the addition of any attribute to an entry
    /// objectclass ( 1.3.6.1.4.1.1466.101.120.111 NAME 'extensibleObject'
    /// DESC 'RFC2252: extensible object' SUP top AUXILIARY )
    /*
    pub async fn load_sync_timestamp(&self, ldap: &mut Ldap) -> Result<String, LdapError> {
        let ts_store_service = self.ldap_services.get(&self.sync_config.ts_store).unwrap();
        let ts_store_service_base_dn = &ts_store_service.base_dn;
        let dn = join_2_dns(&self.sync_config.ts_dn, ts_store_service_base_dn);
        debug!(r#"load_sync_timestamp: loading sync timestamp from dn: "{}""#, dn);
        let search_result = ldap
            .search(
                &dn,
                Scope::Base,
                &format!("(objectClass=*)"),
                vec![SYNC_TIMESTAMP_ATTR_NAME],
            )
            .await?.success()?;

        let result_entries = search_result.0;
        // TODO pruefen: sollte genau 1 sein
        debug!("load_sync_timestamp: found number of entries: {}", result_entries.len());
        let result_entry = result_entries[0].clone();
        let search_entry = SearchEntry::construct(result_entry);
        //debug!("load_sync_timestamp: entry: {:?}", search_entry);
        // TODO check if there is exact one value
        let sync_timestamp_attr = search_entry.attrs.get(SYNC_TIMESTAMP_ATTR_NAME).unwrap(); // TODO: panic oder Fehler zurückgeben?
        let sync_timestamp_value = sync_timestamp_attr[0].clone();
        debug!("timestamp: {}", sync_timestamp_value);
        Ok(sync_timestamp_value)
    }
    */

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
        info!(r#"sync_delete: source_base_dn: "{}", target_base_dn: "{}", sync_dn: "{}")"#, source_base_dn, target_base_dn, sync_dn);

        let target_sync_dn = join_2_dns(sync_dn, target_base_dn);
        let target_norm_dns = search_norm_dns(target_ldap, &target_sync_dn).await?;
        
        debug!("sync_delete: target DNs:");
        // TODO nur ausführen, wenn log level debug
        log_debug_dns("sync_delete:", &target_norm_dns);

        // Wenn es im Ziel-System keine Einträge gibt, kann auch nichts gelöscht werden.
        if target_norm_dns.len() == 0 {
            Ok(0)
        } else {
            let source_sync_dn = join_2_dns(sync_dn, source_base_dn);
            let source_norm_dns = search_norm_dns(source_ldap, &source_sync_dn).await?;
            debug!("sync_delete: source DNs:");
            // TODO nur ausführen, wenn log level debug
            log_debug_dns("sync_delete:", &source_norm_dns);
            let garbage_diff = target_norm_dns.difference(&source_norm_dns);
            let mut garbage_vec: Vec<&String> = garbage_diff.collect();

            // Von den Blättern zur Wurzel, längere DNs zuerst sortieren. Absteigend nach Länge der DNs.
            garbage_vec.sort_by(|a ,b| compare_by_length_desc_then_alphabethical(a, b));

            for dn in garbage_vec.iter() {
                // norm_dn ends with a comma if it is not empty
                //let target_dn = format!("{}{}", norm_dn, target.base_dn);
                let target_dn = join_3_dns(dn, sync_dn, target_base_dn);
                info!(r#"sync_delete: deleting entry: "{}""#, target_dn);
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
    /// TODO vollständig implementieren
    pub async fn sync_modify(
        source_ldap: &mut Ldap,
        target_ldap: &mut Ldap,
        source_base_dn: &str,
        target_base_dn: &str,
        sync_dn: &str,
        old_modify_timestamp: &Option<String>,
        attrs: &Vec<String>,
        exclude_attrs: &Option<Regex>,
        dry_run: bool,
    ) -> Result<ModiStatistics, LdapError> {
        debug!(
            r#"sync_modify: source_base_dn: "{}", target_base_dn: "{}", sync_dn: "{}", old_modify_timestamp: {:?})"#,
            source_base_dn, target_base_dn, sync_dn, old_modify_timestamp
        );
        // im Quell-LDAP alle neulich geänderten Einträge suchen
        let source_sync_dn = join_2_dns(sync_dn, source_base_dn);

        let mut source_search_entries = search_modified_entries_attrs_filtered(
            source_ldap,
            &source_sync_dn,
            old_modify_timestamp,
            attrs,
            exclude_attrs,
        )
        .await?;

        let mut modi_statistics = ModiStatistics { recently_modified: source_search_entries.len(), added: 0, attrs_modified: 0 };

        // Von der Wurzel zu den Blättern, kürzere DNs zuerst sortieren. Austeigend nach Länger der DNs.
        source_search_entries.sort_by(|a, b| a.dn.len().cmp(&b.dn.len()));

        info!(
            r#"sync_modify: subtree: "{}", number of recently modified entries: {}"#,
            source_sync_dn, source_search_entries.len()
        );

        let source_base_dn_len = source_base_dn.len();
        for source_search_entry in source_search_entries {
            let modified = Self::sync_modify_one_entry(
                target_ldap,
                source_base_dn_len,
                target_base_dn,
                source_search_entry,
                exclude_attrs,
                dry_run,
            )
            .await?;
            match modified {
                ModiOne::Unchanged => {},
                ModiOne::Added => modi_statistics.added += 1,
                ModiOne::AttrsModified => modi_statistics.attrs_modified += 1,
            }
        }
        Ok(modi_statistics)
    }

    pub async fn sync_modify_one_entry(
        target_ldap: &mut Ldap,
        source_base_dn_len: usize,
        target_base_dn: &str,
        source_search_entry: SearchEntry,
        exclude_attrs: &Option<Regex>,
        dry_run: bool,
    ) -> Result<ModiOne, LdapError> {
        debug!(r#"sync_modify_one_entry: source entry: {}"#, debug_search_entry(&source_search_entry));
        if source_search_entry.bin_attrs.len() != 0 {
            warn!(r#"sync_modify_one_entry: Ignoring attribute(s) with binary value in source entry."#);
        }

        let mut trunc_dn = source_search_entry.dn.clone();
        truncate_dn(&mut trunc_dn, source_base_dn_len);
        let target_dn = join_2_dns(&trunc_dn, target_base_dn);
        
        let target_search_result = 
            search_one_entry_by_dn(target_ldap, &target_dn).await;

        match target_search_result {
            Ok(mut entry) => {
                match exclude_attrs {
                    Some(ex) => entry.attrs = filter_attrs(&entry.attrs, &ex),
                    None => {},
                };
                debug!(r#"sync_modify_one_entry: target entry exists: {})"#, debug_search_entry(&entry));
                if entry.bin_attrs.len() != 0 {
                    warn!(r#"sync_modify_one_entry: Ignoring attribute(s) with binary value(s) in target entry."#);
                }
                let mods = diff_attributes(&source_search_entry.attrs, &entry.attrs);
                if mods.is_empty() {
                    debug!(r#"sync_modify_one_entry: dn: "{}", no differences found"#, entry.dn);
                    return Ok(ModiOne::Unchanged);
                }
                info!(r#"sync_modify_one_entry: modifying entry: dn: "{}", modifications: {:?}"#, entry.dn, debug_mods(&mods));
                // If mods is empty, maybe because only excluded attributes have changed. Then don't modify.
                if !dry_run {
                    target_ldap.modify(&target_dn, mods).await?;
                }
                Ok(ModiOne::AttrsModified)
            }
            Err(LdapError::LdapResult { // no problem => add entry
                result: LdapResult {
                    rc: RC_NO_SUCH_OBJECT!(),
                    ..
                }
            }) => {
                debug!(r#"sync_modify_one_entry: target entry did not exist"#);
                // convert HashMap<String, Vec<String>> to Vec<(String, HashSet<String>)>
                let target_attrs = source_search_entry
                    .attrs
                    .iter()
                    .map(|(attr_name, attr_values)| {
                        let a: String = attr_name.clone();
                        let vs: HashSet<String> = HashSet::from_iter(attr_values.iter().cloned());
                        (a, vs)
                    })
                    .collect::<Vec<(String, HashSet<String>)>>();
                info!(r#"sync_modify_one_entry: adding entry: {}"#, debug_search_entry(&source_search_entry));
                if !dry_run {
                    target_ldap.add(&target_dn, target_attrs).await?;
                }
                Ok(ModiOne::Added)
            }
            Err(err) => return Err(err) // other return code
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ldap_utils::simple_connect;
    use crate::ldap_utils::test::{start_test_server, search_all, assert_vec_search_entries_eq, next_port};
    use crate::ldif::parse_ldif_as_search_entries;
    use crate::synchronization_config::SynchronizationConfig;
    use indoc::*;
    use chrono::{TimeZone, Utc};
  

    #[tokio::test]
    async fn test_sync_modified() {
        let _ = env_logger::try_init();

        let source_plain_port = next_port();
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

            # to be added
            dn: o=AB,o=de,ou=Users,dc=test
            objectClass: top
            objectClass: organization
            o: AB
            modifyTimestamp: 20231019182738Z
            
            # to be added
            dn: cn=xy012345,o=AB,o=de,ou=Users,dc=test
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: hallowelt123!
            modifyTimestamp: 20231019182739Z"
        };

        let target_plain_port = next_port();
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
    
            # no modifications
            dn: ou=Users,dc=test
            objectClass: top
            objectClass: organizationalUnit
            ou: Users
        
            # differs
            dn: o=de,ou=Users,dc=test
            objectClass: top
            objectClass: organization
            o: de
            description: added a description

            # ignored
            dn: o=XY,o=de,ou=Users,dc=test
            objectClass: top
            objectClass: organization
            o: XY

            # ignored
            dn: cn=xy012345,o=XY,o=de,ou=Users,dc=test
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: hallowelt123!"
        };

        let _source_server = start_test_server(
            source_plain_port,
            &source_base_dn,
            source_content,
        )
        .await;
        let _target_server = start_test_server(
            target_plain_port,
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

        let old_modify_timestamp = "19751129000000Z".to_string();

        let mut source_ldap = simple_connect(&source_service).await.unwrap();
        let mut target_ldap = simple_connect(&target_service).await.unwrap();

        let result = Synchronization::sync_modify(
            &mut source_ldap,
            &mut target_ldap,
            &source_base_dn,
            &target_base_dn,
            "ou=Users",
            &Some(old_modify_timestamp),
            &vec!["*".to_string()],
            &Some(Regex::new("^givenname$").unwrap()),
            true,
        )
        .await.unwrap();
        info!("result: {:?}", result);
        assert_eq!(result.recently_modified, 4);
        assert_eq!(result.added, 2);
        assert_eq!(result.attrs_modified, 1);
    }


    #[tokio::test]
    async fn test_sync_delete_successful() {
        //env_logger::init();
        let _ = env_logger::try_init();

        let source_plain_port = next_port();
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

        let target_plain_port = next_port();
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
            &source_base_dn,
            source_content,
        )
        .await;
        let _target_server = start_test_server(
            target_plain_port,
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

        let expected_source_entries = parse_ldif_as_search_entries( indoc!{ "
            dn: dc=source
            objectClass: dcObject
            objectClass: organization
            dc: source
            o: Source Org

            dn: cn=admin,dc=source
            userPassword: secret
            sn: Admin
            objectClass: inetOrgPerson
            cn: admin

            dn: ou=Users,dc=source
            ou: Users
            objectClass: top
            objectClass: organizationalUnit

            dn: o=de,ou=Users,dc=source
            objectClass: top
            objectClass: organization
            o: de

            dn: o=ABC,o=de,ou=Users,dc=source
            objectClass: top
            objectClass: organization
            o: ABC"
        }).unwrap();

        let expected_target_entries = parse_ldif_as_search_entries( indoc!{ "
            dn: dc=target
            o: Target Org
            dc: target
            objectClass: dcObject
            objectClass: organization

            dn: cn=admin,dc=target
            sn: Admin
            objectClass: inetOrgPerson
            userPassword: secret
            cn: admin

            dn: ou=Users,dc=target
            objectClass: top
            objectClass: organizationalUnit
            ou: Users

            dn: o=de,ou=Users,dc=target
            objectClass: top
            objectClass: organization
            o: de"
        }).unwrap();

        let result = Synchronization::sync_delete(
            &mut source_ldap,
            &mut target_ldap,
            &source_base_dn,
            &target_base_dn,
            "ou=Users",
            false,
        )
        .await.unwrap();
        

        info!("result: {:?}", result);
        assert_eq!(result, 2);

        let source_search_entries = search_all(&mut source_ldap, &source_base_dn).await.unwrap();
        debug!("source entries {:?}", source_search_entries);
        assert_vec_search_entries_eq(&source_search_entries, &expected_source_entries);

        let target_search_entries = search_all(&mut target_ldap, &target_base_dn).await.unwrap();
        debug!("target entries {:?}", target_search_entries);
        assert_vec_search_entries_eq(&target_search_entries, &expected_target_entries);
    }


    #[tokio::test]
    async fn test_sync_delete_base_dn_not_found_in_source() {
        //env_logger::init();
        let _ = env_logger::try_init();

        let source_plain_port = next_port();
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
            ou: Users"
        };

        let target_plain_port = next_port();
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
            o: de"
        };

        let _source_server = start_test_server(
            source_plain_port,
            &source_base_dn,
            source_content,
        )
        .await;
        let _target_server = start_test_server(
            target_plain_port,
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

        let result = Synchronization::sync_delete(
            &mut source_ldap,
            &mut target_ldap,
            &source_base_dn,
            &target_base_dn,
            "o=de,ou=Users",
            false,
        )
        .await;
 
        debug!("result: {:?}", result);
        assert!(matches!(&result, Err(LdapError::LdapResult{result: LdapResult { rc: 32, .. }})));

    }    

    /*
    #[tokio::test]
    async fn test_load_sync_timestamp() {
        let _ = env_logger::try_init();

        let ts_store_name = "ldap1".to_string();
        let ts_store_plain_port = next_port();
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

        let ldap_services_map = HashMap::from([(ts_store_name.clone(), ts_store_service)]);

        let sync_config = SynchronizationConfig {
            source: "provider".to_string(),
            target: "consumer".to_string(),
            base_dns: vec!["cn=unused".to_string()]
        };

        let synchronisation = Synchronization {
            ldap_services: &ldap_services_map,
            sync_config: &sync_config,
            dry_run: true,
            exclude_attrs: &Regex::new("").unwrap(),
        };

        let service_to_use = ldap_services_map.get(&ts_store_name).unwrap();
        debug!("use service: {:?}", &service_to_use);
        let mut ts_store_ldap = simple_connect(service_to_use).await.unwrap();

        debug!("ts_store_ldap: {:?}", ts_store_ldap);
        let result = synchronisation
            .load_sync_timestamp(&mut ts_store_ldap)
            .await
            .unwrap();

        assert_eq!(result, "20231025235959Z");
    }
    */

    /*
    #[tokio::test]
    async fn test_save_sync_timestamp() {
        let _ = env_logger::try_init();

        let sync_timestamp = "20231025235959Z";
        let ts_store_name = "ldap1".to_string();
        let ts_store_plain_port = next_port();
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

        let ldap_services_map = HashMap::from([(ts_store_name.clone(), ts_store_service)]);

        let sync_config = SynchronizationConfig {
            source: "provider".to_string(),
            target: "consumer".to_string(),
            base_dns: vec!["cn=unused".to_string()],
            ts_store: ts_store_name.clone(),
            /// ts_base_dn is relative to the base_dn of the LdapService
            ts_dn: "o=provider-consumer,o=sync_timestamps".to_string(),
        };

        let synchronisation = Synchronization {
            ldap_services: &ldap_services_map,
            sync_config: &sync_config,
            dry_run: false,
            exclude_attrs: &Regex::new("").unwrap(),
        };

        let service_to_use = ldap_services_map.get(&ts_store_name).unwrap();
        debug!("use service: {:?}", &service_to_use);
        let mut ts_store_ldap = simple_connect(service_to_use).await.unwrap();
        
        let result = synchronisation
            .save_sync_timestamp(&mut ts_store_ldap, sync_timestamp)
            .await;
        debug!("result: {:?}", result);
        assert!(result.is_ok());
    }
    */

    #[tokio::test]
    async fn test_synchronisation() {
        let _ = env_logger::try_init();

        let source_plain_port = next_port();
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
            cn: admin
            sn: Admin
            userPassword: secret
            modifyTimestamp: 20231019182735Z

            dn: ou=Users,dc=test
            objectClass: top
            objectClass: organizationalUnit
            ou: Users
            modifyTimestamp: 20231019182736Z
            description: add this
    
            dn: o=de,ou=Users,dc=test
            objEctClass: top
            ObjectClass: organization
            o: de
            modifyTimestamp: 20231019182737Z

            # unchanged
            dn: cn=un012345,o=de,ou=Users,dc=test
            ObjectClass: inetOrgPerson
            cn: un012345
            modifyTimestamp: 19770101131313Z
            sn: von Stein

            # to be added
            dn: o=AB,o=de,ou=Users,dc=test
            objectClass: top
            objectClass: organization
            o: AB
            modifyTimestamp: 20231019182738Z

            # to be added
            dn: cn=xy012345,o=AB,o=de,ou=Users,dc=test
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: hallowelt123!
            modifyTimestamp: 20231019182739Z"
        };

        let target_plain_port = next_port();
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
            cn: admin
            sn: Admin
            userPassword: secret
    
            # to be modified
            dn: ou=Users,dc=test
            objectClass: top
            objectClass: organizationalUnit
            ou: Users
        
            # unchanged
            dn: cn=un012345,o=de,ou=Users,dc=test
            objEctClass: inetOrgPerson
            cn: un012345
            sn: von Stein

            # unchanged
            dn: o=de,ou=Users,dc=test
            ObjectClass: top
            objectClass: organization
            o: de
            descriPtion: remove this

            # to be deleted
            dn: o=XY,o=de,ou=Users,dc=test
            objectClass: top
            objectClass: organization
            o: XY
            
            # to be deleted
            dn: cn=xy012345,o=XY,o=de,ou=Users,dc=test
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: hallowelt123!"
        };

        let expected = parse_ldif_as_search_entries(indoc! { "
            # not synchronized
            dn: dc=test
            objectclass: dcObject
            objectclass: organization
            o: Test Org
            dc: test

            # not synchronized
            dn: cn=admin,dc=test
            objectClass: inetOrgPerson
            cn: admin
            sn: Admin
            userPassword: secret

            # modified
            dn: ou=Users,dc=test
            objectClass: top
            Description: add this
            objectCLASS: organizationalUnit
            ou: Users
    
            # modified
            dn: o=de,ou=Users,dc=test
            objectClass: top
            objectClass: organization
            o: de

            # unchanged
            dn: cn=un012345,o=de,ou=Users,dc=test
            OBJECTClass: inetOrgPerson
            cn: un012345
            SN: von Stein

            # added
            dn: o=AB,o=de,ou=Users,dc=test
            objectClass: top
            objectClass: organization
            o: AB

            # added
            dn: cn=xy012345,o=AB,o=de,ou=Users,dc=test
            cn: xy012345
            objectClass: inetOrgPerson
            sn: Müller
            # no givenName
            userPassword: hallowelt123!"
        }).unwrap();
        let _source_server = start_test_server(
            source_plain_port,
            &source_base_dn,
            source_content,
        )
        .await;
        let _target_server = start_test_server(
            target_plain_port,
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
        let ldap_services = HashMap::from( [("ldap1".to_string(), source_service), ("ldap2".to_string(), target_service.clone())]);
        let sync_config = SynchronizationConfig {
            source: "ldap1".to_string(),
            target: "ldap2".to_string(),
            base_dns: vec!["ou=Users".to_string()],
        };
        let synchronization = Synchronization {
            ldap_services: &ldap_services,
            sync_config: &sync_config,
            attrs: &vec!["*".to_string()],
            exclude_attrs: &Some(Regex::new("^givenname$").unwrap()),
            dry_run: false,
        };
        let date_time = Utc.with_ymd_and_hms(2015, 5, 15, 0, 0, 0).unwrap();

        
        let result = synchronization.synchronize(Some(date_time)).await.unwrap();


        info!("result: {:?}", result);
        assert_eq!(result.recently_modified, 4); // of 5. one entry is very old
        assert_eq!(result.added, 2);
        assert_eq!(result.attrs_modified, 2);
        assert_eq!(result.deleted, 2);

        let mut target_ldap = simple_connect(&target_service).await.unwrap();
        let after = search_all(&mut target_ldap, &target_service.base_dn).await.unwrap();

        assert_vec_search_entries_eq(&after, &expected);

    }

}
