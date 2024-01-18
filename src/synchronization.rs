use chrono::{DateTime, Utc};
use ldap3::{Ldap, LdapError, LdapResult, SearchEntry};
use log::{debug, info, warn};
use regex::Regex;
use std::collections::{HashMap, HashSet};

use crate::cf_services::LdapService;
use crate::ldap_result_codes::*;
use crate::ldap_utils::*;
use crate::rewrite_engine::Rule;
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
    pub deleted: usize,
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
    pub filter: &'a String,
    pub exclude_dns: &'a Option<Regex>,
    pub attrs: &'a Vec<String>,
    pub exclude_attrs: &'a Option<Regex>,
    pub rewrite_rules: &'a Vec<Rule>,
    pub dry_run: bool,

    /// this field mutates
    pub old_sync_datetime: Option<DateTime<Utc>>,
}

impl<'a> Synchronization<'a> {
    /// synchonizes 2 LDAP directories.
    /// - connects to both directories
    /// - for every DN: sync_delete() & sync_modify()
    /// - disconnects
    /// returns: number of touched (added, modified and delted) entries)
    /// TODO: Wenn zu synchronisierender Base-DN im Ziel nicht existiert, dann Eintrag anlegen (statt RC 32 no such object ausgeben).
    pub async fn synchronize(&mut self) -> Result<SyncStatistics, LdapError> {
        info!(
            r#"synchronize: source: "{}" --> target: "{}""#,
            &self.sync_config.source, &self.sync_config.target
        );
        let new_sync_datetime = Utc::now();

        let source_service = self.ldap_services.get(&self.sync_config.source).unwrap();
        let target_service = self.ldap_services.get(&self.sync_config.target).unwrap();

        let mut sync_statistics = SyncStatistics {
            recently_modified: 0,
            added: 0,
            attrs_modified: 0,
            deleted: 0,
        };
        let mut source_ldap = simple_connect(source_service).await?;
        let mut target_ldap = simple_connect(target_service).await?;

        let sync_ldap_timestamp = match self.old_sync_datetime {
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
                self.filter,
                self.exclude_dns,
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
                self.filter,
                self.exclude_dns,
                self.attrs,
                self.exclude_attrs,
                self.rewrite_rules,
                self.dry_run,
            )
            .await?;
            sync_statistics.recently_modified += modi_statistics.recently_modified;
            sync_statistics.added += modi_statistics.added;
            sync_statistics.attrs_modified += modi_statistics.attrs_modified;
        }
        debug!("unbind(). Terminating the connections.");
        source_ldap.unbind().await?;
        target_ldap.unbind().await?;

        // TODO Prio 3: one timestamp for every sync-subtree (2-dimensional Vec)
        // TODO Prio 1: at least for every synchronization
        if !self.dry_run {
            info!(
                "replacing old timestamp {:?} with new timestamp {:?}.",
                self.old_sync_datetime, new_sync_datetime
            );
            self.old_sync_datetime = Some(new_sync_datetime);
        }

        Ok(sync_statistics)
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
        filter: &str,
        exclude_dns: &Option<Regex>,
        dry_run: bool,
    ) -> Result<usize, LdapError> {
        info!(
            r#"sync_delete: source_base_dn: "{}", target_base_dn: "{}", sync_dn: "{}")"#,
            source_base_dn, target_base_dn, sync_dn
        );

        let target_sync_dn = join_2_dns(sync_dn, target_base_dn);
        let target_norm_dns =
            search_norm_dns(target_ldap, &target_sync_dn, filter, exclude_dns).await?;

        // TODO nur ausführen, wenn log level debug
        log_debug_dns("sync_delete: target entry:", &target_norm_dns);

        // Wenn es im Ziel-System keine Einträge gibt, kann auch nichts gelöscht werden.
        if target_norm_dns.len() == 0 {
            Ok(0)
        } else {
            let source_sync_dn = join_2_dns(sync_dn, source_base_dn);
            let source_norm_dns =
                search_norm_dns(source_ldap, &source_sync_dn, filter, exclude_dns).await?;
            // TODO nur ausführen, wenn log level debug
            log_debug_dns("sync_delete: source entry:", &source_norm_dns);
            let garbage_diff = target_norm_dns.difference(&source_norm_dns);
            let mut garbage_vec: Vec<&String> = garbage_diff.collect();

            // Von den Blättern zur Wurzel, längere DNs zuerst sortieren. Absteigend nach Länge der DNs.
            garbage_vec.sort_by(|a, b| compare_by_length_desc_then_alphabethical(a, b));

            for dn in garbage_vec.iter() {
                // norm_dn ends with a comma if it is not empty
                //let target_dn = format!("{}{}", norm_dn, target.base_dn);
                let target_dn = join_3_dns(dn, sync_dn, target_base_dn);
                if dry_run {
                    info!(r#"sync_delete: would delete entry: "{}""#, target_dn);
                } else {
                    info!(r#"sync_delete: deleting entry: "{}""#, target_dn);
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
    /// TODO ignore case for values of attribute objectclass (and maybe others).
    pub async fn sync_modify(
        source_ldap: &mut Ldap,
        target_ldap: &mut Ldap,
        source_base_dn: &str,
        target_base_dn: &str,
        sync_dn: &str,
        old_modify_timestamp: &Option<String>,
        filter: &str,
        exclude_dns: &Option<Regex>,
        attrs: &Vec<String>,
        exclude_attrs: &Option<Regex>,
        rewrite_rules: &Vec<Rule>,
        dry_run: bool,
    ) -> Result<ModiStatistics, LdapError> {
        debug!(
            r#"sync_modify: source_base_dn: "{}", target_base_dn: "{}", sync_dn: "{}", old_modify_timestamp: {:?})"#,
            source_base_dn, target_base_dn, sync_dn, old_modify_timestamp
        );
        // im Quell-LDAP alle neulich geänderten Einträge suchen
        let source_sync_dn = join_2_dns(sync_dn, source_base_dn);
        let target_sync_dn = join_2_dns(&sync_dn, &source_base_dn);

        let mut source_search_entries = search_modified_entries_and_rewrite(
            source_ldap,
            &source_sync_dn,
            old_modify_timestamp,
            filter,
            exclude_dns,
            attrs,
            exclude_attrs,
            rewrite_rules,
        )
        .await?;

        let mut modi_statistics = ModiStatistics {
            recently_modified: source_search_entries.len(),
            added: 0,
            attrs_modified: 0,
        };

        // Von der Wurzel zu den Blättern, kürzere DNs zuerst sortieren. Austeigend nach Länger der DNs.
        source_search_entries.sort_by(|a, b| a.dn.len().cmp(&b.dn.len()));

        info!(
            r#"sync_modify: subtree: "{}", number of recently modified entries: {}"#,
            source_sync_dn,
            source_search_entries.len()
        );

        for source_search_entry in source_search_entries {
            let modified = Self::sync_modify_one_entry(
                target_ldap,
                &target_sync_dn,
                source_search_entry,
                attrs,
                exclude_attrs,
                dry_run,
            )
            .await?;
            match modified {
                ModiOne::Unchanged => {}
                ModiOne::Added => modi_statistics.added += 1,
                ModiOne::AttrsModified => modi_statistics.attrs_modified += 1,
            }
        }
        Ok(modi_statistics)
    }

    pub async fn sync_modify_one_entry(
        target_ldap: &mut Ldap,
        target_base_dn: &str,
        source_search_entry: SearchEntry,
        attrs: &Vec<String>,
        exclude_attrs: &Option<Regex>,
        dry_run: bool,
    ) -> Result<ModiOne, LdapError> {
        debug!(
            r#"sync_modify_one_entry: source entry: {}"#,
            debug_search_entry(&source_search_entry)
        );
        if source_search_entry.bin_attrs.len() != 0 {
            warn!(
                r#"sync_modify_one_entry: Ignoring attribute(s) with binary value in source entry."#
            );
        }

        let target_dn = join_2_dns(&source_search_entry.dn, target_base_dn);

        let target_search_result = search_one_entry_by_dn(target_ldap, &target_dn, attrs).await;

        match target_search_result {
            Ok(mut entry) => {
                match exclude_attrs {
                    Some(ex) => entry.attrs = filter_attrs(&entry.attrs, &ex),
                    None => {}
                };
                debug!(
                    r#"sync_modify_one_entry: target entry exists: {})"#,
                    debug_search_entry(&entry)
                );
                if entry.bin_attrs.len() != 0 {
                    warn!(
                        r#"sync_modify_one_entry: Ignoring attribute(s) with binary value(s) in target entry."#
                    );
                }
                let mods = diff_attributes(&source_search_entry.attrs, &entry.attrs);

                // If mods is empty, maybe because only excluded attributes have changed. Then don't modify.
                if mods.is_empty() {
                    debug!(
                        r#"sync_modify_one_entry: dn: "{}", no differences found"#,
                        entry.dn
                    );
                    return Ok(ModiOne::Unchanged);
                }

                if dry_run {
                    info!(
                        r#"sync_modify_one_entry: would modify entry: dn: "{}", modifications: {:?}"#,
                        entry.dn,
                        debug_mods(&mods)
                    );
                } else {
                    info!(
                        r#"sync_modify_one_entry: modifying entry: dn: "{}", modifications: {:?}"#,
                        entry.dn,
                        debug_mods(&mods)
                    );
                    target_ldap.modify(&target_dn, mods).await?;
                }
                Ok(ModiOne::AttrsModified)
            }
            Err(LdapError::LdapResult {
                // no problem => add entry
                result:
                    LdapResult {
                        rc: RC_NO_SUCH_OBJECT!(),
                        ..
                    },
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
                if dry_run {
                    info!(
                        r#"sync_modify_one_entry: would add entry: {}"#,
                        debug_search_entry(&source_search_entry)
                    );
                } else {
                    info!(
                        r#"sync_modify_one_entry: adding entry: {}"#,
                        debug_search_entry(&source_search_entry)
                    );
                    target_ldap.add(&target_dn, target_attrs).await?;
                }
                Ok(ModiOne::Added)
            }
            Err(err) => return Err(err), // other return code
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::ldap_utils::simple_connect;
    use crate::ldap_utils::test::{
        assert_vec_search_entries_eq, next_port, search_all, start_test_server,
    };
    use crate::ldif::parse_ldif_as_search_entries;
    use crate::synchronization_config::SynchronizationConfig;
    use chrono::{TimeZone, Utc};
    use indoc::*;

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
            cn: xy012345
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
            cn: xy012345
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: hallowelt123!"
        };

        let _source_server =
            start_test_server(source_plain_port, &source_base_dn, source_content).await;
        let _target_server =
            start_test_server(target_plain_port, &target_base_dn, target_content).await;

        //let src_base_dn = "dc=test".to_string();
        //let _ldap_conn = simple_connect_sync(&src_url, &src_bind_dn, &src_password).unwrap();
        let source_service = LdapService {
            url: source_url,
            bind_dn: Some(source_bind_dn),
            password: Some(source_password),
            base_dn: source_base_dn.clone(),
        };

        let target_service = LdapService {
            url: target_url,
            bind_dn: Some(target_bind_dn),
            password: Some(target_password),
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
            "(objectClass=*)",
            &None,
            &vec!["*".to_string()],
            &Some(Regex::new("^givenname$").unwrap()),
            &Vec::new(),
            true,
        )
        .await
        .unwrap();
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

        let _source_server =
            start_test_server(source_plain_port, &source_base_dn, source_content).await;
        let _target_server =
            start_test_server(target_plain_port, &target_base_dn, target_content).await;

        let source_service = LdapService {
            url: source_url,
            bind_dn: Some(source_bind_dn),
            password: Some(source_password),
            base_dn: source_base_dn.clone(),
        };

        let target_service = LdapService {
            url: target_url,
            bind_dn: Some(target_bind_dn),
            password: Some(target_password),
            base_dn: target_base_dn.clone(),
        };

        let mut source_ldap = simple_connect(&source_service).await.unwrap();
        let mut target_ldap = simple_connect(&target_service).await.unwrap();

        let expected_source_entries = parse_ldif_as_search_entries(indoc! { "
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
        })
        .unwrap();

        let expected_target_entries = parse_ldif_as_search_entries(indoc! { "
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
        })
        .unwrap();

        let result = Synchronization::sync_delete(
            &mut source_ldap,
            &mut target_ldap,
            &source_base_dn,
            &target_base_dn,
            "ou=Users",
            "(objectClass=*)",
            &None,
            false,
        )
        .await
        .unwrap();

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

        let _source_server =
            start_test_server(source_plain_port, &source_base_dn, source_content).await;
        let _target_server =
            start_test_server(target_plain_port, &target_base_dn, target_content).await;

        let source_service = LdapService {
            url: source_url,
            bind_dn: Some(source_bind_dn),
            password: Some(source_password),
            base_dn: source_base_dn.clone(),
        };

        let target_service = LdapService {
            url: target_url,
            bind_dn: Some(target_bind_dn),
            password: Some(target_password),
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
            "(objectClass=*)",
            &None,
            false,
        )
        .await;

        debug!("result: {:?}", result);
        assert!(matches!(
            &result,
            Err(LdapError::LdapResult {
                result: LdapResult { rc: 32, .. }
            })
        ));
    }

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
        })
        .unwrap();
        let _source_server =
            start_test_server(source_plain_port, &source_base_dn, source_content).await;
        let _target_server =
            start_test_server(target_plain_port, &target_base_dn, target_content).await;
        let source_service = LdapService {
            url: source_url,
            bind_dn: Some(source_bind_dn),
            password: Some(source_password),
            base_dn: source_base_dn.clone(),
        };
        let target_service = LdapService {
            url: target_url,
            bind_dn: Some(target_bind_dn),
            password: Some(target_password),
            base_dn: target_base_dn.clone(),
        };
        let ldap_services = HashMap::from([
            ("ldap1".to_string(), source_service),
            ("ldap2".to_string(), target_service.clone()),
        ]);
        let sync_config = SynchronizationConfig {
            source: "ldap1".to_string(),
            target: "ldap2".to_string(),
            base_dns: vec!["ou=Users".to_string()],
        };
        let mut synchronization = Synchronization {
            ldap_services: &ldap_services,
            sync_config: &sync_config,
            filter: &"(objectClass=*)".to_string(),
            exclude_dns: &None,
            attrs: &vec!["*".to_string()],
            exclude_attrs: &Some(Regex::new("^givenname$").unwrap()),
            rewrite_rules: &Vec::new(),
            dry_run: false,
            old_sync_datetime: Some(Utc.with_ymd_and_hms(2015, 5, 15, 0, 0, 0).unwrap()),
        };

        let result = synchronization.synchronize().await.unwrap();

        info!("result: {:?}", result);
        assert_eq!(result.recently_modified, 4); // of 5. one entry is very old
        assert_eq!(result.added, 2);
        assert_eq!(result.attrs_modified, 2);
        assert_eq!(result.deleted, 2);

        let mut target_ldap = simple_connect(&target_service).await.unwrap();
        let after = search_all(&mut target_ldap, &target_service.base_dn)
            .await
            .unwrap();
        print!("after {:?}", after);

        assert_vec_search_entries_eq(&after, &expected);
    }

    #[tokio::test]
    async fn test_synchronisation_exclude_by_dn() {
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
    
            # ignore because DN is excluded
            dn: o=local,ou=Users,dc=test
            objEctClass: top
            ObjectClass: organization
            o: local
            modifyTimestamp: 20231019182737Z

            # ignore because DN is excluded
            dn: cn=un012345,o=local,ou=Users,dc=test
            ObjectClass: inetOrgPerson
            cn: un012345
            modifyTimestamp: 20230101131313Z
            sn: von Stein

            # ignore because DN is excluded
            dn: o=AB,o=local,ou=Users,dc=test
            objectClass: top
            objectClass: organization
            o: AB
            modifyTimestamp: 20231019182738Z
            
            # to be modified
            dn: cn=xy012345,ou=Users,dc=test
            cn: xy012345
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: new_password!
            modifyTimestamp: 20231019182739Z
            description: changed
            
            # to be added
            dn: cn=new012345,ou=Users,dc=test
            cn: new012345
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: some_password!
            modifyTimestamp: 20231019182739Z
            description: changed"
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

            # ignore because DN is excluded
            dn: o=local,ou=Users,dc=test
            objEctClass: top
            ObjectClass: organization
            o: local

            # ignore because DN is excluded
            dn: cn=un012345,o=local,ou=Users,dc=test
            ObjectClass: inetOrgPerson
            cn: un012345
            sn: von Stein

            # ignore because DN is excluded
            dn: o=dont_delete,o=local,ou=Users,dc=test
            objectClass: top
            objectClass: organization
            o: dont_delete
            modifyTimestamp: 20231019182738Z
        
            # to be deleted
            dn: o=de,ou=Users,dc=test
            ObjectClass: top
            objectClass: organization
            o: de
            
            # to be modified
            dn: cn=xy012345,ou=Users,dc=test
            cn: xy012345
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: old_password!"
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
            objectClass: organizationalUnit
            ou: Users
            description: add this

            # ignore because DN is excluded
            dn: o=local,ou=Users,dc=test
            objEctClass: top
            ObjectClass: organization
            o: local

            # ignore because DN is excluded
            dn: cn=un012345,o=local,ou=Users,dc=test
            cn: un012345
            ObjectClass: inetOrgPerson
            sn: von Stein

            # ignore because DN is excluded
            dn: o=dont_delete,o=local,ou=Users,dc=test
            objectClass: top
            objectClass: organization
            o: dont_delete

            # to be added
            dn: cn=new012345,ou=Users,dc=test
            cn: new012345
            objectClass: inetOrgPerson
            sn: Müller
            userPassword: some_password!
            description: changed
            
            # to be modified
            dn: cn=xy012345,ou=Users,dc=test
            cn: xy012345
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: new_password!
            description: changed"
        })
        .unwrap();
        let _source_server =
            start_test_server(source_plain_port, &source_base_dn, source_content).await;
        let _target_server =
            start_test_server(target_plain_port, &target_base_dn, target_content).await;
        let source_service = LdapService {
            url: source_url,
            bind_dn: Some(source_bind_dn),
            password: Some(source_password),
            base_dn: source_base_dn.clone(),
        };
        let target_service = LdapService {
            url: target_url,
            bind_dn: Some(target_bind_dn),
            password: Some(target_password),
            base_dn: target_base_dn.clone(),
        };
        let ldap_services = HashMap::from([
            ("ldap1".to_string(), source_service),
            ("ldap2".to_string(), target_service.clone()),
        ]);
        let sync_config = SynchronizationConfig {
            source: "ldap1".to_string(),
            target: "ldap2".to_string(),
            base_dns: vec!["ou=Users".to_string()],
        };
        let mut synchronization = Synchronization {
            ldap_services: &ldap_services,
            sync_config: &sync_config,
            filter: &"(objectClass=*)".to_string(),
            exclude_dns: &Some(Regex::new("(?i)o=local$").unwrap()),
            attrs: &vec!["*".to_string()],
            exclude_attrs: &Some(Regex::new("^givenname$").unwrap()),
            rewrite_rules: &Vec::new(),
            dry_run: false,
            old_sync_datetime: Some(Utc.with_ymd_and_hms(2015, 5, 15, 0, 0, 0).unwrap()),
        };

        let result = synchronization.synchronize().await.unwrap();

        info!("result: {:?}", result);
        assert_eq!(result.recently_modified, 3); // of 5. one entry is very old
        assert_eq!(result.added, 1);
        assert_eq!(result.attrs_modified, 2);
        assert_eq!(result.deleted, 1);

        let mut target_ldap = simple_connect(&target_service).await.unwrap();
        let after = search_all(&mut target_ldap, &target_service.base_dn)
            .await
            .unwrap();
        print!("after {:?}", after);

        assert_vec_search_entries_eq(&after, &expected);
    }
}
