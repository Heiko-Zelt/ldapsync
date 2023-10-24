pub mod sub;

use chrono::{Datelike, Timelike, Utc};
use ldap3::{Ldap, LdapConn, LdapConnAsync, LdapError, ResultEntry, Scope, SearchEntry};
use log::{debug, info};
use std::{env, time::Duration, path::Path};
use std::collections::{HashSet, HashMap};

use crate::sub::app_config::AppConfig;
use crate::sub::synchronisation::Synchronisation;
use crate::sub::cf_services::LdapService;


/// Joins 2 distinguished names.
/// Both parts may be empty strings.
pub fn join_2_dns(periphery_dn: &str, base_dn: &str) -> String {
    if base_dn.is_empty() {
        periphery_dn.to_string()
    } else {
        if periphery_dn.is_empty() {
            base_dn.to_string()
        } else {
            let mut result = periphery_dn.to_string();
            result.push_str(",");
            result.push_str(base_dn);
            result
        }
    }
}

/// Joins 3 distinguished names.
/// All parts may be empty strings.
pub fn join_3_dns(periphery_dn: &str, middle_dn: &str, base_dn: &str) -> String {
    join_2_dns(&join_2_dns(periphery_dn, middle_dn), base_dn)
}

/// Truncates the base DN from DN
/// dn: ""                , base_dn: ""        -> ""
/// dn: "dc=test"         , base_dn: ""        -> "dc=test"
/// dn: "dc=test"         , base_dn: "dc=test" -> ""
/// dn: "cn=Users,dc=test", base_dn: "dc=test" -> "cn=Users" Normalfall
pub fn truncate_dn(dn: &mut String, base_dn_len: usize) {
    print!("dn: {}, base_dn_len: {}", dn, base_dn_len);
    if base_dn_len == 0 { // nichts abscheiden
        return
    }
    if dn.len() == base_dn_len { // Leerstring
        dn.clear();
        return
    }
    // Normalfall
    dn.truncate(dn.len() - base_dn_len - 1); // comma auch abschneiden
}

/*
pub fn simple_connect_sync(service: &LdapService) -> ldap3::result::Result<LdapConn> {
    let mut conn = LdapConn::new(&service.url)?;
    conn.simple_bind(&service.bind_dn, &service.password)?;
    return Ok(conn);
}
*/

async fn simple_connect(service: &LdapService) -> Result<Ldap, LdapError> {
    let (conn, mut ldap) = LdapConnAsync::new(&service.url).await?;
    ldap3::drive!(conn);
    ldap.simple_bind(&service.bind_dn, &service.password)
        .await?;
    Ok(ldap)
}

/// Converts the result entries of a ldap search into a set of DNs.
/// The DNs are normalized to lowercase and the Base DN is truncated.
/// If the resulting DN is not the empty string, it ends with a comma.
/// Hash set is used to efficiently calculate the difference to another set.
fn result_entries_to_norm_dns(result_entries: &Vec<ResultEntry>, base_dn: &str) -> HashSet<String> {
    let base_dn_len = base_dn.len();
    let mut norm_dns = HashSet::new();
    for result_entry in result_entries {
        // debug!("result_entry: {:?}", result_entry); sehr kompliziertes Objekt
        let search_entry = SearchEntry::construct(result_entry.clone());
        debug!("search_entry: {:?}", search_entry);
        let mut dn = search_entry.dn;
        truncate_dn(&mut dn, base_dn_len); // in bytes (not characters)
        let norm_dn = dn.to_lowercase();
        debug!("norm_dn: >>>{}<<<", norm_dn);
        norm_dns.insert(norm_dn);
    }
    norm_dns
}

async fn search_norm_dns(
    ldap_conn: &mut Ldap,
    base_dn: &str,
) -> Result<HashSet<String>, LdapError> {
    let search_result = ldap_conn
        .search(base_dn, Scope::Subtree, "(objectClass=*)", vec!["dn"])
        .await?;

    /*
    let ldap_result = search_result.1;
    if ldap_result.rc != 0 { // Is result code ok?
        return LdapError::LdapResult(ldap_result)
    }
    */

    let result_entries = search_result.0;
    info!("number of entries: {}", result_entries.len());
    let norm_dns = result_entries_to_norm_dns(&result_entries, base_dn);
    Ok(norm_dns)
}

/// synchonizes 2 LDAP directories.
/// - connects to both directories
/// - for every DN: sync_delete() & sync_modify()
/// - disconnects
/// returns: number of touched (added, modified or delted) entries)
pub async fn synchronize(
    source: &LdapService,
    target: &LdapService,
    _source_base_dn: &str,
    _target_base_dn: &str,
    _sync_dns: &Vec<String>,
    _dry_run: bool,
    // todo add parameter for database with modify timestamps
) -> Result<usize, LdapError> {
    let mut _source_ldap = simple_connect(&source).await?;
    let mut _target_ldap = simple_connect(&target).await?;
    Ok(0)
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
async fn sync_delete(
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
/// returns: Wenn erfolgreich: Zeitpunkt, des letzten Abgleichs
async fn sync_modify(
    source: &LdapService,
    target: &LdapService,
    modify_timestamp: &mut String,
) -> Result<String, LdapError> {
    info!(
        "sync_modify(source: {:?}, target: {:?}, modify_timestamp: {:?})",
        source, target, modify_timestamp
    );
    let mut source_ldap_conn = simple_connect(&source).await?;

    // im Quell-LDAP alle geänderten Einträge suchen

    let filter = format!("(modifyTimestamp>={})", modify_timestamp);
    debug!("start search with filter: {}", filter);
    let now = Utc::now();
    let search_result = source_ldap_conn
        .search(&source.base_dn, Scope::Subtree, &filter, vec!["*"])
        .await?;
    let new_timestamp = format!(
        "{}{:02}{:02}{:02}{:02}{:02}Z",
        now.year(),
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    );
    debug!("finished search");

    let ldap_result = search_result.1;
    info!("LDAP result code: {}", ldap_result.rc);
    if ldap_result.rc == 0 {
        // Is result code ok?
        let result_entries = search_result.0;
        // Attribute im Ziel-LDAP ersetzen oder Eintrag neu anlegen
        info!("number of entries: {}", result_entries.len());
        let _target_ldap_conn = simple_connect(&target).await;
        for result_entry in result_entries {
            let search_entry = SearchEntry::construct(result_entry);
            debug!("entry: {:?}", search_entry);
        }
    }
    info!("new modifyTimestamp: {}", new_timestamp);
    Ok(new_timestamp)
}

/// main function.
/// reads configuration from environment variables
/// and calls syncronize() for every entry in SYNCHRONISATIONS.
#[tokio::main]
async fn main() {
    env_logger::init();
    info!("Hello LDAP");

    let source = LdapService {
        url: env::var("SOURCE_URL").unwrap(),
        bind_dn: env::var("SOURCE_BIND_DN").unwrap(),
        password: env::var("SOURCE_PASSWORD").unwrap(),
        base_dn: env::var("SOURCE_BASE_DN").unwrap(),
    };

    let mut _ldap_conn = simple_connect(&source).await;

    info!("Programm finished successfully.");
}

#[cfg(test)]
mod test {
    use super::*;
    use indoc::*;
    use ldap_test_server::{LdapServerBuilder, LdapServerConn};
    use pickledb::{PickleDb, PickleDbDumpPolicy, SerializationMethod};
    use rstest::rstest;

    //use futures::executor::block_on;
    //use tokio::runtime;
    //use std::thread::sleep;
    //use std::time::Duration;
    use log::debug;

    async fn start_test_server(plain_port: u16, tls_port: u16, base_dn: &str, content: &str) -> LdapServerConn {
        info!("start test server()");

        let server = LdapServerBuilder::new(base_dn)
            .port(plain_port)
            // add LDIF to database before LDAP server is started
            .ssl_port(tls_port)
            .add(1, content)
            // init databases and started LDAP server
            .run()
            .await;
        info!("server started: {:?}", server);
        server
    }

    #[tokio::test]
    async fn test_simple_connect() {
        let _ = env_logger::try_init();

        let plain_port = 10389;
        let tls_port = 10636;
        let url = format!("ldap://127.0.0.1:{}", plain_port);
        let bind_dn = "cn=admin,dc=test".to_string();
        let password = "secret".to_string();
        let base_dn = "dc=test".to_string();
        let content = indoc! { "
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
            ou: Users"
        };

        let service = LdapService {
            url: url,
            bind_dn: bind_dn,
            password: password,
            base_dn: base_dn.clone(),
        };

        let _server = start_test_server(plain_port, tls_port, &base_dn, content).await;

        //let src_base_dn = "dc=test".to_string();
        //let _ldap_conn = simple_connect_sync(&src_url, &src_bind_dn, &src_password).unwrap();
        let ldap_conn = simple_connect(&service).await;
        debug!("ldap conn: {:?}", ldap_conn);
    }

    #[tokio::test]
    async fn test_2_servers() {
        //env_logger::init();
        let _ = env_logger::try_init();

        let source_plain_port = 11389;
        let source_tls_port = 11636;
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

            dn: o=AB,o=de,ou=Users,dc=test
            objectClass: top
            objectClass: organization
            o: AB

            dn: cn=xy012345,o=AB,o=de,ou=Users,dc=test
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: hallowelt123!"
        };

        let target_plain_port = 12389;
        let target_tls_port = 12636;
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

        let _source_server =
            start_test_server(source_plain_port, source_tls_port, &source_base_dn, source_content).await;
        let _target_server =
            start_test_server(target_plain_port, target_tls_port, &target_base_dn, target_content).await;

        //let src_base_dn = "dc=test".to_string();
        //let _ldap_conn = simple_connect_sync(&src_url, &src_bind_dn, &src_password).unwrap();
        let source_service = LdapService {
            url: source_url,
            bind_dn: source_bind_dn,
            password: source_password,
            base_dn: source_base_dn,
        };

        let target_service = LdapService {
            url: target_url,
            bind_dn: target_bind_dn,
            password: target_password,
            base_dn: target_base_dn,
        };

        let source_ldap = simple_connect(&source_service).await;
        let target_ldap = simple_connect(&target_service).await;
        debug!("source ldap conn: {:?}", source_ldap);
        debug!("target ldap conn: {:?}", target_ldap);
    }

    #[tokio::test]
    async fn test_sync_modified() {
        //env_logger::init();
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

        let _source_server =
            start_test_server(source_plain_port, source_tls_port, &source_base_dn, source_content).await;
        let _target_server =
            start_test_server(target_plain_port, target_tls_port, &target_base_dn, target_content).await;

        //let src_base_dn = "dc=test".to_string();
        //let _ldap_conn = simple_connect_sync(&src_url, &src_bind_dn, &src_password).unwrap();
        let source_service = LdapService {
            url: source_url,
            bind_dn: source_bind_dn,
            password: source_password,
            base_dn: source_base_dn,
        };

        let target_service = LdapService {
            url: target_url,
            bind_dn: target_bind_dn,
            password: target_password,
            base_dn: target_base_dn,
        };

        let mut modify_timestamp = "19751129000000Z".to_string();

        let result = sync_modify(&source_service, &target_service, &mut modify_timestamp).await;
        info!("result: {:?}", result);
        assert!(result.unwrap() > "20231020120000Z".to_string());
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

        let _source_server =
            start_test_server(source_plain_port, source_tls_port, &source_base_dn, source_content).await;
        let _target_server =
            start_test_server(target_plain_port, target_tls_port, &target_base_dn, target_content).await;

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

        let result = sync_delete(&mut source_ldap, &mut target_ldap, &source_base_dn, &target_base_dn, "ou=Users", false).await;
        // todo assertions: compare norm DNs of subtrees
        
        info!("result: {:?}", result);
        assert_eq!(result.unwrap(), 2);
    }

    #[test]
    fn test_key_value_store() {
        let modify_timestamp = "20231020152100z";

        let url = "ldap://127.0.0.1:389".to_string();
        let base_dn = "o=XY,o=de,cn=Users,dc=test".to_string();

        let key = format!("{}/{}.modifyTimestamp", url, base_dn);

        let mut db = PickleDb::new(
            "example.db",
            PickleDbDumpPolicy::AutoDump,
            SerializationMethod::Json,
        );

        db.set(&key, &modify_timestamp).unwrap();

        let result = db.get::<String>(&key).unwrap();
        // print the value of key1
        debug!("The value of modifyTimestamp is: {}", result);
        assert_eq!(result, modify_timestamp)
    }

    #[rstest]
    #[case("", "", "")] 
    #[case("", "dc=test", "dc=test")]
    #[case("cn=Users", "", "cn=Users")]
    #[case("cn=Users", "dc=test", "cn=Users,dc=test")]
    fn test_join_2_dns(#[case] base_dn: &str, #[case] peripheral_dn: &str, #[case] expected: &str) {
        let result = join_2_dns(base_dn, peripheral_dn);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case("", "", "", "")] 
    #[case("cn=xy012345", "", "", "cn=xy012345")]
    #[case("", "cn=Users", "", "cn=Users")]
    #[case("cn=xy012345", "", "cn=Users", "cn=xy012345,cn=Users")]
    #[case("cn=Users,dc=test", "", "", "cn=Users,dc=test")]
    #[case("cn=Users", "dc=test", "", "cn=Users,dc=test")]
    #[case("cn=xy012345", "cn=Users", "dc=test", "cn=xy012345,cn=Users,dc=test")]
    fn test_join_3_dns(#[case] peripheral_dn: &str, #[case] middle_dn: &str, #[case] base_dn: &str, #[case] expected: &str) {
        let result = join_3_dns(peripheral_dn, middle_dn, base_dn);
        assert_eq!(result, expected);
    }

    #[rstest]
    #[case("cn=Users,dc=test", "dc=test", "cn=Users")] // Normalfall
    #[case("cn=Users,dc=test", "", "cn=Users,dc=test")] // nichts wird abgeschnitten
    #[case("dc=test", "dc=test", "")] // nur Leerstring bleibt übrig
    #[case("", "", "")] // Extrembeispiel
    fn test_truncate_dn(#[case] given_dn: &str, #[case] base_dn: &str, #[case] expected: &str) {
        let mut dn = given_dn.to_string();
        truncate_dn(&mut dn, base_dn.len());
        assert_eq!(dn, expected);
    }

    /*
    #[test]
    fn test_result_entries_to_norm_dns() {
        let result_entry = ResultEntry { ... kompliziert ... }
        let result_entries = vec![result_entry];
        let result = result_entries_to_norm_dns(result_entries, &"cn=Users,cn=test");
        assert ...
    }
     */
}
