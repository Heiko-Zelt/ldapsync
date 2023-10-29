use ldap3::{Ldap, LdapConnAsync, LdapError, Mod, ResultEntry, Scope, SearchEntry};
use log::{debug, info};
use regex::Regex;
use std::collections::{HashMap, HashSet};

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

/// Truncates the base DN from DN in place
/// dn: ""                , base_dn: ""        -> ""
/// dn: "dc=test"         , base_dn: ""        -> "dc=test"
/// dn: "dc=test"         , base_dn: "dc=test" -> ""
/// dn: "cn=Users,dc=test", base_dn: "dc=test" -> "cn=Users" Normalfall
pub fn truncate_dn(dn: &mut String, base_dn_len: usize) {
    if base_dn_len == 0 {
        // nichts abscheiden
        return;
    }
    if dn.len() == base_dn_len {
        // Leerstring
        dn.clear();
        return;
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

pub async fn simple_connect(service: &LdapService) -> Result<Ldap, LdapError> {
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
pub fn result_entries_to_norm_dns(
    result_entries: &Vec<ResultEntry>,
    base_dn: &str,
) -> HashSet<String> {
    let base_dn_len = base_dn.len();
    let mut norm_dns = HashSet::new();
    for result_entry in result_entries {
        // debug!("result_entry: {:?}", result_entry); sehr kompliziertes Objekt
        let search_entry = SearchEntry::construct(result_entry.clone());
        //debug!("search_entry: {:?}", search_entry);
        let mut dn = search_entry.dn;
        truncate_dn(&mut dn, base_dn_len); // in bytes (not characters)
        let norm_dn = dn.to_lowercase();
        debug!(r#"norm_dn: "{}""#, norm_dn);
        norm_dns.insert(norm_dn);
    }
    norm_dns
}

/// todo Error, wenn base_dn gar nicht existiert
pub async fn search_norm_dns(
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

/// returns exactly one entry if found or None if not not found
pub async fn search_one_entry_by_dn(
    ldap_conn: &mut Ldap,
    dn: &str,
) -> Result<Option<SearchEntry>, LdapError> {
    let search_result = ldap_conn
        .search(dn, Scope::Base, "(objectClass=*)", vec!["*"])
        .await?;
    let result_entries = search_result.0;
    info!("number of entries: {}", result_entries.len()); // should be 0 or 1
    match result_entries.len() {
        0 => Ok(None),
        1 => {
            let search_entry = SearchEntry::construct(result_entries[0].clone());
            Ok(Some(search_entry))
        }
        _ => {
            panic!("Found more than 1 entry.")
        }
    }
}

/// converts all attribute names to lower case
/// and filters the attributes by name
pub fn filter_attrs(
    attrs: &HashMap<String, Vec<String>>,
    exclude_attrs: &Regex,
) -> HashMap<String, Vec<String>> {
    attrs
        .iter()
        .map(|(key, value)| (key.to_lowercase(), value.clone()))
        .filter(|(key, _)| !exclude_attrs.is_match(key))
        .collect()
}

/*
neuer Vec, da keys sich ändern
aber die values könnten den Eigentümer wechseln. entnehmen?
pub fn filter_attrs_inplace() {
    let filtered_attrs = entry.attrs
        .into_iter()
        .map(|(key, value)| {
            (key.to_lowercase(), value)
        })
        .filter(|(key, _)| {
            !exclude_attrs.is_match(key)
        })
        .collect();
    entry.attrs = filtered_attrs;
}
*/

/// The attributes list could be very long.
/// So it's more convinient to search for all non-operative attributes '*' and remove unwanted attributes.
/// Additionally attribute names are converted to lower case,
/// because Oracle Interne Directory returns attribute namen in lower case
/// and OpenLdap may return attributes in camel case.
pub async fn search_one_entry_by_dn_attrs_filtered(
    ldap_conn: &mut Ldap,
    dn: &str,
    exclude_attrs: &Regex,
) -> Result<Option<SearchEntry>, LdapError> {
    let search_entry = search_one_entry_by_dn(ldap_conn, dn).await?;
    match search_entry {
        Some(mut entry) => {
            entry.attrs = filter_attrs(&entry.attrs, exclude_attrs);
            Ok(Some(entry))
        }
        None => Ok(None),
    }
}

/// Searches a subtree for recently modified entries.
/// Attribute names are normalized to lowercase
/// and attributes are filtered.
/// todo Error, wenn base_dn gar nicht existiert
pub async fn search_modified_entries_attrs_filtered(
    ldap: &mut Ldap,
    base_dn: &str,
    old_modify_timestamp: &str,
    exclude_attrs: &Regex,
) -> Result<Vec<SearchEntry>, LdapError> {
    let filter = format!("(modifyTimestamp>={})", old_modify_timestamp);
    debug!("search with base: {}, filter: {}", base_dn, filter);
    let mut search_result_stream = ldap
        .streaming_search(&base_dn, Scope::Subtree, &filter, vec!["*"])
        .await?;
    let mut search_entries: Vec<SearchEntry> = Vec::new();
    loop {
        let result_entry = search_result_stream.next().await?;
        match result_entry {
            Some(entry) => {
                let mut search_entry = SearchEntry::construct(entry.clone());
                search_entry.attrs = filter_attrs(&mut search_entry.attrs, exclude_attrs);
                search_entries.push(search_entry);
            }
            None => {
                break;
            }
        }
    }
    Ok(search_entries)
}

/// todo bin_attrs berücksichtigen
pub fn diff_attributes(
    source_attrs: &HashMap<String, Vec<String>>,
    target_attrs: &HashMap<String, Vec<String>>,
) -> Vec<Mod<String>> {
    let source_set: HashSet<String> = source_attrs.keys().cloned().collect();
    let target_set: HashSet<String> = target_attrs.keys().cloned().collect();
    let missing = source_set.difference(&target_set);
    let garbage = target_set.difference(&source_set);
    let common = source_set.intersection(&target_set);

    let mut mods: Vec<Mod<String>> = Vec::new();

    for attr_name in garbage {
        let delete = Mod::Delete(attr_name.clone(), HashSet::new());
        mods.push(delete);
    }
    for attr_name in missing {
        let source_values_vec = source_attrs.get(attr_name).unwrap();
        let source_values_set: HashSet<String> =
            HashSet::from_iter(source_values_vec.iter().cloned());
        let add = Mod::Add(attr_name.clone(), source_values_set);
        mods.push(add);
    }
    for attr_name in common {
        let source_values_vec = source_attrs.get(attr_name).unwrap().clone();
        let target_values_vec = target_attrs.get(attr_name).unwrap().clone();
        let source_values: HashSet<String> = HashSet::from_iter(source_values_vec);
        let target_values: HashSet<String> = HashSet::from_iter(target_values_vec);
        let mut sym_diff = source_values.symmetric_difference(&target_values);
        if sym_diff.next().is_some() {
            let replace = Mod::Replace(attr_name.clone(), source_values);
            mods.push(replace);
        }
    }
    mods
}

#[cfg(test)]
pub mod test {
    use std::str::Utf8Error;

    use super::*;
    use indoc::*;
    use ldap_test_server::{LdapServerBuilder, LdapServerConn};
    use rstest::rstest;
    use serde::Deserialize;

    //use futures::executor::block_on;
    //use tokio::runtime;
    //use std::thread::sleep;
    //use std::time::Duration;
    use log::debug;

    /// ldap3::SearchEntry does not implement the Deserialize trait.
    /// So I define my own struct, which can easily be mapped to SearchEntry.
    #[derive(Deserialize)]
    struct SerdeSearchEntry {
        pub dn: String,
        pub attrs: HashMap<String, Vec<String>>,
        pub bin_attrs: HashMap<String, Vec<Vec<u8>>>,
    }

    pub fn parse_search_entries(json_str: &str) -> Vec<SearchEntry> {
        let serde_search_entries = serde_json::from_str::<Vec<SerdeSearchEntry>>(json_str).unwrap();
        let search_entries = serde_search_entries
            .into_iter()
            .map(|serde_entry| {
               SearchEntry {
                  dn: serde_entry.dn,
                  attrs: serde_entry.attrs,
                  bin_attrs: serde_entry.bin_attrs
               }
            })
            .collect();
        search_entries
    }

    pub fn assert_attrs_eq(attrs1: &HashMap<String, Vec<String>>, attrs2: &HashMap<String, Vec<String>>) {
        let result = diff_attributes(&attrs1, &attrs2);
        if result.len() != 0 {
            panic!("attributes differ");
        }
    }
    
    pub fn assert_search_entries_eq(entry1: &SearchEntry, entry2: &SearchEntry) {
        if entry1.dn != entry2.dn {
            panic!("dns are unequal. {} != {}", entry1.dn, entry2.dn);
        }
        assert_attrs_eq(&entry1.attrs, &entry2.attrs);
        // todo bin_attrs        
    }

    pub fn assert_vec_search_entries_eq(entries1: &Vec<SearchEntry>, entries2: &Vec<SearchEntry>) {
        if entries1.len() != entries2.len() {
            panic!("different number of entries. {} != {}", entries1.len(), entries2.len());
        }
        // map dn to entries
        let entries2_map: HashMap<String, SearchEntry> = entries2
          .iter()
          .map(|entry| {
              (entry.dn.clone(), entry.clone())
          })
          .collect();
        for entry1 in entries1 {
            let entry2 = entries2_map.get(&entry1.dn);
            match entry2 {
                Some(e2) => {
                    assert_search_entries_eq(entry1, e2);
                },
                None => {
                    panic!("entry with dn {} not found", entry1.dn);
                }
            }
        }
    }

    #[test]
    fn parse_bytes_as_utf8_ok() {
        let bytes = vec![72, 105];
        let result = std::str::from_utf8(&bytes);
        assert_eq!(result, Ok("Hi"));
    }

    #[test]
    fn parse_bytes_as_utf8_err() {
        //let bytes = vec![0]; // ist ok
        let bytes = vec![126, 190];
        let result = std::str::from_utf8(&bytes);
        print!("{:?}", result);
        assert!(result.is_err());
    }

    #[test]
    fn encode_bytes() {        
        use base64::{Engine as _, engine::general_purpose};
        //let orig = b"data";
        let orig = vec![126, 190]; // not utf8
        let encoded: String = general_purpose::STANDARD.encode(orig);
        print!("{:?}", encoded);
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
    fn test_join_3_dns(
        #[case] peripheral_dn: &str,
        #[case] middle_dn: &str,
        #[case] base_dn: &str,
        #[case] expected: &str,
    ) {
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

    pub async fn start_test_server(
        plain_port: u16,
        base_dn: &str,
        content: &str,
    ) -> LdapServerConn {
        info!("start test server()");

        let server = LdapServerBuilder::new(base_dn)
            .port(plain_port)
            // add LDIF to database before LDAP server is started
            .ssl_port(plain_port + 1)
            .add(1, content)
            // init databases and started LDAP server
            .run()
            .await;
        //info!("server started: {:?}", server);
        info!("server started on port {}.", plain_port);
        server
    }

    pub async fn search_all(ldap: &mut Ldap, base_dn: &str) -> Result<Vec<SearchEntry>, LdapError> {
        debug!("search all");
        let search_result = ldap
            .search(base_dn, Scope::Subtree, "(objectClass=*)", vec!["*"])
            .await?;
        let result_entries = search_result.0;
        debug!("found {} entries", result_entries.len());
        let search_entries = result_entries
            .into_iter()
            .map(|result_entry| SearchEntry::construct(result_entry.clone()))
            .collect();
        Ok(search_entries)
    }

    // todo write test for unsuccessful bind
    #[tokio::test]
    async fn test_simple_connect() {
        let _ = env_logger::try_init();

        let plain_port = 10389;
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

        let _server = start_test_server(plain_port, &base_dn, content).await;

        //let src_base_dn = "dc=test".to_string();
        //let _ldap_conn = simple_connect_sync(&src_url, &src_bind_dn, &src_password).unwrap();
        let ldap_conn = simple_connect(&service).await.unwrap();
        //debug!("ldap conn: {:?}", ldap_conn);
    }

    #[tokio::test]
    async fn test_search_one_entry_by_dn() {
        let _ = env_logger::try_init();

        let plain_port = 17389;
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
            ou: Users
        
            dn: cn=xy012345,ou=Users,dc=test
            objectClass: inetOrgPerson
            sn: Müller
            givenName: André
            userPassword: hallowelt123!"
        };

        let service = LdapService {
            url: url,
            bind_dn: bind_dn,
            password: password,
            base_dn: base_dn.clone(),
        };

        let _server = start_test_server(plain_port, &base_dn, content).await;

        let mut ldap_conn = simple_connect(&service).await.unwrap();

        let some_dn = "cn=xy012345,ou=Users,dc=test";
        let some_result = search_one_entry_by_dn(&mut ldap_conn, some_dn)
            .await
            .unwrap();
        assert!(some_result.is_some());

        let none_dn = "cn=ab012345,ou=Users,dc=test";
        let none_result = search_one_entry_by_dn(&mut ldap_conn, none_dn)
            .await
            .unwrap();
        assert!(none_result.is_none());
    }


    #[tokio::test]
    async fn test_search_one_entry_by_dn_with_binary_value() {
        let _ = env_logger::try_init();

        let plain_port = 17389;
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
            jpegPhoto:: fr4=
            jpegPhoto: valid utf8"
        };

        let service = LdapService {
            url: url,
            bind_dn: bind_dn,
            password: password,
            base_dn: base_dn.clone(),
        };

        let _server = start_test_server(plain_port, &base_dn, content).await;

        let mut ldap_conn = simple_connect(&service).await.unwrap();

        let dn = "cn=admin,dc=test";
        let entry = search_one_entry_by_dn(&mut ldap_conn, dn)
            .await
            .unwrap().unwrap();
        assert_eq!(entry.dn, dn);
        print!("entry: {:?}", entry);
    }

    #[tokio::test]
    async fn test_search_one_entry_by_dn_attrs_filtered() {
        let _ = env_logger::try_init();

        let plain_port = 18389;
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
            ou: Users
        
            dn: cn=xy012345,ou=Users,dc=test
            objectClass: inetOrgPerson
            cn: xy012345
            sn: Müller
            givenName: André
            userPassword: hallowelt123!"
        };

        let service = LdapService {
            url: url,
            bind_dn: bind_dn,
            password: password,
            base_dn: base_dn.clone(),
        };

        let _server = start_test_server(plain_port, &base_dn, content).await;

        let mut ldap_conn = simple_connect(&service).await.unwrap();

        let some_ex = Regex::new("^(?i)(givenNAME|UserPassword)$").unwrap();
        let some_dn = "cn=xy012345,ou=Users,dc=test";
        let some_result = search_one_entry_by_dn_attrs_filtered(&mut ldap_conn, some_dn, &some_ex)
            .await
            .unwrap();
        assert!(some_result.is_some());
        let attrs = some_result.unwrap().attrs;
        debug!("attrs: {:?}", attrs);
        assert_eq!(attrs.len(), 3);
        assert!(attrs.contains_key("objectclass"));
        assert!(attrs.contains_key("cn"));
        assert!(attrs.contains_key("sn"));

        let none_ex = Regex::new("^sn$").unwrap();
        let none_dn = "cn=ab012345,ou=Users,dc=test";
        let none_result = search_one_entry_by_dn_attrs_filtered(&mut ldap_conn, none_dn, &none_ex)
            .await
            .unwrap();
        assert!(none_result.is_none());
    }

    #[tokio::test]
    async fn test_search_modified_entries_attrs_filtered() {
        let _ = env_logger::try_init();

        let plain_port = 21389;
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
            ou: Users
            modifyTimestamp: 19750101235958Z
        
            dn: cn=old012345,ou=Users,dc=test
            objectClass: inetOrgPerson
            cn: old012345
            sn: Müller
            modifyTimestamp: 19750101235959Z
            
            dn: cn=new012345,ou=Users,dc=test
            objectClass: inetOrgPerson
            cn: new012345
            sn: Habibullah
            givenName: Amira
            userPassword: welt123!
            modifyTimestamp: 20220101235959Z"
        };

        let service = LdapService {
            url: url,
            bind_dn: bind_dn,
            password: password,
            base_dn: base_dn.clone(),
        };

        let _server = start_test_server(plain_port, &base_dn, content).await;

        let mut ldap_conn = simple_connect(&service).await.unwrap();

        let ex = Regex::new("^(?i)(cn|SN|orclPassword)$").unwrap();

        let search_entries = search_modified_entries_attrs_filtered(
            &mut ldap_conn,
            "ou=Users,dc=test",
            "20201231235959Z",
            &ex,
        )
        .await
        .unwrap();

        assert_eq!(search_entries.len(), 1);
        let attrs = &search_entries[0].attrs;
        debug!("attrs: {:?}", attrs);
        assert_eq!(attrs.len(), 3);
        assert!(attrs.contains_key("objectclass"));
        assert!(attrs.contains_key("givenname"));
        assert!(attrs.contains_key("userpassword"));
    }

    #[tokio::test]
    async fn test_2_servers() {
        //env_logger::init();
        let _ = env_logger::try_init();

        let source_plain_port = 11389;
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
            start_test_server(source_plain_port, &source_base_dn, source_content).await;
        let _target_server =
            start_test_server(target_plain_port, &target_base_dn, target_content).await;

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

        let source_ldap = simple_connect(&source_service).await.unwrap();
        let target_ldap = simple_connect(&target_service).await.unwrap();
        //debug!("source ldap conn: {:?}", source_ldap);
        //debug!("target ldap conn: {:?}", target_ldap);
    }


    /// todo test bin_attrs
    #[test]
    fn test_diff_attributes() {
        let _ = env_logger::try_init();

        let source = HashMap::from([
            (
                "instruments".to_string(),
                vec![
                    "violin".to_string(),
                    "clarinette".to_string(),
                    "flute".to_string(),
                ],
            ),
            ("name".to_string(), vec!["Magic Orchestra".to_string()]),
            ("l".to_string(), vec!["Frankfurt".to_string()]),
            (
                "stateorprovincename".to_string(),
                vec!["Hessen".to_string()],
            ),
        ]);
        let target = HashMap::from([
            (
                "instruments".to_string(),
                vec![
                    "violin".to_string(),
                    "clarinette".to_string(),
                    "oboe".to_string(),
                ],
            ),
            ("name".to_string(), vec!["Old Orchestra".to_string()]),
            ("o".to_string(), vec!["Hessischer Rundfunkt".to_string()]),
            (
                "stateorprovincename".to_string(),
                vec!["Hessen".to_string()],
            ),
        ]);
        let result = diff_attributes(&source, &target);
        debug!("result {:?}", result);

        assert_eq!(result.len(), 4);
        let empty_set = HashSet::new();
        let location_set = HashSet::from(["Frankfurt".to_string()]);
        let instruments_set = HashSet::from([
            "violin".to_string(),
            "clarinette".to_string(),
            "flute".to_string(),
        ]);
        let name_set = HashSet::from(["Magic Orchestra".to_string()]);

        assert!(result.contains(&Mod::Delete("o".to_string(), empty_set)));
        assert!(result.contains(&Mod::Add("l".to_string(), location_set)));
        assert!(result.contains(&Mod::Replace("instruments".to_string(), instruments_set)));
        assert!(result.contains(&Mod::Replace("name".to_string(), name_set)));
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
