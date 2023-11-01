use crate::cf_services::LdapService;
use ldap3::{Ldap, LdapConnAsync, LdapError, Mod, ResultEntry, Scope, SearchEntry};
use log::{debug, info};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::cmp::Ordering;

pub fn debug_mods(mods: &Vec<Mod<String>>) -> String {
    let mut v = Vec::new();
    for modi in mods {
      v.push(
        match modi {
          Mod::Add(name, values) => { format!("add: {} {}", name, values.len()) },
          Mod::Delete(name, values) => { format!("delete: {} {}", name, values.len()) },
          Mod::Replace(name, values) => { format!("replace: {} {}", name, values.len()) },
          Mod::Increment(name, _) => { format!("increment: {}", name) },
        }
      )
    };
    format!("[{}]", v.join(", "))
}

pub fn debug_search_entry(search_entry: &SearchEntry) -> String {
    let mut attrs_v = Vec::new();
    let mut bin_attrs_v = Vec::new();

    let mut attr_names_sorted: Vec<String> = search_entry.attrs.keys().cloned().collect();
    attr_names_sorted.sort();
    for name in attr_names_sorted {
        let values = search_entry.attrs.get(&name).unwrap();
        attrs_v.push(format!("{} {}", name, values.len()));
    }

    let mut bin_attr_names_sorted: Vec<String> = search_entry.bin_attrs.keys().cloned().collect();
    bin_attr_names_sorted.sort();
    for name in bin_attr_names_sorted {
        let values = search_entry.bin_attrs.get(&name).unwrap();
        bin_attrs_v.push(format!("{} {}", name, values.len()));
    }
    format!("dn: {}, attrs: [{}], bin_attrs: [{}]", search_entry.dn, attrs_v.join(", "), bin_attrs_v.join(", "))
}

pub fn compare_by_length_desc_then_alphabethical(a: &str, b: &str) -> Ordering {
    let c = b.len().cmp(&a.len());
    match c {
        Ordering::Equal=> a.cmp(b),
        Ordering::Less | Ordering::Greater => c,
    }
}

// todo Sortierung muss auch alphabetisch sein, nicht nur nach Länge
pub fn log_debug_dns(prefix: &str, dns: &HashSet<String>) {
    let mut dns_sorted: Vec<&String> = dns.iter().collect();
    dns_sorted.sort_by(|a ,b| compare_by_length_desc_then_alphabethical(a, b));
    for dn in dns_sorted {
        debug!(r#"{} "{}""#, prefix, dn);
    };
}

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

// todo handle connect failed
pub async fn simple_connect(service: &LdapService) -> Result<Ldap, LdapError> {
    let (conn, mut ldap) = LdapConnAsync::new(&service.url).await?;
    // returns type ldap3::result::Result<(LdapConnAsync, Ldap)>
    // ldap3::result::Result is Result<T> = Result<T, LdapError> is Result<(LdapConnAsync, Ldap), LdapError>

    ldap3::drive!(conn);
    let _ldap_result = ldap
        .simple_bind(&service.bind_dn, &service.password)
        .await?
        .success()?;
    // returns: ldap3::result::Result<LdapResult>
    // ldap3::result::Result is Result<T> = Result<T, LdapError> is Result<LdapResult, LdapError>
    // Enum ldap3::result::LdapError
    // return code is in LdapResult

    // LdapResult {result: LdapResult } is a variant of LdapError

    /*
    does the same as .success()?
    if ldap_result.rc != 0 {
        Err(LdapError::LdapResult { result: ldap_result })
    } else {
        Ok(ldap)
    }
    */

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
        let search_entry = SearchEntry::construct(result_entry.clone());
        let mut dn = search_entry.dn;
        truncate_dn(&mut dn, base_dn_len); // in bytes (not characters)
        let norm_dn = dn.to_lowercase();
        //debug!(r#"result_entries_to_norm_dns: norm_dn: "{}""#, norm_dn);
        norm_dns.insert(norm_dn);
    }
    norm_dns
}

/// todo Error, wenn base_dn gar nicht existiert
pub async fn search_norm_dns(ldap: &mut Ldap, base_dn: &str) -> Result<HashSet<String>, LdapError> {
    debug!(
        r#"search_norm_dns: search for DNs from base: "{}""#,
        base_dn
    );
    let search_result = ldap
        .search(base_dn, Scope::Subtree, "(objectClass=*)", vec!["dn"])
        .await?
        .success()?;

    //SearchResult tuple fields:
    //  0: Vec<ResultEntry>
    //  1: LdapResult

    /*
    let ldap_result = search_result.1;
    if ldap_result.rc != 0 { // Is result code ok?
        return Err(LdapError::LdapResult{ result: ldap_result })
    }
    */

    let result_entries = search_result.0;
    info!(
        "search_norm_dns: found number of entries: {}",
        result_entries.len()
    );
    let norm_dns = result_entries_to_norm_dns(&result_entries, base_dn);
    Ok(norm_dns)
}

/// returns exactly one entry if found or an LdapError
/// Err(LdapResult { result: LdapResult { rc: 32, matched: "ou=Users,dc=test", text: "", refs: [], ctrls: [] } })
pub async fn search_one_entry_by_dn(
    ldap_conn: &mut Ldap,
    dn: &str,
) -> Result<SearchEntry, LdapError> {
    debug!(r#"search_one_entry_by_dn: "{}""#, dn);
    let search_result = ldap_conn
        .search(dn, Scope::Base, "(objectClass=*)", vec!["*"])
        .await?
        .success()?;
    let result_entries = search_result.0;
    debug!(
        "search_one_entry_by_dn: found number of entries: {}",
        result_entries.len()
    ); // should be 0 or 1

    /*
    match result_entries.len() {
        0 => Ok(None),
        1 => {
            let search_entry = SearchEntry::construct(result_entries[0].clone());
            Ok(Some(search_entry))
        }
        _ => {
            panic!("search_one_entry_by_dn: Found more than 1 entry.")
        }
    }
    */

    if result_entries.len() > 1 {
        panic!("search_one_entry_by_dn: Found more than 1 entry.")
    }

    let search_entry = SearchEntry::construct(result_entries[0].clone());
    Ok(search_entry)
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
/// Additionally attribute names are normalized to lower case,
/// because Oracle Interne Directory returns attribute names in lower case
/// and OpenLdap may return attributes in camel case.
pub async fn search_one_entry_by_dn_attrs_filtered(
    ldap_conn: &mut Ldap,
    dn: &str,
    exclude_attrs: &Regex,
) -> Result<SearchEntry, LdapError> {
    let result = search_one_entry_by_dn(ldap_conn, dn).await;
    match result {
        Ok(mut entry) => {
            entry.attrs = filter_attrs(&entry.attrs, exclude_attrs);
            debug!(
                "search_one_entry_by_dn_attrs_filtered: filtered attrs: {}",
                debug_search_entry(&entry)
            );
            Ok(entry)
        }
        Err(err) => Err(err),
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
    debug!(
        r#"search_modified_entries_attrs_filtered with base: "{}", filter: "{}""#,
        base_dn, filter
    );
    let mut search_stream = ldap
        .streaming_search(&base_dn, Scope::Subtree, &filter, vec!["*"])
        .await?;
    let mut search_entries: Vec<SearchEntry> = Vec::new();
    loop {
        let result_entry = search_stream.next().await?;
        // next() returns ldap3::result::Result<Option<ResultEntry>> = Result<Option<ResultEntry>, LdapError>;
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
    let _ldap_result = search_stream.finish().await.success()?;
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
    use super::*;
    use crate::ldap_result_codes::*;
    use crate::ldif::*;
    use indoc::*;
    use ldap3::{LdapError, LdapResult};
    use ldap_test_server::{LdapServerBuilder, LdapServerConn};
    use rstest::rstest;
    use std::sync::Mutex;
    use log::debug;

    // singleton pattern
    static PORT_SEQUENCE: Mutex<u16> = Mutex::new(1389);

    /// Tests may run in parallel and start a test LDAP server each.
    /// So they need different TCP ports.
    /// This function returns the next TCP port,
    /// incrmeneting by 2, so we get 2 ports one for plain LDAP and one for TLS.
    pub fn next_port() -> u16 {
         let mut port_guard = PORT_SEQUENCE.lock().unwrap();
         let result = *port_guard;
         *port_guard += 2; 
         result
    }

    /*
    #[test]
    pub fn test_mutex() {
        println!("port: {}", next_port());
        println!("port: {}", next_port());
        println!("port: {}", next_port());
    }
    */

    #[rstest]
    #[case("A", "B", Ordering::Less)] // 'A' kommt vor 'B'
    #[case("Hallo", "Hi", Ordering::Less)] // zuerst längere, dann kürzere
    pub fn test_compare_by_length_desc_then_alphabethical(#[case] a: &str, #[case] b: &str, #[case] expected: Ordering) {
        assert_eq!(compare_by_length_desc_then_alphabethical(a, b), expected);
    }

    #[test]
    pub fn test_debug_mods() {
        let mods = vec![
            Mod::Delete("description".to_string(), HashSet::new()),
            Mod::Delete("sn".to_string(), HashSet::new()),
            Mod::Add("givenname".to_string(), HashSet::from(["Heinz".to_string()])),
            Mod::Replace("instruments".to_string(), HashSet::from(["violin".to_string(), "clarinette".to_string()]))
        ];
        assert_eq!(debug_mods(&mods), "[delete: description 0, delete: sn 0, add: givenname 1, replace: instruments 2]");
    }

    #[test]
    pub fn test_debug_search_entry() {
        let search_entry = SearchEntry {
            dn: "cn=us012345,cn=Users,dc=test".to_string(),
            attrs: HashMap::from([("givenname".to_string(), vec!["Heinz".to_string()]), ("sn".to_string(), vec!["Müller".to_string()]), ("objectclass".to_string(), vec!["inetorgperson".to_string(), "top".to_string()])]),
            bin_attrs: HashMap::from([]),
        };
        assert_eq!(debug_search_entry(&search_entry), "dn: cn=us012345,cn=Users,dc=test, attrs: [givenname 1, objectclass 2, sn 1], bin_attrs: []");
    }

    pub fn assert_attrs_eq(
        attrs1: &HashMap<String, Vec<String>>,
        attrs2: &HashMap<String, Vec<String>>,
    ) {
        let result = diff_attributes(&attrs1, &attrs2);
        if result.len() != 0 {
            panic!(
                "attributes differ:\nattrs1: {:?},\nattrs2: {:?},\ndiff: {:?}",
                attrs1, attrs2, result
            );
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
            let dns1: Vec<_> = entries1.iter().map(|entry| entry.dn.to_string()).collect();
            let dns2: Vec<_> = entries2.iter().map(|entry| entry.dn.to_string()).collect();
            panic!(
                "different number of entries {} != {}, DNs1: {:?}, DNs2: {:?}",
                entries1.len(),
                entries2.len(),
                dns1,
                dns2
            );
        }
        // map dn to entries
        let entries2_map: HashMap<String, SearchEntry> = entries2
            .iter()
            .map(|entry| (entry.dn.clone(), entry.clone()))
            .collect();
        for entry1 in entries1 {
            let entry2 = entries2_map.get(&entry1.dn);
            match entry2 {
                Some(e2) => {
                    assert_search_entries_eq(entry1, e2);
                }
                None => {
                    panic!("entry with dn {} not found", entry1.dn);
                }
            }
        }
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

    pub fn attr_names_to_lowercase(
        old_attrs: HashMap<String, Vec<String>>,
    ) -> HashMap<String, Vec<String>> {
        let new_attrs = old_attrs
            .iter()
            .map(|(name, values)| (name.to_lowercase(), values.clone()))
            .collect();
        new_attrs
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
            .map(|result_entry| {
                let mut search_entry = SearchEntry::construct(result_entry.clone());
                search_entry.attrs = attr_names_to_lowercase(search_entry.attrs);
                search_entry
            })
            .collect();
        Ok(search_entries)
    }

    // todo write test for unsuccessful bind
    #[tokio::test]
    async fn test_simple_connect_successful() {
        let _ = env_logger::try_init();

        // todo write a function/sequence which returns an unused port/port within a range
        let plain_port = next_port();
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
        let _ldap_conn = simple_connect(&service).await.unwrap();
        //debug!("ldap conn: {:?}", ldap_conn);
    }

    #[tokio::test]
    async fn test_simple_connect_failed() {
        let _ = env_logger::try_init();
        let plain_port = next_port();
        let url = format!("ldap://127.0.0.1:{}", plain_port);
        let bind_dn = "cn=admin,dc=test".to_string();
        let wrong_password = "secret2".to_string();
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
            userPassword: secret1

            dn: ou=Users,dc=test
            objectClass: top
            objectClass: organizationalUnit
            ou: Users"
        };
        let service = LdapService {
            url: url,
            bind_dn: bind_dn,
            password: wrong_password,
            base_dn: base_dn.clone(),
        };
        let _server = start_test_server(plain_port, &base_dn, content).await;

        let result = simple_connect(&service).await;

        debug!("result: {:?}", result);
        assert!(matches!(
            &result,
            Err(LdapError::LdapResult {
                result: LdapResult {
                    rc: RC_INVALID_CREDENTIALS!(),
                    ..
                }
            })
        ));
    }

    #[tokio::test]
    async fn test_search_one_entry_by_dn() {
        let _ = env_logger::try_init();

        let plain_port = next_port();
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
        let some_entry = search_one_entry_by_dn(&mut ldap_conn, some_dn)
            .await
            .unwrap();
        assert_eq!(some_entry.dn, some_dn);
        let attrs = some_entry.attrs;
        // OpenLDAP server returns attribute names in Camel-Case
        assert_eq!(attrs.len(), 5);
        assert_eq!(attrs.get("cn").unwrap()[0], "xy012345"); // generated from DN by OpenLDAP server
        assert_eq!(attrs.get("objectClass").unwrap()[0], "inetOrgPerson");
        assert_eq!(attrs.get("sn").unwrap()[0], "Müller");
        assert_eq!(attrs.get("givenName").unwrap()[0], "André");
        assert_eq!(attrs.get("userPassword").unwrap()[0], "hallowelt123!");
    }

    #[tokio::test]
    async fn test_search_one_entry_by_dn_not_found() {
        let _ = env_logger::try_init();

        let plain_port = next_port();
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
            userPassword: secret"
        };

        let service = LdapService {
            url: url,
            bind_dn: bind_dn,
            password: password,
            base_dn: base_dn.clone(),
        };

        let _server = start_test_server(plain_port, &base_dn, content).await;

        let mut ldap_conn = simple_connect(&service).await.unwrap();

        let none_dn = "cn=ab012345,ou=Users,dc=test";
        let none_result = search_one_entry_by_dn(&mut ldap_conn, none_dn).await;
        debug!("none_result: {:?}", none_result);
        //Err(LdapResult { result: LdapResult { rc: 32, matched: "ou=Users,dc=test", text: "", refs: [], ctrls: [] } })
        assert!(matches!(
            &none_result,
            Err(LdapError::LdapResult {
                result: LdapResult {
                    rc: RC_NO_SUCH_OBJECT!(),
                    ..
                }
            })
        ));
    }

    #[tokio::test]
    async fn test_search_one_entry_by_dn_with_binary_value() {
        let _ = env_logger::try_init();

        let plain_port = next_port();
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
        let entry = search_one_entry_by_dn(&mut ldap_conn, dn).await.unwrap();
        debug!("entry: {:?}", entry);
        assert_eq!(entry.dn, dn);
    }

    #[tokio::test]
    async fn test_search_one_entry_by_dn_attrs_filtered() {
        let _ = env_logger::try_init();

        let plain_port = next_port();
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
        let attrs = some_result.attrs;
        debug!("attrs: {:?}", attrs);
        assert_eq!(attrs.len(), 3);
        assert!(attrs.contains_key("objectclass"));
        assert!(attrs.contains_key("cn"));
        assert!(attrs.contains_key("sn"));

        let none_ex = Regex::new("^sn$").unwrap();
        let none_dn = "cn=ab012345,ou=Users,dc=test";
        let none_result =
            search_one_entry_by_dn_attrs_filtered(&mut ldap_conn, none_dn, &none_ex).await;
        assert!(none_result.is_err());
        // todo what kind of error????
    }

    #[tokio::test]
    async fn test_search_modified_entries_attrs_filtered_success() {
        let _ = env_logger::try_init();
        let plain_port = next_port();
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
        let expected_search_entries = parse_ldif_as_search_entries(indoc! {"
            dn: cn=new012345,ou=Users,dc=test
            objectclass: inetOrgPerson
            givenname: Amira
            userpassword: welt123!"
        })
        .unwrap();

        let search_entries = search_modified_entries_attrs_filtered(
            &mut ldap_conn,
            "ou=Users,dc=test",
            "20201231235959Z",
            &ex,
        )
        .await
        .unwrap();

        assert_vec_search_entries_eq(&search_entries, &expected_search_entries);

        assert_eq!(search_entries.len(), 1);
        let attrs = &search_entries[0].attrs;
        debug!("attrs: {:?}", attrs);
        assert_eq!(attrs.len(), 3);
        assert!(attrs.contains_key("objectclass"));
        assert!(attrs.contains_key("givenname"));
        assert!(attrs.contains_key("userpassword"));
    }


    #[tokio::test]
    async fn test_search_modified_entries_attrs_filtered_fail() {
        let _ = env_logger::try_init();
        let plain_port = next_port();
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
            userPassword: secret"
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

        let failed_result = search_modified_entries_attrs_filtered(
            &mut ldap_conn,
            "ou=Users,dc=test",
            "20201231235959Z",
            &ex,
        )
        .await;

        debug!("failed_result: {:?}", failed_result);
        assert!(matches!(
            &failed_result,
            Err(LdapError::LdapResult {
                result: LdapResult {
                    rc: RC_NO_SUCH_OBJECT!(),
                    ..
                }
            })
        ));

    }

    #[tokio::test]
    async fn test_search_norm_dns_successful() {
        let _ = env_logger::try_init();
        let plain_port = next_port();
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
        
            dn: cn=us012345,ou=Users,dc=test
            objectClass: inetOrgPerson
            cn: us012345
            sn: Müller
            modifyTimestamp: 19750101235959Z"
        };
        let service = LdapService {
            url: url,
            bind_dn: bind_dn,
            password: password,
            base_dn: base_dn.clone(),
        };
        let _server = start_test_server(plain_port, &base_dn, content).await;
        let mut ldap_conn = simple_connect(&service).await.unwrap();

        let expected_dns: HashSet<String> = vec!["".to_string(), "cn=us012345".to_string()]
            .into_iter()
            .collect();

        let norm_dns = search_norm_dns(&mut ldap_conn, "ou=Users,dc=test")
            .await
            .unwrap();

        assert_eq!(&norm_dns, &expected_dns);
    }

    #[tokio::test]
    async fn test_search_norm_dns_base_dn_not_found() {
        let _ = env_logger::try_init();
        let plain_port = next_port();
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
            userPassword: secret"
        };
        let service = LdapService {
            url: url,
            bind_dn: bind_dn,
            password: password,
            base_dn: base_dn.clone(),
        };
        let _server = start_test_server(plain_port, &base_dn, content).await;
        let mut ldap_conn = simple_connect(&service).await.unwrap();

        let result = search_norm_dns(&mut ldap_conn, "ou=Users,dc=test").await;

        //debug!("result: {:?}", &result);
        //Err(LdapResult { result: LdapResult { rc: 32, matched: "dc=test", text: "", refs: [], ctrls: [] } })
        assert!(matches!(
            &result,
            Err(LdapError::LdapResult {
                result: LdapResult {
                    rc: RC_NO_SUCH_OBJECT!(),
                    ..
                }
            })
        ));
    }

    #[tokio::test]
    async fn test_2_servers() {
        //env_logger::init();
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
            o: de"
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

            dn: ou=Users,dc=test
            objectClass: top
            objectClass: organizationalUnit
            ou: Users
    
            dn: o=de,ou=Users,dc=test
            objectClass: top
            objectClass: organization
            o: de"
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

        let _source_ldap = simple_connect(&source_service).await.unwrap();
        let _target_ldap = simple_connect(&target_service).await.unwrap();
        //debug!("source ldap conn: {:?}", source_ldap);
        //debug!("target ldap conn: {:?}", target_ldap);
    }

    /// todo test bin_attrs
    #[test]
    fn test_diff_attributes() {
        let _ = env_logger::try_init();
        let source_entries = parse_ldif_as_search_entries(indoc! {"
            dn: cn=entry,dc=test
            cn: entry
            instruments: violin
            instruments: clarinette
            instruments: flute
            name: Magic Orchestra
            l: Frankfurt
            stateorprovincename: Hessen"
        })
        .unwrap();
        let target_entries = parse_ldif_as_search_entries(indoc! {"
            dn: cn=entry,dc=test
            cn: entry
            instruments: violin
            instruments: clarinette
            instruments: oboe
            name: Old Orchestra
            o: Hessischer Rundfunk
            stateorprovincename: Hessen"
        })
        .unwrap();
        let source_attrs = &source_entries[0].attrs;
        let target_attrs = &target_entries[0].attrs;

        let result = diff_attributes(source_attrs, target_attrs);

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
}