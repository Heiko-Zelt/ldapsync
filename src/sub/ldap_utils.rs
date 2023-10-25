use ldap3::{Ldap, LdapConn, LdapConnAsync, LdapError, ResultEntry, Scope, SearchEntry};
use std::collections::HashSet;
use log::{debug, info};

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
pub fn result_entries_to_norm_dns(result_entries: &Vec<ResultEntry>, base_dn: &str) -> HashSet<String> {
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


#[cfg(test)]
pub mod test {
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

    pub async fn start_test_server(
        plain_port: u16,
        tls_port: u16,
        base_dn: &str,
        content: &str,
    ) -> LdapServerConn {
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

    // todo write test for unsuccessful bind
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
