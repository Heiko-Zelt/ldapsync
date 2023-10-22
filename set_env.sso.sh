RUST_LOG=debug
JOB_SLEEP=10 sec
DATA_DIR=/opt/Anwendungen/ldap_sync/data
DRY_RUN=true
CF_SERVICES="..."
LDAP_SYNC_CONF="[{
    source: "oid_vwase120_orcladmin",
    target: "oid_swase100_orcladmin",
    base_dns: [
        "o=de,cn=users",
        "cn=rights",
        "cn=roles",
        "cn=usages"
    ]
}]"