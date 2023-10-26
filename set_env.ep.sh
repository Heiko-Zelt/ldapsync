RUST_LOG=debug
JOB_SLEEP=15 min
DATA_DIR=/opt/Anwendungen/ldap_sync/data
DRY_RUN=true
CF_SERVICES="..."
SYNCHRONISATIONS="[
    { "source": "ldap_he", "target": "ldap_bk", "base_dns": ["cn=he"] },
    { "source": "ldap_hh", "target": "ldap_bk", "base_dns": ["cn=hh"] },
    { "source": "ldap_hb", "target": "ldap_bk", "base_dns": ["cn=hb"] },
    ...    
    { "source": "ldap_bk", "target": "ldap_he", "base_dns": ["cn=bk",          "cn=hh", "cn=ou", "cn=rp", ... ] }
    { "source": "ldap_bk", "target": "ldap_hh", "base_dns": ["cn=bk", "cn=he",          "cn=ou", "cn=rp", ... ] },
    { "source": "ldap_bk", "target": "ldap_rp", "base_dns": ["cn=bk", "cn=he", "cn=hh", "cn=ou",          ... ] },
    ...
]"