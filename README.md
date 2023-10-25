# LDAP Sync

This program is a daemon/service,
which synchronizes subtrees of LDAP directories continously.

Multiple LDAP directories and subtrees can be synchronized.
A Synchronisation is directional from provider to consumer (master-slave).

It is meant to run continiously as an App in Cloud Foundry.
The configuration is read from environment variables.
It is possible to run outside Cloud Foundry,
but environment variables have to be set like in Cloud Foundry.

I need this programm to synchronize Oracle Internet Directories (OIDs) and OpenLDAP servers.
It may work with other directory servers too, which implement the LDAPv3 protocol.

## Algorithm

To avoid reading and comparing the whole content of the subtrees every time, the following algoritm is used.

 * Added and modified LDAP entries are found by modifyTimestamp attribute.
   modifyTimestamp must be greater or equal to the time of the last successful synchronisation.
 * Deleted LDAP entries are found by the difference in the list of DNs in source and target directory.
 * Moved entries are first deleted and then added. Inbetween they are missing.
   The data is inconsistent for a short time. But unique costraints are respected.

The time of the last successful synchronisation has to be stored somewhere,
to be persitent between restarts of the daemon.
It is stored in an entry in one of the ldap servers.

## Simple Example

Synchronize 2 LDAP directories.
One plays the role of a data provider the other the role of a consumer.

If you deploy in Cloud Foundry, then create 2 services:

```
cf cups ldap1 -p "url, base_dn, bind_dn, password"
cf cups ldap2 -p "url, base_dn, bind_dn, password"
```
If not, set the environment variable VCAP_SERVICES like below and the other user provided variables.
Cloud Foundry's VCAP_SERVICES JSON code usually contains a lot of data, which is unneccessary.
Only the following minimal JSON code is needed.

```
#!/bin/bash
export RUST_LOG=debug
export JOB_SLEEP=10 sec
export DRY_RUN=true
export VCAP_SERVICES='{
  "user-provided": [
    {
      "name": "ldap1",
      "credentials": {
        "url": "ldap://ldap1.provider.de:389",
        "bind_dn": "cn=admin1,dc=de",
        "password": "secret1",
        "base": "dc=de"
      }
    },
    {
      "name": "ldap2",
      "credentials": {
        "url": "ldap://ldap2.consumer.de:389",
        "bind_dn": "cn=admin2,dc=de",
        "password": "secret2",
        "base": "dc=de"
      }
    }
  ]
}'
export SYNCHRONISATIONS='[{
    "source": "ldap1",
    "target": "ldap2",
    "base_dns": [
        "o=de,cn=users",
        "cn=rights",
        "cn=roles"
    ],
    "ts_store": "ldap2",
    "ts_dn": "o=ldap1-ldap2,o=sync_timestamps"
}]'
./ldapsync
```

## Advanced Example

There are 4 organisations. Every organisation operates an own directory server.
Every organisation maintains the data of its own subtree ("o=org1"..."o=org4").
One of the servers ("hub1") additionally plays the role of a central hub.
The hub collects the owned subtrees from the 3 other directories
and redistributes the foreign data to all others. In the end all 4 have the same data.

If you deploy in Cloud Foundry, then create 4 services:

```
cf cups hub1  -p "url, base_dn, bind_dn, password"
cf cups ldap2 -p "url, base_dn, bind_dn, password"
cf cups ldap3 -p "url, base_dn, bind_dn, password"
cf cups ldap4 -p "url, base_dn, bind_dn, password"
```

```
#!/bin/bash
export RUST_LOG=debug
export JOB_SLEEP=15 min
export DRY_RUN=false
export VCAP_SERVICES="export VCAP_SERVICES='{
  "user-provided": [
    {
      "name": "hub1",
      "credentials": {
        "url": "ldap://ldap1.org1.de:389",
        "bind_dn": "cn=admin1,dc=de",
        "password": "secret1",
        "base": "dc=de"
      }
    },
    {
      "name": "ldap2",
      "credentials": {
        "url": "ldap://ldap2.org2.de:389",        
        "bind_dn": "cn=admin2,dc=de",
        "password": "secret2",
        "base": "dc=de"
      }
    },
    {
      "name": "ldap3",
      "credentials": {
        "url": "ldap://ldap3.org3.de:389",
        "bind_dn": "cn=admin3,dc=de",
        "password": "secret3",
        "base": "dc=de"
      }
    },
    {
      "name": "ldap4",
      "credentials": {
        "url": "ldap://ldap4.org4.de:389",
        "bind_dn": "cn=admin4,dc=de",
        "password": "secret4",
        "base": "dc=de"
      }
    }
  ]
}'"
export SYNCHRONISATIONS="[
    {"source": "ldap2", "target": "hub1", "base_dns": ["o=org2"], "ts_store": "hub1", "ts_dn": "o=ldap2-hub1,o=sync_timestamps"},
    {"source": "ldap3", "target": "hub1", "base_dns": ["o=org3"], "ts_store": "hub1", "ts_dn": "o=ldap3-hub1,o=sync_timestamps"},
    {"source": "ldap4", "target": "hub1", "base_dns": ["o=org4"], "ts_store": "hub1", "ts_dn": "o=ldap4-hub1,o=sync_timestamps"},
    {"source": "hub1", "target": "ldap2", "base_dns": ["o=org1",           "o=org3", "o=org4"], "ts_store": "hub1", "ts_dn": "o=hub1-ldap2,o=sync_timestamps"},
    {"source": "hub1", "target": "ldap3", "base_dns": ["o=org1", "o=org2",           "o=org4"], "ts_store": "hub1", "ts_dn": "o=hub1-ldap3,o=sync_timestamps"},
    {"source": "hub1", "target": "ldap4", "base_dns": ["o=org1", "o=org2", "o=org3"          ], "ts_store": "hub1", "ts_dn": "o=hub1-ldap4,o=sync_timestamps"}
]"
./ldapsync
```