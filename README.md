# LDAP Sync

This program is a daemon/service,
which synchronizes subtrees of LDAP directories continously.

Multiple LDAP directories and subtrees can be synchronized.
A Synchronization is directional from provider to consumer (master-slave).

It is meant to run continuously as an app in Cloud Foundry.
The configuration is read from environment variables.
It is possible to run outside Cloud Foundry,
but environment variables have to be set like in Cloud Foundry.

I need this programm to synchronize Microsoft Active Directories, Oracle Internet Directories (OIDs) and OpenLDAP servers.
It may work with other directory servers too, which implement the LDAPv3 protocol, but is not testet (yet).

## Warnings

* In general you should regularily, automatically backup your data.
  But maybe before running this programm, you should manually create an additional backup.
  Even I testet this software, I cannot garantee it is free of bugs.
  If you configure it wrong, LDAP data may accidentally be deleted.
* Attributes, which have at least one binary value (not valid UTF8) are ignored,
  independently of the attribute type. A warning message is logged.
  I don't need binary data in our LDAP servers. So, it's no problem for me.

## Algorithm

To avoid reading and comparing the whole content of the subtrees every time, the following algoritm is used.

 * Added and modified LDAP entries are found by the modifyTimestamp attribute.
   modifyTimestamp must be greater or equal to the time of the last successful synchronization.
 * Deleted LDAP entries are found by the difference in the list of DNs in source and target directory.
   (TODO count entries in source directory and only search in target if the number changed.)
 * Moved entries are first deleted and then added. Inbetween they are missing.
   The data is inconsistent for a short time. But unique costraints are respected.

The time of the last successful synchronization is stored in memory and not persisted.
When started the first run reads the whole content of the source subtree
as if all entries have recently been modified.
But subsequent runs are optimized using the modifyTimestamp.

~~The time of the last successful synchronization has to be stored somewhere,
to be persitent between restarts of the daemon.
It is stored in an entry in one of the ldap servers.
So there is no additional data store service needed.~~

Directory operational attributes can't be synchronized, because they are generated by the LDAP server.
Only attributes which can be found by ldapsearch with the parameter '*' are synchronized.
Attributes can be excluded by providing a regular expression for attribute names.
The attribute names in the reg-ex must be in all lower case.
(alternatively you can prefix the reg-ex by the ignore case flag "(?i)")

## Simple Example: Synchronize 2 LDAP directories

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
export RUST_LOG='debug'
export LS_DAEMON='false'
export LS_DRY_RUN='true'
export LS_ATTRS='*'
export LS_EXCLUDE_ATTRS='^(?i)(authPassword.*|orclPassword|orclAci|orclEntryLevelAci)$'
export VCAP_SERVICES='{
  "user-provided": [
    {
      "name": "ldap1",
      "credentials": {
        "url": "ldap://ldap1.provider.de:389",
        "bind_dn": "cn=admin1,dc=de",
        "password": "secret1",
        "base_dn": "dc=de"
      }
    },
    {
      "name": "ldap2",
      "credentials": {
        "url": "ldap://ldap2.consumer.de:389",
        "bind_dn": "cn=admin2,dc=de",
        "password": "secret2",
        "base_dn": "dc=de"
      }
    }
  ]
}'
export LS_SYNCHRONIZATIONS='[{
    "source": "ldap1",
    "target": "ldap2",
    "base_dns": [
        "o=de,cn=users",
        "cn=rights",
        "cn=roles"
    ]
}]'
./ldapsync
```

## Advanced Example

There are 4 organizations. Every organization operates an own directory server.
Every organization maintains the data of its own subtree ("o=org1"..."o=org4").
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
export RUST_LOG='debug'
export LS_DAEMON='true'
export LS_JOB_SLEEP='15 min'
export LS_DRY_RUN='false'
export LS_FILTER='(objectClass=person)'
export LS_ATTRS='*'
export VCAP_SERVICES='{
  "user-provided": [
    {
      "name": "hub1",
      "credentials": {
        "url": "ldap://ldap1.org1.de:389",
        "bind_dn": "cn=admin1,dc=de",
        "password": "secret1",
        "base_dn": "dc=de"
      }
    },
    {
      "name": "ldap2",
      "credentials": {
        "url": "ldap://ldap2.org2.de:389",        
        "bind_dn": "cn=admin2,dc=de",
        "password": "secret2",
        "base_dn": "dc=de"
      }
    },
    {
      "name": "ldap3",
      "credentials": {
        "url": "ldap://ldap3.org3.de:389",
        "bind_dn": "cn=admin3,dc=de",
        "password": "secret3",
        "base_dn": "dc=de"
      }
    },
    {
      "name": "ldap4",
      "credentials": {
        "url": "ldap://ldap4.org4.de:389",
        "bind_dn": "cn=admin4,dc=de",
        "password": "secret4",
        "base_dn": "dc=de"
      }
    }
  ]
}'"
export LS_SYNCHRONIZATIONS="[
    {"source": "ldap2", "target": "hub1", "base_dns": ["o=org2"]},
    {"source": "ldap3", "target": "hub1", "base_dns": ["o=org3"]},
    {"source": "ldap4", "target": "hub1", "base_dns": ["o=org4"]},
    {"source": "hub1", "target": "ldap2", "base_dns": ["o=org1",           "o=org3", "o=org4"]},
    {"source": "hub1", "target": "ldap3", "base_dns": ["o=org1", "o=org2",           "o=org4"]},
    {"source": "hub1", "target": "ldap4", "base_dns": ["o=org1", "o=org2", "o=org3"          ]}
]"
./ldapsync
```

## Environment Variables

| Name        | Mandatory | Meaning                                                                                                                   |
| ----------- | --------- | ------------------------------------------------------------------------------------------------------------------------- |
| VCAP_SERVICES | yes     | Data to connect to LDAP servers (in typical Cloud Foundry syntax). Only simple authentication with username and password is supported. |
| LS_SYNCHRONIZATIONS | yes | Service names of source and target directory, like defined in VCAP_SERVICES and subtree(s) wich should be synchronized. |
| LS_DAEMON   | yes       | "true" to synchronize continiously or "false" to run only once.                                                           |
| LS_SLEEP    | no        | Time to sleep between runs, if in daemon mode. Examples "10 sec" or "15 min".                                             |
| LS_DRY_RUN  | yes       | "true" to only log what would be changed, "false" to actually modify content of target directory.                         |
| LS_FILTER   | no        | example: "(objectClass=person)", default value is "(objectClass=*)"                                                       |
| LS_ATTRS    | yes       | whitespace-separated list of attribute names, may contain "*" and/or "+", example: "cn sn givenName"                      |
| LS_EXCLUDE_ATTRS | no   | Regular expression for attribute names to be ignored.                                                                     |
| RUST_LOG    | no        | Log-Level: "trace", "debug", "info", "warn", "error" or "off", see: https://docs.rs/env_logger/latest/env_logger/         |


## Additional information

I observed that Oracle Internet Directory returns attribute names in lower case,
OpenLdap Server may return attribute names in camel case.
ldapsync internally converts attribute names to lowercase.
That simplifies filtering attributes by name and comparing lists of attributes.