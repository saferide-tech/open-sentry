# Saferide's OpenSentry Project
OpenSentry is an open source security manager project intended to manage and monitor various  
security aspects on any Linux distribution (if requirements are met).  

## Benefits:  
1. Consolidation: OpenSentry will provide a unified and easy to use interface to various the security tools.  
   Can be used during development and production phases.
2. System Monitoring: OpenSentry will allow to monitor security breaches by collecting behavioral  
   logs and uploading them to the cloud.  
3. Runtime Patches: OpenSentry will allow to apply virtual patches in case a breach was detected  
   (analysis of collected data).  
4. Securing the CAN bus: SafeRide will contribute a Linux Kernel patch that will allow to secure  
   the CAN bus interface.  

## SW block diagram:
![open_sentry_block_diagram](https://user-images.githubusercontent.com/29350758/36203987-31822170-1192-11e8-95e7-0e2b76cc6887.jpg)  

### Sysrepo:
Open source YANG-based configuration and operational state data store for Unix/Linux applications.  
Allow other application to register callbacks on specific data models that will be invoked upon changes.  
In the OpenSentry solution, sysrepo is used as the security policy rules database.  
https://github.com/sysrepo/sysrepo/  

### OpenSentry:
Security management tool that allow:  
  To control various specific security tools (IPTables, SMACK, CANFilter).  
  Monitor various security aspects (IP and CAN traffic, processes activities, file access, etc).  
The open_sentry daemon interact with the sysrepo daemon to retrieve the current security  
policy and be notified when this database is changed.  

### UpdateManager:
This daemon responsible to update the security rules database with the relevant modifications.
see README.md  in https://github.com/saferide-tech/update-manager for more details on configuration.  
This tool has 2 modes of operations:  
1. Remote: in this mode, the update_manager communicate with a remote server to download  
    the latest security policy and to upload logs.  
2. Local: Monitor local security configuration file for modification.  

In both cases, once a new security policy was downloaded and changed, the update  
manager will commit the changes to sysrepo database.  
https://github.com/saferide-tech/update-manager  

## Prerequisites:
1. sysrepo: https://github.com/sysrepo/sysrepo/
2. libnl: https://www.infradead.org/~tgr/libnl/
3. libnetfilter-log: http://www.netfilter.org/
4. iptables: http://www.netfilter.org/
5. audit: http://people.redhat.com/sgrubb/audit/
6. CAN filter kernel patch: (TBD)

## Compiling:
```
\# git clone https://github.com/saferide-tech/open-sentry.git  
\# cd open-sentry/libsentry  
\# make (can add DEBUG=1)  
\# cd ../open-sentry/  
\# INCLUDES="-I../libsentry/inc -I/usr/include/libnl3" make (can add DEBUG=1)  
```
## Installing:
```
1. install saferide's yang file:  
\# sudo sysrepoctl --install --yang=/home/blabla/open-sentry/yang/saferide.yang --permissions=644
2. run the sysrepo daemon:
\# sudo sysrepod (can add -d 1/2/3. see man sysrepod).
3. copy the open-sentry shaered library (libsentry/build/lib/\*) to /usr/lib (or any other directory on your LD_LIBRARY_PATH).
4. copy open-sentry daemon (open-sentry/build/bin/open_sentry) to /usr/bin (or any other directory in you PATH).
```

## Running:
```
\# sudo open_sentry
```

## NOTES:
1. logs (rotation, up to 10 files) are under /var/logs/sentry.log
2. by default, open-sentry contain some exemplary iptables rules (port-scanning prevention, new connections log, etc).   
   if they are not needed or you wish to add more this is the place:  
   https://github.com/saferide-tech/open-sentry/blob/master/open-sentry/src/ip.c#L182

   
