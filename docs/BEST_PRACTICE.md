## Best Practice: **MFT**

### Requirements for Secure Managed File Transfer

#### Secure Managed File Security

* Hardened virtual appliance – shrink the threat surface with a hardened virtual appliance server that includes the OS, databases, file systems, Web servers, application servers, etc.

* Least privilege – apply a default zero-trust or least privilege principle to all folder access and data transfers. Require specific permission to gain access between services internal to the appliance, access between cluster nodes, as well as external file transfers. All access is subject to expiration policies.

* FedRAMP authorized and FIPS validated – a best practice if not a requirement for working with government agencies; FedRAMP authorization and FIPS compliance demonstrate to the US Department of Defense you consider security a top priority when sharing confidential data.

* Integrated AV and ATP with quarantine – automatically quarantine detected files, provide alerts, and enable the security staff to unlock files in the case of false positives.

* Integrated HSM – ensure that any file decryption requires access to keys stored in a hardened security module, protected with layers of derivations, transformations, and obfuscation.

* Secure enterprise storage access – secure content access to cloud and on-premises content management systems, file shares, and other repositories to prevent accidental leaks and intentional breaches.

#### Secure Managed File Governance

* Flow authoring access controls – don’t leave governance of MFT workflows like sources, destinations, sensitive data classes, even ciphers to developers. With unified visibility, you can centralize governance of these workflows and exert the same level of control you have over secure email and secure file sharing.

* Granular folder access control roles – go beyond the root directory level in the file-first model by allowing access permissions to be assigned to a nested folder. With a security-first architecture, a granular data access model is independent of the underlying operating system.

* Role-based user policies – go beyond traditional data access controls to control who is allowed to share data, who is allowed to author transfer workflows, who can run them, what domains the data can be sent to, etc.

* Consolidated and standardized logs – aggregate logs from MFT and all other communication channels like secure email, security file sharing, SFTP, and content access connectors. When syntax and semantics are normalized in a single, clean log, SIEM analysts can focus on finding cross-channel patterns that indicate threats or attacks.

#### Secure Managed File Visibility

* Security visualizations, analytics, notifications – a CISO Dashboard that sees, follows, and records all data movement through all third-party communication channels to detecting anomalies, send alerts, and enable analysis at detailed levels.

#### Secure SFTP Server

There are several approaches you can take to better secure your SFTP servers to support compliance:

* Disable FTP. If you are using your own server, disabling FTP is a good way to lock down a potential attack vector. Likewise, if you work with a third-party vendor, you can ask if they have disabled FTP and, if not, what security protocols they have in place to protect it.

* Use the strongest encryption. AES-256 is currently the strongest standard encryption around, and SHA-2 hashing currently represents the strongest hash encryption to authenticate data. It’s straightforward to get an SFTP server that includes both.

* Use file and folder security for external access. Have proper practices in place to monitor and protect data when third parties need to see it during or before an SFTP transfer. This includes proper user access and identity management features.

* Use folder security for internal access. Access controls can be a pain to set up because somebody has to do it manually on individual folders. Business users typically don’t have the skills or permission to do this, so organizations often resort to these users writing help desk tickets for IT to undertake access management tasks. The Kiteworks platform has a solution that provides web-based (or even mobile) self-service for business users to set and automate these security settings.

* Include documentation and auditing. Most frameworks require some capacity to document things like compliance and file access. Utilizing a method to monitor file access as well as document things like user consent and other requests is a critical part of GDPR compliance.

* Use IP blacklisting and whitelisting. It may be necessary to simply block access to your servers through blacklists to protect data, particularly if there is no reason to accept traffic from, say, foreign countries or specific regions.

* Provide logging integration with your SIEM so your SOC team can detect and mitigate attacks.

* Require certificate-based authentication for external users. This way, you can ensure that anyone accessing your system at least has a security certificate to verify who they are.

* Harden your SFTP server. Once you configure your SFTP server with increased security measures to prevent unauthorized access, data theft, and malware attacks, you’ve hardened it. Access controls, encryption, authentication, and monitoring are additional hardening techniques.

* Protect the SFTP server behind your corporate firewall, and only expose a proxy tier through your firewall as a DMZ against unauthorized access.

#### File Transfer Protocol and Compliance

If you handle personally identifiable information (PII), protected health information (PHI), financial data, and some categories of regulated federal data like controlled unclassified information (CUI), you have to comply with set standards of file transfers. Regulatory compliance should not be taken lightly; noncompliance can be costly and damaging to business reputation.

##### File Transfer Protocol for Healthcare

HIPAA and HITECH demand that PHI and other healthcare records be encrypted before being shared with external parties like insurance providers and consulting physicians. If you are in the healthcare industry, MFT would be a no-brainer to demonstrate compliance since this file transfer standard supports end-to-end encryption.

##### File Transfer Protocol for Federal

The Federal Information Security Management Act (FISMA) requires federal agencies to develop, document, and implement an information security and protection program. It aims to reduce the security risk of federal information and data getting into the wrong hands.

##### File Transfer Protocol for Financial Services

The Gramm-Leach-Bliley Act (GLBA) places the obligation to protect sensitive PII on financial services institutions that generate, store, or share this data. GLBA requires financial services providers to protect sensitive information, which includes corporate financial records, individual account statements, insurance information, and much more. Financial services institutions must also inform their customers their wish to share their data with partners and give their customers the option to opt out of data-sharing.

##### File Transfer Protocol for Retail

The retail industry collects and stores customers’ PII and payment information, namely credit card data. The Payment Card Industry Data Security Standard (PCI DSS) mandates retailers to have encryption controls to protect this data which, if intercepted or mishandled, can lead to identity theft and fraud.

## Control-M Platform

### Sizing Requirements

* [Control-M MFT System Requirements](https://documents.bmc.com/supportu/9.0.21/en-US/Documentation/Control-M_Managed_File_Transfer_installation.htm#ControlMMFTSystemRequirements)
 
* [Control-M MFT Enterprise System Requirements](https://documents.bmc.com/supportu/9.0.21/en-US/Documentation/Control-M_MFT_Enterprise_B2B_installation.htm#ControlMMFTEnterpriseSystemRequirements)

### System Tuning & Security

??? Tip "Log Files: Agent"

    | Path (relative to Agent home) | File Name/Pattern | Description | Is Rolling file | Default retention |
    |------------------------------|------------------|-------------|-----------------|-------------------|
    | /proclog | ctmmft.log ctmmft<n>.log | Diagnostic log for the MFT Client (the java process that runs the jobs and communicates with the agent) | Yes. By default: 20 files of up to 50MB | 1-7 days (depending on the Agent version) |
    | /proclog | ctmhub.log ctmhub<n>.log | Diagnostic log for the MFT Server (FTS for MFT, Hub for MFTE) | Yes. By default: 5 files of up to 10MB | |
    | /proclog | ctmhub_boot.log ctmhub_boot<n>.log | Initialization/boot log for the MFT Server (spring-boot framework initialization) | Yes. By default: 5 files of up to 10MB | |
    | /proclog | mftclient-YYYY-MM-DD.log | Standard output of the MFT client (usually included startup/shutdown details) | No (new file per execution day) | |
    | /proclog | mfthub-YYYY-MM-DD.log | Standard output of the MFT Server (usually included startup/shutdown details) | No (new file per execution day) | |
    | /proclog | zookeeper-YYYY-MM-DD.log | Standard output of the MFT ZooKeeper server, relevant in MFTE only (usually included startup/shutdown details) | No (new file per execution day) | |
    | /proclog | cmupdate_<PID>.log | Diagnostic log for the cmupdate utility, which is executed every few seconds to publish FTS status and File Transfer events | No (file per execution) | |
    | /proclog | fts_access_log.csv fts_access_log.YYYYMMDD.csv | Daily Access log for the FTS when internal users login/logout | No. Daily file | |
    | /measure | ctmmft_agent_request_metrics.csv ctmmft_agent_request_metrics_YYYYMMDD.csv | Daily performance log containing the time spent in the MFT client for all requests that arrived from the Control-M Agent. These requests include different categories: - SYSTEM – General requests (e.g.: Shutdown MFT container) - AGENT – Job-related requests (e.g.: Submit Job, Track Job, Kill Job, Job Statistics, Job Output) - ADMIN – Administrator requests from CCM/Web Config (e.g.: Local Connection Profile operations, PGP templates, Settings, MFTE admin operations like add user, delete folder etc.) - USER – User requests from the WLA/Web job definition in Planning/Monitoring domains (e.g.: List Directory Content when browsing file, List Buckets) | No. Daily file | 30 days by default |
    | /measure | ctmmft_metrics_client.csv ctmmft_metrics_client_YYYYMMDD.csv | Daily metrics file for the MFT Client, sampling the following metrics such as: - CPU usage - Memory consumption - # of active threads - # of running jobs - # of FT events that are stored in the H2 database (aft_events.mv.db) - # of FT events that were sent since last sampling The sampling interval is 5 minutes (configurable) | No. Daily file | |
    | /measure | ctmmft_metrics_hub.csv ctmmft_metrics_hub_YYYYMMDD.csv | Daily metrics file for the MFT Server (FTS/Hub), sampling the following metrics such as: - CPU usage - Memory consumption - # of active threads - # of open sessions for each protocol (SFTP, FTPS, HTTPS) - # of sessions that were opened since last sampling for each protocol (SFTP, FTPS, HTTPS) - Peak # of sessions that were opened since last sampling for each protocol (SFTP, FTPS, HTTPS) - # of events (file uploads and/or Audit events) that are stored in the H2 database (hub_events.mv.db) - # of events that were sent since last sampling The sampling interval is 5 minutes (configurable) | No. Daily file | |

??? Tip "Log Files: Gateway"
    | Path (relative to gateway home) | File Name/Pattern | Description | Is Rolling file | Retention |
    |---------------------------------|-------------------|-------------|-----------------|-----------|
    | /mft-proxy/logs | mft-proxy.log mft-proxy<n>.log | Diagnostic log for the MFT Gateway | Yes. By default: 5 files of up to 10MB | |
    | /mft-proxy/logs | mft-proxy-boot.log | Initialization/boot log for the MFT Gateway (spring-boot framework initialization) | Yes. By default: 5 files of up to 10MB | |
    | /mft-proxy/logs | mft-proxy-start-stop.log | Standard output of the MFT Gateway start/stop command | No | |
    | /mft-proxy/logs | access_log.YYYY-MM-DD.log | Web Server (HTTPS) log for traffic passing through the gateway | No. Daily file | 5 days by default |
    | /mft-proxy/logs | ctmmft_metrics_gateway.csv ctmmft_metrics_gateway_YYYYMMDD.csv | Daily metrics file for the MFT Gateway, sampling the following metrics such as: - CPU usage - Memory consumption - # of active threads - # of open sessions for each protocol (SFTP, FTPS, HTTPS) - # of sessions that were opened since last sampling for each protocol (SFTP, FTPS, HTTPS) - Peak # of sessions that were opened since last sampling for each protocol (SFTP, FTPS, HTTPS) The sampling interval is 5 minutes (configurable) | No. Daily file | |

#### Danger Zone

??? Danger "System Parameters"

    | Parameter                       | Description                                                                                                         | Valid Values                                  | Default    |
    |---------------------------------|---------------------------------------------------------------------------------------------------------------------|-----------------------------------------------|------------|
    | MFTDefaultSearchDayRange (gsr)  | Default number of days to search for file transfer (FT) records, if time is not specified.                         | Valid values >= 1                            | 2          |
    | MFTRequesterThreadPoolSize (gsr)| Number of threads to handle MFT requests.                                                                          | Valid values >= 1                            | 2          |
    | MFTSearchLimit (gsr)            | Maximum number of results that are returned to the client for a search request.                                   | Valid values >= 1                            | 1000       |
    | MFTSearchMode (gsr)             | The MFT search is done in the database or in the search cache.                                                     | Valid values: SQL, CACHE                     | CACHE      |
    | MFTCacheUpdateMinGapMilli (gsr) | The Minimal number of milliseconds before search cache is updated.                                                | Valid values >= 0                            | 5000 (5s)  |
    | MFTCacheUpdateIntervalSec (gsr) | The Number of seconds interval between search cache updates.                                                      | Valid values >= 10                           | 300        |
    | MFTCacheOldestEndMaxTime (gsr)  | The Oldest end time of file transfer to keep in the search cache in minutes prior to current time.                 | Valid values 2880-2890                       | 2881       |
    | MFTCacheMaximalRecords (gsr)    | The Maximal number of FT records to keep in the search cache.                                                      | Valid values 0-2000000000                    | 2500000    |
    | MFTMaxConSearches (gsr)         | The Maximal allowed concurrent SQL searches.                                                                      | Valid values 5-2000000000                    | 50         |
    | MFTDaysToKeep (general)         | The Maximal number of days to keep File Transfer (FT) records in the MFT table in the database.                    |                                               | 30         |
    | MFTRecordsToKeep (general)      | The Maximal number of File Transfer (FT) records to keep in the MFT table in the database.                         |                                               | 7000000    |
    | MFTCleanupIntervalMin (general) | The interval in seconds between the deletion of historical records in MFT table.                                 | Default is 24 hours * 60 minutes * 60 seconds | 21600      |
    | MFTCleanupChunkMin (general)    | The maximum number of old File Transfer records to be deleted, each time a deletion is performed from MFT table. |                                               | 50000      |
    | GSATimeUserSessionLife (gsr)    | The time in seconds that a user session in GSA will be kept if it is inactive (didn't issue a request from GSA).   | Valid values 60                              | 3600       |
    | GSATimeUserManagerCleanup (gsr) | The interval in seconds of cleaning inactive users from GSA.                                                       |                                               | 600        |
    | MFTDashCacheMode (gsr)          | Type of Dashboard Cache                                                                                             | Valid values: 0, 1, 3                        | 1          |
    | MFTSearchTempTableSize (gsr)    | Size of Temporary table for Search                                                                                 | Valid values >= 1                            | 50000      |
    | EMJVMMaxHeapSize (general)      | Java memory size in MB, for all java servers and utilities.                                                         | Valid values >= 1                            | 124        |
    | EMJVMGSAMaxHeapSize (gsr)       | Java memory size for GSA, if 0 automatic calculate the needed size, according to the number of records in the MFT table. If >0, GSA Java memory size in MB. | Valid values >= 0  | 0          |
    | GSAMaxRerun (gsr)               | Number of retries GSR will try to start GSA server.                                                                 | Valid values >= 1                            | 5          |
    | GSARerunWait (gsr)              | Waiting time in GSR to the next series of attempts to start GSA server (sec).                                      | Valid values >= 100                          | 900        |
    | MFTAuthEnable (gsr)             | Enable or disable authorization in GSA. This parameter will be used for POCs, in case the user has authorization definitions that are not supported by MFT. In this case, the MFT won't work at all, and this is a backdoor, to allow a demo of MFT without authorizations. | Valid values: 1 – Enable Authorization, 0 – Disable Authorization (For demo only!) | 1 |
    | MFTActiveConnDurationIntervalSec (gsr) | If time in seconds between Fts, is smaller than this number, Connection (Source host-Destination host) is considered Active. The Active connection cache will be updated every MFTActiveConnDurationIntervalSec /3 seconds, or 1 second. | Valid values >= 1 | 30 |
    | MFTActiveConnDurationMode (gsr) | Active Connection (Source host-Destination host) Duration Mode: 0 - Duration is the max value of all Active File Transfers (that did not end) according to the duration value of the FTs. 1 - Duration is calculated according to the GSA current time and the Start Time of the active FTs. 2 - The time since the connection was established, e.g. first transfer appeared. Duration is calculated according to the GSA current time and the first FT start time. There is a 30 seconds (set by parameter MFTActiveConnDurationIntervalSec) buffer before closing a connection. If there is a new FT that starts during the buffer, the connection will be considered open, and its duration will be from the first FT start time. | Valid values: 0, 1, 2 | 2 |
    | MFTActiveConnDurationMinSec (gsr) | Minimum duration seconds to return in the Active Connection Dashboard. By default, if the Active Connection is open for less than 1 second, do not show it. | Valid values >= 0 | 1 |
    | MFTActiveConnChunkSize (gsr) | The Chunk size that will be used to read all the FT records


??? Danger "System Security"

    The following table lists the available options you can use to secure and encrypt connections in Control-M MFT:

    === "PGP encryption"

        - For push or pull actions (where the File Transfer job initiates a connection to a remote server directly and uploads or downloads a file), you can use PGP templates in File Transfer jobs to encrypt a file before uploading to a remote server or decrypt it after downloading to a local host. For more information, see PGP Template Management.  

        - NOTE: BMC does not provide the PGP utility. You must install it separately.  
        
        - For incoming files from external partners (where they initiate the connection to the Control-M MFT Enterprise Gateway and upload an encrypted file to the Hub), you can either use processing rules or File Watcher jobs to decrypt. For more information, see Creating an MFT Enterprise Post Processing Rule. 
        
        - Defines a rule with the condition files from a specific partner that has a PGP extension and that runs a script that decrypts them so that they are decrypted in the Hub's file system.  
        
        - Defines a file watcher job that watches the specific folder, downloads the file locally, and decrypts it. This can be followed by another job that sends the decrypted file to an application that can process it. 
    
    === "SFTP (SSH) MFT Client"
    
        - Uses libraries that depend on JCE.  
        
        - Generates a key pair (RSA or ECDSA type).  
        
        - The private/public keys are stored in a local file system, with read-write permission only on the Agent account.  
        
        - The public key must be stored in the authorized_keys file of a remote SSH server.  
        
        - File Transfer jobs support both password and key authentication.  
        
        - Fingerprints of remote servers (hostkeys) are stored in the known_hosts local file to allow verification of the remote host after connection.  
        
        - By default, the first connection is accepted, and future connections are blocked when the host key changes. This behavior can be changed.  
        
        ** Supported Algorithms**
        
        - Cipher: blowfish-cbc, 3des-cbc, aes128-cbc, aes192-cbc, aes256-cbc, aes128-ctr, aes192-ctr, aes256-ctr, arcfour, arcfour128, arcfour256, aes128-gcm@openssh.com, aes256-gcm@openssh.com, and rijndael-cbc@lysator.liu.se.  
        
        - Key Exchange: diffie-hellman-group-exchange-sha1, diffie-hellman-group1-sha1, diffie-hellman-group14-sha1, diffie-hellman-group-exchange-sha256, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521, diffie-hellman-group14-sha256, diffie-hellman-group15-sha512, diffie-hellman-group16-sha512, diffie-hellman-group17-sha512, diffie-hellman-group18-sha512, curve25519-sha256, curve25519-sha256@libssh.org, and curve448-sha512.  
        
        - MAC: hmac-md5, hmac-sha1, hmac-md5-96, hmac-sha1-96, hmac-sha2-256, hmac-sha2-512, hmac-md5-etm@openssh.com, hmac-md5-96-etm@openssh.com, hmac-sha1-etm@openssh.com, hmac-sha1-96-etm@openssh.com, hmac-sha2-512-etm@openssh.com, and hmac-sha2-256-etm@openssh.com  
        
        - Host Key Type: ssh-dss, ssh-rsa, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, ssh-ed25519*: Supported only if the Java version is 15 or higher.  - rsa-sha2-512, rsa-sha2-256, ssh-ed448*: Supported only if the Java version is 15 or higher.  
    
    === "SFTP (SSH) MFT Server"

        - FTS/Hub accepts clients with both password and/or key authentication.  
        
        - FTS/Hub also has an authorized_keys file where the Administrator can add other user keys for remote users to connect.  
        
        - Supported SSH key Types: ssh-rsa, ecdsa-sha2-nistp256, ecdsa-sha2-nistp384, ecdsa-sha2-nistp521, and ssh-ed25519.  
        
        **Supported Algorithms**
        
        - Cipher: aes128cbc, aes128ctr, aes192cbc, aes192ctr, aes256cbc, aes256ctr, arcfour128, arcfour256, blowfishcbc, tripledescbc, aes128-gcm@openssh.com, aes256-gcm@openssh.com, chacha20-poly1305@openssh.com  
        
        - Key Exchange: diffie-hellman-group1-sha1, diffie-hellman-group-exchange-sha256, diffie-hellman-group14-sha1, diffie-hellman-group14-sha256, diffie-hellman-group15-sha512, diffie-hellman-group16-sha512, diffie-hellman-group17-sha512, diffie-hellman-group18-sha512, ecdh-sha2-nistp256, ecdh-sha2-nistp384, ecdh-sha2-nistp521, curve25519-sha256, curve25519-sha256@libssh.org, curve448-sha512  
        
        - MAC: hmac-md5, hmac-md5-96, hmac-sha1, hmac-sha1-96, hmac-sha2-256, hmac-sha2-512, hmac-sha1-etm@openssh.com, hmac-sha2-256-etm@openssh.com, and hmac-sha2-512-etm@openssh.com.
    
    === "SSL/TLS"

        - File Transfer jobs and FTS support FTP connection over SSL (FTPS).  
        
        - Hub supports HTTPS.  
        
        - SSL/TLS is supported in Encryption only, Server Authentication only, and Both Server and Client authentication.  
        
        - Supports TLS1.2 and TLS1.3.  
        
        - FTP Client supports both Explicit/Implicit SSL, CCC/CDC.  
        
        - Several keystore files for storing remote server CA x.509 certificates and a few keystores for the server to store its and clients certificates and keys (for different protocols: FTPS, HTTPS, AS2). Supports PKCS12 and BCFKS keystore formats.  
        
        - For FTPS, we support more than 70 different ciphers by default. On FIPS mode, some ciphers are disabled.

    === "Secured data in configurations"
        - MFT secure data is stored with AES256-GCM encryption (local key that can be rotated).  
        
        - Secure data is also transferred with AES256-GCM encryption.  
        
        - External user passwords are stored hashed (cannot be decrypted).  
        
        - Control-M components can communicate over SSL.|


??? Danger "Configuration Files"
    === "FTS"

        | Config Files    | Location | Purpose | 
        | :-------------  | :------- | :------ |
        | *.properties    | /opt/ctmag/ | TBD | 


    === "Hub"

        | Config Files    | Location | Purpose | 
        | :-------------  | :------- | :------ |
        | *.properties    | /opt/ctmag/ | TBD | 

    === "Gateway"

        | Config Files    | Location | Purpose | 
        | :-------------  | :------- | :------ |
        | *.properties    | /opt/ctmfte/ | TBD | 

### Authentication & Authorization

Limiting access based on different personas (Pre-Installation checklist, need help to contact services)

- Control-M Developer
- API Developer
- MFT Admin
- B2B Admin
- Business User
- Other users etc?
