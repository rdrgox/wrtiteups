# anthem

Windows

## Enumeration

### Nmap

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.201.44.13 -oN allPorts.txt

PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server
```

```bash
nmap -sC -sV -p80,3389 -Pn 10.201.44.13 -oN target.txt                                                       

PORT     STATE SERVICE       VERSION
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
3389/tcp open  ms-wbt-server Microsoft Terminal Services
|_ssl-date: 2025-10-17T06:12:48+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=WIN-LU09299160F
| Not valid before: 2025-10-16T06:07:47
|_Not valid after:  2026-04-17T06:07:47
| rdp-ntlm-info: 
|   Target_Name: WIN-LU09299160F
|   NetBIOS_Domain_Name: WIN-LU09299160F
|   NetBIOS_Computer_Name: WIN-LU09299160F
|   DNS_Domain_Name: WIN-LU09299160F
|   DNS_Computer_Name: WIN-LU09299160F
|   Product_Version: 10.0.17763
|_  System_Time: 2025-10-17T06:11:31+00:00
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 96.63 seconds
```

### HTTP (80)

```bash
whatweb http://10.201.44.13   
http://10.201.44.13 [200 OK] Bootstrap, Country[RESERVED][ZZ], HTML5, IP[10.201.44.13], JQuery[1.11.0], Open-Graph-Protocol, OpenSearch[http://10.201.44.13/opensearch/1073], Script[text/javascript], Title[Anthem.com - Welcome to our blog], X-UA-Compatible[IE=edge]
```

![alt text](img/image.png)

```bash
gobuster dir -u http://10.201.44.13 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -x txt,php,js

===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.201.44.13
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Extensions:              js,txt,php
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/# license, visit http://creativecommons.org/licenses/by-sa/3.0/.js (Status: 400) [Size: 3420]
/# license, visit http://creativecommons.org/licenses/by-sa/3.0/.txt (Status: 400) [Size: 3420]
/# license, visit http://creativecommons.org/licenses/by-sa/3.0/ (Status: 400) [Size: 3420]
/search               (Status: 200) [Size: 3418]
/blog                 (Status: 200) [Size: 5394]
/# license, visit http://creativecommons.org/licenses/by-sa/3.0/.php (Status: 400) [Size: 3420]
/sitemap              (Status: 200) [Size: 1041]
/rss                  (Status: 200) [Size: 1868]
/archive              (Status: 301) [Size: 123] [--> /blog/]
/categories           (Status: 200) [Size: 3541]
/authors              (Status: 200) [Size: 4115]
/Search               (Status: 200) [Size: 3468]
/tags                 (Status: 200) [Size: 3594]
/install              (Status: 302) [Size: 126] [--> /umbraco/]
/RSS                  (Status: 200) [Size: 1868]
/Blog                 (Status: 200) [Size: 5394]
/SiteMap              (Status: 200) [Size: 1041]
/Archive              (Status: 301) [Size: 123] [--> /blog/]
/robots.txt           (Status: 200) [Size: 192]
/siteMap              (Status: 200) [Size: 1041]
/INSTALL              (Status: 302) [Size: 126] [--> /umbraco/]
/Sitemap              (Status: 200) [Size: 1041]
/1073                 (Status: 200) [Size: 5394]
/Rss                  (Status: 200) [Size: 1868]
/Categories           (Status: 200) [Size: 3541]
```

![alt text](img/image1.png)

![alt text](img/image2.png)

![alt text](img/image3.png)

![alt text](img/image4.png)

![alt text](img/image5.png)

![alt text](img/image6.png)

### RDP

```bash
xfreerdp /u:sg /p:'UmbracoIsTheBest!' /v:10.201.44.13 /cert-ignore /dynamic-resolution +clipboard
```

```shell
PS C:\Users\SG> whoami /all

USER INFORMATION
----------------

User Name          SID
================== ==============================================
win-lu09299160f\sg S-1-5-21-3886845925-2521176483-1368255183-1000


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Desktop Users           Alias            S-1-5-32-555 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\REMOTE INTERACTIVE LOGON  Well-known group S-1-5-14     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== ========
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled
```

![alt text](img/image7.png)

![alt text](img/image8.png)

```bash
xfreerdp /u:Administrator /p:'ChangeMeBaby1MoreTime' /v:10.201.44.13 /cert-ignore /dynamic-resolution +clipboard
```

![alt text](img/image9.png)