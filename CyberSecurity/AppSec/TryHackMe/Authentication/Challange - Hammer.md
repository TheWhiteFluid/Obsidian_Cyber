- port scanning phase:
	nmap -sC -sV -p- {IP}![](Pasted%20image%2020241206130150.png)
	![](Pasted%20image%2020241206131016.png)

- inspect source page
	![](Pasted%20image%2020241206131028.png)

- dir enumeration phase
```
gobuster dir --url http://10.10.208.169:1337/hmr_ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt -p pattern.txt (hmr_{GOBUSTER})
```
![](Pasted%20image%2020241206145639.png)

- logs dir check
	![](Pasted%20image%2020241206145719.png)
	![](Pasted%20image%2020241206145732.png)
- email address found: tester@hammer.thm
	![](Pasted%20image%2020241206145934.png)
		![](Pasted%20image%2020241206150228.png)
- check for cookies (PHPSESSID: eevapv194ivfivf2ovtibf4vp9)
	![](Pasted%20image%2020241206174908.png)

- using burp for security code fuzz (OTP)
	![](Pasted%20image%2020241206151052.png)

- we have a Rate-Limit-Pending response header and we have to bypass it using 'X-Forwarded- For' request header spoofing our IP address
- let s generate a list of possible code combinations (0000-9999) using: 
  ```
  seq 0000 9999 >> codes.txt
  ```

- we will be using  `ffuf → X-Forwarded-For`
```
ffuf -w codes.txt -u "http://10.10.252.115:1337/reset_password.php" -X "POST" -d "recovery_code=FUZZ&s=60" -H "Cookie: PHPSESSID=7fk71t34qtmphh4s7ge6o7k07n" -H "X-Forwarded-For: FUZZ" -H "Content-Type: application/x-www-form-urlencoded" -fr "Invalid" -s 
```
![](Pasted%20image%2020241206181128.png)

- `**-w codes.txt**`: Specifies the wordlist (`codes.txt`) that will be used for fuzzing. This wordlist contains the payloads that will replace the `FUZZ` keyword in the command.
- `**-u "http://hammer.thm:1337/reset_password.php"**`: The URL of the target web application. This is where the fuzzing request will be sent.
- `**-X "POST"**`: Specifies the HTTP method to be used, which in this case is `POST`.
- `**-d "recovery_code=FUZZ&s=60"**`: The data being sent in the body of the POST request. The `FUZZ` keyword here will be replaced with each entry from `codes.txt` during the fuzzing process. It appears that the fuzzing is targeting the `recovery_code` parameter.
- `**-H "Cookie: PHPSESSID=datlnccflgrmhqc9d5pkb6b8a7"**`: Adds a custom header to the request, specifically a `Cookie` header with a session ID. This is likely needed to maintain a session with the web application.
- `**-H "X-Forwarded-For: FUZZ"**`: Adds another custom header, `X-Forwarded-For`, which is often used to identify the originating IP address of a client connecting to a web server. In this case, it's being fuzzed to see if the application behaves differently based on the IP address.
- `**-H "Content-Type: application/x-www-form-urlencoded"**`: Specifies the content type of the data being sent. This is typical for form submissions.
- `**-fr "Invalid"**`: Filters out responses that contain the string `"Invalid"`. This helps in identifying successful or interesting responses that differ from the common invalid ones.
- `**-s**`: Runs `ffuf` in silent mode, which reduces the amount of output to only essential information.

- we obtained following access code: 6707 and after resseting user password we are in
	![](Pasted%20image%2020241206182436.png)![](Pasted%20image%2020241206182553.png)
- we have found a key
	![](Pasted%20image%2020241206235920.png)
- running other command(high privileged ones) is not allowed so we have to bypass it 
	![](Pasted%20image%2020241207000646.png)
- lets decode the JWT token and try to elevate our privileges
	![](Pasted%20image%2020241207000939.png)

- since the key that we have found is stored on the web page --> location of the kid is : /var/www/html/188ade1.key
- we will modify our role in the payload (user --> admin)
- we will sign using the value that we found in 188ade1.key as a secret
	![](Pasted%20image%2020241207002042.png)![](Pasted%20image%2020241207002131.png)

- changing the authorization bearer token we escalated our privileges
	  ![](Pasted%20image%2020241207002820.png)