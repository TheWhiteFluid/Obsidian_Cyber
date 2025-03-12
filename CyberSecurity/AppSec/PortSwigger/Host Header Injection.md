# Summary
HTTP Host header attacks exploit vulnerabilities in the way web applications handle the Host header. The Host header is designed to specify which website a client wants to access when multiple sites are hosted on the same server. Attackers can manipulate this header to confuse applications into:
- Disclosing sensitive information
- Bypassing security controls
- Poisoning cache entries
- Conducting server-side request forgery

## Common Vulnerability Patterns
- **Password Reset Poisoning**: Attackers manipulate Host headers during password reset workflows to redirect reset links to malicious domains, allowing them to steal tokens and reset victims' passwords.
- **Web Cache Poisoning**: By injecting malicious payloads into the Host header, attackers can poison cached responses that are then served to other users.
- **Routing-Based SSRF**: Host header manipulation can trick applications into sending requests to internal systems that should be inaccessible from the internet.
- **Classic Server-Side Vulnerabilities**: Host headers may be used unsafely in application logic, leading to SQL injection, server-side template injection, or other vulnerabilities.

## Testing methodologies
1. Supplying arbitrary Host headers to identify basic vulnerabilities
2. Testing alternative headers (X-Forwarded-Host, X-Host, etc.)
3. Using duplicate Host headers
4. Inserting line breaks into headers
5. Absolute URLs in requests
6. Adding port numbers to the Host value

## Prevention measures
- Protecting absolute URLs in HTTP responses
- Validating Host headers against a whitelist
- Deploying a reverse proxy to handle Host header validation
- Avoiding server-side reliance on the Host header for security decisions
- Using properly configured CDNs


# 1. Basic password reset poisoning
This lab is vulnerable to password reset poisoning. The user `carlos` will carelessly click on any links in emails that he receives. To solve the lab, log in to Carlos's account.

You can log in to your own account using the following credentials: `wiener:peter`. Any emails sent to this account can be read via the email client on the exploit server.

**Analysis**:
1. Go to the login page and notice the "Forgot your password?" functionality. Request a password reset for your own account. Go to the exploit server and open the email client. Observe that you have received an email containing a link to reset your password. Notice that the URL contains the query parameter `temp-forgot-password-token`.
2. Click the link and observe that you are prompted to enter a new password. Reset your password to whatever you want. In Burp, study the HTTP history. Notice that the `POST /forgot-password` request is used to trigger the password reset email. This contains the username whose password is being reset as a body parameter. Send this request to Burp Repeater.
3. In Burp Repeater, observe that you can change the Host header to an arbitrary value and still successfully trigger a password reset. Go back to the email server and look at the new email that you've received. Notice that the URL in the email contains your arbitrary Host header instead of the usual domain name.
4. Back in Burp Repeater, change the Host header to your exploit server's domain name (`YOUR-EXPLOIT-SERVER-ID.exploit-server.net`) and change the `username` parameter to `carlos`. Send the request. Go to your exploit server and open the access log. You will see a request for `GET /forgot-password` with the `temp-forgot-password-token` parameter containing Carlos's password reset token. Make a note of this token.
5. Go to your email client and copy the genuine password reset URL from your first email. Visit this URL in the browser, but replace your reset token with the one you obtained from the access log. Change Carlos's password to whatever you want, then log in as `carlos` to solve the lab.

**Workflow**:
1. Go to the exploit server and open the email client. Observe that you have received an email containing a link to reset your password. Notice that the URL contains the query parameter `temp-forgot-password-token`.
	![](Pasted%20image%2020250310180018.png)
	![](Pasted%20image%2020250310180248.png)
2. In Burp Repeater, observe that you can change the Host header to an arbitrary value and still successfully trigger a password reset. Go back to the email server and look at the new email that you've received. Notice that the URL in the email contains your arbitrary Host header instead of the usual domain name.
	![](Pasted%20image%2020250310181041.png)
	![](Pasted%20image%2020250310181152.png)
3.  Change the Host header to your exploit server's domain name (`YOUR-EXPLOIT-SERVER-ID.exploit-server.net`) and change the `username` parameter to `carlos`. Send the request. Go to your exploit server and open the access log. You will see a request for `GET /forgot-password` with the `temp-forgot-password-token` parameter containing Carlos's password reset token. 
	![](Pasted%20image%2020250310181419.png)
	![](Pasted%20image%2020250310181541.png)
4. Go to your email client and copy the genuine password reset URL from your first email. Visit this URL in the browser, but replace your reset token with the one you obtained from the access log. Change Carlos's password to whatever you want, then log in as `carlos`.
	![](Pasted%20image%2020250310182806.png)
	![](Pasted%20image%2020250310182844.png)


# 2. Host header authentication bypass
This lab makes an assumption about the privilege level of the user based on the HTTP Host header. To solve the lab, access the admin panel and delete the user `carlos`.

**Analysis**:
1. Send the `GET /` request that received a 200 response to Burp Repeater. Notice that you can change the Host header to an arbitrary value and still successfully access the home page. Browse to `/robots.txt` and observe that there is an admin panel at `/admin`.
2. Try and browse to `/admin`. You do not have access, but notice the error message, which reveals that the panel can be accessed by local users. Send the `GET /admin` request to Burp Repeater.
3. In Burp Repeater, change the Host header to `localhost` and send the request. Observe that you have now successfully accessed the admin panel, which provides the option to delete different users. Change the request line to `GET /admin/delete?username=carlos` and send the request to delete `carlos` to solve the lab.

**Workflow**:
1. . Send the `GET /` request that received a 200 response to Burp Repeater. Notice that you can change the Host header to an arbitrary value and still successfully access the home page. Browse to `/robots.txt` and observe that there is an admin panel at `/admin`
	![](Pasted%20image%2020250310183435.png)
	![](Pasted%20image%2020250310183548.png)
2. Try and browse to `/admin`. You do not have access, but notice the error message, which reveals that the panel can be accessed by local users. Send the `GET /admin` request to Burp Repeater. ![](Pasted%20image%2020250310183612.png)
3. Change the Host header to `localhost` and send the request. Observe that you have now successfully accessed the admin panel, which provides the option to delete different users. Change the request line to `GET /admin/delete?username=carlos` and send the request to delete `carlos` to solve the lab.
	![](Pasted%20image%2020250310183818.png)
	![](Pasted%20image%2020250310183908.png)
	![](Pasted%20image%2020250310184013.png)


# 3. Web cache poisoning via ambiguous requests
This lab is vulnerable to web cache poisoning due to discrepancies in how the cache and the back-end application handle ambiguous requests. An unsuspecting user regularly visits the site's home page.

To solve the lab, poison the cache so the home page executes `alert(document.cookie)` in the victim's browser.

**Analysis**:
1. In Burp's browser, open the lab and click **Home** to refresh the home page. In **Proxy > HTTP history**, right-click the `GET /` request and select **Send to Repeater**. In Repeater, study the lab's behavior. Notice that the website validates the Host header. If you modify the Host header, you can no longer access the home page.
2. In the original response, notice the verbose caching headers, which tell you when you get a cache hit and how old the cached response is. Add an arbitrary query parameter to your requests to serve as a cache buster, for example, `GET /?cb=123`. You can change this parameter each time you want a fresh response from the back-end server.
3. Notice that if you add a second Host header with an arbitrary value, this appears to be ignored when validating and routing your request. Crucially, notice that the arbitrary value of your second Host header is reflected in an absolute URL used to import a script from `/resources/js/tracking.js`.
4. Remove the second Host header and send the request again using the same cache buster. Notice that you still receive the same cached response containing your injected value.
5. Go to the exploit server and create a file at `/resources/js/tracking.js` containing the payload `alert(document.cookie)`. Store the exploit and copy the domain name for your exploit server. Back in Burp Repeater, add a second Host header containing your exploit server domain name. The request should look something like this:
    `GET /?cb=123 HTTP/1.1 Host: YOUR-LAB-ID.web-security-academy.net Host: YOUR-EXPLOIT-SERVER-ID.exploit-server.net`
6. Send the request a couple of times until you get a cache hit with your exploit server URL reflected in the response. To simulate the victim, request the page in the browser using the same cache buster in the URL. Make sure that the `alert()` fires. In Burp Repeater, remove any cache busters and keep replaying the request until you have re-poisoned the cache. The lab is solved when the victim visits the home page.

**Workflow**:
1. In Burp's browser, open the lab and click **Home** to refresh the home page. In **Proxy > HTTP history**, right-click the `GET /` request and select **Send to Repeater**. In Repeater, study the lab's behavior. Notice that the website validates the Host header. If you modify the Host header, you can no longer access the home page.
	![](Pasted%20image%2020250310191920.png)
2. In the original response, notice the verbose caching headers, which tell you when you get a cache hit and how old the cached response is. Add an arbitrary query parameter to your requests to serve as a cache buster, for example, `GET /?cb=123`. You can change this parameter each time you want a fresh response from the back-end server.
	![](Pasted%20image%2020250310192035.png)
	![](Pasted%20image%2020250310192138.png)
3. if you add a second Host header with an arbitrary value, this appears to be ignored when validating and routing your request. Crucially, notice that the arbitrary value of your second Host header is reflected in an absolute URL used to import a script from `/resources/js/tracking.js`.
	![](Pasted%20image%2020250310192852.png)
4.  Remove the second Host header and send the request again using the same cache buster. Notice that you still receive the same cached response containing your injected value.![](Pasted%20image%2020250310193029.png)
5. Go to the exploit server and create a file at `/resources/js/tracking.js` containing the payload `alert(document.cookie)`. Store the exploit and copy the domain name for your exploit server. Back in Burp Repeater, add a second Host header containing your exploit server domain name.
	![](Pasted%20image%2020250310193231.png)
	![](Pasted%20image%2020250310193943.png)


# 4. Routing-based SSRF
This lab is vulnerable to routing-based SSRF via the Host header. You can exploit this to access an insecure intranet admin panel located on an internal IP address.

To solve the lab, access the internal admin panel located in the `192.168.0.0/24` range, then delete the user `carlos`.

**Analysis**:
1. Send the `GET /` request that received a `200` response to Burp Repeater. In Burp Repeater, select the Host header value, right-click and select **Insert Collaborator payload** to replace it with a Collaborator domain name. Send the request.
2. Go to the Collaborator tab and click **Poll now**. You should see a couple of network interactions in the table, including an HTTP request. This confirms that you are able to make the website's middleware issue requests to an arbitrary server.
3. Send the `GET /` request to Burp Intruder. Go to **Intruder**. Deselect **Update Host header to match target**.Delete the value of the Host header and replace it with the following IP address, adding a payload position to the final octet:
    `Host: 192.168.0.§0§`. In the **Payloads** side panel, select the payload type **Numbers**. Under **Payload configuration**, enter the following values:
    `From: 0 To: 255 Step: 1`
5. Click  **Start attack**. A warning will inform you that the Host header does not match the specified target host. As we've done this deliberately, you can ignore this message. When the attack finishes, click the **Status** column to sort the results. Notice that a single request received a `302` response redirecting you to `/admin`. Send this request to Burp Repeater.
6. In Burp Repeater, change the request line to `GET /admin` and send the request. In the response, observe that you have successfully accessed the admin panel. Study the form for deleting users. Notice that it will generate a `POST` request to `/admin/delete` with both a CSRF token and `username` parameter. You need to manually craft an equivalent request to delete `carlos`.
7. Change the path in your request to `/admin/delete`. Copy the CSRF token from the displayed response and add it as a query parameter to your request. Also add a `username` parameter containing `carlos`. The request line should now look like this but with a different CSRF token:
    `GET /admin/delete?csrf=QCT5OmPeAAPnyTKyETt29LszLL7CbPop&username=carlos`
8. Copy the session cookie from the `Set-Cookie` header in the displayed response and add it to your request. Right-click on your request and select **Change request method**. Burp will convert it to a `POST` request. Send the request to delete `carlos` and solve the lab.

**Workflow**:
1. Send the `GET /` request that received a `200` response to Burp Repeater. In Burp Repeater, select the Host header value, right-click and select **Insert Collaborator payload** to replace it with a Collaborator domain name. Send the request.
	![](Pasted%20image%2020250311150907.png)
2. Send the `GET /` request to Burp Intruder. Go to **Intruder**. Deselect **Update Host header to match target**.Delete the value of the Host header and replace it with the following IP address, adding a payload position to the final octet:
    `Host: 192.168.0.§0§`
    ![](Pasted%20image%2020250311151006.png)
    ![](Pasted%20image%2020250311151043.png)
    ![](Pasted%20image%2020250311151511.png)
3. In Burp Repeater, change the request line to `GET /admin` and send the request. In the response, observe that you have successfully accessed the admin panel. Study the form for deleting users. Notice that it will generate a `POST` request to `/admin/delete` with both a CSRF token and `username` parameter. You need to manually craft an equivalent request to delete `carlos`.
	![](Pasted%20image%2020250311151643.png)
	![](Pasted%20image%2020250311151840.png)
4. Change the path in your request to `/admin/delete`. Copy the CSRF token from the displayed response and add it as a query parameter to your request. Also add a `username` parameter containing `carlos`. 
	![](Pasted%20image%2020250311151941.png)
5. Copy the session cookie from the `Set-Cookie` header in the displayed response and add it to your request. Right-click on your request and select **Change request method**. Burp will convert it to a `POST` request. Send the request to delete `carlos` and solve the lab.
	![](Pasted%20image%2020250311152231.png)


# 5. SSRF via flawed request parsing
This lab is vulnerable to routing-based SSRF due to its flawed parsing of the request's intended host. You can exploit this to access an insecure intranet admin panel located at an internal IP address.

To solve the lab, access the internal admin panel located in the `192.168.0.0/24` range, then delete the user `carlos`.

**Analysis:**
1. Send the `GET /` request that received a `200` response to Burp Repeater and study the lab's behavior. Observe that the website validates the Host header and blocks any requests in which it has been modified.
2. Observe that you can also access the home page by supplying an absolute URL in the request line as follows:
    `GET https://YOUR-LAB-ID.web-security-academy.net/`
3. Notice that when you do this, modifying the Host header no longer causes your request to be blocked. Instead, you receive a timeout error. This suggests that the absolute URL is being validated instead of the Host header.
4. Use Burp Collaborator to confirm that you can make the website's middleware issue requests to an arbitrary server in this way. For example, the following request will trigger an HTTP request to your Collaborator server:
    `GET https://YOUR-LAB-ID.web-security-academy.net/ Host: BURP-COLLABORATOR-SUBDOMAIN`
5. Right-click and select **Insert Collaborator payload** to insert a Burp Collaborator subdomain where indicated in the request. Send the request containing the absolute URL to Burp Intruder.
6. Go to **Intruder** and deselect **Update Host header to match target**. Use the Host header to scan the IP range `192.168.0.0/24` to identify the IP address of the admin interface. Send this request to Burp Repeater.
7. In Burp Repeater, append `/admin` to the absolute URL in the request line and send the request. Observe that you now have access to the admin panel, including a form for deleting users. Change the absolute URL in your request to point to `/admin/delete`. Copy the CSRF token from the displayed response and add it as a query parameter to your request. Also add a `username` parameter containing `carlos`. The request line should now look like this but with a different CSRF token:
    `GET https://YOUR-LAB-ID.web-security-academy.net/admin/delete?csrf=QCT5OmPeAAPnyTKyETt29LszLL7CbPop&username=carlos`
8. Copy the session cookie from the `Set-Cookie` header in the displayed response and add it to your request. Right-click on your request and select "Change request method". Burp will convert it to a `POST` request.

**Workflow**: