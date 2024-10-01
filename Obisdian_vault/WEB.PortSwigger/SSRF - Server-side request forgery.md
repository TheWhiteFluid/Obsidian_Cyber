
## 1. Basic SSRF against the local server
This lab has a stock check feature which fetches data from an internal system.
To solve the lab, change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`

1. Browse to `/admin` and observe that you can't directly access the admin page.
2. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
3. Change the URL in the `stockApi` parameter to `http://localhost/admin`. This should display the administration interface.
4. Read the HTML to identify the URL to delete the target user, which is:
    `http://localhost/admin/delete?username=carlos
5. Submit this URL in the `stockApi` parameter, to deliver the [SSRF attack](https://portswigger.net/web-security/ssrf).


Analysis:
- we observe that we have an API parameter which does a request directly to the local server. In this case we will try to manipulate it in order to do request in our behalf.
![[Pasted image 20241001150727.png]]
![[Pasted image 20241001150837.png]]

- after sending the request we cant delete directly the accounts so we have to inspect the delete button in order to execute the request from the server side (not user)
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


1. ![[Pasted image 20241001175528.png]]

2. using the stock check functionality in order to scan the internal 192.168.0.x range for an admin interface on port 8080   ![[Pasted image 20241001175615.png]]
	![[Pasted image 20241001175639.png]]
	![[Pasted image 20241001175707.png]]

3. ![[Pasted image 20241001175814.png]]
	![[Pasted image 20241001175832.png]]

## **3. Blind SSRF with out-of-band detection**
This site uses analytics software which fetches the URL specified in the Referer header when a product page is loaded.
To solve the lab, use this functionality to cause an HTTP request to the public Burp Collaborator server.

1. Visit a product, intercept the request in Burp Suite, and send it to Burp Repeater.
2. Go to the Repeater tab. Select the Referer header, right-click and select "Insert Collaborator Payload" to replace the original domain with a Burp Collaborator generated domain. Send the request.
3. Go to the Collaborator tab, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again, since the server-side command is executed asynchronously.
4. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload.

Analysis:
-  The vulnerable parameter is the `Referer` header:

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

Analysis:
