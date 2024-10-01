
## 1. Basic SSRF against the local server
This lab has a stock check feature which fetches data from an internal system.

To solve the lab, change the stock check URL to access the admin interface at `http://localhost/admin` and delete the user `carlos`

1. Browse to `/admin` and observe that you can't directly access the admin page.
2. Visit a product, click "Check stock", intercept the request in Burp Suite, and send it to Burp Repeater.
3. Change the URL in the `stockApi` parameter to `http://localhost/admin`. This should display the administration interface.
4. Read the HTML to identify the URL to delete the target user, which is:
    `http://localhost/admin/delete?username=carlos
    
5. Submit this URL in the `stockApi` parameter, to deliver the [SSRF attack](https://portswigger.net/web-security/ssrf).

- we observe that we have an API parameter which does a request directly to the local server. In this case we will try to manipulate it in order to do request in our behalf.
![[Pasted image 20241001150727.png]]
![[Pasted image 20241001150837.png]]

- after sending the request we cant delete directly the accounts so we have to inspect the delete button in order to execute the request from the server side (not user)
![[Pasted image 20241001150956.png]]
![[Pasted image 20241001151253.png]]

## **2.  Basic SSRF against another back-end system**
This lab has a stock check feature which fetches data from an internal system.
To solve the lab, use the stock check functionality to scan the internal `192.168.0.X` range for an admin interface on port 8080, then use it to delete the user `carlos`.