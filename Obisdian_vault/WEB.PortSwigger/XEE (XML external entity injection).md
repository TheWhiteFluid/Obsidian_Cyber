## **1. Exploiting XXE using external entities to retrieve files**
This lab has a "Check stock" feature that parses XML input and returns any unexpected values in the response.
1. Visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
2. Insert the following external entity definition in between the XML declaration and the `stockCheck` element:
    `<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>`
3. Replace the `productId` number with a reference to the external entity: `&xxe;`. The response should contain "Invalid product ID:" followed by the contents of the `/etc/passwd` file.

step1:
![[Pasted image 20240925193628.png]]

step2:
![[Pasted image 20240925193654.png]]

step3:
![[Pasted image 20240925193806.png]]

- discovering where we can inject an XML entity and test for it :
![[Pasted image 20240925194015.png]]
- reference the entity as an internal one to prove the concept
	![[Pasted image 20240925194111.png]]

- proceed further using an external XML entity to abuse the system & reveal info
		![[Pasted image 20240925194143.png]]

## **2. Exploiting XXE to perform SSRF attacks**
This lab has a "Check stock" feature that parses XML input and returns any unexpected values in the response. The lab server is running a (simulated) EC2 metadata endpoint at the default URL, which is `http://169.254.169.254/`. This endpoint can be used to retrieve data about the instance, some of which might be sensitive. 
To solve the lab, exploit the [XXE](https://portswigger.net/web-security/xxe) vulnerability to perform an [SSRF attack](https://portswigger.net/web-security/ssrf) that obtains the server's IAM secret access key from the EC2 metadata endpoint.
