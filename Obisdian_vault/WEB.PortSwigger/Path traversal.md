https://www.hackingarticles.in/comprehensive-guide-on-path-traversal/
https://hacktricks.boitatech.com.br/pentesting-web/file-inclusion

# 1. File path traversal, simple case
This lab contains a [path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.
To solve the lab, retrieve the contents of the `/etc/passwd` file.

1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the `filename` parameter, giving it the value:
    `../../../etc/passwd`
3. Observe that the response contains the contents of the `/etc/passwd` file.

Analysis:
- inspecting image --> copy image link --> intercept burp http history
	![[Pasted image 20241013195741.png]]
	
- using dot-dot slash method until we get no errors 
	![[Pasted image 20241013202459.png]]

# 2. File path traversal, traversal sequences blocked with absolute path bypass
This lab contains a [path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.

The application blocks traversal sequences but treats the supplied filename as being relative to a default working directory.

1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the `filename` parameter, giving it the value `/etc/passwd`.
3. Observe that the response contains the contents of the `/etc/passwd` file.

Analysis:
