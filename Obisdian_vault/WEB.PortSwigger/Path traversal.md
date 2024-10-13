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
