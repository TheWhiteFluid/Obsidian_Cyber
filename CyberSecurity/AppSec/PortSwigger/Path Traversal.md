- https://portswigger.net/web-security/file-path-traversal
- https://www.hackingarticles.in/comprehensive-guide-on-path-traversal/
- https://hacktricks.boitatech.com.br/pentesting-web/file-inclusion

# **1. File path traversal, simple case**
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

# **2. File path traversal, traversal sequences blocked with absolute path bypass**
This lab contains a [path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.

The application blocks traversal sequences but treats the supplied filename as being relative to a default working directory.

1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the `filename` parameter, giving it the value `/etc/passwd`.
3. Observe that the response contains the contents of the `/etc/passwd` file.

	![[Pasted image 20241013230749.png]]

Analysis:

- same as previous lab // this time using relative path instead of absolute
  `/etc/passwd`
	![[Pasted image 20241013230611.png]]

# **3. File path traversal, traversal sequences stripped non-recursively**
This lab contains a [path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.
The application strips path traversal sequences from the user-supplied filename before using it.

1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the `filename` parameter, giving it the value:
    `....//....//....//etc/passwd`
3. Observe that the response contains the contents of the `/etc/passwd` file.

Analysis:
- input is being stripped (simple ../ parameter is blocked) --> we obfuscate it using double `../`

# **4. File path traversal, traversal sequences stripped with superfluous URL-decode**
This lab contains a [path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.
The application blocks input containing path traversal sequences. It then performs a URL-decode of the input before using it.

1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the `filename` parameter, giving it the value:
    `..%252f..%252f..%252fetc/passwd`
3. Observe that the response contains the contents of the `/etc/passwd` file.

Analysis:
- if none of the above method is working, we will try to encode the relative path (once/twice)
	![[Pasted image 20241013233650.png]]
	![[Pasted image 20241013234033.png]]


# **5. File path traversal, validation of start of path**
This lab contains a [path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.
The application transmits the full file path via a request parameter, and validates that the supplied path starts with the expected folder.

1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the `filename` parameter, giving it the value:
    `/var/www/images/../../../etc/passwd`

Analysis:
- we have to move from out from the current directory until we reach root one
	![[Pasted image 20241014000248.png]]
		![[Pasted image 20241014000454.png]]
			![[Pasted image 20241014000523.png]]

# **6. File path traversal, validation of file extension with null byte bypass**
This lab contains a [path traversal](https://portswigger.net/web-security/file-path-traversal) vulnerability in the display of product images.
The application validates that the supplied filename ends with the expected file extension.

1. Use Burp Suite to intercept and modify a request that fetches a product image.
2. Modify the `filename` parameter, giving it the value:
    `../../../etc/passwd%00.png`

Analysis:

![[Pasted image 20241014001357.png]]
- using all the above mentioned methods we still get no such file error
	![[Pasted image 20241014001421.png]]

- we will use the null byte `%00` injection (null byte is serving as a separator) and we will keep the original existing file&extension (in our case `48.jpg`)
	![[Pasted image 20241014001833.png]]

