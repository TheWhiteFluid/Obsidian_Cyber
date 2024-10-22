[Unrestricted File Upload](https://www.hackingarticles.in/comprehensive-guide-on-unrestricted-file-upload/)
[Remote File Inclusion (RFI)](https://www.hackingarticles.in/comprehensive-guide-to-remote-file-inclusion-rfi/)
[Local File Inclusion (LFI)](https://www.hackingarticles.in/comprehensive-guide-to-local-file-inclusion/)

https://portswigger.net/web-security/file-upload#what-are-file-upload-vulnerabilities

https://book.hacktricks.xyz/pentesting-web/file-upload

# **1. Remote code execution via web shell upload**
This lab contains a vulnerable image upload function. It doesn't perform any validation on the files users upload before storing them on the server's filesystem.
To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

1. While proxying traffic through Burp, log in to your account and notice the option for uploading an avatar image.
2. Upload an arbitrary image, then return to your account page. Notice that a preview of your avatar is now displayed on the page.
3. In Burp, go to **Proxy > HTTP history**. Click the filter bar to open the **HTTP history filter** window. Under **Filter by MIME type**, enable the **Images** checkbox, then apply your changes.
4. In the proxy history, notice that your image was fetched using a `GET` request to `/files/avatars/<YOUR-IMAGE>`. Send this request to Burp Repeater.
5. On your system, create a file called `exploit.php`, containing a script for fetching the contents of Carlos's secret file. For example:
    `<?php echo file_get_contents('/home/carlos/secret'); ?>`
6. Use the avatar upload function to upload your malicious PHP file. The message in the response confirms that this was uploaded successfully.
7. In Burp Repeater, change the path of the request to point to your PHP file:
    `GET /files/avatars/exploit.php HTTP/1.1`
8. Send the request. Notice that the server has executed your script and returned its output (Carlos's secret) in the response.

Analysis:

- POST -> upload image
- GET -> fetch image by the server (display)
![[Pasted image 20241022170425.png]]
![[Pasted image 20241022170441.png]]
![[Pasted image 20241022170457.png]]

- delete all the previous image content, change filename-->exploit.php and add the new exploit content (we could extract /etc/passwd)
![[Pasted image 20241022170552.png]]
- following the GET response pointing to our malicious file we see that our exploit is fetched .
![[Pasted image 20241022170646.png]]

# **2. Web shell upload via Content-Type restriction bypass**
This lab contains a vulnerable image upload function. It attempts to prevent users from uploading unexpected file types, but relies on checking user-controllable input to verify this.

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`

1. Log in and upload an image as your avatar, then go back to your account page.
2. In Burp, go to **Proxy > HTTP history** and notice that your image was fetched using a `GET` request to `/files/avatars/<YOUR-IMAGE>`. Send this request to Burp Repeater.
3. On your system, create a file called `exploit.php`, containing a script for fetching the contents of Carlos's secret. For example:
    `<?php echo file_get_contents('/home/carlos/secret'); ?>`
4. Attempt to upload this script as your avatar. The response indicates that you are only allowed to upload files with the MIME type `image/jpeg` or `image/png`.
5. In Burp, go back to the proxy history and find the `POST /my-account/avatar` request that was used to submit the file upload. Send this to Burp Repeater.
6. In Burp Repeater, go to the tab containing the `POST /my-account/avatar` request. In the part of the message body related to your file, change the specified `Content-Type` to `image/jpeg`.
7. Send the request. Observe that the response indicates that your file was successfully uploaded.
8. Switch to the other Repeater tab containing the `GET /files/avatars/<YOUR-IMAGE>` request. In the path, replace the name of your image file with `exploit.php` and send the request. Observe that Carlos's secret was returned in the response.
9. Submit the secret to solve the lab.

Analysis:
	![[Pasted image 20241022175941.png]]
	![[Pasted image 20241022175956.png]]
	![[Pasted image 20241022180009.png]]

![[Pasted image 20241022181134.png]]
![[Pasted image 20241022181258.png]]
![[Pasted image 20241022181459.png]]

# **3. Web shell upload via path traversal**

This lab contains a vulnerable image upload function. The server is configured to prevent execution of user-supplied files, but this restriction can be bypassed by exploiting a [secondary vulnerability](https://portswigger.net/web-security/file-path-traversal).

To solve the lab, upload a basic PHP web shell and use it to exfiltrate the contents of the file `/home/carlos/secret`. Submit this secret using the button provided in the lab banner.

You can log in to your own account using the following credentials: `wiener:peter`


1. Log in and upload an image as your avatar, then go back to your account page.
2. In Burp, go to **Proxy > HTTP history** and notice that your image was fetched using a `GET` request to `/files/avatars/<YOUR-IMAGE>`. Send this request to Burp Repeater.
3. On your system, create a file called `exploit.php`, containing a script for fetching the contents of Carlos's secret. For example:
    `<?php echo file_get_contents('/home/carlos/secret'); ?>`
4. Upload this script as your avatar. Notice that the website doesn't seem to prevent you from uploading PHP files.
5. In Burp Repeater, go to the tab containing the `GET /files/avatars/<YOUR-IMAGE>` request. In the path, replace the name of your image file with `exploit.php` and send the request. Observe that instead of executing the script and returning the output, the server has just returned the contents of the PHP file as plain text.
6. In Burp's proxy history, find the `POST /my-account/avatar` request that was used to submit the file upload and send it to Burp Repeater.
7. In Burp Repeater, go to the tab containing the `POST /my-account/avatar` request and find the part of the request body that relates to your PHP file. In the `Content-Disposition` header, change the `filename` to include a directory traversal sequence:
    `Content-Disposition: form-data; name="avatar"; filename="../exploit.php"`
8. Send the request. Notice that the response says `The file avatars/exploit.php has been uploaded.` This suggests that the server is stripping the directory traversal sequence from the file name.
9. Obfuscate the directory traversal sequence by URL encoding the forward slash (`/`) character, resulting in:
    `filename="..%2fexploit.php"`
10. Send the request and observe that the message now says `The file avatars/../exploit.php has been uploaded.` This indicates that the file name is being URL decoded by the server.
11. In the browser, go back to your account page.
12. In Burp's proxy history, find the `GET /files/avatars/..%2fexploit.php` request. Observe that Carlos's secret was returned in the response. This indicates that the file was uploaded to a higher directory in the filesystem hierarchy (`/files`), and subsequently executed by the server. Note that this means you can also request this file using `GET /files/exploit.php`.

Analysis:
