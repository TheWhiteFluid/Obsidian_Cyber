## File Extensions
 In the real world we wouldn't be able to see the code for this, but for this example, it will be included here:
```
<?php
    //Get the extension
    $extension = pathinfo($_FILES["fileToUpload"]["name"])["extension"];
    //Check the extension against the blacklist -- .php and .phtml
    switch($extension){
        case "php":
        case "phtml":
        case NULL:
            $uploadFail = True;
            break;
        default:
            $uploadFail = False;
    }
?>
```

In this instance, the code is looking for the last period (`.`) in the file name and uses that to confirm the extension, so that is what we'll be trying to bypass here. Other ways the code could be working include: searching for the first period in the file name, or splitting the file name at each period and checking to see if any blacklisted extensions show up.

We can see that the code is filtering out the `.php` and `.phtml` extensions, so if we want to upload a PHP script we're going to have to find another extension. We can try `.php3`, `.php4`, `.php5`, `.php7`, `.phps`, `.php-s`, `.pht` and `.phar`. Many of these bypass the filter (which only blocks`.php` and `.phtml`), but it appears that the server is configured not to recognize them as PHP files, as in the below example:
	![](Pasted%20image%2020241112010629.png)
*Note:*
	This is actually the default for Apache2 servers, at the time of writing; however, the sysadmin may have changed the default configuration (or the server may be out of date), so it's well worth trying.

Eventually we find that the `.phar` extension bypasses the filter -- and works -- thus giving us our shell:
	![](Pasted%20image%2020241112010707.png)

*Important:*
	After testing various methods to bypass the file upload filter, we discover that no common shell file extensions are both executable and allowed by the filter. This means we need to try a different approach. In a previous example, the PHP code used the `pathinfo()` function to extract the file extension from the uploaded filename. However, the filter might be implemented differently. For instance, if the filter only checks for the presence of ".jpg" within the filename rather than at the end, we could attempt to upload a file named `shell.jpg.php`. Since JPEG files are generally accepted, this technique might trick the filter by including ".jpg" in the filename, potentially bypassing the restriction and executing the PHP shell.

## Magic Numbers
Magic numbers are used as a more accurate identifier of files. The magic number of a file is a string of hex digits, and is always the very first thing in a file. Knowing this, it's possible to use magic numbers to validate file uploads, simply by reading those first few bytes and comparing them against either a whitelist or a blacklist. Bear in mind that this technique can be very effective against a PHP based webserver; however, it can sometimes fail against other types of webserver (hint hint).

Initially, uploading a basic `shell.php` file results in an error, but a standard JPEG file is accepted without issues. Knowing that JPEG files are allowed, we can attempt to bypass the filter by adding a JPEG "magic number" to our PHP shell file. The magic number is a unique hexadecimal sequence that identifies a file type. For JPEGs, one common magic number is `FF D8 FF DB`. By adding this sequence at the start of our `shell.php` file, we can disguise it as a JPEG. This trick might help the file pass the upload filter while still containing executable PHP code.

*Resource:*
https://en.wikipedia.org/wiki/List_of_file_signatures


Before we get started, let's use the Linux `file` command to check the file type of our shell:

![](https://i.imgur.com/2126EHS.png)  

As expected, the command tells us that the filetype is PHP. Keep this in mind as we proceed with the explanation.  

We can see that the magic number we've chosen is four bytes long`(FF D8 FF DB)`, so let's open up the reverse shell script and add four random characters on the first line. These characters do not matter, so for this example we'll just use four "A"s:
![](Pasted%20image%2020241112021937.png)

Save the file and exit. Next we're going to reopen the file in `hexeditor` (which comes by default on Kali), or any other tool which allows you to see and edit the shell as hex. In hexeditor the file looks like this:
	![](https://i.imgur.com/otIyN96.png)
Note the four bytes in the red box: they are all `41`, which is the hex code for a capital "A" -- exactly what we added at the top of the file previously.

Change this to the magic number we found earlier for JPEG files: `FF D8 FF DB`

![](https://i.imgur.com/2OlGKdQ.png)  

Now if we save and exit the file (Ctrl + x), we can use `file` once again, and see that we have successfully spoofed the filetype of our shell:![](https://i.imgur.com/ldyt88v.png)
![](Pasted%20image%2020241112023339.png)