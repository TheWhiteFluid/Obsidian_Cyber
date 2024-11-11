Client-side filtering tends to be extremely easy to bypass, as it occurs entirely on a machine that _you_ control. When you have access to the code, it's very easy to alter it.

Let's take the reverse shell that we used before and rename it to be called "shell.jpg". As the MIME type (based on the file extension) automatically checks out, the Client-Side filter lets our payload through without complaining:

![](https://i.imgur.com/WNpruFM.png)

Once again we'll activate our Burpsuite intercept, then click "Upload" and catch the request:
	![](https://i.imgur.com/h2164Li.png)

Observe that the MIME type of our PHP shell is currently `image/jpeg`. We'll change this to `text/x-php`, and the file extension from `.jpg` to `.php`, then forward the request to the server:
![](https://i.imgur.com/sqmwssT.png)

Now, when we navigate to `http://demo.uploadvulns.thm/uploads/shell.php` having set up a netcat listener, we receive a connection from the shell!
	![](https://i.imgur.com/cUqNO2L.png)