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
