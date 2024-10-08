https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection

Example of a template where user input is reflected (could be website form template/ email templates etc...)
	![[Pasted image 20241008200755.png]]

- Once we have identified the reflection of our user-controlled input --> enumerate the templating engine(by trying different payloads in order to be validated) -->  specific template documentation research for injection methodologies.

	![[Pasted image 20241008200509.png]]

		![[Pasted image 20241008201457.png]]
## 1.  Basic server-side template injection

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

	![[Pasted image 20241008202239.png]]
- send request to intruder --> fuzzing with a specific list of payloads --> we have discovered that template used is ERB(Ruby) by our payload confirmation
	![[Pasted image 20241008202635.png]]
- using ruby documentation (hacktricks/SSTI) inject desired commands
	![[Pasted image 20241008203010.png]]