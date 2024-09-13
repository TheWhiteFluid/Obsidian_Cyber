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

4) https://portswigger.net/web-security/cross-site-scripting/cheat-sheet



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
