## Links:
1) https://portswigger.net/web-security/cross-site-scripting
   a. https://portswigger.net/web-security/cross-site-scripting#reflected-cross-site-scripting
   b. https://portswigger.net/web-security/cross-site-scripting/stored
   c. https://portswigger.net/web-security/cross-site-scripting/dom-based
   
2) https://portswigger.net/web-security/cross-site-scripting/exploiting
	https://portswigger.net/web-security/cross-site-scripting/contexts
	
3) https://portswigger.net/web-security/cross-site-scripting/content-security-policy

4) https://portswigger.net/web-security/cross-site-scripting/dangling-markup

5) https://portswigger.net/web-security/cross-site-scripting/contexts/client-side-template-injection

6) https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

## Labs:

## 1. Stored XSS into HTML context with nothing encoded

<script>alert(1)</script>

## 2. DOM XSS in `document.write` sink using source `location.search`

String has been placed inside an `img src` attribute.
1. Breaking out of the `img` attribute by:
	`"><svg onload=alert(1)>`  ("> is closing the previous tag )

SVG tags can include scripting capabilities, such as JavaScript, through attributes like `onload`, `onclick`, etc. This means that an attacker can inject an SVG element with an `onload` attribute to execute malicious scripts. Some web applications may not properly sanitize or filter SVG elements. Since SVG is less commonly considered in input sanitization, attackers may exploit it to bypass security filters that would catch more common tags like `<script>`.

## 3. DOM XSS in `innerHTML` sink using source `location.search`

String has been placed inside an `img src` attribute. 
The value of the `src` attribute is invalid and throws an error. This triggers the `onerror` event handler, which then calls the `alert()` function. 
	<img src=0 onerror=alert(0)>
	
![[Pasted image 20240703015300.png]]

## 4. DOM XSS in jQuery anchor `href` attribute sink using `location.search` source

The vulnerability in the submit feedback page. It uses the jQuery library's `$` selector function to find an anchor element, and changes its `href` attribute using data from `location.search`.

Changing the query parameter `returnPath` to `/` followed by a random alphanumeric string we observe that our random string has been placed inside an a `href` attribute.

We will XSS by changing  `returnPath` to: 
```
javascript:alert(document.cookie)
```

![[Pasted image 20240703034210.png]]
![[Pasted image 20240703034106.png]]


## 5. Reflected XSS into attribute with angle brackets HTML-encoded

String has been reflected inside a quoted attribute `value` and we will use onmouseover='alert(0)'

` " onmouseover='alert(0)' `

![[Pasted image 20240703053618.png]]

## 6. Stored XSS into anchor href attribute with double quotes HTML-encoded

String has been reflected inside an anchor `href` attribute
![[Pasted image 20240713161951.png]]


## 7. Reflected XSS into a JavaScript string with angle brackets HTML encoded

String has been reflected inside a JavaScript string
![[Pasted image 20240713173758.png]]
![[Pasted image 20240713173710.png]]
## 8.

JavaScript extracts a `storeId` parameter from the `location.search` source. It then uses `document.write` to create a new option in the select element for the stock checker functionality.

Adding a `storeId` query parameter to the URL and enter a random alphanumeric string as its value we notice that the string is now listed as one of the options in the drop-down list.

` ?productId=1& storeId=paein </option></select><img src="0" onerror="alert(1)"

![[Pasted image 20240713181806.png]]

![[Pasted image 20240713182122.png]]

## 8. DOM XSS in AngularJS expression with angle brackets and double quotes HTML-encoded
