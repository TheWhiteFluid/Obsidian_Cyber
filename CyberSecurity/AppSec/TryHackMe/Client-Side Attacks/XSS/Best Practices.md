
## Context
The injected payload will most likely find its way within one of the following:
- Between HTML tags
- Within HTML tags
- Inside JavaScript

**HTML tags**
When XSS happens between HTML tags, the attacker can run `<script>alert(document.cookie)</script>`.

**Escape from HTML tags**
However, when the injection is within an HTML tag, we need to end the HTML tag to give the script a turn to load. Consequently, we might adapt our payload to `><script>alert(document.cookie)</script>` or `"><script>alert(document.cookie)</script>` or something similar that would fit in the context.

**Escape from JavaScript tags**
We might need to terminate the script to run the injected one if we can inject our XSS within an existing JavaScript. For instance, we can start with `</script>` to end the script and continue from there. If your code is within a JavaScript string, you can close the string with `'`, complete the command with a semicolon, execute your command, and comment out the rest of the line with `//`. You can try something like this `';alert(document.cookie)//`.

This example should give you some ideas to escape the context you start from. Generally speaking, being aware of the context where your XXS payload is executing is very important for the successful execution of the payload.

##  Evasion
Various repositories can be consulted to build your custom XSS payload. This gives you plenty of room for experimentation. One such list is the [XSS Payload List](https://github.com/payloadbox/xss-payload-list).

However, sometimes, there are filters blocking XSS payloads. If there is a limitation based on the payload length, then [Tiny XSS Payloads](https://github.com/terjanq/Tiny-XSS-Payloads) can be a great starting point to bypass length restrictions.

If XSS payloads are blocked based on specific blocklists, there are various tricks for evasion. For instance, a horizontal tab, a new line, or a carriage return can break up the payload and evade the detection engines.
- Horizontal tab (TAB) is `9` in hexadecimal representation
- New line (LF) is `A` in hexadecimal representation
- Carriage return (CR) is `D` in hexadecimal representation


Consequently, based on the [XSS Filter Evasion Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html), we can break up the payload. `<IMG SRC="javascript:alert('XSS');">` in various ways:

```javascript
<IMG SRC="jav&#x09;ascript:alert('XSS');">
<IMG SRC="jav&#x0A;ascript:alert('XSS');">
<IMG SRC="jav&#x0D;ascript:alert('XSS');">
```

*Note:*
	There are hundreds of evasion techniques; the choice would depend on the target security and require trial and error before achieving a successful outcome.