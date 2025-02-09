 XSS is a vulnerability that allows an attacker to inject malicious scripts into a web page viewed by another user. Consequently, they bypass the **Same-Origin Policy (SOP)**; SOP is a security mechanism implemented in modern web browsers to prevent a malicious script on one web page from obtaining access to sensitive data on another page. SOP defines origin based on the protocol, hostname, and port. Consequently, a malicious ad cannot access data or manipulate the page or its functionality on another origin, such as an online shop or bank page. XSS dodges SOP as it is executing from the same origin.

It is worth noting that different browsers process certain code snippets differently. In other words, one exploit code might work against Google Chrome but not against Mozilla Firefox or Safari.

## Types of XSS
- **Reflected XSS**: This attack relies on the user-controlled input reflected to the user. For instance, if you search for a particular term and the resulting page displays the term you searched for (**_reflected_**), the attacker would try to embed a malicious script within the search term.
- **Stored XSS**: This attack relies on the user input stored in the website’s database. For example, if users can write product reviews that are saved in a database (**_stored_**) and being displayed to other users, the attacker would try to insert a malicious script in their review so that it gets executed in the browsers of other users.
- **DOM-based XSS**: This attack exploits vulnerabilities within the Document Object Model (**DOM**) to manipulate existing page elements without needing to be reflected or stored on the server. This vulnerability is the least common among the three.

## Causes
**Insufficient input validation and sanitization**
	Web applications accept user data, e.g., via forms, and use this data in the dynamic generation of HTML pages. Consequently, malicious scripts can be embedded as part of the legitimate input and will eventually be executed by the browser unless adequately sanitized.

**Lack of output encoding**
	The user can use various characters to alter how a web browser processes and displays a web page. For the HTML part, it is critical to properly encode characters such as `<`, `>`, `"`, `'`, and `&` into their respective HTML encoding. For JavaScript, special attention should be given to escape `'`, `"`, and `\`. Failing to encode user-supplied data correctly is a leading cause of XSS vulnerabilities.

**Improper use of security headers**
	Various security headers can help mitigate XSS vulnerabilities. For example, Content Security Policy (CSP) mitigates XSS risks by defining which sources are trusted for executable scripts. A misconfigured CSP, such as overly permissive policies or the improper use of `unsafe-inline` or `unsafe-eval` directives, can make it easier for the attacker to execute their XSS payloads.

**Framework and language vulnerabilities**
	Some older web frameworks did not provide security mechanisms against XSS; others have unpatched XSS vulnerabilities. Modern web frameworks automatically escape XSS by design and promptly patch any discovered vulnerability

**Third-party libraries**
	Integrating third-party libraries in a web application can introduce XSS vulnerabilities; even if the core web application is not vulnerable.

## Implications
**Session hijacking**
	As XSS can be used to steal session cookies, attackers can take over the session and impersonate the victim if successful.

**Phishing and credential theft**
	Leveraging XSS, attackers can present a fake login prompt to the user. In one recent case, the browser’s page was partially hidden by a dialogue box requesting users to connect to their cryptocurrency wallet.

**Social engineering**
	Using XSS, an attacker can create a legitimate-looking pop-up or alert within a trusted website. This can trick users into clicking malicious links or visiting malicious websites.

**Content manipulation and defacement**
	In addition to phishing and social engineering, an attacker might use XSS to change the website for other purposes, such as inflicting damage on the company’s reputation.

**Data exfiltration**
	XSS can access and exfiltrate any information displayed on the user’s browser. This includes sensitive information such as personal data and financial information.

**Malware installation**
	A sophisticated attacker can use XSS to spread malware. In particular, it can deliver drive-by download attacks on the vulnerable website.