Same-origin policy or SOP is a policy that instructs how web browsers interact between web pages. According to this policy, a script on one web page can access data on another only if both pages share the same origin. This "origin" is identified by combining the URI *scheme*, *hostname*, and *port number*. The image below shows what a URL looks like with all its features (it does not use all features in every request).
	![](Pasted%20image%2020250205180325.png)

## Examples of SOP
1. **Same domain, different port**: A script from `https://test.com:80` can access data from `https://test.com:80/about`, as both share the same protocol, domain, and port. However, it cannot access data from `https://test.com:8080` due to a different port.
2. **HTTP/HTTPS interaction**: A script running on `http://test.com` (non-secure HTTP) is not allowed to access resources on `https://test.com` (secure HTTPS), even though they share the same domain because the protocols are different.

## Common Misconceptions
1. **Scope of SOP**: It's commonly misunderstood that SOP only applies to scripts. In reality, it applies to all web page aspects, including embedded images, stylesheets, and frames, restricting how these resources interact based on their origins.
2. **SOP Restricts All Cross-Origin Interactions**: Another misconception is that SOP completely prevents all cross-origin interactions. While SOP does restrict specific interactions, modern web applications often leverage various techniques (like CORS, postMessage, etc.) to enable safe and controlled cross-origin communications.
3. **Same Domain Implies Same Origin**: People often think that if two URLs share the same domain, they are of the same origin. However, SOP also considers protocol and port, so two URLs with the same domain but different protocols or ports are considered different origins.