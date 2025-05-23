SSRF stands for Server-Side Request Forgery. It's a vulnerability that allows a malicious user to cause the webserver to make an additional or edited HTTP request to the resource of the attacker's choosing.

There are two types of SSRF vulnerability:
- regular SSRF where data is returned to the attacker's screen. 
- blind SSRF vulnerability where an SSRF occurs, but no information is returned to the attacker's screen.

A successful SSRF attack can result in any of the following: 
- Access to unauthorized areas.
- Access to customer/organizational data.
- Ability to Scale to internal networks.
- Reveal authentication tokens/credentials.

**Example:**
We have the following URL: `https://website.thm/item/2?server=api`. [(1)]
We want to construct our payload in order to force the webserver to return data from `https://server.website.thm/flag?id=9`. [(2)]

The payload will be `https://website.thm/item/2?server=server.website.thm/flag?id=9&x` [(1)+(2)]. Notice the `&x` at the end of the payload thus this method ensure the URL remains properly formatted. Adding `&x` at the end of an SSRF payload can be a technique to ensure the URL format is preserved, bypass validation mechanisms, or manipulate the server's request handling. 

Potential SSRF vulnerabilities can be spotted in web applications in many different ways. Here is an example of four common places to look:
![[Pasted image 20240602195526.png]]
![[Pasted image 20240602195609.png]]

## ==Deny List==
A Deny List is where all requests are accepted apart from resources specified in a list or matching a particular pattern. A Web Application may employ a deny list to protect sensitive endpoints, IP addresses or domains from being accessed by the public while still allowing access to other locations. A specific endpoint to restrict access is the localhost, which may contain server performance data or further sensitive information, so domain names such as localhost and `127.0.0.1` would appear on a deny list. Attackers can bypass a Deny List by using alternative localhost references such as` 0`, `0.0.0.0`, `0000`, `127.1`, `127.*.*.*`, `2130706433`, `017700000001` or subdomains that have a DNS record which resolves to the IP address `127.0.0.1` such as `127.0.0.1.nip.io`.
  
Also, in a cloud environment, it would be beneficial to block access to the IP address `169.254.169.254`, which contains metadata for the deployed cloud server, including possibly sensitive information. An attacker can bypass this by registering a subdomain on their own domain with a DNS record that points to the IP Address `169.254.169.254`.

## ==Allow List==
An allow list is where all requests get denied unless they appear on a list or match a particular pattern, such as a rule that an URL used in a parameter must begin with `https://website.thm`. An attacker could quickly circumvent this rule by creating a subdomain on an attacker's domain name, such as ``https://website.thm.attackers-domain.thm``. The application logic would now allow this input and let an attacker control the internal HTTP request.

## ==Open Redirect==
If the above bypasses do not work, there is one more trick up the attacker's sleeve, the open redirect. An open redirect is an endpoint on the server where the website visitor gets automatically redirected to another website address. Take, for example, the link `https://website.thm/link?url=https://tryhackme.com`. This endpoint was created to record the number of times visitors have clicked on this link for advertising/marketing purposes. But imagine there was a potential SSRF vulnerability with stringent rules which only allowed URLs beginning with `https://website.thm/`. An attacker could utilize the above feature to redirect the internal HTTP request to a domain of the attacker's choice.

