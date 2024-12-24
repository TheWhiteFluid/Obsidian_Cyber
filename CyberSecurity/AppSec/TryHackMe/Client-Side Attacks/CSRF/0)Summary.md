CSRF is a type of security vulnerability where an attacker tricks a user's web browser into performing an unwanted action on a trusted site where the user is authenticated. This is achieved by exploiting the fact that the browser includes any relevant cookies (credentials) automatically, allowing the attacker to forge and submit unauthorised requests on behalf of the user (through the browser). The attacker's website may contain HTML forms or JavaScript code that is intended to send queries to the targeted web application.

A CSRF attack has **three** essential phases:
- The attacker already knows the format of the web application's requests to carry out a particular task and sends a malicious link to the user.
- The victim's identity on the website is verified, typically by cookies transmitted automatically with each domain request and clicks on the link shared by the attacker. This interaction could be a click, mouse over, or any other action.
- Insufficient security measures prevent the web application from distinguishing between authentic user requests and those that have been falsified.	![](Pasted%20image%2020241224131423.png)

## Effects
Understanding CSRF's impact is crucial for keeping online activities secure. Although CSRF attacks don't directly expose user data, they can still cause harm by changing passwords and email addresses or making financial transactions. The risks associated with CSRF include:

- **Unauthorised Access**: Attackers can access and control a user's actions, putting them at risk of losing money, damaging their reputation, and facing legal consequences.
- **Exploiting Trust**: CSRF exploits the trust websites put in their users, undermining the sense of security in online browsing.
- **Stealthy Exploitation**: CSRF works quietly, using standard browser behaviour without needing advanced malware. Users might be unaware of the attack, making them susceptible to repeated exploitation.


## Types
### **Traditional CSRF**
Conventional CSRF attacks frequently concentrate on state-changing actions carried out by submitting forms. The victim is tricked into submitting a form without realising the associated data like cookies, URL parameters, etc. The victim's web browser sends an HTTP request to a web application form where the victim has already been authenticated. These forms are made to transfer money, modify account information, or alter an email address.
	![](Pasted%20image%2020241224131838.png)

The above diagram shows traditional CSRF examples in the following steps:
- The victim is already logged on to his bank website. The attackers create a crafted malicious link and email it to the victim.
- The victim opens the email in the same browser.
- Once clicked, the malicious link enables the auto-transfer of the amount from the victim's browser to the attacker's bank account.

### **XMLHttpRequest(asynchronous) CSRF**
An asynchronous CSRF exploitation occurs when operations are initiated without a complete page request-response cycle. This is typical of contemporary online apps that leverage asynchronous server communication (via **XMLHttpRequest** or the **Fetch** API) and JavaScript to produce more dynamic user interfaces. These attacks use asynchronous calls instead of the more conventional form submissions. Still, they exploit the same trust relationship between the user and the online service.

Consider an online email client, for instance, where users may change their email preferences without reloading the page. If this online application is CSRF-vulnerable, a hacker might create a fake asynchronous HTTP request, usually a POST request, and alter the victim's email preferences, forwarding all their correspondence to a malicious address.

The following is a simplified overview of the steps that an asynchronous CSRF attack could take:
- The victim opens a session saved in their browser's cookies and logs into the `mailbox.thm`.  
- The attacker entices the victim to open a malicious webpage with a script that can send queries to the `mailbox.thm`.  
- To modify the user's email forwarding preferences, the malicious script on the attacker's page makes an AJAX call to `mailbox.thm/api/updateEmail` (using XMLHttpRequest or Fetch).
- The `mailbox.thm` session cookie is included with the AJAX request in the victim's browser.
- After receiving the AJAX request, mailbox.thm evaluates it and modifies the victim's settings if no CSRF defences exist.

## **Flash-based CSRF**
The term "Flash-based CSRF" describes the technique of conducting a CSRF attack by taking advantage of flaws in Adobe Flash Player components. Internet applications with features like **interactive content, video streaming, and intricate animations** have been made possible with Flash. But over time, security flaws in Flash, particularly those that can be used to launch CSRF attacks, have become a major source of worry. As HTML5 technology advanced and security flaws multiplied, official support for Adobe Flash Player ceased on [December 31, 2020](https://www.adobe.com/products/flashplayer/end-of-life.html)![](Pasted%20image%2020241224132847.png)
Even though Flash is no longer supported, a talk about Flash-based cross-site request forgery threats is instructive, particularly for legacy systems that still rely on antiquated technologies. A **malicious Flash file (.swf)** posted on the attacker's website would typically send unauthorised requests to other websites to carry out Flash-based CSRF attacks.