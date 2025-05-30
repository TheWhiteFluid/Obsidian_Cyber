## **Injection**/.Sql injection
This task will be focusing on injection vulnerabilities. Injection vulnerabilities are quite dangerous to a company as they can potentially cause downtime and/or loss of data. Identifying injection points within a web application is usually quite simple, as most of them will return an error. There are many types of injection attacks, some of them are:

| SQL Injection     | SQL Injection is when an attacker enters a malicious or malformed query to either retrieve or tamper data from a database. And in some cases, log into accounts.                                                                                                   |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Command Injection | Command Injection is when web applications take input or user-controlled data and run them as system commands. An attacker may tamper with this data to execute their own system commands. This can be seen in applications that perform misconfigured ping tests. |
| Email Injection   | Email injection is a security vulnerability that allows malicious users to send email messages without prior authorization by the email server. These occur when the attacker adds extra data to fields, which are not interpreted by the server correctly.        |
	![[Pasted image 20240908022109.png]]

![[Pasted image 20240908022120.png]]
```
' or 1=1--
```
Similar to what we did earlier, we will now log into Bender's account! Capture the login request again, but this time we will put: bender@juice-sh.op'-- as the email. 

![](https://i.imgur.com/1F1ufc3.png)
```
valid@email.com'--
```
Why don't we put the 1=1? Well, as the email address is valid (which will return true), we do not need to force it to be true. Thus we are able to use **'--** to bypass the login system. 

Note the **1=1** can be used when the email or username is not known or invalid.

## **Broken Authentication/.Brute force**
In this task, we will look at exploiting authentication through different flaws. When talking about flaws within authentication, we include mechanisms that are vulnerable to manipulation. These mechanisms, listed below, are what we will be exploiting. 
- Weak passwords in high privileged accounts;
- Forgotten password pages;

We have used SQL Injection to log into the Administrator account but we still don't know the password. Let's try a brute-force attack! We will once again capture a login request, but instead of sending it through the proxy, we will send it to Intruder.
	![[Pasted image 20240908025324.png]]
	Go to Positions and then select the **Clear §** button. In the password field place two § inside the quotes. To clarify, the § § is not two sperate inputs but rather Burp’s implementation of quotations e.g. “”. The request should look like the image below.	
	![[Pasted image 20240908025356.png]]

For the payload, we will be using the `best1050.txt` from Seclists. (Which can be installed via: **apt-get install seclists**). Once the file is loaded into Burp, start the attack. You will want to filter for the request by status:
	![[Pasted image 20240908025935.png]]
	![[Pasted image 20240908025951.png]]

## **Sensitive data exposure**
 A web application should store and transmit sensitive data safely and securely. But in some cases, the developer may not correctly protect their sensitive data, making it vulnerable.

Most of the time, data protection is not applied consistently across the web application making certain pages accessible to the public. Other times information is leaked to the public without the knowledge of the developer, making the web application vulnerable to an attack.
	![[Pasted image 20240908031427.png]]
	![[Pasted image 20240908031934.png]]

That it links to  [http://10.10.154.114](http://machine_ip/ftp/legal.md)[/ftp/legal.md](http://machine_ip/ftp/legal.md). Navigating to that **/ftp/** directory reveals that it is exposed to the public!


We will now go back to the ftp folder and try to download package.json.bak. But it seems we are met with a 403 which says that only .md and .pdf files can be downloaded.
	![[Pasted image 20240908032445.png]]

To get around this, we will use a character bypass called “Poison Null Byte”. A Poison Null Byte is actually a NULL terminator. By placing a NULL character in the string at a certain byte, the string will tell the server to terminate at that point, nulling the rest of the string.

A Poison Null Byte looks like this: %00, so we will encode this into a url encoded format. The Poison Null Byte will now look like this: %2500. Adding this and then a .md to the end will bypass the 403 error!
	![[Pasted image 20240908032557.png]]

## **Broken Acces Control**
Modern-day systems will allow for multiple users to have access to different pages. Administrators most commonly use an administration page to edit, add and remove different elements of a website. You might use these when you are building a website with programs such as Weebly or Wix.

When Broken Access Control exploits or bugs are found, it will be categorised into one of **two types**:

- **Horizontal** Privilege Escalation: Occurs when a user can perform an action or access data of another user with the **same** level of permissions.
- **Vertical** Privilege Escalation: Occurs when a user can perform an action or access data of another user with a higher level of permissions.

	![[Pasted image 20240908033517.png]]

We are then going to refresh the page and look for a javascript file for `main-es2015.js`
	![[Pasted image 20240908034221.png]]

Searching for the term "admin" will come across a couple of different words containing "admin" but the one we are looking for is "path: administration"
	![[Pasted image 20240908034340.png]]

This hints towards a page called “/#/administration” as can be seen by the about path a couple lines below, but going there while not logged in doesn’t work. As this is an Administrator page, it makes sense that we need to be in the Admin account in order to view it.

	A good way to stop users from accessing this is to only load parts of the application that need to be used by them. This stops sensitive information such as an admin page from been leaked or viewed.

**Q) View another user's shopping basket**
	Login to the Admin account and click on 'Your Basket'. Make sure Burp is running so you can capture the request!
	![[Pasted image 20240908162722.png]]

Now, we are going to change the number **1** after /basket/ to **2**. It will now show you the basket of UserID 2. You can do this for other UserIDs as well, provided that they have one.
	![[Pasted image 20240908162811.png]]
	![[Pasted image 20240908162815.png]]


## **Cross-site Scripting XSS**
XSS or Cross-site scripting is a vulnerability that allows attackers to run javascript in web applications. These are one of the most found bugs in web applications. Their complexity ranges from easy to extremely hard, as each web application parses the queries in a different way.

| DOM (Special)            | DOM XSS _(Document Object Model-based Cross-site Scripting)_ uses the HTML environment to execute malicious javascript. This type of attack commonly uses the _<script></script>_ HTML tag.                                       |
| ------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Persistent (Server-side) | Persistent XSS is javascript that is run when the server loads the page containing it. These can occur when the server does not sanitise the user data when it is **uploaded** to a page. These are commonly found on blog posts. |
| Reflected (Client-side)  | Reflected XSS is javascript that is run on the client-side end of the web application. These are most commonly found when the server doesn't sanitise **search** data.                                                            |

We are using **iframe** which is a common HTML element found in many web applications, there are others which also produce the same result. This type of XSS is also called XFS (Cross-Frame Scripting), is one of the most common forms of detecting XSS within web applications. Websites that allow the user to modify the iframe or other DOM elements will most likely be vulnerable to XSS.

It is common practice that the search bar will send a request to the server in which it will then send back the related information, but this is where the flaw lies. Without correct input sanitation, we are able to perform an XSS attack against the search bar.

```javascript
<iframe src="javascript:alert(`xss`)">
```

Inputting this into the **search bar** will trigger the alert.
	![[Pasted image 20240908164125.png]]
					![[Pasted image 20240908164132.png]]


 **Q) Perform a persistent XSS!**
	First, login to the **admin** account. We are going to navigate to the "**Last Login IP**" page for this attack.
	![[Pasted image 20240908164454.png]]

As it logs the 'last' login IP we will now logout so that it logs the 'new' IP. Make sure that Burp **intercept is on**, so it will catch the logout request. We will then head over to the Headers tab where we will add a new header:

| _True-Client-IP_ | ``` <iframe src="javascript:alert(`xss`)"> ``` |
| ---------------- | ---------------------------------------------- |
	![[Pasted image 20240908181809.png]]

**Why do we have to send this Header?**
The _True-Client-IP_  header is similar to the _X-Forwarded-For_ header, both tell the server or proxy what the IP of the client is. Due to there being no sanitation in the header we are able to perform an XSS attack.

**Q) Perform a reflected XSS!**
First, we are going to need to be on the right page to perform the reflected XSS! **Login** into the **admin account** and navigate to the 'Order History' page.
	![[Pasted image 20240908182020.png]]


