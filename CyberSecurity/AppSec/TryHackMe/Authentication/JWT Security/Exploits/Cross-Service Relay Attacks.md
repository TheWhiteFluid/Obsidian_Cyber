## The Audience Claim
A **Cross-Service misconfiguration** happens when a JWT (JSON Web Token) meant for one application is accepted by another, allowing unauthorized access. To prevent this, JWTs use an **audience (`aud`) claim**, which specifies which service the token is valid for. If this claim isn’t properly enforced, attackers can reuse a token across different services, leading to a **Cross-Service Relay attack** and possible **privilege escalation**. The solution is to always validate the audience claim to ensure tokens are only accepted by their intended service.

- **What is the Audience Claim?**  
    The audience (`aud`) claim in a JWT specifies which application the token is meant for. In systems where one authentication server supports multiple applications, this claim helps ensure the token is used only for its intended app.
    
- **The Problem:**  
    If an application **doesn’t verify** the audience claim but still trusts the token (because its signature is valid), it can lead to mistakes. For example:
    - A user might have **admin privileges** on one app, and their JWT reflects this (`"admin": true`).
    - If they use the same JWT on another app that **fails to check the audience**, the second app might incorrectly give them admin access too.
    
- **Cross-Service Relay Attack:**  
    This happens when a user exploits the lack of audience verification to gain unauthorized privileges across different services. Essentially, they "relay" their token to another app where they shouldn’t have the same rights.
    
- **Solution:**  
    Each application must **enforce audience claim checks** to ensure the JWT is valid **only for its specific service**. This prevents tokens from being misused across apps.

	![](Screen%20Recording%202024-12-01%20at%201.20.39%20AM.mov)
### Example
For this last practical example, there are two API endpoints namely `example7_appA` and `example7_appB`. You can use the same GET request you made in the previous examples to recover the flag, but you will need to point it to these endpoints. Furthermore, for authentication, you now also have to include the `"application" : "appX"` data value in the login request made to `example7`. Use the following steps to perform the example:

1. Authenticate to `exa0mple7` using the following data segment: `'{ "username" : "user", "password" : "password7", "application" : "appA"}'`. You will notice that an audience claim is added, but that you are not an admin.  
2. Use this token in both the admin and user requests you make to `example7_appA` and `example7_appB`. You will notice that while appA accepts the token, you are not an admin, and appB does not accept the token as the audience is incorrect.
3. Authenticate to `example7` using the following data segment: `'{ "username" : "user", "password" : "password7", "application" : "appB"}'`. You will notice that an audience claim is added again and you are an admin this time.
4. Use this token again to verify yourself on both applications and see what happens.
	![](Pasted%20image%2020241201010804.png)![](Pasted%20image%2020241201011221.png)

### The Development Mistake
The key issue is that the audience claim is not being verified on appA. This can be either because audience claim verification has been turned off or the audience scope has been set too wide.  

### The Fix
The audience claim should be verified when the token is decoded. This can be done as shown in the example below:
```python
payload = jwt.decode(token, self.secret, audience=["appA"], algorithms="HS256")
```