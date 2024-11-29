
A common cookie-based session management approach is using the server-side session to store several parameters. In PHP, for example, you can use `$SESSION['var']=data` to store a value associated with the user's session. These values are not exposed client-side and can therefore only be recovered server-side. However, with tokens, the claims are exposed as the entire JWT is sent client-side. If the same development practice is followed, sensitive information can be disclosed. Some examples are seen on real applications:

- Credential disclosure with the password hash, or even worse, the clear-text password being sent as a claim.
- Exposure of internal network information such as the private IP or hostname of the authentication server.

## **Practical Example 1**  
Let's take a look at a practical example. Let's authenticate to our API using the following cURL request:

Let's take a look at a practical example. Let's authenticate to our API using the following cURL request:

```
`curl -H 'Content-Type: application/json' -X POST -d '{ "username" : "user", "password" : "password1" }' http://10.10.210.48/api/v1.0/example1`  
```

This will provide you with a JWT token. Once recovered, decode the body of the JWT to uncover sensitive information. You can decode the body manually or use a website such as [JWT.io](https://jwt.io/) for this process.

**The Development Mistake**
In the example, sensitive information was added to the claim, as shown below:
```python
payload = {
    "username" : username,
    "password" : password,
    "admin" : 0,
    "flag" : "[redacted]"
}

access_token = jwt.encode(payload, self.secret, algorithm="HS256")
```

**The Fix**  
Values such as the password or flag should not be added as claims as the JWT will be sent client-side. Instead, these values should be securely stored server-side in the backend. When required, the username can be read from a verified JWT and used to lookup these values, as shown in the example below:
```python
payload = jwt.decode(token, self.secret, algorithms="HS256")

username = payload['username']
flag = self.db_lookup(username, "flag")
```

Let's take a look at a practical example. Let's authenticate to our API using the following cURL request:
```
curl -H 'Content-Type: application/json' -X POST -d '{ "username" : "user", "password" : "password1" }' http://10.10.66.238/api/v1.0/example1
```

![](Pasted%20image%2020241129190006.png)

Token decode using [JWT.io](https://jwt.io/)
	![](Pasted%20image%2020241129190210.png)