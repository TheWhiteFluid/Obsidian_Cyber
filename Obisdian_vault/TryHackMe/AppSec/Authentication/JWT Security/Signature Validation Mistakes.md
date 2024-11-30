The second common mistake with JWTs is not correctly verifying the signature. If the signature isn't correctly verified, a threat actor may be able to forge a valid JWT token to gain access to another user's account. Let's examine the common signature verification issues.

## Not Verifying the Signature
The first issue with signature validation is when there is no signature validation. If the server does not verify the signature of the JWT, then it is possible to modify the claims in the JWT to whatever you prefer them to be. While it is uncommon to find APIs where no signature validation is performed, signature validation may have been omitted from a single endpoint within the API. Depending on the sensitivity of the endpoint, this can have a significant business impact.

### Example1
Let's authenticate to the API:
```
curl -H 'Content-Type: application/json' -X POST -d '{ "username" : "user", "password" : "password2" }' http://10.10.66.238/api/v1.0/example2
```

Once authenticated, let's verify our user:
```
curl -H 'Authorization: Bearer {JWT Token}' http://10.10.66.238/api/v1.0/example2?username=user
```

However, let's try to verify our user without the signature, remove the third part of the JWT (leaving only the dot) and make the request again. You will see that the verification still works! This means that the signature is not being verified. Modify the admin claim in the payload to be `1` and try to verify as the admin user to retrieve your flag.
	![](Pasted%20image%2020241129192432.png)![](Pasted%20image%2020241129193332.png)![](Pasted%20image%2020241129193513.png)
	
### The Development Mistake
In the example, the signature is not being verified, as shown below:

```python
payload = jwt.decode(token, options={'verify_signature': False})
```

﻿While it is rare to see this on normal APIs, it often happens on server-to-server APIs. In cases where a threat actor has direct access to the backend server, JWTs can be forged.

### The Fix  
The JWT should always be verified or additional authentication factors, such as certificates, should be used for server-to-server communication. The JWT can be verified by providing the secret (or public key), as shown in the example below:

```python
payload = jwt.decode(token, self.secret, algorithms="HS256")
```

## Downgrading to None
Another common issue is a signature algorithm downgrade. JWTs support the `None` signing algorithm, which effectively means that no signature is used with the JWT. While this may sound silly, the idea behind this in the standard was for server-to-server communication, where the signature of the JWT was verified in an upstream process. Therefore, the second server would not be required to verify the signature. However, suppose the developers do not lock in the signature algorithm or, at the very least, deny the `None` algorithm. In that case, you can simply change the algorithm specified in your JWT as `None`, which would then cause the library used for signature verification to always return true, thus allowing you again to forge any claims within your token.

### Example2
