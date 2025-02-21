- https://portswigger.net/web-security/jwt
- https://book.hacktricks.wiki/en/pentesting-web/hacking-jwt-json-web-tokens.html

## Summary

JSON Web Tokens (JWTs) are a widely adopted standard for securely transmitting information between parties as a JSON object. They're commonly used in authentication, session management, and access control mechanisms. However, improper implementation or handling can introduce significant security vulnerabilities.

**JWT Structure and Purpose**
1. **Header**: Specifies the token type (JWT) and the signing algorithm used (e.g., HMAC, RSA).
2. **Payload**: Contains the claims or statements about an entity (typically, the user) and additional data.
3. **Signature**: Ensures the token's integrity by verifying that the content hasn't been tampered with.

**Common JWT Vulnerabilities**
- **Algorithm Confusion Attacks**: These occur when an attacker manipulates the token's header to change the signing algorithm, potentially allowing them to forge tokens. For example, switching from a robust algorithm like RSA to 'none' or a weak algorithm can trick the server into accepting an unsigned or improperly signed token.
 - **Weak HMAC Secrets**: If the server uses a weak secret key for HMAC signing, attackers can brute-force the key, modify the token's payload, and generate a valid signature, leading to unauthorized access or privilege escalation.
- **Acceptance of Unsigned Tokens**: Some servers may incorrectly accept tokens with the 'none' algorithm, which means no signature is provided. This flaw allows attackers to create tokens with arbitrary claims without any signature, effectively bypassing authentication.
- **Disclosure of Private Keys**: If a server inadvertently exposes its private keys, perhaps through misconfigured JSON Web Key Sets (JWKS), attackers can sign tokens with these keys, impersonate users, and gain unauthorized access.

**Preventive Measures**
- **Enforce Strong Signing Algorithms**: Configure servers to accept only robust algorithms (e.g., RS256) and reject insecure ones like 'none'.
- **Use Strong, Secure Secrets**: Ensure that HMAC secrets are complex and of sufficient length to withstand brute-force attacks.
- **Proper Key Management**: Safeguard private keys and ensure they're not exposed through headers or endpoints. Regularly rotate keys and use secure storage solutions.
- **Thorough Input Validation**: Validate all JWT components, including headers and payloads, to prevent injection attacks and ensure tokens conform to expected formats.


## 1. Unverified signature
This lab uses a JWT-based mechanism for handling sessions. Due to implementation flaws, the server doesn't verify the signature of any JWTs that it receives.

To solve the lab, modify your session token to gain access to the admin panel at `/admin`, then delete the user `carlos`. 
You can log in to your own account using the following credentials: `wiener:peter`

**Analysis:**
- **Log in** to your account in the lab.
- **Check JWT token** in Burp's **Proxy > HTTP history** after logging in.
- **Decode JWT** in the **Inspector panel** and note the `sub` claim (your username).
- **Send request to Burp Repeater**, modify the path to `/admin`, and check access restrictions.
- **Edit JWT payload**, changing `sub` from `wiener` to `administrator`, then apply changes.
- **Resend the request** to access the **admin panel** successfully.
- **Find and send the delete request** (`/admin/delete?username=carlos`) to solve the lab.

**Workflow:**
1. delete the signature to check it server verify it or not (in our case not)
2. decode the JWS and use cyberchef/jwt.io to modify the payload (wiener -> administrator)
	![](Pasted%20image%2020250219002122.png)
	![](Pasted%20image%2020250219002136.png)
3. acces the /admin endpoint and inject new crafted JWT and follow the response to acces admin panel
	![](Pasted%20image%2020250219002412.png)
	![](Pasted%20image%2020250219002445.png)
		![](Pasted%20image%2020250219002520.png)

## 2. Flawed signature verification
This lab uses a JWT-based mechanism for handling sessions. The server is insecurely configured to accept unsigned JWTs.

To solve the lab, modify your session token to gain access to the admin panel at `/admin`, then delete the user `carlos`. 
You can log in to your own account using the following credentials: `wiener:peter`

**Analysis:**
- **Log in** to your account in the lab.
- **Capture the JWT token** in Burp:
    - Go to **Proxy > HTTP history**
    - Locate the **GET /my-account** request
    - Identify the **JWT session cookie**
- **Decode the JWT**:
    - Double-click the payload to view the **sub claim (your username)**
    - Send the request to **Burp Repeater**
- **Attempt Admin Panel Access**:
    - Change the request path to **/admin** and send it
    - Observe that access is **denied** (only for "administrator" user)
- **Modify the JWT Payload**:
    - Change the `"sub"` value to **"administrator"**
    - Click **Apply changes**
- **Modify the JWT Header**:
    - Change `"alg": "HS256"` to `"alg": "none"`
    - Click **Apply changes**
- **Remove the JWT Signature**:
    - In the message editor, **delete the signature** (keep the trailing `.`)
- **Send the Request**:
    - Observe **successful access** to the admin panel
- **Delete the Target User**:
    - Find the **delete URL** in the response: `/admin/delete?username=carlos`

**Workflow:**

1. if we delete the signature we receive 302 instead of 200 response so we have to tamper also with the header of the JWT (`alg` parameter)
2. decode and tampering with the JWT --> `alg` set on ''**none**'' and change payload values:
	![](Pasted%20image%2020250219013518.png)
3. we have also to **delete the signature** after changing `alg`--> **none** value:
	![](Pasted%20image%2020250219014108.png)


## 3. Weak signing key
This lab uses a JWT-based mechanism for handling sessions. It uses an extremely weak secret key to both sign and verify tokens. This can be easily brute-forced using a [wordlist of common secrets](https://github.com/wallarm/jwt-secrets/blob/master/jwt.secrets.list).

To solve the lab, first brute-force the website's secret key. Once you've obtained this, use it to sign a modified session token that gives you access to the admin panel at `/admin`, then delete the user `carlos`.
You can log in to your own account using the following credentials: `wiener:peter`

Analysis:
- In Burp, load the JWT Editor extension from the BApp store.  
- In the lab, log in to your own account and send the post-login `GET /my-account` request to Burp Repeater.
- In Burp Repeater, change the path to `/admin` and send the request. Observe that the admin panel is only accessible when logged in as the `administrator` user.
- Copy the JWT and brute-force the secret. You can do this using hashcat as follows:

    `hashcat -a 0 -m 16500 <YOUR-JWT> /path/to/jwt.secrets.list`

**Workflow:**
1. get /admin page 
	![](Pasted%20image%2020250219022458.png)

2. send the JWT token to decoder(seems like a weak signature)
	![](Pasted%20image%2020250219022559.png)
3. bruteforce the signature using hashcat
    `hashcat -a 0 -m 16500 <JWT> /path/to/jwt.secrets.list` --> secret: secret1
4. tamper with the token and sign it with the secret
	![](Pasted%20image%2020250219023440.png)
	![](Pasted%20image%2020250219023945.png)


## 4. JWK header injection
This lab uses a JWT-based mechanism for handling sessions. The server supports the `jwk` parameter in the JWT header. This is sometimes used to embed the correct verification key directly in the token. However, it fails to check whether the provided key came from a trusted source.

To solve the lab, modify and sign a JWT that gives you access to the admin panel at `/admin`, then delete the user `carlos`.
You can log in to your own account using the following credentials: `wiener:peter`

**Analysis:**
According to the JWS specification, only the `alg` header parameter is mandatory. In practice, however, JWT headers (also known as JOSE headers) often contain several other parameters. The following ones are of particular interest to attackers.

- `jwk` (JSON Web Key) - Provides an embedded JSON object representing the key.
- `jku` (JSON Web Key Set URL) - Provides a URL from which servers can fetch a set of keys containing the correct key.
- `kid` (Key ID) - Provides an ID that servers can use to identify the correct key in cases where there are multiple keys to choose from. Depending on the format of the key, this may have a matching `kid` parameter.

As we can see, these user-controllable parameters each tell the recipient server which key to use when verifying the signature. In this section, you'll learn how to exploit these to inject modified JWTs signed using your own arbitrary key rather than the server's secret.

### Injecting self-signed JWTs via the jwk parameter

The JSON Web Signature (JWS) specification describes an optional `jwk` header parameter, which servers can use to embed their public key directly within the token itself in JWK format.

A JWK (JSON Web Key) is a standardized format for representing keys as a JSON object. You can see an example of this in the following JWT header:
```json
{
    "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
    "typ": "JWT",
    "alg": "RS256",
    "jwk": {
        "kty": "RSA",
        "e": "AQAB",
        "kid": "ed2Nf8sb-sD6ng0-scs5390g-fFD8sfxG",
        "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9m"
    }
}
```

Ideally, servers should only use a limited whitelist of public keys to verify JWT signatures. However, misconfigured servers sometimes use any key that's embedded in the `jwk` parameter.

You can exploit this behavior by signing a modified JWT using your own RSA private key, then embedding the matching public key in the `jwk` header.

Although you can manually add or modify the `jwk` parameter in Burp, the [JWT Editor extension](https://portswigger.net/bappstore/26aaa5ded2f74beea19e2ed8345a93dd) provides a useful feature to help you test for this vulnerability:
1. With the extension loaded, in Burp's main tab bar, go to the **JWT Editor Keys** tab.
2. [Generate a new RSA key.](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts#adding-a-jwt-signing-key)
3. Send a request containing a JWT to Burp Repeater.
4. In the message editor, switch to the extension-generated **JSON Web Token** tab and [modify](https://portswigger.net/burp/documentation/desktop/testing-workflow/session-management/jwts#editing-jwts) the token's payload however you like.
5. Click **Attack**, then select **Embedded JWK**. When prompted, select your newly generated RSA key.
6. Send the request to test how the server responds.


**Workflow:**
1. after tampering with the JWT payload(invalid signature error tho) we have to generate a new RSA key to sign it
	![](Pasted%20image%2020250219024828.png)
2. we will use JWT editor for that
	![](Pasted%20image%2020250219025217.png)
		![](Pasted%20image%2020250219025258.png)
	
3. tamper the token , sign it with the RSA generated key and attack(**embedded jwk**)
	![](Pasted%20image%2020250219030109.png)

4. after attack SEND the request to see the results 
	![](Pasted%20image%2020250219030603.png)
		![](Pasted%20image%2020250219030712.png)


## 5. JKU header injection
This lab uses a JWT-based mechanism for handling sessions. The server supports the `jku` parameter in the JWT header. However, it fails to check whether the provided URL belongs to a trusted domain before fetching the key.

To solve the lab, forge a JWT that gives you access to the admin panel at `/admin`, then delete the user `carlos`.
You can log in to your own account using the following credentials: `wiener:peter`

**Analysis:**
#### Generate and upload a malicious JWK Set

1. In Burp Repeater, change the path to `/admin` and send the request. Observe that the admin panel is only accessible when logged in as the `administrator` user.
2. Go to the **JWT Editor Keys** tab in Burp's main tab bar.
3. Click **New RSA Key**.
4. In the dialog, click **Generate** to automatically generate a new key pair, then click **OK** to save the key. Note that you don't need to select a key size as this will automatically be updated later.
5. In the browser, go to the exploit server.
6. Replace the contents of the **Body** section with an empty JWK Set as follows:
```
 {
    "keys": [

    ]
    }
```

7. Back on the **JWT Editor Keys** tab, right-click on the entry for the key that you just generated, then select **Copy Public Key as JWK**.
8. Paste the JWK into the `keys` array on the exploit server, then store the exploit. The result should look something like this:
```
{
    "keys": [
        {
            "kty": "RSA",
            "e": "AQAB",
            "kid": "893d8f0b-061f-42c2-a4aa-5056e12b8ae7",
            "n": "yy1wpYmffgXBxhAUJzHHocCuJolwDqql75ZWuCQ_cb33K2vh9mk6GPM9gNN4Y_qTVX67WhsN3JvaFYw"
        }
    ]
}
```

#### Modify and sign the JWT

1. Go back to the `GET /admin` request in Burp Repeater and switch to the extension-generated **JSON Web Token** message editor tab.
2. In the header of the JWT, replace the current value of the `kid` parameter with the `kid` of the JWK that you uploaded to the exploit server.
3. Add a new `jku` parameter to the header of the JWT. Set its value to the URL of your JWK Set on the exploit server.
4. In the payload, change the value of the `sub` claim to `administrator`.
5. At the bottom of the tab, click **Sign**, then select the RSA key that you generated in the previous section.
6. Make sure that the **Don't modify header** option is selected, then click **OK**. The modified token is now signed with the correct signature. 
7. Send the request. Observe that you have successfully accessed the admin panel.
8. In the response, find the URL for deleting `carlos` (`/admin/delete?username=carlos`). Send the request to this endpoint to solve the lab.


**Workflow:**
1. analyse the JWT-> we see that is signed with a RSA key so we will generate a new one
	![](Pasted%20image%2020250221195120.png)
	![](Pasted%20image%2020250221195419.png)

2. On our exploit server from where we will deliver the malicious url, replace the contents of the **Body** section with an empty JWK Set:
	![](Pasted%20image%2020250221195812.png)

3. Back in Burp, on the **JWT Editor Keys** tab, right-click on the entry for the key that you just generated, then select **Copy Public Key as JWK**. We will paste the JWK into the `keys` array on the exploit server, then store the exploit:
	![](Pasted%20image%2020250221200119.png)

4. In the header of the JWT, replace the current value of the `kid` parameter with the `kid` of the JWK that you uploaded to the exploit server. 
	- Add a new `jku` parameter to the header of the JWT. Set its value to the URL of your JWK Set on the exploit server.
	- On the payload section change sub in `administrator`
	![](Pasted%20image%2020250221200535.png)

5. At the bottom of the tab, click **Sign**, then select the RSA key that you generated. Make sure that the **Don't modify header** option is selected, then click **OK**. The modified token is now signed with the correct signature. Click **send**.
	![](Pasted%20image%2020250221200730.png)
	![](Pasted%20image%2020250221202405.png)

Note:
	If it doesn't work try to store the `jwk` as `jwk.json` file on the exploit server as it presented above 