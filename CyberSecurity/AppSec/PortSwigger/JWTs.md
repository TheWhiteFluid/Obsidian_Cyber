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


## 1.Authentication bypass via unverified signature
This lab uses a JWT-based mechanism for handling sessions. Due to implementation flaws, the server doesn't verify the signature of any JWTs that it receives.

To solve the lab, modify your session token to gain access to the admin panel at `/admin`, then delete the user `carlos`. You can log in to your own account using the following credentials: `wiener:peter`

**Analysis:**
- **Log in** to your account in the lab.
- **Check JWT token** in Burp's **Proxy > HTTP history** after logging in.
- **Decode JWT** in the **Inspector panel** and note the `sub` claim (your username).
- **Send request to Burp Repeater**, modify the path to `/admin`, and check access restrictions.
- **Edit JWT payload**, changing `sub` from `wiener` to `administrator`, then apply changes.
- **Resend the request** to access the **admin panel** successfully.
- **Find and send the delete request** (`/admin/delete?username=carlos`) to solve the lab.

**Example:**
