In this room, several common misconfigurations and vulnerabilities with JWT implementations were showcased. 

### Key Takeaways
- As JWTs are sent client-side and encoded, sensitive information should not be stored in their claims.
- The JWT is only as secure as its signature. Care should be taken when verifying the signature to ensure that there is no confusion or weak secrets being used.
- JWTs should expire and have sensible lifetimes to avoid persistent JWTs being used by a threat actor.
- In SSO environments, the audience claim is crucial to ensure that the specific application's JWT is only used on that application.
- As JWTs make use of cryptography to generate the signature, cryptographic attacks can also be relevant for JWT exploitation. We will dive into this a bit more in our cryptography module.

More on: https://portswigger.net/web-security/jwt#what-are-jwt-attacks

### Summary and Key Points of JWT Attacks from PortSwigger:
#### 1. **Overview of JWT (JSON Web Tokens)**
JWTs are used to securely transmit information between parties as a JSON object. They include a payload, a header, and a signature. The payload contains the claims (user information, permissions), and the signature ensures data integrity.

#### 2. **JWT Vulnerabilities and Common Attacks**
Several weaknesses can arise due to misconfiguration or insecure implementation:

- **Weak Signature Verification:** Some servers may not properly verify JWT signatures, leading to vulnerabilities like accepting arbitrary or "none" algorithm tokens. Attackers can modify tokens to gain unauthorized access.
- **Brute-Forcing Secret Keys:** JWTs signed with weak or guessable keys can be brute-forced, allowing attackers to forge valid tokens. Tools like Hashcat are commonly used for this.
- **Algorithm Confusion Attacks:** By switching the token's algorithm from asymmetric (e.g., RS256) to symmetric (HS256), attackers can trick servers into validating tokens incorrectly, potentially using the public key as a secret.
- **Header Parameter Injection:** Manipulating parameters like `kid` (key ID) or `jku` (JSON key URL) in the JWT header can lead to server-side request forgery (SSRF) or bypassing verification.

#### 3. **Key Exploitation Techniques**
- **Changing Algorithms:** An attacker may modify the JWT header to use the "none" algorithm, bypassing signature verification if the server accepts it.
- **Brute Force:** By attempting to guess the signing key, attackers can generate valid tokens and escalate privileges.
- **Parameter Injection:** Exploiting vulnerabilities in key fetching mechanisms can allow attackers to control the keys used for verification.

#### 4. **Prevention and Mitigation**
- **Enforce Strong Algorithms:** Ensure that only secure algorithms are allowed (e.g., HS256, RS256) and block "none" as an option.
- **Strong Secret Management:** Use complex, unpredictable secrets for signing tokens.
- **Validation and Input Handling:** Carefully validate all JWT fields and ensure secure handling of external key URLs.