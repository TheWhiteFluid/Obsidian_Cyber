In this room, several common misconfigurations and vulnerabilities with JWT implementations were showcased. 

### Key Takeaways
- As JWTs are sent client-side and encoded, sensitive information should not be stored in their claims.
- The JWT is only as secure as its signature. Care should be taken when verifying the signature to ensure that there is no confusion or weak secrets being used.
- JWTs should expire and have sensible lifetimes to avoid persistent JWTs being used by a threat actor.
- In SSO environments, the audience claim is crucial to ensure that the specific application's JWT is only used on that application.
- As JWTs make use of cryptography to generate the signature, cryptographic attacks can also be relevant for JWT exploitation. We will dive into this a bit more in our cryptography module.