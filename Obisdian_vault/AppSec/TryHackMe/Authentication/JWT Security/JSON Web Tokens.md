JWTs are self-contained tokens that can be used to securely transmit session information. It is an [open standard](https://tools.ietf.org/html/rfc7519), providing information for any developer or library creator who wants to use JWTs. The JWT structure is shown below:
	![](Pasted%20image%2020241128010341.png)

## JWT Structure
A JWT consists of three components, each Base64Url encoded and separated by dots:
- **Header** - The header usually indicates the type of token, which is JWT, as well as the signing algorithm that is used.
- **Payload** - The payload is the body of the token, which contain the claims. A claim is a piece of information provided for a specific entity. In JWTs, there are registered claims, which are claims predefined by the JWT standard and public or private claims. The public and private claims are those which are defined by the developer. It is worth knowing the different between public and private claims, but not for security purposes, hence this will not be our focus in this room.
- **Signature** - The signature is the part of the token that provides a method for verifying the token's authenticity. The signature is created by using the algorithm specified in the header of the JWT. Let's dive a bit into the main signing algorithms.

## Signing Algorithms
Although there are several different algorithms defined in the JWT standard, we only really care about three main ones:
- **None** - The None algorithm means no algorithm is used for the signature. Effectively, this is a JWT without a signature, meaning that the verification of the claims provided in the JWT cannot be verified through the signature.
- **Symmetric Signing** - A symmetric signing algorithm, such as HS265, creates the signature by appending a secret value to the header and body of the JWT before generating a hash value. Verification of the signature can be performed by any system that has knowledge of the secret key.
- **Asymmetric Signing** - An asymmetric signing algorithm, such as RS256, creates the signature by using a private key to sign the header and body of the JWT. This is created by generating the hash and then encrypting the hash using the private key. Verification of the signature can be performed by any system that has knowledge of the public key associated with the private key that was used to create the signature.

## Security in the Signature
JWTs can be encrypted (called *JWEs*), but the key power of JWTs comes from the signature. Once a JWT is signed, it can be sent to the client, who can use this JWT wherever needed. We can have a centralised authentication server that creates the JWTs used on several applications. Each application can then verify the signature of the JWT; if verified, the claims provided within the JWT can be trusted and acted upon.