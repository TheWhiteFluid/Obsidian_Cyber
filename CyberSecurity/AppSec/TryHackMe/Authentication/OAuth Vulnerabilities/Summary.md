### Structure
The following structure ensures secure access to resources while giving users control over their data and permissions:

1. **Resource Owner:**  
    The user or system that controls the data and grants permission for an application to access it.  
    _Example:_ You, as a customer, giving the coffee shop app access to your account.
    
2. **Client:**  
    The application requesting access on behalf of the resource owner.  
    _Example:_ The coffee shop’s mobile app.
    
3. **Authorization Server:**  
    Issues access tokens after verifying the user’s identity and consent.  
    _Example:_ The backend system that handles your login and grants the app access.
    
4. **Resource Server:**  
    Hosts and protects the data, allowing access only to clients with valid tokens.  
    _Example:_ The database storing your account and order details.
    
5. **Authorization Grant:**  
    A credential (like a login) used by the client to obtain an access token.  
    _Example:_ Logging in to the app to get access to your account.
    
6. **Access Token:**  
    A short-lived credential allowing the client to access protected resources.  
    _Example:_ The app uses this token to place orders without asking you to log in again.
    
7. **Refresh Token:**  
    A long-lived credential used to get a new access token without re-authentication.  
    _Example:_ The app gets a new token after the old one expires, keeping you logged in.
    
8. **Redirect URI:**  
    The URL where the user is sent after login to confirm authorization.  
    _Example:_ Redirecting to the app after successfully logging in.
    
9. **Scope:**  
    Defines the level of access the app requests from the resource owner.  
    _Example:_ The app asks for permission to view your order history and payment details.
    
10. **State Parameter:**  
    A security feature to prevent attacks by linking the authorization response to the client’s request.  
    _Example:_ Ensures the response you get matches your initial login request.
    
11. **Token & Authorization Endpoints:**
    - **Authorization Endpoint:** Where the user logs in and authorizes access.
    - **Token Endpoint:** Where the client exchanges the authorization grant for an access token.  
        _Example:_ The app interacts with these endpoints to authenticate you and access your data.

---

More on: https://portswigger.net/web-security/oauth

### Summary and Key Points of OAuth Attacks from PortSwigger:
#### 1. **OAuth Overview**
OAuth is an open standard for access delegation, allowing third-party services to access resources on behalf of a user without sharing credentials. This is commonly used in scenarios like "Sign in with Google/Facebook." OAuth works by exchanging tokens rather than credentials.

#### 2. **OAuth Grant Types**
Different grant types define how clients interact with the authorization server to obtain access tokens:
- **Authorization Code Grant**: The most secure, designed for server-side applications. It uses a two-step process involving a code exchange for a token, enhancing security by keeping tokens out of the browser.
- **Implicit Grant**: Suitable for client-side apps but less secure. Tokens are issued directly and can be exposed in URLs.
- **Client Credentials Grant**: Used for machine-to-machine communication without user involvement.
- **Resource Owner Password Credentials Grant**: Allows a client to exchange a user’s credentials for a token but is generally discouraged due to security risks​

#### 3. **OAuth Vulnerabilities**
Common vulnerabilities in OAuth implementations include:
- **Improper Redirect URI Validation**: Attackers can exploit weak validation to redirect tokens to malicious endpoints.
- **State Parameter Manipulation**: Without proper usage of the `state` parameter, OAuth flows may be vulnerable to CSRF attacks.
- **Token Leaks**: Tokens can leak through HTTP referers or insufficiently secured storage.
- **Scope Mismanagement**: If scopes are not validated properly, excessive permissions may be granted​

#### 4. **OpenID Connect (OIDC)**
An extension of OAuth 2.0, OIDC adds user authentication, allowing clients to verify a user’s identity and obtain basic profile information. It uses an ID token along with access tokens, adding another layer of security and functionality​

#### 5. **Security Best Practices**
To secure OAuth implementations:
- **Strict Redirect URI Validation**: Only allow exact matches to registered URIs.
- **State Parameter Usage**: Always use and validate the `state` parameter to prevent CSRF.
- **PKCE (Proof Key for Code Exchange)**: Essential for public clients (e.g., mobile apps) to secure authorization codes.
- **Token Storage**: Store tokens securely and avoid exposing them in URLs or client-side scripts​