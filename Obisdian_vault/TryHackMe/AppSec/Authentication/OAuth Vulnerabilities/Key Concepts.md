
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

This structure ensures secure access to resources while giving users control over their data and permissions.