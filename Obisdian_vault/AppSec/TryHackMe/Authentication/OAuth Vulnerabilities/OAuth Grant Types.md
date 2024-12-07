OAuth 2.0 provides several grant types to accommodate various scenarios and client types. These grant types define how an application can obtain an access token to access protected resources on behalf of the resource owner.

## Authorization Code Grant
The **Authorization Code grant** is the most widely used OAuth 2.0 flow, ideal for server-side applications (e.g., PHP, Java, .NET). How it works

1. **User Redirect:**  
    The client (app) redirects the user to the **authorization server** for login and permission.
    
2. **User Authentication & Consent:**  
    The user authenticates and grants access to the client.
    
3. **Authorization Code:**  
    The authorization server sends the user back to the client with an **authorization code** (temporary credential).
    
4. **Access Token Exchange:**  
    The client sends the authorization code to the **token endpoint** of the authorization server to exchange it for an **access token**.

This flow ensures secure handling of tokens, as sensitive data (access tokens) is only exchanged server-side, reducing the risk of exposure. 
![](Pasted%20image%2020241201141944.png)

This grant type is known for its enhanced security, as the authorization code is exchanged for an access token server-to-server, meaning the access token is not exposed to the user agent (e.g., browser), thus reducing the risk of token leakage. It also supports using refresh tokens to maintain long-term access without repeated user authentication.

## Implicit Grant
The Implicit grant is primarily designed for mobile and web applications where clients cannot securely store secrets.

1. **User Redirect:**  
    The client (app) redirects the user to the **authorization server** for login and consent.
    
2. **User Authentication & Authorization:**  
    The user authenticates and grants the client permission to access their data.
    
3. **Access Token Issued:**  
    After authorization, the **authorization server** directly returns an **access token** in the URL fragment.
    
4. **Client Access:**  
    The client extracts the token from the URL and uses it to access protected resources on behalf of the user.

This flow avoids the need for a separate token exchange step, making it faster but less secure, as the token is exposed in the URL.
![](Pasted%20image%2020241201143255.png)

This grant type is simplified and suitable for clients who cannot securely store client secrets. It is faster as it involves fewer steps than the authorization code grant. However, it is less secure as the access token is exposed to the user agent and can be logged in the browser history. It also **does not support refresh tokens**.

## Resource Owner Password Credentials Grant
The Resource Owner Password Credentials grant is used when the client is **highly trusted by the resource owner**, such as first-party applications. The client collects the user’s credentials (username and password) directly and exchanges them for an access token, as shown below:
![](Pasted%20image%2020241201143533.png)

In this flow, the user provides their credentials directly to the client. The client then sends the credentials to the authorization server, which verifies the credentials and issues an access token. This grant type is direct, requiring fewer interactions, making it suitable for highly trusted applications where the user is confident in providing their credentials. However, it is less secure because it involves sharing credentials directly with the client and is unsuitable for third-party applications.

## Client Credentials Grant  
The Client Credentials grant is used for server-to-server interactions without user involvement. The client uses his credentials to authenticate with the authorization server and obtain an access token. In this flow, the client authenticates with the authorization server using its client credentials (client ID and secret), and the authorization server issues an access token directly to the client, as shown below:

![](Pasted%20image%2020241201143726.png)

This grant type is suitable for backend services and server-to-server communication as it does not involve user credentials, thus reducing security risks related to user data exposure.