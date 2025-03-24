https://portswigger.net/web-security/websockets/what-are-websockets

# Summary
WebSockets are a communication protocol that provides full-duplex communication channels over a single TCP connection. Unlike the traditional HTTP request-response model, WebSockets enable persistent connections between client and server, allowing for real-time data exchange in both directions without requiring the client to initiate each communication.

**WebSocket Protocol:**
- Established over HTTP using an upgrade request
- Starts with a standard HTTP handshake
- Uses `ws://` (unencrypted) or `wss://` (encrypted) URI scheme
- Operates on ports 80/443 by default, but can use any port

	![](Pasted%20image%2020250315194728%201.png)

##  Vulnerabilities
1. **Cross-Site WebSocket Hijacking (CSWSH)**
    - Similar to CSRF but for WebSockets
    - Occurs when WebSocket handshakes lack proper origin validation
    - Can lead to session hijacking
2. **Input Validation Vulnerabilities**
    - XSS in WebSocket messages
    - SQL injection via WebSocket data
    - Server-side template injection
    - OS command injection
3. **Authentication Issues**
    - Missing authentication checks after initial handshake
    - Token leakage or improper session handling
4. **Information Disclosure**
    - Sensitive data transmitted over unencrypted WebSockets
    - Excessive error messages revealing implementation details
5. **Denial of Service**
    - Resource exhaustion through multiple connections
    - Message flooding

## Security Best Practices
1. **Secure Communication**
    - Use wss:// (WebSockets Secure) instead of ws://
    - Implement TLS 1.2+ for all WebSocket connections
2. **Authentication and Authorization**
    - Properly authenticate users before establishing WebSocket connections
    - Implement authorization checks for each message
    - Use secure tokens or cookies
    - Re-validate permissions for sensitive operations
3. **Input Validation**
    - Validate and sanitize all data received via WebSockets
    - Implement message schemas and enforce compliance
    - Apply context-appropriate encoding for output
4. **Connection Management**
    - Implement timeouts for inactive connections
    - Limit number of connections per client
    - Properly handle connection termination
5. **Origin Validation**
    - Verify the Origin header during WebSocket handshake
    - Implement CORS policies for WebSocket connections
6. **Monitoring and Rate Limiting**
    - Monitor WebSocket traffic for anomalies
    - Implement rate limiting to prevent abuse
    - Set up alerts for suspicious activities

## Differences from HTTP
1. **Connection Persistence**
    - WebSockets maintain a persistent connection, unlike the stateless nature of HTTP
    - Reduced overhead for multiple communications
2. **Bidirectional Communication**
    - Server can push data to clients without client requests
    - More efficient for real-time applications
3. **Message-Based vs Document-Based**
    - WebSockets use message-based communication
    - HTTP is document-based
4. **Reduced Header Overhead**
    - After handshake, WebSocket frames have minimal headers
    - More efficient for frequent, small messages


# 1. Manipulating WebSocket messages
This online shop has a live chat feature implemented using WebSockets. Chat messages that you submit are viewed by a support agent in real time.

To solve the lab, use a WebSocket message to trigger an `alert()` popup in the support agent's browser.

**Analysis:**
1. Click "Live chat" and send a chat message.
2. In Burp Proxy, go to the WebSockets history tab, and observe that the chat message has been sent via a WebSocket message.
3. Using the browser, send a new message containing a `<` character.
4. In Burp Proxy, find the corresponding WebSocket message and observe that the `<` has been HTML-encoded by the client before sending.
5. Ensure that Burp Proxy is configured to intercept WebSocket messages, then send another chat message.
6. Edit the intercepted message to contain the following payload:
    `<img src=1 onerror='alert(1)'>`
7. Observe that an alert is triggered in the browser. This will also happen in the support agent's browser.

**Workflow:**
