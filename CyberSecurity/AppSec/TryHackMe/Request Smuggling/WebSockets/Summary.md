When using HTTP, the client must make a request before the server can send any information. This complicates the implementation of some application features that require bidirectional communications. For example, suppose you are implementing a web application that needs to send real-time notifications to the user. Since the server can't push information to the user at will, the client would need to constantly poll the server for notifications, requiring lots of wasted requests.

The WebSocket protocol allows the creation of two-way communication channels between a browser and a server by establishing a long-lasting connection that can be used for full-duplex communications.

## Upgrading HTTP connections to Websockets

The WebSocket protocol was designed to be fully compatible with HTTP. Establishing a WebSocket connection follows a process similar to that of **h2c**. The client sends an initial HTTP request with an `Upgrade: websocket` header and other additional headers. If the server supports WebSockets, it responds with a `101 Switching Protocols` response and upgrades the connection accordingly. From that point onwards, the connection uses the WebSocket protocol instead of HTTP.
	![](Pasted%20image%2020250215032347.png)

If we now add a proxy in the middle, something interesting happens: Instead of fronting the connections themselves, most proxies won't handle the upgrade but will instead relay them to the backend server. Once the connection is upgraded, the proxy will establish a tunnel between the client and server, so any further WebSocket traffic is forwarded without interruptions.
	![](Pasted%20image%2020250215032434.png)


