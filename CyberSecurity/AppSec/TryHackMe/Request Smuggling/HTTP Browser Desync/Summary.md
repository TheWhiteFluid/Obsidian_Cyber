
## HTTP features

- **HTTP Keep-Alive** :
  HTTP keep-alive is a mechanism that allows the reuse of a single TCP connection for multiple HTTP requests and responses. It helps reduce latency and improve performance by avoiding the need to open and close connections repeatedly. However, it can introduce a security risk known as Cache Poisoning. If caching mechanisms are in place, the persistence of connections through keep-alive could contribute to cache poisoning attacks. An attacker might exploit desynchronization issues to store malicious content in caches.
	![](Pasted%20image%2020250215043608.png)

- **HTTP Pipelining**
  Usually, with HTTP, one request results in one response. If the HTTP pipelining is enabled in the backend server, it will allow the simultaneous sending of two requests with the corresponding responses without waiting for each response. The only way to differentiate between two requests and a big one is by using the Content-Length header, which specifies the length in bytes of each request. The content header is an unnecessary header for most static file contents in a web application, like images or icons, since the backend server will usually not consider it.
	![](Pasted%20image%2020250215043647.png)


## Browser Desync
In a Browser Desync attack, the attacker aims to take control of a victim's account by exploiting vulnerabilities in a web application's user connection system.
	![](Pasted%20image%2020250215043909.png)

