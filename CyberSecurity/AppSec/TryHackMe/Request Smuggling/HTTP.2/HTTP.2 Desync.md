
## Downgrading
When a reverse proxy serves content to the end user with HTTP/2 (frontend connection) but requests it from the backend servers by using HTTP/1.1 (backend connection), we talk about HTTP/2 downgrading. This type of implementation is still common nowadays, making it possible to reintroduce HTTP request smuggling in the context of HTTP/2, but only where downgrades to HTTP/1.1 occur.
	![](Pasted%20image%2020250209172349.png)

Instead of dealing directly with HTTP/2, we send HTTP/2 requests in the frontend connection to influence the corresponding HTTP/1.1 request generated in the backend connection so that it causes an HTTP desync condition. 

Ideally, the proxy should safely convert a single HTTP/2 request to a single HTTP/1.1 equivalent. This is only sometimes true in practice. Each proxy implementation may handle the conversion slightly differently, making introducing a malicious HTTP/1.1 request in the backend connection possible, leading to any of the typical cases of HTTP desync.

## The Expected Behaviour
Before getting into request smuggling, let's understand how a request would be translated from HTTP/2 to HTTP/1.1. Take the following POST request as an example: