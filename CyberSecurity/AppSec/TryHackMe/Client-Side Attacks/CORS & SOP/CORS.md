Cross-Origin Resource Sharing (CORS) is a mechanism defined by HTTP headers that allows servers to specify how resources can be requested from different origins. While the Same-Origin Policy (SOP) restricts web pages by default to making requests to the same domain, CORS enables servers to declare exceptions to this policy, allowing web pages to request resources from other domains under controlled conditions.

CORS operates through a set of HTTP headers that the server sends as part of its response to a browser. These headers inform the browser about the server's CORS policy, such as:
- which origins are allowed to access the resources, 
- which HTTP methods are permitted, 
- whether credentials can be included with the requests. 

It's important to note that the server does not block or allow a request based on CORS; instead, it processes the request and includes CORS headers in the response. The browser then interprets these headers and enforces the CORS policy by granting or denying the web page's JavaScript access to the response based on the specified rules.

## Different HTTP Headers Involved in CORS
1. **Access-Control-Allow-Origin**: This header specifies which domains are allowed to access the resources. For example, `Access-Control-Allow-Origin: example.com` allows only requests from `example.com`.
2. **Access-Control-Allow-Methods**: Specifies the HTTP methods (GET, POST, etc.) that can be used during the request.
3. **Access-Control-Allow-Headers**: Indicates which HTTP headers can be used during the actual request.
4. **Access-Control-Max-Age**: Defines how long the results of a preflight request can be cached.
5. **Access-Control-Allow-Credentials**: This header instructs the browser whether to expose the response to the frontend JavaScript code when credentials like cookies, HTTP authentication, or client-side SSL certificates are sent with the request. If Access-Control-Allow-Credentials is set to true, it allows the browser to access the response from the server when credentials are included in the request. It's important to note that when this header is used, Access-Control-Allow-Origin cannot be set to * and must specify an explicit domain to maintain security.

## Common Scenarios Where CORS is Applied
CORS is commonly applied in scenarios such as:

1. **APIs and Web Services**: When a web application from one domain needs to access an API hosted on a different domain, CORS enables this interaction. For instance, a frontend application at `example-client.com` might need to fetch data from `example-api.com`.
2. **Content Delivery Networks (CDNs)**: Many websites use CDNs to load libraries like jQuery or fonts. CORS enables these resources to be securely shared across different domains.
3. **Web Fonts**: For web fonts to be used across different domains, CORS headers must be set, allowing websites to load fonts from a centralized location.
4. **Third-Party Plugins/Widgets:** Enabling features like social media buttons or chatbots from external sources on a website.
5. **Multi-Domain User Authentication:** Services that offer single sign-on (SSO) or use tokens (like OAuth) to authenticate users across multiple domains rely on CORS to exchange authentication data secure.

## Simple Requests vs. Preflight Requests
There are two primary types of requests in CORS: 

1. **Simple Requests**: These requests meet certain criteria set by CORS that make them "simple". They are treated similarly to same-origin requests, with some restrictions. A request is considered simple if it uses the GET, HEAD, or POST method, and the POST request's `Content-Type` header is one of `application/x-www-form-urlencoded`, `multipart/form-data`, or `text/plain`. 

	Additionally, the request should not include custom headers that aren't CORS-safe listed. Simple requests are sent directly to the server with the `Origin` header, and the response is subject to CORS policy enforcement based on the `Access-Control-Allow-Origin` header. Importantly, cookies and HTTP authentication data are included in simple requests if the site has previously set such credentials, even without the `Access-Control-Allow-Credentials` header being true.
    
2. **Preflight Requests**: These are CORS requests that the browser "preflights" with an OPTIONS request before sending the actual request to ensure that the server is willing to accept the request based on its CORS policy. Preflight is triggered when the request does not qualify as a "simple request", such as when using HTTP methods other than GET, HEAD, or POST, or when POST requests are made with another `Content-Type` other than the allowed values for simple requests, or when custom headers are included.
 
	The preflight OPTIONS request includes headers like `Access-Control-Request-Method` and `Access-Control-Request-Headers`, indicating the method and custom headers of the actual request. The server must respond with appropriate CORS headers, such as `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`, and `Access-Control-Allow-Origin` to indicate that the actual request is permitted. If the preflight succeeds, the browser will send the actual request with credentials included if `Access-Control-Allow-Credentials` is set to true.


### CORS Request Process
The below flowchart shows the basic process of a CORS request.

1. The browser first sends an HTTP request to the server.
2. The server then checks the Origin header against its list of allowed origins.
3. If the origin is allowed, the server responds with the appropriate `Access-Control-Allow-Origin` header.
4. The browser will block the cross-origin request if the origin is not allowed.
	![](Pasted%20image%2020250205182541.png)